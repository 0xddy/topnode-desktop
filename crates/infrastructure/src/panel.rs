use std::{fmt::Write as _, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{Response, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::{Mutex, RwLock};
use topnode_application::{
    ConfigurationRequest, ConfigurationSource, ConfigurationSourceError, LoginCredentials,
    PanelError, PanelRepository, PasswordChange,
};
use topnode_domain::{
    AffiliateCommission, AffiliateCommissionPage, AffiliateCommissionStatus, AffiliateRebateType,
    AffiliateSummary, AffiliateTransfer, AffiliateTransferPage, BalanceTransaction,
    BalanceTransactionType, ClientConfiguration, EndpointType, Entitlement, GiftCardConfig,
    GiftCardRedeemCheck, GiftCardRewardPreview, GiftCardRewardType, RouteMode, ServerGroup,
    ServerNode, SessionTokens, ShopCatalog, ShopCouponDiscountType, ShopCouponQuote, ShopOrder,
    ShopOrderSelection, ShopOrderStatus, ShopPaymentChoice, ShopPaymentMethod, ShopPaymentSession,
    ShopPaymentStatus, ShopPlan, ShopPlanPrice, ShopPurchaseKind, ShopTrafficAddon,
    SubscriptionLink, SupportTicket, SupportTicketAction, SupportTicketDetail, SupportTicketDraft,
    SupportTicketMessage, SupportTicketPage, SupportTicketPriority, SupportTicketSenderRole,
    SupportTicketStatus, UserIdentity, UserOrder, UserOrderFilter, UserOrderItem, UserOrderPage,
    UserOrderPaymentMethod, UserOrderSource, UserOrderStatus, UserOrderType, UserSession,
};

use crate::{
    PanelEndpoint, SessionVault,
    api_endpoint::build_discovered_endpoint_client,
    tls::{FIXED_PANEL_HOST, fixed_panel_client_config},
};

const SUCCESS_CODE: i64 = 200;
const MAX_RESPONSE_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_DEVICE_ID_BYTES: usize = 191;
const MAX_DEVICE_NAME_BYTES: usize = 128;
const MAX_PLATFORM_BYTES: usize = 32;
const MAX_VERSION_NAME_BYTES: usize = 64;

#[derive(Clone, Debug)]
pub struct PanelClientOptions {
    pub base_url: String,
    pub device_id: String,
    pub device_name: String,
    pub platform: String,
    pub version_name: String,
}

impl PanelClientOptions {
    pub fn fixed(device_id: impl Into<String>) -> Self {
        Self {
            base_url: format!("https://{FIXED_PANEL_HOST}/"),
            device_id: device_id.into(),
            device_name: format!("TOPNODE Desktop ({})", std::env::consts::OS),
            platform: match std::env::consts::OS {
                "macos" => "macos",
                "windows" => "windows",
                "linux" => "linux",
                _ => std::env::consts::OS,
            }
            .to_owned(),
            version_name: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    pub fn for_endpoint(endpoint: &PanelEndpoint, device_id: impl Into<String>) -> Self {
        let mut options = Self::fixed(device_id);
        endpoint
            .logical_base_url()
            .clone_into(&mut options.base_url);
        options
    }

    #[must_use]
    pub fn with_version_name(mut self, version_name: impl Into<String>) -> Self {
        self.version_name = version_name.into();
        self
    }
}

#[derive(Clone)]
pub struct HttpPanelClient {
    inner: Arc<Inner>,
}

struct Inner {
    client: reqwest::Client,
    logical_base_url: Url,
    request_base_url: Url,
    options: PanelClientOptions,
    vault: SessionVault,
    session: RwLock<Option<UserSession>>,
    session_gate: Mutex<()>,
}

impl std::fmt::Debug for HttpPanelClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpPanelClient")
            .field("base_url", &self.inner.logical_base_url)
            .finish_non_exhaustive()
    }
}

impl HttpPanelClient {
    /// Creates the fixed-policy HTTPS Panel client.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-HTTPS/invalid base URL or TLS client failure.
    pub fn new(options: PanelClientOptions, vault: SessionVault) -> Result<Self, PanelError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (options, base_url) = normalize_client_options(options)?;
        let client_builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(20))
            .user_agent(format!("TOPNODE-Desktop/{}", options.version_name));
        let client_builder = if uses_fixed_panel_pins(&base_url) {
            let tls = fixed_panel_client_config()
                .map_err(|error| PanelError::Transport(error.to_string()))?;
            client_builder.use_preconfigured_tls(tls)
        } else {
            client_builder.tls_backend_rustls()
        };
        let client = client_builder
            .build()
            .map_err(|error| PanelError::Transport(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                logical_base_url: base_url.clone(),
                request_base_url: base_url,
                options,
                vault,
                session: RwLock::new(None),
                session_gate: Mutex::new(()),
            }),
        })
    }

    /// Creates a Panel client for a route selected by remote startup probing.
    ///
    /// The endpoint's direct/fronted TLS, DNS, SNI, authority, and pin policy
    /// is the same policy used by the connectivity probe.
    ///
    /// # Errors
    ///
    /// Returns an error when identity fields do not match the endpoint or the
    /// endpoint-specific HTTP client cannot be constructed.
    pub fn new_for_endpoint(
        options: PanelClientOptions,
        endpoint: &PanelEndpoint,
        vault: SessionVault,
    ) -> Result<Self, PanelError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (options, logical_base_url) = normalize_client_options(options)?;
        if endpoint.logical_url() != &logical_base_url {
            return Err(PanelError::InvalidResponse(
                "Panel endpoint 与客户端基础地址不一致".to_owned(),
            ));
        }
        let client = build_discovered_endpoint_client(
            endpoint,
            Duration::from_secs(8),
            Duration::from_secs(20),
            &format!("TOPNODE-Desktop/{}", options.version_name),
        )
        .map_err(|error| PanelError::Transport(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                logical_base_url,
                request_base_url: endpoint.transport_url().clone(),
                options,
                vault,
                session: RwLock::new(None),
                session_gate: Mutex::new(()),
            }),
        })
    }

    async fn authenticated<T, F>(&self, build: F) -> Result<T, PanelError>
    where
        T: DeserializeOwned,
        F: Fn(&str) -> reqwest::RequestBuilder,
    {
        let session = self
            .inner
            .session
            .read()
            .await
            .clone()
            .ok_or(PanelError::NoSession)?;
        let initial_session_id = session.tokens.session_id().to_owned();
        let failed_token = session.tokens.access_token().to_owned();
        let response = send(build(&failed_token)).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            let _guard = self.inner.session_gate.lock().await;
            self.require_session_locked(&initial_session_id).await?;
            return decode(response).await;
        }
        let first_authentication_error = match decode::<T>(response).await {
            Err(error) => error,
            Ok(_) => PanelError::Unauthorized,
        };

        let _guard = self.inner.session_gate.lock().await;
        let current = self.require_session_locked(&initial_session_id).await?;
        if current.tokens.access_token() == failed_token
            && matches!(
                &first_authentication_error,
                PanelError::Business { code: 403_001, .. }
            )
        {
            self.invalidate_session_locked(&first_authentication_error)
                .await;
            return Err(first_authentication_error);
        }
        if current.tokens.access_token() == failed_token
            && let Err(error) = self.refresh_locked(current, &initial_session_id).await
        {
            let surfaced_error = session_authentication_error(&error);
            self.invalidate_session_locked(&error).await;
            return Err(surfaced_error);
        }
        let current = self.require_session_locked(&initial_session_id).await?;
        let access_token = current.tokens.access_token().to_owned();
        let response = send(build(&access_token)).await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            let error = match decode::<T>(response).await {
                Err(error) => error,
                Ok(_) => PanelError::Unauthorized,
            };
            let surfaced_error = session_authentication_error(&error);
            self.invalidate_session_locked(&error).await;
            return Err(surfaced_error);
        }
        decode(response).await
    }

    async fn refresh_locked(
        &self,
        session: UserSession,
        expected_session_id: &str,
    ) -> Result<(), PanelError> {
        if session.tokens.refresh_expires_at_epoch_seconds() <= epoch_seconds() {
            return Err(PanelError::Unauthorized);
        }
        let endpoint = self.endpoint("api/v1/auth/refresh")?;
        let response = send(
            self.inner
                .client
                .post(endpoint)
                .header("X-Request-ID", request_id())
                .header("Cache-Control", "no-store")
                .json(&RefreshRequestDto {
                    refresh_token: session.tokens.refresh_token(),
                }),
        )
        .await?;
        let refreshed: RefreshResponseDto = decode(response).await?;
        let tokens = refreshed.into_tokens()?;
        if tokens.session_id() != expected_session_id {
            return Err(PanelError::InvalidResponse(
                "刷新响应切换了会话标识".to_owned(),
            ));
        }
        let updated = UserSession {
            user: session.user,
            tokens,
        };
        self.inner.vault.write(&updated).await?;
        *self.inner.session.write().await = Some(updated);
        Ok(())
    }

    async fn require_session_locked(
        &self,
        expected_session_id: &str,
    ) -> Result<UserSession, PanelError> {
        self.inner
            .session
            .read()
            .await
            .as_ref()
            .filter(|session| session.tokens.session_id() == expected_session_id)
            .cloned()
            .ok_or(PanelError::Unauthorized)
    }

    async fn clear_session_locked(&self) -> Result<(), PanelError> {
        *self.inner.session.write().await = None;
        self.inner.vault.clear().await
    }

    async fn invalidate_session_locked(&self, cause: &PanelError) {
        *self.inner.session.write().await = None;
        if let Err(clear_error) = self.inner.vault.clear().await {
            tracing::error!(%cause, %clear_error, "session invalidated but credential cleanup failed");
        } else {
            tracing::warn!(%cause, "session invalidated after refresh failure");
        }
    }

    async fn revoke_session(&self, session: &UserSession) -> Result<(), PanelError> {
        let endpoint = self.endpoint("api/v1/auth/logout")?;
        let response = send(
            self.inner
                .client
                .post(endpoint)
                .header("X-Request-ID", request_id())
                .bearer_auth(session.tokens.access_token())
                .header("Cache-Control", "no-store")
                .json(&LogoutRequestDto {
                    refresh_token: session.tokens.refresh_token(),
                }),
        )
        .await?;
        let logout: LogoutResponseDto = decode(response).await?;
        if !logout.revoked {
            return Err(PanelError::InvalidResponse(
                "服务端未确认会话已经撤销".to_owned(),
            ));
        }
        Ok(())
    }

    fn endpoint(&self, path: &str) -> Result<Url, PanelError> {
        self.inner
            .request_base_url
            .join(path)
            .map_err(|error| PanelError::InvalidResponse(error.to_string()))
    }
}

fn normalize_client_options(
    mut options: PanelClientOptions,
) -> Result<(PanelClientOptions, Url), PanelError> {
    let mut base_url = Url::parse(&options.base_url)
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))?;
    if base_url.scheme() != "https" || base_url.cannot_be_a_base() || base_url.host_str().is_none()
    {
        return Err(PanelError::InvalidResponse(
            "Panel 基础地址必须是可拼接的 HTTPS URL".to_owned(),
        ));
    }
    if !base_url.username().is_empty() || base_url.password().is_some() {
        return Err(PanelError::InvalidResponse(
            "Panel 基础地址不能包含用户信息".to_owned(),
        ));
    }
    if base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(PanelError::InvalidResponse(
            "Panel 基础地址不能包含查询参数或片段".to_owned(),
        ));
    }
    if !base_url.path().ends_with('/') {
        base_url
            .path_segments_mut()
            .map_err(|()| PanelError::InvalidResponse("Panel 基础地址无法拼接路径".to_owned()))?
            .push("");
    }

    options.device_id = options.device_id.trim().to_owned();
    options.device_name = options.device_name.trim().to_owned();
    options.platform = options.platform.trim().to_lowercase();
    options.version_name = options.version_name.trim().to_owned();
    validate_device_field("device_id", &options.device_id, MAX_DEVICE_ID_BYTES, false)?;
    validate_device_field(
        "device_name",
        &options.device_name,
        MAX_DEVICE_NAME_BYTES,
        true,
    )?;
    if options.platform.is_empty()
        || options.platform.len() > MAX_PLATFORM_BYTES
        || !options.platform.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(PanelError::InvalidResponse(
            "Panel platform 字段无效".to_owned(),
        ));
    }
    let mut version_bytes = options.version_name.bytes();
    if options.version_name.len() > MAX_VERSION_NAME_BYTES
        || !version_bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !version_bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PanelError::InvalidResponse(
            "Panel version_name 字段无效".to_owned(),
        ));
    }
    options.base_url = base_url.to_string();
    Ok((options, base_url))
}

fn validate_device_field(
    name: &str,
    value: &str,
    maximum_bytes: usize,
    allow_empty: bool,
) -> Result<(), PanelError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
    {
        return Err(PanelError::InvalidResponse(format!(
            "Panel {name} 字段无效"
        )));
    }
    Ok(())
}

fn uses_fixed_panel_pins(base_url: &Url) -> bool {
    base_url.host_str() == Some(FIXED_PANEL_HOST)
}

#[async_trait]
impl PanelRepository for HttpPanelClient {
    async fn restore_session(&self) -> Result<Option<UserIdentity>, PanelError> {
        let _guard = self.inner.session_gate.lock().await;
        *self.inner.session.write().await = None;
        let Some(session) = self.inner.vault.read().await? else {
            return Ok(None);
        };
        if session.tokens.refresh_expires_at_epoch_seconds() <= epoch_seconds() {
            self.inner.vault.clear().await?;
            return Ok(None);
        }
        let user = session.user.clone();
        *self.inner.session.write().await = Some(session);
        Ok(Some(user))
    }

    async fn login(&self, credentials: &LoginCredentials) -> Result<UserIdentity, PanelError> {
        let _guard = self.inner.session_gate.lock().await;
        self.clear_session_locked().await?;
        let endpoint = self.endpoint("api/v1/auth/login")?;
        let response = send(
            self.inner
                .client
                .post(endpoint)
                .header("X-Request-ID", request_id())
                .header("Cache-Control", "no-store")
                .json(&LoginRequestDto {
                    email: credentials.email.trim(),
                    password: credentials.password(),
                    device_id: &self.inner.options.device_id,
                    device_name: &self.inner.options.device_name,
                    platform: &self.inner.options.platform,
                }),
        )
        .await?;
        let login: LoginResponseDto = decode(response).await?;
        let session = login.into_session()?;
        let user = session.user.clone();
        if let Err(error) = self.inner.vault.write(&session).await {
            self.invalidate_session_locked(&error).await;
            return Err(error);
        }
        *self.inner.session.write().await = Some(session);
        Ok(user)
    }

    async fn logout(&self) -> Result<(), PanelError> {
        let (session, local_result) = {
            let _guard = self.inner.session_gate.lock().await;
            let session = self.inner.session.write().await.take();
            let local_result = self.inner.vault.clear().await;
            (session, local_result)
        };
        let remote_result = match session.as_ref() {
            Some(session) => self.revoke_session(session).await,
            None => Ok(()),
        };
        finish_logout(local_result, remote_result)
    }

    async fn profile(&self) -> Result<UserIdentity, PanelError> {
        let endpoint = self.endpoint("api/v1/users/me")?;
        let user: UserDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        user.into_domain()
    }

    async fn change_password(&self, change: &PasswordChange) -> Result<(), PanelError> {
        let endpoint = self.endpoint("api/v1/users/password")?;
        let action: UserActionDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .patch(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&ChangePasswordRequestDto {
                        current_password: change.current_password(),
                        new_password: change.new_password(),
                    })
            })
            .await?;
        if !action.ok {
            return Err(PanelError::InvalidResponse(
                "服务端未确认密码修改".to_owned(),
            ));
        }
        let _guard = self.inner.session_gate.lock().await;
        self.clear_session_locked().await
    }

    async fn subscription_link(&self) -> Result<SubscriptionLink, PanelError> {
        let endpoint = self.endpoint("api/v1/users/subscription-url")?;
        let response: SubscriptionLinkDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        validate_subscription_link(&response.url)
    }

    async fn reset_subscription(&self) -> Result<(), PanelError> {
        let endpoint = self.endpoint("api/v1/users/subscription/reset")?;
        let _: UserDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        Ok(())
    }

    async fn balance_transactions(&self, limit: u8) -> Result<Vec<BalanceTransaction>, PanelError> {
        let endpoint = self.endpoint(&format!(
            "api/v1/users/balance-transactions?page=1&page_size={limit}"
        ))?;
        let response: BalanceTransactionsDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response
            .balance_transactions
            .into_iter()
            .map(BalanceTransactionDto::into_domain)
            .collect()
    }

    async fn orders(
        &self,
        filter: UserOrderFilter,
        page: u32,
        page_size: u8,
    ) -> Result<UserOrderPage, PanelError> {
        let status = match filter {
            UserOrderFilter::All => "",
            UserOrderFilter::Pending => "&status=pending",
            UserOrderFilter::Paid => "&status=paid",
            UserOrderFilter::Refunded => "&status=refunded",
        };
        let endpoint = self.endpoint(&format!(
            "api/v1/users/orders?page={page}&page_size={page_size}{status}"
        ))?;
        let response: UserOrdersDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain(page, page_size)
    }

    async fn support_tickets(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<SupportTicketPage, PanelError> {
        let endpoint = self.endpoint(&format!(
            "api/v1/users/tickets?page={page}&page_size={page_size}"
        ))?;
        let response: SupportTicketListDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain(page, page_size)
    }

    async fn support_ticket(
        &self,
        id: u64,
        message_page: u32,
        message_page_size: u8,
    ) -> Result<SupportTicketDetail, PanelError> {
        let endpoint = self.endpoint(&format!(
            "api/v1/users/tickets/{id}?message_page={message_page}&message_page_size={message_page_size}"
        ))?;
        let response: SupportTicketDetailDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain(message_page, message_page_size)
    }

    async fn create_support_ticket(
        &self,
        draft: &SupportTicketDraft,
    ) -> Result<SupportTicketDetail, PanelError> {
        let endpoint = self.endpoint("api/v1/users/tickets")?;
        let response: SupportTicketDetailDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&SupportTicketCreateRequestDto {
                        title: &draft.title,
                        priority: support_ticket_priority_value(draft.priority),
                        message: &draft.message,
                    })
            })
            .await?;
        response.into_domain(1, 10)
    }

    async fn reply_support_ticket(
        &self,
        id: u64,
        content: &str,
    ) -> Result<SupportTicketDetail, PanelError> {
        let endpoint = self.endpoint(&format!("api/v1/users/tickets/{id}/messages"))?;
        let response: SupportTicketDetailDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&SupportTicketMessageRequestDto { content })
            })
            .await?;
        response.into_domain(1, 10)
    }

    async fn close_support_ticket(&self, id: u64) -> Result<SupportTicketAction, PanelError> {
        let endpoint = self.endpoint(&format!("api/v1/users/tickets/{id}/close"))?;
        let response: SupportTicketActionDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain()
    }

    async fn gift_card_config(&self) -> Result<GiftCardConfig, PanelError> {
        let endpoint = self.endpoint("api/v1/users/gift-cards/config")?;
        let response: GiftCardConfigDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        Ok(GiftCardConfig {
            purchase_url: validate_gift_card_purchase_url(response.purchase_url)?,
        })
    }

    async fn check_gift_card(&self, code: &str) -> Result<GiftCardRedeemCheck, PanelError> {
        let endpoint = self.endpoint("api/v1/users/gift-cards/check")?;
        let response: GiftCardCheckDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&GiftCardCodeRequestDto { code })
            })
            .await?;
        Ok(GiftCardRedeemCheck {
            reward: response.reward_preview.into_domain()?,
            can_redeem: response.can_redeem,
            reason: response.reason,
        })
    }

    async fn redeem_gift_card(&self, code: &str) -> Result<GiftCardRewardPreview, PanelError> {
        let endpoint = self.endpoint("api/v1/users/gift-cards/redeem")?;
        let response: GiftCardRedeemDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&GiftCardCodeRequestDto { code })
            })
            .await?;
        response.reward_preview.into_domain()
    }

    async fn affiliate_summary(&self) -> Result<AffiliateSummary, PanelError> {
        let endpoint = self.endpoint("api/v1/user/affiliate/summary")?;
        let response: AffiliateSummaryDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain()
    }

    async fn affiliate_commissions(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<AffiliateCommissionPage, PanelError> {
        let endpoint = self.endpoint(&format!(
            "api/v1/user/affiliate/commissions?page={page}&page_size={page_size}"
        ))?;
        let response: AffiliateCommissionListDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain(page, page_size)
    }

    async fn affiliate_transfers(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<AffiliateTransferPage, PanelError> {
        let endpoint = self.endpoint(&format!(
            "api/v1/user/affiliate/transfers?page={page}&page_size={page_size}"
        ))?;
        let response: AffiliateTransferListDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        response.into_domain(page, page_size)
    }

    async fn resources(&self) -> Result<Vec<ServerGroup>, PanelError> {
        let endpoint = self.endpoint("api/v1/users/client/resources")?;
        let resources: ClientResourcesDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .bearer_auth(token)
            })
            .await?;
        resources.into_domain()
    }

    async fn shop_catalog(&self) -> Result<ShopCatalog, PanelError> {
        let plans_endpoint = self.endpoint("api/v1/users/shop/plans?page_size=100")?;
        let plans: ShopPlansDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(plans_endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .bearer_auth(token)
            })
            .await?;
        let methods_endpoint = self.endpoint("api/v1/users/payment-methods")?;
        let payment_methods: ShopPaymentMethodsDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(methods_endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .bearer_auth(token)
            })
            .await?;
        Ok(ShopCatalog {
            plans: plans
                .plans
                .into_iter()
                .map(ShopPlanDto::into_domain)
                .collect::<Result<_, _>>()?,
            payment_methods: payment_methods
                .payment_methods
                .into_iter()
                .map(ShopPaymentMethodDto::into_domain)
                .collect::<Result<_, _>>()?,
        })
    }

    async fn check_coupon(
        &self,
        selection: &ShopOrderSelection,
    ) -> Result<ShopCouponQuote, PanelError> {
        let request = ShopOrderSelectionRequestDto::from_selection(selection)?;
        if request.coupon_code.is_none() {
            return Err(PanelError::InvalidResponse("优惠码不能为空".to_owned()));
        }
        let endpoint = self.endpoint("api/v1/users/shop/coupons/check")?;
        let quote: ShopCouponQuoteDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&request)
            })
            .await?;
        quote.into_domain()
    }

    async fn create_order(&self, selection: &ShopOrderSelection) -> Result<ShopOrder, PanelError> {
        let request = ShopOrderSelectionRequestDto::from_selection(selection)?;
        let endpoint = self.endpoint("api/v1/users/orders")?;
        let order: ShopOrderDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&request)
            })
            .await?;
        order.into_domain()
    }

    async fn pay_order(
        &self,
        order_id: u64,
        payment: ShopPaymentChoice,
    ) -> Result<ShopOrder, PanelError> {
        if order_id == 0 {
            return Err(PanelError::InvalidResponse("订单标识无效".to_owned()));
        }
        let request = PayShopOrderRequestDto::from_payment(payment)?;
        let endpoint = self.endpoint(&format!("api/v1/users/orders/{order_id}/pay"))?;
        let order: ShopOrderDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
                    .json(&request)
            })
            .await?;
        order.into_domain()
    }

    async fn get_order(&self, order_id: u64) -> Result<ShopOrder, PanelError> {
        if order_id == 0 {
            return Err(PanelError::InvalidResponse("订单标识无效".to_owned()));
        }
        let endpoint = self.endpoint(&format!("api/v1/users/orders/{order_id}"))?;
        let order: ShopOrderDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .get(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .header("Cache-Control", "no-store")
                    .bearer_auth(token)
            })
            .await?;
        order.into_domain()
    }
}

#[async_trait]
impl ConfigurationSource for HttpPanelClient {
    async fn load(
        &self,
        request: &ConfigurationRequest,
    ) -> Result<ClientConfiguration, ConfigurationSourceError> {
        let group_id = request
            .group_id
            .parse::<u64>()
            .map_err(|_| ConfigurationSourceError::Invalid("服务器组 ID 无效".to_owned()))?;
        let endpoint = self
            .endpoint("api/v1/users/client/config")
            .map_err(configuration_error)?;
        let body = ClientConfigurationRequestDto {
            group_id,
            selected_endpoint_id: &request.selected_endpoint_id,
            route_mode: match request.preferences.route_mode {
                RouteMode::Rule => "rule",
                RouteMode::Global => "global",
            },
            bypass_mainland: request.preferences.bypass_mainland,
            bypass_lan: request.preferences.bypass_lan,
            ipv6: false,
            multiplex_enabled: request.preferences.multiplex_enabled,
            runtime_id: request.runtime_id.as_str(),
            supported_schema_versions: &request.supported_schema_versions,
        };
        let response: ClientConfigurationResponseDto = self
            .authenticated(|token| {
                self.inner
                    .client
                    .post(endpoint.clone())
                    .header("X-Request-ID", request_id())
                    .bearer_auth(token)
                    .header("Cache-Control", "no-store")
                    .json(&body)
            })
            .await
            .map_err(configuration_error)?;
        if response.runtime_id != request.runtime_id.as_str() {
            return Err(ConfigurationSourceError::Invalid(
                "服务端返回了非请求运行时".to_owned(),
            ));
        }
        if !request
            .supported_schema_versions
            .contains(&response.configuration_schema)
        {
            return Err(ConfigurationSourceError::Invalid(
                "服务端返回了客户端不支持的配置版本".to_owned(),
            ));
        }
        let runtime_id = topnode_domain::RuntimeId::new(response.runtime_id)
            .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))?;
        let expires_at = parse_epoch_seconds(&response.expires_at)
            .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))?;
        let payload = response.configuration.get().to_owned();
        ClientConfiguration::new(
            runtime_id,
            response.configuration_schema,
            response.revision,
            expires_at,
            response.selected_endpoint_id,
            payload,
        )
        .map_err(|error| ConfigurationSourceError::Invalid(error.to_string()))
    }
}

async fn send(request: reqwest::RequestBuilder) -> Result<Response, PanelError> {
    request
        .send()
        .await
        .map_err(|error| PanelError::Transport(error.to_string()))
}

async fn decode<T: DeserializeOwned>(mut response: Response) -> Result<T, PanelError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(PanelError::Unauthorized);
    }
    let header_request_id = response
        .headers()
        .get("X-Request-ID")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let bytes = read_bounded(&mut response, MAX_RESPONSE_BYTES).await?;
    decode_bytes(status, header_request_id, &bytes)
}

async fn read_bounded(
    response: &mut Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PanelError> {
    validate_content_length(response.content_length(), maximum_bytes)?;
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| PanelError::Transport(error.to_string()))?
    {
        append_bounded(&mut bytes, &chunk, maximum_bytes)?;
    }
    Ok(bytes)
}

fn validate_content_length(
    content_length: Option<u64>,
    maximum_bytes: usize,
) -> Result<(), PanelError> {
    if content_length
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > maximum_bytes))
    {
        return Err(response_too_large());
    }
    Ok(())
}

fn append_bounded(
    destination: &mut Vec<u8>,
    chunk: &[u8],
    maximum_bytes: usize,
) -> Result<(), PanelError> {
    if chunk.len() > maximum_bytes.saturating_sub(destination.len()) {
        return Err(response_too_large());
    }
    destination.extend_from_slice(chunk);
    Ok(())
}

fn response_too_large() -> PanelError {
    PanelError::InvalidResponse("响应体超过 8 MiB".to_owned())
}

fn decode_bytes<T: DeserializeOwned>(
    status: StatusCode,
    header_request_id: Option<String>,
    bytes: &[u8],
) -> Result<T, PanelError> {
    if status == StatusCode::UNAUTHORIZED {
        if let Ok(envelope) = serde_json::from_slice::<ApiErrorEnvelope>(bytes)
            && envelope.code == Some(403_001)
        {
            return Err(PanelError::Business {
                code: 403_001,
                message: envelope.message,
                request_id: envelope.request_id.or(header_request_id),
            });
        }
        return Err(PanelError::Unauthorized);
    }
    if !status.is_success() {
        let envelope = serde_json::from_slice::<ApiErrorEnvelope>(bytes).ok();
        return Err(http_status_error(
            status,
            envelope.as_ref(),
            header_request_id.as_deref(),
        ));
    }
    let envelope: ApiEnvelope<T> = serde_json::from_slice(bytes)
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))?;
    if envelope.code != SUCCESS_CODE {
        return Err(PanelError::Business {
            code: envelope.code,
            message: envelope.message,
            request_id: envelope.request_id.or(header_request_id),
        });
    }
    envelope
        .data
        .ok_or_else(|| PanelError::InvalidResponse("成功响应缺少 data".to_owned()))
}

fn session_authentication_error(error: &PanelError) -> PanelError {
    match error {
        PanelError::Business { code: 403_001, .. } => error.clone(),
        _ => PanelError::Unauthorized,
    }
}

fn http_status_error(
    status: StatusCode,
    envelope: Option<&ApiErrorEnvelope>,
    header_request_id: Option<&str>,
) -> PanelError {
    let mut details = format!("HTTP {status}");
    if let Some(code) = envelope.and_then(|value| value.code) {
        write!(&mut details, "，业务码 {code}").expect("writing to String cannot fail");
    }
    if let Some(message) = envelope
        .map(|value| value.message.trim())
        .filter(|message| !message.is_empty())
    {
        write!(&mut details, "：{message}").expect("writing to String cannot fail");
    }
    if let Some(request_id) = envelope
        .and_then(|value| value.request_id.as_deref())
        .or(header_request_id)
    {
        write!(&mut details, "（request_id: {request_id}）")
            .expect("writing to String cannot fail");
    }
    PanelError::Transport(details)
}

fn finish_logout(
    local_result: Result<(), PanelError>,
    remote_result: Result<(), PanelError>,
) -> Result<(), PanelError> {
    match (local_result, remote_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(local_error), Ok(())) => Err(local_error),
        (Ok(()), Err(remote_error)) => Err(remote_error),
        (Err(local_error), Err(remote_error)) => {
            tracing::error!(%local_error, %remote_error, "local and remote logout both failed");
            Err(local_error)
        }
    }
}

fn configuration_error(error: PanelError) -> ConfigurationSourceError {
    match error {
        PanelError::Unauthorized | PanelError::NoSession => ConfigurationSourceError::Unauthorized,
        PanelError::InvalidResponse(message) => ConfigurationSourceError::Invalid(message),
        error @ PanelError::Business { .. } => {
            ConfigurationSourceError::Rejected(error.user_message().to_owned())
        }
        other => ConfigurationSourceError::Read(other.to_string()),
    }
}

fn parse_epoch_seconds(value: &str) -> Result<u64, PanelError> {
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))?
        .unix_timestamp();
    u64::try_from(timestamp)
        .map_err(|_| PanelError::InvalidResponse("时间戳早于 Unix epoch".to_owned()))
}

fn parse_money_cents(value: &str) -> Result<i64, PanelError> {
    let value = value.trim();
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 2
    {
        return Err(PanelError::InvalidResponse("账户余额格式无效".to_owned()));
    }
    let whole = whole
        .parse::<i64>()
        .map_err(|_| PanelError::InvalidResponse("账户余额超出范围".to_owned()))?;
    let fraction = match fraction.len() {
        0 => 0,
        1 => {
            fraction
                .parse::<i64>()
                .map_err(|_| PanelError::InvalidResponse("账户余额格式无效".to_owned()))?
                * 10
        }
        2 => fraction
            .parse::<i64>()
            .map_err(|_| PanelError::InvalidResponse("账户余额格式无效".to_owned()))?,
        _ => unreachable!("fraction length was validated"),
    };
    let cents = whole
        .checked_mul(100)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| PanelError::InvalidResponse("账户余额超出范围".to_owned()))?;
    Ok(if negative { -cents } else { cents })
}

fn validate_pay_url(value: String) -> Result<String, PanelError> {
    let url =
        Url::parse(&value).map_err(|_| PanelError::InvalidResponse("支付链接无效".to_owned()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PanelError::InvalidResponse("支付链接无效".to_owned()));
    }
    Ok(value)
}

fn validate_gift_card_purchase_url(value: String) -> Result<String, PanelError> {
    if value.trim().is_empty() {
        return Ok(String::new());
    }
    let url = Url::parse(&value)
        .map_err(|_| PanelError::InvalidResponse("礼品卡购买链接无效".to_owned()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PanelError::InvalidResponse("礼品卡购买链接无效".to_owned()));
    }
    Ok(value)
}

fn validate_subscription_link(value: &str) -> Result<SubscriptionLink, PanelError> {
    let value = value.trim();
    let parsed = Url::parse(value)
        .map_err(|_| PanelError::InvalidResponse("订阅链接地址无效".to_owned()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(PanelError::InvalidResponse("订阅链接地址无效".to_owned()));
    }
    SubscriptionLink::new(value)
        .ok_or_else(|| PanelError::InvalidResponse("订阅链接地址无效".to_owned()))
}

fn epoch_seconds() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default()
}

fn request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[derive(Deserialize)]
struct ApiEnvelope<T> {
    code: i64,
    #[serde(default)]
    message: String,
    data: Option<T>,
    request_id: Option<String>,
}

#[derive(Deserialize)]
struct ApiErrorEnvelope {
    code: Option<i64>,
    #[serde(default)]
    message: String,
    request_id: Option<String>,
}

#[derive(Serialize)]
struct LoginRequestDto<'a> {
    email: &'a str,
    password: &'a str,
    device_id: &'a str,
    device_name: &'a str,
    platform: &'a str,
}

#[derive(Deserialize)]
struct LoginResponseDto {
    access_token: String,
    expires_at: String,
    session_id: String,
    refresh_token: String,
    refresh_expires_at: String,
    user: UserDto,
}

impl LoginResponseDto {
    fn into_session(self) -> Result<UserSession, PanelError> {
        Ok(UserSession {
            user: self.user.into_domain()?,
            tokens: SessionTokens::new(
                self.session_id,
                self.access_token,
                parse_epoch_seconds(&self.expires_at)?,
                self.refresh_token,
                parse_epoch_seconds(&self.refresh_expires_at)?,
            )
            .map_err(|error| PanelError::InvalidResponse(error.to_string()))?,
        })
    }
}

#[derive(Deserialize)]
struct UserDto {
    id: u64,
    #[serde(default)]
    uuid: String,
    username: String,
    email: String,
    #[serde(default = "default_balance")]
    balance: String,
}

#[derive(Serialize)]
struct ChangePasswordRequestDto<'a> {
    current_password: &'a str,
    new_password: &'a str,
}

#[derive(Deserialize)]
struct UserActionDto {
    ok: bool,
}

#[derive(Deserialize)]
struct SubscriptionLinkDto {
    url: String,
}

#[derive(Deserialize)]
struct GiftCardConfigDto {
    #[serde(default)]
    purchase_url: String,
}

#[derive(Serialize)]
struct GiftCardCodeRequestDto<'a> {
    code: &'a str,
}

#[derive(Deserialize)]
struct GiftCardCheckDto {
    reward_preview: GiftCardRewardPreviewDto,
    #[serde(default)]
    can_redeem: bool,
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
struct GiftCardRedeemDto {
    reward_preview: GiftCardRewardPreviewDto,
}

#[derive(Deserialize)]
struct GiftCardRewardPreviewDto {
    #[serde(rename = "type")]
    reward_type: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    balance_amount_cents: i64,
    plan_id: Option<u64>,
    #[serde(default)]
    plan_name: String,
    plan_price_id: Option<u64>,
    #[serde(default)]
    price_label: String,
    group_id: Option<u64>,
    #[serde(default)]
    group_name: String,
    #[serde(default)]
    traffic_quota_bytes: i64,
}

impl GiftCardRewardPreviewDto {
    fn into_domain(self) -> Result<GiftCardRewardPreview, PanelError> {
        if self.balance_amount_cents < 0 || self.traffic_quota_bytes < 0 {
            return Err(PanelError::InvalidResponse("礼品卡权益字段无效".to_owned()));
        }
        Ok(GiftCardRewardPreview {
            reward_type: match self.reward_type.trim().to_ascii_lowercase().as_str() {
                "balance" => GiftCardRewardType::Balance,
                "plan" => GiftCardRewardType::Plan,
                "traffic" => GiftCardRewardType::Traffic,
                _ => GiftCardRewardType::Unknown,
            },
            summary: self.summary,
            balance_amount_cents: self.balance_amount_cents,
            plan_id: self.plan_id.filter(|id| *id > 0),
            plan_name: self.plan_name,
            plan_price_id: self.plan_price_id.filter(|id| *id > 0),
            price_label: self.price_label,
            group_id: self.group_id.filter(|id| *id > 0),
            group_name: self.group_name,
            traffic_quota_bytes: self.traffic_quota_bytes,
        })
    }
}

#[derive(Deserialize)]
struct AffiliateSummaryDto {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    rebate_type: String,
    #[serde(default)]
    effective_rate_bps: i32,
    #[serde(default)]
    total_commission_cents: i64,
    #[serde(default)]
    available_commission_cents: i64,
    #[serde(default)]
    cooling_commission_cents: i64,
    #[serde(default)]
    transferred_commission_cents: i64,
    #[serde(default)]
    invitation_count: u64,
    #[serde(default)]
    affiliate_code: String,
    #[serde(default)]
    invitation_url: String,
}

impl AffiliateSummaryDto {
    fn into_domain(self) -> Result<AffiliateSummary, PanelError> {
        if self.effective_rate_bps < 0
            || self.effective_rate_bps > 10_000
            || self.total_commission_cents < 0
            || self.available_commission_cents < 0
            || self.cooling_commission_cents < 0
            || self.transferred_commission_cents < 0
            || self.affiliate_code.chars().any(char::is_control)
            || self.invitation_url.chars().any(char::is_control)
        {
            return Err(PanelError::InvalidResponse("邀请概览字段无效".to_owned()));
        }
        Ok(AffiliateSummary {
            enabled: self.enabled,
            rebate_type: parse_affiliate_rebate_type(&self.rebate_type),
            effective_rate_bps: self.effective_rate_bps,
            total_commission_cents: self.total_commission_cents,
            available_commission_cents: self.available_commission_cents,
            cooling_commission_cents: self.cooling_commission_cents,
            transferred_commission_cents: self.transferred_commission_cents,
            invitation_count: self.invitation_count,
            affiliate_code: self.affiliate_code,
            invitation_url: self.invitation_url,
        })
    }
}

#[derive(Deserialize)]
struct AffiliateCommissionListDto {
    #[serde(default)]
    commissions: Vec<AffiliateCommissionDto>,
    #[serde(default)]
    pagination: PaginationDto,
}

#[derive(Deserialize)]
struct AffiliateCommissionDto {
    id: u64,
    #[serde(default)]
    invitee: String,
    #[serde(default)]
    order_number: String,
    #[serde(default)]
    rebate_type: String,
    #[serde(default)]
    rate_bps: i32,
    #[serde(default)]
    base_amount_cents: i64,
    #[serde(default)]
    commission_cents: i64,
    #[serde(default)]
    status: String,
    available_at: Option<String>,
    released_at: Option<String>,
    reversed_at: Option<String>,
    #[serde(default)]
    reversed_deducted_cents: i64,
    created_at: String,
}

impl AffiliateCommissionListDto {
    fn into_domain(
        self,
        requested_page: u32,
        requested_page_size: u8,
    ) -> Result<AffiliateCommissionPage, PanelError> {
        Ok(AffiliateCommissionPage {
            commissions: self
                .commissions
                .into_iter()
                .map(AffiliateCommissionDto::into_domain)
                .collect::<Result<_, _>>()?,
            page: nonzero_page(self.pagination.page, requested_page),
            page_size: nonzero_page_size(self.pagination.page_size, requested_page_size),
            total: self.pagination.total,
        })
    }
}

impl AffiliateCommissionDto {
    fn into_domain(self) -> Result<AffiliateCommission, PanelError> {
        if self.id == 0
            || self.rate_bps < 0
            || self.rate_bps > 10_000
            || self.base_amount_cents < 0
            || self.commission_cents < 0
            || self.reversed_deducted_cents < 0
            || self.invitee.chars().any(char::is_control)
            || self.order_number.chars().any(char::is_control)
        {
            return Err(PanelError::InvalidResponse("返佣记录字段无效".to_owned()));
        }
        Ok(AffiliateCommission {
            id: self.id,
            invitee: self.invitee,
            order_number: self.order_number,
            rebate_type: parse_affiliate_rebate_type(&self.rebate_type),
            rate_bps: self.rate_bps,
            base_amount_cents: self.base_amount_cents,
            commission_cents: self.commission_cents,
            status: match self.status.trim().to_ascii_lowercase().as_str() {
                "cooling" => AffiliateCommissionStatus::Cooling,
                "unlocked" => AffiliateCommissionStatus::Unlocked,
                "reversed" => AffiliateCommissionStatus::Reversed,
                _ => AffiliateCommissionStatus::Unknown,
            },
            available_at_epoch_seconds: parse_optional_affiliate_time(
                self.available_at.as_deref(),
            )?,
            released_at_epoch_seconds: parse_optional_affiliate_time(self.released_at.as_deref())?,
            reversed_at_epoch_seconds: parse_optional_affiliate_time(self.reversed_at.as_deref())?,
            reversed_deducted_cents: self.reversed_deducted_cents,
            created_at_epoch_seconds: parse_affiliate_time(&self.created_at)?,
        })
    }
}

#[derive(Deserialize)]
struct AffiliateTransferListDto {
    #[serde(default)]
    transfers: Vec<AffiliateTransferDto>,
    #[serde(default)]
    pagination: PaginationDto,
}

#[derive(Deserialize)]
struct AffiliateTransferDto {
    id: u64,
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    amount_cents: i64,
    #[serde(default)]
    balance_after_cents: i64,
    created_at: String,
}

impl AffiliateTransferListDto {
    fn into_domain(
        self,
        requested_page: u32,
        requested_page_size: u8,
    ) -> Result<AffiliateTransferPage, PanelError> {
        Ok(AffiliateTransferPage {
            transfers: self
                .transfers
                .into_iter()
                .map(AffiliateTransferDto::into_domain)
                .collect::<Result<_, _>>()?,
            page: nonzero_page(self.pagination.page, requested_page),
            page_size: nonzero_page_size(self.pagination.page_size, requested_page_size),
            total: self.pagination.total,
        })
    }
}

impl AffiliateTransferDto {
    fn into_domain(self) -> Result<AffiliateTransfer, PanelError> {
        if self.id == 0
            || self.amount_cents < 0
            || self.balance_after_cents < 0
            || self.request_id.chars().any(char::is_control)
        {
            return Err(PanelError::InvalidResponse(
                "佣金划转记录字段无效".to_owned(),
            ));
        }
        Ok(AffiliateTransfer {
            id: self.id,
            request_id: self.request_id,
            amount_cents: self.amount_cents,
            balance_after_cents: self.balance_after_cents,
            created_at_epoch_seconds: parse_affiliate_time(&self.created_at)?,
        })
    }
}

fn parse_affiliate_rebate_type(value: &str) -> AffiliateRebateType {
    match value.trim().to_ascii_lowercase().as_str() {
        "first" => AffiliateRebateType::First,
        "recurring" => AffiliateRebateType::Recurring,
        _ => AffiliateRebateType::Unknown,
    }
}

fn parse_affiliate_time(value: &str) -> Result<i64, PanelError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))
}

fn parse_optional_affiliate_time(value: Option<&str>) -> Result<Option<i64>, PanelError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(parse_affiliate_time)
        .transpose()
}

const fn nonzero_page(value: u32, fallback: u32) -> u32 {
    if value == 0 { fallback } else { value }
}

const fn nonzero_page_size(value: u8, fallback: u8) -> u8 {
    if value == 0 { fallback } else { value }
}

#[derive(Deserialize)]
struct BalanceTransactionsDto {
    #[serde(default)]
    balance_transactions: Vec<BalanceTransactionDto>,
}

#[derive(Deserialize)]
struct BalanceTransactionDto {
    id: u64,
    #[serde(rename = "type")]
    transaction_type: String,
    #[serde(default)]
    description: String,
    amount_cents: i64,
    balance_before_cents: i64,
    balance_after_cents: i64,
    reference_id: Option<u64>,
    created_at: String,
}

impl BalanceTransactionDto {
    fn into_domain(self) -> Result<BalanceTransaction, PanelError> {
        if self.id == 0 || self.created_at.trim().is_empty() {
            return Err(PanelError::InvalidResponse("余额明细字段无效".to_owned()));
        }
        let created_at_epoch_seconds = OffsetDateTime::parse(&self.created_at, &Rfc3339)
            .map_err(|error| PanelError::InvalidResponse(error.to_string()))?
            .unix_timestamp();
        let transaction_type = match self.transaction_type.trim().to_ascii_lowercase().as_str() {
            "order_payment" => BalanceTransactionType::OrderPayment,
            "order_refund" => BalanceTransactionType::OrderRefund,
            "gift_card" => BalanceTransactionType::GiftCard,
            "affiliate_transfer" => BalanceTransactionType::AffiliateTransfer,
            "admin_adjustment" => BalanceTransactionType::AdminAdjustment,
            _ => BalanceTransactionType::Unknown,
        };
        Ok(BalanceTransaction {
            id: self.id,
            transaction_type,
            description: self.description,
            amount_cents: self.amount_cents,
            balance_before_cents: self.balance_before_cents,
            balance_after_cents: self.balance_after_cents,
            reference_id: self.reference_id.filter(|id| *id > 0),
            created_at_epoch_seconds,
        })
    }
}

#[derive(Deserialize)]
struct UserOrdersDto {
    #[serde(default)]
    orders: Vec<UserOrderDto>,
    #[serde(default)]
    pagination: PaginationDto,
}

#[derive(Deserialize)]
struct UserOrderDto {
    id: u64,
    order_number: String,
    #[serde(rename = "type")]
    order_type: String,
    #[serde(default)]
    source: String,
    item: UserOrderItemDto,
    amount_cents: i64,
    #[serde(default = "default_currency")]
    currency: String,
    status: String,
    #[serde(default)]
    can_pay: bool,
    payment_method: Option<UserOrderPaymentMethodDto>,
    paid_at: Option<String>,
    refunded_at: Option<String>,
    #[serde(default)]
    balance_refunded_cents: i64,
    entitlements_rolled_back_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct UserOrderItemDto {
    id: u64,
    item_type: String,
    plan_id: Option<u64>,
    #[serde(default)]
    plan_name: String,
    plan_price_id: Option<u64>,
    #[serde(default)]
    price_label: String,
    #[serde(default)]
    period_unit: String,
    #[serde(default)]
    period_count: u32,
    traffic_addon_id: Option<u64>,
    #[serde(default)]
    traffic_addon_name: String,
    #[serde(default)]
    traffic_quota_bytes: i64,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct UserOrderPaymentMethodDto {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    provider_name: String,
    #[serde(default)]
    payment_type: String,
    #[serde(default)]
    payment_type_name: String,
}

#[derive(Default, Deserialize)]
struct PaginationDto {
    page: u32,
    page_size: u8,
    total: u64,
}

#[derive(Deserialize)]
struct SupportTicketListDto {
    #[serde(default)]
    tickets: Vec<SupportTicketDto>,
    #[serde(default)]
    pagination: PaginationDto,
}

#[derive(Deserialize)]
struct SupportTicketDto {
    id: u64,
    ticket_number: String,
    title: String,
    priority: String,
    status: String,
    #[serde(default)]
    has_unread_reply: bool,
    last_admin_reply_at: Option<String>,
    closed_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct SupportTicketDetailDto {
    id: u64,
    ticket_number: String,
    title: String,
    priority: String,
    status: String,
    #[serde(default)]
    messages: Vec<SupportTicketMessageDto>,
    #[serde(default)]
    message_pagination: PaginationDto,
    #[serde(default)]
    has_unread_reply: bool,
    last_admin_reply_at: Option<String>,
    closed_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct SupportTicketMessageDto {
    id: u64,
    sender_role: String,
    sender: Option<SupportTicketSenderDto>,
    content: String,
    created_at: String,
}

#[derive(Default, Deserialize)]
struct SupportTicketSenderDto {
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
}

#[derive(Serialize)]
struct SupportTicketCreateRequestDto<'a> {
    title: &'a str,
    priority: &'static str,
    message: &'a str,
}

#[derive(Serialize)]
struct SupportTicketMessageRequestDto<'a> {
    content: &'a str,
}

#[derive(Deserialize)]
struct SupportTicketActionDto {
    id: u64,
    ticket_number: String,
    status: String,
}

impl SupportTicketListDto {
    fn into_domain(
        self,
        requested_page: u32,
        requested_page_size: u8,
    ) -> Result<SupportTicketPage, PanelError> {
        let tickets = self
            .tickets
            .into_iter()
            .map(SupportTicketDto::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SupportTicketPage {
            tickets,
            page: nonzero_page(self.pagination.page, requested_page),
            page_size: nonzero_page_size(self.pagination.page_size, requested_page_size),
            total: self.pagination.total,
        })
    }
}

impl SupportTicketDto {
    fn into_domain(self) -> Result<SupportTicket, PanelError> {
        support_ticket_from_parts(
            self.id,
            self.ticket_number,
            self.title,
            &self.priority,
            &self.status,
            self.has_unread_reply,
            self.last_admin_reply_at.as_deref(),
            self.closed_at.as_deref(),
            &self.created_at,
            &self.updated_at,
        )
    }
}

impl SupportTicketDetailDto {
    fn into_domain(
        self,
        requested_page: u32,
        requested_page_size: u8,
    ) -> Result<SupportTicketDetail, PanelError> {
        let ticket = support_ticket_from_parts(
            self.id,
            self.ticket_number,
            self.title,
            &self.priority,
            &self.status,
            self.has_unread_reply,
            self.last_admin_reply_at.as_deref(),
            self.closed_at.as_deref(),
            &self.created_at,
            &self.updated_at,
        )?;
        let mut messages = self
            .messages
            .into_iter()
            .map(SupportTicketMessageDto::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        messages.sort_by_key(|message| (message.created_at_epoch_seconds, message.id));
        Ok(SupportTicketDetail {
            ticket,
            messages,
            message_page: nonzero_page(self.message_pagination.page, requested_page),
            message_page_size: nonzero_page_size(
                self.message_pagination.page_size,
                requested_page_size,
            ),
            message_total: self.message_pagination.total,
        })
    }
}

impl SupportTicketMessageDto {
    fn into_domain(self) -> Result<SupportTicketMessage, PanelError> {
        if self.id == 0 || self.content.trim().is_empty() || self.content.len() > 64 * 1_024 {
            return Err(PanelError::InvalidResponse("工单消息字段无效".to_owned()));
        }
        let sender_role = parse_support_ticket_sender_role(&self.sender_role);
        let sender = if sender_role == SupportTicketSenderRole::Admin {
            SupportTicketSenderDto {
                username: "客服01".to_owned(),
                email: String::new(),
            }
        } else {
            self.sender.unwrap_or_default()
        };
        Ok(SupportTicketMessage {
            id: self.id,
            sender_role,
            sender_name: sender.username,
            sender_email: sender.email,
            content: self.content,
            created_at_epoch_seconds: parse_support_ticket_time(&self.created_at)?,
        })
    }
}

impl SupportTicketActionDto {
    fn into_domain(self) -> Result<SupportTicketAction, PanelError> {
        if self.id == 0 || self.ticket_number.trim().is_empty() {
            return Err(PanelError::InvalidResponse("工单操作响应无效".to_owned()));
        }
        Ok(SupportTicketAction {
            id: self.id,
            ticket_number: self.ticket_number,
            status: parse_support_ticket_status(&self.status),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn support_ticket_from_parts(
    id: u64,
    ticket_number: String,
    title: String,
    priority: &str,
    status: &str,
    has_unread_reply: bool,
    last_admin_reply_at: Option<&str>,
    closed_at: Option<&str>,
    created_at: &str,
    updated_at: &str,
) -> Result<SupportTicket, PanelError> {
    if id == 0 || ticket_number.trim().is_empty() || title.trim().is_empty() {
        return Err(PanelError::InvalidResponse("工单字段无效".to_owned()));
    }
    Ok(SupportTicket {
        id,
        ticket_number,
        title,
        priority: parse_support_ticket_priority(priority),
        status: parse_support_ticket_status(status),
        has_unread_reply,
        last_admin_reply_at_epoch_seconds: parse_optional_support_ticket_time(last_admin_reply_at)?,
        closed_at_epoch_seconds: parse_optional_support_ticket_time(closed_at)?,
        created_at_epoch_seconds: parse_support_ticket_time(created_at)?,
        updated_at_epoch_seconds: parse_support_ticket_time(updated_at)?,
    })
}

const fn support_ticket_priority_value(value: SupportTicketPriority) -> &'static str {
    match value {
        SupportTicketPriority::Low => "low",
        SupportTicketPriority::Medium | SupportTicketPriority::Unknown => "medium",
        SupportTicketPriority::High => "high",
    }
}

fn parse_support_ticket_priority(value: &str) -> SupportTicketPriority {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => SupportTicketPriority::Low,
        "medium" => SupportTicketPriority::Medium,
        "high" => SupportTicketPriority::High,
        _ => SupportTicketPriority::Unknown,
    }
}

fn parse_support_ticket_status(value: &str) -> SupportTicketStatus {
    match value.trim().to_ascii_lowercase().as_str() {
        "pending_reply" => SupportTicketStatus::PendingReply,
        "replied" => SupportTicketStatus::Replied,
        "closed" => SupportTicketStatus::Closed,
        _ => SupportTicketStatus::Unknown,
    }
}

fn parse_support_ticket_sender_role(value: &str) -> SupportTicketSenderRole {
    match value.trim().to_ascii_lowercase().as_str() {
        "user" => SupportTicketSenderRole::User,
        "admin" => SupportTicketSenderRole::Admin,
        _ => SupportTicketSenderRole::Unknown,
    }
}

fn parse_support_ticket_time(value: &str) -> Result<i64, PanelError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))
}

fn parse_optional_support_ticket_time(value: Option<&str>) -> Result<Option<i64>, PanelError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(parse_support_ticket_time)
        .transpose()
}

impl UserOrdersDto {
    fn into_domain(
        self,
        requested_page: u32,
        requested_page_size: u8,
    ) -> Result<UserOrderPage, PanelError> {
        let orders = self
            .orders
            .into_iter()
            .map(UserOrderDto::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(UserOrderPage {
            orders,
            page: if self.pagination.page > 0 {
                self.pagination.page
            } else {
                requested_page
            },
            page_size: if self.pagination.page_size > 0 {
                self.pagination.page_size
            } else {
                requested_page_size
            },
            total: self.pagination.total,
        })
    }
}

impl UserOrderDto {
    fn into_domain(self) -> Result<UserOrder, PanelError> {
        if self.id == 0
            || self.order_number.trim().is_empty()
            || self.created_at.trim().is_empty()
            || self.updated_at.trim().is_empty()
        {
            return Err(PanelError::InvalidResponse("订单字段无效".to_owned()));
        }
        Ok(UserOrder {
            id: self.id,
            order_number: self.order_number,
            order_type: parse_user_order_type(&self.order_type),
            source: match self.source.trim().to_ascii_lowercase().as_str() {
                "user" => UserOrderSource::User,
                "admin" => UserOrderSource::Admin,
                _ => UserOrderSource::Unknown,
            },
            item: self.item.into_domain(),
            amount_cents: self.amount_cents,
            currency: self.currency,
            status: match self.status.trim().to_ascii_lowercase().as_str() {
                "pending" => UserOrderStatus::Pending,
                "paid" => UserOrderStatus::Paid,
                "refunded" => UserOrderStatus::Refunded,
                _ => UserOrderStatus::Unknown,
            },
            can_pay: self.can_pay,
            payment_method: self
                .payment_method
                .map(UserOrderPaymentMethodDto::into_domain),
            paid_at_epoch_seconds: parse_optional_order_time(self.paid_at.as_deref())?,
            refunded_at_epoch_seconds: parse_optional_order_time(self.refunded_at.as_deref())?,
            balance_refunded_cents: self.balance_refunded_cents,
            entitlements_rolled_back_at_epoch_seconds: parse_optional_order_time(
                self.entitlements_rolled_back_at.as_deref(),
            )?,
            created_at_epoch_seconds: parse_order_time(&self.created_at)?,
            updated_at_epoch_seconds: parse_order_time(&self.updated_at)?,
        })
    }
}

impl UserOrderItemDto {
    fn into_domain(self) -> UserOrderItem {
        UserOrderItem {
            id: self.id,
            order_type: parse_user_order_type(&self.item_type),
            plan_id: self.plan_id.filter(|id| *id > 0),
            plan_name: self.plan_name,
            plan_price_id: self.plan_price_id.filter(|id| *id > 0),
            price_label: self.price_label,
            period_unit: self.period_unit,
            period_count: self.period_count,
            traffic_addon_id: self.traffic_addon_id.filter(|id| *id > 0),
            traffic_addon_name: self.traffic_addon_name,
            traffic_quota_bytes: self.traffic_quota_bytes,
            description: self.description,
        }
    }
}

impl UserOrderPaymentMethodDto {
    fn into_domain(self) -> UserOrderPaymentMethod {
        UserOrderPaymentMethod {
            id: self.id,
            name: self.name,
            provider: self.provider,
            provider_name: self.provider_name,
            payment_type: self.payment_type,
            payment_type_name: self.payment_type_name,
        }
    }
}

fn parse_user_order_type(value: &str) -> UserOrderType {
    match value.trim().to_ascii_lowercase().as_str() {
        "base_plan" => UserOrderType::BasePlan,
        "traffic_addon" => UserOrderType::TrafficAddon,
        _ => UserOrderType::Unknown,
    }
}

fn parse_order_time(value: &str) -> Result<i64, PanelError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))
}

fn parse_optional_order_time(value: Option<&str>) -> Result<Option<i64>, PanelError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(parse_order_time)
        .transpose()
}

impl UserDto {
    fn into_domain(self) -> Result<UserIdentity, PanelError> {
        Ok(UserIdentity {
            id: self.id,
            uuid: self.uuid,
            username: self.username,
            email: self.email,
            balance_cents: parse_money_cents(&self.balance)?,
        })
    }
}

fn default_balance() -> String {
    "0.00".to_owned()
}

#[derive(Deserialize)]
struct ShopPlansDto {
    #[serde(default)]
    plans: Vec<ShopPlanDto>,
}

#[derive(Deserialize)]
struct ShopPlanDto {
    id: u64,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    group_name: String,
    #[serde(default)]
    addon_available: bool,
    #[serde(default)]
    prices: Vec<ShopPlanPriceDto>,
    #[serde(default)]
    traffic_addons: Vec<ShopTrafficAddonDto>,
}

impl ShopPlanDto {
    fn into_domain(self) -> Result<ShopPlan, PanelError> {
        if self.id == 0 || self.name.trim().is_empty() {
            return Err(PanelError::InvalidResponse("商城套餐字段无效".to_owned()));
        }
        Ok(ShopPlan {
            id: self.id,
            name: self.name,
            description: self.description,
            group_name: self.group_name,
            addon_available: self.addon_available,
            prices: self
                .prices
                .into_iter()
                .map(ShopPlanPriceDto::into_domain)
                .collect::<Result<_, _>>()?,
            traffic_addons: self
                .traffic_addons
                .into_iter()
                .map(ShopTrafficAddonDto::into_domain)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Deserialize)]
struct ShopPlanPriceDto {
    id: u64,
    label: String,
    #[serde(default)]
    period_unit: String,
    #[serde(default)]
    period_count: i64,
    price_cents: i64,
    #[serde(default = "default_currency")]
    currency: String,
    included_traffic_quota_bytes: i64,
}

impl ShopPlanPriceDto {
    fn into_domain(self) -> Result<ShopPlanPrice, PanelError> {
        if self.id == 0
            || self.period_count < 0
            || self.price_cents < 0
            || self.included_traffic_quota_bytes < 0
        {
            return Err(PanelError::InvalidResponse(
                "商城套餐规格字段无效".to_owned(),
            ));
        }
        Ok(ShopPlanPrice {
            id: self.id,
            label: self.label,
            period_unit: self.period_unit,
            period_count: u32::try_from(self.period_count)
                .map_err(|_| PanelError::InvalidResponse("套餐周期超出范围".to_owned()))?,
            price_cents: self.price_cents,
            currency: self.currency,
            included_traffic_bytes: self.included_traffic_quota_bytes,
        })
    }
}

#[derive(Deserialize)]
struct ShopTrafficAddonDto {
    id: u64,
    name: String,
    traffic_quota_bytes: i64,
    price_cents: i64,
    #[serde(default = "default_currency")]
    currency: String,
}

impl ShopTrafficAddonDto {
    fn into_domain(self) -> Result<ShopTrafficAddon, PanelError> {
        if self.id == 0 || self.traffic_quota_bytes < 0 || self.price_cents < 0 {
            return Err(PanelError::InvalidResponse("商城流量包字段无效".to_owned()));
        }
        Ok(ShopTrafficAddon {
            id: self.id,
            name: self.name,
            traffic_bytes: self.traffic_quota_bytes,
            price_cents: self.price_cents,
            currency: self.currency,
        })
    }
}

#[derive(Deserialize)]
struct ShopPaymentMethodsDto {
    #[serde(default)]
    payment_methods: Vec<ShopPaymentMethodDto>,
}

#[derive(Deserialize)]
struct ShopPaymentMethodDto {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    icon_url: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    provider_name: String,
    #[serde(default)]
    payment_type: String,
    #[serde(default)]
    payment_type_name: String,
}

impl ShopPaymentMethodDto {
    fn into_domain(self) -> Result<ShopPaymentMethod, PanelError> {
        if self.id == 0 || self.provider.trim().is_empty() || self.payment_type.trim().is_empty() {
            return Err(PanelError::InvalidResponse(
                "商城支付方式字段无效".to_owned(),
            ));
        }
        Ok(ShopPaymentMethod {
            id: self.id,
            name: self.name,
            icon_url: (!self.icon_url.trim().is_empty()).then_some(self.icon_url),
            provider: self.provider,
            provider_name: self.provider_name,
            payment_type: self.payment_type,
            payment_type_name: self.payment_type_name,
        })
    }
}

#[derive(Serialize)]
struct ShopOrderSelectionRequestDto<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    plan_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_price_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    traffic_addon_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coupon_code: Option<&'a str>,
}

impl<'a> ShopOrderSelectionRequestDto<'a> {
    fn from_selection(selection: &'a ShopOrderSelection) -> Result<Self, PanelError> {
        if selection.plan_id == 0 || selection.product_id == 0 {
            return Err(PanelError::InvalidResponse("购买商品标识无效".to_owned()));
        }
        let coupon_code = selection
            .coupon_code
            .as_deref()
            .filter(|code| !code.trim().is_empty());
        Ok(Self {
            kind: match selection.kind {
                ShopPurchaseKind::BasePlan => "base_plan",
                ShopPurchaseKind::TrafficAddon => "traffic_addon",
            },
            plan_id: selection.plan_id,
            plan_price_id: (selection.kind == ShopPurchaseKind::BasePlan)
                .then_some(selection.product_id),
            traffic_addon_id: (selection.kind == ShopPurchaseKind::TrafficAddon)
                .then_some(selection.product_id),
            coupon_code,
        })
    }
}

#[derive(Serialize)]
struct PayShopOrderRequestDto<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_method_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_channel: Option<&'a str>,
    #[serde(skip_serializing_if = "is_false")]
    use_balance: bool,
}

impl PayShopOrderRequestDto<'static> {
    fn from_payment(payment: ShopPaymentChoice) -> Result<Self, PanelError> {
        match payment {
            ShopPaymentChoice::Balance => Ok(Self {
                payment_method_id: None,
                payment_channel: Some("balance"),
                use_balance: true,
            }),
            ShopPaymentChoice::Provider(payment_method_id) if payment_method_id > 0 => Ok(Self {
                payment_method_id: Some(payment_method_id),
                payment_channel: None,
                use_balance: false,
            }),
            ShopPaymentChoice::Provider(_) => {
                Err(PanelError::InvalidResponse("支付方式标识无效".to_owned()))
            }
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip callback takes a reference.
const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Deserialize)]
struct ShopOrderDto {
    id: u64,
    order_number: String,
    amount_cents: i64,
    currency: String,
    status: String,
    #[serde(default)]
    can_pay: bool,
    payment: Option<ShopOrderPaymentDto>,
}

impl ShopOrderDto {
    fn into_domain(self) -> Result<ShopOrder, PanelError> {
        if self.id == 0
            || self.order_number.trim().is_empty()
            || self.amount_cents < 0
            || self.currency.trim().is_empty()
        {
            return Err(PanelError::InvalidResponse("商城订单字段无效".to_owned()));
        }
        let status = shop_order_status(&self.status)?;
        let payment = self
            .payment
            .map(ShopOrderPaymentDto::into_domain)
            .transpose()?;
        Ok(ShopOrder {
            id: self.id,
            order_number: self.order_number,
            amount_cents: self.amount_cents,
            currency: self.currency,
            status,
            can_pay: self.can_pay,
            payment,
        })
    }
}

#[derive(Deserialize)]
struct ShopOrderPaymentDto {
    required: bool,
    status: String,
    payment_method_id: Option<u64>,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    payment_type: String,
    amount_cents: i64,
    fee_amount_cents: i64,
    net_amount_cents: i64,
    currency: String,
    #[serde(default)]
    pay_url: String,
}

impl ShopOrderPaymentDto {
    fn into_domain(self) -> Result<ShopPaymentSession, PanelError> {
        if self.amount_cents < 0
            || self.fee_amount_cents < 0
            || self.net_amount_cents < 0
            || self.currency.trim().is_empty()
        {
            return Err(PanelError::InvalidResponse(
                "商城支付会话字段无效".to_owned(),
            ));
        }
        let pay_url = (!self.pay_url.trim().is_empty())
            .then_some(self.pay_url)
            .map(validate_pay_url)
            .transpose()?;
        Ok(ShopPaymentSession {
            required: self.required,
            status: shop_payment_status(&self.status)?,
            payment_method_id: self.payment_method_id.filter(|id| *id > 0),
            provider: self.provider,
            payment_type: self.payment_type,
            amount_cents: self.amount_cents,
            fee_amount_cents: self.fee_amount_cents,
            net_amount_cents: self.net_amount_cents,
            currency: self.currency,
            pay_url,
        })
    }
}

#[derive(Deserialize)]
struct ShopCouponQuoteDto {
    code: String,
    name: String,
    discount_type: String,
    discount_summary: String,
    original_amount_cents: i64,
    discount_amount_cents: i64,
    payable_amount_cents: i64,
    currency: String,
}

impl ShopCouponQuoteDto {
    fn into_domain(self) -> Result<ShopCouponQuote, PanelError> {
        if self.code.trim().is_empty()
            || self.original_amount_cents < 0
            || self.discount_amount_cents < 0
            || self.payable_amount_cents < 0
            || self.discount_amount_cents > self.original_amount_cents
            || self.payable_amount_cents > self.original_amount_cents
            || self.currency.trim().is_empty()
        {
            return Err(PanelError::InvalidResponse("优惠码报价字段无效".to_owned()));
        }
        let discount_type = match self.discount_type.trim().to_ascii_lowercase().as_str() {
            "amount" => ShopCouponDiscountType::Amount,
            "percent" => ShopCouponDiscountType::Percent,
            _ => {
                return Err(PanelError::InvalidResponse("优惠码折扣类型无效".to_owned()));
            }
        };
        Ok(ShopCouponQuote {
            code: self.code,
            name: self.name,
            discount_type,
            discount_summary: self.discount_summary,
            original_amount_cents: self.original_amount_cents,
            discount_amount_cents: self.discount_amount_cents,
            payable_amount_cents: self.payable_amount_cents,
            currency: self.currency,
        })
    }
}

fn shop_order_status(value: &str) -> Result<ShopOrderStatus, PanelError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pending" => Ok(ShopOrderStatus::Pending),
        "paid_pending_fulfillment" => Ok(ShopOrderStatus::PaidPendingFulfillment),
        "paid" => Ok(ShopOrderStatus::Paid),
        "refunded" => Ok(ShopOrderStatus::Refunded),
        _ => Err(PanelError::InvalidResponse("订单状态无效".to_owned())),
    }
}

fn shop_payment_status(value: &str) -> Result<ShopPaymentStatus, PanelError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pending" => Ok(ShopPaymentStatus::Pending),
        "paid" => Ok(ShopPaymentStatus::Paid),
        "failed" => Ok(ShopPaymentStatus::Failed),
        "closed" => Ok(ShopPaymentStatus::Closed),
        "refunded" => Ok(ShopPaymentStatus::Refunded),
        _ => Err(PanelError::InvalidResponse("支付状态无效".to_owned())),
    }
}

fn default_currency() -> String {
    "CNY".to_owned()
}

#[derive(Serialize)]
struct RefreshRequestDto<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct RefreshResponseDto {
    access_token: String,
    expires_at: String,
    session_id: String,
    refresh_token: String,
    refresh_expires_at: String,
}

impl RefreshResponseDto {
    fn into_tokens(self) -> Result<SessionTokens, PanelError> {
        SessionTokens::new(
            self.session_id,
            self.access_token,
            parse_epoch_seconds(&self.expires_at)?,
            self.refresh_token,
            parse_epoch_seconds(&self.refresh_expires_at)?,
        )
        .map_err(|error| PanelError::InvalidResponse(error.to_string()))
    }
}

#[derive(Serialize)]
struct LogoutRequestDto<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct LogoutResponseDto {
    revoked: bool,
}

#[derive(Deserialize)]
struct ClientResourcesDto {
    #[serde(default)]
    server_groups: Vec<ResourceGroupDto>,
}

impl ClientResourcesDto {
    fn into_domain(self) -> Result<Vec<ServerGroup>, PanelError> {
        self.server_groups
            .into_iter()
            .map(ResourceGroupDto::into_domain)
            .collect()
    }
}

#[derive(Deserialize)]
struct ResourceGroupDto {
    id: u64,
    name: String,
    connectable: bool,
    total_quota_bytes: i64,
    used_bytes: i64,
    remaining_bytes: i64,
    next_expires_at: Option<String>,
    #[serde(default)]
    entitlements: Vec<EntitlementDto>,
    #[serde(default)]
    nodes: Vec<NodeDto>,
}

impl ResourceGroupDto {
    fn into_domain(self) -> Result<ServerGroup, PanelError> {
        let next_expires_at_epoch_seconds = self
            .next_expires_at
            .as_deref()
            .map(parse_epoch_seconds)
            .transpose()?;
        Ok(ServerGroup {
            id: self.id,
            name: self.name,
            connectable: self.connectable,
            total_quota_bytes: self.total_quota_bytes,
            used_bytes: self.used_bytes,
            remaining_bytes: self.remaining_bytes,
            next_expires_at_epoch_seconds,
            entitlements: self
                .entitlements
                .into_iter()
                .map(EntitlementDto::into_domain)
                .collect::<Result<_, _>>()?,
            nodes: self.nodes.into_iter().map(NodeDto::into_domain).collect(),
        })
    }
}

#[derive(Deserialize)]
struct NodeDto {
    endpoint_id: String,
    endpoint_type: String,
    name: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    latency_target: String,
    status: String,
    #[serde(default = "default_multiplier")]
    multiplier: f64,
    #[serde(default = "default_true")]
    selectable: bool,
}

impl NodeDto {
    fn into_domain(self) -> ServerNode {
        ServerNode {
            endpoint_id: self.endpoint_id,
            endpoint_type: match self.endpoint_type.as_str() {
                "node" => EndpointType::Node,
                "load_balance_pool" => EndpointType::LoadBalancePool,
                _ => EndpointType::Unknown,
            },
            name: self.name,
            country_code: self.country_code,
            tags: self.tags,
            latency_target: self.latency_target,
            status: self.status,
            multiplier: Some(self.multiplier),
            selectable: self.selectable,
        }
    }
}

const fn default_multiplier() -> f64 {
    1.0
}

const fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct EntitlementDto {
    grant_id: u64,
    source: String,
    status: String,
    plan_id: u64,
    plan_price_id: Option<u64>,
    traffic_addon_id: Option<u64>,
    plan_name: String,
    #[serde(default)]
    price_label: String,
    #[serde(default)]
    addon_name: String,
    quota_bytes: i64,
    used_bytes: i64,
    remaining_bytes: i64,
    starts_at: String,
    expires_at: String,
}

impl EntitlementDto {
    fn into_domain(self) -> Result<Entitlement, PanelError> {
        Ok(Entitlement {
            grant_id: self.grant_id,
            source: self.source,
            status: self.status,
            plan_id: self.plan_id,
            plan_price_id: self.plan_price_id,
            traffic_addon_id: self.traffic_addon_id,
            plan_name: self.plan_name,
            price_label: self.price_label,
            addon_name: self.addon_name,
            quota_bytes: self.quota_bytes,
            used_bytes: self.used_bytes,
            remaining_bytes: self.remaining_bytes,
            starts_at_epoch_seconds: parse_epoch_seconds(&self.starts_at)?,
            expires_at_epoch_seconds: parse_epoch_seconds(&self.expires_at)?,
        })
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)] // Exact Panel wire contract.
struct ClientConfigurationRequestDto<'a> {
    group_id: u64,
    selected_endpoint_id: &'a str,
    route_mode: &'a str,
    bypass_mainland: bool,
    bypass_lan: bool,
    ipv6: bool,
    multiplex_enabled: bool,
    runtime_id: &'a str,
    supported_schema_versions: &'a [u32],
}

#[derive(Deserialize)]
struct ClientConfigurationResponseDto {
    runtime_id: String,
    configuration_schema: u32,
    revision: String,
    expires_at: String,
    selected_endpoint_id: String,
    configuration: Box<RawValue>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use reqwest::{StatusCode, Url};
    use serde_json::json;
    use topnode_application::{ConfigurationSourceError, PanelError};
    use topnode_domain::{
        BalanceTransactionType, GiftCardRewardType, ShopCouponDiscountType, ShopOrderSelection,
        ShopOrderStatus, ShopPaymentChoice, ShopPaymentStatus, ShopPurchaseKind,
        SupportTicketPriority, SupportTicketSenderRole, SupportTicketStatus,
    };

    use super::{
        AffiliateCommissionListDto, AffiliateSummaryDto, AffiliateTransferListDto,
        BalanceTransactionDto, ClientConfigurationResponseDto, ClientResourcesDto,
        GiftCardCheckDto, HttpPanelClient, PanelClientOptions, PayShopOrderRequestDto,
        ShopCouponQuoteDto, ShopOrderDto, ShopOrderSelectionRequestDto, ShopPaymentMethodsDto,
        ShopPlansDto, SubscriptionLinkDto, SupportTicketDetailDto, UserDto, append_bounded,
        configuration_error, decode_bytes, finish_logout, normalize_client_options,
        parse_epoch_seconds, parse_money_cents, session_authentication_error, shop_order_status,
        shop_payment_status, uses_fixed_panel_pins, validate_content_length,
        validate_gift_card_purchase_url, validate_pay_url, validate_subscription_link,
    };
    use crate::SessionVault;

    #[test]
    fn fixed_http_client_accepts_the_pinned_rustls_configuration() {
        HttpPanelClient::new(
            PanelClientOptions::fixed("11111111-1111-4111-8111-111111111111"),
            SessionVault::new(PathBuf::from("unused-session-envelope")),
        )
        .expect("valid pinned HTTP client");
    }

    #[test]
    fn rfc3339_timestamp_is_parsed() {
        assert_eq!(
            parse_epoch_seconds("1970-01-01T00:01:00Z").expect("valid time"),
            60
        );
    }

    #[test]
    fn resource_endpoint_id_remains_opaque() {
        let resources: ClientResourcesDto = serde_json::from_str(
            r#"{"server_groups":[{"id":1,"name":"A","connectable":true,"total_quota_bytes":10,"used_bytes":2,"remaining_bytes":8,"nodes":[{"endpoint_id":"load_balance_pool:42","endpoint_type":"load_balance_pool","name":"Pool","country_code":"HK","status":"online"}]}]}"#,
        )
        .expect("valid resources");
        let groups = resources.into_domain().expect("valid domain resources");

        assert_eq!(groups[0].nodes[0].endpoint_id, "load_balance_pool:42");
        assert_eq!(groups[0].nodes[0].country_code, "HK");
        assert_eq!(groups[0].nodes[0].multiplier, Some(1.0));
        assert!(groups[0].nodes[0].selectable);
    }

    #[test]
    fn compact_login_user_defaults_the_optional_uuid() {
        let user: UserDto = serde_json::from_str(
            r#"{"id":1,"username":"desktop-user","email":"user@example.com"}"#,
        )
        .expect("valid compact user");

        assert!(user.uuid.is_empty());
    }

    #[test]
    fn profile_balance_uses_exact_decimal_cents() {
        let user: UserDto = serde_json::from_str(
            r#"{"id":1,"uuid":"u","username":"desktop-user","email":"user@example.com","balance":"123.45"}"#,
        )
        .expect("valid user");

        assert_eq!(
            user.into_domain().expect("valid profile").balance_cents,
            12_345
        );
        assert_eq!(parse_money_cents("0.5").expect("valid money"), 50);
        assert!(parse_money_cents("1.234").is_err());
    }

    #[test]
    fn balance_transaction_decodes_the_android_contract() {
        let transaction: BalanceTransactionDto = serde_json::from_value(json!({
            "id": 12,
            "type": "order_refund",
            "description": "退款返还余额 ORD12",
            "amount_cents": 1990,
            "balance_before_cents": 3010,
            "balance_after_cents": 5000,
            "reference_id": 8,
            "created_at": "2026-07-20T18:30:00+08:00"
        }))
        .expect("valid transaction");

        let transaction = transaction.into_domain().expect("valid domain transaction");

        assert_eq!(
            transaction.transaction_type,
            BalanceTransactionType::OrderRefund
        );
        assert_eq!(transaction.amount_cents, 1_990);
        assert_eq!(transaction.reference_id, Some(8));
        assert!(transaction.created_at_epoch_seconds > 0);
    }

    #[test]
    fn support_ticket_detail_decodes_private_senders_and_orders_each_message_page() {
        let response = json!({
            "id": 42,
            "ticket_number": "TKT-20260830-0042",
            "title": "无法连接东京节点",
            "priority": "high",
            "status": "replied",
            "has_unread_reply": true,
            "last_admin_reply_at": "2026-08-30T10:05:00+08:00",
            "closed_at": null,
            "created_at": "2026-08-30T10:00:00+08:00",
            "updated_at": "2026-08-30T10:05:00+08:00",
            "messages": [
                {
                    "id": 102,
                    "sender_role": "admin",
                    "sender": { "username": "TOPNODE 客服", "email": "support@example.test" },
                    "content": "请刷新节点后再试。",
                    "created_at": "2026-08-30T10:05:00+08:00"
                },
                {
                    "id": 101,
                    "sender_role": "user",
                    "sender": { "username": "desktop-user", "email": "user@example.test" },
                    "content": "东京节点连接失败。",
                    "created_at": "2026-08-30T10:00:00+08:00"
                }
            ],
            "message_pagination": { "page": 1, "page_size": 2, "total": 4 }
        });
        for (page, sender) in [
            (1, None),
            (2, None),
            (1, Some(serde_json::Value::Null)),
            (2, Some(json!({"id": 0, "username": "客服01", "email": ""}))),
            (
                1,
                Some(json!({"id": 1, "username": "root", "email": "root@example.test"})),
            ),
        ] {
            let mut data = response.clone();
            let admin_message = data["messages"][0].as_object_mut().expect("message object");
            if let Some(sender) = sender {
                admin_message.insert("sender".to_owned(), sender);
            } else {
                admin_message.remove("sender");
            }
            data["message_pagination"]["page"] = json!(page);
            let body = serde_json::to_vec(&json!({"code": 200, "message": "ok", "data": data}))
                .expect("serialized support-ticket response");
            let detail: SupportTicketDetailDto = decode_bytes(StatusCode::OK, None, &body)
                .expect("valid support-ticket HTTP response");
            let detail = detail.into_domain(page, 2).expect("valid domain detail");

            assert_eq!(detail.ticket.priority, SupportTicketPriority::High);
            assert_eq!(detail.ticket.status, SupportTicketStatus::Replied);
            assert!(detail.ticket.has_unread_reply);
            assert_eq!(detail.messages.len(), 2);
            assert_eq!(detail.messages[0].id, 101);
            assert_eq!(
                detail.messages[0].sender_role,
                SupportTicketSenderRole::User
            );
            assert_eq!(detail.messages[0].sender_name, "desktop-user");
            assert_eq!(detail.messages[0].sender_email, "user@example.test");
            assert_eq!(detail.messages[1].id, 102);
            assert_eq!(
                detail.messages[1].sender_role,
                SupportTicketSenderRole::Admin
            );
            assert_eq!(detail.messages[1].sender_name, "客服01");
            assert!(detail.messages[1].sender_email.is_empty());
            assert_eq!(detail.messages[1].content, "请刷新节点后再试。");
            assert_eq!(detail.message_page, page);
            assert_eq!(detail.message_page_size, 2);
            assert_eq!(detail.message_total, 4);
            assert_eq!(detail.has_earlier_messages(), page == 1);
        }
    }

    #[test]
    fn gift_card_check_decodes_the_complete_android_contract() {
        let body = r#"{
            "code": 200,
            "message": "ok",
            "data": {
                "reward_preview": {
                    "type": "plan",
                    "summary": "VIP 黄金套餐（月付）",
                    "balance_amount_cents": 0,
                    "plan_id": 7,
                    "plan_name": "VIP 黄金套餐",
                    "plan_price_id": 8,
                    "price_label": "月付",
                    "group_id": 9,
                    "group_name": "黄金节点",
                    "traffic_quota_bytes": 429496729600
                },
                "can_redeem": false,
                "reason": "套餐或价格已不可用"
            }
        }"#;
        let response: GiftCardCheckDto =
            decode_bytes(StatusCode::OK, None, body.as_bytes()).expect("valid gift-card response");
        let reward = response
            .reward_preview
            .into_domain()
            .expect("valid gift-card reward");

        assert_eq!(reward.reward_type, GiftCardRewardType::Plan);
        assert_eq!(reward.plan_id, Some(7));
        assert_eq!(reward.plan_price_id, Some(8));
        assert_eq!(reward.group_id, Some(9));
        assert_eq!(reward.traffic_quota_bytes, 429_496_729_600);
        assert!(!response.can_redeem);
        assert_eq!(response.reason, "套餐或价格已不可用");
    }

    #[test]
    fn gift_card_purchase_url_only_accepts_web_targets() {
        assert!(validate_gift_card_purchase_url(String::new()).is_ok());
        assert!(
            validate_gift_card_purchase_url("https://store.example.test/gifts".to_owned()).is_ok()
        );
        assert!(validate_gift_card_purchase_url("file:///C:/secret".to_owned()).is_err());
        assert!(
            validate_gift_card_purchase_url("https://user:secret@example.test/gifts".to_owned())
                .is_err()
        );
    }

    #[test]
    fn subscription_link_contract_is_validated_and_redacted() {
        let body = r#"{
            "code": 200,
            "message": "ok",
            "data": {
                "url": "https://panel.example.test/api/v1/subscription?uuid=secret"
            }
        }"#;
        let response: SubscriptionLinkDto =
            decode_bytes(StatusCode::OK, None, body.as_bytes()).expect("valid link response");
        let link = validate_subscription_link(&response.url).expect("valid subscription link");

        assert_eq!(
            link.expose(),
            "https://panel.example.test/api/v1/subscription?uuid=secret"
        );
        assert!(!format!("{link:?}").contains("secret"));
        assert!(validate_subscription_link("").is_err());
        assert!(validate_subscription_link("file:///C:/subscription").is_err());
        assert!(validate_subscription_link("https://user:secret@panel.example/sub").is_err());
        assert!(validate_subscription_link("https://panel.example/sub#secret").is_err());
    }

    #[test]
    fn affiliate_contract_decodes_summary_commissions_and_transfers() {
        let summary: AffiliateSummaryDto = serde_json::from_value(json!({
            "enabled": true,
            "rebate_type": "recurring",
            "effective_rate_bps": 500,
            "total_commission_cents": 2450,
            "available_commission_cents": 1250,
            "cooling_commission_cents": 500,
            "transferred_commission_cents": 700,
            "invitation_count": 8,
            "affiliate_code": "AbCdEf123456",
            "invitation_url": "https://panel.example.test/aff?id=AbCdEf123456"
        }))
        .expect("valid affiliate summary");
        let summary = summary.into_domain().expect("valid summary domain");
        assert_eq!(summary.available_commission_cents, 1_250);
        assert_eq!(summary.invitation_count, 8);

        let commissions: AffiliateCommissionListDto = serde_json::from_value(json!({
            "commissions": [{
                "id": 31,
                "invitee": "u73921548",
                "order_number": "ORD202608290018",
                "rebate_type": "first",
                "rate_bps": 1000,
                "base_amount_cents": 2000,
                "commission_cents": 200,
                "status": "cooling",
                "available_at": "2026-09-05T15:42:00+08:00",
                "released_at": null,
                "reversed_at": null,
                "reversed_deducted_cents": 0,
                "created_at": "2026-08-29T15:42:00+08:00"
            }],
            "pagination": {"page": 1, "page_size": 20, "total": 21}
        }))
        .expect("valid commission response");
        let commissions = commissions.into_domain(1, 20).expect("valid commissions");
        assert_eq!(commissions.commissions[0].commission_cents, 200);
        assert!(commissions.has_more());

        let transfers: AffiliateTransferListDto = serde_json::from_value(json!({
            "transfers": [{
                "id": 84,
                "request_id": "a32ff4dd-7cee-4bd3-bd9f-d4c293162864",
                "amount_cents": 1650,
                "balance_after_cents": 14500,
                "created_at": "2026-08-28T11:20:00+08:00"
            }],
            "pagination": {"page": 1, "page_size": 20, "total": 1}
        }))
        .expect("valid transfer response");
        let transfers = transfers.into_domain(1, 20).expect("valid transfers");
        assert_eq!(transfers.transfers[0].amount_cents, 1_650);
        assert!(!transfers.has_more());
    }

    #[test]
    fn shop_catalog_decodes_the_panel_wire_fields() {
        let plans: ShopPlansDto = serde_json::from_value(json!({
            "plans": [{
                "id": 7,
                "name": "VIP",
                "description": "Fast",
                "group_name": "Premium",
                "addon_available": true,
                "prices": [{
                    "id": 8,
                    "label": "月付",
                    "period_unit": "month",
                    "period_count": 1,
                    "price_cents": 2900,
                    "currency": "CNY",
                    "included_traffic_quota_bytes": 107_374_182_400_i64
                }],
                "traffic_addons": [{
                    "id": 9,
                    "name": "100GB",
                    "traffic_quota_bytes": 107_374_182_400_i64,
                    "price_cents": 1000,
                    "currency": "CNY"
                }]
            }]
        }))
        .expect("valid plans");
        let plan = plans.plans.into_iter().next().expect("plan");
        let plan = plan.into_domain().expect("valid domain plan");

        assert_eq!(plan.id, 7);
        assert_eq!(plan.prices[0].price_cents, 2_900);
        assert_eq!(plan.traffic_addons[0].traffic_bytes, 107_374_182_400);

        let methods: ShopPaymentMethodsDto = serde_json::from_value(json!({
            "payment_methods": [{
                "id": 3,
                "name": "支付宝",
                "icon_url": "https://example.test/alipay.png",
                "provider": "alipay",
                "provider_name": "Alipay",
                "payment_type": "redirect",
                "payment_type_name": "跳转支付"
            }]
        }))
        .expect("valid methods");
        let method = methods.payment_methods.into_iter().next().expect("method");
        let method = method.into_domain().expect("valid method");
        assert_eq!(method.id, 3);
        assert_eq!(
            method.icon_url.as_deref(),
            Some("https://example.test/alipay.png")
        );
        assert_eq!(method.provider, "alipay");
        assert_eq!(method.provider_name, "Alipay");
        assert_eq!(method.payment_type, "redirect");
    }

    #[test]
    fn shop_requests_keep_the_exact_panel_shape() {
        let plan_selection = ShopOrderSelection {
            kind: ShopPurchaseKind::BasePlan,
            plan_id: 7,
            product_id: 8,
            coupon_code: Some("SAVE20".to_owned()),
        };
        let plan = ShopOrderSelectionRequestDto::from_selection(&plan_selection)
            .expect("valid plan selection");
        assert_eq!(
            serde_json::to_value(plan).expect("serialize plan"),
            json!({"type":"base_plan","plan_id":7,"plan_price_id":8,"coupon_code":"SAVE20"})
        );
        let addon_selection = ShopOrderSelection {
            kind: ShopPurchaseKind::TrafficAddon,
            plan_id: 7,
            product_id: 9,
            coupon_code: None,
        };
        let addon = ShopOrderSelectionRequestDto::from_selection(&addon_selection)
            .expect("valid addon selection");
        assert_eq!(
            serde_json::to_value(addon).expect("serialize addon"),
            json!({"type":"traffic_addon","plan_id":7,"traffic_addon_id":9})
        );
        let balance = PayShopOrderRequestDto::from_payment(ShopPaymentChoice::Balance)
            .expect("valid balance payment");
        assert_eq!(
            serde_json::to_value(balance).expect("serialize balance"),
            json!({"payment_channel":"balance","use_balance":true})
        );
        let online = PayShopOrderRequestDto::from_payment(ShopPaymentChoice::Provider(3))
            .expect("valid provider payment");
        assert_eq!(
            serde_json::to_value(online).expect("serialize online"),
            json!({"payment_method_id":3})
        );
        assert!(PayShopOrderRequestDto::from_payment(ShopPaymentChoice::Provider(0)).is_err());
    }

    #[test]
    fn shop_order_preserves_authoritative_amount_and_payment_session() {
        let external: ShopOrderDto = serde_json::from_value(json!({
            "id": 20,
            "order_number": "ORD20",
            "amount_cents": 1700,
            "currency": "CNY",
            "status": "pending",
            "can_pay": false,
            "payment": {
                "required": true,
                "status": "pending",
                "payment_method_id": 3,
                "provider": "epay",
                "payment_type": "alipay",
                "amount_cents": 1700,
                "fee_amount_cents": 25,
                "net_amount_cents": 1675,
                "currency": "CNY",
                "pay_url": "https://pay.example.test/session?id=20"
            }
        }))
        .expect("valid pending order");
        let external = external.into_domain().expect("valid payment URL");
        assert_eq!(external.status, ShopOrderStatus::Pending);
        assert_eq!(external.amount_cents, 1_700);
        assert_eq!(
            external
                .payment
                .as_ref()
                .and_then(|payment| payment.pay_url.as_deref()),
            Some("https://pay.example.test/session?id=20")
        );
        assert_eq!(
            external.payment.expect("payment").status,
            ShopPaymentStatus::Pending
        );

        let fulfilling: ShopOrderDto = serde_json::from_value(json!({
            "id": 21,
            "order_number": "ORD21",
            "amount_cents": 1700,
            "currency": "CNY",
            "status": "paid_pending_fulfillment",
            "payment": null
        }))
        .expect("valid fulfilling order");
        let fulfilling = fulfilling.into_domain().expect("valid fulfilling order");
        assert_eq!(fulfilling.status, ShopOrderStatus::PaidPendingFulfillment);
        assert!(fulfilling.status.payment_received());
        assert!(!fulfilling.status.is_terminal());
    }

    #[test]
    fn coupon_quote_maps_all_server_amounts() {
        let quote: ShopCouponQuoteDto = serde_json::from_value(json!({
            "code": "SAVE20",
            "name": "新人优惠",
            "discount_type": "percent",
            "discount_summary": "8折",
            "original_amount_cents": 2000,
            "discount_amount_cents": 400,
            "payable_amount_cents": 1600,
            "currency": "CNY"
        }))
        .expect("valid quote");
        let quote = quote.into_domain().expect("valid domain quote");

        assert_eq!(quote.discount_type, ShopCouponDiscountType::Percent);
        assert_eq!(quote.original_amount_cents, 2_000);
        assert_eq!(quote.discount_amount_cents, 400);
        assert_eq!(quote.payable_amount_cents, 1_600);
    }

    #[test]
    fn unknown_order_and_payment_statuses_fail_closed() {
        assert!(shop_order_status("cancelled").is_err());
        assert!(shop_payment_status("unknown").is_err());
    }

    #[test]
    fn external_payment_url_fails_closed_to_https() {
        assert!(validate_pay_url("https://pay.example.test/checkout".to_owned()).is_ok());
        assert!(validate_pay_url("http://pay.example.test/checkout".to_owned()).is_err());
        assert!(validate_pay_url("javascript:alert(1)".to_owned()).is_err());
        assert!(validate_pay_url("https://user:secret@pay.example.test/".to_owned()).is_err());
    }

    #[test]
    fn configuration_payload_keeps_its_exact_raw_json() {
        let body = br#"{"code":200,"message":"success","data":{"runtime_id":"rt1","configuration_schema":1,"revision":"rev","expires_at":"2030-01-01T00:00:00Z","selected_endpoint_id":"node:1","configuration":{ "z":1e+02, "escaped":"\u003c", "a":true }}}"#;

        let response: ClientConfigurationResponseDto =
            decode_bytes(StatusCode::OK, None, body).expect("valid response");

        assert_eq!(
            response.configuration.get(),
            r#"{ "z":1e+02, "escaped":"\u003c", "a":true }"#
        );
    }

    #[test]
    fn bounded_buffer_accepts_the_limit_and_rejects_the_next_byte() {
        let mut bytes = vec![1, 2];
        append_bounded(&mut bytes, &[3, 4], 4).expect("exact limit is accepted");
        assert_eq!(bytes, [1, 2, 3, 4]);
        assert!(matches!(
            append_bounded(&mut bytes, &[5], 4),
            Err(PanelError::InvalidResponse(_))
        ));
        assert!(validate_content_length(Some(4), 4).is_ok());
        assert!(matches!(
            validate_content_length(Some(5), 4),
            Err(PanelError::InvalidResponse(_))
        ));
    }

    #[test]
    fn unauthorized_status_wins_over_a_malformed_body() {
        let result = decode_bytes::<ClientResourcesDto>(
            StatusCode::UNAUTHORIZED,
            Some("request-1".to_owned()),
            b"not json",
        );

        assert!(matches!(result, Err(PanelError::Unauthorized)));
    }

    #[test]
    fn disabled_account_survives_the_http_401_authentication_envelope() {
        let result = decode_bytes::<ClientResourcesDto>(
            StatusCode::UNAUTHORIZED,
            Some("header-request".to_owned()),
            br#"{"code":403001,"message":"user disabled","request_id":"body-request"}"#,
        );

        let Err(error) = result else {
            panic!("disabled account must remain an authentication error");
        };
        assert_eq!(
            error,
            PanelError::Business {
                code: 403_001,
                message: "user disabled".to_owned(),
                request_id: Some("body-request".to_owned()),
            }
        );
    }

    #[test]
    fn successful_http_business_error_preserves_structured_diagnostics() {
        let result = decode_bytes::<ClientResourcesDto>(
            StatusCode::OK,
            Some("header-request".to_owned()),
            br#"{"code":409026,"message":"selected client endpoint is not online","request_id":"body-request"}"#,
        );

        let Err(error) = result else {
            panic!("business envelope must remain an error");
        };
        assert_eq!(
            error,
            PanelError::Business {
                code: 409_026,
                message: "selected client endpoint is not online".to_owned(),
                request_id: Some("body-request".to_owned()),
            }
        );
    }

    #[test]
    fn configuration_business_error_keeps_only_the_safe_customer_message() {
        let error = PanelError::Business {
            code: 409_026,
            message: "selected client endpoint is not online".to_owned(),
            request_id: Some("private-request".to_owned()),
        };

        assert_eq!(
            configuration_error(error),
            ConfigurationSourceError::Rejected(
                "所选节点已离线或不可用，请重新选择节点。".to_owned()
            )
        );
    }

    #[test]
    fn refresh_failure_only_surfaces_a_safe_disabled_account_reason() {
        let disabled = PanelError::Business {
            code: 403_001,
            message: "user disabled".to_owned(),
            request_id: Some("private-request".to_owned()),
        };
        let internal = PanelError::Business {
            code: 500_001,
            message: "database unavailable".to_owned(),
            request_id: Some("private-request".to_owned()),
        };

        assert_eq!(session_authentication_error(&disabled), disabled);
        assert_eq!(
            session_authentication_error(&internal),
            PanelError::Unauthorized
        );
    }

    #[test]
    fn non_success_status_remains_an_http_failure_with_safe_details() {
        let result = decode_bytes::<ClientResourcesDto>(
            StatusCode::BAD_GATEWAY,
            Some("header-request".to_owned()),
            br#"{"code":500001,"message":"upstream failed"}"#,
        );

        let Err(PanelError::Transport(message)) = result else {
            panic!("unexpected error variant");
        };
        assert!(message.contains("502"));
        assert!(message.contains("500001"));
        assert!(message.contains("header-request"));
    }

    #[test]
    fn logout_prioritizes_a_local_credential_cleanup_failure() {
        let local = PanelError::Storage("vault unavailable".to_owned());
        let remote = PanelError::Business {
            code: 500_001,
            message: "logout failed".to_owned(),
            request_id: Some("request-1".to_owned()),
        };

        assert_eq!(finish_logout(Err(local.clone()), Err(remote)), Err(local));
    }

    #[test]
    fn client_options_are_normalized_to_the_panel_contract() {
        let (options, url) = normalize_client_options(PanelClientOptions {
            base_url: "https://example.test/panel".to_owned(),
            device_id: " 11111111-1111-4111-8111-111111111111 ".to_owned(),
            device_name: " Desktop ".to_owned(),
            platform: " WINDOWS ".to_owned(),
            version_name: " 2026.09.01-abcdef12 ".to_owned(),
        })
        .expect("valid options");

        assert_eq!(url.as_str(), "https://example.test/panel/");
        assert_eq!(options.device_id, "11111111-1111-4111-8111-111111111111");
        assert_eq!(options.device_name, "Desktop");
        assert_eq!(options.platform, "windows");
        assert_eq!(options.version_name, "2026.09.01-abcdef12");
    }

    #[test]
    fn client_options_reject_ambiguous_urls_and_invalid_device_fields() {
        for base_url in [
            "http://example.test/",
            "https://user:password@example.test/",
            "https://example.test/?query=1",
            "https://example.test/#fragment",
        ] {
            assert!(normalize_client_options(options(base_url)).is_err());
        }

        let mut invalid = options("https://example.test/");
        invalid.device_id = "device\u{85}id".to_owned();
        assert!(normalize_client_options(invalid).is_err());

        let mut invalid = options("https://example.test/");
        invalid.device_name = "界".repeat(43);
        assert!(normalize_client_options(invalid).is_err());

        let mut invalid = options("https://example.test/");
        invalid.platform = "win/dows".to_owned();
        assert!(normalize_client_options(invalid).is_err());
    }

    #[test]
    fn production_pins_are_scoped_to_the_exact_fixed_host() {
        assert!(uses_fixed_panel_pins(
            &Url::parse("https://api.anyrelink.top/").expect("valid URL")
        ));
        assert!(!uses_fixed_panel_pins(
            &Url::parse("https://api.anyrelink.top.example/").expect("valid URL")
        ));
        assert!(!uses_fixed_panel_pins(
            &Url::parse("https://example.test/").expect("valid URL")
        ));
    }

    fn options(base_url: &str) -> PanelClientOptions {
        PanelClientOptions {
            base_url: base_url.to_owned(),
            device_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            device_name: "Desktop".to_owned(),
            platform: "windows".to_owned(),
            version_name: "2026.09.01-abcdef12".to_owned(),
        }
    }
}
