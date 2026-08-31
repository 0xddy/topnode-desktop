use std::{fmt, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::{Mutex, watch};
use topnode_domain::{
    AffiliateCommissionPage, AffiliateSummary, AffiliateTransferPage, BalanceTransaction,
    GiftCardConfig, GiftCardRedeemCheck, GiftCardRewardPreview, ServerGroup, ShopCatalog,
    ShopCouponQuote, ShopOrder, ShopOrderSelection, ShopPaymentChoice, ShopPurchaseKind,
    SubscriptionLink, SupportTicketAction, SupportTicketDetail, SupportTicketDraft,
    SupportTicketPage, SupportTicketPriority, UserIdentity, UserOrderFilter, UserOrderPage,
};

#[derive(Clone)]
pub struct LoginCredentials {
    pub email: String,
    password: String,
}

impl LoginCredentials {
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for LoginCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginCredentials")
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct PasswordChange {
    current_password: String,
    new_password: String,
}

impl PasswordChange {
    pub fn new(current_password: impl Into<String>, new_password: impl Into<String>) -> Self {
        Self {
            current_password: current_password.into(),
            new_password: new_password.into(),
        }
    }

    pub fn current_password(&self) -> &str {
        &self.current_password
    }

    pub fn new_password(&self) -> &str {
        &self.new_password
    }
}

impl fmt::Debug for PasswordChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordChange")
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PanelError {
    #[error("账户操作正在进行")]
    Busy,
    #[error("请先登录")]
    NoSession,
    #[error("登录状态已失效，请重新登录")]
    Unauthorized,
    #[error("Panel 业务错误 {code}：{message}")]
    Business {
        code: i64,
        message: String,
        request_id: Option<String>,
    },
    #[error("Panel 网络请求失败：{0}")]
    Transport(String),
    #[error("Panel 返回内容无效：{0}")]
    InvalidResponse(String),
    #[error("系统凭据存储失败：{0}")]
    Storage(String),
}

impl PanelError {
    /// Returns a localized message suitable for the product UI. Internal
    /// transport details, request identifiers, and server messages stay in
    /// diagnostics and logs.
    #[must_use]
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::Busy => "操作正在进行，请稍候。",
            Self::NoSession | Self::Unauthorized => "登录状态已失效，请重新登录。",
            Self::Business { code, .. } => business_user_message(*code),
            Self::Transport(_) => "暂时无法连接服务，请检查网络后重试。",
            Self::InvalidResponse(_) => "服务响应异常，请稍后重试。",
            Self::Storage(_) => "无法安全保存登录状态，请检查系统设置后重试。",
        }
    }

    #[must_use]
    const fn login_message(&self) -> &'static str {
        match self {
            Self::Unauthorized
            | Self::Business {
                code: 401_001 | 404_002,
                ..
            } => "邮箱或密码错误，请重新输入。",
            Self::Business {
                code: 400_001..=400_002,
                ..
            } => "请输入有效的邮箱和密码。",
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "登录服务暂时不可用，请稍后重试。"
            }
            Self::Transport(_) => "暂时无法连接登录服务，请检查网络后重试。",
            _ => self.user_message(),
        }
    }

    /// Returns a localized message for coupon, order, and payment operations.
    /// The Panel currently reuses validation code 400002 for several distinct
    /// shop failures, so stable server messages are translated here without
    /// ever exposing the original diagnostics to the product UI.
    #[must_use]
    pub fn shop_user_message(&self) -> &'static str {
        match self {
            Self::Business { code: 404_001, .. } => "商品或订单已失效，请返回刷新后重试。",
            Self::Business { code: 409_011, .. } => "该套餐已有有效订阅，暂不支持重复购买。",
            Self::Business { code: 409_017, .. } => "该套餐或规格已下架，请刷新商品列表后重试。",
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "购买服务暂时不可用，请稍后重试。"
            }
            Self::Business { message, .. } => {
                shop_business_user_message(message).unwrap_or_else(|| self.user_message())
            }
            Self::Transport(_) => "暂时无法连接购买服务，请检查网络后重试。",
            Self::InvalidResponse(message) if message == "商品信息已更新" => {
                "商品信息已更新，请刷新商品列表后重新选择。"
            }
            Self::InvalidResponse(message) if message == "支付方式已更新" => {
                "支付方式已更新，请重新选择。"
            }
            _ => self.user_message(),
        }
    }

    /// Returns a localized message for account-security operations without
    /// exposing server diagnostics.
    #[must_use]
    pub fn account_user_message(&self) -> &'static str {
        match self {
            Self::Business { message, .. }
                if message
                    .trim()
                    .eq_ignore_ascii_case("current password is incorrect") =>
            {
                "当前密码不正确，请重新输入。"
            }
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "账号安全服务暂时不可用，请稍后重试。"
            }
            _ => self.user_message(),
        }
    }

    /// Returns a localized message for the complete user gift-card contract.
    /// Stable business messages are mapped explicitly because the Panel uses
    /// the shared validation code for several distinct redemption failures.
    #[must_use]
    pub fn gift_card_user_message(&self) -> &'static str {
        match self {
            Self::Business { code: 404_001, .. } => "未找到这张礼品卡，请检查兑换码是否输入正确。",
            Self::Business { code: 409_017, .. } => {
                "礼品卡关联的套餐或规格已不可用，请联系管理员。"
            }
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "礼品卡服务暂时不可用，请稍后重试。"
            }
            Self::Business { message, .. } => {
                gift_card_business_user_message(message).unwrap_or_else(|| self.user_message())
            }
            Self::Transport(_) => "暂时无法连接礼品卡服务，请检查网络后重试。",
            Self::InvalidResponse(message) if message == "礼品卡兑换码不能为空" => {
                "请输入礼品卡兑换码。"
            }
            Self::InvalidResponse(message) if message == "礼品卡兑换码过长" => {
                "兑换码不能超过 96 个字符。"
            }
            _ => self.user_message(),
        }
    }

    /// Returns a localized message for invitation summary and record requests.
    /// Server diagnostics remain available to logs without leaking into the UI.
    #[must_use]
    pub const fn affiliate_user_message(&self) -> &'static str {
        match self {
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "邀请服务暂时不可用，请稍后重试。"
            }
            Self::Transport(_) => "暂时无法读取邀请信息，请检查网络后重试。",
            Self::InvalidResponse(_) => "邀请信息响应异常，请稍后重试。",
            _ => self.user_message(),
        }
    }

    /// Returns a safe message for subscription-link reads and resets. The
    /// credential-bearing URL and server diagnostics are never included.
    #[must_use]
    pub const fn subscription_link_user_message(&self) -> &'static str {
        match self {
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "订阅链接服务暂时不可用，请稍后重试。"
            }
            Self::Transport(_) => "暂时无法连接订阅链接服务，请检查网络后重试。",
            Self::InvalidResponse(_) => "订阅链接响应异常，请稍后重试。",
            _ => self.user_message(),
        }
    }

    /// Returns a safe, operation-specific message for the support-ticket IM.
    #[must_use]
    pub fn support_ticket_user_message(&self) -> &'static str {
        match self {
            Self::Business { code: 404_001, .. } => "该工单不存在或已被删除，请返回刷新列表。",
            Self::Business { code, .. } if *code / 1_000 == 500 => {
                "工单服务暂时不可用，请稍后重试。"
            }
            Self::Business { message, .. } => {
                support_ticket_business_user_message(message).unwrap_or_else(|| self.user_message())
            }
            Self::Transport(_) => "暂时无法连接工单服务，请检查网络后重试。",
            Self::InvalidResponse(message) => match message.as_str() {
                "工单标题不能为空" => "请输入工单标题。",
                "工单标题过长" => "工单标题不能超过 128 个字符。",
                "工单消息不能为空" => "请输入消息内容。",
                "工单消息过长" => "消息内容过长，请精简后重试。",
                "工单优先级无效" => "请选择有效的优先级。",
                _ => "工单服务响应异常，请稍后重试。",
            },
            _ => self.user_message(),
        }
    }

    /// Returns whether the failure means the cached authenticated session can
    /// no longer be used. A disabled account is deliberately included so the
    /// UI signs out while preserving the more useful disabled-account message.
    #[must_use]
    pub const fn invalidates_session(&self) -> bool {
        matches!(
            self,
            Self::NoSession
                | Self::Unauthorized
                | Self::Business {
                    code: 401_001..=401_005 | 403_001,
                    ..
                }
        )
    }

    /// Returns whether an order poll hit the Panel's generic not-found code.
    /// A known self-created pending order is deliberately hidden until payment
    /// is confirmed, so callers with such an order may treat this as transient.
    #[must_use]
    pub const fn is_pending_order_not_visible(&self) -> bool {
        matches!(self, Self::Business { code: 404_001, .. })
    }
}

const fn business_user_message(code: i64) -> &'static str {
    match code {
        400_001 => "请求内容有误，请检查后重试。",
        400_002 => "提交的信息不完整或已失效，请检查后重试。",
        400_003 => "邮箱格式不正确，请重新输入。",
        400_006 => "当前操作需要完成安全验证，请稍后再试。",
        400_007 | 422_001 => "验证码无效或已过期，请重新获取。",
        401_001..=401_005 => "登录状态已失效，请重新登录。",
        403_001 => "账号已被停用，请联系管理员。",
        403_002 => "当前账号无权执行此操作。",
        404_001 => "相关内容不存在或已不可用，请刷新后重试。",
        404_002 => "账号不存在，请检查输入。",
        409_011 => "该套餐已有有效订阅，暂不支持重复购买。",
        409_017 => "该套餐或规格已下架，请刷新商品列表后重试。",
        409_023 => "当前客户端版本不支持服务端运行配置，请升级客户端。",
        409_024 => "客户端与服务端配置版本不兼容，请升级客户端或联系管理员。",
        409_025 => "当前订阅已失效、流量已用尽或已过期，请刷新订阅后重试。",
        409_026 => "所选节点已离线或不可用，请重新选择节点。",
        429_003 => "登录失败次数过多，账号已暂时锁定，请稍后再试。",
        _ => match code / 1_000 {
            400 => "请求内容有误，请检查后重试。",
            401 => "登录状态已失效，请重新登录。",
            403 => "当前账号无权执行此操作。",
            404 => "相关内容不存在或已不可用，请刷新后重试。",
            409 => "数据状态已发生变化，请刷新后重试。",
            422 => "提交的信息无法验证，请检查后重试。",
            429 => "操作过于频繁，请稍后再试。",
            502 => "后端服务暂时不可用，请稍后重试。",
            503 => "服务正在恢复，请稍后重试。",
            504 => "服务响应超时，请稍后重试。",
            _ => "服务暂时不可用，请稍后重试。",
        },
    }
}

fn shop_business_user_message(message: &str) -> Option<&'static str> {
    let message = message.trim();
    let friendly = match message {
        "coupon_code is required" => "请输入优惠码。",
        "coupon is invalid" => "优惠码无效，请检查后重试。",
        "coupon is not active yet" => "优惠码尚未生效。",
        "coupon has expired" => "优惠码已过期。",
        "coupon usage limit reached" => "优惠码已被使用完。",
        "coupon user usage limit reached" => "你已达到该优惠码的使用次数上限。",
        "coupon is not available for this plan" => "该优惠码不适用于当前套餐。",
        "coupon is not available for this spec" => "该优惠码不适用于当前规格。",
        "plan price is disabled" => "当前套餐规格暂不可购买，请刷新商品列表后重新选择。",
        "traffic addon is disabled" => "当前流量包暂不可购买，请刷新商品列表后重新选择。",
        "user has no active subscription for this plan" => {
            "当前账户没有该套餐的有效订阅，暂不能购买此流量包。"
        }
        "payment_method_id is required" => "请选择支付方式。",
        "payment method is not available" => "该支付方式暂不可用，请选择其他方式。",
        "insufficient balance" => "账户余额不足，请选择其他支付方式。",
        "order payment is already pending" => "该订单已发起支付，请完成当前支付。",
        "order is not pending" => "订单状态已发生变化，请刷新后重试。",
        "order does not require payment" => "该订单无需再次支付，请刷新订单状态。",
        "order amount is invalid" | "invalid balance" => "订单或账户金额异常，请联系管理员。",
        "id is required" => "订单信息无效，请重新提交。",
        "type has invalid value"
        | "plan_id is required"
        | "plan_price_id is required"
        | "traffic_addon_id is required" => "商品信息已更新，请刷新商品列表后重新选择。",
        "order item is incomplete"
        | "order item does not match plan price"
        | "order item does not match traffic addon"
        | "order item has invalid group snapshot"
        | "invalid plan period" => "订单中的商品信息已失效，请返回刷新后重新下单。",
        "provider has invalid value" | "payment provider config is incomplete" => {
            "支付渠道暂不可用，请选择其他方式或稍后再试。"
        }
        _ if is_payment_configuration_message(message) => {
            "支付渠道暂不可用，请选择其他方式或稍后再试。"
        }
        _ => return None,
    };
    Some(friendly)
}

fn is_payment_configuration_message(message: &str) -> bool {
    matches!(
        message,
        "payment_type is required"
            | "out_trade_no is required"
            | "amount_cents must not be negative"
    ) || message.starts_with("gateway_url ")
        || message.starts_with("notify_url ")
        || message.starts_with("return_url ")
}

fn gift_card_business_user_message(message: &str) -> Option<&'static str> {
    let friendly = match message.trim() {
        "code is required" => "请输入礼品卡兑换码。",
        "礼品卡模板已禁用" => "这张礼品卡已停用，请联系发卡方。",
        "兑换码不可用或已达到使用次数" => "这张礼品卡已使用、已过期或已停用。",
        "用户不存在" => "当前账号不存在，请重新登录后再试。",
        "用户已禁用" => "当前账号已被停用，无法兑换礼品卡。",
        "套餐卡配置不完整" => "礼品卡的套餐权益配置不完整，请联系管理员。",
        "流量卡配置不完整" => "礼品卡的流量权益配置不完整，请联系管理员。",
        "关联套餐不存在或已删除" => "礼品卡关联的套餐不存在或已删除，请联系管理员。",
        "套餐或价格已不可用" | "plan or specification is unavailable" => {
            "礼品卡关联的套餐或规格已不可用，请联系管理员。"
        }
        "用户暂无该套餐的有效订阅" | "user has no active subscription for this plan" => {
            "当前账号没有该套餐的有效订阅，无法领取这份流量权益。"
        }
        "用户暂无有效订阅" | "user has no active subscription" => {
            "当前账号暂无有效订阅，无法领取这份流量权益。"
        }
        "invalid balance" => "礼品卡金额配置异常，请联系管理员。",
        "invalid plan period" => "礼品卡套餐周期配置异常，请联系管理员。",
        _ => return None,
    };
    Some(friendly)
}

fn gift_card_reason_user_message(reason: &str) -> &'static str {
    let reason = reason.trim();
    if reason.is_empty() {
        return "";
    }
    gift_card_business_user_message(reason)
        .unwrap_or("这张礼品卡当前无法兑换，请稍后重试或联系管理员。")
}

fn support_ticket_business_user_message(message: &str) -> Option<&'static str> {
    let friendly = match message.trim() {
        "support ticket title is required" => "请输入工单标题。",
        "support ticket title is too long" => "工单标题不能超过 128 个字符。",
        "support ticket priority is invalid" => "请选择有效的优先级。",
        "support ticket message is required" => "请输入消息内容。",
        "support ticket message is too large" => "消息内容过长，请精简后重试。",
        "support ticket is closed" => "该工单已关闭，刷新后可继续发送消息并自动重新打开。",
        _ => return None,
    };
    Some(friendly)
}

fn normalize_gift_card_code(value: &str) -> Result<String, PanelError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PanelError::InvalidResponse(
            "礼品卡兑换码不能为空".to_owned(),
        ));
    }
    if value.chars().count() > 96 {
        return Err(PanelError::InvalidResponse("礼品卡兑换码过长".to_owned()));
    }
    if value.chars().any(char::is_control) {
        return Err(PanelError::InvalidResponse(
            "礼品卡兑换码格式无效".to_owned(),
        ));
    }
    Ok(value.to_uppercase())
}

fn validate_affiliate_pagination(page: u32, page_size: u8) -> Result<(), PanelError> {
    if page == 0 || page_size == 0 || page_size > 100 {
        return Err(PanelError::InvalidResponse(
            "邀请记录分页参数无效".to_owned(),
        ));
    }
    Ok(())
}

fn validate_ticket_pagination(page: u32, page_size: u8) -> Result<(), PanelError> {
    if page == 0 || page_size == 0 || page_size > 100 {
        return Err(PanelError::InvalidResponse("工单分页参数无效".to_owned()));
    }
    Ok(())
}

fn normalize_ticket_title(value: &str) -> Result<String, PanelError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PanelError::InvalidResponse("工单标题不能为空".to_owned()));
    }
    if value.chars().count() > 128 {
        return Err(PanelError::InvalidResponse("工单标题过长".to_owned()));
    }
    if value.chars().any(char::is_control) {
        return Err(PanelError::InvalidResponse("工单标题格式无效".to_owned()));
    }
    Ok(value.to_owned())
}

fn normalize_ticket_message(value: &str) -> Result<String, PanelError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PanelError::InvalidResponse("工单消息不能为空".to_owned()));
    }
    if value.len() > 64 * 1_024 {
        return Err(PanelError::InvalidResponse("工单消息过长".to_owned()));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(PanelError::InvalidResponse("工单消息格式无效".to_owned()));
    }
    Ok(value.to_owned())
}

#[async_trait]
pub trait PanelRepository: Send + Sync {
    async fn restore_session(&self) -> Result<Option<UserIdentity>, PanelError>;
    async fn login(&self, credentials: &LoginCredentials) -> Result<UserIdentity, PanelError>;
    async fn logout(&self) -> Result<(), PanelError>;
    async fn profile(&self) -> Result<UserIdentity, PanelError>;
    async fn change_password(&self, change: &PasswordChange) -> Result<(), PanelError>;
    async fn subscription_link(&self) -> Result<SubscriptionLink, PanelError>;
    async fn reset_subscription(&self) -> Result<(), PanelError>;
    async fn balance_transactions(&self, limit: u8) -> Result<Vec<BalanceTransaction>, PanelError>;
    async fn orders(
        &self,
        filter: UserOrderFilter,
        page: u32,
        page_size: u8,
    ) -> Result<UserOrderPage, PanelError>;
    async fn support_tickets(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<SupportTicketPage, PanelError>;
    async fn support_ticket(
        &self,
        id: u64,
        message_page: u32,
        message_page_size: u8,
    ) -> Result<SupportTicketDetail, PanelError>;
    async fn create_support_ticket(
        &self,
        draft: &SupportTicketDraft,
    ) -> Result<SupportTicketDetail, PanelError>;
    async fn reply_support_ticket(
        &self,
        id: u64,
        content: &str,
    ) -> Result<SupportTicketDetail, PanelError>;
    async fn close_support_ticket(&self, id: u64) -> Result<SupportTicketAction, PanelError>;
    async fn gift_card_config(&self) -> Result<GiftCardConfig, PanelError>;
    async fn check_gift_card(&self, code: &str) -> Result<GiftCardRedeemCheck, PanelError>;
    async fn redeem_gift_card(&self, code: &str) -> Result<GiftCardRewardPreview, PanelError>;
    async fn affiliate_summary(&self) -> Result<AffiliateSummary, PanelError>;
    async fn affiliate_commissions(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<AffiliateCommissionPage, PanelError>;
    async fn affiliate_transfers(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<AffiliateTransferPage, PanelError>;
    async fn resources(&self) -> Result<Vec<ServerGroup>, PanelError>;
    async fn shop_catalog(&self) -> Result<ShopCatalog, PanelError>;
    async fn check_coupon(
        &self,
        selection: &ShopOrderSelection,
    ) -> Result<ShopCouponQuote, PanelError>;
    async fn create_order(&self, selection: &ShopOrderSelection) -> Result<ShopOrder, PanelError>;
    async fn pay_order(
        &self,
        order_id: u64,
        payment: ShopPaymentChoice,
    ) -> Result<ShopOrder, PanelError>;
    async fn get_order(&self, order_id: u64) -> Result<ShopOrder, PanelError>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccountPhase {
    #[default]
    Restoring,
    SignedOut,
    Authenticating,
    LoadingResources,
    RefreshingResources,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AccountSnapshot {
    pub phase: AccountPhase,
    pub user: Option<UserIdentity>,
    pub groups: Vec<ServerGroup>,
    pub message: Option<String>,
}

impl AccountSnapshot {
    pub const fn is_authenticated(&self) -> bool {
        self.user.is_some()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShopPhase {
    #[default]
    Idle,
    Loading,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShopSnapshot {
    pub phase: ShopPhase,
    pub catalog: ShopCatalog,
    pub purchasing: bool,
    pub message: Option<String>,
}

pub struct PanelCoordinator {
    repository: Arc<dyn PanelRepository>,
    state_tx: watch::Sender<AccountSnapshot>,
    shop_tx: watch::Sender<ShopSnapshot>,
    operation_gate: Mutex<()>,
    shop_operation_gate: Mutex<()>,
    gift_card_operation_gate: Mutex<()>,
    subscription_operation_gate: Mutex<()>,
    support_ticket_operation_gate: Mutex<()>,
}

impl fmt::Debug for PanelCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PanelCoordinator")
            .finish_non_exhaustive()
    }
}

impl PanelCoordinator {
    pub fn new(repository: Arc<dyn PanelRepository>) -> Self {
        let (state_tx, _) = watch::channel(AccountSnapshot::default());
        let (shop_tx, _) = watch::channel(ShopSnapshot::default());
        Self {
            repository,
            state_tx,
            shop_tx,
            operation_gate: Mutex::new(()),
            shop_operation_gate: Mutex::new(()),
            gift_card_operation_gate: Mutex::new(()),
            subscription_operation_gate: Mutex::new(()),
            support_ticket_operation_gate: Mutex::new(()),
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<AccountSnapshot> {
        self.state_tx.subscribe()
    }

    pub fn subscribe_shop(&self) -> watch::Receiver<ShopSnapshot> {
        self.shop_tx.subscribe()
    }

    /// Restores a credential-vault session and loads its resources.
    ///
    /// # Errors
    ///
    /// Returns a Panel or credential-store error.
    pub async fn restore(&self) -> Result<(), PanelError> {
        let _guard = self.operation_gate.lock().await;
        self.publish(AccountSnapshot::default());
        self.publish_shop(ShopSnapshot::default());
        match self.repository.restore_session().await {
            Ok(Some(user)) => self.load_resources(user).await,
            Ok(None) => {
                self.publish(AccountSnapshot {
                    phase: AccountPhase::SignedOut,
                    ..AccountSnapshot::default()
                });
                Ok(())
            }
            Err(error) => {
                self.publish_failure(None, Vec::new(), &error);
                Err(error)
            }
        }
    }

    /// Authenticates and loads the account's connectable resources.
    ///
    /// # Errors
    ///
    /// Returns [`PanelError::Busy`] for concurrent account operations or the
    /// repository failure from login/resource loading.
    pub async fn login(&self, credentials: LoginCredentials) -> Result<(), PanelError> {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        self.publish(AccountSnapshot {
            phase: AccountPhase::Authenticating,
            ..AccountSnapshot::default()
        });
        self.publish_shop(ShopSnapshot::default());
        let user = match self.repository.login(&credentials).await {
            Ok(user) => user,
            Err(error) => {
                self.publish(AccountSnapshot {
                    phase: AccountPhase::SignedOut,
                    message: Some(error.login_message().to_owned()),
                    ..AccountSnapshot::default()
                });
                return Err(error);
            }
        };
        self.load_resources(user).await
    }

    /// Reloads server groups for the active account.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another account operation is active, or
    /// the Panel request fails.
    pub async fn refresh_resources(&self) -> Result<(), PanelError> {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        let current = self.state_tx.borrow().clone();
        let user = current.user.clone().ok_or(PanelError::NoSession)?;
        self.publish(AccountSnapshot {
            phase: AccountPhase::RefreshingResources,
            user: Some(user.clone()),
            groups: current.groups.clone(),
            message: None,
        });
        match self.repository.resources().await {
            Ok(groups) => {
                self.publish(AccountSnapshot {
                    phase: AccountPhase::Ready,
                    user: Some(user),
                    groups,
                    message: None,
                });
                Ok(())
            }
            Err(error) => {
                self.publish_failure(Some(user), current.groups, &error);
                Err(error)
            }
        }
    }

    /// Reloads the current user's live profile without disturbing resources.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another account operation is active, or
    /// the Panel request fails.
    pub async fn refresh_profile(&self) -> Result<(), PanelError> {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        let current = self.state_tx.borrow().clone();
        let previous_user = current.user.clone().ok_or(PanelError::NoSession)?;
        match self.repository.profile().await {
            Ok(user) => {
                self.publish(AccountSnapshot {
                    user: Some(user),
                    message: None,
                    ..current
                });
                Ok(())
            }
            Err(error) => {
                if error.invalidates_session() {
                    self.publish_failure(Some(previous_user), current.groups, &error);
                }
                Err(error)
            }
        }
    }

    /// Changes the login password and signs the local account out after the
    /// Panel revokes its sessions.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another account operation is active, or
    /// the Panel rejects the password change.
    pub async fn change_password(&self, change: PasswordChange) -> Result<(), PanelError> {
        let _guard = self
            .operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.change_password(&change).await {
            Ok(()) => {
                self.publish(AccountSnapshot {
                    phase: AccountPhase::SignedOut,
                    ..AccountSnapshot::default()
                });
                self.publish_shop(ShopSnapshot::default());
                Ok(())
            }
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads the current credential-bearing subscription link.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another subscription-link operation is
    /// active, or the Panel request fails.
    pub async fn subscription_link(&self) -> Result<SubscriptionLink, PanelError> {
        let _guard = self
            .subscription_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.subscription_link().await {
            Ok(link) => Ok(link),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Invalidates the current subscription link and asks the Panel to issue
    /// a new credential.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another subscription-link operation is
    /// active, or the Panel rejects the reset.
    pub async fn reset_subscription(&self) -> Result<(), PanelError> {
        let _guard = self
            .subscription_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.reset_subscription().await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads the most recent balance transactions without disturbing the
    /// resource snapshot.
    ///
    /// # Errors
    ///
    /// Returns when no session exists or the Panel request fails.
    pub async fn balance_transactions(
        &self,
        limit: u8,
    ) -> Result<Vec<BalanceTransaction>, PanelError> {
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        if limit == 0 || limit > 100 {
            return Err(PanelError::InvalidResponse("余额明细数量无效".to_owned()));
        }
        match self.repository.balance_transactions(limit).await {
            Ok(transactions) => Ok(transactions),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads one page of the authenticated user's order history without
    /// changing the shop or resource snapshots.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, pagination is invalid, or the Panel
    /// request fails.
    pub async fn orders(
        &self,
        filter: UserOrderFilter,
        page: u32,
        page_size: u8,
    ) -> Result<UserOrderPage, PanelError> {
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        if page == 0 || page_size == 0 || page_size > 100 {
            return Err(PanelError::InvalidResponse("订单分页参数无效".to_owned()));
        }
        match self.repository.orders(filter, page, page_size).await {
            Ok(orders) => Ok(orders),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads one page of the authenticated user's support conversations.
    ///
    /// # Errors
    ///
    /// Returns when pagination is invalid, no session exists, another ticket
    /// operation is running, or the Panel request fails.
    pub async fn support_tickets(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<SupportTicketPage, PanelError> {
        validate_ticket_pagination(page, page_size)?;
        let _guard = self
            .support_ticket_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.support_tickets(page, page_size).await {
            Ok(tickets) => Ok(tickets),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads one page of messages and marks administrator replies as read.
    ///
    /// # Errors
    ///
    /// Returns when the ticket or pagination is invalid, no session exists,
    /// another ticket operation is running, or the Panel request fails.
    pub async fn support_ticket(
        &self,
        id: u64,
        message_page: u32,
        message_page_size: u8,
    ) -> Result<SupportTicketDetail, PanelError> {
        validate_ticket_pagination(message_page, message_page_size)?;
        if id == 0 {
            return Err(PanelError::InvalidResponse("工单信息无效".to_owned()));
        }
        let _guard = self
            .support_ticket_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self
            .repository
            .support_ticket(id, message_page, message_page_size)
            .await
        {
            Ok(ticket) => Ok(ticket),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Creates a new conversation and its first user message.
    ///
    /// # Errors
    ///
    /// Returns when the draft is invalid, no session exists, another ticket
    /// operation is running, or the Panel request fails.
    pub async fn create_support_ticket(
        &self,
        draft: &SupportTicketDraft,
    ) -> Result<SupportTicketDetail, PanelError> {
        let draft = SupportTicketDraft {
            title: normalize_ticket_title(&draft.title)?,
            priority: match draft.priority {
                SupportTicketPriority::Low
                | SupportTicketPriority::Medium
                | SupportTicketPriority::High => draft.priority,
                SupportTicketPriority::Unknown => {
                    return Err(PanelError::InvalidResponse("工单优先级无效".to_owned()));
                }
            },
            message: normalize_ticket_message(&draft.message)?,
        };
        let _guard = self
            .support_ticket_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.create_support_ticket(&draft).await {
            Ok(ticket) => Ok(ticket),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Sends a message. The Panel reopens closed tickets automatically.
    ///
    /// # Errors
    ///
    /// Returns when the ticket or message is invalid, no session exists,
    /// another ticket operation is running, or the Panel request fails.
    pub async fn reply_support_ticket(
        &self,
        id: u64,
        content: &str,
    ) -> Result<SupportTicketDetail, PanelError> {
        if id == 0 {
            return Err(PanelError::InvalidResponse("工单信息无效".to_owned()));
        }
        let content = normalize_ticket_message(content)?;
        let _guard = self
            .support_ticket_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.reply_support_ticket(id, &content).await {
            Ok(ticket) => Ok(ticket),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Closes a conversation while retaining all history.
    ///
    /// # Errors
    ///
    /// Returns when the ticket is invalid, no session exists, another ticket
    /// operation is running, or the Panel request fails.
    pub async fn close_support_ticket(&self, id: u64) -> Result<SupportTicketAction, PanelError> {
        if id == 0 {
            return Err(PanelError::InvalidResponse("工单信息无效".to_owned()));
        }
        let _guard = self
            .support_ticket_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.close_support_ticket(id).await {
            Ok(action) => Ok(action),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads user-facing gift-card configuration.
    ///
    /// # Errors
    ///
    /// Returns when no session exists or the Panel request fails.
    pub async fn gift_card_config(&self) -> Result<GiftCardConfig, PanelError> {
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.gift_card_config().await {
            Ok(config) => Ok(config),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Checks a normalized gift-card code without consuming it.
    ///
    /// # Errors
    ///
    /// Returns for invalid input, no session, a concurrent gift-card action,
    /// or a Panel failure.
    pub async fn check_gift_card(&self, code: &str) -> Result<GiftCardRedeemCheck, PanelError> {
        let _guard = self
            .gift_card_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        let code = normalize_gift_card_code(code)?;
        match self.repository.check_gift_card(&code).await {
            Ok(mut check) => {
                check.reason = gift_card_reason_user_message(&check.reason).to_owned();
                Ok(check)
            }
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Redeems a normalized gift-card code.
    ///
    /// # Errors
    ///
    /// Returns for invalid input, no session, a concurrent gift-card action,
    /// or a Panel failure.
    pub async fn redeem_gift_card(&self, code: &str) -> Result<GiftCardRewardPreview, PanelError> {
        let _guard = self
            .gift_card_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        let code = normalize_gift_card_code(code)?;
        match self.repository.redeem_gift_card(&code).await {
            Ok(reward) => Ok(reward),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads the authenticated user's invitation and commission overview.
    ///
    /// # Errors
    ///
    /// Returns when no session exists or the Panel request fails.
    pub async fn affiliate_summary(&self) -> Result<AffiliateSummary, PanelError> {
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.affiliate_summary().await {
            Ok(summary) => Ok(summary),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads one page of commission records.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, pagination is invalid, or the Panel
    /// request fails.
    pub async fn affiliate_commissions(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<AffiliateCommissionPage, PanelError> {
        validate_affiliate_pagination(page, page_size)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.affiliate_commissions(page, page_size).await {
            Ok(commissions) => Ok(commissions),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads one page of commission-to-balance transfers.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, pagination is invalid, or the Panel
    /// request fails.
    pub async fn affiliate_transfers(
        &self,
        page: u32,
        page_size: u8,
    ) -> Result<AffiliateTransferPage, PanelError> {
        validate_affiliate_pagination(page, page_size)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        match self.repository.affiliate_transfers(page, page_size).await {
            Ok(transfers) => Ok(transfers),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Loads the independently purchasable plan and payment catalog.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another shop operation is active, or
    /// the Panel request fails.
    pub async fn refresh_shop(&self) -> Result<(), PanelError> {
        let _guard = self
            .shop_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        let current = self.shop_tx.borrow().clone();
        self.publish_shop(ShopSnapshot {
            phase: ShopPhase::Loading,
            message: None,
            ..current.clone()
        });
        match self.repository.shop_catalog().await {
            Ok(catalog) => {
                self.publish_shop(ShopSnapshot {
                    phase: ShopPhase::Ready,
                    catalog,
                    purchasing: false,
                    message: None,
                });
                Ok(())
            }
            Err(error) => {
                self.publish_shop(ShopSnapshot {
                    phase: ShopPhase::Failed,
                    purchasing: false,
                    message: Some(error.user_message().to_owned()),
                    ..current
                });
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Validates a coupon against the selected catalog item and returns a
    /// preview quote. Order creation remains authoritative and re-quotes it.
    ///
    /// # Errors
    ///
    /// Returns when the selection or coupon is invalid, no session exists,
    /// another shop operation is active, or the Panel request fails.
    pub async fn check_coupon(
        &self,
        selection: ShopOrderSelection,
    ) -> Result<ShopCouponQuote, PanelError> {
        let _guard = self
            .shop_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        let current = self.shop_tx.borrow().clone();
        validate_shop_selection(&current.catalog, &selection)?;
        if selection
            .coupon_code
            .as_deref()
            .is_none_or(|code| code.trim().is_empty())
        {
            return Err(PanelError::InvalidResponse("请输入优惠码".to_owned()));
        }
        self.publish_shop(ShopSnapshot {
            purchasing: true,
            message: None,
            ..current.clone()
        });
        match self.repository.check_coupon(&selection).await {
            Ok(quote) => {
                self.publish_shop(ShopSnapshot {
                    purchasing: false,
                    message: None,
                    ..current
                });
                Ok(quote)
            }
            Err(error) => {
                self.publish_shop(ShopSnapshot {
                    purchasing: false,
                    message: None,
                    ..current
                });
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Creates an order from a validated catalog selection. The amount in the
    /// returned order is the authoritative server quote.
    ///
    /// # Errors
    ///
    /// Returns when the selection is stale, no session exists, another shop
    /// operation is active, or the Panel request fails.
    pub async fn create_order(
        &self,
        selection: ShopOrderSelection,
    ) -> Result<ShopOrder, PanelError> {
        let _guard = self
            .shop_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        let current = self.shop_tx.borrow().clone();
        validate_shop_selection(&current.catalog, &selection)?;
        self.publish_shop(ShopSnapshot {
            purchasing: true,
            message: None,
            ..current.clone()
        });
        match self.repository.create_order(&selection).await {
            Ok(order) => {
                self.publish_shop(ShopSnapshot {
                    purchasing: false,
                    message: None,
                    ..current
                });
                Ok(order)
            }
            Err(error) => {
                self.publish_shop(ShopSnapshot {
                    purchasing: false,
                    message: None,
                    ..current
                });
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Starts payment for an existing order using exactly one payment route.
    ///
    /// # Errors
    ///
    /// Returns when the selected provider is stale, no session exists, another
    /// shop operation is active, or the Panel request fails.
    pub async fn pay_order(
        &self,
        order_id: u64,
        payment: ShopPaymentChoice,
    ) -> Result<ShopOrder, PanelError> {
        let _guard = self
            .shop_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        if order_id == 0 {
            return Err(PanelError::InvalidResponse("订单标识无效".to_owned()));
        }
        let current = self.shop_tx.borrow().clone();
        validate_shop_payment(&current.catalog, payment)?;
        self.publish_shop(ShopSnapshot {
            purchasing: true,
            message: None,
            ..current.clone()
        });
        match self.repository.pay_order(order_id, payment).await {
            Ok(order) => {
                self.publish_shop(ShopSnapshot {
                    purchasing: false,
                    message: None,
                    ..current
                });
                Ok(order)
            }
            Err(error) => {
                self.publish_shop(ShopSnapshot {
                    purchasing: false,
                    message: None,
                    ..current
                });
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Fetches the latest order state without replacing its creation/payment
    /// session. Callers should merge this status update with the current order.
    ///
    /// # Errors
    ///
    /// Returns when no session exists, another shop operation is active, or
    /// the Panel request fails. A hidden self-created pending order is exposed
    /// as a recognizable 404001 [`PanelError::Business`].
    pub async fn get_order(&self, order_id: u64) -> Result<ShopOrder, PanelError> {
        let _guard = self
            .shop_operation_gate
            .try_lock()
            .map_err(|_| PanelError::Busy)?;
        if !self.state_tx.borrow().is_authenticated() {
            return Err(PanelError::NoSession);
        }
        if order_id == 0 {
            return Err(PanelError::InvalidResponse("订单标识无效".to_owned()));
        }
        match self.repository.get_order(order_id).await {
            Ok(order) => Ok(order),
            Err(error) => {
                self.publish_session_failure_if_needed(&error);
                Err(error)
            }
        }
    }

    /// Clears local credentials before requesting remote revocation.
    ///
    /// # Errors
    ///
    /// Returns a credential-store or remote-revocation error. The published
    /// state remains signed out when either cleanup step fails.
    pub async fn logout(&self) -> Result<(), PanelError> {
        let _guard = self.operation_gate.lock().await;
        let _shop_guard = self.shop_operation_gate.lock().await;
        self.publish(AccountSnapshot {
            phase: AccountPhase::SignedOut,
            ..AccountSnapshot::default()
        });
        self.publish_shop(ShopSnapshot::default());
        self.repository.logout().await
    }

    async fn load_resources(&self, user: UserIdentity) -> Result<(), PanelError> {
        self.publish(AccountSnapshot {
            phase: AccountPhase::LoadingResources,
            user: Some(user.clone()),
            ..AccountSnapshot::default()
        });
        match self.repository.resources().await {
            Ok(groups) => {
                self.publish(AccountSnapshot {
                    phase: AccountPhase::Ready,
                    user: Some(user),
                    groups,
                    message: None,
                });
                Ok(())
            }
            Err(error) => {
                self.publish_failure(Some(user), Vec::new(), &error);
                Err(error)
            }
        }
    }

    fn publish_failure(
        &self,
        user: Option<UserIdentity>,
        groups: Vec<ServerGroup>,
        error: &PanelError,
    ) {
        if error.invalidates_session() {
            self.publish(AccountSnapshot {
                phase: AccountPhase::SignedOut,
                message: Some(error.user_message().to_owned()),
                ..AccountSnapshot::default()
            });
            return;
        }
        self.publish(AccountSnapshot {
            phase: AccountPhase::Failed,
            user,
            groups,
            message: Some(error.user_message().to_owned()),
        });
    }

    fn publish_session_failure_if_needed(&self, error: &PanelError) {
        if !error.invalidates_session() {
            return;
        }
        let current = self.state_tx.borrow().clone();
        self.publish_failure(current.user, current.groups, error);
    }

    fn publish(&self, snapshot: AccountSnapshot) {
        self.state_tx.send_replace(snapshot);
    }

    fn publish_shop(&self, snapshot: ShopSnapshot) {
        self.shop_tx.send_replace(snapshot);
    }
}

fn validate_shop_selection(
    catalog: &ShopCatalog,
    selection: &ShopOrderSelection,
) -> Result<(), PanelError> {
    let plan = catalog
        .plans
        .iter()
        .find(|plan| plan.id == selection.plan_id)
        .ok_or_else(|| PanelError::InvalidResponse("商品信息已更新".to_owned()))?;
    let found = match selection.kind {
        ShopPurchaseKind::BasePlan => plan
            .prices
            .iter()
            .any(|price| price.id == selection.product_id),
        ShopPurchaseKind::TrafficAddon if plan.addon_available => plan
            .traffic_addons
            .iter()
            .any(|addon| addon.id == selection.product_id),
        ShopPurchaseKind::TrafficAddon => false,
    };
    if !found {
        return Err(PanelError::InvalidResponse("商品信息已更新".to_owned()));
    }
    Ok(())
}

fn validate_shop_payment(
    catalog: &ShopCatalog,
    payment: ShopPaymentChoice,
) -> Result<(), PanelError> {
    if let ShopPaymentChoice::Provider(payment_method_id) = payment
        && (payment_method_id == 0
            || !catalog
                .payment_methods
                .iter()
                .any(|method| method.id == payment_method_id))
    {
        return Err(PanelError::InvalidResponse("支付方式已更新".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use topnode_domain::{
        AffiliateCommissionPage, AffiliateSummary, AffiliateTransferPage, BalanceTransaction,
        GiftCardConfig, GiftCardRedeemCheck, GiftCardRewardPreview, GiftCardRewardType,
        ServerGroup, ShopCatalog, ShopCouponDiscountType, ShopCouponQuote, ShopOrder,
        ShopOrderSelection, ShopOrderStatus, ShopPaymentChoice, ShopPaymentMethod, ShopPlan,
        ShopPlanPrice, ShopPurchaseKind, ShopTrafficAddon, SubscriptionLink, SupportTicketAction,
        SupportTicketDetail, SupportTicketDraft, SupportTicketPage, SupportTicketStatus,
        UserIdentity, UserOrderFilter, UserOrderPage,
    };

    use super::{
        AccountPhase, LoginCredentials, PanelCoordinator, PanelError, PanelRepository,
        PasswordChange, gift_card_reason_user_message, normalize_gift_card_code,
        validate_shop_payment, validate_shop_selection,
    };

    #[derive(Debug)]
    struct FakePanel {
        restored: Option<UserIdentity>,
        purchase_error: Option<PanelError>,
    }

    #[async_trait]
    impl PanelRepository for FakePanel {
        async fn restore_session(&self) -> Result<Option<UserIdentity>, PanelError> {
            Ok(self.restored.clone())
        }

        async fn login(&self, _credentials: &LoginCredentials) -> Result<UserIdentity, PanelError> {
            Ok(user())
        }

        async fn logout(&self) -> Result<(), PanelError> {
            Ok(())
        }

        async fn profile(&self) -> Result<UserIdentity, PanelError> {
            Ok(user())
        }

        async fn change_password(&self, _change: &PasswordChange) -> Result<(), PanelError> {
            Ok(())
        }

        async fn subscription_link(&self) -> Result<SubscriptionLink, PanelError> {
            SubscriptionLink::new("https://panel.example/api/v1/subscription?uuid=secret")
                .ok_or_else(|| PanelError::InvalidResponse("invalid fake link".to_owned()))
        }

        async fn reset_subscription(&self) -> Result<(), PanelError> {
            Ok(())
        }

        async fn balance_transactions(
            &self,
            _limit: u8,
        ) -> Result<Vec<BalanceTransaction>, PanelError> {
            Ok(Vec::new())
        }

        async fn orders(
            &self,
            _filter: UserOrderFilter,
            page: u32,
            page_size: u8,
        ) -> Result<UserOrderPage, PanelError> {
            Ok(UserOrderPage {
                page,
                page_size,
                ..UserOrderPage::default()
            })
        }

        async fn support_tickets(
            &self,
            page: u32,
            page_size: u8,
        ) -> Result<SupportTicketPage, PanelError> {
            Ok(SupportTicketPage {
                page,
                page_size,
                ..SupportTicketPage::default()
            })
        }

        async fn support_ticket(
            &self,
            _id: u64,
            message_page: u32,
            message_page_size: u8,
        ) -> Result<SupportTicketDetail, PanelError> {
            Ok(SupportTicketDetail {
                message_page,
                message_page_size,
                ..SupportTicketDetail::default()
            })
        }

        async fn create_support_ticket(
            &self,
            _draft: &SupportTicketDraft,
        ) -> Result<SupportTicketDetail, PanelError> {
            Ok(SupportTicketDetail::default())
        }

        async fn reply_support_ticket(
            &self,
            _id: u64,
            _content: &str,
        ) -> Result<SupportTicketDetail, PanelError> {
            Ok(SupportTicketDetail::default())
        }

        async fn close_support_ticket(&self, id: u64) -> Result<SupportTicketAction, PanelError> {
            Ok(SupportTicketAction {
                id,
                ticket_number: "TKT1".to_owned(),
                status: SupportTicketStatus::Closed,
            })
        }

        async fn gift_card_config(&self) -> Result<GiftCardConfig, PanelError> {
            Ok(GiftCardConfig::default())
        }

        async fn check_gift_card(&self, _code: &str) -> Result<GiftCardRedeemCheck, PanelError> {
            Ok(GiftCardRedeemCheck {
                reward: gift_card_reward(),
                can_redeem: true,
                reason: String::new(),
            })
        }

        async fn redeem_gift_card(&self, _code: &str) -> Result<GiftCardRewardPreview, PanelError> {
            Ok(gift_card_reward())
        }

        async fn affiliate_summary(&self) -> Result<AffiliateSummary, PanelError> {
            Ok(AffiliateSummary::default())
        }

        async fn affiliate_commissions(
            &self,
            page: u32,
            page_size: u8,
        ) -> Result<AffiliateCommissionPage, PanelError> {
            Ok(AffiliateCommissionPage {
                page,
                page_size,
                ..AffiliateCommissionPage::default()
            })
        }

        async fn affiliate_transfers(
            &self,
            page: u32,
            page_size: u8,
        ) -> Result<AffiliateTransferPage, PanelError> {
            Ok(AffiliateTransferPage {
                page,
                page_size,
                ..AffiliateTransferPage::default()
            })
        }

        async fn resources(&self) -> Result<Vec<ServerGroup>, PanelError> {
            Ok(vec![ServerGroup {
                id: 7,
                name: "Primary".to_owned(),
                connectable: true,
                total_quota_bytes: 100,
                used_bytes: 10,
                remaining_bytes: 90,
                next_expires_at_epoch_seconds: None,
                entitlements: Vec::new(),
                nodes: Vec::new(),
            }])
        }

        async fn shop_catalog(&self) -> Result<topnode_domain::ShopCatalog, PanelError> {
            Ok(shop_catalog())
        }

        async fn check_coupon(
            &self,
            _selection: &ShopOrderSelection,
        ) -> Result<ShopCouponQuote, PanelError> {
            if let Some(error) = &self.purchase_error {
                return Err(error.clone());
            }
            Ok(ShopCouponQuote {
                code: "SAVE10".to_owned(),
                name: "优惠码".to_owned(),
                discount_type: ShopCouponDiscountType::Amount,
                discount_summary: "减免 10 元".to_owned(),
                original_amount_cents: 2_900,
                discount_amount_cents: 1_000,
                payable_amount_cents: 1_900,
                currency: "CNY".to_owned(),
            })
        }

        async fn create_order(
            &self,
            _selection: &ShopOrderSelection,
        ) -> Result<ShopOrder, PanelError> {
            if let Some(error) = &self.purchase_error {
                return Err(error.clone());
            }
            Ok(order())
        }

        async fn pay_order(
            &self,
            _order_id: u64,
            _payment: ShopPaymentChoice,
        ) -> Result<ShopOrder, PanelError> {
            if let Some(error) = &self.purchase_error {
                return Err(error.clone());
            }
            Ok(order())
        }

        async fn get_order(&self, _order_id: u64) -> Result<ShopOrder, PanelError> {
            Ok(order())
        }
    }

    fn gift_card_reward() -> GiftCardRewardPreview {
        GiftCardRewardPreview {
            reward_type: GiftCardRewardType::Balance,
            summary: "余额 10 元".to_owned(),
            balance_amount_cents: 1_000,
            plan_id: None,
            plan_name: String::new(),
            plan_price_id: None,
            price_label: String::new(),
            group_id: None,
            group_name: String::new(),
            traffic_quota_bytes: 0,
        }
    }

    #[test]
    fn gift_card_business_failures_have_actionable_messages() {
        let cases = [
            ("code is required", "请输入礼品卡兑换码。"),
            ("礼品卡模板已禁用", "这张礼品卡已停用，请联系发卡方。"),
            (
                "兑换码不可用或已达到使用次数",
                "这张礼品卡已使用、已过期或已停用。",
            ),
            ("用户不存在", "当前账号不存在，请重新登录后再试。"),
            ("用户已禁用", "当前账号已被停用，无法兑换礼品卡。"),
            (
                "套餐卡配置不完整",
                "礼品卡的套餐权益配置不完整，请联系管理员。",
            ),
            (
                "流量卡配置不完整",
                "礼品卡的流量权益配置不完整，请联系管理员。",
            ),
            (
                "关联套餐不存在或已删除",
                "礼品卡关联的套餐不存在或已删除，请联系管理员。",
            ),
            (
                "套餐或价格已不可用",
                "礼品卡关联的套餐或规格已不可用，请联系管理员。",
            ),
            (
                "用户暂无该套餐的有效订阅",
                "当前账号没有该套餐的有效订阅，无法领取这份流量权益。",
            ),
            (
                "user has no active subscription for this plan",
                "当前账号没有该套餐的有效订阅，无法领取这份流量权益。",
            ),
            (
                "用户暂无有效订阅",
                "当前账号暂无有效订阅，无法领取这份流量权益。",
            ),
            (
                "user has no active subscription",
                "当前账号暂无有效订阅，无法领取这份流量权益。",
            ),
            ("invalid balance", "礼品卡金额配置异常，请联系管理员。"),
            (
                "invalid plan period",
                "礼品卡套餐周期配置异常，请联系管理员。",
            ),
        ];
        for (message, expected) in cases {
            let error = PanelError::Business {
                code: 400_002,
                message: message.to_owned(),
                request_id: Some("request-id".to_owned()),
            };
            assert_eq!(error.gift_card_user_message(), expected, "{message}");
        }
    }

    #[test]
    fn affiliate_failures_have_context_specific_messages() {
        let transport = PanelError::Transport("connection refused".to_owned());
        assert_eq!(
            transport.affiliate_user_message(),
            "暂时无法读取邀请信息，请检查网络后重试。"
        );

        let invalid = PanelError::InvalidResponse("bad timestamp".to_owned());
        assert_eq!(
            invalid.affiliate_user_message(),
            "邀请信息响应异常，请稍后重试。"
        );

        let server = PanelError::Business {
            code: 500_001,
            message: "load affiliate balances failed".to_owned(),
            request_id: Some("request-id".to_owned()),
        };
        assert_eq!(
            server.affiliate_user_message(),
            "邀请服务暂时不可用，请稍后重试。"
        );
    }

    #[test]
    fn subscription_link_failures_are_safe_and_context_specific() {
        let transport = PanelError::Transport(
            "GET https://panel.example/api/v1/subscription?uuid=secret failed".to_owned(),
        );
        assert_eq!(
            transport.subscription_link_user_message(),
            "暂时无法连接订阅链接服务，请检查网络后重试。"
        );

        let invalid = PanelError::InvalidResponse("secret was malformed".to_owned());
        assert_eq!(
            invalid.subscription_link_user_message(),
            "订阅链接响应异常，请稍后重试。"
        );

        let server = PanelError::Business {
            code: 500_001,
            message: "reset subscription failed".to_owned(),
            request_id: Some("request-id".to_owned()),
        };
        assert_eq!(
            server.subscription_link_user_message(),
            "订阅链接服务暂时不可用，请稍后重试。"
        );
    }

    #[test]
    fn gift_card_not_found_and_plan_unavailable_codes_are_specific() {
        let not_found = PanelError::Business {
            code: 404_001,
            message: "not found".to_owned(),
            request_id: None,
        };
        assert_eq!(
            not_found.gift_card_user_message(),
            "未找到这张礼品卡，请检查兑换码是否输入正确。"
        );
        let unavailable = PanelError::Business {
            code: 409_017,
            message: "plan or specification is unavailable".to_owned(),
            request_id: None,
        };
        assert_eq!(
            unavailable.gift_card_user_message(),
            "礼品卡关联的套餐或规格已不可用，请联系管理员。"
        );
    }

    #[test]
    fn gift_card_check_reasons_never_expose_unknown_server_text() {
        assert_eq!(gift_card_reason_user_message(""), "");
        assert_eq!(
            gift_card_reason_user_message("database table gift_codes missing"),
            "这张礼品卡当前无法兑换，请稍后重试或联系管理员。"
        );
    }

    #[test]
    fn gift_card_codes_are_trimmed_and_normalized() {
        assert_eq!(
            normalize_gift_card_code("  gift-ab12  ").expect("valid gift-card code"),
            "GIFT-AB12"
        );
        assert!(normalize_gift_card_code("  ").is_err());
        assert!(normalize_gift_card_code(&"a".repeat(97)).is_err());
        assert!(normalize_gift_card_code("line\nbreak").is_err());
    }

    #[tokio::test]
    async fn restore_loads_resources_for_saved_session() {
        let coordinator = PanelCoordinator::new(Arc::new(FakePanel {
            restored: Some(user()),
            purchase_error: None,
        }));
        let state = coordinator.subscribe();

        coordinator.restore().await.expect("restore succeeds");

        assert_eq!(state.borrow().phase, AccountPhase::Ready);
        assert_eq!(state.borrow().groups.len(), 1);
    }

    #[tokio::test]
    async fn missing_session_publishes_signed_out() {
        let coordinator = PanelCoordinator::new(Arc::new(FakePanel {
            restored: None,
            purchase_error: None,
        }));
        let state = coordinator.subscribe();

        coordinator.restore().await.expect("restore succeeds");

        assert_eq!(state.borrow().phase, AccountPhase::SignedOut);
    }

    #[test]
    fn unauthorized_failure_drops_the_authenticated_snapshot() {
        let coordinator = PanelCoordinator::new(Arc::new(FakePanel {
            restored: None,
            purchase_error: None,
        }));

        coordinator.publish_failure(Some(user()), Vec::new(), &PanelError::Unauthorized);

        let snapshot = coordinator.subscribe().borrow().clone();
        assert_eq!(snapshot.phase, AccountPhase::SignedOut);
        assert!(snapshot.user.is_none());
    }

    #[test]
    fn login_credentials_redact_password() {
        let credentials = LoginCredentials::new("user@example.com", "do-not-print");
        assert!(!format!("{credentials:?}").contains("do-not-print"));
    }

    #[test]
    fn password_change_redacts_both_passwords() {
        let change = PasswordChange::new("old-secret", "new-secret");
        let debug = format!("{change:?}");
        assert!(!debug.contains("old-secret"));
        assert!(!debug.contains("new-secret"));
    }

    #[tokio::test]
    async fn successful_password_change_signs_the_account_out() {
        let coordinator = PanelCoordinator::new(Arc::new(FakePanel {
            restored: Some(user()),
            purchase_error: None,
        }));
        coordinator.restore().await.expect("restore succeeds");

        coordinator
            .change_password(PasswordChange::new("password123", "newpassword123"))
            .await
            .expect("password change succeeds");

        let snapshot = coordinator.subscribe().borrow().clone();
        assert_eq!(snapshot.phase, AccountPhase::SignedOut);
        assert!(snapshot.user.is_none());
    }

    #[test]
    fn product_messages_do_not_expose_panel_internals() {
        let error = PanelError::Business {
            code: 500_001,
            message: "database shard unavailable".to_owned(),
            request_id: Some("request-secret".to_owned()),
        };

        let message = error.user_message();
        assert!(!message.contains("Panel"));
        assert!(!message.contains("database"));
        assert!(!message.contains("request-secret"));
    }

    #[test]
    fn login_unauthorized_has_a_clear_customer_action() {
        assert_eq!(
            PanelError::Unauthorized.login_message(),
            "邮箱或密码错误，请重新输入。"
        );
    }

    #[test]
    fn login_errors_are_contextual_and_do_not_reveal_account_existence() {
        for code in [401_001, 404_002] {
            let error = PanelError::Business {
                code,
                message: "server authentication detail".to_owned(),
                request_id: Some("private-request".to_owned()),
            };
            assert_eq!(error.login_message(), "邮箱或密码错误，请重新输入。");
        }

        let disabled = PanelError::Business {
            code: 403_001,
            message: "user disabled".to_owned(),
            request_id: None,
        };
        let locked = PanelError::Business {
            code: 429_003,
            message: "login temporarily locked".to_owned(),
            request_id: None,
        };
        assert_eq!(disabled.login_message(), "账号已被停用，请联系管理员。");
        assert_eq!(
            locked.login_message(),
            "登录失败次数过多，账号已暂时锁定，请稍后再试。"
        );
    }

    #[test]
    fn product_business_codes_have_actionable_messages() {
        let cases = [
            (403_001, "账号已被停用，请联系管理员。"),
            (409_011, "该套餐已有有效订阅，暂不支持重复购买。"),
            (409_017, "该套餐或规格已下架，请刷新商品列表后重试。"),
            (
                409_023,
                "当前客户端版本不支持服务端运行配置，请升级客户端。",
            ),
            (
                409_024,
                "客户端与服务端配置版本不兼容，请升级客户端或联系管理员。",
            ),
            (
                409_025,
                "当前订阅已失效、流量已用尽或已过期，请刷新订阅后重试。",
            ),
            (409_026, "所选节点已离线或不可用，请重新选择节点。"),
        ];

        for (code, expected) in cases {
            let error = PanelError::Business {
                code,
                message: "untrusted server detail".to_owned(),
                request_id: Some("private-request".to_owned()),
            };
            assert_eq!(error.user_message(), expected);
        }
    }

    #[test]
    fn shop_errors_match_the_panel_contract_without_exposing_server_text() {
        let cases = [
            ("coupon_code is required", "请输入优惠码。"),
            ("coupon is invalid", "优惠码无效，请检查后重试。"),
            ("coupon is not active yet", "优惠码尚未生效。"),
            ("coupon has expired", "优惠码已过期。"),
            ("coupon usage limit reached", "优惠码已被使用完。"),
            (
                "coupon user usage limit reached",
                "你已达到该优惠码的使用次数上限。",
            ),
            (
                "coupon is not available for this plan",
                "该优惠码不适用于当前套餐。",
            ),
            (
                "coupon is not available for this spec",
                "该优惠码不适用于当前规格。",
            ),
            (
                "plan price is disabled",
                "当前套餐规格暂不可购买，请刷新商品列表后重新选择。",
            ),
            (
                "traffic addon is disabled",
                "当前流量包暂不可购买，请刷新商品列表后重新选择。",
            ),
            (
                "user has no active subscription for this plan",
                "当前账户没有该套餐的有效订阅，暂不能购买此流量包。",
            ),
            ("payment_method_id is required", "请选择支付方式。"),
            (
                "payment method is not available",
                "该支付方式暂不可用，请选择其他方式。",
            ),
            ("insufficient balance", "账户余额不足，请选择其他支付方式。"),
            (
                "order payment is already pending",
                "该订单已发起支付，请完成当前支付。",
            ),
            ("order is not pending", "订单状态已发生变化，请刷新后重试。"),
            (
                "order does not require payment",
                "该订单无需再次支付，请刷新订单状态。",
            ),
            (
                "payment provider config is incomplete",
                "支付渠道暂不可用，请选择其他方式或稍后再试。",
            ),
        ];

        for (server_message, expected) in cases {
            let error = PanelError::Business {
                code: 400_002,
                message: server_message.to_owned(),
                request_id: Some("private-request".to_owned()),
            };
            let customer_message = error.shop_user_message();
            assert_eq!(customer_message, expected);
            assert!(!customer_message.contains(server_message));
            assert!(!customer_message.contains("private-request"));
        }
    }

    #[tokio::test]
    async fn checkout_failures_do_not_pollute_the_catalog_error_state() {
        let purchase_error = PanelError::Business {
            code: 400_002,
            message: "coupon is invalid".to_owned(),
            request_id: Some("request-1".to_owned()),
        };
        let coordinator = PanelCoordinator::new(Arc::new(FakePanel {
            restored: Some(user()),
            purchase_error: Some(purchase_error),
        }));
        coordinator.restore().await.expect("restore succeeds");
        coordinator
            .refresh_shop()
            .await
            .expect("catalog load succeeds");
        let selection = ShopOrderSelection {
            kind: ShopPurchaseKind::BasePlan,
            plan_id: 7,
            product_id: 8,
            coupon_code: Some("SAVE20".to_owned()),
        };

        assert!(coordinator.check_coupon(selection.clone()).await.is_err());
        assert!(coordinator.create_order(selection).await.is_err());
        assert!(
            coordinator
                .pay_order(1, ShopPaymentChoice::Provider(3))
                .await
                .is_err()
        );

        let snapshot = coordinator.subscribe_shop().borrow().clone();
        assert_eq!(snapshot.phase, super::ShopPhase::Ready);
        assert!(!snapshot.purchasing);
        assert!(snapshot.message.is_none());
    }

    #[test]
    fn disabled_account_is_a_session_failure_with_a_specific_message() {
        let error = PanelError::Business {
            code: 403_001,
            message: "user disabled".to_owned(),
            request_id: None,
        };

        assert!(error.invalidates_session());
        assert_eq!(error.user_message(), "账号已被停用，请联系管理员。");
    }

    #[test]
    fn support_ticket_failures_are_specific_without_leaking_server_diagnostics() {
        let cases = [
            (
                PanelError::Business {
                    code: 404_001,
                    message: "database row missing".to_owned(),
                    request_id: Some("private-request".to_owned()),
                },
                "该工单不存在或已被删除，请返回刷新列表。",
            ),
            (
                PanelError::Business {
                    code: 400_002,
                    message: "support ticket message is required".to_owned(),
                    request_id: Some("private-request".to_owned()),
                },
                "请输入消息内容。",
            ),
            (
                PanelError::Transport("secret upstream address".to_owned()),
                "暂时无法连接工单服务，请检查网络后重试。",
            ),
        ];

        for (error, expected) in cases {
            let customer_message = error.support_ticket_user_message();
            assert_eq!(customer_message, expected);
            assert!(!customer_message.contains("private-request"));
            assert!(!customer_message.contains("secret"));
        }
    }

    #[test]
    fn shop_selection_and_payment_are_revalidated_against_the_loaded_catalog() {
        let catalog = shop_catalog();
        let plan = ShopOrderSelection {
            kind: ShopPurchaseKind::BasePlan,
            plan_id: 7,
            product_id: 8,
            coupon_code: None,
        };
        assert!(validate_shop_selection(&catalog, &plan).is_ok());
        assert!(validate_shop_payment(&catalog, ShopPaymentChoice::Provider(3)).is_ok());
        assert!(validate_shop_payment(&catalog, ShopPaymentChoice::Balance).is_ok());
        assert!(validate_shop_payment(&catalog, ShopPaymentChoice::Provider(4)).is_err());

        let missing_plan = ShopOrderSelection {
            product_id: 11,
            ..plan
        };
        assert!(validate_shop_selection(&catalog, &missing_plan).is_err());

        let disabled_addon = ShopOrderSelection {
            kind: ShopPurchaseKind::TrafficAddon,
            plan_id: 7,
            product_id: 9,
            coupon_code: None,
        };
        assert!(validate_shop_selection(&catalog, &disabled_addon).is_err());
    }

    #[test]
    fn pending_order_visibility_error_remains_machine_readable() {
        let error = PanelError::Business {
            code: 404_001,
            message: "resource not found".to_owned(),
            request_id: None,
        };

        assert!(error.is_pending_order_not_visible());
        assert!(!PanelError::Unauthorized.is_pending_order_not_visible());
    }

    fn shop_catalog() -> ShopCatalog {
        ShopCatalog {
            plans: vec![ShopPlan {
                id: 7,
                name: "VIP".to_owned(),
                description: String::new(),
                group_name: "Premium".to_owned(),
                addon_available: false,
                prices: vec![
                    ShopPlanPrice {
                        id: 8,
                        label: "月付".to_owned(),
                        period_unit: "month".to_owned(),
                        period_count: 1,
                        price_cents: 2_900,
                        currency: "CNY".to_owned(),
                        included_traffic_bytes: 100,
                    },
                    ShopPlanPrice {
                        id: 10,
                        label: "试用".to_owned(),
                        period_unit: "day".to_owned(),
                        period_count: 1,
                        price_cents: 0,
                        currency: "CNY".to_owned(),
                        included_traffic_bytes: 10,
                    },
                ],
                traffic_addons: vec![ShopTrafficAddon {
                    id: 9,
                    name: "100GB".to_owned(),
                    traffic_bytes: 100,
                    price_cents: 1_000,
                    currency: "CNY".to_owned(),
                }],
            }],
            payment_methods: vec![ShopPaymentMethod {
                id: 3,
                name: "支付宝".to_owned(),
                icon_url: None,
                provider: "epay".to_owned(),
                provider_name: "Alipay".to_owned(),
                payment_type: "alipay".to_owned(),
                payment_type_name: "跳转支付".to_owned(),
            }],
        }
    }

    fn order() -> ShopOrder {
        ShopOrder {
            id: 1,
            order_number: "ORD1".to_owned(),
            amount_cents: 2_900,
            currency: "CNY".to_owned(),
            status: ShopOrderStatus::Pending,
            can_pay: false,
            payment: None,
        }
    }

    fn user() -> UserIdentity {
        UserIdentity {
            id: 1,
            uuid: "11111111-1111-4111-8111-111111111111".to_owned(),
            username: "user".to_owned(),
            email: "user@example.com".to_owned(),
            balance_cents: 0,
        }
    }
}
