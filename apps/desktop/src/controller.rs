use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use topnode_application::{
    AccountSnapshot, ConfigurationRequest, ConfigurationSourceError, ConnectError,
    ConnectionCoordinator, LoginCredentials, PanelCoordinator, PanelError, PasswordChange,
    ShopSnapshot,
};
use topnode_domain::{
    AffiliateCommissionPage, AffiliateSummary, AffiliateTransferPage, BalanceTransaction,
    ConnectionState, EngineError, Entitlement, GiftCardConfig, GiftCardRedeemCheck,
    GiftCardRewardPreview, RouteMode, RuntimeId, RuntimeTelemetrySnapshot, ServerGroup,
    ShopCouponQuote, ShopOrder, ShopOrderSelection, ShopOrderStatus, ShopPaymentChoice,
    ShopPurchaseKind, StopReason, SubscriptionLink, SupportTicketAction, SupportTicketDetail,
    SupportTicketDraft, SupportTicketPage, SupportTicketPriority, UserOrderFilter, UserOrderPage,
};
use topnode_infrastructure::{DesktopSettings, SettingsStore};

use crate::platform::{self, TunElevationOutcome};

const CONNECTION_ACTION_INTERVAL: Duration = Duration::from_millis(1_200);
const BALANCE_TRANSACTION_LIMIT: u8 = 50;
pub const ORDER_PAGE_SIZE: u8 = 20;
pub const AFFILIATE_PAGE_SIZE: u8 = 20;
pub const SUPPORT_TICKET_PAGE_SIZE: u8 = 20;
pub const SUPPORT_TICKET_MESSAGE_PAGE_SIZE: u8 = 20;

#[derive(Debug)]
pub struct InvitationDashboard {
    pub summary: Result<AffiliateSummary, String>,
    pub commissions: Result<AffiliateCommissionPage, String>,
    pub transfers: Result<AffiliateTransferPage, String>,
}

#[derive(Debug)]
struct ConnectionActionGate {
    last_accepted_at: StdMutex<Option<Instant>>,
    minimum_interval: Duration,
}

impl ConnectionActionGate {
    fn new(minimum_interval: Duration) -> Self {
        Self {
            last_accepted_at: StdMutex::new(None),
            minimum_interval,
        }
    }

    fn try_acquire(&self) -> bool {
        let now = Instant::now();
        let mut last_accepted_at = self
            .last_accepted_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last_accepted_at
            .is_some_and(|previous| now.saturating_duration_since(previous) < self.minimum_interval)
        {
            return false;
        }
        *last_accepted_at = Some(now);
        true
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PreferenceChange {
    TunMode(bool),
    GlobalMode(bool),
    BypassMainland(bool),
    BypassLan(bool),
    UdpForwarding(bool),
    Multiplex(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunModeUpdate {
    Applied,
    Restarting,
    Cancelled,
}

#[derive(Clone, Debug, Default)]
pub struct NodeLatencySnapshot {
    pub measuring_node_ids: HashSet<String>,
    pub values_by_node_id: HashMap<String, Option<u64>>,
}

#[derive(Debug)]
pub struct NodeLatencyBatch {
    pub generation: u64,
    pub targets_by_node_id: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct NodeLatencyState {
    generation: u64,
    measuring_node_ids: HashSet<String>,
    values_by_node_id: HashMap<String, Option<u64>>,
}

pub struct DesktopController {
    coordinator: Arc<ConnectionCoordinator>,
    panel: Arc<PanelCoordinator>,
    settings_store: SettingsStore,
    settings: Mutex<DesktopSettings>,
    catalog_action_gate: Mutex<()>,
    support_ticket_action_gate: Mutex<()>,
    connection_action_gate: ConnectionActionGate,
    node_latency: StdMutex<NodeLatencyState>,
}

impl std::fmt::Debug for DesktopController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopController")
            .field("coordinator", &self.coordinator)
            .field("settings_store", &self.settings_store)
            .finish_non_exhaustive()
    }
}

impl DesktopController {
    pub fn new(
        coordinator: Arc<ConnectionCoordinator>,
        panel: Arc<PanelCoordinator>,
        settings_store: SettingsStore,
        settings: DesktopSettings,
    ) -> Self {
        Self {
            coordinator,
            panel,
            settings_store,
            settings: Mutex::new(settings),
            catalog_action_gate: Mutex::new(()),
            support_ticket_action_gate: Mutex::new(()),
            connection_action_gate: ConnectionActionGate::new(CONNECTION_ACTION_INTERVAL),
            node_latency: StdMutex::new(NodeLatencyState::default()),
        }
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<ConnectionState> {
        self.coordinator.subscribe()
    }

    pub fn subscribe_telemetry(&self) -> tokio::sync::watch::Receiver<RuntimeTelemetrySnapshot> {
        self.coordinator.subscribe_telemetry()
    }

    pub fn subscribe_account(&self) -> tokio::sync::watch::Receiver<AccountSnapshot> {
        self.panel.subscribe()
    }

    pub fn subscribe_shop(&self) -> tokio::sync::watch::Receiver<ShopSnapshot> {
        self.panel.subscribe_shop()
    }

    pub async fn login(&self, email: String, password: String) -> Result<(), String> {
        let _guard = self.catalog_action_gate.lock().await;
        self.panel
            .login(LoginCredentials::new(email, password))
            .await
            .map_err(panel_message)?;
        self.reconcile_selection(true).await
    }

    pub async fn refresh_resources(&self) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.ensure_selection_allowed()?;
        self.panel
            .refresh_resources()
            .await
            .map_err(panel_message)?;
        self.reconcile_selection(false).await
    }

    pub async fn refresh_subscriptions(&self) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel.refresh_resources().await.map_err(panel_message)
    }

    pub async fn refresh_profile(&self) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel.refresh_profile().await.map_err(panel_message)
    }

    pub async fn load_balance_details(&self) -> Result<Vec<BalanceTransaction>, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let (profile, transactions) = tokio::join!(
            self.panel.refresh_profile(),
            self.panel.balance_transactions(BALANCE_TRANSACTION_LIMIT),
        );
        if let Err(error) = profile {
            if error.invalidates_session() {
                return Err(panel_message(error));
            }
            tracing::warn!(
                ?error,
                "profile refresh failed while loading balance details"
            );
        }
        transactions.map_err(panel_message)
    }

    pub async fn load_subscription_link(&self) -> Result<SubscriptionLink, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .subscription_link()
            .await
            .map_err(subscription_link_message)
    }

    pub async fn reset_subscription_link(&self) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .reset_subscription()
            .await
            .map_err(subscription_link_message)
    }

    pub async fn load_orders(
        &self,
        filter: UserOrderFilter,
        page: u32,
    ) -> Result<UserOrderPage, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .orders(filter, page, ORDER_PAGE_SIZE)
            .await
            .map_err(panel_message)
    }

    pub async fn load_support_tickets(&self, page: u32) -> Result<SupportTicketPage, String> {
        let _guard = self
            .support_ticket_action_gate
            .try_lock()
            .map_err(|_| "工单操作正在进行，请稍候。".to_owned())?;
        self.panel
            .support_tickets(page, SUPPORT_TICKET_PAGE_SIZE)
            .await
            .map_err(support_ticket_message)
    }

    pub async fn load_support_ticket(
        &self,
        id: &str,
        message_page: u32,
    ) -> Result<SupportTicketDetail, String> {
        let _guard = self
            .support_ticket_action_gate
            .try_lock()
            .map_err(|_| "工单操作正在进行，请稍候。".to_owned())?;
        let id = parse_positive_id(id, "工单信息无效，请返回刷新列表。")?;
        self.panel
            .support_ticket(id, message_page, SUPPORT_TICKET_MESSAGE_PAGE_SIZE)
            .await
            .map_err(support_ticket_message)
    }

    pub async fn create_support_ticket(
        &self,
        title: String,
        priority: &str,
        message: String,
    ) -> Result<SupportTicketDetail, String> {
        let _guard = self
            .support_ticket_action_gate
            .try_lock()
            .map_err(|_| "工单操作正在进行，请稍候。".to_owned())?;
        let draft = SupportTicketDraft {
            title,
            priority: parse_support_ticket_priority(priority)?,
            message,
        };
        self.panel
            .create_support_ticket(&draft)
            .await
            .map_err(support_ticket_message)
    }

    pub async fn reply_support_ticket(
        &self,
        id: &str,
        content: String,
    ) -> Result<SupportTicketDetail, String> {
        let _guard = self
            .support_ticket_action_gate
            .try_lock()
            .map_err(|_| "正在发送上一条消息，请稍候。".to_owned())?;
        let id = parse_positive_id(id, "工单信息无效，请返回刷新列表。")?;
        self.panel
            .reply_support_ticket(id, &content)
            .await
            .map_err(support_ticket_message)
    }

    pub async fn close_support_ticket(&self, id: &str) -> Result<SupportTicketAction, String> {
        let _guard = self
            .support_ticket_action_gate
            .try_lock()
            .map_err(|_| "工单操作正在进行，请稍候。".to_owned())?;
        let id = parse_positive_id(id, "工单信息无效，请返回刷新列表。")?;
        self.panel
            .close_support_ticket(id)
            .await
            .map_err(support_ticket_message)
    }

    pub async fn load_gift_card_config(&self) -> Result<GiftCardConfig, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .gift_card_config()
            .await
            .map_err(gift_card_message)
    }

    pub async fn check_gift_card(&self, code: &str) -> Result<GiftCardRedeemCheck, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .check_gift_card(code)
            .await
            .map_err(gift_card_message)
    }

    pub async fn redeem_gift_card(&self, code: &str) -> Result<GiftCardRewardPreview, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let reward = self
            .panel
            .redeem_gift_card(code)
            .await
            .map_err(gift_card_message)?;
        if let Err(error) = self.panel.refresh_profile().await {
            tracing::warn!(?error, "profile refresh failed after gift-card redemption");
        }
        if let Err(error) = self.panel.refresh_resources().await {
            tracing::warn!(?error, "resource refresh failed after gift-card redemption");
        }
        Ok(reward)
    }

    pub async fn load_invitations(&self) -> Result<InvitationDashboard, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let (summary, commissions, transfers) = tokio::join!(
            self.panel.affiliate_summary(),
            self.panel.affiliate_commissions(1, AFFILIATE_PAGE_SIZE),
            self.panel.affiliate_transfers(1, AFFILIATE_PAGE_SIZE),
        );
        Ok(InvitationDashboard {
            summary: summary.map_err(affiliate_message),
            commissions: commissions.map_err(affiliate_message),
            transfers: transfers.map_err(affiliate_message),
        })
    }

    pub async fn load_affiliate_commissions(
        &self,
        page: u32,
    ) -> Result<AffiliateCommissionPage, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .affiliate_commissions(page, AFFILIATE_PAGE_SIZE)
            .await
            .map_err(affiliate_message)
    }

    pub async fn load_affiliate_transfers(
        &self,
        page: u32,
    ) -> Result<AffiliateTransferPage, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .affiliate_transfers(page, AFFILIATE_PAGE_SIZE)
            .await
            .map_err(affiliate_message)
    }

    pub async fn change_password(
        &self,
        current_password: String,
        new_password: String,
        confirm_password: String,
    ) -> Result<(), String> {
        validate_password_change(&current_password, &new_password, &confirm_password)?;
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.panel
            .change_password(PasswordChange::new(current_password, new_password))
            .await
            .map_err(account_message)?;
        self.coordinator.cancel_pending();
        if let Err(error) = self
            .coordinator
            .disconnect(StopReason::SessionInvalid)
            .await
        {
            tracing::warn!(?error, "failed to disconnect after password change");
        }
        let mut settings = self.settings.lock().await;
        settings.selected_group_id.clear();
        settings.selected_entitlement_id.clear();
        settings.selected_endpoint_id.clear();
        if let Err(error) = self.settings_store.save(&settings).await {
            tracing::warn!(%error, "failed to clear desktop selection after password change");
        }
        Ok(())
    }

    pub async fn refresh_shop(&self) -> Result<(), String> {
        self.panel.refresh_shop().await.map_err(panel_message)
    }

    pub async fn check_coupon(
        &self,
        kind: &str,
        plan_id: &str,
        product_id: &str,
        coupon_code: &str,
    ) -> Result<ShopCouponQuote, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let selection = parse_shop_selection(kind, plan_id, product_id, coupon_code)?;
        if selection.coupon_code.is_none() {
            return Err("请输入优惠码。".to_owned());
        }
        self.panel
            .check_coupon(selection)
            .await
            .map_err(shop_message)
    }

    pub async fn create_order(
        &self,
        kind: &str,
        plan_id: &str,
        product_id: &str,
        coupon_code: &str,
    ) -> Result<ShopOrder, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let selection = parse_shop_selection(kind, plan_id, product_id, coupon_code)?;
        let order = self
            .panel
            .create_order(selection)
            .await
            .map_err(shop_message)?;
        self.refresh_after_completed_order(&order).await;
        Ok(order)
    }

    pub async fn pay_order(
        &self,
        order_id: &str,
        payment_method_id: &str,
        use_balance: bool,
    ) -> Result<ShopOrder, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let order_id = parse_positive_id(order_id, "订单信息无效，请重新提交。")?;
        let payment = parse_payment_choice(payment_method_id, use_balance)?;
        let order = self
            .panel
            .pay_order(order_id, payment)
            .await
            .map_err(shop_message)?;
        self.refresh_after_completed_order(&order).await;
        Ok(order)
    }

    /// Returns `Ok(None)` while a known self-created pending order is hidden by
    /// the Panel. Callers should keep their last order/payment session and poll
    /// again without presenting an error.
    pub async fn get_order(&self, order_id: &str) -> Result<Option<ShopOrder>, String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let order_id = parse_positive_id(order_id, "订单信息无效，请重新提交。")?;
        let order = match self.panel.get_order(order_id).await {
            Ok(order) => order,
            Err(error) if error.is_pending_order_not_visible() => return Ok(None),
            Err(error) => return Err(shop_message(error)),
        };
        self.refresh_after_completed_order(&order).await;
        Ok(Some(order))
    }

    async fn refresh_after_completed_order(&self, order: &ShopOrder) {
        if order.status != ShopOrderStatus::Paid {
            return;
        }
        if let Err(error) = self.panel.refresh_profile().await {
            tracing::warn!(%error, "failed to refresh profile after completed order");
        }
        if let Err(error) = self.panel.refresh_resources().await {
            tracing::warn!(%error, "failed to refresh resources after completed order");
        }
        if let Err(error) = self.panel.refresh_shop().await {
            tracing::warn!(%error, "failed to refresh shop after completed order");
        }
    }

    pub async fn logout(&self) -> Result<(), String> {
        self.coordinator.cancel_pending();
        let _guard = self.catalog_action_gate.lock().await;
        let logout = self.panel.logout();
        let disconnect = self.coordinator.disconnect(StopReason::SessionInvalid);
        let (logout_result, disconnect_result) = tokio::join!(logout, disconnect);
        {
            let mut settings = self.settings.lock().await;
            settings.selected_group_id.clear();
            settings.selected_entitlement_id.clear();
            settings.selected_endpoint_id.clear();
            self.settings_store
                .save(&settings)
                .await
                .map_err(settings_message)?;
        }
        logout_result.map_err(panel_message)?;
        disconnect_result.map_err(disconnect_message)
    }

    pub async fn settings(&self) -> DesktopSettings {
        self.settings.lock().await.clone()
    }

    pub fn node_latency_snapshot(&self) -> NodeLatencySnapshot {
        let state = self
            .node_latency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        NodeLatencySnapshot {
            measuring_node_ids: state.measuring_node_ids.clone(),
            values_by_node_id: state.values_by_node_id.clone(),
        }
    }

    pub async fn begin_node_latency(&self) -> NodeLatencyBatch {
        let selected_group_id = self.settings.lock().await.selected_group_id.clone();
        let snapshot = self.panel.subscribe().borrow().clone();
        let selected_group = snapshot
            .groups
            .iter()
            .find(|group| group.id.to_string() == selected_group_id);
        let targets_by_node_id = selected_group
            .map(|group| {
                group
                    .nodes
                    .iter()
                    .filter(|node| !node.latency_target.trim().is_empty())
                    .map(|node| (node.endpoint_id.clone(), node.latency_target.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let visible_node_ids = selected_group
            .map(|group| {
                group
                    .nodes
                    .iter()
                    .map(|node| node.endpoint_id.as_str())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let mut state = self
            .node_latency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.wrapping_add(1);
        state
            .values_by_node_id
            .retain(|node_id, _| visible_node_ids.contains(node_id.as_str()));
        state.measuring_node_ids = targets_by_node_id
            .iter()
            .map(|(node_id, _)| node_id.clone())
            .collect();
        NodeLatencyBatch {
            generation: state.generation,
            targets_by_node_id,
        }
    }

    pub fn finish_node_latency(
        &self,
        generation: u64,
        values_by_node_id: Vec<(String, Option<u64>)>,
    ) {
        let mut state = self
            .node_latency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != generation {
            return;
        }
        for (node_id, latency) in values_by_node_id {
            state.values_by_node_id.insert(node_id, latency);
        }
        state.measuring_node_ids.clear();
    }

    pub fn cancel_node_latency(&self) {
        let mut state = self
            .node_latency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.wrapping_add(1);
        state.measuring_node_ids.clear();
    }

    pub async fn toggle_connection(&self) -> Result<(), String> {
        if !self.connection_action_gate.try_acquire() {
            return Ok(());
        }
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let state = self.coordinator.subscribe().borrow().clone();
        if state.is_connected() {
            return self
                .coordinator
                .disconnect(StopReason::User)
                .await
                .map_err(disconnect_message);
        }
        if state.is_transitioning() {
            return Err("连接操作正在进行，请稍候。".to_owned());
        }
        if matches!(state, ConnectionState::Failed { .. }) {
            self.coordinator
                .disconnect(StopReason::RuntimeError)
                .await
                .map_err(disconnect_message)?;
        }
        self.connect_current_settings().await
    }

    pub async fn select_group(
        &self,
        group_id: String,
        entitlement_id: String,
    ) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.ensure_selection_allowed()?;
        let snapshot = self.panel.subscribe().borrow().clone();
        let group = snapshot
            .groups
            .iter()
            .find(|group| group.id.to_string() == group_id && group.connectable)
            .ok_or_else(|| "该服务套餐当前不可用，请选择其他套餐。".to_owned())?;
        if !resource_entitlement_available(group, &entitlement_id) {
            return Err("该套餐权益当前不可用，请刷新后重新选择。".to_owned());
        }
        let mut settings = self.settings.lock().await;
        let changed_group = settings.selected_group_id != group.id.to_string();
        settings.selected_group_id = group.id.to_string();
        settings.selected_entitlement_id = entitlement_id;
        if changed_group {
            settings.selected_endpoint_id.clear();
        }
        self.settings_store
            .save(&settings)
            .await
            .map_err(settings_message)
    }

    pub async fn select_node(&self, endpoint_id: String) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        self.ensure_selection_allowed()?;
        let snapshot = self.panel.subscribe().borrow().clone();
        let mut settings = self.settings.lock().await;
        let group = snapshot
            .groups
            .iter()
            .find(|group| group.id.to_string() == settings.selected_group_id)
            .ok_or_else(|| "请先选择一个服务套餐。".to_owned())?;
        let node = group
            .nodes
            .iter()
            .find(|node| node.endpoint_id == endpoint_id && node.selectable)
            .ok_or_else(|| "该节点当前不可用，请选择其他节点。".to_owned())?;
        settings.selected_endpoint_id.clone_from(&node.endpoint_id);
        // Endpoint selection is session-only (serde(skip)); persisting here
        // rewrites identical TOML and delays the UI for an unnecessary disk flush.
        Ok(())
    }

    pub async fn update_preference(&self, change: PreferenceChange) -> Result<(), String> {
        let _guard = self
            .catalog_action_gate
            .try_lock()
            .map_err(|_| "另一项操作正在进行，请稍候。".to_owned())?;
        let state = self.coordinator.subscribe().borrow().clone();
        if state.is_transitioning() {
            return Err("连接正在切换，请稍候再修改设置。".to_owned());
        }

        let Some(previous) = self.persist_preference(change).await? else {
            return Ok(());
        };
        if !state.is_connected() {
            return Ok(());
        }

        if let Err(error) = self
            .coordinator
            .disconnect(StopReason::NetworkRestart)
            .await
        {
            let disconnect_error = disconnect_message(error);
            if let Err(rollback_error) = self.replace_settings(previous).await {
                tracing::error!(%rollback_error, "failed to roll back preferences after reconnect stop failed");
                return Err(format!(
                    "设置已保存，但当前连接未能刷新：{disconnect_error}"
                ));
            }
            return Err("当前连接未能刷新，已恢复原设置。".to_owned());
        }

        self.connect_current_settings()
            .await
            .map_err(|error| format!("设置已保存，但自动重新连接失败：{error}"))
    }

    async fn persist_preference(
        &self,
        change: PreferenceChange,
    ) -> Result<Option<DesktopSettings>, String> {
        let mut current = self.settings.lock().await;
        let mut next = current.clone();
        match change {
            PreferenceChange::TunMode(enabled) => {
                next.preferences.tun_enabled = enabled;
            }
            PreferenceChange::GlobalMode(enabled) => {
                next.preferences = next.preferences.clone().with_route_mode(if enabled {
                    RouteMode::Global
                } else {
                    RouteMode::Rule
                });
            }
            PreferenceChange::BypassMainland(enabled) => {
                next.preferences.bypass_mainland = enabled;
            }
            PreferenceChange::BypassLan(enabled) => {
                next.preferences.bypass_lan = enabled;
            }
            PreferenceChange::UdpForwarding(enabled) => {
                next.preferences.udp_forwarding_enabled = enabled;
            }
            PreferenceChange::Multiplex(enabled) => {
                next.preferences.multiplex_enabled = enabled;
            }
        }
        next.preferences = next.preferences.normalized();
        if next == *current {
            return Ok(None);
        }
        let previous = current.clone();
        self.settings_store
            .save(&next)
            .await
            .map_err(settings_message)?;
        *current = next;
        Ok(Some(previous))
    }

    async fn replace_settings(&self, replacement: DesktopSettings) -> Result<(), String> {
        self.settings_store
            .save(&replacement)
            .await
            .map_err(settings_message)?;
        *self.settings.lock().await = replacement;
        Ok(())
    }

    pub async fn set_tun_mode(&self, enabled: bool) -> Result<TunModeUpdate, String> {
        tracing::info!(enabled, "TUN mode change requested");
        let current = self.settings.lock().await.preferences.tun_enabled;
        if current == enabled {
            return Ok(TunModeUpdate::Applied);
        }
        let reconnect = self.stop_connection_for_tun_change().await?;
        let update = self.apply_tun_mode(enabled).await;

        match update {
            Ok(TunModeUpdate::Restarting) => Ok(TunModeUpdate::Restarting),
            Ok(update) => {
                if reconnect {
                    self.connect_current_settings()
                        .await
                        .map_err(|error| format!("连接模式已处理，但自动重新连接失败：{error}"))?;
                }
                Ok(update)
            }
            Err(error) => {
                if reconnect && let Err(reconnect_error) = self.connect_current_settings().await {
                    tracing::warn!(%reconnect_error, "failed to restore connection after TUN mode change error");
                    return Err(format!("{error} 原连接也未能自动恢复，请手动重连。"));
                }
                Err(error)
            }
        }
    }

    async fn stop_connection_for_tun_change(&self) -> Result<bool, String> {
        let state = self.coordinator.subscribe().borrow().clone();
        if state.is_transitioning() {
            return Err("连接正在切换，请稍候再修改连接模式。".to_owned());
        }
        if !state.is_connected() {
            return Ok(false);
        }
        self.coordinator
            .disconnect(StopReason::NetworkRestart)
            .await
            .map_err(disconnect_message)?;
        Ok(true)
    }

    async fn apply_tun_mode(&self, enabled: bool) -> Result<TunModeUpdate, String> {
        if !enabled {
            let _ = self
                .persist_preference(PreferenceChange::TunMode(false))
                .await?;
            return Ok(TunModeUpdate::Applied);
        }

        if platform::tun_permission_available().map_err(tun_permission_message)? {
            let _ = self
                .persist_preference(PreferenceChange::TunMode(true))
                .await?;
            return Ok(TunModeUpdate::Applied);
        }

        match platform::request_tun_elevation_restart()
            .await
            .map_err(tun_permission_message)?
        {
            TunElevationOutcome::NotRequired => {
                let _ = self
                    .persist_preference(PreferenceChange::TunMode(true))
                    .await?;
                Ok(TunModeUpdate::Applied)
            }
            TunElevationOutcome::RestartLaunched => Ok(TunModeUpdate::Restarting),
            TunElevationOutcome::Cancelled => Ok(TunModeUpdate::Cancelled),
        }
    }

    pub async fn shutdown(&self) {
        if let Err(error) = self
            .coordinator
            .disconnect(StopReason::ApplicationExit)
            .await
        {
            tracing::warn!(%error, "failed to stop sidecar while shutting down");
        }
    }

    pub async fn disconnect_if_session_invalid(&self) -> Result<(), String> {
        let state = self.coordinator.subscribe().borrow().clone();
        if matches!(state, ConnectionState::Disconnected) {
            return Ok(());
        }
        self.coordinator
            .disconnect(StopReason::SessionInvalid)
            .await
            .map_err(disconnect_message)
    }

    async fn connect_current_settings(&self) -> Result<(), String> {
        let settings = self.settings.lock().await.clone();
        if settings.preferences.tun_enabled
            && !platform::tun_permission_available().map_err(tun_permission_message)?
        {
            return match platform::request_tun_elevation_restart()
                .await
                .map_err(tun_permission_message)?
            {
                TunElevationOutcome::RestartLaunched => Ok(()),
                TunElevationOutcome::Cancelled => {
                    Err("未获得管理员权限，全局模式连接未启动。".to_owned())
                }
                TunElevationOutcome::NotRequired => {
                    Err("系统权限状态已变更，请重新尝试开启全局模式。".to_owned())
                }
            };
        }
        if settings.selected_group_id.is_empty() || settings.selected_endpoint_id.is_empty() {
            return Err("请先选择一个可用节点。".to_owned());
        }
        let account = self.panel.subscribe().borrow().clone();
        let selected_is_available = account
            .groups
            .iter()
            .find(|group| group.connectable && group.id.to_string() == settings.selected_group_id)
            .is_some_and(|group| {
                group.nodes.iter().any(|node| {
                    node.selectable && node.endpoint_id == settings.selected_endpoint_id
                })
            });
        if !account.is_authenticated() || !selected_is_available {
            return Err("当前节点已不可用，请刷新节点列表后重试。".to_owned());
        }
        let request = ConfigurationRequest {
            group_id: settings.selected_group_id,
            selected_endpoint_id: settings.selected_endpoint_id,
            preferences: settings.preferences.normalized(),
            runtime_id: RuntimeId::new("rt1").map_err(|error| {
                tracing::error!(?error, "built-in runtime identifier is invalid");
                "连接服务初始化失败，请重新启动应用。".to_owned()
            })?,
            supported_schema_versions: vec![1],
        };
        let result = self.coordinator.connect(request).await;
        if matches!(
            &result,
            Err(ConnectError::Configuration(
                ConfigurationSourceError::Unauthorized
            ))
        ) {
            let _ = self.panel.restore().await;
        }
        result.map_err(connect_message)
    }

    async fn reconcile_selection(&self, clear_endpoint: bool) -> Result<(), String> {
        let snapshot = self.panel.subscribe().borrow().clone();
        if !snapshot.is_authenticated() {
            return Ok(());
        }
        let mut settings = self.settings.lock().await;
        let previous_group_id = settings.selected_group_id.clone();
        let previous_entitlement_id = settings.selected_entitlement_id.clone();
        let selected_group = snapshot
            .groups
            .iter()
            .find(|group| {
                group.id.to_string() == previous_group_id
                    && group.connectable
                    && resource_entitlement_available(group, &previous_entitlement_id)
            })
            .or_else(|| snapshot.groups.iter().find(|group| group.connectable));
        let Some(group) = selected_group else {
            settings.selected_group_id.clear();
            settings.selected_entitlement_id.clear();
            settings.selected_endpoint_id.clear();
            return self
                .settings_store
                .save(&settings)
                .await
                .map_err(settings_message);
        };
        let changed_group = group.id.to_string() != previous_group_id;
        let entitlement_id =
            if !changed_group && resource_entitlement_available(group, &previous_entitlement_id) {
                previous_entitlement_id
            } else {
                default_resource_entitlement_id(group)
            };
        settings.selected_group_id = group.id.to_string();
        settings.selected_entitlement_id = entitlement_id;
        if clear_endpoint
            || changed_group
            || !group
                .nodes
                .iter()
                .any(|node| node.endpoint_id == settings.selected_endpoint_id && node.selectable)
        {
            settings.selected_endpoint_id.clear();
        }
        self.settings_store
            .save(&settings)
            .await
            .map_err(settings_message)
    }

    fn ensure_selection_allowed(&self) -> Result<(), String> {
        let state = self.coordinator.subscribe().borrow().clone();
        if matches!(
            state,
            ConnectionState::Disconnected | ConnectionState::Failed { .. }
        ) {
            Ok(())
        } else {
            Err("请断开当前连接后再更换套餐或节点。".to_owned())
        }
    }
}

fn parse_shop_selection(
    kind: &str,
    plan_id: &str,
    product_id: &str,
    coupon_code: &str,
) -> Result<ShopOrderSelection, String> {
    let kind = match kind {
        "base_plan" => ShopPurchaseKind::BasePlan,
        "traffic_addon" => ShopPurchaseKind::TrafficAddon,
        _ => return Err("购买商品类型无效，请刷新后重试。".to_owned()),
    };
    let coupon_code = normalize_coupon_code(coupon_code);
    Ok(ShopOrderSelection {
        kind,
        plan_id: parse_positive_id(plan_id, "购买商品信息无效，请刷新后重试。")?,
        product_id: parse_positive_id(product_id, "购买商品信息无效，请刷新后重试。")?,
        coupon_code: (!coupon_code.is_empty()).then_some(coupon_code),
    })
}

fn parse_positive_id(value: &str, message: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| message.to_owned())
}

fn parse_support_ticket_priority(value: &str) -> Result<SupportTicketPriority, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" => Ok(SupportTicketPriority::Low),
        "medium" => Ok(SupportTicketPriority::Medium),
        "high" => Ok(SupportTicketPriority::High),
        _ => Err("请选择有效的工单优先级。".to_owned()),
    }
}

fn is_active_plan_entitlement(entitlement: &Entitlement) -> bool {
    entitlement.status.eq_ignore_ascii_case("active")
        && entitlement.traffic_addon_id.is_none()
        && !entitlement.source.eq_ignore_ascii_case("traffic_addon")
        && !entitlement.plan_name.trim().is_empty()
}

fn resource_entitlement_available(group: &ServerGroup, entitlement_id: &str) -> bool {
    let mut active_entitlements = group
        .entitlements
        .iter()
        .filter(|entitlement| is_active_plan_entitlement(entitlement));
    if entitlement_id.trim().is_empty() {
        return active_entitlements.next().is_none();
    }
    let Ok(grant_id) = entitlement_id.parse::<u64>() else {
        return false;
    };
    active_entitlements.any(|entitlement| entitlement.grant_id == grant_id)
}

fn default_resource_entitlement_id(group: &ServerGroup) -> String {
    group
        .entitlements
        .iter()
        .find(|entitlement| is_active_plan_entitlement(entitlement))
        .map(|entitlement| entitlement.grant_id.to_string())
        .unwrap_or_default()
}

fn normalize_coupon_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_uppercase)
        .take(32)
        .collect()
}

fn parse_payment_choice(
    payment_method_id: &str,
    use_balance: bool,
) -> Result<ShopPaymentChoice, String> {
    if use_balance {
        if !payment_method_id.trim().is_empty() {
            return Err("不能同时选择余额和在线支付。".to_owned());
        }
        return Ok(ShopPaymentChoice::Balance);
    }
    Ok(ShopPaymentChoice::Provider(parse_positive_id(
        payment_method_id,
        "请选择支付方式。",
    )?))
}

fn validate_password_change(
    current_password: &str,
    new_password: &str,
    confirm_password: &str,
) -> Result<(), String> {
    validate_password_length(current_password, "当前密码")?;
    validate_password_length(new_password, "新密码")?;
    if confirm_password != new_password {
        return Err("两次输入的新密码不一致。".to_owned());
    }
    Ok(())
}

fn validate_password_length(password: &str, label: &str) -> Result<(), String> {
    let length = password.len();
    if length < 8 {
        return Err(format!("{label}至少需要 8 个字节。"));
    }
    if length > 72 {
        return Err(format!("{label}不能超过 72 个字节。"));
    }
    Ok(())
}

fn shop_message(error: PanelError) -> String {
    tracing::warn!(?error, "shop operation failed");
    let message = error.shop_user_message().to_owned();
    drop(error);
    message
}

fn account_message(error: PanelError) -> String {
    tracing::warn!(?error, "account security operation failed");
    let message = error.account_user_message().to_owned();
    drop(error);
    message
}

fn gift_card_message(error: PanelError) -> String {
    tracing::warn!(?error, "gift-card operation failed");
    let message = error.gift_card_user_message().to_owned();
    drop(error);
    message
}

fn affiliate_message(error: PanelError) -> String {
    let message = error.affiliate_user_message().to_owned();
    tracing::warn!(?error, "affiliate operation failed");
    drop(error);
    message
}

fn subscription_link_message(error: PanelError) -> String {
    let message = error.subscription_link_user_message().to_owned();
    tracing::warn!(?error, "subscription-link operation failed");
    drop(error);
    message
}

fn support_ticket_message(error: PanelError) -> String {
    let message = error.support_ticket_user_message().to_owned();
    tracing::warn!(?error, "support-ticket operation failed");
    drop(error);
    message
}

fn panel_message(error: PanelError) -> String {
    tracing::warn!(?error, "panel operation failed");
    let message = error.user_message().to_owned();
    drop(error);
    message
}

fn settings_message(error: std::io::Error) -> String {
    tracing::error!(%error, "desktop settings operation failed");
    drop(error);
    "设置未能保存，请稍后重试。".to_owned()
}

fn tun_permission_message(error: platform::TunElevationError) -> String {
    tracing::warn!(?error, "TUN privilege operation failed");
    let message = if matches!(&error, platform::TunElevationError::UacResponseTimeout) {
        "等待管理员授权超时，已保持系统代理模式。请重试并确认 Windows 权限提示。".to_owned()
    } else {
        "当前无法获取全局模式所需的系统权限，请稍后重试。".to_owned()
    };
    drop(error);
    message
}

fn disconnect_message(error: EngineError) -> String {
    tracing::warn!(?error, "connection stop failed");
    drop(error);
    "暂时无法断开连接，请稍后重试。".to_owned()
}

fn connect_message(error: ConnectError) -> String {
    tracing::warn!(?error, "connection attempt failed");
    let message = match &error {
        ConnectError::Busy => "连接操作正在进行，请稍候。",
        ConnectError::Cancelled | ConnectError::Engine(EngineError::Cancelled) => "连接已取消。",
        ConnectError::Configuration(ConfigurationSourceError::Unauthorized) => {
            "登录状态已失效，请重新登录。"
        }
        ConnectError::Configuration(ConfigurationSourceError::Invalid(_)) => {
            "连接信息无效，请刷新节点列表后重试。"
        }
        ConnectError::Configuration(ConfigurationSourceError::Rejected(message)) => message,
        ConnectError::Configuration(
            ConfigurationSourceError::Unavailable(_) | ConfigurationSourceError::Read(_),
        ) => "暂时无法获取连接信息，请检查网络后重试。",
        ConnectError::Engine(EngineError::MissingBinary(_)) => {
            "连接服务不可用，请重新安装应用或联系客户支持。"
        }
        ConnectError::Engine(EngineError::InsufficientPrivileges) => {
            "全局模式需要管理员权限。请在设置中重新开启全局模式，并在系统提示中允许授权。"
        }
        ConnectError::Engine(EngineError::SystemProxy(_)) => {
            "无法启用系统代理模式，请检查系统网络设置后重试。"
        }
        ConnectError::Engine(_) => "连接失败，请稍后重试。",
    }
    .to_owned();
    drop(error);
    message
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use topnode_application::{ConfigurationSourceError, ConnectError};
    use topnode_domain::{ShopPaymentChoice, ShopPurchaseKind};

    use super::{
        ConnectionActionGate, connect_message, normalize_coupon_code, parse_payment_choice,
        parse_shop_selection, validate_password_change,
    };

    #[test]
    fn connection_action_gate_ignores_an_immediate_second_action() {
        let gate = ConnectionActionGate::new(Duration::from_secs(1));

        assert!(gate.try_acquire());
        assert!(!gate.try_acquire());
    }

    #[test]
    fn connection_action_gate_can_be_disabled_for_deterministic_callers() {
        let gate = ConnectionActionGate::new(Duration::ZERO);

        assert!(gate.try_acquire());
        assert!(gate.try_acquire());
    }

    #[test]
    fn coupon_code_matches_the_web_normalization_rule() {
        assert_eq!(normalize_coupon_code(" save 20\t"), "SAVE20");
        assert_eq!(normalize_coupon_code(&"a".repeat(40)).len(), 32);
    }

    #[test]
    fn shop_selection_parses_the_product_without_payment_state() {
        let selection =
            parse_shop_selection("base_plan", "7", "8", " save20 ").expect("valid selection");

        assert_eq!(selection.kind, ShopPurchaseKind::BasePlan);
        assert_eq!(selection.plan_id, 7);
        assert_eq!(selection.product_id, 8);
        assert_eq!(selection.coupon_code.as_deref(), Some("SAVE20"));
        assert!(parse_shop_selection("unknown", "7", "8", "").is_err());
        assert!(parse_shop_selection("base_plan", "0", "8", "").is_err());
    }

    #[test]
    fn payment_choice_cannot_mix_balance_and_a_provider() {
        assert_eq!(
            parse_payment_choice("", true).expect("balance"),
            ShopPaymentChoice::Balance
        );
        assert_eq!(
            parse_payment_choice("3", false).expect("provider"),
            ShopPaymentChoice::Provider(3)
        );
        assert!(parse_payment_choice("3", true).is_err());
        assert!(parse_payment_choice("", false).is_err());
    }

    #[test]
    fn password_change_validation_uses_utf8_bytes() {
        assert!(validate_password_change("password", "new-pass", "new-pass").is_ok());
        assert_eq!(
            validate_password_change("短", "new-pass", "new-pass").unwrap_err(),
            "当前密码至少需要 8 个字节。"
        );
        assert!(validate_password_change("密码密码密", "new-pass", "new-pass").is_ok());
        assert_eq!(
            validate_password_change("password", "new-pass", "other-pass").unwrap_err(),
            "两次输入的新密码不一致。"
        );
        assert!(validate_password_change("password", &"a".repeat(73), &"a".repeat(73)).is_err());
    }

    #[test]
    fn connection_rejection_surfaces_the_safe_server_business_reason() {
        let message = "所选节点已离线或不可用，请重新选择节点。";

        assert_eq!(
            connect_message(ConnectError::Configuration(
                ConfigurationSourceError::Rejected(message.to_owned())
            )),
            message
        );
    }
}
