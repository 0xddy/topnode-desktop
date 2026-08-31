use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use time::{OffsetDateTime, UtcOffset};
use tokio::time::Instant;
use topnode_application::{
    AccountPhase, AccountSnapshot, ShopPhase as ApplicationShopPhase, ShopSnapshot,
};
use topnode_domain::{
    AffiliateCommission, AffiliateCommissionPage, AffiliateCommissionStatus, AffiliateRebateType,
    AffiliateSummary, AffiliateTransfer, AffiliateTransferPage, BalanceTransaction,
    BalanceTransactionType, ConnectionState, Entitlement, GiftCardConfig, GiftCardRedeemCheck,
    GiftCardRewardPreview, GiftCardRewardType, RouteMode, RuntimeTelemetrySnapshot, ServerGroup,
    ServerNode, ShopCatalog, ShopPlan, SubscriptionLink, SupportTicket, SupportTicketAction,
    SupportTicketDetail, SupportTicketMessage, SupportTicketPage, SupportTicketPriority,
    SupportTicketSenderRole, SupportTicketStatus, UserOrder, UserOrderPage, UserOrderStatus,
    UserOrderType,
};
use topnode_infrastructure::DesktopSettings;

use crate::{
    AffiliateCommissionItem, AffiliateTransferItem, AppPhase, AppTray, AppWindow,
    BalanceTransactionItem, ConnectionPhase, GiftCardRewardItem, NodeItem, OrderItem,
    PaymentMethodItem, ResourceGroupItem, ResourcePhase, ShopAddonItem, ShopPhase, ShopPlanItem,
    ShopPriceItem, SubscriptionItem, SubscriptionStatus, SupportTicketItem,
    SupportTicketMessageItem,
    controller::{DesktopController, NodeLatencySnapshot},
};

const MINIMUM_TRANSITION_VISIBILITY: Duration = Duration::from_millis(1_200);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VisualTransition {
    Connecting,
    Stopping,
}

fn visual_transition(state: &ConnectionState) -> Option<VisualTransition> {
    match state {
        ConnectionState::Preparing | ConnectionState::Validating | ConnectionState::Starting => {
            Some(VisualTransition::Connecting)
        }
        ConnectionState::Stopping => Some(VisualTransition::Stopping),
        ConnectionState::Disconnected
        | ConnectionState::Connected { .. }
        | ConnectionState::Failed { .. } => None,
    }
}

pub fn spawn_state_forwarder(
    ui: &AppWindow,
    mut states: tokio::sync::watch::Receiver<ConnectionState>,
) {
    let weak = ui.as_weak();
    tokio::spawn(async move {
        let publish = |state: ConnectionState| {
            let weak = weak.clone();
            weak.upgrade_in_event_loop(move |ui| apply_connection_state(&ui, &state))
                .is_ok()
        };
        let mut visual_state: Option<ConnectionState> = None;
        let mut minimum_until: Option<Instant> = None;
        let mut pending_state: Option<ConnectionState> = None;
        let mut first_state = true;

        loop {
            let state = if first_state {
                first_state = false;
                states.borrow_and_update().clone()
            } else if let (Some(deadline), Some(_)) = (minimum_until, pending_state.as_ref()) {
                tokio::select! {
                    changed = states.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        states.borrow_and_update().clone()
                    }
                    () = tokio::time::sleep_until(deadline) => {
                        let state = pending_state
                            .take()
                            .expect("pending visual state exists while its deadline is armed");
                        minimum_until = None;
                        if !publish(state.clone()) {
                            return;
                        }
                        visual_state = Some(state);
                        continue;
                    }
                }
            } else {
                if states.changed().await.is_err() {
                    return;
                }
                states.borrow_and_update().clone()
            };

            let next_transition = visual_transition(&state);
            let current_transition = visual_state.as_ref().and_then(visual_transition);
            if let Some(next_transition) = next_transition {
                if current_transition != Some(next_transition) || pending_state.is_some() {
                    minimum_until = Some(Instant::now() + MINIMUM_TRANSITION_VISIBILITY);
                }
                pending_state = None;
            } else if current_transition.is_some()
                && minimum_until.is_some_and(|deadline| deadline > Instant::now())
            {
                pending_state = Some(state);
                continue;
            } else {
                minimum_until = None;
                pending_state = None;
            }

            if !publish(state.clone()) {
                return;
            }
            visual_state = Some(state);
        }
    });
}

pub fn spawn_tray_state_forwarder(
    tray: &AppTray,
    mut states: tokio::sync::watch::Receiver<ConnectionState>,
    core_available: bool,
) {
    let weak = tray.as_weak();
    tokio::spawn(async move {
        loop {
            let state = states.borrow_and_update().clone();
            let weak = weak.clone();
            if weak
                .upgrade_in_event_loop(move |tray| {
                    tray.set_connection_active(state.is_connected());
                    tray.set_connection_action_enabled(
                        state.is_connected()
                            || (core_available
                                && matches!(
                                    state,
                                    ConnectionState::Disconnected | ConnectionState::Failed { .. }
                                )),
                    );
                })
                .is_err()
            {
                return;
            }
            if states.changed().await.is_err() {
                return;
            }
        }
    });
}

pub fn spawn_telemetry_forwarder(
    ui: &AppWindow,
    mut snapshots: tokio::sync::watch::Receiver<RuntimeTelemetrySnapshot>,
) {
    let weak = ui.as_weak();
    tokio::spawn(async move {
        loop {
            let snapshot = snapshots.borrow_and_update().clone();
            let weak = weak.clone();
            if weak
                .upgrade_in_event_loop(move |ui| apply_runtime_telemetry(&ui, &snapshot))
                .is_err()
            {
                return;
            }
            if snapshots.changed().await.is_err() {
                return;
            }
        }
    });
}

pub fn spawn_account_forwarder(ui: &AppWindow, controller: Arc<DesktopController>) {
    let weak = ui.as_weak();
    let mut states = controller.subscribe_account();
    tokio::spawn(async move {
        loop {
            let snapshot = states.borrow_and_update().clone();
            let settings = controller.settings().await;
            let latency = controller.node_latency_snapshot();
            if post_account_view(&weak, snapshot, settings, latency).is_err() {
                return;
            }
            if states.changed().await.is_err() {
                return;
            }
        }
    });
}

pub fn spawn_shop_forwarder(
    ui: &AppWindow,
    mut snapshots: tokio::sync::watch::Receiver<ShopSnapshot>,
) {
    let weak = ui.as_weak();
    tokio::spawn(async move {
        loop {
            let snapshot = snapshots.borrow_and_update().clone();
            let weak = weak.clone();
            if weak
                .upgrade_in_event_loop(move |ui| apply_shop_snapshot(&ui, &snapshot))
                .is_err()
            {
                return;
            }
            if snapshots.changed().await.is_err() {
                return;
            }
        }
    });
}

pub async fn refresh_account_view(weak: &slint::Weak<AppWindow>, controller: &DesktopController) {
    let snapshot = controller.subscribe_account().borrow().clone();
    let settings = controller.settings().await;
    let latency = controller.node_latency_snapshot();
    let _ = post_account_view(weak, snapshot, settings, latency);
}

pub fn post_notice(weak: &slint::Weak<AppWindow>, message: impl Into<SharedString>) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| ui.set_notice(message));
}

pub fn post_balance_details(weak: &slint::Weak<AppWindow>, transactions: &[BalanceTransaction]) {
    let items = transactions
        .iter()
        .map(map_balance_transaction)
        .collect::<Vec<_>>();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_balance_transactions(ModelRc::from(Rc::new(VecModel::from(items))));
        ui.set_balance_details_loading(false);
        ui.set_balance_details_error("".into());
    });
}

pub fn post_balance_details_error(weak: &slint::Weak<AppWindow>, message: impl Into<SharedString>) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_balance_details_loading(false);
        ui.set_balance_details_error(message);
    });
}

pub fn post_subscription_link(weak: &slint::Weak<AppWindow>, link: &SubscriptionLink) {
    let url = link.expose().to_owned();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_subscription_link_url(url.into());
        ui.set_subscription_link_has_link(true);
        ui.set_subscription_link_loading(false);
        ui.set_subscription_link_resetting(false);
        ui.set_subscription_link_error("".into());
        ui.set_subscription_link_reset_error("".into());
    });
}

pub fn post_subscription_link_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_subscription_link_loading(false);
        ui.set_subscription_link_error(message);
    });
}

pub fn post_subscription_reset_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_subscription_link_resetting(false);
        ui.set_subscription_link_reset_error(message);
    });
}

pub fn post_subscription_reset_refresh_error(weak: &slint::Weak<AppWindow>) {
    let _ = weak.upgrade_in_event_loop(|ui| {
        ui.set_subscription_link_url("".into());
        ui.set_subscription_link_has_link(false);
        ui.set_subscription_link_loading(false);
        ui.set_subscription_link_resetting(false);
        ui.set_subscription_link_reset_error("".into());
        ui.set_subscription_link_error("订阅地址已重置，但暂时无法读取新地址，请重新加载。".into());
    });
}

pub fn post_orders(weak: &slint::Weak<AppWindow>, page: &UserOrderPage, append: bool) {
    let mut items = page.orders.iter().map(map_order).collect::<Vec<_>>();
    let page_number = i32::try_from(page.page).unwrap_or(i32::MAX);
    let total = i32::try_from(page.total).unwrap_or(i32::MAX);
    let has_more = page.has_more();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        if append {
            let mut existing = ui.get_orders().iter().collect::<Vec<_>>();
            existing.append(&mut items);
            items = existing;
        }
        ui.set_orders(ModelRc::from(Rc::new(VecModel::from(items))));
        ui.set_orders_page(page_number);
        ui.set_orders_total(total);
        ui.set_orders_has_more(has_more);
        ui.set_orders_loading(false);
        ui.set_orders_loading_more(false);
        ui.set_orders_error("".into());
    });
}

pub fn post_orders_error(weak: &slint::Weak<AppWindow>, message: impl Into<SharedString>) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_orders_loading(false);
        ui.set_orders_loading_more(false);
        ui.set_orders_error(message);
    });
}

pub fn post_support_tickets(weak: &slint::Weak<AppWindow>, page: &SupportTicketPage, append: bool) {
    let mut items = page
        .tickets
        .iter()
        .map(map_support_ticket)
        .collect::<Vec<_>>();
    let page_number = i32::try_from(page.page).unwrap_or(i32::MAX);
    let total = i32::try_from(page.total).unwrap_or(i32::MAX);
    let has_more = page.has_more();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        if append {
            let mut existing = ui.get_support_tickets().iter().collect::<Vec<_>>();
            let mut ids = existing
                .iter()
                .map(|item| item.id.to_string())
                .collect::<HashSet<_>>();
            existing.extend(
                items
                    .drain(..)
                    .filter(|item| ids.insert(item.id.to_string())),
            );
            items = existing;
        }
        ui.set_support_tickets(ModelRc::from(Rc::new(VecModel::from(items))));
        ui.set_tickets_list_page(page_number);
        ui.set_tickets_list_total(total);
        ui.set_tickets_list_has_more(has_more);
        ui.set_tickets_list_loading(false);
        ui.set_tickets_list_refreshing(false);
        ui.set_tickets_list_loading_more(false);
        ui.set_tickets_list_error("".into());
        ui.set_tickets_list_more_error("".into());
    });
}

pub fn post_support_tickets_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
    append: bool,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_tickets_list_loading(false);
        ui.set_tickets_list_refreshing(false);
        ui.set_tickets_list_loading_more(false);
        if append {
            ui.set_tickets_list_more_error(message);
        } else {
            ui.set_tickets_list_error(message);
        }
    });
}

pub fn post_support_ticket_opened(weak: &slint::Weak<AppWindow>, detail: &SupportTicketDetail) {
    let ticket = map_support_ticket(&detail.ticket);
    let messages = map_support_ticket_messages(&detail.messages);
    let message_page = i32::try_from(detail.message_page).unwrap_or(i32::MAX);
    let message_total = i32::try_from(detail.message_total).unwrap_or(i32::MAX);
    let has_earlier = detail.has_earlier_messages();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        apply_selected_support_ticket(&ui, &ticket);
        upsert_support_ticket_item(&ui, ticket);
        ui.set_support_ticket_messages(ModelRc::from(Rc::new(VecModel::from(messages))));
        ui.set_ticket_message_page(message_page);
        ui.set_ticket_message_total(message_total);
        ui.set_ticket_has_earlier(has_earlier);
        ui.set_ticket_detail_loading(false);
        ui.set_ticket_detail_error("".into());
        ui.set_ticket_loading_earlier(false);
        ui.set_ticket_earlier_error("".into());
        ui.set_ticket_sending(false);
        ui.set_ticket_send_error("".into());
        ui.set_tickets_mode("chat".into());
        ui.set_ticket_creating(false);
        ui.set_ticket_create_error("".into());
        ui.set_ticket_create_title("".into());
        ui.set_ticket_create_message("".into());
    });
    schedule_ticket_scroll_to_bottom(weak);
}

pub fn post_support_ticket_detail_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_ticket_detail_loading(false);
        ui.set_ticket_detail_error(message);
    });
}

pub fn post_earlier_support_ticket_messages(
    weak: &slint::Weak<AppWindow>,
    detail: &SupportTicketDetail,
) {
    let older = map_support_ticket_messages(&detail.messages);
    let message_page = i32::try_from(detail.message_page).unwrap_or(i32::MAX);
    let message_total = i32::try_from(detail.message_total).unwrap_or(i32::MAX);
    let has_earlier = detail.has_earlier_messages();
    let ticket = map_support_ticket(&detail.ticket);
    let _ = weak.upgrade_in_event_loop(move |ui| {
        let existing = ui.get_support_ticket_messages().iter().collect::<Vec<_>>();
        let existing_ids = existing
            .iter()
            .map(|item| item.id.to_string())
            .collect::<HashSet<_>>();
        let mut merged = older
            .into_iter()
            .filter(|item| !existing_ids.contains(item.id.as_str()))
            .collect::<Vec<_>>();
        merged.extend(existing);
        apply_selected_support_ticket(&ui, &ticket);
        upsert_support_ticket_item(&ui, ticket);
        ui.set_support_ticket_messages(ModelRc::from(Rc::new(VecModel::from(merged))));
        ui.set_ticket_message_page(message_page);
        ui.set_ticket_message_total(message_total);
        ui.set_ticket_has_earlier(has_earlier);
        ui.set_ticket_loading_earlier(false);
        ui.set_ticket_earlier_error("".into());
    });
}

pub fn post_earlier_support_ticket_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_ticket_loading_earlier(false);
        ui.set_ticket_earlier_error(message);
    });
}

pub fn post_support_ticket_sending(
    weak: &slint::Weak<AppWindow>,
    local_id: String,
    content: String,
) {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let item = SupportTicketMessageItem {
        id: local_id.into(),
        content: content.into(),
        sender_label: "我".into(),
        time_label: format_chat_time(now).into(),
        own: true,
        sending: true,
        failed: false,
        show_time: false,
    };
    let _ = weak.upgrade_in_event_loop(move |ui| {
        let mut messages = ui.get_support_ticket_messages().iter().collect::<Vec<_>>();
        messages.push(item);
        ui.set_support_ticket_messages(ModelRc::from(Rc::new(VecModel::from(messages))));
        ui.set_ticket_reply_text("".into());
        ui.set_ticket_sending(true);
        ui.set_ticket_send_error("".into());
    });
    schedule_ticket_scroll_to_bottom(weak);
}

pub fn post_support_ticket_retrying(weak: &slint::Weak<AppWindow>, local_id: &str) {
    let local_id = local_id.to_owned();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        let mut messages = ui.get_support_ticket_messages().iter().collect::<Vec<_>>();
        for message in &mut messages {
            if message.id.as_str() == local_id {
                message.sending = true;
                message.failed = false;
            }
        }
        ui.set_support_ticket_messages(ModelRc::from(Rc::new(VecModel::from(messages))));
        ui.set_ticket_sending(true);
        ui.set_ticket_send_error("".into());
    });
}

pub fn post_support_ticket_delivered(
    weak: &slint::Weak<AppWindow>,
    local_id: &str,
    detail: &SupportTicketDetail,
) {
    let local_id = local_id.to_owned();
    let delivered = map_support_ticket_messages(&detail.messages);
    let ticket = map_support_ticket(&detail.ticket);
    let message_page = i32::try_from(detail.message_page).unwrap_or(i32::MAX);
    let message_total = i32::try_from(detail.message_total).unwrap_or(i32::MAX);
    let has_earlier = detail.has_earlier_messages();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        let mut existing = ui
            .get_support_ticket_messages()
            .iter()
            .filter(|message| message.id.as_str() != local_id)
            .collect::<Vec<_>>();
        let mut ids = existing
            .iter()
            .map(|item| item.id.to_string())
            .collect::<HashSet<_>>();
        existing.extend(
            delivered
                .into_iter()
                .filter(|item| ids.insert(item.id.to_string())),
        );
        apply_selected_support_ticket(&ui, &ticket);
        upsert_support_ticket_item(&ui, ticket);
        ui.set_support_ticket_messages(ModelRc::from(Rc::new(VecModel::from(existing))));
        ui.set_ticket_message_page(message_page);
        ui.set_ticket_message_total(message_total);
        ui.set_ticket_has_earlier(has_earlier);
        ui.set_ticket_sending(false);
        ui.set_ticket_send_error("".into());
    });
    schedule_ticket_scroll_to_bottom(weak);
}

pub fn post_support_ticket_send_error(
    weak: &slint::Weak<AppWindow>,
    local_id: &str,
    message: impl Into<SharedString>,
) {
    let local_id = local_id.to_owned();
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        let mut messages = ui.get_support_ticket_messages().iter().collect::<Vec<_>>();
        for item in &mut messages {
            if item.id.as_str() == local_id {
                item.sending = false;
                item.failed = true;
            }
        }
        ui.set_support_ticket_messages(ModelRc::from(Rc::new(VecModel::from(messages))));
        ui.set_ticket_sending(false);
        ui.set_ticket_send_error(message);
    });
}

pub fn post_support_ticket_create_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_ticket_creating(false);
        ui.set_ticket_create_error(message);
    });
}

pub fn post_support_ticket_closed(weak: &slint::Weak<AppWindow>, action: &SupportTicketAction) {
    let id = action.id.to_string();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_selected_ticket_closed(true);
        ui.set_selected_ticket_status_label("已关闭".into());
        ui.set_selected_ticket_status_tone("closed".into());
        ui.set_ticket_closing(false);
        ui.set_ticket_close_error("".into());
        ui.set_ticket_close_confirmation_visible(false);
        let mut tickets = ui.get_support_tickets().iter().collect::<Vec<_>>();
        for ticket in &mut tickets {
            if ticket.id.as_str() == id {
                ticket.closed = true;
                ticket.status_label = "已关闭".into();
                ticket.status_tone = "closed".into();
            }
        }
        ui.set_support_tickets(ModelRc::from(Rc::new(VecModel::from(tickets))));
    });
}

pub fn post_support_ticket_close_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_ticket_closing(false);
        ui.set_ticket_close_error(message);
    });
}

fn schedule_ticket_scroll_to_bottom(weak: &slint::Weak<AppWindow>) {
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        // The message model and the conditional chat view are updated in the
        // same event-loop turn. Wait for the next rendered layout before
        // reading the ScrollView's viewport height, otherwise a newly opened
        // conversation can incorrectly stay at its oldest message.
        slint::Timer::single_shot(Duration::from_millis(32), move || {
            if let Some(ui) = weak.upgrade() {
                ui.invoke_scroll_ticket_chat_to_bottom();
            }
        });
    });
}

pub fn post_gift_card_config(weak: &slint::Weak<AppWindow>, config: &GiftCardConfig) {
    let purchase_url = config.purchase_url.clone();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_gift_card_purchase_url(purchase_url.into());
        ui.set_gift_card_initializing(false);
        ui.set_gift_card_initialization_error("".into());
    });
}

pub fn post_gift_card_initialization_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_gift_card_initializing(false);
        ui.set_gift_card_initialization_error(message);
    });
}

pub fn post_gift_card_check(weak: &slint::Weak<AppWindow>, check: &GiftCardRedeemCheck) {
    let reward = map_gift_card_reward(&check.reward);
    let can_redeem = check.can_redeem;
    let reason = check.reason.clone();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_gift_card_reward(reward);
        ui.set_gift_card_has_check(true);
        ui.set_gift_card_can_redeem(can_redeem);
        ui.set_gift_card_check_reason(reason.into());
        ui.set_gift_card_checking(false);
        ui.set_gift_card_check_error("".into());
        ui.set_gift_card_redeem_error("".into());
    });
}

pub fn post_gift_card_check_error(weak: &slint::Weak<AppWindow>, message: impl Into<SharedString>) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_gift_card_checking(false);
        ui.set_gift_card_check_error(message);
        ui.set_gift_card_has_check(false);
        ui.set_gift_card_can_redeem(false);
    });
}

pub fn post_gift_card_redeemed(weak: &slint::Weak<AppWindow>, reward: &GiftCardRewardPreview) {
    let reward = map_gift_card_reward(reward);
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_gift_card_reward(reward);
        ui.set_gift_card_redeeming(false);
        ui.set_gift_card_redeem_error("".into());
        ui.set_gift_card_redeemed(true);
        ui.set_gift_card_has_check(false);
        ui.set_gift_card_can_redeem(false);
    });
}

pub fn post_gift_card_redeem_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_gift_card_redeeming(false);
        ui.set_gift_card_redeem_error(message);
    });
}

pub fn post_affiliate_summary(weak: &slint::Weak<AppWindow>, summary: &AffiliateSummary) {
    let available = format_money(summary.available_commission_cents, "CNY");
    let total = format_money(summary.total_commission_cents, "CNY");
    let cooling = format_money(summary.cooling_commission_cents, "CNY");
    let rate = format_rate_bps(summary.effective_rate_bps);
    let count = format!("{} 人", summary.invitation_count);
    let code = summary.affiliate_code.clone();
    let url = summary.invitation_url.clone();
    let enabled = summary.enabled;
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_invitation_available_commission(available.into());
        ui.set_invitation_total_commission(total.into());
        ui.set_invitation_cooling_commission(cooling.into());
        ui.set_invitation_rate(rate.into());
        ui.set_invitation_count(count.into());
        ui.set_invitation_code(code.into());
        ui.set_invitation_url(url.into());
        ui.set_invitation_enabled(enabled);
        ui.set_invitation_has_summary(true);
        ui.set_invitation_loading(false);
        ui.set_invitation_error("".into());
    });
}

pub fn post_affiliate_summary_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_invitation_loading(false);
        ui.set_invitation_error(message);
    });
}

pub fn post_affiliate_commissions(
    weak: &slint::Weak<AppWindow>,
    page: &AffiliateCommissionPage,
    append: bool,
) {
    let mut items = page
        .commissions
        .iter()
        .map(map_affiliate_commission)
        .collect::<Vec<_>>();
    let page_number = i32::try_from(page.page).unwrap_or(i32::MAX);
    let total = i32::try_from(page.total).unwrap_or(i32::MAX);
    let has_more = page.has_more();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        if append {
            let mut existing = ui.get_invitation_commissions().iter().collect::<Vec<_>>();
            existing.append(&mut items);
            items = existing;
        }
        ui.set_invitation_commissions(ModelRc::from(Rc::new(VecModel::from(items))));
        ui.set_invitation_commissions_page(page_number);
        ui.set_invitation_commissions_total(total);
        ui.set_invitation_commissions_has_more(has_more);
        ui.set_invitation_commissions_loading(false);
        ui.set_invitation_commissions_loading_more(false);
        ui.set_invitation_commissions_error("".into());
    });
}

pub fn post_affiliate_commissions_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_invitation_commissions_loading(false);
        ui.set_invitation_commissions_loading_more(false);
        ui.set_invitation_commissions_error(message);
    });
}

pub fn post_affiliate_transfers(
    weak: &slint::Weak<AppWindow>,
    page: &AffiliateTransferPage,
    append: bool,
) {
    let mut items = page
        .transfers
        .iter()
        .map(map_affiliate_transfer)
        .collect::<Vec<_>>();
    let page_number = i32::try_from(page.page).unwrap_or(i32::MAX);
    let total = i32::try_from(page.total).unwrap_or(i32::MAX);
    let has_more = page.has_more();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        if append {
            let mut existing = ui.get_invitation_transfers().iter().collect::<Vec<_>>();
            existing.append(&mut items);
            items = existing;
        }
        ui.set_invitation_transfers(ModelRc::from(Rc::new(VecModel::from(items))));
        ui.set_invitation_transfers_page(page_number);
        ui.set_invitation_transfers_total(total);
        ui.set_invitation_transfers_has_more(has_more);
        ui.set_invitation_transfers_loading(false);
        ui.set_invitation_transfers_loading_more(false);
        ui.set_invitation_transfers_error("".into());
    });
}

pub fn post_affiliate_transfers_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_invitation_transfers_loading(false);
        ui.set_invitation_transfers_loading_more(false);
        ui.set_invitation_transfers_error(message);
    });
}

pub fn post_account_settings_error(
    weak: &slint::Weak<AppWindow>,
    message: impl Into<SharedString>,
) {
    let message = message.into();
    let _ = weak.upgrade_in_event_loop(move |ui| {
        ui.set_account_settings_busy(false);
        ui.set_account_settings_error(message);
    });
}

fn post_account_view(
    weak: &slint::Weak<AppWindow>,
    snapshot: AccountSnapshot,
    settings: DesktopSettings,
    latency: NodeLatencySnapshot,
) -> Result<(), slint::EventLoopError> {
    weak.upgrade_in_event_loop(move |ui| {
        apply_account_snapshot(&ui, &snapshot, &settings, &latency);
    })
}

fn apply_account_snapshot(
    ui: &AppWindow,
    snapshot: &AccountSnapshot,
    settings: &DesktopSettings,
    latency: &NodeLatencySnapshot,
) {
    let authenticated = snapshot.is_authenticated();
    let app_phase = match snapshot.phase {
        AccountPhase::Restoring => AppPhase::Restoring,
        AccountPhase::SignedOut | AccountPhase::Authenticating => AppPhase::SignedOut,
        AccountPhase::LoadingResources
        | AccountPhase::RefreshingResources
        | AccountPhase::Ready => AppPhase::SignedIn,
        AccountPhase::Failed => {
            if authenticated {
                AppPhase::SignedIn
            } else {
                AppPhase::SignedOut
            }
        }
    };
    let resource_phase = match snapshot.phase {
        AccountPhase::LoadingResources => ResourcePhase::Loading,
        AccountPhase::RefreshingResources => ResourcePhase::Refreshing,
        AccountPhase::Ready => ResourcePhase::Ready,
        AccountPhase::Failed if authenticated => ResourcePhase::Failed,
        _ => ResourcePhase::Idle,
    };
    ui.set_app_phase(app_phase);
    ui.set_login_submitting(snapshot.phase == AccountPhase::Authenticating);
    ui.set_login_error(
        if authenticated {
            String::new()
        } else {
            snapshot.message.clone().unwrap_or_default()
        }
        .into(),
    );
    ui.set_resource_phase(resource_phase);
    ui.set_resource_error(
        if authenticated {
            snapshot.message.clone().unwrap_or_default()
        } else {
            String::new()
        }
        .into(),
    );
    if let Some(user) = &snapshot.user {
        ui.set_user_display_name(user.username.clone().into());
        ui.set_user_email(user.email.clone().into());
        ui.set_user_balance_label(format_money(user.balance_cents, "CNY").into());
        ui.set_user_balance_cents(clamp_i64_to_i32(user.balance_cents));
    } else {
        ui.set_user_display_name("".into());
        ui.set_user_email("".into());
        ui.set_user_balance_label("¥0.00".into());
        ui.set_user_balance_cents(0);
    }

    let groups = map_resource_groups(
        &snapshot.groups,
        &settings.selected_group_id,
        &settings.selected_entitlement_id,
    );
    let resource_groups = ui.get_resource_groups();
    if !update_model_rows(&resource_groups, &groups, |left, right| left.id == right.id) {
        ui.set_resource_groups(ModelRc::from(Rc::new(VecModel::from(groups))));
    }

    apply_subscription_snapshot(ui, &snapshot.groups);

    let selected_group = snapshot
        .groups
        .iter()
        .find(|group| group.id.to_string() == settings.selected_group_id);
    let nodes = selected_group
        .map(|group| {
            group
                .nodes
                .iter()
                .map(|node| map_node(node, &settings.selected_endpoint_id, latency))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ui.set_available_node_count(selected_group.map_or(0, |group| {
        i32::try_from(group.nodes.iter().filter(|node| node.selectable).count()).unwrap_or(i32::MAX)
    }));
    let selected_node = selected_group.and_then(|group| {
        group
            .nodes
            .iter()
            .find(|node| node.endpoint_id == settings.selected_endpoint_id && node.selectable)
    });
    let visible_nodes = ui.get_visible_nodes();
    if !update_model_rows(&visible_nodes, &nodes, |left, right| left.id == right.id) {
        ui.set_visible_nodes(ModelRc::from(Rc::new(VecModel::from(nodes))));
    }
    ui.set_has_selected_node(selected_node.is_some());
    ui.set_selected_node(selected_node.map_or_else(empty_node, |node| {
        map_node(node, &settings.selected_endpoint_id, latency)
    }));
    update_action_availability(ui);
}

fn apply_subscription_snapshot(ui: &AppWindow, groups: &[ServerGroup]) {
    let (plans, addons) = map_subscription_items(groups);
    let current_selection = ui.get_selected_subscription_plan_id();
    let selected = resolve_selected_subscription_plan(&plans, current_selection.as_str());
    let selected_id = selected.map_or_else(SharedString::default, |item| item.id.clone());
    let selected_catalog_plan_id =
        selected.map_or_else(SharedString::default, |item| item.plan_id.clone());
    let selected_addon_count = selected.map_or(0, |item| item.related_addon_count);
    let plan_model = ui.get_subscription_plans();
    if !update_model_rows(&plan_model, &plans, |left, right| left.id == right.id) {
        ui.set_subscription_plans(ModelRc::from(Rc::new(VecModel::from(plans))));
    }
    let addon_model = ui.get_subscription_addons();
    if !update_model_rows(&addon_model, &addons, |left, right| left.id == right.id) {
        ui.set_subscription_addons(ModelRc::from(Rc::new(VecModel::from(addons))));
    }
    ui.set_selected_subscription_plan_id(selected_id);
    ui.set_selected_subscription_catalog_plan_id(selected_catalog_plan_id);
    ui.set_selected_subscription_addon_count(selected_addon_count);
}

fn apply_shop_snapshot(ui: &AppWindow, snapshot: &ShopSnapshot) {
    ui.set_shop_phase(match snapshot.phase {
        ApplicationShopPhase::Idle => ShopPhase::Idle,
        ApplicationShopPhase::Loading => ShopPhase::Loading,
        ApplicationShopPhase::Ready => ShopPhase::Ready,
        ApplicationShopPhase::Failed => ShopPhase::Failed,
    });
    ui.set_shop_error(snapshot.message.clone().unwrap_or_default().into());
    ui.set_shop_purchasing(snapshot.purchasing);
    let (plans, prices, addons, payment_methods) = map_shop_catalog(&snapshot.catalog);
    ui.set_shop_plans(ModelRc::from(Rc::new(VecModel::from(plans))));
    ui.set_shop_prices(ModelRc::from(Rc::new(VecModel::from(prices))));
    ui.set_shop_addons(ModelRc::from(Rc::new(VecModel::from(addons))));
    ui.set_payment_methods(ModelRc::from(Rc::new(VecModel::from(payment_methods))));
}

fn map_shop_catalog(
    catalog: &ShopCatalog,
) -> (
    Vec<ShopPlanItem>,
    Vec<ShopPriceItem>,
    Vec<ShopAddonItem>,
    Vec<PaymentMethodItem>,
) {
    let plans = catalog
        .plans
        .iter()
        .filter(|plan| !plan.prices.is_empty())
        .map(map_shop_plan)
        .collect();
    let prices = catalog
        .plans
        .iter()
        .flat_map(|plan| {
            plan.prices
                .iter()
                .enumerate()
                .map(move |(option_index, price)| ShopPriceItem {
                    id: price.id.to_string().into(),
                    plan_id: plan.id.to_string().into(),
                    option_index: i32::try_from(option_index).unwrap_or(i32::MAX),
                    label: shop_period_label(&price.label, &price.period_unit, price.period_count)
                        .into(),
                    price_label: format_money(price.price_cents, &price.currency).into(),
                    traffic_label: format_subscription_bytes(price.included_traffic_bytes).into(),
                    price_cents: clamp_i64_to_i32(price.price_cents),
                    requires_payment: price.price_cents > 0,
                })
        })
        .collect();
    let addons = catalog
        .plans
        .iter()
        .flat_map(|plan| {
            plan.traffic_addons
                .iter()
                .enumerate()
                .map(move |(option_index, addon)| ShopAddonItem {
                    id: addon.id.to_string().into(),
                    plan_id: plan.id.to_string().into(),
                    option_index: i32::try_from(option_index).unwrap_or(i32::MAX),
                    plan_addon_count: i32::try_from(plan.traffic_addons.len()).unwrap_or(i32::MAX),
                    title: addon.name.trim().into(),
                    plan_title: plan.name.trim().into(),
                    plan_description: plain_shop_description(&plan.description).into(),
                    price_label: format_money(addon.price_cents, &addon.currency).into(),
                    traffic_label: format_subscription_bytes(addon.traffic_bytes).into(),
                    price_cents: clamp_i64_to_i32(addon.price_cents),
                    requires_payment: addon.price_cents > 0,
                    purchase_enabled: plan.addon_available,
                })
        })
        .collect();
    let payment_methods = catalog
        .payment_methods
        .iter()
        .filter(|method| method.id > 0)
        .map(|method| {
            let title = non_blank(&method.name)
                .or_else(|| non_blank(&method.provider_name))
                .or_else(|| non_blank(&method.payment_type_name))
                .unwrap_or("在线支付");
            let subtitle = [&method.provider_name, &method.payment_type_name]
                .into_iter()
                .map(String::as_str)
                .filter_map(non_blank)
                .filter(|value| *value != title)
                .collect::<Vec<_>>()
                .join(" · ");
            PaymentMethodItem {
                id: method.id.to_string().into(),
                title: title.into(),
                subtitle: subtitle.into(),
                provider: method.provider.trim().into(),
                payment_type: method.payment_type.trim().into(),
            }
        })
        .collect();
    (plans, prices, addons, payment_methods)
}

fn map_shop_plan(plan: &ShopPlan) -> ShopPlanItem {
    let starting_price = plan.prices.iter().min_by_key(|price| price.price_cents);
    let default_price = plan.prices.first();
    ShopPlanItem {
        id: plan.id.to_string().into(),
        title: plan.name.trim().into(),
        description: plain_shop_description(&plan.description).into(),
        starting_price_label: starting_price
            .map_or_else(
                || "—".to_owned(),
                |price| format_money(price.price_cents, &price.currency),
            )
            .into(),
        default_price_id: default_price
            .map_or_else(String::new, |price| price.id.to_string())
            .into(),
        default_price_label: default_price
            .map_or_else(
                || "—".to_owned(),
                |price| format_money(price.price_cents, &price.currency),
            )
            .into(),
        default_price_cents: default_price.map_or(0, |price| clamp_i64_to_i32(price.price_cents)),
        default_price_requires_payment: default_price.is_some_and(|price| price.price_cents > 0),
        traffic_label: starting_price
            .map_or_else(
                || "—".to_owned(),
                |price| format_subscription_bytes(price.included_traffic_bytes),
            )
            .into(),
        option_label: format!("{} 种", plan.prices.len()).into(),
        price_count: i32::try_from(plan.prices.len()).unwrap_or(i32::MAX),
    }
}

fn plain_shop_description(description: &str) -> String {
    description
        .lines()
        .map(str::trim)
        .map(|line| line.trim_start_matches('#').trim())
        .map(|line| {
            ["- ", "* ", "+ "]
                .into_iter()
                .find_map(|prefix| line.strip_prefix(prefix))
                .unwrap_or(line)
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

fn shop_period_label(label: &str, unit: &str, count: u32) -> String {
    if let Some(label) = non_blank(label) {
        return label.to_owned();
    }
    let unit = match unit.to_ascii_lowercase().as_str() {
        "day" | "days" => "天",
        "week" | "weeks" => "周",
        "month" | "months" => "个月",
        "year" | "years" => "年",
        _ => "个周期",
    };
    format!("{count} {unit}")
}

pub(crate) fn format_money(cents: i64, currency: &str) -> String {
    let amount = cents.unsigned_abs();
    let sign = if cents < 0 { "-" } else { "" };
    let amount = format!("{}.{:02}", amount / 100, amount % 100);
    match currency.trim().to_ascii_uppercase().as_str() {
        "" | "CNY" | "RMB" => format!("{sign}¥{amount}"),
        "USD" => format!("{sign}${amount}"),
        "EUR" => format!("{sign}€{amount}"),
        currency => format!("{sign}{currency} {amount}"),
    }
}

fn map_balance_transaction(transaction: &BalanceTransaction) -> BalanceTransactionItem {
    let (title, kind_icon) = match transaction.transaction_type {
        BalanceTransactionType::OrderPayment => ("余额支付", "↓"),
        BalanceTransactionType::OrderRefund => ("退款返还余额", "↙"),
        BalanceTransactionType::GiftCard => ("礼品卡充值", "+"),
        BalanceTransactionType::AffiliateTransfer => ("佣金转入余额", "⇩"),
        BalanceTransactionType::AdminAdjustment => ("余额调整", "↕"),
        BalanceTransactionType::Unknown => ("余额变动", "↕"),
    };
    let description = transaction.description.trim();
    let description = if matches!(
        transaction.transaction_type,
        BalanceTransactionType::OrderPayment | BalanceTransactionType::OrderRefund
    ) || description == title
    {
        String::new()
    } else {
        description.to_owned()
    };
    BalanceTransactionItem {
        id: transaction.id.to_string().into(),
        title: title.into(),
        kind_icon: kind_icon.into(),
        description: description.into(),
        amount_label: format_signed_amount(transaction.amount_cents).into(),
        balance_after_label: format_money(transaction.balance_after_cents, "CNY").into(),
        balance_before_label: format_money(transaction.balance_before_cents, "CNY").into(),
        created_at_label: format_transaction_time(transaction.created_at_epoch_seconds).into(),
        reference_label: transaction_reference_label(transaction).into(),
        credit: transaction.amount_cents >= 0,
    }
}

fn map_order(order: &UserOrder) -> OrderItem {
    let (status_label, status_tone) = match order.status {
        UserOrderStatus::Paid => ("已完成", "paid"),
        UserOrderStatus::Pending if order.can_pay => ("待支付", "pending"),
        UserOrderStatus::Pending => ("处理中", "neutral"),
        UserOrderStatus::Refunded => ("已退款", "refunded"),
        UserOrderStatus::Unknown => ("状态已更新", "neutral"),
    };
    let title = order_title(order);
    let specification = order_specification(order, &title);
    let payment_method = order.payment_method.as_ref().map_or_else(
        || {
            if order.amount_cents == 0 {
                "免支付".to_owned()
            } else if order.status == UserOrderStatus::Pending {
                "尚未选择".to_owned()
            } else {
                "—".to_owned()
            }
        },
        |method| {
            [
                method.name.as_str(),
                method.payment_type_name.as_str(),
                method.payment_type.as_str(),
                method.provider_name.as_str(),
                method.provider.as_str(),
            ]
            .into_iter()
            .find_map(non_blank)
            .unwrap_or("—")
            .to_owned()
        },
    );
    let list_time = order
        .refunded_at_epoch_seconds
        .or(order.paid_at_epoch_seconds)
        .unwrap_or(order.created_at_epoch_seconds);
    OrderItem {
        id: order.id.to_string().into(),
        order_number: order.order_number.clone().into(),
        title: title.into(),
        specification: specification.into(),
        amount_label: format_money(order.amount_cents, &order.currency).into(),
        status_label: status_label.into(),
        status_tone: status_tone.into(),
        list_time_label: format_order_list_time(list_time).into(),
        type_label: match order.order_type {
            UserOrderType::BasePlan => "套餐订阅",
            UserOrderType::TrafficAddon => "流量包",
            UserOrderType::Unknown => "其他",
        }
        .into(),
        payment_method_label: payment_method.into(),
        balance_refunded_label: if order.balance_refunded_cents > 0 {
            format_money(order.balance_refunded_cents, &order.currency)
        } else {
            String::new()
        }
        .into(),
        created_at_label: format_transaction_time(order.created_at_epoch_seconds).into(),
        paid_at_label: order
            .paid_at_epoch_seconds
            .map(format_transaction_time)
            .unwrap_or_default()
            .into(),
        refunded_at_label: order
            .refunded_at_epoch_seconds
            .map(format_transaction_time)
            .unwrap_or_default()
            .into(),
        updated_at_label: format_transaction_time(order.updated_at_epoch_seconds).into(),
    }
}

fn map_support_ticket(ticket: &SupportTicket) -> SupportTicketItem {
    let (status_label, status_tone, closed) = match ticket.status {
        SupportTicketStatus::PendingReply => ("待客服回复", "pending", false),
        SupportTicketStatus::Replied => ("客服已回复", "replied", false),
        SupportTicketStatus::Closed => ("已关闭", "closed", true),
        SupportTicketStatus::Unknown => ("状态已更新", "neutral", false),
    };
    let priority_label = match ticket.priority {
        SupportTicketPriority::Low => "低优先级",
        SupportTicketPriority::Medium => "普通优先级",
        SupportTicketPriority::High => "高优先级",
        SupportTicketPriority::Unknown => "优先级未知",
    };
    SupportTicketItem {
        id: ticket.id.to_string().into(),
        ticket_number: ticket.ticket_number.clone().into(),
        title: ticket.title.clone().into(),
        status_label: status_label.into(),
        status_tone: status_tone.into(),
        priority_label: priority_label.into(),
        updated_at_label: format_order_list_time(ticket.updated_at_epoch_seconds).into(),
        unread: ticket.has_unread_reply,
        closed,
    }
}

fn map_support_ticket_messages(messages: &[SupportTicketMessage]) -> Vec<SupportTicketMessageItem> {
    messages
        .iter()
        .enumerate()
        .map(|(index, message)| {
            let show_time = index == 0
                || messages[index - 1]
                    .created_at_epoch_seconds
                    .checked_add(5 * 60)
                    .is_none_or(|threshold| message.created_at_epoch_seconds >= threshold);
            let own = message.sender_role == SupportTicketSenderRole::User;
            let sender_label = if own {
                "我"
            } else {
                non_blank(&message.sender_name).unwrap_or("客服")
            };
            SupportTicketMessageItem {
                id: message.id.to_string().into(),
                content: message.content.clone().into(),
                sender_label: sender_label.into(),
                time_label: format_chat_time(message.created_at_epoch_seconds).into(),
                own,
                sending: false,
                failed: false,
                show_time,
            }
        })
        .collect()
}

fn apply_selected_support_ticket(ui: &AppWindow, ticket: &SupportTicketItem) {
    ui.set_selected_ticket_id(ticket.id.clone());
    ui.set_selected_ticket_title(ticket.title.clone());
    ui.set_selected_ticket_number(ticket.ticket_number.clone());
    ui.set_selected_ticket_status_label(ticket.status_label.clone());
    ui.set_selected_ticket_status_tone(ticket.status_tone.clone());
    ui.set_selected_ticket_priority_label(ticket.priority_label.clone());
    ui.set_selected_ticket_closed(ticket.closed);
}

fn upsert_support_ticket_item(ui: &AppWindow, mut ticket: SupportTicketItem) {
    ticket.unread = false;
    let existing = ui.get_support_tickets().iter().collect::<Vec<_>>();
    let mut tickets = vec![ticket.clone()];
    tickets.extend(
        existing
            .into_iter()
            .filter(|existing| existing.id != ticket.id),
    );
    ui.set_support_tickets(ModelRc::from(Rc::new(VecModel::from(tickets))));
}

fn format_chat_time(epoch_seconds: i64) -> String {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let Some(value) = OffsetDateTime::from_unix_timestamp(epoch_seconds)
        .ok()
        .map(|value| value.to_offset(offset))
    else {
        return "时间未知".to_owned();
    };
    let now = OffsetDateTime::now_utc().to_offset(offset);
    if value.date() == now.date() {
        return format!("{:02}:{:02}", value.hour(), value.minute());
    }
    if now.date().previous_day() == Some(value.date()) {
        return format!("昨天 {:02}:{:02}", value.hour(), value.minute());
    }
    if value.year() == now.year() {
        return format!(
            "{:02}-{:02} {:02}:{:02}",
            u8::from(value.month()),
            value.day(),
            value.hour(),
            value.minute()
        );
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute()
    )
}

fn map_gift_card_reward(reward: &GiftCardRewardPreview) -> GiftCardRewardItem {
    let (reward_type, title, subtitle) = match reward.reward_type {
        GiftCardRewardType::Balance => (
            "balance",
            if reward.balance_amount_cents > 0 {
                format_money(reward.balance_amount_cents, "CNY")
            } else {
                non_blank(&reward.summary).unwrap_or("余额权益").to_owned()
            },
            "将充值至当前账户余额".to_owned(),
        ),
        GiftCardRewardType::Plan => (
            "plan",
            non_blank(&reward.plan_name)
                .or_else(|| non_blank(&reward.summary))
                .unwrap_or("套餐权益")
                .to_owned(),
            join_gift_card_details([&reward.price_label, &reward.group_name]),
        ),
        GiftCardRewardType::Traffic => (
            "traffic",
            if reward.traffic_quota_bytes > 0 {
                format_bytes(reward.traffic_quota_bytes.unsigned_abs())
            } else {
                non_blank(&reward.summary).unwrap_or("流量权益").to_owned()
            },
            join_gift_card_details([&reward.plan_name, &reward.group_name]),
        ),
        GiftCardRewardType::Unknown => (
            "unknown",
            non_blank(&reward.summary)
                .unwrap_or("礼品卡权益")
                .to_owned(),
            String::new(),
        ),
    };
    GiftCardRewardItem {
        reward_type: reward_type.into(),
        title: title.into(),
        subtitle: subtitle.into(),
        summary: reward.summary.clone().into(),
    }
}

fn map_affiliate_commission(commission: &AffiliateCommission) -> AffiliateCommissionItem {
    let (status_label, status_tone) = match commission.status {
        AffiliateCommissionStatus::Cooling => ("冷却中", "cooling"),
        AffiliateCommissionStatus::Unlocked => ("可用", "available"),
        AffiliateCommissionStatus::Reversed => ("已撤销", "reversed"),
        AffiliateCommissionStatus::Unknown => ("状态已更新", "neutral"),
    };
    AffiliateCommissionItem {
        id: commission.id.to_string().into(),
        invitee: non_blank(&commission.invitee).unwrap_or("受邀用户").into(),
        order_number: commission.order_number.clone().into(),
        rebate_type_label: match commission.rebate_type {
            AffiliateRebateType::First => "首次返佣",
            AffiliateRebateType::Recurring => "循环返佣",
            AffiliateRebateType::Unknown => "返佣",
        }
        .into(),
        rate_label: format_rate_bps(commission.rate_bps).into(),
        base_amount_label: format_money(commission.base_amount_cents, "CNY").into(),
        amount_label: format_money(commission.commission_cents, "CNY").into(),
        status_label: status_label.into(),
        status_tone: status_tone.into(),
        created_at_label: format_transaction_time(commission.created_at_epoch_seconds).into(),
        available_at_label: commission
            .available_at_epoch_seconds
            .map(format_transaction_time)
            .unwrap_or_default()
            .into(),
        released_at_label: commission
            .released_at_epoch_seconds
            .map(format_transaction_time)
            .unwrap_or_default()
            .into(),
        reversed_at_label: commission
            .reversed_at_epoch_seconds
            .map(format_transaction_time)
            .unwrap_or_default()
            .into(),
        reversed_deducted_label: if commission.reversed_deducted_cents > 0 {
            format_money(commission.reversed_deducted_cents, "CNY")
        } else {
            String::new()
        }
        .into(),
    }
}

fn map_affiliate_transfer(transfer: &AffiliateTransfer) -> AffiliateTransferItem {
    AffiliateTransferItem {
        id: transfer.id.to_string().into(),
        request_id: transfer.request_id.clone().into(),
        amount_label: format_money(transfer.amount_cents, "CNY").into(),
        balance_after_label: format_money(transfer.balance_after_cents, "CNY").into(),
        created_at_label: format_transaction_time(transfer.created_at_epoch_seconds).into(),
    }
}

fn format_rate_bps(rate_bps: i32) -> String {
    let whole = rate_bps / 100;
    let fractional = rate_bps.unsigned_abs() % 100;
    if fractional == 0 {
        format!("{whole}%")
    } else if fractional.is_multiple_of(10) {
        format!("{whole}.{}%", fractional / 10)
    } else {
        format!("{whole}.{fractional:02}%")
    }
}

fn join_gift_card_details<const N: usize>(values: [&String; N]) -> String {
    values
        .into_iter()
        .filter_map(|value| non_blank(value))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn order_title(order: &UserOrder) -> String {
    match order.order_type {
        UserOrderType::TrafficAddon => non_blank(&order.item.traffic_addon_name)
            .or_else(|| non_blank(&order.item.description))
            .unwrap_or("流量包购买"),
        UserOrderType::BasePlan => non_blank(&order.item.plan_name)
            .or_else(|| non_blank(&order.item.description))
            .unwrap_or("套餐订单"),
        UserOrderType::Unknown => non_blank(&order.item.description).unwrap_or("订单"),
    }
    .to_owned()
}

fn order_specification(order: &UserOrder, title: &str) -> String {
    let mut values = Vec::new();
    match order.order_type {
        UserOrderType::TrafficAddon => {
            push_distinct_non_blank(&mut values, &order.item.plan_name);
            if order.item.traffic_quota_bytes > 0 {
                push_distinct_non_blank(
                    &mut values,
                    &format_bytes(order.item.traffic_quota_bytes.unsigned_abs()),
                );
            }
        }
        UserOrderType::BasePlan => {
            push_distinct_non_blank(&mut values, &order.item.price_label);
            let period = order_period_description(order);
            push_distinct_non_blank(&mut values, &period);
            if values.is_empty() && order.item.description.trim() != title {
                push_distinct_non_blank(&mut values, &order.item.description);
            }
        }
        UserOrderType::Unknown => {
            if order.item.description.trim() != title {
                push_distinct_non_blank(&mut values, &order.item.description);
            }
        }
    }
    values.join(" · ")
}

fn push_distinct_non_blank(values: &mut Vec<String>, value: &str) {
    if let Some(value) = non_blank(value)
        && !values.iter().any(|existing| existing == value)
    {
        values.push(value.to_owned());
    }
}

fn order_period_description(order: &UserOrder) -> String {
    if order.item.period_count == 0 {
        return String::new();
    }
    let unit = match order.item.period_unit.trim().to_ascii_lowercase().as_str() {
        "day" => "天",
        "month" => "个月",
        "year" => "年",
        _ => return String::new(),
    };
    format!("{}{unit}", order.item.period_count)
}

fn format_order_list_time(epoch_seconds: i64) -> String {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    OffsetDateTime::from_unix_timestamp(epoch_seconds)
        .ok()
        .map(|value| value.to_offset(offset))
        .map_or_else(
            || "时间未知".to_owned(),
            |value| {
                format!(
                    "{:02}-{:02} {:02}:{:02}",
                    u8::from(value.month()),
                    value.day(),
                    value.hour(),
                    value.minute()
                )
            },
        )
}

fn format_signed_amount(cents: i64) -> String {
    let sign = match cents.cmp(&0) {
        std::cmp::Ordering::Greater => "+",
        std::cmp::Ordering::Less => "-",
        std::cmp::Ordering::Equal => "",
    };
    let amount = cents.unsigned_abs();
    format!("{sign}{}.{:02}", amount / 100, amount % 100)
}

fn format_transaction_time(epoch_seconds: i64) -> String {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    format_transaction_time_at_offset(epoch_seconds, offset)
        .unwrap_or_else(|| "时间未知".to_owned())
}

fn format_transaction_time_at_offset(epoch_seconds: i64, offset: UtcOffset) -> Option<String> {
    let value = OffsetDateTime::from_unix_timestamp(epoch_seconds)
        .ok()?
        .to_offset(offset);
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
    ))
}

fn transaction_reference_label(transaction: &BalanceTransaction) -> String {
    find_order_number(&transaction.description)
        .map(str::to_owned)
        .or_else(|| transaction.reference_id.map(|id| format!("关联记录 #{id}")))
        .unwrap_or_default()
}

fn find_order_number(value: &str) -> Option<&str> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .find(|part| {
            part.len() > 3
                && part
                    .get(..3)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ORD"))
                && part[3..].bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

pub(crate) fn clamp_i64_to_i32(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(if value.is_negative() {
        i32::MIN
    } else {
        i32::MAX
    })
}

fn apply_connection_state(ui: &AppWindow, state: &ConnectionState) {
    let (phase, title, detail, button) = match state {
        ConnectionState::Disconnected => (
            ConnectionPhase::Disconnected,
            "准备连接",
            "请先选择节点，再建立安全连接",
            "开始连接",
        ),
        ConnectionState::Preparing => (
            ConnectionPhase::Preparing,
            "正在连接",
            "正在建立安全通道，请稍候",
            "正在准备",
        ),
        ConnectionState::Validating => (
            ConnectionPhase::Validating,
            "正在连接",
            "正在建立安全通道，请稍候",
            "正在连接",
        ),
        ConnectionState::Starting => (
            ConnectionPhase::Starting,
            "正在连接",
            "正在建立安全通道，请稍候",
            "正在连接",
        ),
        ConnectionState::Connected { .. } => (
            ConnectionPhase::Connected,
            "已安全连接",
            "设备流量正在通过安全通道传输",
            "断开连接",
        ),
        ConnectionState::Stopping => (
            ConnectionPhase::Stopping,
            "正在断开",
            "正在释放连接资源",
            "正在断开",
        ),
        ConnectionState::Failed { .. } => (
            ConnectionPhase::Failed,
            "连接未完成",
            "请检查当前网络后重新尝试",
            "重新连接",
        ),
    };
    ui.set_connection_phase(phase);
    ui.set_connection_title(title.into());
    ui.set_connection_detail(detail.into());
    ui.set_connection_button_label(button.into());
    ui.set_node_selection_enabled(matches!(
        state,
        ConnectionState::Disconnected | ConnectionState::Failed { .. }
    ));
    update_action_availability(ui);
}

fn update_action_availability(ui: &AppWindow) {
    let can_toggle = match ui.get_connection_phase() {
        ConnectionPhase::Connected => true,
        ConnectionPhase::Disconnected | ConnectionPhase::Failed => {
            ui.get_core_available()
                && ui.get_has_selected_node()
                && ui.get_app_phase() == AppPhase::SignedIn
        }
        _ => false,
    };
    ui.set_can_toggle(can_toggle);
}

fn apply_runtime_telemetry(ui: &AppWindow, snapshot: &RuntimeTelemetrySnapshot) {
    ui.set_download_rate(format!("{}/s", format_bytes(snapshot.download_bytes_per_second)).into());
    ui.set_upload_rate(format!("{}/s", format_bytes(snapshot.upload_bytes_per_second)).into());
    ui.set_download_total(format_bytes(snapshot.download_total_bytes).into());
    ui.set_upload_total(format_bytes(snapshot.upload_total_bytes).into());
    ui.set_active_connections(i32::try_from(snapshot.active_connections).unwrap_or(i32::MAX));
    ui.set_runtime_memory(
        snapshot
            .memory_bytes
            .map_or_else(|| "--".to_owned(), format_bytes)
            .into(),
    );
}

fn map_resource_groups(
    groups: &[ServerGroup],
    selected_group_id: &str,
    selected_entitlement_id: &str,
) -> Vec<ResourceGroupItem> {
    groups
        .iter()
        .flat_map(|group| {
            let active_entitlements = group
                .entitlements
                .iter()
                .filter(|entitlement| is_active_plan_entitlement(entitlement))
                .collect::<Vec<_>>();
            if active_entitlements.is_empty() {
                vec![map_resource_group(
                    group,
                    None,
                    selected_group_id,
                    selected_entitlement_id,
                )]
            } else {
                active_entitlements
                    .into_iter()
                    .map(|entitlement| {
                        map_resource_group(
                            group,
                            Some(entitlement),
                            selected_group_id,
                            selected_entitlement_id,
                        )
                    })
                    .collect()
            }
        })
        .collect()
}

fn map_resource_group(
    group: &ServerGroup,
    entitlement: Option<&Entitlement>,
    selected_group_id: &str,
    selected_entitlement_id: &str,
) -> ResourceGroupItem {
    let name = entitlement
        .map(|value| value.plan_name.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or(group.name.as_str());
    let total_bytes = entitlement.map_or(group.total_quota_bytes, |value| value.quota_bytes);
    let remaining_bytes = entitlement.map_or(group.remaining_bytes, |value| value.remaining_bytes);
    let expires_at_epoch_seconds = entitlement
        .and_then(|value| {
            (value.expires_at_epoch_seconds > 0).then_some(value.expires_at_epoch_seconds)
        })
        .or_else(|| {
            group
                .next_expires_at_epoch_seconds
                .filter(|value| *value > 0)
        });
    ResourceGroupItem {
        id: entitlement
            .map_or_else(
                || format!("{}:group", group.id),
                |value| format!("{}:{}", group.id, value.grant_id),
            )
            .into(),
        group_id: group.id.to_string().into(),
        entitlement_id: entitlement
            .map(|value| value.grant_id.to_string())
            .unwrap_or_default()
            .into(),
        name: name.into(),
        quota_label: format!(
            "剩余 {} / {}",
            format_quota_bytes(remaining_bytes),
            format_quota_bytes(total_bytes)
        )
        .into(),
        expiry_label: expires_at_epoch_seconds
            .and_then(format_expiry_label)
            .unwrap_or_else(|| "未设置统一期限".to_owned())
            .into(),
        selected: selected_group_id == group.id.to_string()
            && selected_entitlement_id
                == entitlement
                    .map(|value| value.grant_id.to_string())
                    .unwrap_or_default(),
        connectable: group.connectable,
    }
}

fn format_expiry_label(epoch_seconds: u64) -> Option<String> {
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    format_expiry_label_at_offset(epoch_seconds, offset)
}

fn format_expiry_label_at_offset(epoch_seconds: u64, offset: UtcOffset) -> Option<String> {
    let timestamp = i64::try_from(epoch_seconds).ok()?;
    let expiry = OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()?
        .to_offset(offset);
    Some(format!(
        "到期 {:04}-{:02}-{:02}",
        expiry.year(),
        u8::from(expiry.month()),
        expiry.day()
    ))
}

fn is_active_plan_entitlement(entitlement: &Entitlement) -> bool {
    entitlement.status.eq_ignore_ascii_case("active")
        && !is_traffic_addon(entitlement)
        && !entitlement.plan_name.trim().is_empty()
}

fn map_subscription_items(
    groups: &[ServerGroup],
) -> (Vec<SubscriptionItem>, Vec<SubscriptionItem>) {
    let mut seen_grant_ids = HashSet::new();
    let mut plans = Vec::new();
    let mut addons = Vec::new();
    for entitlement in groups.iter().flat_map(|group| &group.entitlements) {
        if !seen_grant_ids.insert(entitlement.grant_id) {
            continue;
        }
        if is_traffic_addon(entitlement) {
            addons.push(entitlement);
        } else {
            plans.push(entitlement);
        }
    }
    plans.sort_by(|left, right| compare_subscription_entitlements(left, right));
    addons.sort_by(|left, right| compare_subscription_entitlements(left, right));
    let addon_counts_by_plan_id = addons
        .iter()
        .fold(HashMap::new(), |mut counts, entitlement| {
            *counts.entry(entitlement.plan_id).or_insert(0_usize) += 1;
            counts
        });
    (
        plans
            .into_iter()
            .map(|entitlement| {
                let related_addon_count = addon_counts_by_plan_id
                    .get(&entitlement.plan_id)
                    .copied()
                    .unwrap_or_default();
                map_subscription_item(
                    entitlement,
                    false,
                    i32::try_from(related_addon_count).unwrap_or(i32::MAX),
                )
            })
            .collect(),
        addons
            .into_iter()
            .map(|entitlement| map_subscription_item(entitlement, true, 0))
            .collect(),
    )
}

fn resolve_selected_subscription_plan<'a>(
    plans: &'a [SubscriptionItem],
    selected_plan_id: &str,
) -> Option<&'a SubscriptionItem> {
    plans
        .iter()
        .find(|plan| plan.id == selected_plan_id)
        .or_else(|| plans.first())
}

fn is_traffic_addon(entitlement: &Entitlement) -> bool {
    entitlement.traffic_addon_id.is_some()
        || entitlement.source.eq_ignore_ascii_case("traffic_addon")
}

fn compare_subscription_entitlements(
    left: &Entitlement,
    right: &Entitlement,
) -> std::cmp::Ordering {
    let status_rank =
        |entitlement: &Entitlement| u8::from(!entitlement.status.eq_ignore_ascii_case("active"));
    let expiry_rank = |entitlement: &Entitlement| {
        if entitlement.expires_at_epoch_seconds == 0 {
            u64::MAX
        } else {
            entitlement.expires_at_epoch_seconds
        }
    };
    status_rank(left)
        .cmp(&status_rank(right))
        .then_with(|| expiry_rank(left).cmp(&expiry_rank(right)))
        // Android entitlement identifiers are strings, so preserve its final
        // lexicographic tie-breaker instead of comparing grant IDs numerically.
        .then_with(|| left.grant_id.to_string().cmp(&right.grant_id.to_string()))
}

fn map_subscription_item(
    entitlement: &Entitlement,
    traffic_addon: bool,
    related_addon_count: i32,
) -> SubscriptionItem {
    let status = map_subscription_status(&entitlement.status);
    let total_bytes = entitlement.quota_bytes.max(0);
    let remaining_bytes = entitlement
        .quota_bytes
        .saturating_sub(entitlement.used_bytes)
        .max(0);
    let usage_progress =
        subscription_usage_progress(entitlement.used_bytes, entitlement.quota_bytes);
    let usage_percentage =
        subscription_usage_percentage(entitlement.used_bytes, entitlement.quota_bytes);
    let title = if traffic_addon {
        non_blank(&entitlement.addon_name)
            .or_else(|| non_blank(&entitlement.plan_name))
            .unwrap_or_default()
    } else {
        non_blank(&entitlement.plan_name).unwrap_or("未命名套餐")
    };
    SubscriptionItem {
        id: entitlement.grant_id.to_string().into(),
        plan_id: entitlement.plan_id.to_string().into(),
        title: title.into(),
        badge_label: if traffic_addon {
            "".into()
        } else {
            non_blank(&entitlement.price_label).unwrap_or("套餐").into()
        },
        status,
        status_label: subscription_status_label(status).into(),
        remaining_value: format_subscription_bytes(remaining_bytes).into(),
        total_value: format_subscription_bytes(total_bytes).into(),
        usage_label: format!("已使用 {usage_percentage}%").into(),
        usage_progress,
        expiry_label: format_subscription_expiry_label(entitlement.expires_at_epoch_seconds).into(),
        related_addon_count,
    }
}

fn non_blank(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn map_subscription_status(status: &str) -> SubscriptionStatus {
    if status.eq_ignore_ascii_case("active") {
        SubscriptionStatus::Active
    } else if status.eq_ignore_ascii_case("expired") {
        SubscriptionStatus::Expired
    } else if status.eq_ignore_ascii_case("exhausted") {
        SubscriptionStatus::Exhausted
    } else {
        SubscriptionStatus::Disabled
    }
}

const fn subscription_status_label(status: SubscriptionStatus) -> &'static str {
    match status {
        SubscriptionStatus::Active => "可用",
        SubscriptionStatus::Expired => "已到期",
        SubscriptionStatus::Exhausted => "已耗尽",
        SubscriptionStatus::Disabled => "已停用",
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn subscription_usage_progress(used_bytes: i64, total_bytes: i64) -> f32 {
    if total_bytes <= 0 {
        return 0.0;
    }
    ((used_bytes as f64) / (total_bytes as f64)).clamp(0.0, 1.0) as f32
}

fn subscription_usage_percentage(used_bytes: i64, total_bytes: i64) -> u32 {
    if used_bytes <= 0 || total_bytes <= 0 {
        return 0;
    }
    if used_bytes >= total_bytes {
        return 100;
    }
    u32::try_from(
        (u128::from(used_bytes.unsigned_abs()) * 100) / u128::from(total_bytes.unsigned_abs()),
    )
    .unwrap_or(100)
}

fn format_subscription_expiry_label(expires_at_epoch_seconds: u64) -> String {
    let now_epoch_seconds =
        u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default();
    format_subscription_expiry_label_at(expires_at_epoch_seconds, now_epoch_seconds)
}

fn format_subscription_expiry_label_at(
    expires_at_epoch_seconds: u64,
    now_epoch_seconds: u64,
) -> String {
    if expires_at_epoch_seconds == 0 {
        return "长期有效".to_owned();
    }
    let remaining_days = expires_at_epoch_seconds.saturating_sub(now_epoch_seconds) / 86_400;
    format!("剩余 {remaining_days} 天")
}

fn format_subscription_bytes(value: i64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    let value = u64::try_from(value.max(0)).unwrap_or_default();
    if value < 1_024 {
        return format!("{value} B");
    }
    let mut divisor = 1_024_u64;
    let mut unit = 0;
    while value / divisor >= 1_024 && unit < UNITS.len() - 1 {
        divisor = divisor.saturating_mul(1_024);
        unit += 1;
    }
    let tenths = (u128::from(value) * 10 + u128::from(divisor / 2)) / u128::from(divisor);
    format!("{}.{:01} {}", tenths / 10, tenths % 10, UNITS[unit])
}

fn update_model_rows<T, F>(model: &ModelRc<T>, next: &[T], same_identity: F) -> bool
where
    T: Clone + PartialEq + 'static,
    F: Fn(&T, &T) -> bool,
{
    if model.row_count() != next.len() {
        return false;
    }
    let current = (0..next.len())
        .map(|index| model.row_data(index))
        .collect::<Option<Vec<_>>>();
    let Some(current) = current else {
        return false;
    };
    if current
        .iter()
        .zip(next)
        .any(|(left, right)| !same_identity(left, right))
    {
        return false;
    }
    for (index, (left, right)) in current.iter().zip(next).enumerate() {
        if left != right {
            model.set_row_data(index, right.clone());
        }
    }
    true
}

fn map_node(
    node: &ServerNode,
    selected_endpoint_id: &str,
    latency: &NodeLatencySnapshot,
) -> NodeItem {
    let measured_latency = latency.values_by_node_id.get(&node.endpoint_id);
    NodeItem {
        id: node.endpoint_id.clone().into(),
        name: node.name.clone().into(),
        country_code: node.country_code.trim().to_ascii_uppercase().into(),
        status_label: match node.status.as_str() {
            "online" => "在线",
            "waiting" => "等待上线",
            "offline" => "离线",
            _ => "未知",
        }
        .into(),
        tags_label: format_node_tags(&node.tags).into(),
        multiplier_label: format_multiplier(node.multiplier.unwrap_or(1.0)).into(),
        latency_label: measured_latency
            .and_then(|value| *value)
            .map_or_else(|| "—".to_owned(), |value| format!("{value}ms"))
            .into(),
        latency_available: measured_latency.is_some_and(Option::is_some),
        selected: node.endpoint_id == selected_endpoint_id,
        selectable: node.selectable,
        measuring: latency.measuring_node_ids.contains(&node.endpoint_id),
    }
}

fn empty_node() -> NodeItem {
    NodeItem {
        id: "".into(),
        name: "".into(),
        country_code: "".into(),
        status_label: "".into(),
        tags_label: "".into(),
        multiplier_label: "".into(),
        latency_label: "".into(),
        latency_available: false,
        selected: false,
        selectable: false,
        measuring: false,
    }
}

fn format_multiplier(value: f64) -> String {
    if !value.is_finite() {
        return "1.0x".to_owned();
    }
    if value.fract().abs() < f64::EPSILON {
        format!("{value:.1}x")
    } else {
        format!("{value}x")
    }
}

fn format_node_tags(tags: &[String]) -> String {
    let mut unique = Vec::new();
    for tag in tags
        .iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
    {
        if !unique.contains(&tag) {
            unique.push(tag);
        }
    }
    unique.join(" · ")
}

fn format_quota_bytes(value: i64) -> String {
    format_bytes(u64::try_from(value.max(0)).unwrap_or_default())
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut divisor = 1_u64;
    let mut unit = 0;
    while value / divisor >= 1_024 && unit < UNITS.len() - 1 {
        divisor *= 1_024;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} {}", UNITS[unit])
    } else {
        let whole = value / divisor;
        let decimal = (value % divisor) * 10 / divisor;
        format!("{whole}.{decimal} {}", UNITS[unit])
    }
}

pub fn bind_preference_callback<F>(
    controller: Arc<DesktopController>,
    weak: slint::Weak<AppWindow>,
    change: F,
) where
    F: FnOnce() -> crate::controller::PreferenceChange + Send + 'static,
{
    if let Some(ui) = weak.upgrade() {
        ui.set_settings_apply_pending(true);
    }
    tokio::spawn(async move {
        let error = controller.update_preference(change()).await.err();
        let settings = controller.settings().await;
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let preferences = &settings.preferences;
            ui.set_tun_mode(preferences.tun_enabled);
            ui.set_global_mode(preferences.route_mode == RouteMode::Global);
            ui.set_bypass_mainland(preferences.bypass_mainland);
            ui.set_bypass_lan(preferences.bypass_lan);
            ui.set_udp_forwarding(preferences.udp_forwarding_enabled);
            ui.set_multiplex(preferences.multiplex_enabled);
            ui.set_settings_apply_pending(false);
            if let Some(error) = error {
                ui.set_notice(error.into());
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use time::UtcOffset;
    use topnode_domain::{
        BalanceTransaction, BalanceTransactionType, Entitlement, ServerGroup, ShopPlan,
        ShopPlanPrice,
    };

    use super::{
        SubscriptionStatus, find_order_number, format_expiry_label_at_offset, format_multiplier,
        format_node_tags, format_signed_amount, format_subscription_bytes,
        format_subscription_expiry_label_at, format_transaction_time_at_offset,
        map_balance_transaction, map_resource_groups, map_shop_plan, map_subscription_item,
        map_subscription_items, resolve_selected_subscription_plan, subscription_usage_percentage,
        subscription_usage_progress,
    };

    #[test]
    fn shop_plan_keeps_the_catalog_order_for_the_default_checkout_option() {
        let plan = ShopPlan {
            id: 7,
            name: "VIP 黄金套餐".to_owned(),
            description: "高速线路".to_owned(),
            group_name: "Premium".to_owned(),
            addon_available: true,
            prices: vec![
                ShopPlanPrice {
                    id: 71,
                    label: "年付".to_owned(),
                    period_unit: "year".to_owned(),
                    period_count: 1,
                    price_cents: 21_000,
                    currency: "CNY".to_owned(),
                    included_traffic_bytes: 3_520_000_000_000,
                },
                ShopPlanPrice {
                    id: 72,
                    label: "月付".to_owned(),
                    period_unit: "month".to_owned(),
                    period_count: 1,
                    price_cents: 2_000,
                    currency: "CNY".to_owned(),
                    included_traffic_bytes: 300_000_000_000,
                },
            ],
            traffic_addons: Vec::new(),
        };

        let item = map_shop_plan(&plan);

        assert_eq!(item.default_price_id.as_str(), "71");
        assert_eq!(item.default_price_label.as_str(), "¥210.00");
        assert_eq!(item.default_price_cents, 21_000);
        assert!(item.default_price_requires_payment);
        assert_eq!(item.starting_price_label.as_str(), "¥20.00");
    }

    #[test]
    fn balance_transaction_matches_the_android_labels() {
        let transaction = BalanceTransaction {
            id: 12,
            transaction_type: BalanceTransactionType::OrderRefund,
            description: "退款返还余额 ORD202607200001".to_owned(),
            amount_cents: 1_990,
            balance_before_cents: 3_010,
            balance_after_cents: 5_000,
            reference_id: Some(8),
            created_at_epoch_seconds: 0,
        };

        let item = map_balance_transaction(&transaction);

        assert_eq!(item.title.as_str(), "退款返还余额");
        assert_eq!(item.amount_label.as_str(), "+19.90");
        assert_eq!(item.reference_label.as_str(), "ORD202607200001");
        assert!(item.credit);
        assert_eq!(format_signed_amount(-500), "-5.00");
        assert_eq!(format_signed_amount(500), "+5.00");
        assert_eq!(find_order_number("订单 ordA12 已退款"), Some("ordA12"));
        assert_eq!(
            format_transaction_time_at_offset(0, UtcOffset::UTC).as_deref(),
            Some("1970-01-01 00:00")
        );
    }

    #[test]
    fn package_card_uses_the_active_plan_instead_of_the_permission_group_name() {
        let group = ServerGroup {
            id: 7,
            name: "高级权限组".to_owned(),
            connectable: true,
            total_quota_bytes: 9_000,
            used_bytes: 1_000,
            remaining_bytes: 8_000,
            next_expires_at_epoch_seconds: Some(4_102_444_800),
            entitlements: vec![
                entitlement("traffic_addon", "流量补充包", Some(9), "active"),
                entitlement("plan", "畅享套餐", None, "active"),
            ],
            nodes: Vec::new(),
        };

        let items = map_resource_groups(&[group], "7", "1");
        let item = &items[0];

        assert_eq!(item.name.as_str(), "畅享套餐");
        assert!(item.selected);
        assert_eq!(item.quota_label.as_str(), "剩余 1.0 KB / 2.0 KB");
    }

    #[test]
    fn node_selector_keeps_same_plan_grants_as_separate_cards() {
        let mut earlier = entitlement("plan", "VIP 黄金套餐", None, "active");
        earlier.grant_id = 11;
        earlier.quota_bytes = 400;
        earlier.remaining_bytes = 350;
        earlier.expires_at_epoch_seconds = 1_787_443_200;
        let mut later = earlier.clone();
        later.grant_id = 12;
        later.remaining_bytes = 400;
        later.expires_at_epoch_seconds = 1_787_702_400;
        let group = ServerGroup {
            id: 7,
            name: "高级权限组".to_owned(),
            connectable: true,
            total_quota_bytes: 800,
            used_bytes: 50,
            remaining_bytes: 750,
            next_expires_at_epoch_seconds: Some(1_787_443_200),
            entitlements: vec![earlier, later],
            nodes: Vec::new(),
        };

        let items = map_resource_groups(&[group], "7", "12");

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id.as_str(), "7:11");
        assert_eq!(items[1].id.as_str(), "7:12");
        assert_eq!(items[0].name.as_str(), "VIP 黄金套餐");
        assert_eq!(items[1].name.as_str(), "VIP 黄金套餐");
        assert_eq!(items[0].quota_label.as_str(), "剩余 350 B / 400 B");
        assert_eq!(items[1].quota_label.as_str(), "剩余 400 B / 400 B");
        assert!(!items[0].selected);
        assert!(items[1].selected);
    }

    #[test]
    fn android_node_text_formatting_is_preserved() {
        assert_eq!(format_multiplier(1.0), "1.0x");
        assert_eq!(format_multiplier(0.5), "0.5x");
        assert_eq!(
            format_node_tags(&[
                " 视频 ".to_owned(),
                String::new(),
                "低延迟".to_owned(),
                "视频".to_owned(),
            ]),
            "视频 · 低延迟"
        );
    }

    #[test]
    fn package_expiry_uses_the_android_date_shape() {
        assert_eq!(
            format_expiry_label_at_offset(1_787_443_200, UtcOffset::UTC).as_deref(),
            Some("到期 2026-08-23")
        );
    }

    #[test]
    fn subscriptions_are_deduplicated_classified_and_sorted_like_android() {
        let mut later_active_plan = subscription_entitlement(10, "plan", "active", 10, None, 500);
        later_active_plan.plan_name = "首次出现的套餐".to_owned();
        let mut earlier_active_plan = subscription_entitlement(2, "plan", "active", 200, None, 400);
        earlier_active_plan.plan_name = "更早到期的套餐".to_owned();
        let long_term_active_plan = subscription_entitlement(3, "plan", "active", 3, None, 0);
        let expired_plan = subscription_entitlement(20, "plan", "expired", 20, None, 300);
        let addon_from_source =
            subscription_entitlement(30, "TRAFFIC_ADDON", "active", 10, None, 450);
        let addon_from_id = subscription_entitlement(31, "plan", "active", 200, Some(7), 350);
        let mut duplicate = later_active_plan.clone();
        duplicate.plan_name = "重复权益不应覆盖首次出现".to_owned();
        let groups = vec![
            subscription_group(vec![expired_plan, later_active_plan, addon_from_source]),
            subscription_group(vec![
                duplicate,
                earlier_active_plan,
                long_term_active_plan,
                addon_from_id,
            ]),
        ];

        let (plans, addons) = map_subscription_items(&groups);

        assert_eq!(
            plans
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            ["2", "10", "3", "20"]
        );
        assert_eq!(plans[1].title.as_str(), "首次出现的套餐");
        assert_eq!(
            addons
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            ["31", "30"]
        );
        assert_eq!(addons[0].plan_id.as_str(), "200");
        assert_eq!(addons[1].plan_id.as_str(), "10");
        assert_eq!(plans[0].related_addon_count, 1);
        assert_eq!(plans[1].related_addon_count, 1);
        assert_eq!(plans[2].related_addon_count, 0);
        let selected = resolve_selected_subscription_plan(&plans, "2").expect("grant is selected");
        assert_eq!(selected.id.as_str(), "2");
        assert_eq!(selected.plan_id.as_str(), "200");
        assert_eq!(selected.related_addon_count, 1);
        let selected_without_addons =
            resolve_selected_subscription_plan(&plans, "3").expect("long-term plan is selected");
        assert_eq!(
            selected_without_addons.related_addon_count, 0,
            "其他套餐有流量包时，当前无流量包套餐仍应显示空状态"
        );
        assert_eq!(
            resolve_selected_subscription_plan(&plans, "missing")
                .expect("失效选择回退到首个套餐")
                .id
                .as_str(),
            "2"
        );
        assert!(addons.iter().all(|item| item.related_addon_count == 0));
    }

    #[test]
    fn subscription_item_preserves_android_card_content() {
        let mut entitlement = subscription_entitlement(7, "plan", "exhausted", 9, None, 0);
        entitlement.plan_name = " VIP 黄金套餐 ".to_owned();
        entitlement.price_label = "月付".to_owned();
        entitlement.quota_bytes = 2_048;
        entitlement.used_bytes = 512;

        let item = map_subscription_item(&entitlement, false, 3);

        assert_eq!(item.title.as_str(), "VIP 黄金套餐");
        assert_eq!(item.badge_label.as_str(), "月付");
        assert_eq!(item.status, SubscriptionStatus::Exhausted);
        assert_eq!(item.status_label.as_str(), "已耗尽");
        assert_eq!(item.remaining_value.as_str(), "1.5 KB");
        assert_eq!(item.total_value.as_str(), "2.0 KB");
        assert_eq!(item.usage_label.as_str(), "已使用 25%");
        assert!((item.usage_progress - 0.25).abs() < f32::EPSILON);
        assert_eq!(item.expiry_label.as_str(), "长期有效");
        assert_eq!(item.related_addon_count, 3);
    }

    #[test]
    fn subscription_formatters_clamp_server_values_and_expiry() {
        assert_eq!(format_subscription_bytes(-1), "0 B");
        assert_eq!(format_subscription_bytes(1_536), "1.5 KB");
        assert!(subscription_usage_progress(-10, 100).abs() < f32::EPSILON);
        assert!((subscription_usage_progress(150, 100) - 1.0).abs() < f32::EPSILON);
        assert!(subscription_usage_progress(10, 0).abs() < f32::EPSILON);
        assert_eq!(subscription_usage_percentage(1, 3), 33);
        assert_eq!(subscription_usage_percentage(150, 100), 100);
        assert_eq!(subscription_usage_percentage(-10, 100), 0);
        assert_eq!(format_subscription_expiry_label_at(0, 100), "长期有效");
        assert_eq!(
            format_subscription_expiry_label_at(172_900, 100),
            "剩余 2 天"
        );
        assert_eq!(format_subscription_expiry_label_at(99, 100), "剩余 0 天");
    }

    fn entitlement(
        source: &str,
        plan_name: &str,
        traffic_addon_id: Option<u64>,
        status: &str,
    ) -> Entitlement {
        Entitlement {
            grant_id: 1,
            source: source.to_owned(),
            status: status.to_owned(),
            plan_id: 2,
            plan_price_id: Some(3),
            traffic_addon_id,
            plan_name: plan_name.to_owned(),
            price_label: String::new(),
            addon_name: String::new(),
            quota_bytes: 2_048,
            used_bytes: 1_024,
            remaining_bytes: 1_024,
            starts_at_epoch_seconds: 1,
            expires_at_epoch_seconds: 4_102_444_800,
        }
    }

    fn subscription_group(entitlements: Vec<Entitlement>) -> ServerGroup {
        ServerGroup {
            id: 1,
            name: "权限组".to_owned(),
            connectable: true,
            total_quota_bytes: 0,
            used_bytes: 0,
            remaining_bytes: 0,
            next_expires_at_epoch_seconds: None,
            entitlements,
            nodes: Vec::new(),
        }
    }

    fn subscription_entitlement(
        grant_id: u64,
        source: &str,
        status: &str,
        plan_id: u64,
        traffic_addon_id: Option<u64>,
        expires_at_epoch_seconds: u64,
    ) -> Entitlement {
        Entitlement {
            grant_id,
            source: source.to_owned(),
            status: status.to_owned(),
            plan_id,
            plan_price_id: Some(3),
            traffic_addon_id,
            plan_name: format!("套餐 {grant_id}"),
            price_label: String::new(),
            addon_name: format!("流量包 {grant_id}"),
            quota_bytes: 1_024,
            used_bytes: 0,
            remaining_bytes: 1_024,
            starts_at_epoch_seconds: 1,
            expires_at_epoch_seconds,
        }
    }
}
