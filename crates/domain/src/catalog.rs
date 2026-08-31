#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointType {
    Node,
    LoadBalancePool,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerNode {
    pub endpoint_id: String,
    pub endpoint_type: EndpointType,
    pub name: String,
    pub country_code: String,
    pub tags: Vec<String>,
    pub latency_target: String,
    pub status: String,
    pub multiplier: Option<f64>,
    pub selectable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entitlement {
    pub grant_id: u64,
    pub source: String,
    pub status: String,
    pub plan_id: u64,
    pub plan_price_id: Option<u64>,
    pub traffic_addon_id: Option<u64>,
    pub plan_name: String,
    pub price_label: String,
    pub addon_name: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub remaining_bytes: i64,
    pub starts_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerGroup {
    pub id: u64,
    pub name: String,
    pub connectable: bool,
    pub total_quota_bytes: i64,
    pub used_bytes: i64,
    pub remaining_bytes: i64,
    pub next_expires_at_epoch_seconds: Option<u64>,
    pub entitlements: Vec<Entitlement>,
    pub nodes: Vec<ServerNode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopPlan {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub group_name: String,
    pub addon_available: bool,
    pub prices: Vec<ShopPlanPrice>,
    pub traffic_addons: Vec<ShopTrafficAddon>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopPlanPrice {
    pub id: u64,
    pub label: String,
    pub period_unit: String,
    pub period_count: u32,
    pub price_cents: i64,
    pub currency: String,
    pub included_traffic_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopTrafficAddon {
    pub id: u64,
    pub name: String,
    pub traffic_bytes: i64,
    pub price_cents: i64,
    pub currency: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopPaymentMethod {
    pub id: u64,
    pub name: String,
    pub icon_url: Option<String>,
    pub provider: String,
    pub provider_name: String,
    pub payment_type: String,
    pub payment_type_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShopCatalog {
    pub plans: Vec<ShopPlan>,
    pub payment_methods: Vec<ShopPaymentMethod>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShopPurchaseKind {
    BasePlan,
    TrafficAddon,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopOrderSelection {
    pub kind: ShopPurchaseKind,
    pub plan_id: u64,
    pub product_id: u64,
    pub coupon_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShopCouponDiscountType {
    Amount,
    Percent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopCouponQuote {
    pub code: String,
    pub name: String,
    pub discount_type: ShopCouponDiscountType,
    pub discount_summary: String,
    pub original_amount_cents: i64,
    pub discount_amount_cents: i64,
    pub payable_amount_cents: i64,
    pub currency: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShopPaymentChoice {
    Balance,
    Provider(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShopOrderStatus {
    Pending,
    PaidPendingFulfillment,
    Paid,
    Refunded,
}

impl ShopOrderStatus {
    pub const fn payment_received(self) -> bool {
        matches!(self, Self::PaidPendingFulfillment | Self::Paid)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Paid | Self::Refunded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShopPaymentStatus {
    Pending,
    Paid,
    Failed,
    Closed,
    Refunded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopPaymentSession {
    pub required: bool,
    pub status: ShopPaymentStatus,
    pub payment_method_id: Option<u64>,
    pub provider: String,
    pub payment_type: String,
    pub amount_cents: i64,
    pub fee_amount_cents: i64,
    pub net_amount_cents: i64,
    pub currency: String,
    pub pay_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShopOrder {
    pub id: u64,
    pub order_number: String,
    pub amount_cents: i64,
    pub currency: String,
    pub status: ShopOrderStatus,
    pub can_pay: bool,
    pub payment: Option<ShopPaymentSession>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UserOrderFilter {
    #[default]
    All,
    Pending,
    Paid,
    Refunded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserOrderStatus {
    Pending,
    Paid,
    Refunded,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserOrderType {
    BasePlan,
    TrafficAddon,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserOrderSource {
    User,
    Admin,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserOrderItem {
    pub id: u64,
    pub order_type: UserOrderType,
    pub plan_id: Option<u64>,
    pub plan_name: String,
    pub plan_price_id: Option<u64>,
    pub price_label: String,
    pub period_unit: String,
    pub period_count: u32,
    pub traffic_addon_id: Option<u64>,
    pub traffic_addon_name: String,
    pub traffic_quota_bytes: i64,
    pub description: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserOrderPaymentMethod {
    pub id: u64,
    pub name: String,
    pub provider: String,
    pub provider_name: String,
    pub payment_type: String,
    pub payment_type_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserOrder {
    pub id: u64,
    pub order_number: String,
    pub order_type: UserOrderType,
    pub source: UserOrderSource,
    pub item: UserOrderItem,
    pub amount_cents: i64,
    pub currency: String,
    pub status: UserOrderStatus,
    pub can_pay: bool,
    pub payment_method: Option<UserOrderPaymentMethod>,
    pub paid_at_epoch_seconds: Option<i64>,
    pub refunded_at_epoch_seconds: Option<i64>,
    pub balance_refunded_cents: i64,
    pub entitlements_rolled_back_at_epoch_seconds: Option<i64>,
    pub created_at_epoch_seconds: i64,
    pub updated_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserOrderPage {
    pub orders: Vec<UserOrder>,
    pub page: u32,
    pub page_size: u8,
    pub total: u64,
}

impl UserOrderPage {
    pub fn has_more(&self) -> bool {
        u64::from(self.page).saturating_mul(u64::from(self.page_size)) < self.total
    }
}

impl ShopOrder {
    /// Applies a polled order update without discarding the payment session
    /// returned by order creation/payment. The Panel order-detail endpoint
    /// intentionally omits that session and its payment URL.
    #[must_use]
    pub fn merge_status_update(self, mut update: Self) -> Self {
        if self.id == update.id && update.payment.is_none() {
            update.payment = self.payment;
        }
        update
    }
}

#[cfg(test)]
mod tests {
    use super::{ShopOrder, ShopOrderStatus, ShopPaymentSession, ShopPaymentStatus};

    #[test]
    fn polled_order_update_preserves_the_checkout_payment_session() {
        let current = ShopOrder {
            id: 7,
            order_number: "ORD7".to_owned(),
            amount_cents: 2_000,
            currency: "CNY".to_owned(),
            status: ShopOrderStatus::Pending,
            can_pay: false,
            payment: Some(ShopPaymentSession {
                required: true,
                status: ShopPaymentStatus::Pending,
                payment_method_id: Some(3),
                provider: "epay".to_owned(),
                payment_type: "alipay".to_owned(),
                amount_cents: 2_000,
                fee_amount_cents: 0,
                net_amount_cents: 2_000,
                currency: "CNY".to_owned(),
                pay_url: Some("https://pay.example.test/7".to_owned()),
            }),
        };
        let update = ShopOrder {
            status: ShopOrderStatus::Paid,
            payment: None,
            ..current.clone()
        };

        let merged = current.merge_status_update(update);

        assert_eq!(merged.status, ShopOrderStatus::Paid);
        assert_eq!(
            merged.payment.and_then(|payment| payment.pay_url),
            Some("https://pay.example.test/7".to_owned())
        );
    }

    #[test]
    fn order_status_distinguishes_payment_from_fulfillment_completion() {
        assert!(ShopOrderStatus::PaidPendingFulfillment.payment_received());
        assert!(!ShopOrderStatus::PaidPendingFulfillment.is_terminal());
        assert!(ShopOrderStatus::Paid.is_terminal());
        assert!(ShopOrderStatus::Refunded.is_terminal());
    }

    #[test]
    fn order_update_never_carries_a_payment_url_across_orders() {
        let current = ShopOrder {
            id: 7,
            order_number: "ORD7".to_owned(),
            amount_cents: 2_000,
            currency: "CNY".to_owned(),
            status: ShopOrderStatus::Pending,
            can_pay: false,
            payment: Some(ShopPaymentSession {
                required: true,
                status: ShopPaymentStatus::Pending,
                payment_method_id: Some(3),
                provider: "epay".to_owned(),
                payment_type: "alipay".to_owned(),
                amount_cents: 2_000,
                fee_amount_cents: 0,
                net_amount_cents: 2_000,
                currency: "CNY".to_owned(),
                pay_url: Some("https://pay.example.test/7".to_owned()),
            }),
        };
        let other = ShopOrder {
            id: 8,
            order_number: "ORD8".to_owned(),
            amount_cents: 1_000,
            currency: "CNY".to_owned(),
            status: ShopOrderStatus::Paid,
            can_pay: false,
            payment: None,
        };

        assert!(current.merge_status_update(other).payment.is_none());
    }
}
