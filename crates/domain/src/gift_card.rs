//! Gift-card contracts shared by the application and Panel adapter.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GiftCardRewardType {
    Balance,
    Plan,
    Traffic,
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GiftCardConfig {
    pub purchase_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GiftCardRewardPreview {
    pub reward_type: GiftCardRewardType,
    pub summary: String,
    pub balance_amount_cents: i64,
    pub plan_id: Option<u64>,
    pub plan_name: String,
    pub plan_price_id: Option<u64>,
    pub price_label: String,
    pub group_id: Option<u64>,
    pub group_name: String,
    pub traffic_quota_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GiftCardRedeemCheck {
    pub reward: GiftCardRewardPreview,
    pub can_redeem: bool,
    pub reason: String,
}
