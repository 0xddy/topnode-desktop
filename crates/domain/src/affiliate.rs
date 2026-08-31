#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AffiliateRebateType {
    First,
    Recurring,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AffiliateSummary {
    pub enabled: bool,
    pub rebate_type: AffiliateRebateType,
    pub effective_rate_bps: i32,
    pub total_commission_cents: i64,
    pub available_commission_cents: i64,
    pub cooling_commission_cents: i64,
    pub transferred_commission_cents: i64,
    pub invitation_count: u64,
    pub affiliate_code: String,
    pub invitation_url: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AffiliateCommissionStatus {
    Cooling,
    Unlocked,
    Reversed,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffiliateCommission {
    pub id: u64,
    pub invitee: String,
    pub order_number: String,
    pub rebate_type: AffiliateRebateType,
    pub rate_bps: i32,
    pub base_amount_cents: i64,
    pub commission_cents: i64,
    pub status: AffiliateCommissionStatus,
    pub available_at_epoch_seconds: Option<i64>,
    pub released_at_epoch_seconds: Option<i64>,
    pub reversed_at_epoch_seconds: Option<i64>,
    pub reversed_deducted_cents: i64,
    pub created_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AffiliateCommissionPage {
    pub commissions: Vec<AffiliateCommission>,
    pub page: u32,
    pub page_size: u8,
    pub total: u64,
}

impl AffiliateCommissionPage {
    pub fn has_more(&self) -> bool {
        u64::from(self.page).saturating_mul(u64::from(self.page_size)) < self.total
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AffiliateTransfer {
    pub id: u64,
    pub request_id: String,
    pub amount_cents: i64,
    pub balance_after_cents: i64,
    pub created_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AffiliateTransferPage {
    pub transfers: Vec<AffiliateTransfer>,
    pub page: u32,
    pub page_size: u8,
    pub total: u64,
}

impl AffiliateTransferPage {
    pub fn has_more(&self) -> bool {
        u64::from(self.page).saturating_mul(u64::from(self.page_size)) < self.total
    }
}
