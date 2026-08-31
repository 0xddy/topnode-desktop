#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceTransactionType {
    OrderPayment,
    OrderRefund,
    GiftCard,
    AffiliateTransfer,
    AdminAdjustment,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceTransaction {
    pub id: u64,
    pub transaction_type: BalanceTransactionType,
    pub description: String,
    pub amount_cents: i64,
    pub balance_before_cents: i64,
    pub balance_after_cents: i64,
    pub reference_id: Option<u64>,
    pub created_at_epoch_seconds: i64,
}
