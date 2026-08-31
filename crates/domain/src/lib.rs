//! Pure connection and runtime contracts shared by the desktop adapters.

mod affiliate;
mod balance;
mod catalog;
mod connection;
mod gift_card;
mod preferences;
mod runtime;
mod session;
mod subscription_link;
mod support_ticket;
mod telemetry;

pub use affiliate::{
    AffiliateCommission, AffiliateCommissionPage, AffiliateCommissionStatus, AffiliateRebateType,
    AffiliateSummary, AffiliateTransfer, AffiliateTransferPage,
};
pub use balance::{BalanceTransaction, BalanceTransactionType};
pub use catalog::{
    EndpointType, Entitlement, ServerGroup, ServerNode, ShopCatalog, ShopCouponDiscountType,
    ShopCouponQuote, ShopOrder, ShopOrderSelection, ShopOrderStatus, ShopPaymentChoice,
    ShopPaymentMethod, ShopPaymentSession, ShopPaymentStatus, ShopPlan, ShopPlanPrice,
    ShopPurchaseKind, ShopTrafficAddon, UserOrder, UserOrderFilter, UserOrderItem, UserOrderPage,
    UserOrderPaymentMethod, UserOrderSource, UserOrderStatus, UserOrderType,
};
pub use connection::{ConnectionState, StopReason};
pub use gift_card::{
    GiftCardConfig, GiftCardRedeemCheck, GiftCardRewardPreview, GiftCardRewardType,
};
pub use preferences::{ConnectionPreferences, RouteMode};
pub use runtime::{
    ClientConfiguration, ConfigurationValidation, ConnectionCancellation, ConnectionEngine,
    EngineCapabilities, EngineError, RuntimeConfiguration, RuntimeDescriptor, RuntimeId,
};
pub use session::{SessionTokens, SessionValidationError, UserIdentity, UserSession};
pub use subscription_link::SubscriptionLink;
pub use support_ticket::{
    SupportTicket, SupportTicketAction, SupportTicketDetail, SupportTicketDraft,
    SupportTicketMessage, SupportTicketPage, SupportTicketPriority, SupportTicketSenderRole,
    SupportTicketStatus,
};
pub use telemetry::RuntimeTelemetrySnapshot;
