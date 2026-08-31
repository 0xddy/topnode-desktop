#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SupportTicketPriority {
    Low,
    #[default]
    Medium,
    High,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SupportTicketStatus {
    #[default]
    PendingReply,
    Replied,
    Closed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SupportTicketSenderRole {
    #[default]
    User,
    Admin,
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupportTicket {
    pub id: u64,
    pub ticket_number: String,
    pub title: String,
    pub priority: SupportTicketPriority,
    pub status: SupportTicketStatus,
    pub has_unread_reply: bool,
    pub last_admin_reply_at_epoch_seconds: Option<i64>,
    pub closed_at_epoch_seconds: Option<i64>,
    pub created_at_epoch_seconds: i64,
    pub updated_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupportTicketMessage {
    pub id: u64,
    pub sender_role: SupportTicketSenderRole,
    pub sender_name: String,
    pub sender_email: String,
    pub content: String,
    pub created_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupportTicketPage {
    pub tickets: Vec<SupportTicket>,
    pub page: u32,
    pub page_size: u8,
    pub total: u64,
}

impl SupportTicketPage {
    #[must_use]
    pub fn has_more(&self) -> bool {
        u64::from(self.page).saturating_mul(u64::from(self.page_size)) < self.total
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupportTicketDetail {
    pub ticket: SupportTicket,
    /// Ordered from oldest to newest for direct timeline rendering.
    pub messages: Vec<SupportTicketMessage>,
    pub message_page: u32,
    pub message_page_size: u8,
    pub message_total: u64,
}

impl SupportTicketDetail {
    #[must_use]
    pub fn has_earlier_messages(&self) -> bool {
        u64::from(self.message_page).saturating_mul(u64::from(self.message_page_size))
            < self.message_total
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportTicketDraft {
    pub title: String,
    pub priority: SupportTicketPriority,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SupportTicketAction {
    pub id: u64,
    pub ticket_number: String,
    pub status: SupportTicketStatus,
}

#[cfg(test)]
mod tests {
    use super::{SupportTicketDetail, SupportTicketPage};

    #[test]
    fn pagination_distinguishes_complete_and_partial_timelines() {
        assert!(
            SupportTicketPage {
                page: 1,
                page_size: 20,
                total: 21,
                ..SupportTicketPage::default()
            }
            .has_more()
        );
        assert!(
            !SupportTicketDetail {
                message_page: 2,
                message_page_size: 10,
                message_total: 20,
                ..SupportTicketDetail::default()
            }
            .has_earlier_messages()
        );
    }
}
