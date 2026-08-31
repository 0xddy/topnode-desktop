use std::fmt;

/// A credential-bearing subscription URL returned by the Panel.
///
/// Debug output is deliberately redacted because the query string grants
/// access to the account's subscription configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct SubscriptionLink(String);

impl SubscriptionLink {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() || value.chars().any(char::is_control) {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SubscriptionLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubscriptionLink([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::SubscriptionLink;

    #[test]
    fn trims_valid_links_and_redacts_debug_output() {
        let link = SubscriptionLink::new("  https://panel.example/sub?uuid=secret  ")
            .expect("valid subscription link");

        assert_eq!(link.expose(), "https://panel.example/sub?uuid=secret");
        assert_eq!(format!("{link:?}"), "SubscriptionLink([REDACTED])");
    }

    #[test]
    fn rejects_empty_or_control_character_values() {
        assert!(SubscriptionLink::new("   ").is_none());
        assert!(SubscriptionLink::new("https://panel.example/\nsecret").is_none());
    }
}
