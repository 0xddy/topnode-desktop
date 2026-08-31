use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    #[default]
    Rule,
    Global,
}

/// User connection preferences applied at the runtime boundary.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct ConnectionPreferences {
    pub route_mode: RouteMode,
    pub bypass_mainland: bool,
    pub bypass_lan: bool,
    pub tun_enabled: bool,
    pub udp_forwarding_enabled: bool,
    pub multiplex_enabled: bool,
}

impl Default for ConnectionPreferences {
    fn default() -> Self {
        Self {
            route_mode: RouteMode::Rule,
            bypass_mainland: true,
            bypass_lan: true,
            tun_enabled: false,
            udp_forwarding_enabled: true,
            multiplex_enabled: false,
        }
    }
}

impl ConnectionPreferences {
    #[must_use]
    pub fn with_route_mode(mut self, route_mode: RouteMode) -> Self {
        self.route_mode = route_mode;
        if route_mode == RouteMode::Global {
            self.bypass_mainland = false;
        }
        self
    }

    #[must_use]
    pub fn normalized(mut self) -> Self {
        if self.route_mode == RouteMode::Global {
            self.bypass_mainland = false;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionPreferences, RouteMode};

    #[test]
    fn global_mode_disables_mainland_bypass_without_changing_lan_choice() {
        let preferences = ConnectionPreferences {
            bypass_lan: false,
            ..ConnectionPreferences::default()
        };
        let preferences = preferences.with_route_mode(RouteMode::Global);

        assert!(!preferences.bypass_mainland);
        assert!(!preferences.bypass_lan);
    }

    #[test]
    fn normalization_preserves_rule_mode_defaults() {
        assert_eq!(
            ConnectionPreferences::default().normalized(),
            ConnectionPreferences::default()
        );
    }

    #[test]
    fn tun_is_disabled_by_default() {
        assert!(!ConnectionPreferences::default().tun_enabled);
    }
}
