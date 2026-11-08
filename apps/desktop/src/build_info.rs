pub const VERSION_NAME: &str = env!("TOPNODE_VERSION_NAME");
pub const GIT_COMMIT: &str = env!("TOPNODE_GIT_COMMIT");
pub const BUILD_TARGET: &str = env!("TOPNODE_BUILD_TARGET");

pub fn version_code() -> u64 {
    env!("TOPNODE_VERSION_CODE")
        .parse()
        .expect("build.rs always emits a validated TOPNODE_VERSION_CODE")
}

#[cfg(test)]
mod tests {
    use super::{BUILD_TARGET, GIT_COMMIT, VERSION_NAME, version_code};

    #[test]
    fn embedded_build_identity_is_valid() {
        assert!(version_code() > 0);
        assert!(!VERSION_NAME.is_empty());
        assert!(!BUILD_TARGET.is_empty());
        assert!(
            GIT_COMMIT == "unknown"
                || ((40..=64).contains(&GIT_COMMIT.len())
                    && GIT_COMMIT.bytes().all(|byte| byte.is_ascii_hexdigit()))
        );
    }
}
