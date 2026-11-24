pub const HOST: &str = "host";
pub const MAIN: &str = "main";

/// The real home and the desktop have one persistent clipboard identity.
/// Network-qualified names are accepted only as legacy real-home aliases.
pub fn canonical_history(name: &str) -> &str {
    let legacy_main = name.strip_prefix("main:").is_some_and(|network| {
        !network.is_empty()
            && network.len() <= 128
            && !network.starts_with(['.', '-'])
            && network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    });
    if name == HOST || name == MAIN || legacy_main {
        HOST
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_real_home_and_its_legacy_network_aliases_share_a_history() {
        for name in ["host", "main", "main:DE", "main:NL", "main:host"] {
            assert_eq!(canonical_history(name), HOST);
        }
        for name in [
            "work",
            "main-work",
            "work:DE",
            "main:",
            "main:-",
            "main:../DE",
            "main:DE/NL",
        ] {
            assert_eq!(canonical_history(name), name);
        }
    }
}
