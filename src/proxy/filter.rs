/// Check if a hostname matches a domain pattern.
///
/// Supports wildcard patterns like `*.example.com` which matches
/// any subdomain but not the base domain itself.
pub fn matches_domain_pattern(hostname: &str, pattern: &str) -> bool {
    if let Some(base_domain) = pattern.strip_prefix("*.") {
        hostname
            .to_lowercase()
            .ends_with(&format!(".{}", base_domain.to_lowercase()))
    } else {
        hostname.to_lowercase() == pattern.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_domain_pattern("example.com", "example.com"));
        assert!(matches_domain_pattern("EXAMPLE.COM", "example.com"));
        assert!(!matches_domain_pattern("other.com", "example.com"));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(matches_domain_pattern("sub.example.com", "*.example.com"));
        assert!(matches_domain_pattern("deep.sub.example.com", "*.example.com"));
        assert!(!matches_domain_pattern("example.com", "*.example.com"));
        assert!(!matches_domain_pattern("notexample.com", "*.example.com"));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(matches_domain_pattern("Sub.Example.COM", "*.example.com"));
        assert!(matches_domain_pattern("LOCALHOST", "localhost"));
    }

    #[test]
    fn test_empty_hostname_returns_false() {
        assert!(!matches_domain_pattern("", "example.com"));
    }

    #[test]
    fn test_empty_pattern_returns_false() {
        assert!(!matches_domain_pattern("example.com", ""));
    }

    #[test]
    fn test_wildcard_does_not_match_base_domain() {
        // Security property: *.example.com should NOT match example.com
        assert!(!matches_domain_pattern("example.com", "*.example.com"));
    }

    #[test]
    fn test_deep_subdomain_matches_wildcard() {
        assert!(matches_domain_pattern(
            "a.b.c.d.example.com",
            "*.example.com"
        ));
    }

    #[test]
    fn test_localhost_exact_match() {
        assert!(matches_domain_pattern("localhost", "localhost"));
        assert!(!matches_domain_pattern("notlocalhost", "localhost"));
    }

    #[test]
    fn test_trailing_dot_behavior() {
        // Trailing dot in hostname should not match bare pattern
        assert!(!matches_domain_pattern("example.com.", "example.com"));
    }
}
