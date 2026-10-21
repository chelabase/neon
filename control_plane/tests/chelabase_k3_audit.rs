//! Fork round 4, K3 (plan pre-flight 7): neon_local's endpoint code.
//!
//! - No `NEON_AUTH_TOKEN` for `pg_ctl`: the compute's storage token reaches
//!   Postgres only through compute_ctl's token file (one source).
//! - Its `:3081` call (`refresh_configuration`) sends the endpoint's internal
//!   secret as a bearer, read from `<endpoint dir>/compute_ctl_internal.token`.

const ENDPOINT_RS: &str = include_str!("../src/endpoint.rs");

/// The text of `fn <name>` in endpoint.rs, up to the next method.
fn endpoint_fn(name: &str) -> &'static str {
    let start = ENDPOINT_RS
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("fn {name} in endpoint.rs"));
    let rest = &ENDPOINT_RS[start + 3..];
    let end = [
        "\n    pub fn ",
        "\n    fn ",
        "\n    pub async fn ",
        "\n    async fn ",
    ]
    .iter()
    .filter_map(|marker| rest.find(marker))
    .min()
    .unwrap_or(rest.len());
    &ENDPOINT_RS[start..start + 3 + end]
}

#[test]
fn neon_local_hands_no_token_to_pg_ctl() {
    let hits: Vec<&str> = ENDPOINT_RS
        .lines()
        .filter(|l| l.contains("NEON_AUTH_TOKEN"))
        .map(str::trim)
        .collect();
    assert!(
        hits.is_empty(),
        "endpoint.rs still sets NEON_AUTH_TOKEN: {hits:?}"
    );
}

#[test]
fn refresh_configuration_sends_the_internal_secret() {
    let body = endpoint_fn("refresh_configuration");
    assert!(
        body.contains("bearer_auth(")
            || body.contains("AUTHORIZATION")
            || body.contains("\"Authorization\""),
        "refresh_configuration sends no bearer:\n{body}"
    );
    assert!(
        ENDPOINT_RS.contains("compute_ctl_internal.token")
            || ENDPOINT_RS.contains("INTERNAL_API_TOKEN_FILE"),
        "endpoint.rs doesn't read the endpoint's internal token file"
    );
}
