//! Enterprise integration: SSO token exchange, fleet policy sync and audit
//! forwarding. All endpoints are configured through `ZENTRION_ENTERPRISE_URL`;
//! there is no built-in mock server and no fabricated success path.

pub mod client;
pub mod sso;
pub mod sync;
pub mod telemetry;
