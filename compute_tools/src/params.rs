pub const DEFAULT_LOG_LEVEL: &str = "info";
// From Postgres docs:
//   To ease transition from the md5 method to the newer SCRAM method, if md5 is specified
//   as a method in pg_hba.conf but the user's password on the server is encrypted for SCRAM
//   (see below), then SCRAM-based authentication will automatically be chosen instead.
//   https://www.postgresql.org/docs/15/auth-password.html
//
// So it's safe to set md5 here, as `control-plane` anyway uses SCRAM for all roles.
//
// `hostssl`: a password login from anywhere but loopback (the basebackup's
// `trust` lines, which come first) is accepted only over TLS (chelabase#248).
pub const PG_HBA_ALL_MD5: &str = "hostssl\tall\t\tall\t\tall\t\tmd5";
/// The catch-all written before chelabase#248, which also accepted plaintext:
/// replaced by [`PG_HBA_ALL_MD5`] where it stands.
pub const PG_HBA_ALL_MD5_PLAIN: &str = "host\tall\t\tall\t\tall\t\tmd5";
