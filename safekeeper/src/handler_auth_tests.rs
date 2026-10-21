//! `SafekeeperPostgresHandler::check_permission` is total (K7 fix round): with auth on and
//! no claims (the connection never authenticated), it answers `Unauthorized` instead of
//! panicking on `expect("claims presence already checked")`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use postgres_backend::QueryError;
use utils::auth::{JwtAuth, Scope};
use utils::id::TenantId;

use super::SafekeeperPostgresHandler;
use crate::wal_backup::WalBackup;
use crate::{GlobalTimelines, SafeKeeperConf};

#[tokio::test]
async fn permission_without_claims_is_unauthorized_not_a_panic() {
    let conf = Arc::new(SafeKeeperConf::dummy());
    let wal_backup = Arc::new(WalBackup::new(&conf).await.unwrap());
    let global_timelines = Arc::new(GlobalTimelines::new(conf.clone(), wal_backup));
    let auth = Some((Scope::SafekeeperData, Arc::new(JwtAuth::new(vec![]))));
    let handler = SafekeeperPostgresHandler::new(conf, 0, None, auth, global_timelines);

    for tenant_id in [Some(TenantId::generate()), None] {
        match catch_unwind(AssertUnwindSafe(|| handler.check_permission(tenant_id))) {
            Ok(Err(QueryError::Unauthorized(_))) => {}
            Ok(Err(other)) => panic!("tenant {tenant_id:?}: want Unauthorized, got {other:?}"),
            Ok(Ok(())) => panic!("tenant {tenant_id:?}: no claims, yet permitted"),
            Err(panic) => panic!(
                "tenant {tenant_id:?}: check_permission panicked: {:?}",
                panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
            ),
        }
    }
}
