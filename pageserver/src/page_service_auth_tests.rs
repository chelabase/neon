//! `PageServerHandler::check_permission` is total (K7 fix round): with auth on and no
//! claims (the connection never authenticated), it answers `Unauthorized` instead of
//! panicking on `expect("claims presence already checked")`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use camino::Utf8PathBuf;
use postgres_backend::QueryError;
use storage_broker::BrokerClientChannel;
use tokio_util::sync::CancellationToken;
use utils::auth::{JwtAuth, SwappableJwtAuth};
use utils::id::TenantId;
use utils::sync::gate::Gate;

use super::{ConnectionPerfSpanFields, PageServerHandler};
use crate::basebackup_cache::BasebackupCache;
use crate::context::{DownloadBehavior, RequestContext};
use crate::feature_resolver::FeatureResolver;
use crate::l0_flush::L0FlushGlobalState;
use crate::task_mgr::TaskKind;
use crate::tenant::TenantSharedResources;
use crate::tenant::harness::TenantHarness;
use crate::tenant::mgr::{self, BackgroundPurges};

#[tokio::test]
async fn permission_without_claims_is_unauthorized_not_a_panic() {
    let h = TenantHarness::create("page_service_permission_without_claims")
        .await
        .unwrap();
    let (basebackup_cache, _) = BasebackupCache::new(Utf8PathBuf::new(), None);
    let resources = TenantSharedResources {
        broker_client: BrokerClientChannel::connect_lazy("foobar.com")
            .await
            .unwrap(),
        remote_storage: h.remote_storage.clone(),
        deletion_queue_client: h.deletion_queue.new_client(),
        l0_flush_global_state: L0FlushGlobalState::new(h.conf.l0_flush.clone()),
        basebackup_cache,
        feature_resolver: FeatureResolver::new_disabled(),
    };
    let tenant_manager = Arc::new(mgr::init(
        h.conf,
        BackgroundPurges::default(),
        resources,
        CancellationToken::new(),
    ));
    let gate = Gate::default();
    let handler = PageServerHandler::new(
        tenant_manager,
        Some(Arc::new(SwappableJwtAuth::new(JwtAuth::new(vec![])))),
        h.conf.page_service_pipelining.clone(),
        h.conf.get_vectored_concurrent_io,
        ConnectionPerfSpanFields {
            peer_addr: "127.0.0.1:0".to_string(),
            application_name: None,
            compute_mode: None,
        },
        RequestContext::new(TaskKind::PageRequestHandler, DownloadBehavior::Download),
        CancellationToken::new(),
        FeatureResolver::new_disabled(),
        gate.enter().unwrap(),
    );

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
