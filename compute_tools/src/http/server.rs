use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::middleware::{self};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use compute_api::responses::ComputeCtlConfig;
use http::StatusCode;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    auth::AsyncRequireAuthorizationLayer, request_id::PropagateRequestIdLayer, trace::TraceLayer,
};
use tracing::{Span, error, info, warn};

use super::middleware::request_id::maybe_add_request_id_header;
use super::{
    headers::X_REQUEST_ID,
    middleware::{authorize::Authorize, internal_auth},
    routes::{
        check_writability, configure, database_schema, dbs_and_roles, extension_server, extensions,
        grants, hadron_liveness_probe, insights, lfc, metrics, metrics_json, promote,
        refresh_configuration, status, storage_token, terminate,
    },
};
use crate::compute::ComputeNode;

/// `compute_ctl` has two servers: internal and external. The internal server
/// binds to the loopback interface (127.0.0.1, and ::1 where the host has it)
/// and handles communication from clients on the compute; every one of its
/// routes needs the per-start secret as a bearer (D2: each handler takes
/// `InternalAuth` first, and the served router carries the same check as a
/// route layer, [`Server::with_internal_auth`]). The external server is what receives communication
/// from the control plane, the metrics scraper, etc. We make the distinction
/// because certain routes in `compute_ctl` only need to be exposed to local
/// processes like Postgres via the neon extension and local_proxy.
#[derive(Clone, Debug)]
pub enum Server {
    Internal {
        port: u16,
    },
    External {
        port: u16,
        config: ComputeCtlConfig,
        compute_id: String,
        instance_id: Option<String>,
    },
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Server::Internal { .. } => f.write_str("internal"),
            Server::External { .. } => f.write_str("external"),
        }
    }
}

impl From<&Server> for Router<Arc<ComputeNode>> {
    fn from(server: &Server) -> Self {
        let mut router = Router::<Arc<ComputeNode>>::new();

        router = match server {
            Server::Internal { .. } => {
                router = router
                    .route(
                        "/extension_server/{*filename}",
                        post(extension_server::download_extension),
                    )
                    .route("/extensions", post(extensions::install_extension))
                    .route("/grants", post(grants::add_grant))
                    // Hadron: Compute-initiated configuration refresh
                    .route(
                        "/refresh_configuration",
                        post(refresh_configuration::refresh_configuration),
                    );

                // Add in any testing support
                if cfg!(feature = "testing") {
                    use super::routes::failpoints;

                    router = router.route("/failpoints", post(failpoints::configure_failpoints));
                }

                router
            }
            Server::External {
                config,
                compute_id,
                instance_id,
                ..
            } => {
                let unauthenticated_router = Router::<Arc<ComputeNode>>::new()
                    .route("/metrics", get(metrics::get_metrics))
                    .route(
                        "/autoscaling_metrics",
                        get(metrics::get_autoscaling_metrics),
                    );

                let authenticated_router = Router::<Arc<ComputeNode>>::new()
                    .route(
                        "/lfc/prewarm",
                        get(lfc::prewarm_state)
                            .post(lfc::prewarm)
                            .delete(lfc::cancel_prewarm),
                    )
                    .route("/lfc/offload", get(lfc::offload_state).post(lfc::offload))
                    .route("/promote", post(promote::promote))
                    .route("/check_writability", post(check_writability::is_writable))
                    .route("/configure", post(configure::configure))
                    .route("/database_schema", get(database_schema::get_schema_dump))
                    .route("/dbs_and_roles", get(dbs_and_roles::get_catalog_objects))
                    .route("/insights", get(insights::get_insights))
                    .route("/metrics.json", get(metrics_json::get_metrics))
                    .route("/status", get(status::get_status))
                    .route("/storage_token", post(storage_token::refresh_storage_token))
                    .route("/terminate", post(terminate::terminate))
                    .route(
                        "/hadron_liveness_probe",
                        get(hadron_liveness_probe::hadron_liveness_probe),
                    )
                    .layer(AsyncRequireAuthorizationLayer::new(Authorize::new(
                        compute_id.clone(),
                        instance_id.clone(),
                        config.jwks.clone(),
                    )));

                router
                    .merge(unauthenticated_router)
                    .merge(authenticated_router)
            }
        };

        router
            .fallback(Server::handle_404)
            .method_not_allowed_fallback(Server::handle_405)
            .layer(
                ServiceBuilder::new()
                    .layer(tower_otel::trace::HttpLayer::server(tracing::Level::INFO))
                    // Add this middleware since we assume the request ID exists
                    .layer(middleware::from_fn(maybe_add_request_id_header))
                    .layer(
                        TraceLayer::new_for_http()
                            .on_request(|request: &http::Request<_>, _span: &Span| {
                                let request_id = request
                                    .headers()
                                    .get(X_REQUEST_ID)
                                    .unwrap()
                                    .to_str()
                                    .unwrap();

                                info!(%request_id, "{} {}", request.method(), request.uri());
                            })
                            .on_response(
                                |response: &http::Response<_>, latency: Duration, _span: &Span| {
                                    let request_id = response
                                        .headers()
                                        .get(X_REQUEST_ID)
                                        .unwrap()
                                        .to_str()
                                        .unwrap();

                                    info!(
                                        %request_id,
                                        code = response.status().as_u16(),
                                        latency = latency.as_millis()
                                    );
                                },
                            ),
                    )
                    .layer(PropagateRequestIdLayer::x_request_id()),
            )
    }
}

impl Server {
    async fn handle_404() -> impl IntoResponse {
        StatusCode::NOT_FOUND
    }

    async fn handle_405() -> impl IntoResponse {
        StatusCode::METHOD_NOT_ALLOWED
    }

    /// The addresses the server listens on: the internal server on loopback
    /// only, `127.0.0.1` and `::1` (D2, P5; the `::1` one best effort, for hosts
    /// and pods without IPv6), the external server on every address.
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        match self {
            Server::Internal { port } => vec![
                SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), *port),
                SocketAddr::new(IpAddr::from(Ipv6Addr::LOCALHOST), *port),
            ],
            Server::External { port, .. } => {
                vec![SocketAddr::new(IpAddr::from(Ipv6Addr::UNSPECIFIED), *port)]
            }
        }
    }

    /// Binds every listen address, synchronously: on `Ok`, every listener is
    /// bound and accepts connections. Any bind error fails the start, naming
    /// the address, except the internal server's `::1` on a host without an
    /// IPv6 loopback (`EADDRNOTAVAIL`, `EAFNOSUPPORT`). Anything else there (a
    /// local process squatting `[::1]:<port>` included) would hand the bearer
    /// of every caller dialling `localhost` to someone else. On an error the
    /// listeners already bound are dropped (released).
    fn bind(&self) -> anyhow::Result<Vec<std::net::TcpListener>> {
        let mut listeners = Vec::new();
        for addr in self.listen_addrs() {
            match std::net::TcpListener::bind(addr) {
                Ok(listener) => {
                    listener.set_nonblocking(true).with_context(|| {
                        format!("compute_ctl {self} HTTP server: setting {addr} non-blocking")
                    })?;
                    listeners.push(listener);
                }
                Err(e)
                    if matches!(self, Server::Internal { .. })
                        && addr.is_ipv6()
                        && no_ipv6_loopback(&e) =>
                {
                    warn!(
                        "compute_ctl {self} HTTP server not listening at {addr} (no IPv6 loopback): {e}"
                    );
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "failed to bind the compute_ctl {self} HTTP server to {addr}"
                    )));
                }
            }
        }
        Ok(listeners)
    }

    /// The internal router's route layer: the same bearer check as the
    /// [`InternalAuth`](super::middleware::internal_auth::InternalAuth)
    /// extractor (one code path), so a route added without the extractor still
    /// needs the bearer. `serve` applies it to the internal router.
    pub fn with_internal_auth(
        router: Router<Arc<ComputeNode>>,
        compute: &Arc<ComputeNode>,
    ) -> Router<Arc<ComputeNode>> {
        router.route_layer(middleware::from_fn_with_state(
            Arc::clone(compute),
            internal_auth::require,
        ))
    }

    async fn serve(self, listeners: Vec<TcpListener>, compute: Arc<ComputeNode>) {
        let router = Router::from(&self);
        let router = match self {
            Server::Internal { .. } => Server::with_internal_auth(router, &compute),
            Server::External { .. } => router,
        };
        let router = router
            .with_state(compute)
            .into_make_service_with_connect_info::<SocketAddr>();

        let mut servers = tokio::task::JoinSet::new();
        for listener in listeners {
            if let Ok(local_addr) = listener.local_addr() {
                info!(
                    "compute_ctl {} HTTP server listening at {}",
                    self, local_addr
                );
            }
            let (router, name) = (router.clone(), self.to_string());
            servers.spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    error!("compute_ctl {} HTTP server error: {}", name, e);
                }
            });
        }
        while servers.join_next().await.is_some() {}
    }

    /// Binds every listener (see [`Server::listen_addrs`]) and only then spawns
    /// the serving tasks on the current Tokio runtime. On `Ok` a connection is
    /// accepted right away; a bind error is returned and nothing stays bound,
    /// so the caller (`ComputeNode::run`) fails compute_ctl's start.
    pub fn launch(self, compute: &Arc<ComputeNode>) -> anyhow::Result<()> {
        info!("Launching the {} server", self);

        let listeners = self
            .bind()?
            .into_iter()
            .map(|listener| {
                let addr = listener.local_addr().ok();
                TcpListener::from_std(listener).with_context(|| {
                    format!("compute_ctl {self} HTTP server: registering the listener at {addr:?}")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        tokio::spawn(self.serve(listeners, Arc::clone(compute)));
        Ok(())
    }
}

/// Whether binding an IPv6 address failed because the host has no IPv6
/// loopback (or no IPv6 at all).
fn no_ipv6_loopback(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::AddrNotAvailable
        || e.raw_os_error() == Some(nix::errno::Errno::EAFNOSUPPORT as i32)
}
