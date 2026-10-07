use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use http_utils::error::ApiError;
use pageserver_api::key::Key;
use pageserver_api::keyspace::KeySpace;
use pageserver_api::models::DetachBehavior;
use pageserver_api::models::detach_ancestor::AncestorDetached;
use pageserver_api::shard::ShardIdentity;
use pageserver_compaction::helpers::overlaps_with;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use utils::completion;
use utils::generation::Generation;
use utils::id::TimelineId;
use utils::lsn::Lsn;
use utils::sync::gate::GateError;

use super::layer_manager::{LayerManager, LayerManagerLockHolder};
use super::{FlushLayerError, Timeline, WaitLsnError, WaitLsnTimeout, WaitLsnWaiter};
use crate::context::{DownloadBehavior, RequestContext};
use crate::task_mgr::TaskKind;
use crate::tenant::TenantShard;
use crate::tenant::remote_timeline_client::index::GcBlockingReason::DetachAncestor;
use crate::tenant::storage_layer::layer::local_layer_path;
use crate::tenant::storage_layer::{
    AsLayerDesc as _, DeltaLayerName, DeltaLayerWriter, ImageLayerWriter, IoConcurrency, Layer,
    LayerName, ResidentLayer, ValuesReconstructState,
};
use crate::tenant::timeline::VersionedKeySpaceQuery;
use crate::virtual_file::{MaybeFatalIo, VirtualFile};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("no ancestors")]
    NoAncestor,

    #[error("too many ancestors")]
    TooManyAncestors,

    #[error("shutting down, please retry later")]
    ShuttingDown,

    #[error("archived: {}", .0)]
    Archived(TimelineId),

    #[error(transparent)]
    NotFound(crate::tenant::GetTimelineError),

    #[error("failed to reparent all candidate timelines, please retry")]
    FailedToReparentAll,

    #[error("ancestor is already being detached by: {}", .0)]
    OtherTimelineDetachOngoing(TimelineId),

    #[error("preparing to timeline ancestor detach failed")]
    Prepare(#[source] anyhow::Error),

    #[error("detaching and reparenting failed")]
    DetachReparent(#[source] anyhow::Error),

    #[error("completing ancestor detach failed")]
    Complete(#[source] anyhow::Error),

    #[error("failpoint: {}", .0)]
    Failpoint(&'static str),

    #[error("ancestor {ancestor} has not caught up to {lsn} yet, please retry later")]
    AncestorLsnTimeout { ancestor: TimelineId, lsn: Lsn },

    #[error("two ancestor levels have a layer named {layer}")]
    LayerNameCollision { layer: String },

    #[error("ancestor {ancestor} is broken, detach cannot proceed: {reason}")]
    AncestorBroken {
        ancestor: TimelineId,
        reason: String,
    },
}

impl Error {
    /// Try to catch cancellation from within the `anyhow::Error`, or wrap the anyhow as the given
    /// variant or fancier `or_else`.
    fn launder<F>(e: anyhow::Error, or_else: F) -> Error
    where
        F: Fn(anyhow::Error) -> Error,
    {
        use remote_storage::TimeoutOrCancel;

        use crate::tenant::remote_timeline_client::WaitCompletionError;
        use crate::tenant::upload_queue::NotInitialized;

        if e.is::<NotInitialized>()
            || TimeoutOrCancel::caused_by_cancel(&e)
            || e.downcast_ref::<remote_storage::DownloadError>()
                .is_some_and(|e| e.is_cancelled())
            || e.is::<WaitCompletionError>()
        {
            Error::ShuttingDown
        } else {
            or_else(e)
        }
    }
}

impl From<Error> for ApiError {
    fn from(value: Error) -> Self {
        match value {
            Error::NoAncestor => ApiError::Conflict(value.to_string()),
            Error::TooManyAncestors => ApiError::BadRequest(anyhow::anyhow!("{value}")),
            Error::ShuttingDown => ApiError::ShuttingDown,
            Error::Archived(_) => ApiError::BadRequest(anyhow::anyhow!("{value}")),
            Error::OtherTimelineDetachOngoing(_)
            | Error::FailedToReparentAll
            | Error::AncestorLsnTimeout { .. } => {
                ApiError::ResourceUnavailable(value.to_string().into())
            }
            Error::NotFound(e) => ApiError::from(e),
            // these variants should have no cancellation errors because of Error::launder
            Error::Prepare(_)
            | Error::DetachReparent(_)
            | Error::Complete(_)
            | Error::Failpoint(_)
            | Error::LayerNameCollision { .. }
            | Error::AncestorBroken { .. } => ApiError::InternalServerError(value.into()),
        }
    }
}

impl From<crate::tenant::upload_queue::NotInitialized> for Error {
    fn from(_: crate::tenant::upload_queue::NotInitialized) -> Self {
        // treat all as shutting down signals, even though that is not entirely correct
        // (uninitialized state)
        Error::ShuttingDown
    }
}
impl From<super::layer_manager::Shutdown> for Error {
    fn from(_: super::layer_manager::Shutdown) -> Self {
        Error::ShuttingDown
    }
}

pub(crate) enum Progress {
    Prepared(Attempt, PreparedTimelineDetach),
    Done(AncestorDetached),
}

pub(crate) struct PreparedTimelineDetach {
    layers: Vec<Layer>,
}

/// How long a detach waits for each ancestor to ingest its WAL up to the cut before giving up
/// with a retryable [`Error::AncestorLsnTimeout`].
const ANCESTOR_WAIT_LSN_TIMEOUT: Duration = Duration::from_secs(30);

// TODO: this should be part of PageserverConf because we cannot easily modify cplane arguments.
#[derive(Debug)]
pub(crate) struct Options {
    pub(crate) rewrite_concurrency: std::num::NonZeroUsize,
    pub(crate) copy_concurrency: std::num::NonZeroUsize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            rewrite_concurrency: std::num::NonZeroUsize::new(2).unwrap(),
            copy_concurrency: std::num::NonZeroUsize::new(100).unwrap(),
        }
    }
}

/// Represents an across tenant reset exclusive single attempt to detach ancestor.
#[derive(Debug)]
pub(crate) struct Attempt {
    pub(crate) timeline_id: TimelineId,
    pub(crate) ancestor_timeline_id: TimelineId,
    pub(crate) ancestor_lsn: Lsn,
    _guard: completion::Completion,
    gate_entered: Option<utils::sync::gate::GateGuard>,
}

impl Attempt {
    pub(crate) fn before_reset_tenant(&mut self) {
        let taken = self.gate_entered.take();
        assert!(taken.is_some());
    }

    pub(crate) fn new_barrier(&self) -> completion::Barrier {
        self._guard.barrier()
    }
}

/// Writes one image layer at `image_lsn` (the detached timeline's branch point) with a tombstone
/// for every non-inherited key that any level of `chain` holds at its cut: those keys never
/// descend into ancestors, so the copied layers must not expose them.
pub(crate) async fn generate_tombstone_image_layer(
    detached: &Arc<Timeline>,
    chain: &[(Arc<Timeline>, Lsn)],
    image_lsn: Lsn,
    historic_layers_to_copy: &[Layer],
    ctx: &RequestContext,
) -> Result<Option<ResidentLayer>, Error> {
    tracing::info!(
        "removing non-inherited keys by writing an image layer with tombstones at the detach LSN"
    );
    // Directly use `get_vectored_impl` to skip the max_vectored_read_key limit check. Note that the keyspace should
    // not contain too many keys, otherwise this takes a lot of memory. Currently we limit it to 10k keys in the compute.
    let key_range = Key::sparse_non_inherited_keyspace();
    // `image_lsn` is the detached timeline's ancestor LSN: this avoids generating a "future
    // layer" which will then be removed

    {
        for layer in historic_layers_to_copy {
            let desc = layer.layer_desc();
            if !desc.is_delta
                && desc.lsn_range.start == image_lsn
                && overlaps_with(&key_range, &desc.key_range)
            {
                tracing::info!(
                    layer=%layer, "will copy tombstone from ancestor instead of creating a new one"
                );

                return Ok(None);
            }
        }

        let layers = detached
            .layers
            .read(LayerManagerLockHolder::DetachAncestor)
            .await;
        for layer in layers.all_persistent_layers() {
            if !layer.is_delta
                && layer.lsn_range.start == image_lsn
                && overlaps_with(&key_range, &layer.key_range)
            {
                tracing::warn!(
                    layer=%layer, "image layer at the detach LSN already exists, skipping removing aux files"
                );
                return Ok(None);
            }
        }
    }

    let mut keys = BTreeSet::new();
    for (level, cut) in chain {
        let io_concurrency = IoConcurrency::spawn_from_conf(
            detached.conf.get_vectored_concurrent_io,
            detached.gate.enter().map_err(|_| Error::ShuttingDown)?,
        );
        let mut reconstruct_state = ValuesReconstructState::new(io_concurrency);
        let query = VersionedKeySpaceQuery::uniform(KeySpace::single(key_range.clone()), *cut);
        let data = level
            .get_vectored_impl(query, &mut reconstruct_state, ctx)
            .await
            .context("failed to retrieve aux keys")
            .map_err(|e| Error::launder(e, Error::Prepare))?;
        keys.extend(data.into_keys());
    }
    if !keys.is_empty() {
        // TODO: is it possible that we can have an image at `image_lsn`? Unlikely because image layers are only generated
        // upon compaction but theoretically possible.
        let mut image_layer_writer = ImageLayerWriter::new(
            detached.conf,
            detached.timeline_id,
            detached.tenant_shard_id,
            &key_range,
            image_lsn,
            &detached.gate,
            detached.cancel.clone(),
            ctx,
        )
        .await
        .context("failed to create image layer writer")
        .map_err(Error::Prepare)?;
        for key in keys {
            image_layer_writer
                .put_image(key, Bytes::new(), ctx)
                .await
                .context("failed to write key")
                .map_err(|e| Error::launder(e, Error::Prepare))?;
        }
        let (desc, path) = image_layer_writer
            .finish(ctx)
            .await
            .context("failed to finish image layer writer for removing the metadata keys")
            .map_err(|e| Error::launder(e, Error::Prepare))?;
        let generated = Layer::finish_creating(detached.conf, detached, desc, &path)
            .map_err(|e| Error::launder(e, Error::Prepare))?;
        detached
            .remote_client
            .upload_layer_file(&generated, &detached.cancel)
            .await
            .map_err(|e| Error::launder(e, Error::Prepare))?;
        tracing::info!(layer=%generated, "wrote image layer");
        Ok(Some(generated))
    } else {
        tracing::info!("no aux keys found in ancestor");
        Ok(None)
    }
}

/// See [`Timeline::prepare_to_detach_from_ancestor`]
pub(super) async fn prepare(
    detached: &Arc<Timeline>,
    tenant: &TenantShard,
    behavior: DetachBehavior,
    options: Options,
    ctx: &RequestContext,
) -> Result<Progress, Error> {
    use Error::*;

    let Some((ancestor, ancestor_lsn)) = detached
        .ancestor_timeline
        .as_ref()
        .map(|tl| (tl.clone(), detached.ancestor_lsn))
    else {
        let ancestor_id;
        let ancestor_lsn;
        let still_in_progress = {
            let accessor = detached.remote_client.initialized_upload_queue()?;

            // we are safe to inspect the latest uploaded, because we can only witness this after
            // restart is complete and ancestor is no more.
            let latest = accessor.latest_uploaded_index_part();
            let Some((id, lsn)) = latest.lineage.detached_previous_ancestor() else {
                return Err(NoAncestor);
            };
            ancestor_id = id;
            ancestor_lsn = lsn;

            latest
                .gc_blocking
                .as_ref()
                .is_some_and(|b| b.blocked_by(DetachAncestor))
        };

        if still_in_progress {
            // gc is still blocked, we can still reparent and complete.
            // we are safe to reparent remaining, because they were locked in in the beginning.
            let attempt =
                continue_with_blocked_gc(detached, tenant, ancestor_id, ancestor_lsn).await?;

            // because the ancestor of detached is already set to none, we have published all
            // of the layers, so we are still "prepared."
            return Ok(Progress::Prepared(
                attempt,
                PreparedTimelineDetach { layers: Vec::new() },
            ));
        }

        let reparented_timelines = reparented_direct_children(detached, tenant)?;
        return Ok(Progress::Done(AncestorDetached {
            reparented_timelines,
        }));
    };

    if detached.is_archived() != Some(false) {
        return Err(Archived(detached.timeline_id));
    }

    if !ancestor_lsn.is_valid() {
        // rare case, probably wouldn't even load
        tracing::error!("ancestor is set, but ancestor_lsn is invalid, this timeline needs fixing");
        return Err(NoAncestor);
    }

    check_no_archived_children_of_ancestor(tenant, detached, &ancestor, ancestor_lsn, behavior)?;

    // [(parent, detached.ancestor_lsn), (grandparent, parent.ancestor_lsn), ...]
    let chain = detach_chain(
        (ancestor, ancestor_lsn),
        |level: &Arc<Timeline>| {
            level
                .ancestor_timeline
                .clone()
                .map(|next| (next, level.ancestor_lsn))
        },
        behavior,
    )?;

    for (level, cut) in chain.iter().skip(1) {
        // TODO: do we still need to check if we don't want to reparent?
        check_no_archived_children_of_ancestor(tenant, detached, level, *cut, behavior)?;
    }

    let root = &chain.last().expect("never empty").0;

    tracing::info!(
        "attempt to detach the timeline from the ancestor: {}@{}, behavior={:?}, levels={}",
        root.timeline_id,
        ancestor_lsn,
        behavior,
        chain.len(),
    );

    // An ancestor reloaded since its last flush only has its WAL up to its disk consistent LSN
    // until its walreceiver catches up; copying before that would lose the writes in between.
    // Wait before taking the attempt and the gc block, so that a timeout holds neither.
    // The levels are waited for one after the other, each up to ANCESTOR_WAIT_LSN_TIMEOUT, so
    // the worst case is that timeout times the chain's depth before the 503.
    for (level, cut) in &chain {
        level
            .wait_lsn(
                *cut,
                WaitLsnWaiter::Timeline(detached),
                WaitLsnTimeout::Custom(ANCESTOR_WAIT_LSN_TIMEOUT),
                ctx,
            )
            .await
            .map_err(|e| ancestor_wait_error(e, level.timeline_id, *cut))?;
    }

    // The lineage records the root at the detached timeline's own ancestor LSN.
    let attempt = start_new_attempt(detached, tenant, root.timeline_id, ancestor_lsn).await?;

    utils::pausable_failpoint!("timeline-detach-ancestor::before_starting_after_locking-pausable");

    fail::fail_point!(
        "timeline-detach-ancestor::before_starting_after_locking",
        |_| Err(Error::Failpoint(
            "timeline-detach-ancestor::before_starting_after_locking"
        ))
    );

    // Every level contributes its layers up to its cut: straddling deltas are rewritten to end
    // at `cut + 1`, the rest is copied as is. A level whose cut equals its own branch point
    // contributes nothing (all of its layers start after the cut).
    let mut straddling_branchpoint: Vec<(Layer, Lsn)> = Vec::new();
    let mut rest_of_historic: Vec<Layer> = Vec::new();
    let mut layer_names = HashSet::new();

    for (level, cut) in &chain {
        if *cut >= level.get_disk_consistent_lsn() {
            freeze_and_flush_ancestor(level).await?;
        }

        let end_lsn = *cut + 1;

        let (filtered_layers, straddling, rest) = {
            // we do not need to start from our layers, because they can only be layers that come
            // *after* ancestor_lsn
            let layers = tokio::select! {
                guard = level.layers.read(LayerManagerLockHolder::DetachAncestor) => guard,
                _ = detached.cancel.cancelled() => {
                    return Err(ShuttingDown);
                }
                _ = level.cancel.cancelled() => {
                    return Err(ShuttingDown);
                }
            };

            // between retries, these can change if compaction or gc ran in between. this will mean
            // we have to redo work.
            partition_work(*cut, &layers)?
        };

        // TODO: layers are already sorted by something: use that to determine how much of remote
        // copies are already done -- gc is blocked, but a compaction could had happened on ancestor,
        // which is something to keep in mind if copy skipping is implemented.
        tracing::info!(ancestor=%level.timeline_id, %cut, filtered=%filtered_layers, to_rewrite = straddling.len(), historic=%rest.len(), "collected layers");

        // Refuse before copying anything if two levels would produce the same layer name. This
        // runs after `start_new_attempt`, so the refusal keeps the gc block of the attempt; a
        // retry then hits the same (deterministic) collision. Unreachable in practice: the
        // levels contribute disjoint LSN ranges (a level's own layers start at its branch
        // point, where its ancestor's contribution ends), and layer names carry the LSN range.
        for layer in &straddling {
            check_layer_name_unique(&mut layer_names, &rewritten_layer_name(layer, end_lsn))?;
        }
        for layer in &rest {
            check_layer_name_unique(
                &mut layer_names,
                &layer.layer_desc().layer_name().to_string(),
            )?;
        }

        straddling_branchpoint.extend(straddling.into_iter().map(|layer| (layer, end_lsn)));
        rest_of_historic.extend(rest);
    }

    // Layers in `rest_of_historic` are copied remote to remote, so each must already be in
    // remote storage. The HTTP handler drained the upload queues before `prepare`, but layers
    // flushed or compacted since (during the catch-up waits, or by the flushes above) may still
    // be uploading: wait for every level's queued uploads before copying. Every layer-map
    // update schedules its uploads under the same write lock that makes the layers visible,
    // so each layer selected above already has its upload queued, and the barrier covers it.
    // Like the handler's own drain, the wait has no timeout: a stuck upload queue (remote
    // storage down) holds the detach until shutdown or cancellation.
    for (level, _) in &chain {
        tokio::select! {
            res = level.remote_client.wait_completion() => {
                // The level's upload queue is stopped or not (yet, or any more) initialized:
                // shutdown or deletion, retryable as for a cancelled level (`Error::launder`
                // maps `WaitCompletionError` the same way).
                res.map_err(|_| ShuttingDown)?;
            }
            _ = detached.cancel.cancelled() => return Err(ShuttingDown),
            _ = level.cancel.cancelled() => return Err(ShuttingDown),
        }
    }

    // TODO: copying and lsn prefix copying could be done at the same time with a single fsync after
    let mut new_layers: Vec<Layer> =
        Vec::with_capacity(straddling_branchpoint.len() + rest_of_historic.len() + 1);

    if let Some(tombstone_layer) =
        generate_tombstone_image_layer(detached, &chain, ancestor_lsn, &rest_of_historic, ctx)
            .await?
    {
        new_layers.push(tombstone_layer.into());
    }

    {
        tracing::info!(to_rewrite = %straddling_branchpoint.len(), "copying prefix of delta layers");

        let mut tasks = tokio::task::JoinSet::new();

        let mut wrote_any = false;

        let limiter = Arc::new(Semaphore::new(options.rewrite_concurrency.get()));

        for (layer, end_lsn) in straddling_branchpoint {
            let limiter = limiter.clone();
            let timeline = detached.clone();
            let ctx = ctx.detached_child(TaskKind::DetachAncestor, DownloadBehavior::Download);

            let span = tracing::info_span!("upload_rewritten_layer", %layer);
            tasks.spawn(
                async move {
                    let _permit = limiter.acquire().await;
                    let copied =
                        upload_rewritten_layer(end_lsn, &layer, &timeline, &timeline.cancel, &ctx)
                            .await?;
                    if let Some(copied) = copied.as_ref() {
                        tracing::info!(%copied, "rewrote and uploaded");
                    }
                    Ok(copied)
                }
                .instrument(span),
            );
        }

        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(Ok(Some(copied))) => {
                    wrote_any = true;
                    new_layers.push(copied);
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => return Err(e),
                Err(je) => return Err(Error::Prepare(je.into())),
            }
        }

        // FIXME: the fsync should be mandatory, after both rewrites and copies
        if wrote_any {
            fsync_timeline_dir(detached, ctx).await;
        }
    }

    let mut tasks = tokio::task::JoinSet::new();
    let limiter = Arc::new(Semaphore::new(options.copy_concurrency.get()));
    let cancel_eval = CancellationToken::new();

    for adopted in rest_of_historic {
        let limiter = limiter.clone();
        let timeline = detached.clone();
        let cancel_eval = cancel_eval.clone();

        tasks.spawn(
            async move {
                let _permit = tokio::select! {
                    permit = limiter.acquire() => {
                        permit
                    }
                    // Wait for the cancellation here instead of letting the entire task be cancelled.
                    // Cancellations are racy in that they might leave layers on disk.
                    _ = cancel_eval.cancelled() => {
                        Err(Error::ShuttingDown)?
                    }
                };
                let (owned, did_hardlink) = remote_copy(
                    &adopted,
                    &timeline,
                    timeline.generation,
                    timeline.shard_identity,
                    &timeline.cancel,
                )
                .await?;
                tracing::info!(layer=%owned, did_hard_link=%did_hardlink, "remote copied");
                Ok((owned, did_hardlink))
            }
            .in_current_span(),
        );
    }

    fn delete_layers(timeline: &Timeline, layers: Vec<Layer>) -> Result<(), Error> {
        // We are deleting layers, so we must hold the gate
        let _gate = timeline.gate.enter().map_err(|e| match e {
            GateError::GateClosed => Error::ShuttingDown,
        })?;
        {
            layers.into_iter().for_each(|l: Layer| {
                l.delete_on_drop();
                std::mem::drop(l);
            });
        }
        Ok(())
    }

    let mut should_fsync = false;
    let mut first_err = None;
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok((owned, did_hardlink))) => {
                if did_hardlink {
                    should_fsync = true;
                }
                new_layers.push(owned);
            }

            // Don't stop the evaluation on errors, so that we get the full set of hardlinked layers to delete.
            Ok(Err(failed)) => {
                cancel_eval.cancel();
                first_err.get_or_insert(failed);
            }
            Err(je) => {
                cancel_eval.cancel();
                first_err.get_or_insert(Error::Prepare(je.into()));
            }
        }
    }

    if let Some(failed) = first_err {
        delete_layers(detached, new_layers)?;
        return Err(failed);
    }

    // fsync directory again if we hardlinked something
    if should_fsync {
        fsync_timeline_dir(detached, ctx).await;
    }

    let prepared = PreparedTimelineDetach { layers: new_layers };

    Ok(Progress::Prepared(attempt, prepared))
}

/// The ancestor chain to copy from, nearest first: `[(parent, cut), (grandparent, cut), ...]`,
/// where each cut is the LSN the level's child branched at. `parent_of` returns a level's own
/// ancestor and its ancestor LSN. The default behavior refuses a chain longer than one.
fn detach_chain<T>(
    first: (T, Lsn),
    parent_of: impl Fn(&T) -> Option<(T, Lsn)>,
    behavior: DetachBehavior,
) -> Result<Vec<(T, Lsn)>, Error> {
    let mut chain = vec![first];
    while let Some(next) = parent_of(&chain.last().expect("never empty").0) {
        if let DetachBehavior::NoAncestorAndReparent = behavior {
            // non-technical requirement; we could flatten N ancestors just as easily but we chose
            // not to, at least initially
            return Err(Error::TooManyAncestors);
        }
        chain.push(next);
    }
    Ok(chain)
}

/// Maps a failed wait for an ancestor's WAL: cancellation is a shutdown, a broken ancestor a
/// 500 (retrying won't help), anything else (a timeout, a loading ancestor) a retryable 503.
fn ancestor_wait_error(e: WaitLsnError, ancestor: TimelineId, lsn: Lsn) -> Error {
    if e.is_cancel() {
        return Error::ShuttingDown;
    }
    match e {
        WaitLsnError::BadState(pageserver_api::models::TimelineState::Broken {
            reason, ..
        }) => Error::AncestorBroken { ancestor, reason },
        _ => Error::AncestorLsnTimeout { ancestor, lsn },
    }
}

/// Layer file names carry no timeline id, so two levels could yield the same name.
fn check_layer_name_unique(seen: &mut HashSet<String>, name: &str) -> Result<(), Error> {
    if seen.insert(name.to_owned()) {
        Ok(())
    } else {
        Err(Error::LayerNameCollision {
            layer: name.to_owned(),
        })
    }
}

/// The name [`copy_lsn_prefix`] gives the rewritten prefix of `layer` ending at `end_lsn`.
fn rewritten_layer_name(layer: &Layer, end_lsn: Lsn) -> String {
    let desc = layer.layer_desc();
    LayerName::Delta(DeltaLayerName {
        key_range: desc.key_range.clone(),
        lsn_range: desc.lsn_range.start..end_lsn,
    })
    .to_string()
}

/// Freezes and flushes an ancestor's open layer: copying a delta prefix is unsupported for
/// `InMemoryLayer`, so the layers up to the cut must be on disk.
async fn freeze_and_flush_ancestor(ancestor: &Arc<Timeline>) -> Result<(), Error> {
    let span = tracing::info_span!("freeze_and_flush", ancestor_timeline_id=%ancestor.timeline_id);
    async {
        let started_at = std::time::Instant::now();
        let freeze_and_flush = ancestor.freeze_and_flush0();
        let mut freeze_and_flush = std::pin::pin!(freeze_and_flush);

        let res =
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut freeze_and_flush).await;

        let res = match res {
            Ok(res) => res,
            Err(_elapsed) => {
                tracing::info!("freezing and flushing ancestor is still ongoing");
                freeze_and_flush.await
            }
        };

        res.map_err(|e| {
            use FlushLayerError::*;
            match e {
                Cancelled | NotRunning(_) => {
                    // FIXME(#6424): technically statically unreachable right now, given how we never
                    // drop the sender
                    Error::ShuttingDown
                }
                CreateImageLayersError(_) | Other(_) => Error::Prepare(e.into()),
            }
        })?;

        // we do not need to wait for uploads to complete but we do need `struct Layer`,
        // copying delta prefix is unsupported currently for `InMemoryLayer`.
        tracing::info!(
            elapsed_ms = started_at.elapsed().as_millis(),
            "froze and flushed the ancestor"
        );
        Ok::<_, Error>(())
    }
    .instrument(span)
    .await
}

async fn start_new_attempt(
    detached: &Timeline,
    tenant: &TenantShard,
    ancestor_timeline_id: TimelineId,
    ancestor_lsn: Lsn,
) -> Result<Attempt, Error> {
    let attempt = obtain_exclusive_attempt(detached, tenant, ancestor_timeline_id, ancestor_lsn)?;

    // insert the block in the index_part.json, if not already there.
    let _dont_care = tenant
        .gc_block
        .insert(
            detached,
            crate::tenant::remote_timeline_client::index::GcBlockingReason::DetachAncestor,
        )
        .await
        .map_err(|e| Error::launder(e, Error::Prepare))?;

    Ok(attempt)
}

async fn continue_with_blocked_gc(
    detached: &Timeline,
    tenant: &TenantShard,
    ancestor_timeline_id: TimelineId,
    ancestor_lsn: Lsn,
) -> Result<Attempt, Error> {
    // FIXME: it would be nice to confirm that there is an in-memory version, since we've just
    // verified there is a persistent one?
    obtain_exclusive_attempt(detached, tenant, ancestor_timeline_id, ancestor_lsn)
}

fn obtain_exclusive_attempt(
    detached: &Timeline,
    tenant: &TenantShard,
    ancestor_timeline_id: TimelineId,
    ancestor_lsn: Lsn,
) -> Result<Attempt, Error> {
    use Error::{OtherTimelineDetachOngoing, ShuttingDown};

    // ensure we are the only active attempt for this tenant
    let (guard, barrier) = completion::channel();
    {
        let mut guard = tenant.ongoing_timeline_detach.lock().unwrap();
        if let Some((tl, other)) = guard.as_ref() {
            if !other.is_ready() {
                return Err(OtherTimelineDetachOngoing(*tl));
            }
            // FIXME: no test enters here
        }
        *guard = Some((detached.timeline_id, barrier));
    }

    // ensure the gate is still open
    let _gate_entered = detached.gate.enter().map_err(|_| ShuttingDown)?;

    Ok(Attempt {
        timeline_id: detached.timeline_id,
        ancestor_timeline_id,
        ancestor_lsn,
        _guard: guard,
        gate_entered: Some(_gate_entered),
    })
}

fn reparented_direct_children(
    detached: &Arc<Timeline>,
    tenant: &TenantShard,
) -> Result<HashSet<TimelineId>, Error> {
    let mut all_direct_children = tenant
        .timelines
        .lock()
        .unwrap()
        .values()
        .filter_map(|tl| {
            let is_direct_child = matches!(tl.ancestor_timeline.as_ref(), Some(ancestor) if Arc::ptr_eq(ancestor, detached));

            if is_direct_child {
                Some(tl.clone())
            } else {
                if let Some(timeline) = tl.ancestor_timeline.as_ref() {
                    assert_ne!(timeline.timeline_id, detached.timeline_id, "we cannot have two timelines with the same timeline_id live");
                }
                None
            }
        })
        // Collect to avoid lock taking order problem with Tenant::timelines and
        // Timeline::remote_client
        .collect::<Vec<_>>();

    let mut any_shutdown = false;

    all_direct_children.retain(|tl| match tl.remote_client.initialized_upload_queue() {
        Ok(accessor) => accessor
            .latest_uploaded_index_part()
            .lineage
            .is_reparented(),
        Err(_shutdownalike) => {
            // not 100% a shutdown, but let's bail early not to give inconsistent results in
            // sharded enviroment.
            any_shutdown = true;
            true
        }
    });

    if any_shutdown {
        // it could be one or many being deleted; have client retry
        return Err(Error::ShuttingDown);
    }

    Ok(all_direct_children
        .into_iter()
        .map(|tl| tl.timeline_id)
        .collect())
}

fn partition_work(
    ancestor_lsn: Lsn,
    source: &LayerManager,
) -> Result<(usize, Vec<Layer>, Vec<Layer>), Error> {
    let mut straddling_branchpoint = vec![];
    let mut rest_of_historic = vec![];

    let mut later_by_lsn = 0;

    for desc in source.layer_map()?.iter_historic_layers() {
        // off by one chances here:
        // - start is inclusive
        // - end is exclusive
        if desc.lsn_range.start > ancestor_lsn {
            later_by_lsn += 1;
            continue;
        }

        let target = if desc.lsn_range.start <= ancestor_lsn
            && desc.lsn_range.end > ancestor_lsn
            && desc.is_delta
        {
            // TODO: image layer at Lsn optimization
            &mut straddling_branchpoint
        } else {
            &mut rest_of_historic
        };

        target.push(source.get_from_desc(&desc));
    }

    Ok((later_by_lsn, straddling_branchpoint, rest_of_historic))
}

async fn upload_rewritten_layer(
    end_lsn: Lsn,
    layer: &Layer,
    target: &Arc<Timeline>,
    cancel: &CancellationToken,
    ctx: &RequestContext,
) -> Result<Option<Layer>, Error> {
    let copied = copy_lsn_prefix(end_lsn, layer, target, ctx).await?;

    let Some(copied) = copied else {
        return Ok(None);
    };

    target
        .remote_client
        .upload_layer_file(&copied, cancel)
        .await
        .map_err(|e| Error::launder(e, Error::Prepare))?;

    Ok(Some(copied.into()))
}

async fn copy_lsn_prefix(
    end_lsn: Lsn,
    layer: &Layer,
    target_timeline: &Arc<Timeline>,
    ctx: &RequestContext,
) -> Result<Option<ResidentLayer>, Error> {
    if target_timeline.cancel.is_cancelled() {
        return Err(Error::ShuttingDown);
    }

    tracing::debug!(%layer, %end_lsn, "copying lsn prefix");

    let mut writer = DeltaLayerWriter::new(
        target_timeline.conf,
        target_timeline.timeline_id,
        target_timeline.tenant_shard_id,
        layer.layer_desc().key_range.start,
        layer.layer_desc().lsn_range.start..end_lsn,
        &target_timeline.gate,
        target_timeline.cancel.clone(),
        ctx,
    )
    .await
    .with_context(|| format!("prepare to copy lsn prefix of ancestors {layer}"))
    .map_err(Error::Prepare)?;

    let resident = layer.download_and_keep_resident(ctx).await.map_err(|e| {
        if e.is_cancelled() {
            Error::ShuttingDown
        } else {
            Error::Prepare(e.into())
        }
    })?;

    let records = resident
        .copy_delta_prefix(&mut writer, end_lsn, ctx)
        .await
        .with_context(|| format!("copy lsn prefix of ancestors {layer}"))
        .map_err(Error::Prepare)?;

    drop(resident);

    tracing::debug!(%layer, records, "copied records");

    if records == 0 {
        drop(writer);
        // TODO: we might want to store an empty marker in remote storage for this
        // layer so that we will not needlessly walk `layer` on repeated attempts.
        Ok(None)
    } else {
        // reuse the key instead of adding more holes between layers by using the real
        // highest key in the layer.
        let reused_highest_key = layer.layer_desc().key_range.end;
        let (desc, path) = writer
            .finish(reused_highest_key, ctx)
            .await
            .map_err(Error::Prepare)?;
        let copied = Layer::finish_creating(target_timeline.conf, target_timeline, desc, &path)
            .map_err(Error::Prepare)?;

        tracing::debug!(%layer, %copied, "new layer produced");

        Ok(Some(copied))
    }
}

/// Creates a new Layer instance for the adopted layer, and ensures it is found in the remote
/// storage on successful return. without the adopted layer being added to `index_part.json`.
/// Returns (Layer, did hardlink)
async fn remote_copy(
    adopted: &Layer,
    adoptee: &Arc<Timeline>,
    generation: Generation,
    shard_identity: ShardIdentity,
    cancel: &CancellationToken,
) -> Result<(Layer, bool), Error> {
    let mut metadata = adopted.metadata();
    debug_assert!(metadata.generation <= generation);
    metadata.generation = generation;
    metadata.shard = shard_identity.shard_index();

    let conf = adoptee.conf;
    let file_name = adopted.layer_desc().layer_name();

    // We don't want to shut the timeline down during this operation because we do `delete_on_drop` below
    let _gate = adoptee.gate.enter().map_err(|e| match e {
        GateError::GateClosed => Error::ShuttingDown,
    })?;

    // depending if Layer::keep_resident, do a hardlink
    let did_hardlink;
    let owned = if let Some(adopted_resident) = adopted.keep_resident().await {
        let adopted_path = adopted_resident.local_path();
        let adoptee_path = local_layer_path(
            conf,
            &adoptee.tenant_shard_id,
            &adoptee.timeline_id,
            &file_name,
            &metadata.generation,
        );

        match std::fs::hard_link(adopted_path, &adoptee_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // In theory we should not get into this situation as we are doing cleanups of the layer file after errors.
                // However, we don't do cleanups for errors past `prepare`, so there is the slight chance to get to this branch.

                // Double check that the file is orphan (probably from an earlier attempt), then delete it
                let key = file_name.clone().into();
                if adoptee
                    .layers
                    .read(LayerManagerLockHolder::DetachAncestor)
                    .await
                    .contains_key(&key)
                {
                    // We are supposed to filter out such cases before coming to this function
                    return Err(Error::Prepare(anyhow::anyhow!(
                        "layer file {file_name} already present and inside layer map"
                    )));
                }
                tracing::info!("Deleting orphan layer file to make way for hard linking");
                // Delete orphan layer file and try again, to ensure this layer has a well understood source
                std::fs::remove_file(&adoptee_path)
                    .map_err(|e| Error::launder(e.into(), Error::Prepare))?;
                std::fs::hard_link(adopted_path, &adoptee_path)
                    .map_err(|e| Error::launder(e.into(), Error::Prepare))?;
            }
            Err(e) => {
                return Err(Error::launder(e.into(), Error::Prepare));
            }
        };
        did_hardlink = true;
        Layer::for_resident(conf, adoptee, adoptee_path, file_name, metadata).drop_eviction_guard()
    } else {
        did_hardlink = false;
        Layer::for_evicted(conf, adoptee, file_name, metadata)
    };

    let layer = match adoptee
        .remote_client
        .copy_timeline_layer(adopted, &owned, cancel)
        .await
    {
        Ok(()) => owned,
        Err(e) => {
            {
                // Clean up the layer so that on a retry we don't get errors that the file already exists
                owned.delete_on_drop();
                std::mem::drop(owned);
            }
            return Err(Error::launder(e, Error::Prepare));
        }
    };

    Ok((layer, did_hardlink))
}

pub(crate) enum DetachingAndReparenting {
    /// All of the following timeline ids were reparented and the timeline ancestor detach must be
    /// marked as completed.
    Reparented(HashSet<TimelineId>),

    /// Some of the reparentings failed. The timeline ancestor detach must **not** be marked as
    /// completed.
    ///
    /// Nested `must_reset_tenant` is set to true when any restart requiring changes were made.
    SomeReparentingFailed { must_reset_tenant: bool },

    /// Detaching and reparentings were completed in a previous attempt. Timeline ancestor detach
    /// must be marked as completed.
    AlreadyDone(HashSet<TimelineId>),
}

impl DetachingAndReparenting {
    pub(crate) fn reset_tenant_required(&self) -> bool {
        use DetachingAndReparenting::*;
        match self {
            Reparented(_) => true,
            SomeReparentingFailed { must_reset_tenant } => *must_reset_tenant,
            AlreadyDone(_) => false,
        }
    }

    pub(crate) fn completed(self) -> Option<HashSet<TimelineId>> {
        use DetachingAndReparenting::*;
        match self {
            Reparented(x) | AlreadyDone(x) => Some(x),
            SomeReparentingFailed { .. } => None,
        }
    }
}

/// See [`Timeline::detach_from_ancestor_and_reparent`].
pub(super) async fn detach_and_reparent(
    detached: &Arc<Timeline>,
    tenant: &TenantShard,
    prepared: PreparedTimelineDetach,
    ancestor_timeline_id: TimelineId,
    // the attempt's LSN; no longer checked against the chain, whose levels may differ
    _ancestor_lsn: Lsn,
    behavior: DetachBehavior,
    _ctx: &RequestContext,
) -> Result<DetachingAndReparenting, Error> {
    let PreparedTimelineDetach { layers } = prepared;

    #[derive(Debug)]
    enum Ancestor {
        NotDetached(Arc<Timeline>, Lsn),
        Detached(Arc<Timeline>, Lsn),
    }

    let (recorded_branchpoint, still_ongoing) = {
        let access = detached.remote_client.initialized_upload_queue()?;
        let latest = access.latest_uploaded_index_part();

        (
            latest.lineage.detached_previous_ancestor(),
            latest
                .gc_blocking
                .as_ref()
                .is_some_and(|b| b.blocked_by(DetachAncestor)),
        )
    };
    assert!(
        still_ongoing,
        "cannot (detach? reparent)? complete if the operation is not still ongoing"
    );

    let ancestor_to_detach = match detached.ancestor_timeline.as_ref() {
        Some(mut ancestor) => {
            // multi-level detach: the levels may have been branched at different LSNs, all of
            // them were copied in `prepare`
            while ancestor.timeline_id != ancestor_timeline_id {
                match ancestor.ancestor_timeline.as_ref() {
                    Some(found) => {
                        ancestor = found;
                    }
                    None => {
                        return Err(Error::DetachReparent(anyhow::anyhow!(
                            "cannot find the ancestor timeline to detach from"
                        )));
                    }
                }
            }
            Some(ancestor)
        }
        None => None,
    };
    let ancestor = match (ancestor_to_detach, recorded_branchpoint) {
        (Some(ancestor), None) => {
            assert!(
                !layers.is_empty(),
                "there should always be at least one layer to inherit"
            );
            Ancestor::NotDetached(ancestor.clone(), detached.ancestor_lsn)
        }
        (Some(_), Some(_)) => {
            panic!(
                "it should be impossible to get to here without having gone through the tenant reset; if the tenant was reset, then the ancestor_timeline would be None"
            );
        }
        (None, Some((ancestor_id, ancestor_lsn))) => {
            // it has been either:
            // - detached but still exists => we can try reparenting
            // - detached and deleted
            //
            // either way, we must complete
            assert!(
                layers.is_empty(),
                "no layers should had been copied as detach is done"
            );

            let existing = tenant.timelines.lock().unwrap().get(&ancestor_id).cloned();

            if let Some(ancestor) = existing {
                Ancestor::Detached(ancestor, ancestor_lsn)
            } else {
                let direct_children = reparented_direct_children(detached, tenant)?;
                return Ok(DetachingAndReparenting::AlreadyDone(direct_children));
            }
        }
        (None, None) => {
            // TODO: make sure there are no `?` before tenant_reset from after a questionmark from
            // here.
            panic!(
                "bug: detach_and_reparent called on a timeline which has not been detached or which has no live ancestor"
            );
        }
    };

    // publish the prepared layers before we reparent any of the timelines, so that on restart
    // reparented timelines find layers. also do the actual detaching.
    //
    // if we crash after this operation, a retry will allow reparenting the remaining timelines as
    // gc is blocked.

    let (ancestor, ancestor_lsn, was_detached) = match ancestor {
        Ancestor::NotDetached(ancestor, ancestor_lsn) => {
            // this has to complete before any reparentings because otherwise they would not have
            // layers on the new parent.
            detached
                .remote_client
                .schedule_adding_existing_layers_to_index_detach_and_wait(
                    &layers,
                    (ancestor.timeline_id, ancestor_lsn),
                )
                .await
                .context("publish layers and detach ancestor")
                .map_err(|e| Error::launder(e, Error::DetachReparent))?;

            tracing::info!(
                ancestor=%ancestor.timeline_id,
                %ancestor_lsn,
                inherited_layers=%layers.len(),
                "detached from ancestor"
            );
            (ancestor, ancestor_lsn, true)
        }
        Ancestor::Detached(ancestor, ancestor_lsn) => (ancestor, ancestor_lsn, false),
    };

    if let DetachBehavior::MultiLevelAndNoReparent = behavior {
        // Do not reparent if the user requests to behave so.
        return Ok(DetachingAndReparenting::Reparented(HashSet::new()));
    }

    let mut tasks = tokio::task::JoinSet::new();

    // Returns a single permit semaphore which will be used to make one reparenting succeed,
    // others will fail as if those timelines had been stopped for whatever reason.
    #[cfg(feature = "testing")]
    let failpoint_sem = || -> Option<Arc<Semaphore>> {
        fail::fail_point!("timeline-detach-ancestor::allow_one_reparented", |_| Some(
            Arc::new(Semaphore::new(1))
        ));
        None
    }();

    // because we are now keeping the slot in progress, it is unlikely that there will be any
    // timeline deletions during this time. if we raced one, then we'll just ignore it.
    {
        let g = tenant.timelines.lock().unwrap();
        reparentable_timelines(g.values(), detached, &ancestor, ancestor_lsn)
            .cloned()
            .for_each(|timeline| {
                // important in this scope: we are holding the Tenant::timelines lock
                let span = tracing::info_span!("reparent", reparented=%timeline.timeline_id);
                let new_parent = detached.timeline_id;
                #[cfg(feature = "testing")]
                let failpoint_sem = failpoint_sem.clone();

                tasks.spawn(
                    async move {
                        let res = async {
                            #[cfg(feature = "testing")]
                            if let Some(failpoint_sem) = failpoint_sem {
                                let _permit = failpoint_sem.acquire().await.map_err(|_| {
                                    anyhow::anyhow!(
                                        "failpoint: timeline-detach-ancestor::allow_one_reparented",
                                    )
                                })?;
                                failpoint_sem.close();
                            }

                            timeline
                                .remote_client
                                .schedule_reparenting_and_wait(&new_parent)
                                .await
                        }
                        .await;

                        match res {
                            Ok(()) => {
                                tracing::info!("reparented");
                                Some(timeline)
                            }
                            Err(e) => {
                                // with the use of tenant slot, raced timeline deletion is the most
                                // likely reason.
                                tracing::warn!("reparenting failed: {e:#}");
                                None
                            }
                        }
                    }
                    .instrument(span),
                );
            });
    }

    let reparenting_candidates = tasks.len();
    let mut reparented = HashSet::with_capacity(tasks.len());

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(Some(timeline)) => {
                assert!(
                    reparented.insert(timeline.timeline_id),
                    "duplicate reparenting? timeline_id={}",
                    timeline.timeline_id
                );
            }
            Err(je) if je.is_cancelled() => unreachable!("not used"),
            // just ignore failures now, we can retry
            Ok(None) => {}
            Err(je) if je.is_panic() => {}
            Err(je) => tracing::error!("unexpected join error: {je:?}"),
        }
    }

    let reparented_all = reparenting_candidates == reparented.len();

    if reparented_all {
        Ok(DetachingAndReparenting::Reparented(reparented))
    } else {
        tracing::info!(
            reparented = reparented.len(),
            candidates = reparenting_candidates,
            "failed to reparent all candidates; they can be retried after the tenant_reset",
        );

        let must_reset_tenant = !reparented.is_empty() || was_detached;
        Ok(DetachingAndReparenting::SomeReparentingFailed { must_reset_tenant })
    }
}

pub(super) async fn complete(
    detached: &Arc<Timeline>,
    tenant: &TenantShard,
    mut attempt: Attempt,
    _ctx: &RequestContext,
) -> Result<(), Error> {
    assert_eq!(detached.timeline_id, attempt.timeline_id);

    if attempt.gate_entered.is_none() {
        let entered = detached.gate.enter().map_err(|_| Error::ShuttingDown)?;
        attempt.gate_entered = Some(entered);
    } else {
        // Some(gate_entered) means the tenant was not restarted, as is not required
    }

    assert!(detached.ancestor_timeline.is_none());

    // this should be an 503 at least...?
    fail::fail_point!(
        "timeline-detach-ancestor::complete_before_uploading",
        |_| Err(Error::Failpoint(
            "timeline-detach-ancestor::complete_before_uploading"
        ))
    );

    tenant
        .gc_block
        .remove(
            detached,
            crate::tenant::remote_timeline_client::index::GcBlockingReason::DetachAncestor,
        )
        .await
        .map_err(|e| Error::launder(e, Error::Complete))?;

    Ok(())
}

/// Query against a locked `Tenant::timelines`.
///
/// A timeline is reparentable if:
///
/// - It is not the timeline being detached.
/// - It has the same ancestor as the timeline being detached. Note that the ancestor might not be the direct ancestor.
fn reparentable_timelines<'a, I>(
    timelines: I,
    detached: &'a Arc<Timeline>,
    ancestor: &'a Arc<Timeline>,
    ancestor_lsn: Lsn,
) -> impl Iterator<Item = &'a Arc<Timeline>> + 'a
where
    I: Iterator<Item = &'a Arc<Timeline>> + 'a,
{
    timelines.filter_map(move |tl| {
        if Arc::ptr_eq(tl, detached) {
            return None;
        }

        let tl_ancestor = tl.ancestor_timeline.as_ref()?;
        let is_same = Arc::ptr_eq(ancestor, tl_ancestor);
        let is_earlier = tl.get_ancestor_lsn() <= ancestor_lsn;

        let is_deleting = tl
            .delete_progress
            .try_lock()
            .map(|flow| !flow.is_not_started())
            .unwrap_or(true);

        if is_same && is_earlier && !is_deleting {
            Some(tl)
        } else {
            None
        }
    })
}

fn check_no_archived_children_of_ancestor(
    tenant: &TenantShard,
    detached: &Arc<Timeline>,
    ancestor: &Arc<Timeline>,
    ancestor_lsn: Lsn,
    detach_behavior: DetachBehavior,
) -> Result<(), Error> {
    match detach_behavior {
        DetachBehavior::NoAncestorAndReparent => {
            let timelines = tenant.timelines.lock().unwrap();
            let timelines_offloaded = tenant.timelines_offloaded.lock().unwrap();

            for timeline in
                reparentable_timelines(timelines.values(), detached, ancestor, ancestor_lsn)
            {
                if timeline.is_archived() == Some(true) {
                    return Err(Error::Archived(timeline.timeline_id));
                }
            }

            for timeline_offloaded in timelines_offloaded.values() {
                if timeline_offloaded.ancestor_timeline_id != Some(ancestor.timeline_id) {
                    continue;
                }
                // This forbids the detach ancestor feature if flattened timelines are present,
                // even if the ancestor_lsn is from after the branchpoint of the detached timeline.
                // But as per current design, we don't record the ancestor_lsn of flattened timelines.
                // This is a bit unfortunate, but as of writing this we don't support flattening
                // anyway. Maybe we can evolve the data model in the future.
                if let Some(retain_lsn) = timeline_offloaded.ancestor_retain_lsn {
                    let is_earlier = retain_lsn <= ancestor_lsn;
                    if !is_earlier {
                        continue;
                    }
                }
                return Err(Error::Archived(timeline_offloaded.timeline_id));
            }
        }
        DetachBehavior::MultiLevelAndNoReparent => {
            // We don't need to check anything if the user requested to not reparent.
        }
    }

    Ok(())
}

async fn fsync_timeline_dir(timeline: &Timeline, ctx: &RequestContext) {
    let path = &timeline
        .conf
        .timeline_path(&timeline.tenant_shard_id, &timeline.timeline_id);
    let timeline_dir = VirtualFile::open(&path, ctx)
        .await
        .fatal_err("VirtualFile::open for timeline dir fsync");
    timeline_dir
        .sync_all()
        .await
        .fatal_err("VirtualFile::sync_all timeline dir");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pageserver_api::models::TimelineState;

    use super::*;

    /// `child -> (ancestor, ancestor_lsn)` for a toy timeline tree.
    fn tree(
        edges: &[(&'static str, &'static str, u64)],
    ) -> HashMap<&'static str, (&'static str, Lsn)> {
        edges
            .iter()
            .map(|(child, ancestor, lsn)| (*child, (*ancestor, Lsn(*lsn))))
            .collect()
    }

    fn chain(
        tree: &HashMap<&'static str, (&'static str, Lsn)>,
        detached: &'static str,
        behavior: DetachBehavior,
    ) -> Result<Vec<(&'static str, Lsn)>, Error> {
        detach_chain(tree[detached], |tl| tree.get(tl).copied(), behavior)
    }

    #[test]
    fn detach_chain_single_level() {
        let tree = tree(&[("child", "root", 10)]);
        for behavior in [
            DetachBehavior::NoAncestorAndReparent,
            DetachBehavior::MultiLevelAndNoReparent,
        ] {
            let levels = chain(&tree, "child", behavior).unwrap();
            assert_eq!(levels, vec![("root", Lsn(10))], "{behavior:?}");
        }
    }

    #[test]
    fn detach_chain_multi_level_cuts() {
        let tree = tree(&[
            ("child", "parent", 30),
            ("parent", "grandparent", 20),
            ("grandparent", "root", 20),
        ]);
        let levels = chain(&tree, "child", DetachBehavior::MultiLevelAndNoReparent).unwrap();
        assert_eq!(
            levels,
            vec![
                ("parent", Lsn(30)),
                ("grandparent", Lsn(20)),
                ("root", Lsn(20)),
            ]
        );
    }

    #[test]
    fn detach_chain_default_behavior_refuses_depth_two() {
        let tree = tree(&[("child", "parent", 30), ("parent", "root", 20)]);
        let err = chain(&tree, "child", DetachBehavior::NoAncestorAndReparent).unwrap_err();
        assert!(matches!(err, Error::TooManyAncestors), "{err:?}");
    }

    #[test]
    fn layer_name_collision_detected() {
        let mut seen = HashSet::new();
        check_layer_name_unique(&mut seen, "a").unwrap();
        check_layer_name_unique(&mut seen, "b").unwrap();
        let err = check_layer_name_unique(&mut seen, "a").unwrap_err();
        assert!(
            matches!(&err, Error::LayerNameCollision { layer } if layer == "a"),
            "{err:?}"
        );
        assert!(matches!(
            ApiError::from(err),
            ApiError::InternalServerError(_)
        ));
    }

    #[test]
    fn ancestor_lsn_timeout_maps_to_503() {
        let ancestor = TimelineId::generate();
        for e in [
            WaitLsnError::Timeout("timed out".to_string()),
            WaitLsnError::BadState(TimelineState::Loading),
        ] {
            let err = ancestor_wait_error(e, ancestor, Lsn(42));
            assert!(
                matches!(err, Error::AncestorLsnTimeout { ancestor: a, lsn } if a == ancestor && lsn == Lsn(42)),
                "{err:?}"
            );
            assert!(
                matches!(ApiError::from(err), ApiError::ResourceUnavailable(_)),
                "must be a retryable 503"
            );
        }
    }

    #[test]
    fn broken_ancestor_maps_to_500() {
        let ancestor = TimelineId::generate();
        let e = WaitLsnError::BadState(TimelineState::Broken {
            reason: "disk on fire".to_string(),
            backtrace: String::new(),
        });
        let err = ancestor_wait_error(e, ancestor, Lsn(42));
        assert!(
            matches!(&err, Error::AncestorBroken { ancestor: a, reason } if *a == ancestor && reason == "disk on fire"),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("broken") && !msg.contains("retry"),
            "must not read as retryable: {msg}"
        );
        assert!(
            matches!(ApiError::from(err), ApiError::InternalServerError(_)),
            "a broken ancestor must not be a retryable 503"
        );
    }

    #[test]
    fn wait_lsn_cancel_maps_to_shutting_down() {
        let ancestor = TimelineId::generate();
        for e in [
            WaitLsnError::Shutdown,
            WaitLsnError::BadState(TimelineState::Stopping),
        ] {
            let err = ancestor_wait_error(e, ancestor, Lsn(42));
            assert!(matches!(err, Error::ShuttingDown), "{err:?}");
        }
    }
}
