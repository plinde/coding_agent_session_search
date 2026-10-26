//! CASS adapter for `franken_agent_detection::connectors::pi_agent`.
//!
//! FAD owns parsing and discovery. This adapter enforces CASS's first-class
//! OMP identity boundary when a broad copied-home or remote-mirror root makes
//! Pi's permissive explicit-root detection walk into an OMP store.

use std::cell::RefCell;
use std::collections::HashSet;

use anyhow::Result;
use franken_agent_detection::connectors::{SourceCompletion, SourceScanHooks};

use super::{
    Connector, DetectionResult, DiscoveredSourceFile, NormalizedConversation, ScanContext,
};

pub struct PiAgentConnector {
    inner: franken_agent_detection::PiAgentConnector,
}

impl Default for PiAgentConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiAgentConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: franken_agent_detection::PiAgentConnector::new(),
        }
    }

    /// Pi stores under this scan's roots that the connector does not read,
    /// without stores the Pi-family ownership policy assigns to OMP.
    #[must_use]
    pub fn unsupported_store_diagnostics(
        &self,
        ctx: &ScanContext,
    ) -> Vec<franken_agent_detection::connectors::pi_agent::UnsupportedPiStore> {
        let ownership = super::omp::PiFamilyOwnership::live();
        let mut stores = self.inner.unsupported_store_diagnostics(ctx);
        stores.retain(|store| ownership.owner(&store.path) != super::omp::PiFamilyOwner::Omp);
        stores
    }
}

impl Connector for PiAgentConnector {
    fn detect(&self) -> DetectionResult {
        let ownership = super::omp::PiFamilyOwnership::live();
        let mut detection = self.inner.detect();
        detection
            .root_paths
            .retain(|root| ownership.owner(root) == super::omp::PiFamilyOwner::PiAgent);
        for root in ownership.pi_detection_roots() {
            let canonical = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
            let already_reported = detection.root_paths.iter().any(|existing| {
                std::fs::canonicalize(existing).unwrap_or_else(|_| existing.clone()) == canonical
            });
            if !already_reported {
                detection.evidence.push(format!(
                    "CASS Pi-family ownership policy found Pi Agent root: {}",
                    root.display()
                ));
                detection.root_paths.push(root);
            }
        }
        detection.detected = !detection.root_paths.is_empty();
        detection
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        self.scan_with_source_boundaries(
            ctx,
            &mut SourceScanHooks::default(),
            &mut |conversation| {
                conversations.push(conversation);
                Ok(())
            },
        )?;
        Ok(conversations)
    }

    // FAD's Pi reader reports per-source boundaries; forward them so the
    // indexer's source ledger can skip unchanged sessions. Without this the
    // indexer fell back to a plain scan, and since remote mirror roots are
    // always scanned without a `since_ts` cutoff, every `cass index` re-parsed
    // and re-ingested every Pi session synced from every remote source.
    fn supports_source_boundaries(&self) -> bool {
        true
    }

    fn scan_with_source_boundaries(
        &self,
        ctx: &ScanContext,
        hooks: &mut SourceScanHooks<'_>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        let ownership = super::omp::PiFamilyOwnership::live();
        let hooks = RefCell::new(hooks);
        // FAD's roots and the direct-root fallback can reach the same file.
        // Each source is offered to the host at most once, so the fallback
        // never re-admits a source the host already declined as unchanged.
        let considered = RefCell::new(HashSet::new());
        let mut should_scan = |source: &DiscoveredSourceFile| {
            let key = std::fs::canonicalize(&source.source_path)
                .unwrap_or_else(|_| source.source_path.clone());
            considered.borrow_mut().insert(key)
                && ownership.owner(&source.source_path) != super::omp::PiFamilyOwner::Omp
                && hooks.borrow_mut().should_scan(source)
        };
        let mut complete = |completion: &SourceCompletion| hooks.borrow_mut().complete(completion);
        let mut boundaries = SourceScanHooks {
            should_scan_source: Some(&mut should_scan),
            on_source_complete: Some(&mut complete),
        };
        let mut deliver = |mut conversation: NormalizedConversation| {
            if ownership.owner(&conversation.source_path) == super::omp::PiFamilyOwner::Omp {
                return Ok(());
            }
            super::omp::promote_transcript_session_ids(std::slice::from_mut(&mut conversation));
            on_conversation(conversation)
        };

        self.inner
            .scan_with_source_boundaries(ctx, &mut boundaries, &mut deliver)?;

        if !ctx.use_default_detection() {
            let direct_roots = ctx
                .scan_roots
                .iter()
                .filter(|root| ownership.owner(&root.path) == super::omp::PiFamilyOwner::PiAgent)
                .map(|root| (root.clone(), None))
                .collect::<Vec<_>>();
            if !direct_roots.is_empty() {
                franken_agent_detection::connectors::pi_wire::scan_roots_with_boundaries(
                    &direct_roots,
                    ctx,
                    "pi_agent",
                    &mut boundaries,
                    &mut deliver,
                )?;
            }
        }
        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let ownership = super::omp::PiFamilyOwnership::live();
        let mut sources = self.inner.discover_source_files(ctx)?;

        if !ctx.use_default_detection() {
            let direct_roots = ctx
                .scan_roots
                .iter()
                .filter(|root| ownership.owner(&root.path) == super::omp::PiFamilyOwner::PiAgent)
                .cloned()
                .collect::<Vec<_>>();
            if !direct_roots.is_empty() {
                let fallback = franken_agent_detection::connectors::pi_wire::discover_sources(
                    &direct_roots,
                    ctx,
                    "pi_agent",
                );
                super::omp::append_missing_sources(&mut sources, fallback);
            }
        }

        sources.retain(|source| {
            ownership.owner(&source.source_path) != super::omp::PiFamilyOwner::Omp
        });
        Ok(sources)
    }
}
