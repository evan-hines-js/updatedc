use updated_contracts::reconciler::{
    HostAction, LastReconciliation, Operation, Reason, ReconciledRelease, ReconcilerIdentity,
    ResultDocument, ResultStatus,
};
use updated_contracts::telemetry::{Envelope, NodeReport};

const MANIFEST_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(crate) fn bind_reconciliation(report: &mut NodeReport) {
    if report.version.is_empty() {
        report.reconciliation = None;
        return;
    }
    let running = ReconciledRelease {
        version: report.version.clone(),
        manifest_sha256: MANIFEST_SHA256.into(),
        archive_sha256: report.archive_sha256.clone(),
    };
    report.reconciliation = Some(LastReconciliation {
        schema: LastReconciliation::SCHEMA,
        operation: Operation::Apply,
        reason: Reason::Restart,
        attempt_id: updated_contracts::reconciler::attempt::CONVERGE.into(),
        candidate: running.clone(),
        predecessor: running,
        reconciler: ReconcilerIdentity {
            provider_set_sha256: report.provider_set_sha256.clone(),
            product: "system".into(),
            release: ReconciledRelease {
                version: "1.0.0".into(),
                manifest_sha256: MANIFEST_SHA256.into(),
                archive_sha256: MANIFEST_SHA256.into(),
            },
        },
        result: ResultDocument {
            schema: ResultDocument::SCHEMA,
            status: ResultStatus::Succeeded,
            changed: false,
            host_action: HostAction::None,
            retry_after_seconds: None,
            message: None,
        },
        completed_at_ms: 1,
    });
}

pub(crate) fn sign_report(report: &mut NodeReport, key: &[u8]) -> Envelope {
    bind_reconciliation(report);
    updated_contracts::telemetry::sign_report(report, key).unwrap()
}
