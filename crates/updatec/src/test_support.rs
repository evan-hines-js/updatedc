use updated_contracts::reconciler::{
    HostAction, LastReconciliation, MutationOperation, Reason, ReconciledRelease,
    ReconcilerIdentity, ReconciliationTransition, SuccessfulMutation,
};
use updated_contracts::telemetry::{Envelope, NodeReport};

const MANIFEST_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(crate) fn bind_reconciliation(report: &mut NodeReport) {
    if report.version.is_empty() {
        report.reconciliation = None;
        return;
    }
    let running = ReconciledRelease::new(
        report.version.clone(),
        MANIFEST_SHA256.into(),
        report.archive_sha256.clone(),
    )
    .unwrap();
    let transition = ReconciliationTransition::new(running.clone(), running);
    let reconciler_release = ReconciledRelease::new(
        "1.0.0".into(),
        MANIFEST_SHA256.into(),
        MANIFEST_SHA256.into(),
    )
    .unwrap();
    report.reconciliation = Some(
        LastReconciliation::new(
            MutationOperation::Apply,
            Reason::Restart,
            updated_contracts::reconciler::attempt::CONVERGE.into(),
            transition,
            ReconcilerIdentity::new(
                report.provider_set_sha256.clone(),
                "system".into(),
                reconciler_release,
            )
            .unwrap(),
            SuccessfulMutation::new(false, HostAction::None, None).unwrap(),
            1,
        )
        .unwrap(),
    );
}

pub(crate) fn sign_report(report: &mut NodeReport, key: &[u8]) -> Envelope {
    bind_reconciliation(report);
    let body = updated_contracts::telemetry::encode_signed_report(report, key).unwrap();
    serde_json::from_slice(&body).unwrap()
}
