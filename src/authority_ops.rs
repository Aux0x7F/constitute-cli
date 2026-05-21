use anyhow::Result;
use constitute_protocol::{
    AGREEMENT_PLANE_ACCESS_AUTHORITY, AGREEMENT_PLANE_ACTION_AUTHORITY,
    AGREEMENT_PLANE_DELIVERY_WITNESS, AUTHORITY_PROOF_CHECK_READ,
    AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE, AUTHORITY_PROOF_CHECK_SYNC,
    AUTHORITY_PROOF_CHECK_WRITE_REDUCE, AUTHORITY_PROOF_STATE_PROVED,
    AuthorityMultiIdentityProofRecord, AuthorityProofCheck, RECORD_AUTHORITY_MULTI_IDENTITY_PROOF,
    validate_authority_multi_identity_proof,
};
use serde_json::json;

use crate::cli::AuthorityProofArgs;
use crate::protocol_ops::now_unix;

pub fn build_authority_proof(
    args: &AuthorityProofArgs,
) -> Result<AuthorityMultiIdentityProofRecord> {
    let issued_at = now_unix();
    let expires_at = issued_at.saturating_add(args.expires_secs);
    let subject_refs = defaulted(
        &args.subject_refs,
        &[
            "contract:gateway.default",
            "contract:logging.default",
            "contract:nvr.streams",
            "contract:storage.default",
            "contract:source.default",
            "contract:build.default",
            "app:constitute-cybersec",
        ],
    );
    let action_grant_refs = defaulted(
        &args.action_grant_refs,
        &[
            "grant:gateway:agent-full-access",
            "grant:logging:agent-writer",
            "grant:nvr:agent-preview",
            "grant:storage:agent-pin",
            "grant:source:agent-update",
            "grant:build:agent-run",
        ],
    );
    let access_group_refs = defaulted(
        &args.access_group_refs,
        &[
            "access-group:identity:aux:cybersec-events",
            "access-group:identity:aux:source-build",
        ],
    );
    let access_epoch_refs = defaulted(
        &args.access_epoch_refs,
        &[
            "access-epoch:identity:aux:cybersec-events:current",
            "access-epoch:identity:aux:source-build:current",
        ],
    );
    let private_envelope_refs = defaulted(
        &args.private_envelope_refs,
        &[
            "private-envelope:logging-event:sample",
            "private-envelope:source-build:sample",
        ],
    );
    let revocation_refs = defaulted(
        &args.revocation_refs,
        &["revocation:grant:agent-full-access"],
    );
    let evidence_refs = defaulted(&args.evidence_refs, &["proof:multi-identity:agent-dev"]);
    let first_action_grant = action_grant_refs
        .first()
        .cloned()
        .unwrap_or_else(|| "grant:gateway:agent-full-access".to_string());
    let proof = AuthorityMultiIdentityProofRecord {
        kind: Some(RECORD_AUTHORITY_MULTI_IDENTITY_PROOF.to_string()),
        proof_id: format!(
            "authority-proof:{}-to-{}:full-access",
            sanitize_ref(&args.owner_identity_ref),
            sanitize_ref(&args.grantee_identity_ref)
        ),
        owner_identity_ref: args.owner_identity_ref.clone(),
        grantee_identity_ref: args.grantee_identity_ref.clone(),
        grantee_member_ref: args.grantee_member_ref.clone(),
        subject_refs,
        action_grant_refs: action_grant_refs.clone(),
        access_group_refs: access_group_refs.clone(),
        access_epoch_refs: access_epoch_refs.clone(),
        private_envelope_refs,
        revocation_refs: revocation_refs.clone(),
        checks: vec![
            AuthorityProofCheck {
                check: AUTHORITY_PROOF_CHECK_SYNC.to_string(),
                plane: AGREEMENT_PLANE_DELIVERY_WITNESS.to_string(),
                state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                target_ref: "contract:gateway.default".to_string(),
                grant_refs: vec![first_action_grant.clone()],
                access_group_refs: vec![],
                access_epoch_refs: vec![],
                exercise_refs: vec![],
                evidence_refs: vec!["witness:gateway:agent-sync".to_string()],
                blocked_reason: None,
                expires_at: None,
            },
            AuthorityProofCheck {
                check: AUTHORITY_PROOF_CHECK_READ.to_string(),
                plane: AGREEMENT_PLANE_ACCESS_AUTHORITY.to_string(),
                state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                target_ref: "event-fabric:logging.default".to_string(),
                grant_refs: vec![],
                access_group_refs: access_group_refs.clone(),
                access_epoch_refs: access_epoch_refs.clone(),
                exercise_refs: vec![],
                evidence_refs: vec!["proof:caac-open:agent-dev".to_string()],
                blocked_reason: None,
                expires_at: None,
            },
            AuthorityProofCheck {
                check: AUTHORITY_PROOF_CHECK_WRITE_REDUCE.to_string(),
                plane: AGREEMENT_PLANE_ACTION_AUTHORITY.to_string(),
                state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                target_ref: "contract:logging.default".to_string(),
                grant_refs: action_grant_refs.clone(),
                access_group_refs: vec![],
                access_epoch_refs: vec![],
                exercise_refs: action_grant_refs
                    .iter()
                    .map(|grant| format!("exercise:{grant}:proof"))
                    .collect(),
                evidence_refs: vec!["event:logging:agent-test".to_string()],
                blocked_reason: None,
                expires_at: None,
            },
            AuthorityProofCheck {
                check: AUTHORITY_PROOF_CHECK_REVOKE_EXPIRE.to_string(),
                plane: AGREEMENT_PLANE_ACTION_AUTHORITY.to_string(),
                state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
                target_ref: first_action_grant.clone(),
                grant_refs: vec![first_action_grant],
                access_group_refs: vec![],
                access_epoch_refs: vec![],
                exercise_refs: vec![],
                evidence_refs: revocation_refs.clone(),
                blocked_reason: None,
                expires_at: Some(expires_at),
            },
        ],
        state: AUTHORITY_PROOF_STATE_PROVED.to_string(),
        blocked_reasons: vec![],
        evidence_refs,
        safe_facts: json!({
            "proofClass": "multiIdentityFullAccess",
            "owner": args.owner_identity_ref,
            "grantee": args.grantee_identity_ref,
            "granteeMember": args.grantee_member_ref,
        }),
        issued_at,
        expires_at: Some(expires_at),
    };
    validate_authority_multi_identity_proof(&proof)?;
    Ok(proof)
}

fn defaulted(values: &[String], defaults: &[&str]) -> Vec<String> {
    if values.is_empty() {
        defaults.iter().map(|value| value.to_string()).collect()
    } else {
        values
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect()
    }
}

fn sanitize_ref(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}
