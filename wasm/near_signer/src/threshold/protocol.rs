use std::collections::BTreeMap;

pub(super) type CommitmentsWire = signer_platform_web::near_threshold_ed25519::CommitmentsWire;
pub(super) type ClientRound1State = signer_platform_web::near_threshold_ed25519::ClientRound1State;

pub(super) fn base64_url_encode(input: &[u8]) -> String {
    signer_platform_web::near_threshold_ed25519::base64_url_encode(input)
}

pub(super) fn client_round1_commit(
    key_package: &frost_ed25519::keys::KeyPackage,
) -> Result<ClientRound1State, String> {
    signer_platform_web::near_threshold_ed25519::client_round1_commit(key_package)
        .map_err(|e| e.to_string())
}

pub(super) fn commitments_from_wire(
    wire: &CommitmentsWire,
) -> Result<frost_ed25519::round1::SigningCommitments, String> {
    signer_platform_web::near_threshold_ed25519::commitments_from_wire(wire)
        .map_err(|e| e.to_string())
}

pub(super) fn build_signing_package(
    message: &[u8],
    commitments_by_id: BTreeMap<
        frost_ed25519::Identifier,
        frost_ed25519::round1::SigningCommitments,
    >,
) -> frost_ed25519::SigningPackage {
    signer_platform_web::near_threshold_ed25519::build_signing_package(message, commitments_by_id)
}

pub(super) fn client_round2_signature_share(
    signing_package: &frost_ed25519::SigningPackage,
    nonces: &frost_ed25519::round1::SigningNonces,
    key_package: &frost_ed25519::keys::KeyPackage,
) -> Result<frost_ed25519::round2::SignatureShare, String> {
    signer_platform_web::near_threshold_ed25519::client_round2_signature_share(
        signing_package,
        nonces,
        key_package,
    )
    .map_err(|e| e.to_string())
}

pub(super) fn signature_share_to_b64u(
    share: &frost_ed25519::round2::SignatureShare,
) -> Result<String, String> {
    signer_platform_web::near_threshold_ed25519::signature_share_to_b64u(share)
        .map_err(|e| e.to_string())
}

pub(super) fn signature_share_from_b64u(
    b64u: &str,
) -> Result<frost_ed25519::round2::SignatureShare, String> {
    signer_platform_web::near_threshold_ed25519::signature_share_from_b64u(b64u)
        .map_err(|e| e.to_string())
}

pub(super) fn verifying_share_from_b64u(
    b64u: &str,
) -> Result<frost_ed25519::keys::VerifyingShare, String> {
    signer_platform_web::near_threshold_ed25519::verifying_share_from_b64u(b64u)
        .map_err(|e| e.to_string())
}

pub(super) fn aggregate_signature(
    signing_package: &frost_ed25519::SigningPackage,
    verifying_key: frost_ed25519::VerifyingKey,
    verifying_shares: BTreeMap<frost_ed25519::Identifier, frost_ed25519::keys::VerifyingShare>,
    signature_shares: BTreeMap<frost_ed25519::Identifier, frost_ed25519::round2::SignatureShare>,
) -> Result<[u8; 64], String> {
    signer_platform_web::near_threshold_ed25519::aggregate_signature(
        signing_package,
        verifying_key,
        verifying_shares,
        signature_shares,
    )
    .map_err(|e| e.to_string())
}
