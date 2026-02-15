pub fn normalize_participant_ids(ids: Option<&Vec<u16>>) -> Vec<u16> {
    signer_platform_web::near_threshold_ed25519::normalize_participant_ids(ids)
}

pub fn validate_threshold_ed25519_participant_ids_2p(
    client_id_opt: Option<u16>,
    relayer_id_opt: Option<u16>,
    participant_ids_norm: &[u16],
) -> Result<(u16, u16), String> {
    signer_platform_web::near_threshold_ed25519::validate_threshold_ed25519_participant_ids_2p(
        client_id_opt,
        relayer_id_opt,
        participant_ids_norm,
    )
    .map_err(|e| e.to_string())
}
