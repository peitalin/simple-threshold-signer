use crate::error::{CoreResult, SignerCoreError};

pub const WEBAUTHN_TYPE_ID: u8 = 0x02;
const BASE64URL_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode_no_pad(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(BASE64URL_TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(BASE64URL_TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(BASE64URL_TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(BASE64URL_TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match bytes.len().saturating_sub(i) {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(BASE64URL_TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(BASE64URL_TABLE[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(BASE64URL_TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(BASE64URL_TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(BASE64URL_TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

fn extract_json_string_value(input: &str, key: &str) -> Option<String> {
    let key_pattern = format!("\"{key}\"");
    let key_start = input.find(&key_pattern)?;
    let after_key = &input[key_start + key_pattern.len()..];
    let colon_rel = after_key.find(':')?;
    let mut rest = &after_key[colon_rel + 1..];
    rest = rest.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for ch in rest[1..].chars() {
        if escaped {
            out.push(match ch {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{0008}',
                'f' => '\u{000C}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                _ => return None,
            });
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            return Some(out);
        }
        out.push(ch);
    }
    None
}

fn read_der_length(der: &[u8], offset: usize) -> CoreResult<(usize, usize)> {
    let first = *der
        .get(offset)
        .ok_or_else(|| SignerCoreError::decode_error("DER truncated while reading length"))?;
    if (first & 0x80) == 0 {
        return Ok((first as usize, offset + 1));
    }

    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(SignerCoreError::decode_error("DER invalid length prefix"));
    }
    if offset + 1 + n > der.len() {
        return Err(SignerCoreError::decode_error(
            "DER truncated while reading long length",
        ));
    }

    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | der[offset + 1 + i] as usize;
    }
    Ok((len, offset + 1 + n))
}

fn strip_der_int_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut i = 0usize;
    while i + 1 < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

fn pad32(bytes: &[u8], field_name: &str) -> CoreResult<[u8; 32]> {
    if bytes.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must not be empty",
        )));
    }
    if bytes.len() > 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} is longer than 32 bytes",
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn parse_der_ecdsa_signature_p256(der: &[u8]) -> CoreResult<([u8; 32], [u8; 32])> {
    let mut o = 0usize;
    if *der
        .get(o)
        .ok_or_else(|| SignerCoreError::decode_error("DER truncated"))?
        != 0x30
    {
        return Err(SignerCoreError::decode_error(
            "DER signature must start with SEQUENCE (0x30)",
        ));
    }
    o += 1;

    let (seq_len, next_after_seq_len) = read_der_length(der, o)?;
    o = next_after_seq_len;
    let seq_end = o
        .checked_add(seq_len)
        .ok_or_else(|| SignerCoreError::decode_error("DER sequence length overflow"))?;
    if seq_end != der.len() {
        return Err(SignerCoreError::decode_error(
            "DER sequence length mismatch",
        ));
    }

    if *der
        .get(o)
        .ok_or_else(|| SignerCoreError::decode_error("DER truncated before INTEGER(r)"))?
        != 0x02
    {
        return Err(SignerCoreError::decode_error(
            "DER signature missing INTEGER(r)",
        ));
    }
    o += 1;
    let (r_len, next_after_r_len) = read_der_length(der, o)?;
    o = next_after_r_len;
    let r_end = o
        .checked_add(r_len)
        .ok_or_else(|| SignerCoreError::decode_error("DER INTEGER(r) length overflow"))?;
    if r_end > der.len() {
        return Err(SignerCoreError::decode_error("DER truncated in INTEGER(r)"));
    }
    let r_bytes = &der[o..r_end];
    o = r_end;

    if *der
        .get(o)
        .ok_or_else(|| SignerCoreError::decode_error("DER truncated before INTEGER(s)"))?
        != 0x02
    {
        return Err(SignerCoreError::decode_error(
            "DER signature missing INTEGER(s)",
        ));
    }
    o += 1;
    let (s_len, next_after_s_len) = read_der_length(der, o)?;
    o = next_after_s_len;
    let s_end = o
        .checked_add(s_len)
        .ok_or_else(|| SignerCoreError::decode_error("DER INTEGER(s) length overflow"))?;
    if s_end > der.len() {
        return Err(SignerCoreError::decode_error("DER truncated in INTEGER(s)"));
    }
    let s_bytes = &der[o..s_end];
    o = s_end;

    if o != seq_end {
        return Err(SignerCoreError::decode_error(
            "DER signature has trailing bytes",
        ));
    }

    let r = strip_der_int_leading_zeros(r_bytes);
    let s = strip_der_int_leading_zeros(s_bytes);
    Ok((pad32(r, "DER INTEGER(r)")?, pad32(s, "DER INTEGER(s)")?))
}

pub fn build_webauthn_p256_signature(
    challenge32: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
    pub_key_x32: Vec<u8>,
    pub_key_y32: Vec<u8>,
) -> CoreResult<Vec<u8>> {
    if challenge32.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "challenge32 must be 32 bytes (got {})",
            challenge32.len()
        )));
    }
    if authenticator_data.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "authenticator_data must be non-empty",
        ));
    }
    if client_data_json.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "client_data_json must be non-empty",
        ));
    }
    if signature_der.is_empty() {
        return Err(SignerCoreError::invalid_input(
            "signature_der must be non-empty",
        ));
    }
    if pub_key_x32.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "pub_key_x32 must be 32 bytes (got {})",
            pub_key_x32.len()
        )));
    }
    if pub_key_y32.len() != 32 {
        return Err(SignerCoreError::invalid_length(format!(
            "pub_key_y32 must be 32 bytes (got {})",
            pub_key_y32.len()
        )));
    }

    let client_data_str = std::str::from_utf8(&client_data_json)
        .map_err(|_| SignerCoreError::utf8_error("client_data_json is not valid UTF-8"))?;
    let client_data_type = extract_json_string_value(client_data_str, "type")
        .ok_or_else(|| SignerCoreError::decode_error("client_data_json.type is missing"))?;
    if client_data_type != "webauthn.get" {
        return Err(SignerCoreError::invalid_input(
            "client_data_json.type must be webauthn.get",
        ));
    }

    let challenge = extract_json_string_value(client_data_str, "challenge")
        .ok_or_else(|| SignerCoreError::decode_error("client_data_json.challenge is missing"))?;
    let expected_challenge = base64url_encode_no_pad(&challenge32);
    if challenge != expected_challenge {
        return Err(SignerCoreError::invalid_input(
            "client_data_json.challenge mismatch",
        ));
    }

    let (r32, s32) = parse_der_ecdsa_signature_p256(&signature_der)?;
    let mut out = Vec::with_capacity(
        1 + authenticator_data.len() + client_data_json.len() + 32 + 32 + 32 + 32,
    );
    out.push(WEBAUTHN_TYPE_ID);
    out.extend_from_slice(&authenticator_data);
    out.extend_from_slice(&client_data_json);
    out.extend_from_slice(&r32);
    out.extend_from_slice(&s32);
    out.extend_from_slice(&pub_key_x32);
    out.extend_from_slice(&pub_key_y32);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_data(challenge_b64u: &str) -> Vec<u8> {
        format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://example.localhost\"}}",
            challenge_b64u
        )
        .into_bytes()
    }

    #[test]
    fn builds_packed_signature_for_valid_minimal_der() {
        let challenge32 = vec![7u8; 32];
        let expected_challenge = base64url_encode_no_pad(&challenge32);
        let client_data_json = build_client_data(&expected_challenge);
        let authenticator_data = vec![9u8, 9u8, 9u8, 9u8];
        let signature_der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let pub_key_x32 = vec![0x11u8; 32];
        let pub_key_y32 = vec![0x22u8; 32];

        let out = build_webauthn_p256_signature(
            challenge32,
            authenticator_data.clone(),
            client_data_json.clone(),
            signature_der,
            pub_key_x32,
            pub_key_y32,
        )
        .expect("expected valid packed signature");

        assert_eq!(out[0], WEBAUTHN_TYPE_ID);
        assert_eq!(
            &out[1..1 + authenticator_data.len()],
            authenticator_data.as_slice()
        );
        assert_eq!(
            &out[1 + authenticator_data.len()
                ..1 + authenticator_data.len() + client_data_json.len()],
            client_data_json.as_slice()
        );
        assert_eq!(
            out.len(),
            1 + authenticator_data.len() + client_data_json.len() + 128
        );
    }
}
