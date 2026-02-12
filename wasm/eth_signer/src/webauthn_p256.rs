use wasm_bindgen::prelude::*;

use crate::errors::js_err;

const WEBAUTHN_TYPE_ID: u8 = 0x02;
const BASE64URL_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode_no_pad(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    let mut i = 0usize;
    while i + 3 <= bytes.len() {
        let n =
            ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
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
                // Keep unicode escapes unsupported for this constrained parser.
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

fn read_der_length(der: &[u8], offset: usize) -> Result<(usize, usize), String> {
    let first = *der
        .get(offset)
        .ok_or_else(|| "DER truncated while reading length".to_string())?;
    if (first & 0x80) == 0 {
        return Ok((first as usize, offset + 1));
    }

    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err("DER invalid length prefix".to_string());
    }
    if offset + 1 + n > der.len() {
        return Err("DER truncated while reading long length".to_string());
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

fn pad32(bytes: &[u8], field_name: &str) -> Result<[u8; 32], String> {
    if bytes.is_empty() {
        return Err(format!("{field_name} must not be empty"));
    }
    if bytes.len() > 32 {
        return Err(format!("{field_name} is longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn parse_der_ecdsa_signature_p256(der: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let mut o = 0usize;
    if *der
        .get(o)
        .ok_or_else(|| "DER truncated".to_string())?
        != 0x30
    {
        return Err("DER signature must start with SEQUENCE (0x30)".to_string());
    }
    o += 1;

    let (seq_len, next_after_seq_len) = read_der_length(der, o)?;
    o = next_after_seq_len;
    let seq_end = o
        .checked_add(seq_len)
        .ok_or_else(|| "DER sequence length overflow".to_string())?;
    if seq_end != der.len() {
        return Err("DER sequence length mismatch".to_string());
    }

    if *der
        .get(o)
        .ok_or_else(|| "DER truncated before INTEGER(r)".to_string())?
        != 0x02
    {
        return Err("DER signature missing INTEGER(r)".to_string());
    }
    o += 1;
    let (r_len, next_after_r_len) = read_der_length(der, o)?;
    o = next_after_r_len;
    let r_end = o
        .checked_add(r_len)
        .ok_or_else(|| "DER INTEGER(r) length overflow".to_string())?;
    if r_end > der.len() {
        return Err("DER truncated in INTEGER(r)".to_string());
    }
    let r_bytes = &der[o..r_end];
    o = r_end;

    if *der
        .get(o)
        .ok_or_else(|| "DER truncated before INTEGER(s)".to_string())?
        != 0x02
    {
        return Err("DER signature missing INTEGER(s)".to_string());
    }
    o += 1;
    let (s_len, next_after_s_len) = read_der_length(der, o)?;
    o = next_after_s_len;
    let s_end = o
        .checked_add(s_len)
        .ok_or_else(|| "DER INTEGER(s) length overflow".to_string())?;
    if s_end > der.len() {
        return Err("DER truncated in INTEGER(s)".to_string());
    }
    let s_bytes = &der[o..s_end];
    o = s_end;

    if o != seq_end {
        return Err("DER signature has trailing bytes".to_string());
    }

    let r = strip_der_int_leading_zeros(r_bytes);
    let s = strip_der_int_leading_zeros(s_bytes);
    Ok((pad32(r, "DER INTEGER(r)")?, pad32(s, "DER INTEGER(s)")?))
}

fn build_webauthn_p256_signature_core(
    challenge32: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
    pub_key_x32: Vec<u8>,
    pub_key_y32: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if challenge32.len() != 32 {
        return Err(format!(
            "challenge32 must be 32 bytes (got {})",
            challenge32.len()
        ));
    }
    if authenticator_data.is_empty() {
        return Err("authenticator_data must be non-empty".to_string());
    }
    if client_data_json.is_empty() {
        return Err("client_data_json must be non-empty".to_string());
    }
    if signature_der.is_empty() {
        return Err("signature_der must be non-empty".to_string());
    }
    if pub_key_x32.len() != 32 {
        return Err(format!(
            "pub_key_x32 must be 32 bytes (got {})",
            pub_key_x32.len()
        ));
    }
    if pub_key_y32.len() != 32 {
        return Err(format!(
            "pub_key_y32 must be 32 bytes (got {})",
            pub_key_y32.len()
        ));
    }

    let client_data_str = std::str::from_utf8(&client_data_json)
        .map_err(|_| "client_data_json is not valid UTF-8".to_string())?;
    let client_data_type = extract_json_string_value(client_data_str, "type")
        .ok_or_else(|| "client_data_json.type is missing".to_string())?;
    if client_data_type != "webauthn.get" {
        return Err("client_data_json.type must be webauthn.get".to_string());
    }

    let challenge = extract_json_string_value(client_data_str, "challenge")
        .ok_or_else(|| "client_data_json.challenge is missing".to_string())?;
    let expected_challenge = base64url_encode_no_pad(&challenge32);
    if challenge != expected_challenge {
        return Err("client_data_json.challenge mismatch".to_string());
    }

    let (r32, s32) = parse_der_ecdsa_signature_p256(&signature_der)?;
    let mut out = Vec::with_capacity(1 + authenticator_data.len() + client_data_json.len() + 32 + 32 + 32 + 32);
    out.push(WEBAUTHN_TYPE_ID);
    out.extend_from_slice(&authenticator_data);
    out.extend_from_slice(&client_data_json);
    out.extend_from_slice(&r32);
    out.extend_from_slice(&s32);
    out.extend_from_slice(&pub_key_x32);
    out.extend_from_slice(&pub_key_y32);
    Ok(out)
}

pub fn build_webauthn_p256_signature(
    challenge32: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature_der: Vec<u8>,
    pub_key_x32: Vec<u8>,
    pub_key_y32: Vec<u8>,
) -> Result<Vec<u8>, JsValue> {
    build_webauthn_p256_signature_core(
        challenge32,
        authenticator_data,
        client_data_json,
        signature_der,
        pub_key_x32,
        pub_key_y32,
    )
    .map_err(js_err)
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
        let signature_der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]; // r=1,s=2
        let pub_key_x32 = vec![0x11u8; 32];
        let pub_key_y32 = vec![0x22u8; 32];

        let out = build_webauthn_p256_signature_core(
            challenge32,
            authenticator_data.clone(),
            client_data_json.clone(),
            signature_der,
            pub_key_x32.clone(),
            pub_key_y32.clone(),
        )
        .expect("expected valid packed signature");

        assert_eq!(out[0], WEBAUTHN_TYPE_ID);
        assert_eq!(&out[1..1 + authenticator_data.len()], authenticator_data.as_slice());
        assert_eq!(
            &out[1 + authenticator_data.len()..1 + authenticator_data.len() + client_data_json.len()],
            client_data_json.as_slice()
        );
        assert_eq!(out.len(), 1 + authenticator_data.len() + client_data_json.len() + 128);
        assert_eq!(out[out.len() - 128 + 31], 1);
        assert_eq!(out[out.len() - 96 + 31], 2);
        assert!(out[out.len() - 64..out.len() - 32]
            .iter()
            .all(|b| *b == 0x11));
        assert!(out[out.len() - 32..].iter().all(|b| *b == 0x22));
    }

    #[test]
    fn rejects_challenge_mismatch() {
        let challenge32 = vec![7u8; 32];
        let wrong_challenge = base64url_encode_no_pad(vec![8u8; 32].as_slice());
        let err = build_webauthn_p256_signature_core(
            challenge32,
            vec![9u8, 9u8, 9u8, 9u8],
            build_client_data(&wrong_challenge),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            vec![0x11u8; 32],
            vec![0x22u8; 32],
        )
        .expect_err("expected challenge mismatch");

        assert_eq!(err, "client_data_json.challenge mismatch");
    }

    #[test]
    fn rejects_der_with_trailing_bytes() {
        let challenge32 = vec![7u8; 32];
        let expected_challenge = base64url_encode_no_pad(&challenge32);
        let err = build_webauthn_p256_signature_core(
            challenge32,
            vec![9u8, 9u8, 9u8, 9u8],
            build_client_data(&expected_challenge),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00],
            vec![0x11u8; 32],
            vec![0x22u8; 32],
        )
        .expect_err("expected DER trailing bytes rejection");

        assert_eq!(err, "DER sequence length mismatch");
    }

    #[test]
    fn rejects_der_integer_longer_than_32_bytes() {
        let challenge32 = vec![7u8; 32];
        let expected_challenge = base64url_encode_no_pad(&challenge32);
        let mut der = vec![0x30, 0x26, 0x02, 0x21];
        der.extend_from_slice(&[0x01u8; 33]); // r = 33 bytes (invalid for 32-byte padded scalar)
        der.extend_from_slice(&[0x02, 0x01, 0x01]); // s = 1

        let err = build_webauthn_p256_signature_core(
            challenge32,
            vec![9u8, 9u8, 9u8, 9u8],
            build_client_data(&expected_challenge),
            der,
            vec![0x11u8; 32],
            vec![0x22u8; 32],
        )
        .expect_err("expected DER INTEGER length rejection");

        assert_eq!(err, "DER INTEGER(r) is longer than 32 bytes");
    }
}
