import Foundation

enum VectorReplayError: Error, CustomStringConvertible {
    case usage
    case utf8Failure(String)
    case ffiFailure(String)
    case shapeFailure(String)
    case mismatch(String, String, String)

    var description: String {
        switch self {
        case .usage:
            return "usage: vector-replay <vectors-v1.json path>"
        case let .utf8Failure(label):
            return "utf8 conversion failed: \(label)"
        case let .ffiFailure(label):
            return "ffi call failed: \(label)"
        case let .shapeFailure(label):
            return "unexpected value shape: \(label)"
        case let .mismatch(label, expected, actual):
            return "mismatch for \(label): expected=\(expected) actual=\(actual)"
        }
    }
}

@_silgen_name("signer_platform_ios_string_free")
func signer_platform_ios_string_free(_ ptr: UnsafeMutablePointer<CChar>?)

@_silgen_name("signer_platform_ios_v1_hex_to_bytes_hex")
func signer_platform_ios_v1_hex_to_bytes_hex(_ input: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_u256_bytes_be_from_dec_hex")
func signer_platform_ios_v1_u256_bytes_be_from_dec_hex(_ input: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_strip_leading_zeros_hex")
func signer_platform_ios_v1_strip_leading_zeros_hex(_ input: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_rlp_encode_bytes_hex")
func signer_platform_ios_v1_rlp_encode_bytes_hex(_ input: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_rlp_encode_list_hex")
func signer_platform_ios_v1_rlp_encode_list_hex(
    _ first: UnsafePointer<CChar>?,
    _ second: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_derive_threshold_secp256k1_client_share_hex")
func signer_platform_ios_v1_derive_threshold_secp256k1_client_share_hex(
    _ prfFirst32Hex: UnsafePointer<CChar>?,
    _ userId: UnsafePointer<CChar>?,
    _ derivationPath: UInt32
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_derive_secp256k1_keypair_from_prf_second_hex")
func signer_platform_ios_v1_derive_secp256k1_keypair_from_prf_second_hex(
    _ prfSecondHex: UnsafePointer<CChar>?,
    _ nearAccountId: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_map_additive_share_to_threshold_signatures_share_2p_hex")
func signer_platform_ios_v1_map_additive_share_to_threshold_signatures_share_2p_hex(
    _ additiveShare32Hex: UnsafePointer<CChar>?,
    _ participantId: UInt32
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_validate_secp256k1_public_key_33_hex")
func signer_platform_ios_v1_validate_secp256k1_public_key_33_hex(
    _ publicKey33Hex: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_add_secp256k1_public_keys_33_hex")
func signer_platform_ios_v1_add_secp256k1_public_keys_33_hex(
    _ left33Hex: UnsafePointer<CChar>?,
    _ right33Hex: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_derive_ed25519_keypair")
func signer_platform_ios_v1_derive_ed25519_keypair(
    _ prfOutputB64u: UnsafePointer<CChar>?,
    _ accountId: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_derive_kek_from_wrap_key_seed_b64u_hex")
func signer_platform_ios_v1_derive_kek_from_wrap_key_seed_b64u_hex(
    _ wrapKeySeedB64u: UnsafePointer<CChar>?,
    _ wrapKeySaltB64u: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_encrypt_data_chacha20_hex")
func signer_platform_ios_v1_encrypt_data_chacha20_hex(
    _ plainTextData: UnsafePointer<CChar>?,
    _ keyHex: UnsafePointer<CChar>?,
    _ nonceHex: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("signer_platform_ios_v1_decrypt_data_chacha20")
func signer_platform_ios_v1_decrypt_data_chacha20(
    _ encryptedHex: UnsafePointer<CChar>?,
    _ nonceHex: UnsafePointer<CChar>?,
    _ keyHex: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar>?

func withRustString(_ ptr: UnsafeMutablePointer<CChar>?, _ label: String) throws -> String {
    guard let ptr else { throw VectorReplayError.ffiFailure(label) }
    defer { signer_platform_ios_string_free(ptr) }
    return String(cString: ptr)
}

func call1(
    _ label: String,
    _ fn: (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
    _ a: String
) throws -> String {
    try a.withCString { cA in
        try withRustString(fn(cA), label)
    }
}

func call2(
    _ label: String,
    _ fn: (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
    _ a: String,
    _ b: String
) throws -> String {
    try a.withCString { cA in
        try b.withCString { cB in
            try withRustString(fn(cA, cB), label)
        }
    }
}

func call3(
    _ label: String,
    _ fn: (UnsafePointer<CChar>?, UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
    _ a: String,
    _ b: String,
    _ c: String
) throws -> String {
    try a.withCString { cA in
        try b.withCString { cB in
            try c.withCString { cC in
                try withRustString(fn(cA, cB, cC), label)
            }
        }
    }
}

func assertEqual(_ label: String, _ expected: String, _ actual: String) throws {
    if expected.lowercased() != actual.lowercased() {
        throw VectorReplayError.mismatch(label, expected, actual)
    }
}

typealias Json = [String: Any]

func loadVectors(_ path: String) throws -> Json {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    guard let root = try JSONSerialization.jsonObject(with: data, options: []) as? Json else {
        throw VectorReplayError.shapeFailure("root")
    }
    return root
}

func jsonObject(_ parent: Json, _ key: String) throws -> Json {
    guard let value = parent[key] as? Json else {
        throw VectorReplayError.shapeFailure(key)
    }
    return value
}

func jsonString(_ parent: Json, _ key: String) throws -> String {
    guard let value = parent[key] as? String else {
        throw VectorReplayError.shapeFailure(key)
    }
    return value
}

func jsonUInt32(_ parent: Json, _ key: String) throws -> UInt32 {
    if let value = parent[key] as? UInt32 {
        return value
    }
    if let value = parent[key] as? Int, value >= 0 {
        return UInt32(value)
    }
    if let value = parent[key] as? NSNumber, value.intValue >= 0 {
        return UInt32(value.intValue)
    }
    throw VectorReplayError.shapeFailure(key)
}

func jsonStringArray(_ parent: Json, _ key: String) throws -> [String] {
    guard let value = parent[key] as? [String] else {
        throw VectorReplayError.shapeFailure(key)
    }
    return value
}

func runReplay(vectors: Json) throws {
    let codec = try jsonObject(vectors, "codec")
    let codecHexCase = try jsonObject(codec, "hex_case")
    let codecU256Case = try jsonObject(codec, "u256_case")
    let codecStripCase = try jsonObject(codec, "strip_leading_zeros_case")
    let codecRlpBytesCase = try jsonObject(codec, "rlp_bytes_case")
    let codecRlpListCase = try jsonObject(codec, "rlp_list_case")

    let secp = try jsonObject(vectors, "secp256k1")
    let secpDeriveThreshold = try jsonObject(secp, "derive_threshold_client_share")
    let secpDeriveKeypair = try jsonObject(secp, "derive_keypair_from_prf_second")
    let secpMapShare = try jsonObject(secp, "map_additive_share_2p")
    let secpValidate = try jsonObject(secp, "validate_public_key_33")
    let secpAdd = try jsonObject(secp, "add_public_keys_33")

    let nearEd25519 = try jsonObject(vectors, "near_ed25519")
    let nearDerive = try jsonObject(nearEd25519, "derive_keypair")

    let nearCrypto = try jsonObject(vectors, "near_crypto")
    let nearDeriveKek = try jsonObject(nearCrypto, "derive_kek")
    let nearEncrypt = try jsonObject(nearCrypto, "encrypt_fixed_nonce")

    try assertEqual(
        "codec.hex_case",
        try jsonString(codecHexCase, "expected_hex"),
        try call1("hex_to_bytes", signer_platform_ios_v1_hex_to_bytes_hex, try jsonString(codecHexCase, "input"))
    )

    try assertEqual(
        "codec.u256_case",
        try jsonString(codecU256Case, "expected_hex"),
        try call1("u256_bytes_be_from_dec", signer_platform_ios_v1_u256_bytes_be_from_dec_hex, try jsonString(codecU256Case, "input"))
    )

    try assertEqual(
        "codec.strip_leading_zeros_case",
        try jsonString(codecStripCase, "expected_hex"),
        try call1("strip_leading_zeros", signer_platform_ios_v1_strip_leading_zeros_hex, try jsonString(codecStripCase, "input_hex"))
    )

    try assertEqual(
        "codec.rlp_bytes_case",
        try jsonString(codecRlpBytesCase, "expected_hex"),
        try call1("rlp_encode_bytes", signer_platform_ios_v1_rlp_encode_bytes_hex, try jsonString(codecRlpBytesCase, "input_hex"))
    )

    let rlpItems = try jsonStringArray(codecRlpListCase, "items_hex")
    guard rlpItems.count == 2 else {
        throw VectorReplayError.shapeFailure("codec.rlp_list_case.items_hex")
    }
    try assertEqual(
        "codec.rlp_list_case",
        try jsonString(codecRlpListCase, "expected_hex"),
        try call2(
            "rlp_encode_list",
            signer_platform_ios_v1_rlp_encode_list_hex,
            rlpItems[0],
            rlpItems[1]
        )
    )

    let secpDeriveClient = try jsonString(secpDeriveThreshold, "prf_first32_hex").withCString { prf in
        try jsonString(secpDeriveThreshold, "user_id").withCString { user in
            try withRustString(
                signer_platform_ios_v1_derive_threshold_secp256k1_client_share_hex(
                    prf,
                    user,
                    try jsonUInt32(secpDeriveThreshold, "derivation_path")
                ),
                "derive_threshold_secp256k1_client_share"
            )
        }
    }
    try assertEqual(
        "secp256k1.derive_threshold_client_share",
        try jsonString(secpDeriveThreshold, "expected_hex"),
        secpDeriveClient
    )

    try assertEqual(
        "secp256k1.derive_keypair_from_prf_second",
        try jsonString(secpDeriveKeypair, "expected_hex"),
        try call2(
            "derive_secp256k1_keypair_from_prf_second",
            signer_platform_ios_v1_derive_secp256k1_keypair_from_prf_second_hex,
            try jsonString(secpDeriveKeypair, "prf_second_hex"),
            try jsonString(secpDeriveKeypair, "near_account_id")
        )
    )

    let mappedShare = try jsonString(secpMapShare, "additive_share32_hex").withCString { share in
        try withRustString(
            signer_platform_ios_v1_map_additive_share_to_threshold_signatures_share_2p_hex(
                share,
                try jsonUInt32(secpMapShare, "participant_id")
            ),
            "map_additive_share_to_threshold_signatures_share_2p"
        )
    }
    try assertEqual(
        "secp256k1.map_additive_share_2p",
        try jsonString(secpMapShare, "expected_hex"),
        mappedShare
    )

    try assertEqual(
        "secp256k1.validate_public_key_33",
        try jsonString(secpValidate, "expected_hex"),
        try call1(
            "validate_secp256k1_public_key_33",
            signer_platform_ios_v1_validate_secp256k1_public_key_33_hex,
            try jsonString(secpValidate, "public_key33_hex")
        )
    )

    try assertEqual(
        "secp256k1.add_public_keys_33",
        try jsonString(secpAdd, "expected_hex"),
        try call2(
            "add_secp256k1_public_keys_33",
            signer_platform_ios_v1_add_secp256k1_public_keys_33_hex,
            try jsonString(secpAdd, "left33_hex"),
            try jsonString(secpAdd, "right33_hex")
        )
    )

    let ed25519Combined = try call2(
        "derive_ed25519_keypair",
        signer_platform_ios_v1_derive_ed25519_keypair,
        try jsonString(nearDerive, "prf_output_b64u"),
        try jsonString(nearDerive, "account_id")
    )
    let keypairParts = ed25519Combined.split(separator: "\n", maxSplits: 1).map(String.init)
    guard keypairParts.count == 2 else {
        throw VectorReplayError.shapeFailure("near_ed25519.derive_keypair")
    }
    try assertEqual(
        "near_ed25519.derive_keypair.private",
        try jsonString(nearDerive, "expected_private_key"),
        keypairParts[0]
    )
    try assertEqual(
        "near_ed25519.derive_keypair.public",
        try jsonString(nearDerive, "expected_public_key"),
        keypairParts[1]
    )

    try assertEqual(
        "near_crypto.derive_kek",
        try jsonString(nearDeriveKek, "expected_hex"),
        try call2(
            "derive_kek_from_wrap_key_seed_b64u",
            signer_platform_ios_v1_derive_kek_from_wrap_key_seed_b64u_hex,
            try jsonString(nearDeriveKek, "wrap_key_seed_b64u"),
            try jsonString(nearDeriveKek, "wrap_key_salt_b64u")
        )
    )

    try assertEqual(
        "near_crypto.encrypt_fixed_nonce",
        try jsonString(nearEncrypt, "expected_ciphertext_hex"),
        try call3(
            "encrypt_data_chacha20",
            signer_platform_ios_v1_encrypt_data_chacha20_hex,
            try jsonString(nearEncrypt, "plain_text"),
            try jsonString(nearEncrypt, "key_hex"),
            try jsonString(nearEncrypt, "nonce_hex")
        )
    )

    try assertEqual(
        "near_crypto.decrypt_fixed_nonce",
        try jsonString(nearEncrypt, "expected_plain_text"),
        try call3(
            "decrypt_data_chacha20",
            signer_platform_ios_v1_decrypt_data_chacha20,
            try jsonString(nearEncrypt, "expected_ciphertext_hex"),
            try jsonString(nearEncrypt, "nonce_hex"),
            try jsonString(nearEncrypt, "key_hex")
        )
    )
}

do {
    let args = CommandLine.arguments
    guard args.count == 2 else { throw VectorReplayError.usage }
    let vectors = try loadVectors(args[1])
    try runReplay(vectors: vectors)
    print("swift vector replay: OK")
} catch {
    fputs("swift vector replay: FAIL: \(error)\n", stderr)
    exit(1)
}
