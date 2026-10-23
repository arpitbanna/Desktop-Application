import Foundation
import CryptoKit

// Standalone verification script for iOS / macOS native CryptoKit primitives
print("==================================================")
print("TrustRoot Mobile - Native Swift CryptoKit Verification")
print("==================================================")

// 1. Generate Ephemeral Symmetric Key & Nonce
let symmetricKey = SymmetricKey(size: .bits256)
let nonce = AES.GCM.Nonce()

let testData = "UIDAI Hardware Root of Trust Native Swift Payload".data(using: .utf8)!
let originalDigest = SHA256.hash(data: testData).map { String(format: "%02x", $0) }.joined()

// 2. Form AAD
let aadData = "{\"version\":\"1.0\",\"packageId\":\"pkg_native_swift_test\"}".data(using: .utf8)!

// 3. Encrypt with AES-GCM
do {
    let sealedBox = try AES.GCM.seal(testData, using: symmetricKey, nonce: nonce, authenticating: aadData)
    print("✓ AES-256-GCM sealed successfully")
    print("  Ciphertext bytes: \(sealedBox.ciphertext.count)")
    print("  Tag bytes (128-bit): \(sealedBox.tag.count)")

    // 4. Decrypt and verify
    let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aadData)
    let recoveredText = String(data: decryptedData, encoding: .utf8)!
    let recoveredDigest = SHA256.hash(data: decryptedData).map { String(format: "%02x", $0) }.joined()

    assert(recoveredText == "UIDAI Hardware Root of Trust Native Swift Payload")
    assert(originalDigest == recoveredDigest)
    print("✓ Authenticated decryption verified: Exact payload match")

    // 5. Test Tampering Rejection
    var tamperedCiphertext = sealedBox.ciphertext
    tamperedCiphertext[0] ^= 0x5a
    let tamperedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: tamperedCiphertext, tag: sealedBox.tag)

    var tamperCaught = false
    do {
        _ = try AES.GCM.open(tamperedBox, using: symmetricKey, authenticating: aadData)
    } catch {
        tamperCaught = true
        print("✓ Tampered ciphertext correctly REJECTED by AES-GCM: \(error)")
    }

    if !tamperCaught {
        print("✗ ERROR: Tampered ciphertext was not rejected!")
        exit(1)
    }

    print("==================================================")
    print("ALL SWIFT NATIVE CRYPTOKIT CHECKS PASSED (100%)")
    print("==================================================")
} catch {
    print("Error during Swift test: \(error)")
    exit(1)
}
