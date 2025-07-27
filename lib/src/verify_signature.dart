import 'dart:convert';
import 'dart:typed_data';
import 'package:curveauth_dart/src/ecc_utils.dart';
import 'package:pointycastle/pointycastle.dart';

/// A utility class for verifying ECDSA signatures using a public key.
///
/// This class uses the SHA-256/ECDSA algorithm for signature verification.
class VerifySignature {
  /// Verifies a base64-encoded ECDSA signature against a message and a base64-encoded public key.
  ///
  /// The signature must be DER-encoded and base64-encoded.
  /// The public key must be a base64-encoded uncompressed ECC key (65 bytes, starting with 0x04).
  ///
  /// Returns `true` if the signature is valid, `false` otherwise.
  /// Catches and suppresses any exceptions during decoding or verification.
  ///
  /// [message] is the original plaintext message that was signed.
  /// [signatureB64] is the base64-encoded DER ECDSA signature.
  /// [publicKeyB64] is the base64-encoded uncompressed ECC public key.
  static bool verifySignature(
    String message,
    String signatureB64,
    String publicKeyB64,
  ) {
    try {
      final signatureBytes = base64Decode(signatureB64);
      final publicKey = ECCUtils.loadPublicKeyRawBase64(publicKeyB64);
      final sig = ECCUtils.decodeDer(signatureBytes);

      final signer = Signer('SHA-256/ECDSA');
      signer.init(false, PublicKeyParameter<ECPublicKey>(publicKey));

      final messageBytes = Uint8List.fromList(message.codeUnits);
      return signer.verifySignature(messageBytes, sig);
    } catch (_) {
      return false;
    }
  }
}
