import 'package:pointycastle/export.dart';
import 'dart:typed_data';

/// A utility class for verifying webhook signatures using HMAC.
///
/// Currently supports GitHub webhooks using HMAC-SHA256.
class WebhookVerifier {
  /// Verifies a GitHub webhook signature against a payload and secret.
  ///
  /// The signature should be the raw signature string from the 'X-Hub-Signature-256' header
  /// without the 'sha256=' prefix.
  ///
  /// Returns `true` if the signature is valid, `false` otherwise.
  /// Catches and suppresses any exceptions during verification.
  ///
  /// [payload] is the raw request body as a string.
  /// [signature] is the HMAC signature from the webhook header.
  /// [secret] is the webhook secret key.
  static bool verifyGitHubWebhook(
    String payload,
    String signature,
    String secret,
  ) {
    try {
      final key = Uint8List.fromList(secret.codeUnits);
      final data = Uint8List.fromList(payload.codeUnits);

      final hmac = HMac(SHA256Digest(), 64);
      hmac.init(KeyParameter(key));
      hmac.update(data, 0, data.length);

      final mac = Uint8List(hmac.macSize);
      hmac.doFinal(mac, 0);
      final computedSignature = mac
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();

      return computedSignature == signature;
    } catch (_) {
      return false;
    }
  }
}
