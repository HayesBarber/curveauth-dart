import 'package:curveauth_dart/curveauth_dart.dart';
import 'package:test/test.dart';

void main() {
  group('WebhookVerifier', () {
    test('verifies a valid GitHub webhook signature', () {
      const secret = 'It\'s a Secret to Everybody';
      const payload = 'Hello, World!';
      const expectedSignature =
          '757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';

      final isValid = WebhookVerifier.verifyGitHubWebhook(
        payload,
        expectedSignature,
        secret,
      );
      expect(isValid, isTrue);
    });

    test('fails to verify invalid GitHub webhook signature', () {
      const secret = 'It\'s a Secret to Everybody';
      const payload = 'Hello, World!';
      const invalidSignature = 'invalid_signature_hash';

      final isValid = WebhookVerifier.verifyGitHubWebhook(
        payload,
        invalidSignature,
        secret,
      );
      expect(isValid, isFalse);
    });

    test('fails to verify signature with wrong secret', () {
      const secret = 'Wrong Secret';
      const payload = 'Hello, World!';
      const validSignature =
          '757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';

      final isValid = WebhookVerifier.verifyGitHubWebhook(
        payload,
        validSignature,
        secret,
      );
      expect(isValid, isFalse);
    });

    test('fails to verify signature with wrong payload', () {
      const secret = 'It\'s a Secret to Everybody';
      const payload = 'Wrong payload';
      const validSignature =
          '757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';

      final isValid = WebhookVerifier.verifyGitHubWebhook(
        payload,
        validSignature,
        secret,
      );
      expect(isValid, isFalse);
    });
  });
}
