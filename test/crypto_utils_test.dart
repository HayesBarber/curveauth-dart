import 'package:curveauth_dart/curveauth_dart.dart';
import 'package:test/test.dart';

void main() {
  group('CryptoUtils.generateApiKey', () {
    test('generates API key with default length', () {
      final apiKey = CryptoUtils.generateApiKey();

      expect(apiKey, isNotNull);
      expect(apiKey, isNotEmpty);
      expect(apiKey.length, equals(43));
    });

    test('generates API key with custom length', () {
      final apiKey = CryptoUtils.generateApiKey(length: 16);

      expect(apiKey, isNotNull);
      expect(apiKey, isNotEmpty);
      expect(apiKey.length, equals(22));
    });

    test('generates different keys on multiple calls', () {
      final key1 = CryptoUtils.generateApiKey();
      final key2 = CryptoUtils.generateApiKey();

      expect(key1, isNot(equals(key2)));
    });

    test('generates URL-safe base64 characters only', () {
      final apiKey = CryptoUtils.generateApiKey();

      final pattern = RegExp(r'^[A-Za-z0-9_-]+$');
      expect(apiKey, matches(pattern));
    });

    test('does not contain padding characters', () {
      final apiKey = CryptoUtils.generateApiKey();

      expect(apiKey, isNot(contains('=')));
    });

    test('throws ArgumentError for length 0', () {
      expect(
        () => CryptoUtils.generateApiKey(length: 0),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws ArgumentError for negative length', () {
      expect(
        () => CryptoUtils.generateApiKey(length: -1),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws ArgumentError for length > 1024', () {
      expect(
        () => CryptoUtils.generateApiKey(length: 1025),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('handles minimum valid length', () {
      final apiKey = CryptoUtils.generateApiKey(length: 1);

      expect(apiKey, isNotNull);
      expect(apiKey, isNotEmpty);
      expect(apiKey.length, equals(2));
    });

    test('handles maximum valid length', () {
      final apiKey = CryptoUtils.generateApiKey(length: 1024);

      expect(apiKey, isNotNull);
      expect(apiKey, isNotEmpty);
      expect(apiKey.length, equals(1366));
    });

    test('produces expected length for various inputs', () {
      final testCases = [
        (1, 2), // 1 byte -> 2 chars
        (2, 3), // 2 bytes -> 3 chars
        (3, 4), // 3 bytes -> 4 chars
        (4, 6), // 4 bytes -> 6 chars
        (8, 11), // 8 bytes -> 11 chars
        (16, 22), // 16 bytes -> 22 chars
        (32, 43), // 32 bytes -> 43 chars
      ];

      for (final (input, expectedLength) in testCases) {
        final apiKey = CryptoUtils.generateApiKey(length: input);
        expect(
          apiKey.length,
          equals(expectedLength),
          reason: 'Length $input should produce $expectedLength characters',
        );
      }
    });
  });
}
