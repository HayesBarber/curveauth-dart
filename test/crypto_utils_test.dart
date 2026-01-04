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
        (1, 2),
        (2, 3),
        (3, 4),
        (4, 6),
        (8, 11),
        (16, 22),
        (32, 43),
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

  group('CryptoUtils.generateThreeDigitCode', () {
    test('generates 3-digit code', () {
      final code = CryptoUtils.generateThreeDigitCode();

      expect(code, isNotNull);
      expect(code.length, equals(3));
    });

    test('generates numeric code only', () {
      final code = CryptoUtils.generateThreeDigitCode();

      final pattern = RegExp(r'^[0-9]{3}$');
      expect(code, matches(pattern));
    });

    test('generates codes in valid range', () {
      for (var i = 0; i < 100; i++) {
        final code = CryptoUtils.generateThreeDigitCode();
        final intValue = int.parse(code);
        expect(intValue, greaterThanOrEqualTo(100));
        expect(intValue, lessThanOrEqualTo(999));
      }
    });

    test('generates different codes on multiple calls', () {
      final codes = <String>{};
      for (var i = 0; i < 50; i++) {
        codes.add(CryptoUtils.generateThreeDigitCode());
      }
      expect(codes.length, greaterThan(1));
    });
  });
}
