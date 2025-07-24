import 'dart:convert';
import 'dart:typed_data';
import 'package:curveauth_dart/curveauth_dart.dart';
import 'package:test/test.dart';

void main() {
  group('VerifySignature', () {
    test('verifies a valid signature', () async {
      final keyPair = ECCKeyPair.generate();
      final message = 'hello world';
      final signature = await keyPair.createSignature(message);

      final publicKeyB64 = keyPair.exportPublicKeyRawBase64();

      final isValid = VerifySignature.verifySignature(
        message,
        signature,
        publicKeyB64,
      );
      expect(isValid, isTrue);
    });

    test('fails to verify invalid signature', () {
      final message = 'hello world';
      final fakeSignature = base64Encode(
        Uint8List.fromList(List.filled(70, 0)),
      );
      final fakePublicKey = base64Encode(
        Uint8List.fromList(List.filled(65, 0x04)),
      );

      final isValid = VerifySignature.verifySignature(
        message,
        fakeSignature,
        fakePublicKey,
      );
      expect(isValid, isFalse);
    });
  });
}
