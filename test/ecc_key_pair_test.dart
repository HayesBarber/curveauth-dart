import 'package:test/test.dart';
import 'package:curveauth_dart/curveauth_dart.dart';
import 'dart:convert';

void main() {
  test('ECCKeyPair generates valid key pair', () {
    final keyPair = ECCKeyPair.generate();
    expect(keyPair.privateKey, isNotNull);
    expect(keyPair.publicKey, isNotNull);
  });

  test('ECCKeyPair serializes and deserializes correctly', () {
    final original = ECCKeyPair.generate();
    final jsonMap = original.toJson();
    final restored = ECCKeyPair.fromJson(jsonMap);

    expect(restored.privateKey.d, equals(original.privateKey.d));
    expect(
      restored.publicKey.Q!.x!.toBigInteger(),
      equals(original.publicKey.Q!.x!.toBigInteger()),
    );
    expect(
      restored.publicKey.Q!.y!.toBigInteger(),
      equals(original.publicKey.Q!.y!.toBigInteger()),
    );
  });

  test('ECCKeyPair generates a base64-encoded DER signature', () async {
    final keyPair = ECCKeyPair.generate();
    final challenge = 'test-challenge';
    final signature = await keyPair.createSignature(challenge);

    final der = base64Decode(signature);
    expect(der[0], equals(0x30)); // SEQUENCE
    expect(der.length, greaterThan(64)); // DER signature should be > raw r||s
  });
}
