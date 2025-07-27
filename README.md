# curveauth-dart

A lightweight Dart library for working with elliptic curve cryptography (ECC) using the `secp256r1` curve.

## Features

- Generate ECC key pairs
- Serialize/deserialize keys to/from JSON
- Export public keys in uncompressed base64 format
- Create and verify ECDSA signatures (DER encoded, base64)
- Utility functions for DER encoding/decoding

## Getting Started

### Generate a Key Pair

```dart
final keyPair = ECCKeyPair.generate();
```

### Sign a Message

```dart
final signature = await keyPair.createSignature('hello world');
```

### Verify a Signature

```dart
final isValid = VerifySignature.verifySignature(
  'hello world',
  signature,
  keyPair.exportPublicKeyRawBase64(),
);
```

## Key Serialization

```dart
final json = keyPair.toJson();
final restored = ECCKeyPair.fromJson(json);
```
