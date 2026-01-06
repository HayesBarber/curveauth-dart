# curveauth-dart

A lightweight Dart library for working with elliptic curve cryptography (ECC) using the `secp256r1` curve. Also includes a webhook verifier.

## Features

- Generate ECC key pairs
- Serialize/deserialize keys to/from JSON
- Export public keys in uncompressed base64 format
- Create and verify ECDSA signatures (DER encoded, base64)
- Verify GitHub webhook signatures using HMAC-SHA256
- Generate cryptographically secure API keys, verification codes, and UUIDs
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
import 'package:curveauth_dart/curveauth_dart.dart';

// Instance method (uses key pair's public key)
final isValid = keyPair.verifySignature('hello world', signature);

// Static method (requires public key parameter)
final isValid = ECCKeyPair.verifySignatureStatic(
  message: 'hello world',
  signature: signature,
  publicKeyBase64: publicKeyBase64,
);
```

## Key Serialization

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

final json = keyPair.toJson();
final restored = ECCKeyPair.fromJson(json);
```

## GitHub Webhook Verification

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

// Verify webhook with or without 'sha256=' prefix
final isValid = WebhookVerifier.verifyGitHubWebhook(
  payload: payload,
  signature: 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17',
  secret: 'your-webhook-secret',
);
```

### Generate Webhook Signature (for testing)

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

// Generate a webhook signature
final signature = WebhookVerifier.generateGitHubWebhookSignature(
  payload: payload,
  secret: 'your-webhook-secret',
);
```

## Cryptographic Utilities

### Generate API Key

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

final apiKey = CryptoUtils.generateApiKey();

// Generate API key with custom length in bytes
final customKey = CryptoUtils.generateApiKey(length: 16);
```

### Generate Three-Digit Code

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

// Returns string like "123", "456", "789", etc.
final code = CryptoUtils.generateThreeDigitCode();
```

### Generate Challenge String

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

final challenge = CryptoUtils.generateChallenge();

// Generate challenge with custom length in bytes
final customChallenge = CryptoUtils.generateChallenge(length: 32);
```

### Generate UUID

```dart
import 'package:curveauth_dart/curveauth_dart.dart';

final id = CryptoUtils.generateId();
```
