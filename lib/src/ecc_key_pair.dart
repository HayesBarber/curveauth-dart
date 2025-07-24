import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:curveauth_dart/src/ecc_utils.dart';
import 'package:pointycastle/export.dart';

class ECCKeyPair {
  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  ECCKeyPair._(this.privateKey, this.publicKey);

  factory ECCKeyPair.generate() {
    final ecDomain = ECDomainParameters('secp256r1');
    final keyGen = ECKeyGenerator();

    final secureRandom = FortunaRandom();
    final src = Random.secure();
    final seed = Uint8List.fromList(List.generate(32, (_) => src.nextInt(256)));
    secureRandom.seed(KeyParameter(seed));

    keyGen.init(
      ParametersWithRandom(ECKeyGeneratorParameters(ecDomain), secureRandom),
    );
    final pair = keyGen.generateKeyPair();

    final priv = pair.privateKey;
    final pub = pair.publicKey;

    return ECCKeyPair._(priv, pub);
  }

  factory ECCKeyPair.fromJson(Map<String, String> json) {
    final ecDomain = ECDomainParameters('secp256r1');

    final dStr = json['privateKey'];
    final xStr = json['publicKeyX'];
    final yStr = json['publicKeyY'];

    if (dStr == null || xStr == null || yStr == null) {
      throw ArgumentError('Missing required key material in JSON map.');
    }

    final d = BigInt.parse(dStr, radix: 16);
    final x = BigInt.parse(xStr, radix: 16);
    final y = BigInt.parse(yStr, radix: 16);
    final Q = ecDomain.curve.createPoint(x, y);
    final privateKey = ECPrivateKey(d, ecDomain);
    final publicKey = ECPublicKey(Q, ecDomain);

    return ECCKeyPair._(privateKey, publicKey);
  }

  Map<String, String> toJson() {
    final d = privateKey.d;
    final q = publicKey.Q;
    if (d == null || q == null || q.x == null || q.y == null) {
      throw StateError('Invalid ECC key: missing required components.');
    }

    final privHex = d.toRadixString(16).padLeft(64, '0');
    final pubX = q.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0');
    final pubY = q.y!.toBigInteger()!.toRadixString(16).padLeft(64, '0');

    return {'privateKey': privHex, 'publicKeyX': pubX, 'publicKeyY': pubY};
  }

  String exportPublicKeyRawBase64() {
    final q = publicKey.Q;
    if (q == null || q.x == null || q.y == null) {
      throw StateError('Public key is incomplete.');
    }

    final xBytes = q.x!.toBigInteger()!.toRadixString(16).padLeft(64, '0');
    final yBytes = q.y!.toBigInteger()!.toRadixString(16).padLeft(64, '0');

    final xList = List<int>.generate(
      32,
      (i) => int.parse(xBytes.substring(i * 2, i * 2 + 2), radix: 16),
    );
    final yList = List<int>.generate(
      32,
      (i) => int.parse(yBytes.substring(i * 2, i * 2 + 2), radix: 16),
    );

    final pubBytes = Uint8List(65);
    pubBytes[0] = 0x04;
    pubBytes.setRange(1, 33, xList);
    pubBytes.setRange(33, 65, yList);

    return base64Encode(pubBytes);
  }

  Future<String> createSignature(String challenge) async {
    final signer = Signer('SHA-256/ECDSA');
    final random = FortunaRandom();
    final src = Random.secure();
    final seed = Uint8List.fromList(List.generate(32, (_) => src.nextInt(256)));
    random.seed(KeyParameter(seed));

    signer.init(
      true,
      ParametersWithRandom(
        PrivateKeyParameter<ECPrivateKey>(privateKey),
        random,
      ),
    );

    final message = Uint8List.fromList(challenge.codeUnits);
    final sig = signer.generateSignature(message) as ECSignature;

    final der = ECCUtils.encodeDer(sig.r, sig.s);
    return base64Encode(der);
  }
}
