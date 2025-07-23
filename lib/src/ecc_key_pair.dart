import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

class ECCKeyPair {
  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  ECCKeyPair._(this.privateKey, this.publicKey);

  static ECCKeyPair generate() {
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

    final der = _encodeDer(sig.r, sig.s);
    return base64Encode(der);
  }

  Uint8List _encodeDer(BigInt r, BigInt s) {
    List<int> encodeInt(BigInt i) {
      var bytes = i.toUnsigned(256).toRadixString(16).padLeft(64, '0');
      var b = Uint8List.fromList(
        List.generate(
          bytes.length ~/ 2,
          (i) => int.parse(bytes.substring(i * 2, i * 2 + 2), radix: 16),
        ),
      );
      if (b[0] & 0x80 != 0) {
        b = Uint8List.fromList([0x00, ...b]);
      }
      return [0x02, b.length, ...b];
    }

    final rEnc = encodeInt(r);
    final sEnc = encodeInt(s);
    final seq = [0x30, rEnc.length + sEnc.length, ...rEnc, ...sEnc];
    return Uint8List.fromList(seq);
  }
}
