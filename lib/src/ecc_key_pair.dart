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
}
