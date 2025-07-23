import 'package:cryptography/cryptography.dart';

class ECCKeyPair {
  final EcKeyPair keyPair;
  final EcPublicKey publicKey;

  ECCKeyPair._(this.keyPair, this.publicKey);

  /// Generates a new key pair using P-256 curve
  static Future<ECCKeyPair> generate() async {
    final algorithm = Ecdsa.p256(Sha256());
    final keyPair = await algorithm.newKeyPair();
    final publicKey = await keyPair.extractPublicKey();
    return ECCKeyPair._(keyPair, publicKey);
  }

  Future<Signature> createSignature(String challenge) async {
    final algorithm = Ecdsa.p256(Sha256());
    final data = challenge.codeUnits;
    final signature = await algorithm.sign(data, keyPair: keyPair);
    return signature;
  }
}
