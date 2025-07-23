import 'dart:convert';
import 'dart:typed_data';
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

  /// Signs the challenge and returns a base64-encoded DER-encoded ECDSA signature string.
  Future<String> createSignature(String challenge) async {
    final algorithm = Ecdsa.p256(Sha256());
    final signature = await algorithm.signString(challenge, keyPair: keyPair);

    final r = signature.bytes.sublist(0, 32);
    final s = signature.bytes.sublist(32, 64);
    final derEncoded = _encodeDer(r, s);
    return base64Encode(derEncoded);
  }

  /// DER-encodes the ECDSA signature (r, s) as per ASN.1.
  Uint8List _encodeDer(List<int> r, List<int> s) {
    List<int> encodeInt(List<int> bytes) {
      // Ensure positive INTEGER in DER
      if (bytes.isNotEmpty && (bytes[0] & 0x80) != 0) {
        bytes = [0x00, ...bytes];
      }
      return [0x02, bytes.length, ...bytes];
    }

    final rEnc = encodeInt(r);
    final sEnc = encodeInt(s);
    final seq = [0x30, rEnc.length + sEnc.length, ...rEnc, ...sEnc];
    return Uint8List.fromList(seq);
  }
}
