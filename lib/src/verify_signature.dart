import 'dart:convert';
import 'dart:typed_data';
import 'package:curveauth_dart/curveauth_dart.dart';
import 'package:curveauth_dart/src/ecc_utils.dart';
import 'package:pointycastle/pointycastle.dart';

class VerifySignature {
  static bool verifySignature(
    String message,
    String signatureB64,
    ECCKeyPair keyPair,
  ) {
    try {
      final signatureBytes = base64Decode(signatureB64);
      final publicKey = keyPair.publicKey;
      final sig = EccUtils.decodeDer(signatureBytes);

      final signer = Signer('SHA-256/ECDSA');
      signer.init(false, PublicKeyParameter<ECPublicKey>(publicKey));

      final messageBytes = Uint8List.fromList(message.codeUnits);
      return signer.verifySignature(messageBytes, sig);
    } catch (_) {
      return false;
    }
  }
}
