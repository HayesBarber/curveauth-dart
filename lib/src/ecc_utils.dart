import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

/// A utility class for working with elliptic curve cryptography (ECC) in Dart.
///
/// Provides methods for:
/// - Encoding and decoding ECDSA signatures in DER format.
/// - Parsing raw base64-encoded uncompressed ECC public keys.
class ECCUtils {
  /// Encodes the given ECDSA signature components into DER format.
  ///
  /// The signature is encoded as a DER sequence of two ASN.1 integers (r, s).
  ///
  /// Returns a [Uint8List] containing the DER-encoded signature.
  static Uint8List encodeDer(BigInt r, BigInt s) {
    final seq = ASN1Sequence();

    seq.add(ASN1Integer(r));
    seq.add(ASN1Integer(s));

    return seq.encode();
  }

  /// Decodes a DER-encoded ECDSA signature into its r and s components.
  ///
  /// Expects a DER-encoded ASN.1 sequence containing two integers.
  ///
  /// Throws an [ArgumentError] if the format is invalid or the integers are null.
  ///
  /// Returns an [ECSignature] containing the r and s values.
  static ECSignature decodeDer(Uint8List bytes) {
    final parser = ASN1Parser(bytes);
    final sequence = parser.nextObject();

    if (sequence is! ASN1Sequence ||
        sequence.elements == null ||
        sequence.elements!.length < 2) {
      throw ArgumentError('Invalid DER signature format');
    }

    final rElem = sequence.elements![0];
    final sElem = sequence.elements![1];

    if (rElem is! ASN1Integer || sElem is! ASN1Integer) {
      throw ArgumentError('DER elements are not ASN1Integer');
    }

    final r = rElem.integer;
    final s = sElem.integer;

    if (r == null || s == null) {
      throw ArgumentError('Signature integers cannot be null');
    }

    return ECSignature(r, s);
  }

  /// Loads an uncompressed ECC public key from a base64-encoded string.
  ///
  /// The input must be a base64-encoded 65-byte array starting with 0x04, followed by
  /// 32 bytes for the x-coordinate and 32 bytes for the y-coordinate.
  ///
  /// Throws an [ArgumentError] if the input is not a valid uncompressed key.
  ///
  /// Returns an [ECPublicKey] using the secp256r1 curve.
  static ECPublicKey loadPublicKeyRawBase64(String b64) {
    final bytes = base64Decode(b64);
    if (bytes.length != 65 || bytes[0] != 0x04) {
      throw ArgumentError('Invalid uncompressed public key format');
    }

    final x = BigInt.parse(
      bytes
          .sublist(1, 33)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(),
      radix: 16,
    );
    final y = BigInt.parse(
      bytes.sublist(33).map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16,
    );

    final ecDomain = ECDomainParameters('secp256r1');
    final Q = ecDomain.curve.createPoint(x, y);
    return ECPublicKey(Q, ecDomain);
  }
}
