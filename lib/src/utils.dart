import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

class Utils {
  static Uint8List encodeDer(BigInt r, BigInt s) {
    final seq = ASN1Sequence();

    seq.add(ASN1Integer(r));
    seq.add(ASN1Integer(s));

    return seq.encode();
  }

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
}
