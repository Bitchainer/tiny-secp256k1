import 'dart:ffi' show Bool, Int8, Uint8;
import 'dart:typed_data';

import 'errors.dart' show Errors, throwError;

const privateKeySize = 32;
const publicKeyCompressedSize = 33;
const publickKeyUncompressedSize = 65;
const xOnlyPublicKeySize = 32;
const tweakSize = 32;
const hashSize = 32;
const extraDataSize = 32;
const signatureSize = 64;

final bn32Zero = Uint8List(32);
final bn32N = Uint8List.fromList([
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  255,
  254,
  186,
  174,
  220,
  230,
  175,
  72,
  160,
  59,
  191,
  210,
  94,
  140,
  208,
  54,
  65,
  65,
]);

// Difference between field and order
final bn32PMinusN = Uint8List.fromList([
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  1,
  69,
  81,
  35,
  25,
  80,
  183,
  95,
  196,
  64,
  45,
  161,
  114,
  47,
  201,
  186,
  238,
]);

@Bool()
bool isUint8List(dynamic value) => value is Uint8List;

@Int8()
int cmpBn32(Uint8List data1, Uint8List data2) {
  for (int i = 0; i < 32; i++) {
    if (data1[i] != data2[i]) {
      return data1[i] < data2[i] ? -1 : 1;
    }
  }
  return 0;
}

@Bool()
bool isZero(Uint8List x) => cmpBn32(x, bn32Zero) == 0;

@Bool()
bool isPrivate(Uint8List x) {
  return x.length == privateKeySize &&
      cmpBn32(x, bn32Zero) > 0 &&
      cmpBn32(x, bn32N) < 0;
}

@Bool()
bool isPoint(Uint8List p) {
  return (p.length == publicKeyCompressedSize ||
          p.length == publickKeyUncompressedSize ||
          p.length == xOnlyPublicKeySize) &&
      !isZero(p);
}

@Bool()
bool isXOnlyPoint(Uint8List p) => p.length == xOnlyPublicKeySize;

@Bool()
bool isDERPoint(Uint8List p) {
  return (p.length == publicKeyCompressedSize ||
      p.length == publickKeyUncompressedSize);
}

@Bool()
bool isPointCompressed(Uint8List p) => p.length == publicKeyCompressedSize;

@Bool()
bool isTweak(Uint8List tweak) {
  return tweak.length == tweakSize && cmpBn32(tweak, bn32N) < 0;
}

@Bool()
bool isHash(Uint8List h) {
  return h.length == hashSize;
}

@Bool()
bool isExtraData(Uint8List? e) {
  return e == null || e.length == extraDataSize;
}

@Bool()
bool isSignature(Uint8List signature) {
  return signature.length == signatureSize &&
      cmpBn32(signature.sublist(0, 32), bn32N) < 0 &&
      cmpBn32(signature.sublist(32, 64), bn32N) < 0;
}

@Bool()
bool isSigrLessThanPMinusN(Uint8List signature) {
  return (signature.length == signatureSize &&
      cmpBn32(signature.sublist(0, 32), bn32PMinusN) < 0);
}

void validateParity(@Uint8() int p) {
  if (p != 0 && p != 1) {
    throwError(Errors.errorBadParity);
  }
}

void validatePrivate(Uint8List d) {
  if (!isPrivate(d)) throwError(Errors.errorBadPrivate);
}

void validatePoint(Uint8List p) {
  if (!isPoint(p)) throwError(Errors.errorBadPoint);
}

void validateXOnlyPoint(Uint8List p) {
  if (!isXOnlyPoint(p)) throwError(Errors.errorBadPoint);
}

void validateTweak(Uint8List tweak) {
  if (!isTweak(tweak)) throwError(Errors.errorBadTweak);
}

void validateHash(Uint8List h) {
  if (!isHash(h)) throwError(Errors.errorBadHash);
}

void validateExtraData(Uint8List? e) {
  if (!isExtraData(e)) throwError(Errors.errorBadExtraData);
}

void validateSignature(Uint8List signature) {
  if (!isSignature(signature)) throwError(Errors.errorBadSignature);
}

void validateSignatureCustom(bool Function() validatorFn) {
  if (!validatorFn()) throwError(Errors.errorBadSignature);
}

void validateSignatureNonzeroRS(Uint8List signature) {
  if (isZero(signature.sublist(0, 32)) || isZero(signature.sublist(32, 64))) {
    throwError(Errors.errorBadSignature);
  }
}

void validateSigrPMinusN(Uint8List signature) {
  if (!isSigrLessThanPMinusN(signature)) throwError(Errors.errorBadRecovery);
}
