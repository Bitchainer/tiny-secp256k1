enum Errors {
  errorBadPrivate,
  errorBadPoint,
  errorBadTweak,
  errorBadHash,
  errorBadSignature,
  errorBadExtraData,
  errorBadParity,
  errorBadRecovery,
}

const errorMessages = {
  Errors.errorBadPrivate: 'Expected Private',
  Errors.errorBadPoint: 'Expected Point',
  Errors.errorBadTweak: 'Expected Tweak',
  Errors.errorBadHash: 'Expected Hash',
  Errors.errorBadSignature: 'Expected Signature',
  Errors.errorBadExtraData: 'Expected Extra Data (32 bytes)',
  Errors.errorBadParity: 'Expected Parity (1 | 0)',
  Errors.errorBadRecovery: 'Bad Recovery',
};

typedef ValidateError = Errors;

void throwError(ValidateError errCode) {
  final message = errorMessages[Errors.values[errCode.index]];
  throw ArgumentError('Error: $message (code: $errCode)');
}
