import { _setSignedPolicyRequiredForTests } from "../src/policy/pinned-keys.js";

// Suites written before signed policies use unsigned enforcing fixtures.
// They keep working with the signature requirement off; a body that carries
// a signature is still verified. test/policy-signature.test.ts turns the
// requirement back on and covers signing end to end.
_setSignedPolicyRequiredForTests(false);
