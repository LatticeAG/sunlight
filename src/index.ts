/** Public SDK surface for `@latticeag/sunlight` (spec §7 CoreApi). */

export { jcsBytes, jcsString, JcsError } from "./encoding/jcs.js";
export { parseStrictJson, parseStrictJsonString, StrictJsonError } from "./encoding/strict-json.js";
export { newId, isValidId, randomHex } from "./ids.js";
export {
  SunlightError, errorBody, cliExitFor, httpStatusFor, isRetryableCode,
  type ErrorCode, type ErrorBody,
} from "./errors.js";
export {
  ed25519Sign, ed25519Verify, ed25519PublicFromSeed, ed25519Generate,
  isCanonicalPointEncoding, isValidPublicKey, isCanonicalSignature,
  privateKeyFromSeed,
} from "./crypto/ed25519.js";
export {
  B, D, RAW, sha256, hashDomain, signatureDomain, signatureMessage,
  DIGEST_RE, HEX32_RE, HEX64_RE,
} from "./crypto/domains.js";
export * from "./schema.js";
export {
  hashArtifact, hashFileBytes, hashJcsFile, enumerateTree, stageTree,
  manifestArtifact,
} from "./artifact.js";
export {
  capture, filesIdentical,
  type CaptureRequest, type CaptureResult, type CaptureState, type CaptureTemplate,
  type Journal,
} from "./capture.js";
export {
  signStatement, signCommand, signReceipt, signHead, verifySignedObject,
  seedSigner, type Signer,
} from "./objects.js";
export {
  generateKey, loadKeyFile, writeKeyFile, writePublicKeyFile, keyFileFromSeed,
  derToSeed,
} from "./keys.js";
export { verify, type VerifyRequest } from "./verify.js";
export { computeEvidenceRef } from "./evidence.js";
export { loadConfig, resolveRegistry, configPath, DEFAULT_CONFIG_PATH } from "./config.js";
export { Cache } from "./cache.js";
export { RegistryTransport, type TransportOptions } from "./transport.js";
export { NodeSqliteStore, applySchema, SCHEMA_SQL, SCHEMA_VERSION, type Store, type SqlParam } from "./ledger/store.js";
export { LedgerEngine, type EngineHooks, keyStatusAtCut } from "./ledger/engine.js";
export { LedgerService, type ServiceState, type DisabledReason } from "./ledger/service.js";
export { RegistryGateway, serveHttp, type GatewayDeps } from "./server.js";
export { loadDeployment, startRegistryFromDeployment, type RegistryInfo } from "./registry.js";
export { runConformance, type ConformanceReport, type VectorResult } from "./conformance.js";
export {
  nowMs, freshNonceHex, fixedRequestId, fixedNonceHex, keyEntropyHex, conformanceEnabled,
} from "./conformance-env.js";
