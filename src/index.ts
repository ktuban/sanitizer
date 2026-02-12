/**
 * Entry Point: @ktuban/sanitizer
 * -------------------------
 * Public API surface for the sanitization framework.
 *
 * Exposes:
 * - Core & Security sanitizers
 * - Global configuration engine
 * - Validation strategy registry
 * - Built‑in validators
 * - Diagnostics utilities
 * - Public types
 */
// Public types
export * from "./types.js";
export * from "./SanitizerError.js";

// Sanitizers
export * from "./sanitizers/BaseSanitizer.js";
export * from "./sanitizers/CoreStringSanitizer.js";
export * from "./sanitizers/SecurityStringSanitizer.js";
export * from "./sanitizers/factory.js";
export * from "./config/configValidator.js";

// Export all built‑in validators
export * from "./validators/validaters.js";

// Diagnostics
export * from "./diagnostics/SanitizerDiagnostics.js";
export * from "./diagnostics/SanitizerDiagnostics_Enhanced.js";

// test
/*
import { asyncCreateSanitizerSystem } from "./sanitizers/factory.js";

asyncCreateSanitizerSystem().then(async (s)=> {
    let report = await s.diagnostics.runAll({deep:true})
    console.log(report)
    console.log(s.security.exportAuditLogs("json"));
});

*/


