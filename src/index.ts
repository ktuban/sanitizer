/**
 * Entry Point: @k/sanitizer
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

export * from "./sanitizers/BaseSanitizer.js";
export * from "./sanitizers/CoreStringSanitizer.js";
export * from "./sanitizers/SecurityStringSanitizer.js";
export * from "./sanitizers/factory.js";
export * from "./config/configValidator.js";

// Export all built‑in validators
export * from "./validators/validaters.js";

// Diagnostics
export * from "./diagnostics/SanitizerDiagnostics.js";

import { asyncCreateSanitizerSystem } from "./sanitizers/factory.js";

asyncCreateSanitizerSystem().then(async (s)=>{
const report = await s.diagnostics.runAll({deep:true});

console.log("Diagnostics Summary:");
console.table(report.summary);

console.log("Detailed Results:");
console.dir(report.results, { depth: null });
})
