// factory.ts

import {
  ISanitizerGlobalConfig,
  ValidationStrategy,
  SanitizerPlugins,
} from "../types.js";

import { ConfigValidator } from "../config/configValidator.js";
import {
  AbusePrevention,
  SecurityAuditLogger,
  ValidationStrategyRegistry,
} from "../validators/validaters.js";

import { CoreStringSanitizer } from "./CoreStringSanitizer.js";
import { SecurityStringSanitizer } from "./SecurityStringSanitizer.js";
import { SanitizerDiagnostics } from "../diagnostics/SanitizerDiagnostics.js";


/**
 * ============================================================
 * 1. CORE-ONLY SANITIZER (FAST, NO SECURITY LAYERS)
 * ============================================================
 */
export function createCoreOnlySanitizer(
  config?: Partial<ISanitizerGlobalConfig>
): CoreStringSanitizer {
  // Initialize global config engine
  ConfigValidator.initialize(config);

  // Snapshot effective config
  const effectiveConfig = ConfigValidator.getEffectiveConfig();

  // Strategy registry (all validators)
  const registry = new ValidationStrategyRegistry();
  registry.initializeDefaultValidators();


  // Return pure core sanitizer
  return new CoreStringSanitizer(effectiveConfig, registry);
}

// Async version
export const asyncCoreOnlySanitizer = async (
  config?: Partial<ISanitizerGlobalConfig>
): Promise<CoreStringSanitizer> => createCoreOnlySanitizer(config);

/**
 * ============================================================
 * 2. FULL SECURITY SANITIZER (DECORATOR + PLUGINS)
 * ============================================================
 */
export function createConfiguredSecuritySanitizer(
  config?: Partial<ISanitizerGlobalConfig>
): SecurityStringSanitizer {
  // Initialize config + core sanitizer
  const core = createCoreOnlySanitizer(config);
  // Plugins
  SecurityAuditLogger.initialize({
  enabled: core.config.auditLogging.enabled,
  logLevels: core.config.auditLogging.logLevels[0].toLowerCase() as any,
  destination: core.config.auditLogging.destination,
  maxLogs: core.config.auditLogging.maxLogs,
  filePath: core.config.auditLogging.filePath,
  remoteEndpoint: core.config.auditLogging.remoteEndpoint,
});

const auditLogger = SecurityAuditLogger.getInstance();
  const abusePrevention = new AbusePrevention();

  // Configure plugins from global config
  abusePrevention.configure({
    requestsPerMinute: core.config.rateLimiting.requestsPerMinute,
    blockDurationMs: core.config.rateLimiting.blockDurationMs,
    suspiciousPatterns: core.config.rateLimiting.suspiciousPatterns,
  });


  const plugins: SanitizerPlugins = {
    abusePrevention,
    auditLogger,
  };

  // Build full security sanitizer (decorator)
  return new SecurityStringSanitizer(plugins,core);
}

// Async version
export const asyncConfiguredSecuritySanitizer = async (
  config?: Partial<ISanitizerGlobalConfig>
): Promise<SecurityStringSanitizer> => createConfiguredSecuritySanitizer(config);

export function createSanitizerDiagnostics(security:SecurityStringSanitizer){
  // 3. Diagnostics (tests the full security perimeter)
  const diagnostics = new SanitizerDiagnostics(security);
  return diagnostics;
}

export async function asyncCreateSanitizerDiagnostics(security:SecurityStringSanitizer){
return createSanitizerDiagnostics(security)
}
/**
 * createSanitizerSystem
 * ---------------------
 * Builds the full sanitizer stack:
 *
 * 1. CoreStringSanitizer  (pure sanitization engine)
 * 2. SecurityStringSanitizer (security perimeter)
 * 3. SanitizerDiagnostics (full-suite diagnostics)
 *
 * All instances share:
 * - config
 * - validators
 * - plugins
 */
export function createSanitizerSystem(config?: Partial<ISanitizerGlobalConfig>) {

  // 2. Security sanitizer (decorator)
  const security = createConfiguredSecuritySanitizer(config);

  // 3. Diagnostics (tests the full security perimeter)
  const diagnostics = createSanitizerDiagnostics(security);

  return {
    core:security.core,
    security,
    diagnostics,
  };
}

export async function asyncCreateSanitizerSystem(config?: Partial<ISanitizerGlobalConfig>) {
  return createSanitizerSystem(config);
}

