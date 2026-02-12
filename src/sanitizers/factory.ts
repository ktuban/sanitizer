// factory.ts

import {
  ISanitizerGlobalConfig,
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
import { SanitizerDiagnostics_Enhanced } from "../diagnostics/SanitizerDiagnostics_Enhanced.js";

/**
 * ============================================================
 * INTERNAL HELPERS (Single source of truth)
 * ============================================================
 */

/**
 * Internal: Initialize core sanitizer
 * Encapsulates config initialization and validator registry setup
 */
function _createCoreOnlySanitizerImpl(
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

/**
 * Internal: Initialize security sanitizer with plugins
 * Wraps core sanitizer with audit logging and abuse prevention
 */
function _createConfiguredSecuritySanitizerImpl(
  core: CoreStringSanitizer
): SecurityStringSanitizer {
  // Plugins
  SecurityAuditLogger.initialize(core.config.auditLogging);
  const auditLogger = SecurityAuditLogger.getInstance();
  const abusePrevention = new AbusePrevention();

  // Configure plugins from global config
  if (core.config.rateLimiting) {
    abusePrevention.configure(core.config.rateLimiting);
  }

  const plugins: SanitizerPlugins = {
    abusePrevention,
    auditLogger,
  };

  // Build full security sanitizer (decorator)
  return new SecurityStringSanitizer(plugins, core);
}

/**
 * Internal: Initialize diagnostics
 * Tests the full security perimeter
 */
function _createSanitizerDiagnosticsImpl(
  security: SecurityStringSanitizer
): SanitizerDiagnostics {
  return new SanitizerDiagnostics(security);
}

/**
 * ============================================================
 * PUBLIC API: SYNC VERSIONS (Primary API - CJS Compatible)
 * ============================================================
 */

/**
 * Create a pure core-only sanitizer
 * - Fast, no security layers (audit logging, rate limiting, etc.)
 * - Suitable for high-throughput, security-sensitive paths
 * - CJS and ESM compatible (synchronous)
 *
 * @param config Optional partial configuration
 * @returns CoreStringSanitizer instance
 *
 * @example
 * const core = createCoreOnlySanitizer({ environment: 'production' });
 * const result = await core.sanitize(input, { sanitizeAs: 'email' });
 */
export function createCoreOnlySanitizer(
  config?: Partial<ISanitizerGlobalConfig>
): CoreStringSanitizer {
  return _createCoreOnlySanitizerImpl(config);
}

/**
 * Create a full security sanitizer with plugins
 * - Includes audit logging, rate limiting, abuse prevention
 * - Full security perimeter with observability
 * - CJS and ESM compatible (synchronous)
 *
 * @param config Optional partial configuration
 * @returns SecurityStringSanitizer instance
 *
 * @example
 * const security = createConfiguredSecuritySanitizer({ environment: 'production' });
 * const result = await security.sanitize(input, { sanitizeAs: 'email' });
 */
export function createConfiguredSecuritySanitizer(
  config?: Partial<ISanitizerGlobalConfig>
): SecurityStringSanitizer {
  const core = _createCoreOnlySanitizerImpl(config);
  return _createConfiguredSecuritySanitizerImpl(core);
}

/**
 * Create a sanitizer with diagnostics suite
 * - Full system: core + security + diagnostics
 * - Perfect for testing, validation, and compliance checks
 * - CJS and ESM compatible (synchronous)
 *
 * @param config Optional partial configuration
 * @returns Object with core, security, and diagnostics
 *
 * @example
 * const system = createSanitizerSystem({ environment: 'production' });
 * const report = await system.diagnostics.runAll({ deep: true });
 */
export function createSanitizerSystem(
  config?: Partial<ISanitizerGlobalConfig>
) {
  const core = _createCoreOnlySanitizerImpl(config);
  const security = _createConfiguredSecuritySanitizerImpl(core);
  const diagnostics = _createSanitizerDiagnosticsImpl(security);

  return {
    core,
    security,
    diagnostics,
  };
}

/**
 * Create a sanitizer diagnostics instance
 * - Standalone diagnostics for an existing SecurityStringSanitizer
 * - CJS and ESM compatible (synchronous)
 *
 * @param security SecurityStringSanitizer instance
 * @returns SanitizerDiagnostics instance
 */
export function createSanitizerDiagnostics(
  security: SecurityStringSanitizer
): SanitizerDiagnostics {
  return _createSanitizerDiagnosticsImpl(security);
}

/**
 * ============================================================
 * PUBLIC API: ASYNC VERSIONS (Modern async/await pattern)
 * ============================================================
 * These are async wrappers around the sync implementations.
 * Use these when you prefer async/await patterns in async contexts.
 * Both versions are equivalent in functionality (initialization is synchronous).
 */

/**
 * Async version of createCoreOnlySanitizer
 * @param config Optional partial configuration
 * @returns Promise<CoreStringSanitizer>
 *
 * @example
 * const core = await createCoreOnlySanitizerAsync({ environment: 'production' });
 */
export async function createCoreOnlySanitizerAsync(
  config?: Partial<ISanitizerGlobalConfig>
): Promise<CoreStringSanitizer> {
  return _createCoreOnlySanitizerImpl(config);
}

/**
 * Async version of createConfiguredSecuritySanitizer
 * @param config Optional partial configuration
 * @returns Promise<SecurityStringSanitizer>
 *
 * @example
 * const security = await createConfiguredSecuritySanitizerAsync({ environment: 'production' });
 */
export async function createConfiguredSecuritySanitizerAsync(
  config?: Partial<ISanitizerGlobalConfig>
): Promise<SecurityStringSanitizer> {
  const core = _createCoreOnlySanitizerImpl(config);
  return _createConfiguredSecuritySanitizerImpl(core);
}

/**
 * Async version of createSanitizerSystem
 * @param config Optional partial configuration
 * @returns Promise of object with core, security, and diagnostics
 *
 * @example
 * const system = await createSanitizerSystemAsync({ environment: 'production' });
 */
export async function createSanitizerSystemAsync(
  config?: Partial<ISanitizerGlobalConfig>
) {
  const core = _createCoreOnlySanitizerImpl(config);
  const security = _createConfiguredSecuritySanitizerImpl(core);
  const diagnostics = _createSanitizerDiagnosticsImpl(security);

  return {
    core,
    security,
    diagnostics,
  };
}

/**
 * Async version of createSanitizerDiagnostics
 * @param security SecurityStringSanitizer instance
 * @returns Promise<SanitizerDiagnostics>
 */
export async function createSanitizerDiagnosticsAsync(
  security: SecurityStringSanitizer
): Promise<SanitizerDiagnostics> {
  return _createSanitizerDiagnosticsImpl(security);
}

/**
 * ============================================================
 * ENHANCED DIAGNOSTICS API
 * ============================================================
 */

/**
 * Create enhanced sanitizer diagnostics with command injection tests
 * - Includes command injection tests for all 28 sanitizeAs types
 * - Includes edge case testing (empty strings, null values, very long inputs)
 * - Includes internationalization testing (Unicode, emoji, RTL text)
 * - Perfect for comprehensive security testing
 *
 * @param security SecurityStringSanitizer instance
 * @returns SanitizerDiagnostics_EnhancedFinal instance
 *
 * @example
 * const security = await createConfiguredSecuritySanitizerAsync();
 * const enhanced = createEnhancedSanitizerDiagnostics(security);
 * const report = await enhanced.runAllEnhanced({ deep: true });
 */
export function createEnhancedSanitizerDiagnostics(
  security: SecurityStringSanitizer
): SanitizerDiagnostics_Enhanced {
  return new SanitizerDiagnostics_Enhanced(security);
}

/**
 * Async version of createEnhancedSanitizerDiagnostics
 * @param security SecurityStringSanitizer instance
 * @returns Promise<SanitizerDiagnostics_EnhancedFinal>
 */
export async function createEnhancedSanitizerDiagnosticsAsync(
  security: SecurityStringSanitizer
): Promise<SanitizerDiagnostics_Enhanced> {
  return new SanitizerDiagnostics_Enhanced(security);
}

/**
 * Create a sanitizer system with enhanced diagnostics
 * - Full system: core + security + enhanced diagnostics
 * - Includes all enhanced tests (command injection, edge cases, internationalization)
 * - Perfect for comprehensive security validation and compliance checks
 *
 * @param config Optional partial configuration
 * @returns Object with core, security, and enhanced diagnostics
 *
 * @example
 * const system = await createEnhancedSanitizerSystemAsync({ environment: 'production' });
 * const report = await system.enhancedDiagnostics.runAllEnhanced({ deep: true });
 */
export async function createEnhancedSanitizerSystemAsync(
  config?: Partial<ISanitizerGlobalConfig>
) {
  const core = _createCoreOnlySanitizerImpl(config);
  const security = _createConfiguredSecuritySanitizerImpl(core);
  const diagnostics = _createSanitizerDiagnosticsImpl(security);
  const enhancedDiagnostics = new SanitizerDiagnostics_Enhanced(security);

  return {
    core,
    security,
    diagnostics,
    enhancedDiagnostics,
  };
}
