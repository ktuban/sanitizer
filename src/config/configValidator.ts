/**
 * ConfigValidator (Unified + Env‑Integrated + Industry‑Grade)
 * -----------------------------------------------------------
 * Single source of truth for all sanitizer configuration.
 *
 * Responsibilities:
 * - Hold global configuration (ISanitizerGlobalConfig)
 * - Initialize defaults
 * - Apply user overrides
 * - Apply environment presets (dev, test, staging, production)
 * - Apply SANITIZER_* environment variable overrides
 * - Apply environmentOverrides from config
 * - Validate global configuration
 * - Validate and normalize per-call SanitizationOptions
 * - Enforce input bounds
 * - Provide recommended modes and security levels
 */

import { stringify } from "safe-stable-stringify";
import { ISanitizerGlobalConfig, ISanitizationOptions, SanitizeAsValidTypesValue, SanitizeAs, SanitizationMode, SecurityLevel, recommendedSecurityLevelsValue } from "../types.js";


export class ConfigValidator {
  private static globalConfig: ISanitizerGlobalConfig | null = null;
  private static configValidators = new Map<string, (value: any) => boolean>();
  private static environment = process.env['NODE_ENV'] || 'development';

  // ============================================================
  // PUBLIC API
  // ============================================================

  /**
   * Initialize global configuration.
   *
   * ORDER OF PRECEDENCE (highest → lowest):
   * 1. User overrides passed to initialize()
   * 2. Environment variable overrides (SANITIZER_*)
   * 3. Environment presets (dev/test/staging/prod)
   * 4. environmentOverrides from config
   * 5. Internal defaults
   */
  static initialize(overrides?: Partial<ISanitizerGlobalConfig>): void {
    // 1. Start from internal defaults
    this.globalConfig = this.createDefaultConfig();

    // 2. Apply user overrides
    if (overrides) {
      this.globalConfig = this.mergeConfigs(this.globalConfig, overrides);
    }

    // 3. Apply environment preset (dev/test/staging/prod)
    this.applyEnvironmentPreset(this.environment);

    // 4. Apply SANITIZER_* environment variable overrides
    this.applyEnvVarOverrides();

    // 5. Apply environmentOverrides from config
    this.applyEnvironmentConfig();

    // 6. Validate final configuration
    const errors = this.validateGlobalConfig();
    if (errors.length > 0) {
      throw new Error(`Invalid configuration: ${errors.join('; ')}`);
    }
  }

  /**
   * Validate and normalize SanitizationOptions.
   * Applies global defaults and type defaults.
   */
  static validateOptions(options: ISanitizationOptions): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Required
    if (!options.sanitizeAs) {
      errors.push('"sanitizeAs" is required');
    }

    // sanitizeAs type validation
    if (options.sanitizeAs && !SanitizeAsValidTypesValue.includes(options.sanitizeAs)) {
      errors.push(`Invalid sanitizeAs type: ${options.sanitizeAs}`);
    }

    // Security level validation
    if (options.securityLevel && !['low', 'medium', 'high', 'paranoid'].includes(options.securityLevel)) {
      errors.push('Invalid securityLevel. Must be one of: low, medium, high, paranoid');
    }

    // Mode validation
    if (options.mode && !['validate-only', 'sanitize-for-storage'].includes(options.mode)) {
      errors.push('Invalid mode. Must be either "validate-only" or "sanitize-for-storage"');
    }

    // Credit card rule
    if (options.sanitizeAs === 'credit-card' && options.mode === 'sanitize-for-storage') {
      errors.push('Credit card data must not be stored. Use mode: "validate-only".');
    }

    // Length constraints
    this.validateLengthConstraints(options, errors, warnings);

    // Credit card specifics
    if (options.sanitizeAs === 'credit-card') {
      this.validateCreditCardOptions(options, errors, warnings);
    }

    // HTML config
    if (options.html) {
      this.validateHtmlOptions(options.html, errors, warnings);
    }

    // Pattern
    if (options.pattern && !(options.pattern instanceof RegExp)) {
      errors.push('pattern must be a RegExp');
    }

    // Enum
    if (options.enum && !Array.isArray(options.enum)) {
      errors.push('enum must be an array');
    }

    // Custom validator
    if (options.customValidator && typeof options.customValidator !== 'function') {
      errors.push('customValidator must be a function');
    }

    // onError
    if (options.onError && !['throw', 'return-default', 'return-original'].includes(options.onError)) {
      errors.push('onError must be one of: throw, return-default, return-original');
    }

    // Apply global defaults
    if (this.globalConfig) {
      this.applyGlobalDefaults(options);
    }

    // Additional recommendations
    if (options.mode === 'sanitize-for-storage' && options.securityLevel === 'low') {
      warnings.push('Using low security level for storage may be unsafe');
    }

    if (options.sanitizeAs === 'html' && options.mode === 'validate-only') {
      warnings.push('HTML validate-only may not be sufficient; consider sanitization');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate input bounds (size, length, type-specific limits).
   */
  static validateInputBounds(value: string, type: SanitizeAs, bytes: number): void {
    const cfg = this.getEffectiveConfig();
    const c = cfg.securityConstants;

    if (bytes > c.MAX_INPUT_BYTES) {
      throw new Error(
        `Input too large: ${bytes} bytes exceeds ${c.MAX_INPUT_BYTES}`
      );
    }

    if ((type === 'html' || type === 'html-attribute') && bytes > c.MAX_HTML_BYTES) {
      throw new Error(
        `HTML input too large: ${bytes} bytes exceeds ${c.MAX_HTML_BYTES}`
      );
    }

    if (type === 'json' && bytes > c.MAX_JSON_BYTES) {
      throw new Error(
        `JSON input too large: ${bytes} bytes exceeds ${c.MAX_JSON_BYTES}`
      );
    }

    if (value.length > c.MAX_STRING_LENGTH) {
      throw new Error(
        `Input too long: ${value.length} characters exceeds ${c.MAX_STRING_LENGTH}`
      );
    }

    if (type === 'filename' && value.length > c.MAX_FILENAME_LENGTH) {
      throw new Error(
        `Filename too long: ${value.length} characters exceeds ${c.MAX_FILENAME_LENGTH}`
      );
    }

    if (type === 'credit-card' && bytes > 1024) {
      throw new Error('Credit card input too large');
    }
  }

  /**
   * Get effective config (defaults + overrides + env).
   */
  static getEffectiveConfig(): ISanitizerGlobalConfig {
    if (!this.globalConfig) {
      this.initialize();
    }

    const cfg = this.globalConfig!;
    const env = this.environment;

    if (cfg.environmentOverrides[env]) {
      return this.mergeConfigs(cfg, cfg.environmentOverrides[env]!);
    }

    return cfg;
  }

  /**
   * Update config at runtime.
   */
  static updateConfig(updates: Partial<ISanitizerGlobalConfig>): void {
    if (!this.globalConfig) {
      throw new Error('ConfigValidator not initialized');
    }

    const merged = this.mergeConfigs(this.globalConfig, updates);
    const errors = this.validateGlobalConfigInternal(merged);

    if (errors.length > 0) {
      throw new Error(`Invalid configuration update: ${errors.join('; ')}`);
    }

    this.globalConfig = merged;
  }

  /**
   * Export config as JSON or YAML.
   */
  static exportConfig(format: 'json' | 'yaml' = 'json'): string {
    const cfg = this.getEffectiveConfig();

    if (format === 'json') {
      return stringify(cfg, null, 2);
    }

    const lines: string[] = [];
    this.configToYaml(cfg, lines);
    return lines.join('\n');
  }

  /**
   * Reset to defaults, re-applying env preset + env vars + environmentOverrides.
   */
  static resetConfig(): void {
    this.globalConfig = this.createDefaultConfig();
    this.applyEnvironmentPreset(this.environment);
    this.applyEnvVarOverrides();
    this.applyEnvironmentConfig();
  }

  /**
   * Recommended mode for a given sanitizeAs.
   */
  static getRecommendedMode(sanitizeAs: SanitizeAs): SanitizationMode {
    switch (sanitizeAs) {
      case 'credit-card':
      case 'password':
        return 'validate-only';
      default:
        return 'sanitize-for-storage';
    }
  }

  /**
   * Recommended security level for a given sanitizeAs and mode.
   */
  static getRecommendedSecurityLevel(
    sanitizeAs: SanitizeAs,
    mode?: SanitizationMode
  ): SecurityLevel {
    const level = recommendedSecurityLevelsValue[sanitizeAs];
    return mode === 'validate-only' ? (level || 'low') : (level || 'high');
  }

  // ============================================================
  // ENV / OVERRIDES
  // ============================================================

  /**
   * Apply environment presets based on NODE_ENV.
   * These are coarse-grained, opinionated defaults for dev/test/staging.
   */
  private static applyEnvironmentPreset(env: string): void {
    const cfg = this.globalConfig!;
    switch (env) {
      case 'production':
        return;

      case 'staging':
        cfg.securityLevels.html = 'high';
        cfg.securityLevels['html-attribute'] = 'high';
        cfg.securityLevels['plain-text'] = 'medium';
        cfg.auditLogging.logLevels = ['CRITICAL', 'HIGH'];
        return;

      case 'development':
      case 'test':
        cfg.securityLevels.html = 'medium';
        cfg.securityLevels['html-attribute'] = 'medium';
        cfg.securityLevels['plain-text'] = 'low';
        cfg.rateLimiting.enabled = false;
        cfg.auditLogging.enabled = false;
        cfg.securityConstants.MAX_HTML_BYTES = 5 * 1024 * 1024;
        cfg.securityConstants.MAX_JSON_BYTES = 50 * 1024 * 1024;
        return;
    }
  }

  /**
   * Apply SANITIZER_* environment variable overrides.
   * These are fine-grained, explicit overrides.
   */
  private static applyEnvVarOverrides(): void {
    const cfg = this.globalConfig!;

    // SANITIZER_SECURITY_LEVEL=low|medium|high|paranoid
    if (process.env['SANITIZER_SECURITY_LEVEL']) {
      const level = process.env['SANITIZER_SECURITY_LEVEL'] as SecurityLevel;
      Object.keys(cfg.securityLevels).forEach(key => {
        cfg.securityLevels[key as SanitizeAs] = level;
      });
    }

    // SANITIZER_RATE_LIMIT=200
    if (process.env['SANITIZER_RATE_LIMIT']) {
      cfg.rateLimiting.requestsPerMinute = parseInt(
        process.env['SANITIZER_RATE_LIMIT']!,
        10
      );
    }

    // SANITIZER_MAX_JSON_BYTES=...
    if (process.env['SANITIZER_MAX_JSON_BYTES']) {
      cfg.securityConstants.MAX_JSON_BYTES = parseInt(
        process.env['SANITIZER_MAX_JSON_BYTES']!,
        10
      );
    }

    // SANITIZER_MAX_HTML_BYTES=...
    if (process.env['SANITIZER_MAX_HTML_BYTES']) {
      cfg.securityConstants.MAX_HTML_BYTES = parseInt(
        process.env['SANITIZER_MAX_HTML_BYTES']!,
        10
      );
    }

    // SANITIZER_MAX_STRING_LENGTH=...
    if (process.env['SANITIZER_MAX_STRING_LENGTH']) {
      cfg.securityConstants.MAX_STRING_LENGTH = parseInt(
        process.env['SANITIZER_MAX_STRING_LENGTH']!,
        10
      );
    }

    // SANITIZER_AUDIT_ENABLED=true/false
    if (process.env['SANITIZER_AUDIT_ENABLED']) {
      cfg.auditLogging.enabled = process.env['SANITIZER_AUDIT_ENABLED'] === 'true';
    }
  }

  /**
   * Apply environmentOverrides section from config (per-env, deep overrides).
   */
  private static applyEnvironmentConfig(): void {
    if (!this.globalConfig) return;

    const env = this.environment;
    const overrides = this.globalConfig.environmentOverrides[env];

    if (overrides) {
      this.globalConfig = this.mergeConfigs(this.globalConfig, overrides);
    }
  }

  // ============================================================
  // VALIDATION HELPERS
  // ============================================================

  private static validateGlobalConfig(): string[] {
    if (!this.globalConfig) {
      return ['Configuration not initialized'];
    }
    return this.validateGlobalConfigInternal(this.globalConfig);
  }

  private static validateGlobalConfigInternal(
    config: ISanitizerGlobalConfig
  ): string[] {
    const errors: string[] = [];

    // Security levels
    SanitizeAsValidTypesValue.forEach(type => {
      if (!config.securityLevels[type]) {
        errors.push(`Missing security level for type: ${type}`);
      }
    });

    // Security constants
    const c = config.securityConstants;
    if (c.MAX_INPUT_BYTES <= 0) errors.push('MAX_INPUT_BYTES must be positive');
    if (c.MAX_HTML_BYTES <= 0) errors.push('MAX_HTML_BYTES must be positive');
    if (c.MAX_JSON_BYTES <= 0) errors.push('MAX_JSON_BYTES must be positive');
    if (c.MAX_STRING_LENGTH <= 0) errors.push('MAX_STRING_LENGTH must be positive');
    if (c.MAX_FILENAME_LENGTH <= 0) errors.push('MAX_FILENAME_LENGTH must be positive');

    // HTML defaults
    if (config.htmlDefaults.allowedTags?.length === 0) {
      errors.push('HTML allowedTags cannot be empty');
    }

    const conflict = config.htmlDefaults.allowedTags?.find(tag =>
      config.htmlDefaults.forbiddenTags?.includes(tag)
    );
    if (conflict) {
      errors.push(`HTML tag conflict: ${conflict} is both allowed and forbidden`);
    }

    // Rate limiting
    if (config.rateLimiting.requestsPerMinute <= 0) {
      errors.push('requestsPerMinute must be positive');
    }
    if (config.rateLimiting.blockDurationMs <= 0) {
      errors.push('blockDurationMs must be positive');
    }

    return errors;
  }

  private static validateLengthConstraints(
    options: ISanitizationOptions,
    errors: string[],
    warnings: string[]
  ): void {
    if (options.minLength !== undefined && options.minLength < 0) {
      errors.push('minLength cannot be negative');
    }

    if (options.maxLength !== undefined && options.maxLength < 0) {
      errors.push('maxLength cannot be negative');
    }

    if (
      options.minLength !== undefined &&
      options.maxLength !== undefined &&
      options.minLength > options.maxLength
    ) {
      errors.push('minLength cannot be greater than maxLength');
    }

    if (options.truncate && !options.maxLength) {
      warnings.push('truncate is enabled but maxLength is not specified');
    }

    if (options.sanitizeAs === 'email' && options.maxLength && options.maxLength > 254) {
      warnings.push('Email addresses should not exceed 254 characters');
    }

    if (options.sanitizeAs === 'password' && options.minLength && options.minLength < 8) {
      warnings.push('Password minimum length should be at least 8 characters');
    }
  }

  private static validateCreditCardOptions(
    options: ISanitizationOptions,
    errors: string[],
    warnings: string[]
  ): void {
    if (options.mode && options.mode !== 'validate-only') {
      errors.push('Credit card must use mode: "validate-only" (never store credit card data)');
    }

    if (!options.mode) {
      warnings.push('Credit card mode automatically set to "validate-only" for security');
    }

    if (options.securityLevel && options.securityLevel === 'low') {
      warnings.push('Credit card validation should use high or paranoid security level');
    }

    if (options.truncate) {
      errors.push('Credit card numbers must not be truncated');
    }

    if (options.onError === 'return-original') {
      warnings.push('Credit card validation should not return original value on error');
    }
  }

  private static validateHtmlOptions(
    html: NonNullable<ISanitizationOptions['html']>,
    errors: string[],
    warnings: string[]
  ): void {
    if (html.allowedTags && html.forbiddenTags) {
      const conflict = html.allowedTags.find(tag => html.forbiddenTags!.includes(tag));
      if (conflict) {
        errors.push(`HTML tag conflict: '${conflict}' is both allowed and forbidden`);
      }
    }

    if (html.allowedAttributes) {
      Object.entries(html.allowedAttributes).forEach(([tag, attrs]) => {
        if (!Array.isArray(attrs)) {
          errors.push(`allowedAttributes for tag '${tag}' must be an array`);
        }
      });
    }

    if (html.allowDataAttributes && html.forbiddenAttributes?.includes('data-*')) {
      warnings.push('Data attributes are both allowed and forbidden');
    }

    if (html.allowComments) {
      warnings.push('HTML comments are allowed - potential security risk');
    }
  }

  // ============================================================
  // DEFAULT APPLICATION TO OPTIONS
  // ============================================================

  /**
   * Apply global defaults (securityLevels, typeDefaults, HTML defaults, credit-card hardening, default mode).
   * Mutates the given options object.
   */
  private static applyGlobalDefaults(options: ISanitizationOptions): void {
    if (!this.globalConfig) return;

    const cfg = this.globalConfig;
    const result = options;

    // Security level default
    if (!result.securityLevel && cfg.securityLevels[result.sanitizeAs]) {
      result.securityLevel = cfg.securityLevels[result.sanitizeAs];
    }

    // Type defaults
    const typeDefaults = cfg.typeDefaults[result.sanitizeAs];
    if (typeDefaults) {
      Object.keys(typeDefaults).forEach(key => {
        const k = key as keyof ISanitizationOptions;
        if (result[k] === undefined) {
          (result as any)[k] = typeDefaults[k as keyof typeof typeDefaults];
        }
      });
    }

    // Credit card hardening
    if (result.sanitizeAs === 'credit-card') {
      result.mode = 'validate-only';

      if (!result.securityLevel || result.securityLevel === 'low') {
        result.securityLevel = 'paranoid';
      }

      result.truncate = false;

      if (!result.onError || result.onError === 'return-original') {
        result.onError = 'throw';
        result.defaultValue = '';
      }
    }

    // HTML defaults
    if (
      (result.sanitizeAs === 'html' || result.sanitizeAs === 'html-attribute') &&
      !result.html
    ) {
      result.html = { ...cfg.htmlDefaults };
    } else if (result.html) {
      result.html = {
        ...cfg.htmlDefaults,
        ...result.html,
        allowedTags: result.html.allowedTags || cfg.htmlDefaults.allowedTags,
        allowedAttributes:
          result.html.allowedAttributes || cfg.htmlDefaults.allowedAttributes,
        forbiddenTags:
          result.html.forbiddenTags || cfg.htmlDefaults.forbiddenTags,
        forbiddenAttributes:
          result.html.forbiddenAttributes || cfg.htmlDefaults.forbiddenAttributes,
      };
    }

    // Default mode: sanitize-for-storage for most, validate-only for sensitive types
    if (!result.mode) {
      result.mode =
        result.sanitizeAs === 'credit-card' || result.sanitizeAs === 'password'
          ? 'validate-only'
          : 'sanitize-for-storage';
    }
  }

  // ============================================================
  // MERGE / YAML / DEFAULT CONFIG
  // ============================================================

  private static mergeConfigs(
    base: ISanitizerGlobalConfig,
    updates: Partial<ISanitizerGlobalConfig>
  ): ISanitizerGlobalConfig {
    const merged = { ...base };

    if (updates.securityConstants) {
      merged.securityConstants = { ...base.securityConstants, ...updates.securityConstants };
    }
    if (updates.securityLevels) {
      merged.securityLevels = { ...base.securityLevels, ...updates.securityLevels };
    }
    if (updates.typeDefaults) {
      merged.typeDefaults = { ...base.typeDefaults, ...updates.typeDefaults };
    }
    if (updates.htmlDefaults) {
      merged.htmlDefaults = { ...base.htmlDefaults, ...updates.htmlDefaults };
    }
    if (updates.rateLimiting) {
      merged.rateLimiting = { ...base.rateLimiting, ...updates.rateLimiting };
    }
    if (updates.auditLogging) {
      merged.auditLogging = { ...base.auditLogging, ...updates.auditLogging };
    }
    if (updates.performance) {
      merged.performance = { ...base.performance, ...updates.performance };
    }
    if (updates.environmentOverrides) {
      merged.environmentOverrides = {
        ...base.environmentOverrides,
        ...updates.environmentOverrides,
      };
    }

    return merged;
  }

  private static configToYaml(obj: any, lines: string[], indent = 0): void {
    const pad = ' '.repeat(indent);
    for (const [key, value] of Object.entries(obj)) {
      if (value === null || value === undefined) continue;

      if (typeof value === 'object' && !(value instanceof RegExp) && !(value instanceof Set)) {
        lines.push(`${pad}${key}:`);
        this.configToYaml(value, lines, indent + 2);
      } else if (value instanceof Set) {
        lines.push(`${pad}${key}:`);
        for (const v of value) {
          lines.push(`${pad}  - "${v}"`);
        }
      } else if (value instanceof RegExp) {
        lines.push(`${pad}${key}: "${value.toString()}"`);
      } else if (typeof value === 'string') {
        lines.push(`${pad}${key}: "${value}"`);
      } else {
        lines.push(`${pad}${key}: ${value}`);
      }
    }
  }

  /**
   * Single place where internal defaults are defined.
   */
  private static createDefaultConfig(): ISanitizerGlobalConfig {
    return {
      securityConstants: {
        MAX_INPUT_BYTES: 10 * 1024 * 1024,   // 10MB global cap
        MAX_HTML_BYTES: 1 * 1024 * 1024,     // 1MB HTML cap
        MAX_JSON_BYTES: 10 * 1024 * 1024,    // 10MB JSON cap
        MAX_STRING_LENGTH: 10000,
        MAX_FILENAME_LENGTH: 255,
        ALLOWED_URL_PROTOCOLS: new Set([
          'http:',
          'https:',
          'mailto:',
          'ftp:',
          'tel:',
          'sms:',
        ]),
      },

      securityLevels: recommendedSecurityLevelsValue,

      typeDefaults: {
        email: {
          minLength: 5,
          maxLength: 254,
          pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
          patternDescription: 'valid email format',
          mode: 'sanitize-for-storage',
          securityLevel: 'high',
        },
        password: {
          minLength: 8,
          maxLength: 128,
          pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/,
          patternDescription: 'must contain uppercase, lowercase, and number',
          mode: 'validate-only',
          securityLevel: 'high',
        },
        username: {
          minLength: 2,
          maxLength: 30,
          pattern: /^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,28}[a-zA-Z0-9])?$/,
          patternDescription: 'alphanumeric with underscores or hyphens',
          mode: 'sanitize-for-storage',
          securityLevel: 'medium',
        },
        phone: {
          pattern: /^\+[1-9]\d{1,14}$|^[2-9]\d{9}$|^[2-9]\d{6}$/,
          patternDescription: 'valid phone number format',
          mode: 'sanitize-for-storage',
          securityLevel: 'medium',
        },
        'credit-card': {
          mode: 'validate-only',
          minLength: 13,
          maxLength: 19,
          securityLevel: 'paranoid',
        },
        url: {
          maxLength: 2048,
          pattern: /^(https?|ftp|mailto|tel):\/\/.+/,
          patternDescription: 'valid URL with allowed protocol',
          mode: 'sanitize-for-storage',
          securityLevel: 'high',
        },
        filename: {
          maxLength: 255,
          pattern: /^[^<>:"/\\|?*]+$/,
          patternDescription: 'valid filename without illegal characters',
          mode: 'sanitize-for-storage',
          securityLevel: 'high',
        },
        html: {
          securityLevel: 'paranoid',
          mode: 'sanitize-for-storage',
        },
        'html-attribute': {
          securityLevel: 'paranoid',
          mode: 'sanitize-for-storage',
        },
      },

      htmlDefaults: {
        allowedTags: [
          'p',
          'b',
          'i',
          'u',
          'em',
          'strong',
          'a',
          'br',
          'ul',
          'ol',
          'li',
        ],
        allowedAttributes: {
          a: ['href', 'title', 'target'],
          p: ['class'],
          span: ['class'],
        },
        forbiddenTags: ['script', 'style', 'iframe', 'object', 'embed'],
        forbiddenAttributes: ['onclick', 'onload', 'onerror', 'style'],
        allowComments: false,
        allowDataAttributes: false,
      },

      rateLimiting: {
        enabled: true,
        requestsPerMinute: 100,
        blockDurationMs: 300000,
        suspiciousPatterns: ['<script>', 'javascript:', 'eval(', 'union select'],
      },

      auditLogging: {
        enabled: true,
        logLevels: ['MEDIUM', 'HIGH', 'CRITICAL'],
        destination: 'console',
        maxLogs: 10000,
        retentionDays: 30,
        alertOn: ['CRITICAL'],
        redactFields: ["password", "token", "authorization", "creditCard"]
      },

      performance: {
        cacheEnabled: true,
        maxCacheSize: 1000,
        cleanupIntervalMs: 60000,
      },

      environmentOverrides: {
        production: {
          auditLogging: {
            destination: 'file',
            filePath: '/var/log/sanitizer.log',
          } as any,
          rateLimiting: {
            requestsPerMinute: 50,
          } as any,
        },
        test: {
          performance: {
            cacheEnabled: false,
          } as any,
        },
      },
    };
  }
}