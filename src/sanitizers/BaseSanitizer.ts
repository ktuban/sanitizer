// BaseSanitizer.ts
import {
  ISanitizationOptions,
  SecurityLevel,
  SanitizationMode,
  ISanitizerGlobalConfig,
  ValidationStrategy,
  SanitizerPlugins,
  SanitizeAs,
} from "../types.js";

import { ConfigValidator } from "../config/configValidator.js";
import { StringConverter, ValidationStrategyRegistry } from "../validators/validaters.js";

/**
 * Normalized sanitization options.
 */
export interface NormalizedSanitizationOptions extends ISanitizationOptions {
  securityLevel: SecurityLevel;
  mode: SanitizationMode;
  truncate: boolean;
  enum: any[];
  onError: "throw" | "return-default" | "return-original";
  defaultValue: string;

  /**
   * Added by BaseSanitizer:
   * - converted string value
   * - byte length
   * - resolved strategy
   */
  _converted: string;
  _bytes: number;
  _strategy: ValidationStrategy;
}

/**
 * Result of option validation and normalization.
 */
export interface OptionsNormalizationResult {
  normalized: NormalizedSanitizationOptions;
  configWarnings: string[];
}

/**
 * BaseSanitizer
 * -------------
 * The unified root class for all sanitizers.
 *
 * Responsibilities:
 * - Hold shared global config
 * - Hold shared validator registry
 * - Hold shared plugin instances
 * - Normalize options
 * - Convert input to string
 * - Enforce global bounds
 * - Resolve validation strategy
 *
 * Concrete sanitizers extend this class and implement sanitize().
 */
export abstract class BaseSanitizer {
  constructor(
    /** Global configuration (shared across all sanitizers & diagnostics) */
    public readonly config: ISanitizerGlobalConfig,

    /** Validator registry (shared) */
    public readonly validationRegistry: ValidationStrategyRegistry,

    /** Plugins (shared) */
    protected plugins?: SanitizerPlugins
  ) {}

  setPlugins(plugins: SanitizerPlugins){
    if(plugins) this.plugins = plugins;
  }
  /**
   * Validate and normalize SanitizationOptions into a fully-resolved structure.
   *
   * NEW responsibilities added:
   * - Convert input to string
   * - Enforce bounds BEFORE sanitization
   * - Resolve validation strategy
   */
  protected validateAndNormalizeOptions(
    options: ISanitizationOptions,
    input?: unknown
  ): OptionsNormalizationResult {
    // 1. Validate option structure
    const validation = ConfigValidator.validateOptions(options);

    if (!validation.valid) {
      throw new Error(`Invalid configuration: ${validation.errors.join("; ")}`);
    }

    // 2. Resolve mode + security level
    const mode: SanitizationMode = options.mode || "sanitize-for-storage";
    const securityLevel: SecurityLevel =
      options.securityLevel ||
      this.config.securityLevels[options.sanitizeAs];

    // 3. Credit card storage restriction
    if (options.sanitizeAs === "credit-card" && mode === "sanitize-for-storage") {
      throw new Error(
        'Credit card data must not be stored. Use { mode: "validate-only" }.'
      );
    }

    // 4. Convert input to string (if provided)
    let converted = "";
    let conversionWarnings: string[] = [];
    let bytes = 0;

    if (input !== undefined) {
      const conversion = StringConverter.toString(input, options.sanitizeAs);
      converted = conversion.value;
      conversionWarnings = conversion.warnings;
      bytes = Buffer.byteLength(converted, "utf8");
    }

    // 5. Bounds checking (if input provided)
    if (input !== undefined) {
      ConfigValidator.validateInputBounds(
        converted,
        options.sanitizeAs as SanitizeAs,
        bytes
      );
    }

    // 6. Resolve strategy
    const strategy = this.validationRegistry.getStrategy(options.sanitizeAs);
    if (!strategy) {
      throw new Error(
        `No validator registered for sanitizeAs='${options.sanitizeAs}'`
      );
    }

    // 7. Build normalized options
    const normalized: NormalizedSanitizationOptions = {
      sanitizeAs: options.sanitizeAs,
      securityLevel,
      mode,
      minLength: options.minLength ?? 0,
      maxLength: options.maxLength ?? Infinity,
      pattern: options.pattern ?? undefined,
      patternDescription: options.patternDescription ?? "",
      enum: options.enum ?? [],
      html: options.html ?? undefined,
      truncate: options.truncate ?? false,
      customValidator: options.customValidator,
      onError: options.onError ?? "throw",
      defaultValue: options.defaultValue ?? "",
      fieldName: options.fieldName ?? "",

      // NEW internal fields
      _converted: converted,
      _bytes: bytes,
      _strategy: strategy,
    };

    return {
      normalized,
      configWarnings: [...validation.warnings, ...conversionWarnings],
    };
  }
}