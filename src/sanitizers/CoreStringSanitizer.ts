// CoreStringSanitizer.ts

import {
  ISanitizationOptions,
  ISanitizationResult,
  ValidationStrategy,
  ISanitizerGlobalConfig,
  SanitizerPlugins,
} from "../types.js";

import {
  BaseSanitizer,
  NormalizedSanitizationOptions,
} from "./BaseSanitizer.js";
import { SanitizerError } from "../SanitizerError.js";

import { CharacterSecurity, ValidationStrategyRegistry } from "../validators/validaters.js";

/**
 * CoreStringSanitizer
 * -------------------
 * High-performance, pure sanitization engine.
 *
 * Responsibilities:
 * - Use BaseSanitizer to:
 *   - validate options
 *   - resolve mode & security level
 *   - convert input to string
 *   - enforce global bounds
 *   - resolve validation strategy
 * - Execute the full core sanitization pipeline:
 *   1. Validation
 *   2. Security-level character filtering
 *   3. Custom validator
 *   4. Sanitization
 *   5. Truncation
 *
 * DOES NOT:
 * - Log
 * - Rate limit
 * - Invoke plugins
 * - Detect abuse/suspicious patterns
 */
export class CoreStringSanitizer extends BaseSanitizer {
  constructor(
    /** Global configuration (shared across all sanitizers & diagnostics) */
     config: ISanitizerGlobalConfig,
    /** Validator registry (shared) */
     validationRegistry: ValidationStrategyRegistry
  ) {
    super(config, validationRegistry);
  }

  

  async sanitize(
    input: unknown,
    options: ISanitizationOptions
  ): Promise<ISanitizationResult> 
   {
    const { normalized, configWarnings } = this.validateAndNormalizeOptions(
      options,
      input
    );

    const result = await this.sanitizeWithNormalizedOptions(
      normalized,
      configWarnings
    );

    return result;
  }


    async sanitizeForStorage(
    input: unknown,
    options: Omit<ISanitizationOptions, "mode">
  ): Promise<string> {


    const result = await this.sanitize(
      input,
      { ...options, mode: "sanitize-for-storage" }
    );

    if (!result.isValid) {
      switch (options.onError || "throw") {
        case "throw":
          throw new SanitizerError(`Sanitization failed: ${result.errors.join("; ")}`);
        case "return-default":
          return options.defaultValue || "";
        case "return-original":
          return result.original;
      }
    }

    return result.sanitized;
  }

    async validate(
      input: unknown,
      options: Omit<ISanitizationOptions, "mode">
    ): Promise<{ isValid: boolean; errors: string[]; warnings: string[] }> {
      const result = await this.sanitize(
        input,
        { ...options, mode: "validate-only" }
      );
      return {
        isValid: result.isValid,
        errors: result.errors,
        warnings: result.warnings,
      };
    }
  /**
   * Internal entry point for callers that already have normalized options.
   */
  async sanitizeWithNormalizedOptions(
    options: NormalizedSanitizationOptions,
    configWarnings: string[] = []
  ): Promise<ISanitizationResult> {
    const startTime = performance.now();

    const original = options._converted;
    const bytesProcessed = options._bytes;
    const strategy = options._strategy;

    const initialWarnings: string[] = [...configWarnings];

    const {
      sanitized,
      errors,
      warnings,
      transformations,
    } = this.processWithStrategy(
      original,
      strategy,
      options,
      bytesProcessed,
      initialWarnings
    );

    const processingTimeMs = performance.now() - startTime;

    return {
      original,
      sanitized,
      sanitizeAs: options.sanitizeAs,
      isValid: errors.length === 0,
      errors,
      warnings,
      metadata: {
        processingTimeMs,
        mode: options.mode,
        bytesProcessed,
        transformations,
      },
    };
  }

  private processWithStrategy(
    original: string,
    strategy: ValidationStrategy,
    options: NormalizedSanitizationOptions,
    _bytesProcessed: number,
    initialWarnings: string[]
  ): {
    sanitized: string;
    errors: string[];
    warnings: string[];
    transformations: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [...initialWarnings];
    const transformations: string[] = [];

    try {
      // 1. VALIDATION
      const validation = strategy.validate(original, options);
      errors.push(...validation.errors);
      warnings.push(...validation.warnings);

      if (errors.length > 0) {
        return {
          sanitized: original,
          errors,
          warnings,
          transformations: ["validation-failed"],
        };
      }

      // 2. SECURITY LEVEL FILTERING
      let intermediate = original;
      if (options.mode === "sanitize-for-storage") {
        const sec = CharacterSecurity.applySecurityLevel(
          original,
          options.securityLevel
        );
        intermediate = sec.result;
        transformations.push(...sec.transformations);
        warnings.push(...sec.warnings);
      }

      // 3. CUSTOM VALIDATOR
      if (options.customValidator) {
        try {
          const result = options.customValidator(intermediate);
          if (result !== true) {
            errors.push(
              typeof result === "string" ? result : "Custom validation failed"
            );
          }
        } catch (e) {
          errors.push(
            `Validator Error: ${e instanceof Error ? e.message : String(e)}`
          );
          warnings.push("Custom validator threw an error");
        }
      }

      if (errors.length > 0) {
        return {
          sanitized: intermediate,
          errors,
          warnings,
          transformations: ["validation-failed"],
        };
      }

      // 4. SANITIZATION
      let sanitized = intermediate;
      if (options.mode === "sanitize-for-storage") {
        const sanitization = strategy.sanitize(intermediate, options);
        sanitized = sanitization.result;
        transformations.push(...sanitization.transformations);
        warnings.push(...sanitization.warnings);
      }

      // 5. TRUNCATION
      if (
        Number.isFinite(options.maxLength) &&
        sanitized.length > (options.maxLength ?? 0)
      ) {
        if (options.truncate) {
          sanitized = sanitized.substring(0, options.maxLength);
          transformations.push("final-truncation");
          warnings.push(
            `Final value truncated to ${options.maxLength} characters`
          );
        } else {
          errors.push(`Maximum length ${options.maxLength} exceeded`);
        }
      }

      return { sanitized, errors, warnings, transformations };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      errors.push(`Processing Error: ${errorMessage}`);
      warnings.push("An error occurred during processing");

      return {
        sanitized: original,
        errors,
        warnings,
        transformations: ["error-occurred"],
      };
    }
  }
}