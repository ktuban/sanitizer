// SecurityStringSanitizer.ts

import {
  ISanitizationOptions,
  ISanitizationResult,
  SanitizationMode,
  IAuditLogEntry,
  ISanitizerGlobalConfig,
  SanitizerContext,
  SanitizerPlugins,
  SanitizeAs,
  ValidationStrategy,
} from "../types.js";
import { ValidationStrategyRegistry } from "../validators/validaters.js";

import { BaseSanitizer } from "./BaseSanitizer.js";
import { CoreStringSanitizer } from "./CoreStringSanitizer.js";
import { SanitizerError } from "../SanitizerError.js";

/**
 * SecurityStringSanitizer
 * -----------------------
 * Security-aware decorator that wraps CoreStringSanitizer.
 *
 * Responsibilities:
 * - Delegate normalization + core pipeline to CoreStringSanitizer
 * - Apply rate limiting
 * - Detect suspicious patterns
 * - Audit log security events & sanitization outcomes
 * - Track metrics
 * - Provide health & observability hooks
 *
 * DOES NOT:
 * - Implement the actual sanitization pipeline (delegates to core)
 * - Re-run validateAndNormalizeOptions (done once in core)
 */
export class SecurityStringSanitizer  {
  private metrics = {
    calls: 0,
    validationFailures: 0,
    securityEvents: 0,
    processingTimeMs: 0,
    lastReset: Date.now(),
  };

  constructor(
  public readonly plugins: SanitizerPlugins,
  public readonly core: CoreStringSanitizer
  ) {
   
  }

  async sanitize(
    input: unknown,
    options: ISanitizationOptions,
    context?: SanitizerContext
  ): Promise<ISanitizationResult> {
    const startTime = performance.now();
    this.metrics.calls++;

    const type = options.sanitizeAs;
    const { abusePrevention, auditLogger } = this.plugins;

    try {

            // 2. Rate limiting (if plugin + context)
      if (context && context?.ipAddress && abusePrevention) {
        const rateLimit = abusePrevention.checkRateLimit(context?.ipAddress);

        if (!rateLimit.allowed) {
          this.metrics.securityEvents++;
          auditLogger?.logSecurityEvent({
            severity: 'HIGH',
            type: 'SECURITY',
            message: 'Rate limit exceeded',
            details: {
              ipAddress: context.ipAddress,
              message: rateLimit.message,
              requestId: context.requestId,
              type,
            },
            userId: context?.userId,
            ipAddress: context?.ipAddress,
          });
          throw new SanitizerError(`Rate limit exceeded: ${rateLimit.message}`);
        
        }
      }
      // 1. Delegate to core with exposeNormalized=true (normalization + pipeline)
      const coreResult = await this.core.sanitize(input,options);

     // const mode: SanitizationMode = normalized.mode;

      // 2. Rate limiting (if plugin + context)
      /*
      if (abusePrevention && context?.ipAddress && mode !== "validate-only") {
        const rateLimit = abusePrevention.checkRateLimit(context.ipAddress);
        if (!rateLimit.allowed) {
          this.metrics.securityEvents++;
          auditLogger?.logSecurityEvent({
            severity: "HIGH",
            type: "SECURITY",
            message: "Rate limit exceeded",
            details: {
              ipAddress: context.ipAddress,
              message: rateLimit.message,
              type,
            },
            userId: context?.userId,
            ipAddress: context?.ipAddress,
          });
          throw new SanitizerError(`Rate limit exceeded: ${rateLimit.message}`);
        }
      }
      */
      // 3. Suspicious pattern detection
      const warnings = [...coreResult.warnings];
      let suspicious = false;

      if (abusePrevention) {
        const check = abusePrevention.detectSuspiciousPatterns(
          coreResult.original,
          type as SanitizeAs
        );
        if (check.suspicious) {
          suspicious = true;
          this.metrics.securityEvents++;
          warnings.push(...check.reasons.map((r) => `Security: ${r}`));

          auditLogger?.logSecurityEvent({
            severity: "MEDIUM",
            type: "SECURITY",
            message: "Suspicious input pattern detected",
            details: {
              type,
              patterns: check.reasons,
              inputLength: coreResult.original.length,
              context,
            },
            userId: context?.userId,
            ipAddress: context?.ipAddress,
          requestId:context?.requestId
          });
        }
      }

      const processingTimeMs = performance.now() - startTime;

      const result: ISanitizationResult = {
        ...coreResult,
        warnings,
        metadata: {
          ...coreResult.metadata,
          processingTimeMs,
        },
      };

      if (!result.isValid) {
        this.metrics.validationFailures++;
      }

      this.metrics.processingTimeMs += result.metadata.processingTimeMs;

      // 4. Audit log sanitization outcome
      if (!result.isValid || result.warnings.length > 0 || suspicious) {
        const severity: IAuditLogEntry["severity"] = !result.isValid
          ? "HIGH"
          : result.warnings.length > 0
          ? "MEDIUM"
          : "LOW";

        auditLogger?.logSanitization({
          timestamp: new Date().toISOString(),
          severity,
          type: "SANITIZATION",
          message: `Sanitization ${
            result.isValid ? "completed" : "failed"
          } for ${type}`,
          details: {
            type,
            isValid: result.isValid,
            errors: result.errors,
            warnings: result.warnings,
            inputLength: result.original.length,
            processingTime: result.metadata.processingTimeMs,
            fieldName: options.fieldName,
            context,
          },
          userId: context?.userId,
          ipAddress: context?.ipAddress,
          requestId:context?.requestId
        });
      }

      return result;
    } catch (error:any) {
      const errorMessage:string = error  ? error.message : String(error);
      if(errorMessage?.startsWith("Rate limit exceeded")){
        throw error
      }
      // 5. Error handling + security logging
      this.metrics.securityEvents++;

      
      this.plugins.auditLogger?.logSecurityEvent({
        severity: "HIGH",
        type: "SECURITY",
        message: "Sanitization error",
        details: {
          error: errorMessage,
          type,
          stack: error ? error.stack : undefined,
          context,
        },
        userId: context?.userId,
        ipAddress: context?.ipAddress,
        requestId:context?.requestId
      });

      const processingTimeMs = performance.now() - startTime;
      const original = String(input);

      return {
        original,
        sanitized: original,
        sanitizeAs: type,
        isValid: false,
        errors: [errorMessage],
        warnings: [],
        metadata: {
          processingTimeMs,
          mode: options.mode || "sanitize-for-storage",
          bytesProcessed: Buffer.byteLength(original, "utf8"),
          transformations: ["error-occurred"],
        },
      };
    }
  }

  // Convenience wrappers

//  async sanitizeSimple(
//    input: unknown,
//    options: ISanitizationOptions
//  ): Promise<ISanitizationResult> {
//    return this.sanitize(input, options);
//  }

  async validate(
    input: unknown,
    options: Omit<ISanitizationOptions, "mode">,
    context?: SanitizerContext
  ): Promise<{ isValid: boolean; errors: string[]; warnings: string[] }> {
    const result = await this.sanitize(
      input,
      { ...options, mode: "validate-only" },
      context
    );
    return {
      isValid: result.isValid,
      errors: result.errors,
      warnings: result.warnings,
    };
  }

  async sanitizeForStorage(
    input: unknown,
    options: Omit<ISanitizationOptions, "mode">,
    context?: SanitizerContext
  ): Promise<string> {


    const result = await this.sanitize(
      input,
      { ...options, mode: "sanitize-for-storage" },
      context
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

  // Metrics & observability

  getMetrics() {
    const now = Date.now();
    const elapsedSeconds = (now - this.metrics.lastReset) / 1000;

    return {
      ...this.metrics,
      callsPerSecond:
        elapsedSeconds > 0 ? this.metrics.calls / elapsedSeconds : 0,
      avgProcessingTimeMs:
        this.metrics.calls > 0
          ? this.metrics.processingTimeMs / this.metrics.calls
          : 0,
      securityEventsPerMinute:
        elapsedSeconds > 0
          ? (this.metrics.securityEvents / elapsedSeconds) * 60
          : 0,
      failureRate:
        this.metrics.calls > 0
          ? (this.metrics.validationFailures / this.metrics.calls) * 100
          : 0,
    };
  }

  resetMetrics(): void {
    this.metrics = {
      calls: 0,
      validationFailures: 0,
      securityEvents: 0,
      processingTimeMs: 0,
      lastReset: Date.now(),
    };
  }

  getSecurityStatus() {
    const abuseStatus = this.plugins.abusePrevention?.getStatus() ?? {
      blockedIPs: 0,
      activeRequests: 0,
      lastCleanup: undefined,
    };
    return {
      ...abuseStatus,
      securityEvents: this.metrics.securityEvents,
    };
  }

  getAuditLogs(filter?: {
    severity?: string;
    type?: string;
    startTime?: Date;
    endTime?: Date;
  }): IAuditLogEntry[] {
    
    return this.plugins.auditLogger?.getLogs(filter) ?? [];
  }

  exportAuditLogs(format: "json" | "csv" | "text" = "json"): string {
    return this.plugins.auditLogger?.exportLogs(format) ?? "";
  }

  clearAuditLogs(): void {
    this.plugins.auditLogger?.clearLogs();
  }

  unblockIP(ipAddress: string): boolean {
    return this.plugins.abusePrevention?.unblockIP(ipAddress) ?? false;
  }

  async healthCheck(): Promise<{
    status: "healthy" | "degraded" | "unhealthy";
    details: Record<string, any>;
  }> {
    const metrics = this.getMetrics();
    const securityStatus = this.getSecurityStatus();

    let status: "healthy" | "degraded" | "unhealthy" = "healthy";
    const details: Record<string, any> = {
      uptime: Date.now() - this.metrics.lastReset,
      ...metrics,
      ...securityStatus,
    };

    if (securityStatus.blockedIPs > 10) {
      status = "degraded";
      details["issue"] = "High number of blocked IPs";
    }

    if (metrics.failureRate > 20) {
      status = "degraded";
      details["issue"] = "High validation failure rate";
    }

    if (metrics.avgProcessingTimeMs > 1000) {
      status = "degraded";
      details["issue"] = "High processing time";
    }

    if (securityStatus.securityEvents > 100) {
      status = "unhealthy";
      details["issue"] = "High security event rate";
    }

    return { status, details };
  }
}