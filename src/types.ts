// types.ts

export type SanitizeAs =
  | 'email' | 'password' | 'username' | 'html' | 'html-attribute'
  | 'plain-text' | 'url' | 'filename' | 'search-query' | 'json'
  | 'sql-identifier' | 'path' | 'phone' | 'zip-code' | 'credit-card'
  | 'uuid' | 'base64' | 'hex' | 'ip-address' | 'mongodb-id'
  | 'currency' | 'percentage' | 'color-hex' | 'date-iso'
  | 'time-iso' | 'datetime-iso' | 'mongodb-filter' | 'path-safe';

export const SanitizeAsValidTypesValue: SanitizeAs[] = [
        'email', 'password', 'username', 'html', 'html-attribute',
        'plain-text', 'url', 'filename', 'search-query', 'json',
        'sql-identifier', 'path', 'phone', 'zip-code', 'credit-card',
        'uuid', 'base64', 'hex', 'ip-address', 'mongodb-id',
        'currency', 'percentage', 'color-hex', 'date-iso',
        'time-iso', 'datetime-iso', 'mongodb-filter', 'path-safe'
      ];
      
export type SanitizationMode = 'validate-only' | 'sanitize-for-storage';
export type SecurityLevel = 'low' | 'medium' | 'high' | 'paranoid';
export type LogLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ErrorHandling = 'throw' | 'return-default' | 'return-original';

export type ISecurityConstants ={
    MAX_INPUT_BYTES: number;
    MAX_HTML_BYTES: number;
    MAX_STRING_LENGTH: number;
    MAX_JSON_BYTES: number;
    MAX_FILENAME_LENGTH: number;
    ALLOWED_URL_PROTOCOLS: Set<string>;
  }
export interface IHtmlSanitizationConfig {
  allowedTags?: string[];
  allowedAttributes?: Record<string, string[]>;
  forbiddenTags?: string[];
  forbiddenAttributes?: string[];
  allowComments?: boolean;
  allowDataAttributes?: boolean;
}


export interface ISanitizationOptions {
  sanitizeAs: SanitizeAs;
  securityLevel?: SecurityLevel;
  mode?: SanitizationMode;
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  patternDescription?: string;
  enum?: any[];
  html?: IHtmlSanitizationConfig;
  truncate?: boolean;
  customValidator?: (value: string) => boolean;
  onError?: ErrorHandling;
  defaultValue?: string;
  fieldName?: string;
}


export interface ISanitizationResult {
  original: string;
  sanitized: string;
  sanitizeAs: SanitizeAs;
  isValid: boolean;
  errors: string[];
  warnings: string[];
  metadata: {
    processingTimeMs: number;
    mode: SanitizationMode;
    bytesProcessed: number;
    transformations: string[];
  };
}


export interface SanitizerContext {
  userId?: string;
  ipAddress?: string;
  requestId?: string;
}


export const SECURITY_Constants_Values:ISecurityConstants = {
  MAX_INPUT_BYTES: 10 * 1024 * 1024,      // 10MB
  MAX_HTML_BYTES: 1 * 1024 * 1024,        // 1MB
  MAX_STRING_LENGTH: 10000,               // 10k chars
  MAX_JSON_BYTES: 10 * 1024 * 1024,
  ALLOWED_URL_PROTOCOLS: new Set(['http:', 'https:', 'mailto:', 'ftp:']),
  MAX_FILENAME_LENGTH: 255,
};

      
/* ============================
   Validation Strategies (Pattern)
   ============================ */

export interface ValidationStrategy {
  readonly type: SanitizeAs;
  validate(value: string, options: ISanitizationOptions): { errors: string[]; warnings: string[] };
  sanitize(value: string, options: ISanitizationOptions): { result: string; transformations: string[]; warnings: string[] };
}


/* ============================
   Unified Configuration Types
   ============================ */
   // Security Levels by Data Type - MAPPED TO ACTUAL SanitizeAs TYPES
export const   recommendedSecurityLevelsValue:Record<SanitizeAs, SecurityLevel>= {
    'email': 'high',
    'password': 'high',
    'username': 'medium',
    'html': 'paranoid',
    'html-attribute': 'paranoid',
    'plain-text': 'high',
    'url': 'high',
    'filename': 'high',
    'search-query': 'medium',
    'json': 'medium',
    'sql-identifier': 'low',
    'path': 'high',
    'phone': 'medium',
    'zip-code': 'low',
    'credit-card': 'paranoid',
    'uuid': 'low',
    'base64': 'medium',
    'hex': 'low',
    'ip-address': 'medium',
    'mongodb-id': 'low',
    'currency': 'low',
    'percentage': 'low',
    'color-hex': 'low',
    'date-iso': 'low',
    'time-iso': 'low',
    'datetime-iso': 'low',
    'mongodb-filter': 'high',
    'path-safe': 'high'
  }
export interface ISanitizerGlobalConfig{
  // Global security constants
  securityConstants:ISecurityConstants
  
  // Security level mappings
  securityLevels: Record<SanitizeAs, SecurityLevel>;
  
  // Default options by type
  typeDefaults: Partial<Record<SanitizeAs, Partial<ISanitizationOptions>>>;
  
  // HTML sanitization defaults
  htmlDefaults: IHtmlSanitizationConfig
  
  // Rate limiting configuration
  rateLimiting: {
    enabled: boolean;
    requestsPerMinute: number;
    blockDurationMs: number;
    suspiciousPatterns: string[];
  };
  
  // Audit logging configuration
  auditLogging: IAuditLoggerConfig
  
  // Performance settings
  performance: {
    cacheEnabled: boolean;
    maxCacheSize: number;
    cleanupIntervalMs: number;
  };
  
  // Environment-specific overrides
  environmentOverrides: Partial<Record<string, Partial<ISanitizerGlobalConfig>>>;
}

export interface IAuditLogEntry {
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: 'SANITIZATION' | 'VALIDATION' | 'SECURITY' | 'PERFORMANCE';
  message: string;
  details?: any;
  userId?: string;
  requestId?:string;
  ipAddress?: string;
  hash?:string
}

export interface ISecurityEvent {
  severity: IAuditLogEntry['severity'];
  type: IAuditLogEntry['type'];
  message: string;
  details?: any;
  userId?: string;
  ipAddress?: string;
  requestId?:string
}


export type IAuditLoggerConfig ={
    enabled: boolean;
    logLevels: LogLevel[];
    destination: 'console' | 'file' | 'remote';
    maxLogs: number;
    retentionDays: number;
    alertOn: ('CRITICAL' | 'HIGH')[];
    filePath?: string;
    remoteEndpoint?: string;
    redactFields: ["password", "token", "authorization", "creditCard"]
}
/**
 * Audit logger plugin interface.
 * Your existing SecurityAuditLogger implements this.
 */
export interface AuditLogger {
  logSanitization(entry: IAuditLogEntry): void;
  logSecurityEvent(event: {
    severity: IAuditLogEntry['severity'];
    type: IAuditLogEntry['type'];
    message: string;
    details?: any;
    userId?: string;
    ipAddress?: string;
    requestId?:string;
  }): void;

 // configure(config: {
  //  enabled?: boolean;
  //  logLevel?: 'low' | 'medium' | 'high' | 'all';
  //  destination?: 'console' | 'file' | 'remote';
  //  maxLogs?: number;
  //  filePath?: string;
   // remoteEndpoint?: string;
 // }): void;

  getLogs(filter?: {
    severity?: string;
    type?: string;
    startTime?: Date;
    endTime?: Date;
    userId?: string;
    ipAddress?: string;
    requestId?:string;
  }): IAuditLogEntry[];
  exportLogs(format?: 'json' | 'csv' | 'text'): string;
  clearLogs(): void;
}

/**
 * Abuse prevention plugin interface.
 * Your existing AbusePrevention implements this.
 */
export interface AbusePreventionPlugin {
  checkRateLimit(ipAddress: string): { allowed: boolean; message?: string };
  detectSuspiciousPatterns(
    input: string,
    type: SanitizeAs
  ): { suspicious: boolean; reasons: string[] };
  getStatus(): { blockedIPs: number; activeRequests: number; lastCleanup?: string };
  configure(config: {
    requestsPerMinute?: number;
    blockDurationMs?: number;
    suspiciousPatterns?: string[];
  }): void;
  unblockIP(ipAddress: string): boolean;
}

/**
 * Optional plugins used by SecurityStringSanitizer.
 */
export interface SanitizerPlugins {
  abusePrevention?: AbusePreventionPlugin;
  auditLogger?: AuditLogger;
}