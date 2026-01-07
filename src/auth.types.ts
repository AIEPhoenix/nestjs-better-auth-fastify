import type { Auth } from 'better-auth';
import type { createAuthMiddleware } from 'better-auth/api';
import type { FastifyRequest, FastifyReply } from 'fastify';
import type { ModuleMetadata, Type } from '@nestjs/common';

// ============================================
// Module Options
// ============================================

/**
 * Custom error messages configuration
 */
export interface AuthErrorMessages {
  unauthorized?: string;
  forbidden?: string;
  sessionNotFresh?: string;
  userBanned?: string;
  orgRequired?: string;
  orgRoleRequired?: string;
  orgPermissionRequired?: string;
  apiKeyRequired?: string;
  apiKeyInvalidPermissions?: string;
}

/**
 * Organization role permissions configuration
 * Maps role names to resource permissions
 *
 * @example
 * ```typescript
 * {
 *   owner: {
 *     organization: 'all',
 *     member: 'all',
 *   },
 *   admin: {
 *     organization: ['read', 'update'],
 *     member: ['read', 'create'],
 *   },
 *   member: {
 *     organization: ['read'],
 *   },
 * }
 * ```
 */
export type OrgRolePermissions = Record<
  string,
  Record<string, string[] | 'all'>
>;

/**
 * Configuration options for AuthModule
 *
 * @template T - Better Auth instance type for type inference
 */
export interface AuthModuleOptions<T = Auth> {
  /** Better Auth instance */
  auth: T;

  /**
   * Authentication route prefix
   * If not specified, automatically reads from auth.options.basePath
   * @default "/api/auth"
   */
  basePath?: string;

  /**
   * Whether to disable global AuthGuard
   * @default false
   */
  disableGlobalGuard?: boolean;

  /**
   * Custom middleware wrapping the Better Auth handler
   * Useful for scenarios requiring operations before/after the handler (e.g., MikroORM RequestContext)
   */
  middleware?: (
    request: FastifyRequest,
    reply: FastifyReply,
    next: () => Promise<void>,
  ) => Promise<void> | void;

  /**
   * Whether to enable debug logging
   * @default false
   */
  debug?: boolean;

  /**
   * Custom error messages
   * Useful for internationalization (i18n)
   */
  errorMessages?: AuthErrorMessages;

  /**
   * Custom organization role permissions
   * Override the default role-permission mapping
   */
  orgRolePermissions?: OrgRolePermissions;
}

/**
 * Async configuration options for AuthModule - Factory pattern
 */
export interface AuthModuleAsyncOptionsFactory {
  useFactory: (
    ...args: any[]
  ) => AuthModuleOptions | Promise<AuthModuleOptions>;
  inject?: any[];
}

/**
 * Async configuration options for AuthModule - Class pattern
 */
export interface AuthModuleAsyncOptionsClass {
  useClass: Type<AuthModuleOptionsFactory>;
}

/**
 * Async configuration options for AuthModule - Existing pattern
 */
export interface AuthModuleAsyncOptionsExisting {
  useExisting: Type<AuthModuleOptionsFactory>;
}

/**
 * Factory interface for AuthModule configuration
 */
export interface AuthModuleOptionsFactory {
  createAuthModuleOptions(): AuthModuleOptions | Promise<AuthModuleOptions>;
}

/**
 * Async configuration options for AuthModule
 */
export type AuthModuleAsyncOptions = {
  /**
   * Whether to disable global AuthGuard (at async config level)
   */
  disableGlobalGuard?: boolean;

  /**
   * Additional modules to import
   */
  imports?: ModuleMetadata['imports'];
} & (
  | AuthModuleAsyncOptionsFactory
  | AuthModuleAsyncOptionsClass
  | AuthModuleAsyncOptionsExisting
);

/**
 * Injection token for AuthModule configuration
 */
export const AUTH_MODULE_OPTIONS = Symbol('AUTH_MODULE_OPTIONS');

// ============================================
// Session Types
// ============================================

/**
 * Base user fields
 */
export interface BaseUser {
  id: string;
  email: string;
  name: string;
  image?: string | null;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Extended user fields for Admin plugin
 */
export interface AdminUser extends BaseUser {
  role?: string | string[];
  banned?: boolean;
  banReason?: string | null;
  banExpires?: Date | null;
}

/**
 * Base session fields
 */
export interface BaseSession {
  id: string;
  userId: string;
  /** Session expiration time. May be null/undefined if session never expires */
  expiresAt: Date | string | null;
  createdAt: Date;
  updatedAt: Date;
  token: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/**
 * Extended session fields for Admin plugin (supports impersonation)
 */
export interface AdminSession extends BaseSession {
  impersonatedBy?: string | null;
}

/**
 * User session type
 *
 * @template TUser - Custom user type, extends BaseUser
 * @template TSession - Custom session type, extends BaseSession
 *
 * @example
 * ```typescript
 * // Using default types
 * @Session() session: UserSession
 *
 * // Using custom types
 * interface MyUser extends BaseUser {
 *   role: string;
 *   permissions: string[];
 * }
 * @Session() session: UserSession<MyUser>
 *
 * // Using Admin plugin types
 * @Session() session: UserSession<AdminUser, AdminSession>
 * ```
 */
export type UserSession<
  TUser extends BaseUser = BaseUser & { role?: string | string[] },
  TSession extends BaseSession = BaseSession,
> = {
  session: TSession;
  user: TUser;
};

// ============================================
// Organization Types (Organization Plugin)
// ============================================

/**
 * Base organization type
 */
export interface Organization {
  id: string;
  name: string;
  slug: string;
  logo?: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt: Date;
}

/**
 * Organization member type
 */
export interface OrganizationMember {
  id: string;
  userId: string;
  organizationId: string;
  role: string;
  createdAt: Date;
}

/**
 * Organization permission check options
 */
export interface OrgPermissionOptions {
  /**
   * Resource type
   * Common values: 'organization', 'member', 'invitation'
   */
  resource: string;

  /**
   * Action type
   */
  action: string | string[];

  /**
   * Matching mode
   */
  mode?: 'any' | 'all';

  /**
   * Custom error message
   */
  message?: string;
}

// ============================================
// API Key Types (API Key Plugin)
// ============================================

/**
 * API Key validation result
 */
export interface ApiKeyValidation {
  valid: boolean;
  key?: {
    id: string;
    name: string;
    userId: string;
    prefix?: string;
    permissions?: Record<string, string[]>;
    metadata?: Record<string, unknown>;
    remaining?: number | null;
    expiresAt?: Date | null;
    createdAt: Date;
  };
  error?: {
    code: string;
    message: string;
  };
}

/**
 * API Key permission options
 */
export interface ApiKeyPermissionOptions {
  /**
   * Resource-action permission mapping
   * @example { files: ['read', 'write'], users: ['read'] }
   */
  permissions?: Record<string, string[]>;

  /**
   * Custom error message
   */
  message?: string;
}

// ============================================
// Session Freshness Types
// ============================================

/**
 * Fresh session options
 */
export interface FreshSessionOptions {
  /**
   * Maximum freshness duration (in seconds)
   * If session.createdAt exceeds this duration, the session is considered stale
   * @default Reads from auth.options.session.freshAge, defaults to 86400 (1 day)
   */
  maxAge?: number;

  /**
   * Custom error message
   */
  message?: string;
}

// ============================================
// Hook Types
// ============================================

/**
 * Hook context type
 * Inferred from better-auth's createAuthMiddleware parameters
 */
export type AuthHookContext = Parameters<
  Parameters<typeof createAuthMiddleware>[0]
>[0];

/**
 * Enhanced hook context type definition
 * Contains all available properties described in Better Auth documentation
 */
export interface EnhancedAuthHookContext {
  /** Request path */
  path: string;
  /** Request body */
  body: unknown;
  /** Request headers */
  headers: Headers;
  /** Query parameters */
  query: Record<string, string>;
  /** Raw request object */
  request: Request;
  /** Authentication context */
  context: {
    /** Newly created session (only available in after hook) */
    newSession?: UserSession | null;
    /** Return value from previous hook */
    returned?: unknown;
    /** Accumulated response headers */
    responseHeaders: Headers;
    /** Predefined cookie configuration */
    authCookies: Record<string, unknown>;
    /** Auth instance secret */
    secret: string;
    /** Password utilities (hash/verify) */
    password: {
      hash: (password: string) => Promise<string>;
      verify: (data: { password: string; hash: string }) => Promise<boolean>;
    };
    /** Database adapter */
    adapter: unknown;
    /** ID generation function */
    generateId: (options?: { model?: string; size?: number }) => string;
  };
  /** Return JSON response */
  json: <T>(data: T, status?: number) => Response;
  /** Redirect */
  redirect: (url: string) => never;
  /** Set cookie */
  setCookies: (
    name: string,
    value: string,
    options?: Record<string, unknown>,
  ) => void;
  /** Get cookies */
  getCookies: () => Record<string, string>;
}

// ============================================
// Decorator Options
// ============================================

/**
 * Roles decorator options
 */
export interface RolesOptions {
  /**
   * Role matching mode
   * - 'any': User must have at least one of the specified roles (OR logic, default)
   * - 'all': User must have all specified roles (AND logic)
   */
  mode?: 'any' | 'all';

  /**
   * Custom error message
   */
  message?: string;
}

/**
 * Permissions decorator options
 */
export interface PermissionsOptions {
  /**
   * Permission matching mode
   * - 'any': User must have at least one of the specified permissions (OR logic, default)
   * - 'all': User must have all specified permissions (AND logic)
   */
  mode?: 'any' | 'all';

  /**
   * Custom error message
   */
  message?: string;
}

// ============================================
// Request Extension
// ============================================

/**
 * Extends FastifyRequest type with authentication-related properties
 */
declare module 'fastify' {
  interface FastifyRequest {
    /** User session */
    session: UserSession | null;
    /** Current user */
    user: UserSession['user'] | null;
    /** API Key (when using API Key authentication) */
    apiKey?: ApiKeyValidation['key'] | null;
    /** Current organization (when using Organization plugin) */
    organization?: Organization | null;
    /** Current user's membership info in the organization */
    organizationMember?: OrganizationMember | null;
    /** Whether the session is being impersonated */
    isImpersonating?: boolean;
    /** ID of the admin performing impersonation */
    impersonatedBy?: string | null;
  }
}

// ============================================
// Auth Context (for createAuthParamDecorator)
// ============================================

export interface AuthContext {
  session: UserSession | null;
  user: UserSession['user'] | null;
  organization: Organization | null;
  orgMember: OrganizationMember | null;
  isImpersonating: boolean;
  impersonatedBy: string | null;
  apiKey: ApiKeyValidation['key'] | null;
}

// ============================================
// Auth Method Types
// ============================================

/**
 * Authentication method
 */
export type AuthMethod = 'session' | 'bearer' | 'apiKey';

/**
 * Authentication result
 */
export interface AuthResult {
  /** Authentication method */
  method: AuthMethod;
  /** Whether authentication succeeded */
  authenticated: boolean;
  /** Session (when using session/bearer authentication) */
  session?: UserSession | null;
  /** API Key (when using API Key authentication) */
  apiKey?: ApiKeyValidation['key'] | null;
}
