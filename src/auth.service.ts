import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import {
  AUTH_MODULE_OPTIONS,
  AuthModuleOptions,
  UserSession,
  AdminUser,
  AdminSession,
  ApiKeyValidation,
  Organization,
} from './auth.types';
import { getWebHeadersFromRequest, normalizeBasePath } from './auth.utils';

/**
 * Infer Session type from Better Auth instance
 * Inspired by the auth.$Infer pattern from Hono integration
 */
export type InferSession<T> = T extends { $Infer: { Session: infer S } }
  ? S
  : UserSession;

/**
 * Infer User type from Better Auth instance
 */
export type InferUser<T> = T extends { $Infer: { Session: { user: infer U } } }
  ? U
  : UserSession['user'];

/**
 * Better Auth API interface (subset used by AuthService)
 */
interface BetterAuthApi {
  getSession: (options: { headers: Headers }) => Promise<UserSession | null>;
  revokeSession?: (options: {
    headers: Headers;
    body: { token: string };
  }) => Promise<void>;
  revokeSessions?: (options: { headers: Headers }) => Promise<void>;
  listSessions?: (options: { headers: Headers }) => Promise<UserSession[]>;
  getToken?: (options: {
    headers: Headers;
  }) => Promise<{ token: string } | null>;
  verifyApiKey?: (options: {
    body: { key: string; permissions?: Record<string, string[]> };
  }) => Promise<ApiKeyValidation>;
  getFullOrganization?: (options: {
    headers: Headers;
  }) => Promise<Organization | null>;
  hasPermission?: (options: {
    headers: Headers;
    body: { permission: { resource: string; action: string } };
  }) => Promise<{ hasPermission: boolean } | null>;
}

/**
 * Extended Auth type with API access
 */
interface AuthWithApi {
  api: BetterAuthApi;
  options?: {
    basePath?: string;
    session?: {
      freshAge?: number;
    };
  };
}

/**
 * Better Auth Service
 *
 * Provides access to Better Auth instance and API with convenient methods
 *
 * Performance optimizations:
 * - Cached basePath computation
 * - Efficient role/permission parsing
 *
 * @example
 * ```typescript
 * // Use generics for full type support (recommended)
 * constructor(private authService: AuthService<typeof auth>) {}
 *
 * async someMethod(request: FastifyRequest) {
 *   // Convenient method - automatically infers session type
 *   const session = await this.authService.getSessionFromRequest(request);
 *   // session type is automatically inferred from auth.$Infer.Session
 *
 *   // Or access the API directly
 *   const accounts = await this.authService.api.listUserAccounts({
 *     headers: getWebHeadersFromRequest(request),
 *   });
 * }
 *
 * // Type inference example (inspired by Hono integration)
 * type Session = typeof authService.$Infer.Session;
 * type User = typeof authService.$Infer.User;
 * ```
 */
@Injectable()
export class AuthService<T extends { api: T['api'] } = AuthWithApi> {
  constructor(
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions<T>,
  ) {}

  /**
   * Get typed auth instance
   */
  private get auth(): AuthWithApi {
    return this.options.auth as unknown as AuthWithApi;
  }

  /**
   * Type inference helper
   * Inspired by the auth.$Infer pattern from Hono integration
   *
   * WARNING: This is a compile-time type helper only.
   * Do NOT access this property at runtime.
   *
   * @example
   * ```typescript
   * // Get types in components (correct usage)
   * type Session = typeof authService.$Infer.Session;
   * type User = typeof authService.$Infer.User;
   *
   * // Or get types directly from auth instance
   * type Session = typeof auth.$Infer.Session;
   *
   * // WRONG: Do not use at runtime
   * // const session = authService.$Infer.Session; // This will throw!
   * ```
   */
  get $Infer(): {
    Session: InferSession<T>;
    User: InferUser<T>;
  } {
    throw new Error(
      '$Infer is a compile-time type helper and should not be accessed at runtime. ' +
        'Use "typeof authService.$Infer.Session" for type inference instead.',
    );
  }

  /**
   * Get Better Auth API
   * Use to call authentication-related API methods
   */
  get api(): T['api'] {
    return this.options.auth.api;
  }

  /**
   * Get the complete Better Auth instance
   * Use to access plugin-extended functionality
   */
  get instance(): T {
    return this.options.auth;
  }

  get basePath(): string {
    const authBasePath = this.auth.options?.basePath;
    return normalizeBasePath(
      this.options.basePath ?? authBasePath ?? '/api/auth',
    );
  }

  /**
   * Get session from FastifyRequest
   * Return type is automatically inferred from auth.$Infer.Session
   *
   * @param request - Fastify request object
   * @returns Inferred Session type or null
   *
   * @example
   * ```typescript
   * const session = await this.authService.getSessionFromRequest(request);
   * if (session) {
   *   console.log('Logged in as:', session.user.email);
   *   // session.user type is automatically inferred
   * }
   * ```
   */
  async getSessionFromRequest(
    request: FastifyRequest,
  ): Promise<InferSession<T> | null> {
    const headers = getWebHeadersFromRequest(request);
    return this.getSessionFromHeaders(headers);
  }

  /**
   * Get session from Web Headers
   * Return type is automatically inferred from auth.$Infer.Session
   *
   * @param headers - Web standard Headers object
   * @returns Inferred Session type or null
   *
   * @example
   * ```typescript
   * const headers = new Headers({ cookie: 'session=...' });
   * const session = await this.authService.getSessionFromHeaders(headers);
   * ```
   */
  async getSessionFromHeaders(
    headers: Headers,
  ): Promise<InferSession<T> | null> {
    try {
      const session = await this.auth.api.getSession({ headers });
      return session as InferSession<T> | null;
    } catch {
      return null;
    }
  }

  /**
   * Validate and get session, throws UnauthorizedException if invalid
   * Return type is automatically inferred from auth.$Infer.Session
   *
   * @param request - Fastify request object
   * @returns Inferred Session type
   * @throws UnauthorizedException
   *
   * @example
   * ```typescript
   * // Manually validate when not using Guard
   * const session = await this.authService.validateSession(request);
   * // session is guaranteed to exist, otherwise throws exception
   * // session.user type is automatically inferred
   * ```
   */
  async validateSession(request: FastifyRequest): Promise<InferSession<T>> {
    const session = await this.getSessionFromRequest(request);
    if (!session) {
      throw new UnauthorizedException({
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
    }
    return session;
  }

  /**
   * Check if user has specified roles
   *
   * @param session - User session
   * @param roles - List of roles
   * @param mode - Matching mode: 'any' (OR) or 'all' (AND)
   *
   * @example
   * ```typescript
   * if (this.authService.hasRole(session, ['admin', 'moderator'])) {
   *   // User has admin or moderator role
   * }
   *
   * if (this.authService.hasRole(session, ['admin', 'verified'], 'all')) {
   *   // User has both admin and verified roles
   * }
   * ```
   */
  hasRole(
    session: UserSession,
    roles: string[],
    mode: 'any' | 'all' = 'any',
  ): boolean {
    const userRole = session.user.role;
    if (!userRole) {
      return false;
    }

    const userRoles = this.parseRoles(userRole);

    return mode === 'all'
      ? roles.every((role) => userRoles.includes(role))
      : roles.some((role) => userRoles.includes(role));
  }

  /**
   * Check if user has specified permissions
   *
   * @param session - User session
   * @param permissions - List of permissions
   * @param mode - Matching mode: 'any' (OR) or 'all' (AND)
   *
   * @example
   * ```typescript
   * if (this.authService.hasPermission(session, ['user:read', 'user:write'])) {
   *   // User has at least one permission
   * }
   * ```
   */
  hasPermission(
    session: UserSession,
    permissions: string[],
    mode: 'any' | 'all' = 'any',
  ): boolean {
    const userWithPermissions = session.user as {
      permissions?: string | string[];
    };
    const userPermissions = userWithPermissions.permissions;
    if (!userPermissions) {
      return false;
    }

    const permArray = this.parseRoles(userPermissions);

    return mode === 'all'
      ? permissions.every((perm) => permArray.includes(perm))
      : permissions.some((perm) => permArray.includes(perm));
  }

  // ============================================
  // Session Freshness
  // ============================================

  /**
   * Check if session is fresh
   *
   * @param session - User session
   * @param maxAge - Maximum freshness duration (seconds), defaults to auth config value
   *
   * @example
   * ```typescript
   * if (this.authService.isSessionFresh(session)) {
   *   // Allow sensitive operations
   * } else {
   *   // Require re-authentication
   * }
   * ```
   */
  isSessionFresh(session: UserSession, maxAge?: number): boolean {
    const createdAt = new Date(session.session.createdAt);
    const freshAge = maxAge ?? this.auth.options?.session?.freshAge ?? 86400;
    const ageInSeconds = (Date.now() - createdAt.getTime()) / 1000;
    return ageInSeconds <= freshAge;
  }

  // ============================================
  // Session Management
  // ============================================

  /**
   * Revoke a specific session
   *
   * @param sessionToken - Session token
   * @param request - Fastify request object (for headers)
   *
   * @example
   * ```typescript
   * await this.authService.revokeSession(sessionToken, request);
   * ```
   */
  async revokeSession(
    sessionToken: string,
    request: FastifyRequest,
  ): Promise<boolean> {
    const revokeSession = this.auth.api.revokeSession;
    if (!revokeSession) return false;

    try {
      const headers = getWebHeadersFromRequest(request);
      await revokeSession({ headers, body: { token: sessionToken } });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Revoke all sessions for the user
   *
   * @param request - Fastify request object (for headers)
   *
   * @example
   * ```typescript
   * await this.authService.revokeAllSessions(request);
   * ```
   */
  async revokeAllSessions(request: FastifyRequest): Promise<boolean> {
    const revokeSessions = this.auth.api.revokeSessions;
    if (!revokeSessions) return false;

    try {
      const headers = getWebHeadersFromRequest(request);
      await revokeSessions({ headers });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * List all sessions for the user
   *
   * @param request - Fastify request object (for headers)
   *
   * @example
   * ```typescript
   * const sessions = await this.authService.listUserSessions(request);
   * ```
   */
  async listUserSessions(request: FastifyRequest): Promise<UserSession[]> {
    const listSessions = this.auth.api.listSessions;
    if (!listSessions) return [];

    try {
      const headers = getWebHeadersFromRequest(request);
      const result = await listSessions({ headers });
      return result ?? [];
    } catch {
      return [];
    }
  }

  // ============================================
  // JWT Token (Requires JWT Plugin)
  // ============================================

  /**
   * Get JWT Token
   * Requires Better Auth JWT plugin to be enabled
   *
   * @param request - Fastify request object (for headers)
   * @returns JWT token or null
   *
   * @example
   * ```typescript
   * const jwt = await this.authService.getJwtToken(request);
   * if (jwt) {
   *   // Use JWT to call other services
   * }
   * ```
   */
  async getJwtToken(request: FastifyRequest): Promise<string | null> {
    const getToken = this.auth.api.getToken;
    if (!getToken) return null;

    try {
      const headers = getWebHeadersFromRequest(request);
      const result = await getToken({ headers });
      return result?.token ?? null;
    } catch {
      return null;
    }
  }

  // ============================================
  // API Key (Requires API Key Plugin)
  // ============================================

  /**
   * Verify API Key
   * Requires Better Auth API Key plugin to be enabled
   *
   * @param apiKey - API Key string
   * @param permissions - Optional permission requirements
   *
   * @example
   * ```typescript
   * const result = await this.authService.verifyApiKey(apiKey);
   * if (result.valid) {
   *   console.log('API Key belongs to user:', result.key?.userId);
   * }
   * ```
   */
  async verifyApiKey(
    apiKey: string,
    permissions?: Record<string, string[]>,
  ): Promise<ApiKeyValidation> {
    const verifyApiKey = this.auth.api.verifyApiKey;

    if (!verifyApiKey) {
      return {
        valid: false,
        error: {
          code: 'PLUGIN_NOT_ENABLED',
          message: 'API Key plugin not enabled',
        },
      };
    }

    try {
      return await verifyApiKey({ body: { key: apiKey, permissions } });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Unknown error occurred';
      return {
        valid: false,
        error: { code: 'VERIFICATION_FAILED', message },
      };
    }
  }

  // ============================================
  // Admin Features (Requires Admin Plugin)
  // ============================================

  /**
   * Check if user is banned
   *
   * @param user - User object (with Admin plugin fields)
   * @returns Whether the user is banned
   *
   * @example
   * ```typescript
   * if (this.authService.isUserBanned(session.user)) {
   *   throw new ForbiddenException('User is banned');
   * }
   * ```
   */
  isUserBanned(user: AdminUser): boolean {
    if (!user.banned) {
      return false;
    }

    const banExpires = user.banExpires ? new Date(user.banExpires) : null;
    return !banExpires || banExpires > new Date();
  }

  /**
   * Check if session is an impersonation session
   *
   * @param session - User session
   * @returns Whether the session is being impersonated
   *
   * @example
   * ```typescript
   * if (this.authService.isImpersonating(session)) {
   *   // Some operations are not allowed in impersonation mode
   * }
   * ```
   */
  isImpersonating(session: UserSession): boolean {
    const adminSession = session.session as AdminSession;
    return !!adminSession.impersonatedBy;
  }

  /**
   * Get the ID of the administrator performing impersonation
   *
   * @param session - User session
   * @returns Administrator ID or null
   */
  getImpersonatedBy(session: UserSession): string | null {
    const adminSession = session.session as AdminSession;
    return adminSession.impersonatedBy ?? null;
  }

  // ============================================
  // Organization (Requires Organization Plugin)
  // ============================================

  /**
   * Get user's active organization
   * Requires Better Auth Organization plugin to be enabled
   *
   * @param request - Fastify request object
   *
   * @example
   * ```typescript
   * const org = await this.authService.getActiveOrganization(request);
   * ```
   */
  async getActiveOrganization(
    request: FastifyRequest,
  ): Promise<Organization | null> {
    const getFullOrganization = this.auth.api.getFullOrganization;
    if (!getFullOrganization) return null;

    try {
      const headers = getWebHeadersFromRequest(request);
      return await getFullOrganization({ headers });
    } catch {
      return null;
    }
  }

  /**
   * Check user's permission within organization
   * Requires Better Auth Organization plugin to be enabled
   *
   * @param request - Fastify request object
   * @param permission - Permission object { resource, action }
   */
  async hasOrgPermission(
    request: FastifyRequest,
    permission: { resource: string; action: string },
  ): Promise<boolean> {
    const hasPermission = this.auth.api.hasPermission;
    if (!hasPermission) return false;

    try {
      const headers = getWebHeadersFromRequest(request);
      const result = await hasPermission({ headers, body: { permission } });
      return result?.hasPermission ?? false;
    } catch {
      return false;
    }
  }

  /**
   * Parse roles/permissions string or array to array
   * Optimized to avoid unnecessary array creation
   * Handles empty strings by returning empty array
   */
  private parseRoles(value: string | string[]): string[] {
    if (Array.isArray(value)) {
      return value;
    }
    if (!value) {
      return [];
    }
    return value
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean);
  }
}
