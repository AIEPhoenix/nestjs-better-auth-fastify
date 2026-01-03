import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
  Inject,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Auth } from 'better-auth';
import type { FastifyRequest } from 'fastify';
import {
  AUTH_MODULE_OPTIONS,
  AuthModuleOptions,
  UserSession,
  AdminUser,
  AdminSession,
  ApiKeyValidation,
  Organization,
  OrganizationMember,
  OrgPermissionOptions,
  OrgRolePermissions,
  AuthErrorMessages,
} from './auth.types';
import {
  ALLOW_ANONYMOUS_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  API_KEY_AUTH_KEY,
  DISALLOW_IMPERSONATION_KEY,
  ORG_REQUIRED_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  getRequestFromContext,
  RolesMetadata,
  PermissionsMetadata,
  FreshSessionMetadata,
  ApiKeyAuthMetadata,
  OrgRolesMetadata,
  OrgPermissionsMetadata,
} from './auth.decorators';
import { toWebHeaders, getHeadersFromRequest } from './auth.utils';

/**
 * Better Auth API interface (subset used by AuthGuard)
 */
interface BetterAuthApi {
  getSession: (options: { headers: Headers }) => Promise<UserSession | null>;
  verifyApiKey?: (options: {
    body: { key: string };
  }) => Promise<ApiKeyValidation | null>;
}

/**
 * Extended Auth type with API access
 */
type AuthWithApi = Auth & {
  api: BetterAuthApi;
  options?: {
    session?: {
      freshAge?: number;
    };
  };
};

/**
 * Error type mapping
 */
type ContextType = 'http' | 'graphql' | 'ws' | 'rpc';

/**
 * Custom error constructor type
 */
type CustomErrorConstructor = new (...args: unknown[]) => Error;

/**
 * Cached GraphQLError class
 */
let cachedGraphQLError: CustomErrorConstructor | null = null;

/**
 * Lazily load GraphQLError from graphql module
 * Falls back to standard Error when graphql module is unavailable
 */
function getGraphQLError(): CustomErrorConstructor {
  if (cachedGraphQLError) {
    return cachedGraphQLError;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const graphqlModule = require('graphql') as {
      GraphQLError: CustomErrorConstructor;
    };
    cachedGraphQLError = graphqlModule.GraphQLError;
    return cachedGraphQLError;
  } catch {
    // graphql module unavailable, use standard Error as fallback
    cachedGraphQLError = Error as unknown as CustomErrorConstructor;
    return cachedGraphQLError;
  }
}

/**
 * Cached WsException class
 */
let cachedWsException: CustomErrorConstructor | null = null;

/**
 * Lazily load WsException from @nestjs/websockets module
 * WebSocket support requires @nestjs/websockets module
 */
function getWsException(): CustomErrorConstructor {
  if (cachedWsException) {
    return cachedWsException;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const wsModule = require('@nestjs/websockets') as {
      WsException: CustomErrorConstructor;
    };
    cachedWsException = wsModule.WsException;
    return cachedWsException;
  } catch {
    throw new Error(
      '@nestjs/websockets is required for WebSocket support. Please install it.',
    );
  }
}

// ============================================
// Error Factory - Lazy creation for performance
// ============================================

type ErrorType =
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'SESSION_NOT_FRESH'
  | 'USER_BANNED'
  | 'ORG_REQUIRED'
  | 'ORG_ROLE_REQUIRED'
  | 'ORG_PERMISSION_REQUIRED'
  | 'API_KEY_REQUIRED'
  | 'API_KEY_INVALID_PERMISSIONS';

interface ErrorOptions {
  message?: string;
  code?: string;
  banExpires?: string;
}

/**
 * Default error messages (can be overridden via AuthModuleOptions)
 */
const DEFAULT_ERROR_MESSAGES: Record<ErrorType, string> = {
  UNAUTHORIZED: 'Authentication required',
  FORBIDDEN: 'Insufficient permissions',
  SESSION_NOT_FRESH: 'Session is not fresh. Please re-authenticate.',
  USER_BANNED: 'User account is banned',
  ORG_REQUIRED:
    'Organization context required. Please set an active organization.',
  ORG_ROLE_REQUIRED: 'Insufficient organization role',
  ORG_PERMISSION_REQUIRED: 'Insufficient organization permission',
  API_KEY_REQUIRED: 'Valid API key required',
  API_KEY_INVALID_PERMISSIONS: 'API key lacks required permissions',
};

/**
 * Map ErrorType to AuthErrorMessages key
 */
const ERROR_MESSAGE_MAPPING: Record<ErrorType, keyof AuthErrorMessages> = {
  UNAUTHORIZED: 'unauthorized',
  FORBIDDEN: 'forbidden',
  SESSION_NOT_FRESH: 'sessionNotFresh',
  USER_BANNED: 'userBanned',
  ORG_REQUIRED: 'orgRequired',
  ORG_ROLE_REQUIRED: 'orgRoleRequired',
  ORG_PERMISSION_REQUIRED: 'orgPermissionRequired',
  API_KEY_REQUIRED: 'apiKeyRequired',
  API_KEY_INVALID_PERMISSIONS: 'apiKeyInvalidPermissions',
};

/**
 * Get custom error message for ErrorType
 */
function getCustomMessage(
  errorType: ErrorType,
  customMessages?: AuthErrorMessages,
): string | undefined {
  if (!customMessages) return undefined;
  const key = ERROR_MESSAGE_MAPPING[errorType];
  return customMessages[key];
}

/**
 * Create error based on context type and error type
 * Lazy creation to avoid unnecessary object allocation
 */
function createError(
  contextType: ContextType,
  errorType: ErrorType,
  options?: ErrorOptions,
  customMessages?: AuthErrorMessages,
): Error {
  const message =
    options?.message ??
    getCustomMessage(errorType, customMessages) ??
    DEFAULT_ERROR_MESSAGES[errorType];
  const code = options?.code ?? errorType;

  switch (contextType) {
    case 'http':
      switch (errorType) {
        case 'UNAUTHORIZED':
        case 'API_KEY_REQUIRED':
          return new UnauthorizedException({ code, message });
        case 'SESSION_NOT_FRESH':
          return new HttpException({ code, message }, HttpStatus.FORBIDDEN);
        default:
          return new ForbiddenException({ code, message, ...options });
      }

    case 'graphql': {
      const GqlError = getGraphQLError();
      return new GqlError(message, { extensions: { code, ...options } });
    }

    case 'ws': {
      const WsExceptionClass = getWsException();
      return new WsExceptionClass({ code, message, ...options });
    }

    case 'rpc':
    default:
      return new Error(`${code}: ${message}`);
  }
}

// ============================================
// Metadata Cache - Performance optimization
// ============================================

interface CachedMetadata {
  isPublic?: boolean;
  isOptional?: boolean;
  apiKeyAuth?: ApiKeyAuthMetadata;
  banCheck?: boolean;
  disallowImpersonation?: { message?: string };
  freshSession?: FreshSessionMetadata;
  adminOnly?: { message?: string };
  roles?: RolesMetadata;
  permissions?: PermissionsMetadata;
  orgRequired?: boolean;
  orgRoles?: OrgRolesMetadata;
  orgPermissions?: OrgPermissionsMetadata;
}

/**
 * Session with organization context (Organization plugin extends session)
 */
interface SessionWithOrganization {
  activeOrganizationId?: string | null;
}

/**
 * Default role permissions for organization
 * Can be overridden via AuthModuleOptions.orgRolePermissions
 */
const DEFAULT_ORG_ROLE_PERMISSIONS: Record<
  string,
  Record<string, string[] | 'all'>
> = {
  owner: {
    organization: 'all',
    member: 'all',
    invitation: 'all',
    project: 'all',
  },
  admin: {
    organization: ['read', 'update'],
    member: ['read', 'create', 'update'],
    invitation: ['read', 'create', 'delete'],
    project: 'all',
  },
  member: {
    organization: ['read'],
    member: ['read'],
    invitation: [],
    project: ['read', 'create'],
  },
};

/**
 * Default API Key header (matches Better Auth's default)
 * API keys should be sent via dedicated headers, not mixed with Bearer tokens
 * Can be customized via Better Auth apiKey plugin's apiKeyHeaders config
 */
const DEFAULT_API_KEY_HEADERS = ['x-api-key'];

/**
 * Authentication Guard
 *
 * Globally registered by default, all routes require authentication
 * Supports HTTP, GraphQL, WebSocket
 *
 * Supported decorators:
 * - @AllowAnonymous() - Skip authentication
 * - @OptionalAuth() - Optional authentication
 * - @Roles(['admin']) - Role validation
 * - @Permissions(['read']) - Permission validation
 * - @RequireFreshSession() - Require fresh session
 * - @AdminOnly() - Admin only
 * - @BanCheck() - Check ban status
 * - @BearerAuth() - Bearer Token authentication
 * - @ApiKeyAuth() - API Key authentication
 * - @DisallowImpersonation() - Disallow impersonation
 * - @OrgRequired() - Require organization context
 * - @OrgRoles(['owner', 'admin']) - Organization role validation
 * - @OrgPermission({ resource, action }) - Organization permission validation
 *
 * Performance optimizations:
 * - Metadata caching per handler
 * - Lazy evaluation of checks
 * - Early returns for common cases
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  /** Metadata cache - WeakMap for automatic cleanup */
  private readonly metadataCache = new WeakMap<object, CachedMetadata>();

  /** Cached API key headers - computed once on first use */
  private cachedApiKeyHeaders: string[] | null = null;

  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = getRequestFromContext(context);
    const contextType = context.getType<string>() as ContextType;
    const handler = context.getHandler();
    const errorMessages: AuthErrorMessages | undefined =
      this.options.errorMessages;

    // Get cached metadata or compute and cache
    const metadata = this.getMetadata(context, handler);

    // 1. Check @AllowAnonymous() first - Performance optimization
    if (metadata.isPublic) {
      await this.tryAttachSession(request);
      return true;
    }

    // 2. Try API Key authentication if configured
    if (metadata.apiKeyAuth) {
      const apiKeyResult = await this.tryApiKeyAuth(request);
      if (apiKeyResult) {
        // Check API key permissions if required
        if (metadata.apiKeyAuth.permissions?.permissions) {
          if (
            !this.checkApiKeyPermissions(
              apiKeyResult,
              metadata.apiKeyAuth.permissions.permissions,
            )
          ) {
            throw createError(
              contextType,
              'API_KEY_INVALID_PERMISSIONS',
              { message: metadata.apiKeyAuth.permissions.message },
              errorMessages,
            );
          }
        }
        return true;
      }
      // If session fallback not allowed, fail
      if (!metadata.apiKeyAuth.allowSession) {
        throw createError(
          contextType,
          'API_KEY_REQUIRED',
          undefined,
          errorMessages,
        );
      }
    }

    // 3. Get session (supports Cookie or Bearer Token via bearer plugin)
    const session = await this.getSession(request);

    // 4. Attach to request
    request.session = session;
    request.user = session?.user ?? null;

    // Detect impersonation
    if (session) {
      const adminSession = session.session as AdminSession;
      const impersonatedBy = adminSession.impersonatedBy;
      request.isImpersonating = !!impersonatedBy;
      request.impersonatedBy = impersonatedBy ?? null;
    }

    // 5. Handle no session
    if (!session) {
      if (metadata.isOptional) {
        return true;
      }
      throw createError(contextType, 'UNAUTHORIZED', undefined, errorMessages);
    }

    // 6. Run security checks (only if needed)
    this.runSecurityChecks(
      contextType,
      metadata,
      session,
      request,
      errorMessages,
    );

    // 7. Run authorization checks (only if needed)
    this.runAuthorizationChecks(contextType, metadata, session, errorMessages);

    // 8. Run organization checks (only if needed)
    await this.runOrganizationChecks(
      contextType,
      metadata,
      session,
      request,
      errorMessages,
    );

    return true;
  }

  /**
   * Get or compute cached metadata
   */
  private getMetadata(
    context: ExecutionContext,
    handler: object,
  ): CachedMetadata {
    let cached = this.metadataCache.get(handler);
    if (cached) {
      return cached;
    }

    const targets = [context.getHandler(), context.getClass()];

    cached = {
      isPublic: this.reflector.getAllAndOverride<boolean>(
        ALLOW_ANONYMOUS_KEY,
        targets,
      ),
      isOptional: this.reflector.getAllAndOverride<boolean>(
        OPTIONAL_AUTH_KEY,
        targets,
      ),
      apiKeyAuth: this.reflector.getAllAndOverride<ApiKeyAuthMetadata>(
        API_KEY_AUTH_KEY,
        targets,
      ),
      banCheck: this.reflector.getAllAndOverride<boolean>(
        BAN_CHECK_KEY,
        targets,
      ),
      disallowImpersonation: this.reflector.getAllAndOverride<{
        message?: string;
      }>(DISALLOW_IMPERSONATION_KEY, targets),
      freshSession: this.reflector.getAllAndOverride<FreshSessionMetadata>(
        FRESH_SESSION_KEY,
        targets,
      ),
      adminOnly: this.reflector.getAllAndOverride<{ message?: string }>(
        ADMIN_ONLY_KEY,
        targets,
      ),
      roles: this.reflector.getAllAndOverride<RolesMetadata>(
        ROLES_KEY,
        targets,
      ),
      permissions: this.reflector.getAllAndOverride<PermissionsMetadata>(
        PERMISSIONS_KEY,
        targets,
      ),
      orgRequired: this.reflector.getAllAndOverride<boolean>(
        ORG_REQUIRED_KEY,
        targets,
      ),
      orgRoles: this.reflector.getAllAndOverride<OrgRolesMetadata>(
        ORG_ROLES_KEY,
        targets,
      ),
      orgPermissions: this.reflector.getAllAndOverride<OrgPermissionsMetadata>(
        ORG_PERMISSIONS_KEY,
        targets,
      ),
    };

    this.metadataCache.set(handler, cached);
    return cached;
  }

  /**
   * Run security checks (ban, impersonation, fresh session)
   */
  private runSecurityChecks(
    contextType: ContextType,
    metadata: CachedMetadata,
    session: UserSession,
    request: FastifyRequest,
    errorMessages?: AuthErrorMessages,
  ): void {
    // Check @BanCheck()
    if (metadata.banCheck) {
      const user = session.user as AdminUser;
      if (user.banned) {
        const banExpires = user.banExpires ? new Date(user.banExpires) : null;
        if (!banExpires || banExpires > new Date()) {
          throw createError(
            contextType,
            'USER_BANNED',
            {
              message: user.banReason ?? undefined,
              banExpires: banExpires?.toISOString(),
            },
            errorMessages,
          );
        }
      }
    }

    // Check @DisallowImpersonation()
    if (metadata.disallowImpersonation && request.isImpersonating) {
      throw createError(
        contextType,
        'FORBIDDEN',
        {
          message:
            metadata.disallowImpersonation.message ??
            'This action is not allowed during impersonation',
        },
        errorMessages,
      );
    }

    // Check @RequireFreshSession()
    if (metadata.freshSession) {
      if (
        !this.checkSessionFreshness(
          session,
          metadata.freshSession.options.maxAge,
        )
      ) {
        throw createError(
          contextType,
          'SESSION_NOT_FRESH',
          { message: metadata.freshSession.options.message },
          errorMessages,
        );
      }
    }
  }

  /**
   * Run authorization checks (roles, permissions, admin)
   */
  private runAuthorizationChecks(
    contextType: ContextType,
    metadata: CachedMetadata,
    session: UserSession,
    errorMessages?: AuthErrorMessages,
  ): void {
    // Check @AdminOnly()
    if (metadata.adminOnly) {
      if (!this.checkUserRoles(session.user.role, ['admin'], 'any')) {
        throw createError(
          contextType,
          'FORBIDDEN',
          { message: metadata.adminOnly.message ?? 'Admin access required' },
          errorMessages,
        );
      }
    }

    // Check @Roles()
    if (metadata.roles?.roles?.length) {
      if (
        !this.checkUserRoles(
          session.user.role,
          metadata.roles.roles,
          metadata.roles.options.mode ?? 'any',
        )
      ) {
        throw createError(
          contextType,
          'FORBIDDEN',
          {
            message:
              metadata.roles.options.message ?? 'Insufficient role permissions',
          },
          errorMessages,
        );
      }
    }

    // Check @Permissions()
    if (metadata.permissions?.permissions?.length) {
      const userWithPermissions = session.user as {
        permissions?: string | string[];
      };
      if (
        !this.checkUserPermissions(
          userWithPermissions.permissions,
          metadata.permissions.permissions,
          metadata.permissions.options.mode ?? 'any',
        )
      ) {
        throw createError(
          contextType,
          'FORBIDDEN',
          {
            message:
              metadata.permissions.options.message ??
              'Insufficient permissions',
          },
          errorMessages,
        );
      }
    }
  }

  /**
   * Run organization checks (only if org decorators are used)
   */
  private async runOrganizationChecks(
    contextType: ContextType,
    metadata: CachedMetadata,
    session: UserSession,
    request: FastifyRequest,
    errorMessages?: AuthErrorMessages,
  ): Promise<void> {
    // Skip if no org decorators used
    if (
      !metadata.orgRequired &&
      !metadata.orgRoles &&
      !metadata.orgPermissions
    ) {
      return;
    }

    const orgContext = await this.getOrganizationContext(request, session);

    // Attach to request
    request.organization = orgContext?.organization ?? null;
    request.organizationMember = orgContext?.member ?? null;

    // Check @OrgRequired()
    if (metadata.orgRequired && !orgContext) {
      throw createError(contextType, 'ORG_REQUIRED', undefined, errorMessages);
    }

    // Check @OrgRoles()
    if (metadata.orgRoles?.roles?.length) {
      if (!orgContext?.member) {
        throw createError(
          contextType,
          'ORG_ROLE_REQUIRED',
          {
            message:
              metadata.orgRoles.options.message ??
              'Organization membership required',
          },
          errorMessages,
        );
      }

      if (
        !this.checkOrgRoles(
          orgContext.member.role,
          metadata.orgRoles.roles,
          metadata.orgRoles.options.mode ?? 'any',
        )
      ) {
        throw createError(
          contextType,
          'ORG_ROLE_REQUIRED',
          {
            message:
              metadata.orgRoles.options.message ??
              'Insufficient organization role',
          },
          errorMessages,
        );
      }
    }

    // Check @OrgPermission()
    if (metadata.orgPermissions?.options) {
      if (!orgContext?.member) {
        throw createError(
          contextType,
          'ORG_PERMISSION_REQUIRED',
          {
            message:
              metadata.orgPermissions.options.message ??
              'Organization membership required',
          },
          errorMessages,
        );
      }

      if (
        !this.checkOrgPermission(
          orgContext.member,
          metadata.orgPermissions.options,
        )
      ) {
        throw createError(
          contextType,
          'ORG_PERMISSION_REQUIRED',
          {
            message:
              metadata.orgPermissions.options.message ??
              'Insufficient organization permission',
          },
          errorMessages,
        );
      }
    }
  }

  /**
   * Get auth instance with typed API
   */
  private get auth(): AuthWithApi {
    return this.options.auth as AuthWithApi;
  }

  /**
   * Get session from Better Auth
   * Supports Cookie and Bearer Token (via bearer plugin)
   *
   * Note: API keys should be sent via dedicated headers (x-api-key, api-key, etc.)
   * not via Authorization: Bearer header
   */
  private async getSession(
    request: FastifyRequest,
  ): Promise<UserSession | null> {
    try {
      const headers = toWebHeaders(getHeadersFromRequest(request));
      return await this.auth.api.getSession({ headers });
    } catch (error) {
      if (this.options.debug) {
        this.logger.debug('Failed to get session from Better Auth', error);
      }
      return null;
    }
  }

  /**
   * Get API key headers to check
   * Reads from Better Auth apiKey plugin's apiKeyHeaders config if available
   */
  private getApiKeyHeaders(): string[] {
    // Return cached headers if available
    if (this.cachedApiKeyHeaders !== null) {
      return this.cachedApiKeyHeaders;
    }

    // Try to read from Better Auth apiKey plugin config
    const configuredHeaders = this.getApiKeyHeadersFromAuth();
    if (configuredHeaders) {
      this.cachedApiKeyHeaders = configuredHeaders;

      if (this.options.debug) {
        this.logger.debug(
          `Using API key headers from Better Auth config: ${JSON.stringify(configuredHeaders)}`,
        );
      }

      return this.cachedApiKeyHeaders;
    }

    // Default headers
    this.cachedApiKeyHeaders = DEFAULT_API_KEY_HEADERS;
    return this.cachedApiKeyHeaders;
  }

  /**
   * Try to read apiKey plugin's apiKeyHeaders from Better Auth instance
   * Returns null if not found or plugin not configured
   */
  private getApiKeyHeadersFromAuth(): string[] | null {
    try {
      const auth = this.options.auth as {
        options?: {
          plugins?: Array<{
            id?: string;
            // Plugin options
            apiKeyHeaders?: string | string[];
            options?: {
              apiKeyHeaders?: string | string[];
            };
          }>;
        };
      };

      // Try to find apiKey plugin config
      const plugins = auth.options?.plugins;
      if (plugins && Array.isArray(plugins)) {
        for (const plugin of plugins) {
          if (plugin.id === 'api-key' || plugin.id === 'apiKey') {
            // Check direct property
            const headers =
              plugin.apiKeyHeaders ?? plugin.options?.apiKeyHeaders;
            if (headers) {
              return Array.isArray(headers) ? headers : [headers];
            }
          }
        }
      }

      return null;
    } catch {
      // Failed to read config, will use default headers
      return null;
    }
  }

  /**
   * Get organization context from session
   * IMPORTANT: Does NOT create fallback context to avoid security issues
   */
  private async getOrganizationContext(
    request: FastifyRequest,
    session: UserSession,
  ): Promise<{
    organization: Organization;
    member: OrganizationMember;
  } | null> {
    try {
      const sessionData = session.session as SessionWithOrganization;
      const activeOrgId = sessionData.activeOrganizationId;

      // Check for organization ID in headers as fallback
      const headerOrgId =
        request.headers['x-organization-id'] ||
        request.headers['x-org-id'] ||
        request.headers['organization-id'];

      const orgId = activeOrgId || headerOrgId;

      if (!orgId || typeof orgId !== 'string') {
        return null;
      }

      // Try to get organization info from Better Auth API
      const authApi = this.auth.api as unknown as {
        getFullOrganization?: (options: {
          organizationId: string;
          headers?: Headers;
        }) => Promise<{
          organization: Organization;
          members: unknown[];
        } | null>;
        organization?: {
          getFullOrganization?: (options: {
            organizationId: string;
            headers?: Headers;
          }) => Promise<{
            organization: Organization;
            members: unknown[];
          } | null>;
        };
      };

      const getOrgFn =
        authApi.getFullOrganization ||
        authApi.organization?.getFullOrganization;

      if (!getOrgFn) {
        // Organization plugin not installed or API not available
        // DO NOT create a fallback - this would be a security risk
        if (this.options.debug) {
          this.logger.warn(
            'Organization context requested but getFullOrganization API not available',
          );
        }
        return null;
      }

      // Pass headers for authentication
      const headers = toWebHeaders(getHeadersFromRequest(request));
      const orgData = await getOrgFn({ organizationId: orgId, headers });

      if (!orgData?.organization) {
        return null;
      }

      const members = orgData.members as Array<{
        userId: string;
        role: string;
        id: string;
        organizationId: string;
        createdAt: Date;
      }>;

      // IMPORTANT: User MUST be a member of the organization
      const member = members?.find((m) => m.userId === session.user.id);

      if (!member) {
        // User is NOT a member of this organization
        // This is a security-critical check
        return null;
      }

      return {
        organization: orgData.organization,
        member: {
          id: member.id,
          userId: member.userId,
          organizationId: member.organizationId,
          role: member.role,
          createdAt: member.createdAt,
        },
      };
    } catch (error) {
      if (this.options.debug) {
        this.logger.error('Error getting organization context', error);
      }
      return null;
    }
  }

  /**
   * Try API Key authentication
   * API keys must be sent via dedicated headers (x-api-key, api-key, etc.)
   * NOT via Authorization: Bearer header (that's for session tokens)
   */
  private async tryApiKeyAuth(
    request: FastifyRequest,
  ): Promise<Record<string, string[]> | null> {
    // Check configured API key headers
    const headers = this.getApiKeyHeaders();
    let apiKey: string | undefined;

    for (const headerName of headers) {
      const headerValue = request.headers[headerName.toLowerCase()];
      if (headerValue && typeof headerValue === 'string') {
        apiKey = headerValue;
        break;
      }
    }

    if (!apiKey) {
      return null;
    }

    try {
      const verifyApiKey = this.auth.api.verifyApiKey;
      if (!verifyApiKey) {
        return null;
      }

      const result = await verifyApiKey({ body: { key: apiKey } });

      if (result?.valid && result?.key) {
        request.apiKey = result.key;
        return result.key.permissions ?? {};
      }
    } catch (error) {
      // Log in debug mode only to avoid leaking sensitive info in production
      if (this.options.debug) {
        this.logger.debug('API key verification failed', error);
      }
    }

    return null;
  }

  /**
   * Check API Key permissions
   */
  private checkApiKeyPermissions(
    keyPermissions: Record<string, string[]> | undefined,
    requiredPermissions: Record<string, string[]>,
  ): boolean {
    if (!keyPermissions) {
      return false;
    }

    for (const [resource, actions] of Object.entries(requiredPermissions)) {
      const keyActions = keyPermissions[resource];
      if (!keyActions) {
        return false;
      }
      for (const action of actions) {
        if (!keyActions.includes(action)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Check if session is fresh
   */
  private checkSessionFreshness(
    session: UserSession,
    maxAge?: number,
  ): boolean {
    const createdAt = new Date(session.session.createdAt);
    const freshAge = maxAge ?? this.auth.options?.session?.freshAge ?? 86400;
    const ageInSeconds = (Date.now() - createdAt.getTime()) / 1000;
    return ageInSeconds <= freshAge;
  }

  /**
   * Attach session to request (for public routes)
   * Errors are logged in debug mode but don't affect the request
   */
  private async tryAttachSession(request: FastifyRequest): Promise<void> {
    try {
      const session = await this.getSession(request);
      request.session = session;
      request.user = session?.user ?? null;

      if (session) {
        const adminSession = session.session as AdminSession;
        const impersonatedBy = adminSession.impersonatedBy;
        request.isImpersonating = !!impersonatedBy;
        request.impersonatedBy = impersonatedBy ?? null;
      }
    } catch (error) {
      if (this.options.debug) {
        this.logger.debug('Failed to attach session for public route', error);
      }
    }
  }

  /**
   * Check if user has required roles
   */
  private checkUserRoles(
    userRole: string | string[] | undefined,
    requiredRoles: string[],
    mode: 'any' | 'all',
  ): boolean {
    if (!userRole) {
      return false;
    }

    const userRoles = Array.isArray(userRole)
      ? userRole
      : userRole.split(',').map((v) => v.trim());

    return mode === 'all'
      ? requiredRoles.every((role) => userRoles.includes(role))
      : requiredRoles.some((role) => userRoles.includes(role));
  }

  /**
   * Check if user has required organization roles
   */
  private checkOrgRoles(
    memberRole: string | string[] | undefined,
    requiredRoles: string[],
    mode: 'any' | 'all',
  ): boolean {
    if (!memberRole) {
      return false;
    }

    const memberRoles = Array.isArray(memberRole)
      ? memberRole
      : memberRole
          .split(',')
          .map((v) => v.trim())
          .filter(Boolean);

    return mode === 'all'
      ? requiredRoles.every((role) => memberRoles.includes(role))
      : requiredRoles.some((role) => memberRoles.includes(role));
  }

  /**
   * Check organization permission using role-based permissions
   */
  private checkOrgPermission(
    member: OrganizationMember,
    options: OrgPermissionOptions,
  ): boolean {
    const { resource, action, mode = 'any' } = options;

    // Use custom permissions from options if provided, otherwise use defaults
    const allRolePermissions: OrgRolePermissions = this.getOrgRolePermissions();
    const rolePermissions: Record<string, string[] | 'all'> | undefined =
      allRolePermissions[member.role];
    if (!rolePermissions) {
      return false;
    }

    const resourcePermissions: string[] | 'all' | undefined =
      rolePermissions[resource];
    if (!resourcePermissions) {
      return false;
    }

    if (resourcePermissions === 'all') {
      return true;
    }

    const actions = Array.isArray(action) ? action : [action];

    return mode === 'all'
      ? actions.every((a) => resourcePermissions.includes(a))
      : actions.some((a) => resourcePermissions.includes(a));
  }

  /**
   * Get organization role permissions
   * Can be customized via AuthModuleOptions.orgRolePermissions
   */
  private getOrgRolePermissions(): OrgRolePermissions {
    return this.options.orgRolePermissions ?? DEFAULT_ORG_ROLE_PERMISSIONS;
  }

  /**
   * Check if user has required permissions
   */
  private checkUserPermissions(
    userPermissions: string | string[] | undefined,
    requiredPermissions: string[],
    mode: 'any' | 'all',
  ): boolean {
    if (!userPermissions) {
      return false;
    }

    const permissions = Array.isArray(userPermissions)
      ? userPermissions
      : userPermissions.split(',').map((v) => v.trim());

    return mode === 'all'
      ? requiredPermissions.every((perm) => permissions.includes(perm))
      : requiredPermissions.some((perm) => permissions.includes(perm));
  }
}
