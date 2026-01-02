import {
  SetMetadata,
  createParamDecorator,
  ExecutionContext,
  CustomDecorator,
  applyDecorators,
} from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import {
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
  HOOK_KEY,
  RolesOptions,
  PermissionsOptions,
  FreshSessionOptions,
  OrgPermissionOptions,
  ApiKeyPermissionOptions,
} from './auth.types';

/**
 * GraphQL context interface
 */
interface GqlContext {
  req: FastifyRequest;
}

/**
 * GqlExecutionContext type for lazy loading
 * This interface matches the subset of @nestjs/graphql GqlExecutionContext we use
 */
interface GqlExecutionContextClass {
  create(context: ExecutionContext): {
    getContext<T = object>(): T;
  };
}

/**
 * Cached GqlExecutionContext class
 */
let cachedGqlExecutionContext: GqlExecutionContextClass | null = null;

/**
 * Lazily load GqlExecutionContext from @nestjs/graphql
 * Only loaded when GraphQL context is actually used
 */
function getGqlExecutionContext(): GqlExecutionContextClass {
  if (cachedGqlExecutionContext) {
    return cachedGqlExecutionContext;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const graphqlModule = require('@nestjs/graphql') as {
      GqlExecutionContext: GqlExecutionContextClass;
    };
    cachedGqlExecutionContext = graphqlModule.GqlExecutionContext;
    return cachedGqlExecutionContext;
  } catch {
    throw new Error(
      'GraphQL context detected but @nestjs/graphql is not installed. ' +
        'Please install it: pnpm add @nestjs/graphql graphql',
    );
  }
}

// ============================================
// Metadata Keys (Internal Use)
// ============================================

/** @internal */
export const ALLOW_ANONYMOUS_KEY = 'auth:allowAnonymous';
export const OPTIONAL_AUTH_KEY = 'auth:optional';
export const ROLES_KEY = 'auth:roles';
export const PERMISSIONS_KEY = 'auth:permissions';
export const FRESH_SESSION_KEY = 'auth:freshSession';
export const ADMIN_ONLY_KEY = 'auth:adminOnly';
export const BAN_CHECK_KEY = 'auth:banCheck';
export const BEARER_AUTH_KEY = 'auth:bearerAuth';
export const API_KEY_AUTH_KEY = 'auth:apiKeyAuth';
export const DISALLOW_IMPERSONATION_KEY = 'auth:disallowImpersonation';
export const ORG_REQUIRED_KEY = 'auth:orgRequired';
export const ORG_ROLES_KEY = 'auth:orgRoles';
export const ORG_PERMISSIONS_KEY = 'auth:orgPermissions';

// ============================================
// Metadata Value Types
// ============================================

export interface RolesMetadata {
  roles: string[];
  options: RolesOptions;
}

export interface PermissionsMetadata {
  permissions: string[];
  options: PermissionsOptions;
}

export interface FreshSessionMetadata {
  options: FreshSessionOptions;
}

export interface ApiKeyAuthMetadata {
  /** Whether to allow session authentication as fallback */
  allowSession?: boolean;
  /** API Key permission requirements */
  permissions?: ApiKeyPermissionOptions;
}

export interface OrgRolesMetadata {
  roles: string[];
  options: RolesOptions;
}

export interface OrgPermissionsMetadata {
  options: OrgPermissionOptions;
}

// ============================================
// Route Decorators
// ============================================

/**
 * Allow anonymous access, bypassing authentication checks
 *
 * @example
 * ```typescript
 * @Get('public')
 * @AllowAnonymous()
 * getPublicData() {
 *   return { message: 'public data' };
 * }
 * ```
 */
export const AllowAnonymous = (): CustomDecorator<string> =>
  SetMetadata(ALLOW_ANONYMOUS_KEY, true);

/**
 * Optional authentication - injects session if present, allows access without session
 *
 * @example
 * ```typescript
 * @Get('optional')
 * @OptionalAuth()
 * getData(@Session() session: UserSession | null) {
 *   return { authenticated: !!session };
 * }
 * ```
 */
export const OptionalAuth = (): CustomDecorator<string> =>
  SetMetadata(OPTIONAL_AUTH_KEY, true);

/**
 * Role-based access control - requires user to have specified roles
 *
 * @param roles - List of allowed roles
 * @param options - Configuration options
 *
 * @example
 * ```typescript
 * // OR logic (default): user must have either admin or moderator role
 * @Roles(['admin', 'moderator'])
 *
 * // AND logic: user must have both admin and verified roles
 * @Roles(['admin', 'verified'], { mode: 'all' })
 *
 * // Custom error message
 * @Roles(['admin'], { message: 'Administrator access required' })
 * ```
 */
export function Roles(
  roles: string[],
  options: RolesOptions = {},
): CustomDecorator<string> {
  const metadata: RolesMetadata = {
    roles,
    options: { mode: 'any', ...options },
  };
  return SetMetadata(ROLES_KEY, metadata);
}

/**
 * Permission-based access control - requires user to have specified permissions
 *
 * @param permissions - List of required permissions
 * @param options - Configuration options
 *
 * @example
 * ```typescript
 * // OR logic (default): user must have at least one permission
 * @Permissions(['user:read', 'user:write'])
 *
 * // AND logic: user must have all permissions
 * @Permissions(['user:read', 'user:write'], { mode: 'all' })
 *
 * // Custom error message
 * @Permissions(['admin:access'], { message: 'Admin access required' })
 * ```
 */
export function Permissions(
  permissions: string[],
  options: PermissionsOptions = {},
): CustomDecorator<string> {
  const metadata: PermissionsMetadata = {
    permissions,
    options: { mode: 'any', ...options },
  };
  return SetMetadata(PERMISSIONS_KEY, metadata);
}

// ============================================
// Session Freshness Decorators
// ============================================

/**
 * Require a fresh session (recently authenticated)
 * Suitable for sensitive operations like password changes, 2FA binding, etc.
 *
 * In Better Auth, session.createdAt within the freshAge window is considered "fresh"
 *
 * @param options - Configuration options
 *
 * @example
 * ```typescript
 * // Use default freshAge (from auth config, defaults to 1 day)
 * @RequireFreshSession()
 * @Post('change-password')
 * changePassword() {}
 *
 * // Custom freshAge (5 minutes)
 * @RequireFreshSession({ maxAge: 300 })
 * @Post('enable-2fa')
 * enable2FA() {}
 * ```
 */
export function RequireFreshSession(
  options: FreshSessionOptions = {},
): CustomDecorator<string> {
  const metadata: FreshSessionMetadata = { options };
  return SetMetadata(FRESH_SESSION_KEY, metadata);
}

// ============================================
// Admin Plugin Decorators
// ============================================
// The following decorators require the Better Auth Admin plugin
// Documentation: https://www.better-auth.com/docs/plugins/admin
//
// Configuration example:
// ```typescript
// import { betterAuth } from "better-auth";
// import { admin } from "better-auth/plugins";
//
// export const auth = betterAuth({
//   plugins: [admin()],
// });
// ```
// ============================================

/**
 * Restrict access to administrators only
 * Requires user role to be 'admin'
 *
 * **Requires Admin Plugin**: `admin()` from "better-auth/plugins"
 *
 * @param message - Custom error message
 *
 * @example
 * ```typescript
 * @AdminOnly()
 * @Get('admin/users')
 * listUsers() {}
 *
 * @AdminOnly('Administrator privileges required')
 * @Delete('admin/users/:id')
 * deleteUser() {}
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/admin
 */
export function AdminOnly(message?: string): CustomDecorator<string> {
  return SetMetadata(ADMIN_ONLY_KEY, { message });
}

/**
 * Check if user is banned
 * Denies access if user is banned
 *
 * **Requires Admin Plugin**: `admin()` from "better-auth/plugins"
 *
 * The Admin plugin adds `banned`, `banReason`, and `banExpires` fields to the user
 *
 * @example
 * ```typescript
 * @BanCheck()
 * @Post('comments')
 * createComment() {}
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/admin#ban-users
 */
export const BanCheck = (): CustomDecorator<string> =>
  SetMetadata(BAN_CHECK_KEY, true);

/**
 * Prevent impersonated sessions from accessing the route
 * Suitable for sensitive operations like fund transfers, account deletion, etc.
 *
 * **Requires Admin Plugin**: `admin()` from "better-auth/plugins"
 *
 * The Admin plugin's impersonation feature allows administrators to log in as other users.
 * This decorator prevents such sessions from performing sensitive operations.
 *
 * @param message - Custom error message
 *
 * @example
 * ```typescript
 * @DisallowImpersonation()
 * @Post('transfer-funds')
 * transferFunds() {}
 *
 * @DisallowImpersonation('This action cannot be performed while impersonating')
 * @Delete('account')
 * deleteAccount() {}
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/admin#user-impersonation
 */
export function DisallowImpersonation(
  message?: string,
): CustomDecorator<string> {
  return SetMetadata(DISALLOW_IMPERSONATION_KEY, { message });
}

// ============================================
// Alternative Auth Method Decorators
// ============================================
// For supporting non-cookie authentication methods
// ============================================

/**
 * Enable Bearer Token authentication
 * For clients that don't support cookies (e.g., mobile apps, CLI, third-party integrations)
 *
 * **Requires Bearer Plugin**: `bearer()` from "better-auth/plugins"
 *
 * The Bearer plugin enables authentication via `Authorization: Bearer <session-token>` header,
 * suitable for mobile applications, CLI tools, or scenarios where cookies are inconvenient.
 *
 * @example
 * ```typescript
 * // Better Auth configuration
 * import { bearer } from "better-auth/plugins";
 * export const auth = betterAuth({
 *   plugins: [bearer()],
 * });
 *
 * // Controller usage
 * @BearerAuth()
 * @Get('api/mobile/data')
 * getMobileData() {}
 * ```
 *
 * Client usage:
 * ```bash
 * curl -H "Authorization: Bearer <session-token>" /api/mobile/data
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/bearer
 */
export const BearerAuth = (): CustomDecorator<string> =>
  SetMetadata(BEARER_AUTH_KEY, true);

/**
 * Enable API Key authentication
 * For server-to-server communication, CI/CD, automation scripts, etc.
 *
 * **Requires API Key Plugin**: `apiKey()` from "better-auth/plugins"
 *
 * The API Key plugin allows users to create long-lived API keys with fine-grained permission control
 *
 * @param options - Configuration options
 * @param options.allowSession - Whether to allow session authentication as fallback
 * @param options.permissions - API Key permission requirements (resource-action mapping)
 *
 * @example
 * ```typescript
 * // Better Auth configuration
 * import { apiKey } from "better-auth/plugins";
 * export const auth = betterAuth({
 *   plugins: [apiKey()],
 * });
 *
 * // API Key authentication only
 * @ApiKeyAuth()
 * @Get('api/external')
 * externalApi() {}
 *
 * // Allow API Key or Session authentication (flexible mode)
 * @ApiKeyAuth({ allowSession: true })
 * @Get('api/flexible')
 * flexibleApi() {}
 *
 * // Require specific resource permissions
 * @ApiKeyAuth({
 *   permissions: {
 *     permissions: { files: ['read', 'write'] },
 *     message: 'Requires files:read and files:write permissions',
 *   },
 * })
 * @Post('api/files')
 * uploadFile() {}
 * ```
 *
 * Client usage:
 * ```bash
 * curl -H "X-API-Key: <api-key>" /api/external
 * # or
 * curl -H "Authorization: Bearer <api-key>" /api/external
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/api-key
 */
export function ApiKeyAuth(
  options: ApiKeyAuthMetadata = {},
): CustomDecorator<string> {
  return SetMetadata(API_KEY_AUTH_KEY, options);
}

// ============================================
// Organization Plugin Decorators
// ============================================
// The following decorators require the Better Auth Organization plugin
// Documentation: https://www.better-auth.com/docs/plugins/organization
//
// Configuration example:
// ```typescript
// import { betterAuth } from "better-auth";
// import { organization } from "better-auth/plugins";
//
// export const auth = betterAuth({
//   plugins: [
//     organization({
//       // Optional: custom roles
//       roles: {
//         owner: { inherit: ["admin"] },
//         admin: { inherit: ["member"] },
//         member: { permissions: ["read"] },
//       },
//     }),
//   ],
// });
// ```
// ============================================

/**
 * Require user to belong to an organization
 * Request must include organization ID (typically via header or query parameter)
 *
 * **Requires Organization Plugin**: `organization()` from "better-auth/plugins"
 *
 * @example
 * ```typescript
 * @OrgRequired()
 * @Get('org/dashboard')
 * getOrgDashboard(@CurrentOrg() org: Organization) {
 *   return { name: org.name };
 * }
 * ```
 *
 * Client usage (must include organization ID):
 * ```bash
 * curl -H "x-organization-id: <org-id>" /org/dashboard
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/organization
 */
export const OrgRequired = (): CustomDecorator<string> =>
  SetMetadata(ORG_REQUIRED_KEY, true);

/**
 * Require user to have specified roles within the organization
 *
 * **Requires Organization Plugin**: `organization()` from "better-auth/plugins"
 *
 * Default roles: owner, admin, member
 * Custom roles and permission inheritance can be configured in the Organization plugin
 *
 * @param roles - List of allowed organization roles
 * @param options - Configuration options
 *
 * @example
 * ```typescript
 * // Require owner or admin role (OR logic, default)
 * @OrgRoles(['owner', 'admin'])
 * @Put('org/settings')
 * updateOrgSettings(@CurrentOrg() org: Organization) {}
 *
 * // Require multiple roles (AND logic)
 * @OrgRoles(['admin', 'billing'], { mode: 'all' })
 * @Post('org/billing')
 * manageBilling() {}
 *
 * // Custom error message
 * @OrgRoles(['owner'], { message: 'Only organization owner can perform this action' })
 * @Delete('org')
 * deleteOrg() {}
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/organization#roles--permissions
 */
export function OrgRoles(
  roles: string[],
  options: RolesOptions = {},
): CustomDecorator<string> {
  const metadata: OrgRolesMetadata = {
    roles,
    options: { mode: 'any', ...options },
  };
  return SetMetadata(ORG_ROLES_KEY, metadata);
}

/**
 * Require user to have specified permissions within the organization
 *
 * **Requires Organization Plugin**: `organization()` from "better-auth/plugins"
 *
 * Fine-grained permission control based on resources and actions,
 * customizable in the Organization plugin configuration
 *
 * @param options - Permission configuration
 * @param options.resource - Resource name (e.g., 'member', 'organization', 'invite')
 * @param options.action - Action name or array of actions (e.g., 'create', 'read', 'update', 'delete')
 * @param options.mode - Matching mode ('any' | 'all'), defaults to 'any'
 * @param options.message - Custom error message
 *
 * @example
 * ```typescript
 * // Single permission check
 * @OrgPermission({ resource: 'member', action: 'create' })
 * @Post('org/members')
 * inviteMember(@CurrentOrg() org: Organization) {}
 *
 * // Multiple actions check (OR logic)
 * @OrgPermission({ resource: 'organization', action: ['update', 'delete'], mode: 'any' })
 * @Put('org/settings')
 * updateOrg() {}
 *
 * // Multiple actions check (AND logic)
 * @OrgPermission({ resource: 'member', action: ['read', 'update'], mode: 'all' })
 * @Put('org/members/:id')
 * updateMember() {}
 *
 * // Custom error message
 * @OrgPermission({
 *   resource: 'invite',
 *   action: 'create',
 *   message: 'You do not have permission to invite members',
 * })
 * @Post('org/invitations')
 * createInvitation() {}
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/organization#roles--permissions
 */
export function OrgPermission(
  options: OrgPermissionOptions,
): CustomDecorator<string> {
  const metadata: OrgPermissionsMetadata = { options };
  return SetMetadata(ORG_PERMISSIONS_KEY, metadata);
}

// ============================================
// Composite Decorators
// ============================================
// Convenience methods combining multiple decorators for common use cases
// ============================================

/**
 * Composite decorator: Secure admin operations
 * Requires: Admin role + Fresh session + Non-impersonated session
 *
 * **Requires Admin Plugin**: `admin()` from "better-auth/plugins"
 *
 * Suitable for high-risk admin operations such as:
 * - Deleting users
 * - Modifying system configuration
 * - Viewing sensitive logs
 *
 * @example
 * ```typescript
 * // Equivalent to applying:
 * // @AdminOnly()
 * // @RequireFreshSession()
 * // @DisallowImpersonation()
 *
 * @SecureAdminOnly()
 * @Delete('admin/users/:id')
 * deleteUser(@Session() session: UserSession) {
 *   // Only real admins with fresh sessions can execute this
 * }
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/admin
 */
export function SecureAdminOnly() {
  return applyDecorators(
    AdminOnly(),
    RequireFreshSession(),
    DisallowImpersonation(),
  );
}

// ============================================
// Parameter Decorators
// ============================================

/**
 * WebSocket data with request info
 */
interface WsData {
  request?: FastifyRequest;
  req?: FastifyRequest;
  handshake?: {
    headers?: Record<string, string | string[] | undefined>;
  };
}

/**
 * Extract request object from execution context
 * Supports HTTP, GraphQL, and WebSocket
 */
export function getRequestFromContext(ctx: ExecutionContext): FastifyRequest {
  const contextType = ctx.getType<string>();

  // GraphQL (@nestjs/graphql is an optional peer dependency, loaded lazily)
  if (contextType === 'graphql') {
    const GqlExecutionContext = getGqlExecutionContext();
    const gqlContext = GqlExecutionContext.create(ctx).getContext<GqlContext>();
    return gqlContext.req;
  }

  // WebSocket - get request from connection data, not from client
  if (contextType === 'ws') {
    const wsContext = ctx.switchToWs();

    // Try to get request from data (set during connection handshake)
    const data = wsContext.getData<WsData>();
    if (data?.request) {
      return data.request;
    }
    if (data?.req) {
      return data.req;
    }

    // Fallback: try to get from client (Socket.io style)
    const client = wsContext.getClient<{ handshake?: WsData['handshake'] }>();
    if (client?.handshake?.headers) {
      // Create a minimal request-like object from handshake
      return {
        headers: client.handshake.headers,
        session: null,
        user: null,
      } as unknown as FastifyRequest;
    }

    // Last resort: return HTTP request (might work in some setups)
    return ctx.switchToHttp().getRequest<FastifyRequest>();
  }

  // HTTP (default)
  return ctx.switchToHttp().getRequest<FastifyRequest>();
}

/**
 * Get current user session
 * Supports HTTP, GraphQL, and WebSocket
 *
 * @example
 * ```typescript
 * @Get('profile')
 * getProfile(@Session() session: UserSession) {
 *   return session;
 * }
 * ```
 */
export const Session = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.session;
  },
);

/**
 * Get current user information (shorthand for session.user)
 * Supports HTTP, GraphQL, and WebSocket
 *
 * @example
 * ```typescript
 * @Get('me')
 * getMe(@CurrentUser() user: UserSession['user']) {
 *   return user;
 * }
 * ```
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.user;
  },
);

/**
 * Get a specific property from the current user
 *
 * @param property - Name of the user property to retrieve
 *
 * @example
 * ```typescript
 * @Get('my-id')
 * getMyId(@UserProperty('id') userId: string) {
 *   return { userId };
 * }
 *
 * @Get('my-email')
 * getMyEmail(@UserProperty('email') email: string) {
 *   return { email };
 * }
 * ```
 */
export const UserProperty = createParamDecorator(
  (property: string, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.user?.[property as keyof typeof request.user];
  },
);

/**
 * Get API Key validation result
 * Returns ApiKeyValidation object containing key info, remaining quota, etc.
 *
 * **Requires API Key Plugin**: `apiKey()` from "better-auth/plugins"
 *
 * Must be used with @ApiKeyAuth() decorator
 *
 * @example
 * ```typescript
 * @ApiKeyAuth()
 * @Get('api/usage')
 * getUsage(@ApiKey() apiKey: ApiKeyValidation) {
 *   return {
 *     name: apiKey?.key?.name,
 *     remaining: apiKey?.key?.remaining,
 *     permissions: apiKey?.key?.permissions,
 *   };
 * }
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/api-key
 */
export const ApiKey = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.apiKey;
  },
);

/**
 * Get current organization information
 * Returns Organization object containing organization ID, name, slug, etc.
 *
 * **Requires Organization Plugin**: `organization()` from "better-auth/plugins"
 *
 * Typically used with @OrgRequired() decorator to ensure organization context exists
 *
 * @example
 * ```typescript
 * @OrgRequired()
 * @Get('org/info')
 * getOrgInfo(@CurrentOrg() org: Organization) {
 *   return {
 *     id: org.id,
 *     name: org.name,
 *     slug: org.slug,
 *   };
 * }
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/organization
 */
export const CurrentOrg = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.organization;
  },
);

/**
 * Get current user's membership information within the organization
 * Returns OrganizationMember object containing role, permissions, join date, etc.
 *
 * **Requires Organization Plugin**: `organization()` from "better-auth/plugins"
 *
 * Typically used with @OrgRequired() decorator to ensure organization context exists
 *
 * @example
 * ```typescript
 * @OrgRequired()
 * @Get('org/my-role')
 * getMyOrgRole(@OrgMember() member: OrganizationMember) {
 *   return {
 *     role: member.role,
 *     userId: member.userId,
 *     createdAt: member.createdAt,
 *   };
 * }
 *
 * // Combined with permission checks
 * @OrgRoles(['admin', 'owner'])
 * @Get('org/admin-info')
 * getAdminInfo(
 *   @CurrentOrg() org: Organization,
 *   @OrgMember() member: OrganizationMember
 * ) {
 *   return { org, member };
 * }
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/organization
 */
export const OrgMember = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.organizationMember;
  },
);

/**
 * Check if current session is being impersonated
 * Returns true when an administrator is logged in as another user via impersonation
 *
 * **Requires Admin Plugin**: `admin()` from "better-auth/plugins"
 *
 * Use cases:
 * - Display "Operating as XXX" notice in UI
 * - Mark impersonation in audit logs
 * - Show additional warning messages on certain pages
 *
 * @example
 * ```typescript
 * @Get('profile')
 * getProfile(
 *   @CurrentUser() user: UserSession['user'],
 *   @IsImpersonating() isImpersonating: boolean
 * ) {
 *   return {
 *     user,
 *     isImpersonating,
 *     warning: isImpersonating ? 'Currently in impersonation mode' : null,
 *   };
 * }
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/admin#user-impersonation
 */
export const IsImpersonating = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.isImpersonating ?? false;
  },
);

/**
 * Get the ID of the administrator performing impersonation
 * Used for audit logging to track which administrator performed the impersonation
 *
 * **Requires Admin Plugin**: `admin()` from "better-auth/plugins"
 *
 * Only has value during impersonation sessions; returns null for regular sessions
 *
 * @example
 * ```typescript
 * // Audit logging example
 * @Post('sensitive-action')
 * async sensitiveAction(
 *   @CurrentUser() user: UserSession['user'],
 *   @IsImpersonating() isImpersonating: boolean,
 *   @ImpersonatedBy() adminId: string | null
 * ) {
 *   // Record audit log
 *   await this.auditService.log({
 *     action: 'sensitive-action',
 *     userId: user.id,
 *     isImpersonated: isImpersonating,
 *     impersonatedBy: adminId,  // Record admin ID if impersonating
 *   });
 *   return { success: true };
 * }
 * ```
 *
 * @see https://www.better-auth.com/docs/plugins/admin#user-impersonation
 */
export const ImpersonatedBy = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.impersonatedBy ?? null;
  },
);

// ============================================
// Hook Decorators
// ============================================
// Enable custom logic before and after Better Auth processes authentication requests
// Use cases: data validation, user association, logging, notifications, etc.
//
// Usage steps:
// 1. Create a Hook Provider class with @Hook() and @Injectable() decorators
// 2. Add @BeforeHook() or @AfterHook() decorators to methods
// 3. Register the Hook Provider in the module's providers array
// ============================================

/**
 * Mark a class as a Hook Provider
 * Must be used with @BeforeHook or @AfterHook
 *
 * Hook Provider classes require:
 * 1. @Hook() decorator
 * 2. @Injectable() decorator
 * 3. Registration in the module's providers array
 *
 * @example
 * ```typescript
 * // src/auth/hooks/sign-up.hook.ts
 * import { Injectable } from '@nestjs/common';
 * import { Hook, BeforeHook, AfterHook, AuthHookContext } from '../auth/index.js';
 *
 * @Hook()
 * @Injectable()
 * export class SignUpHook {
 *   constructor(private readonly emailService: EmailService) {}
 *
 *   // Validate before sign-up
 *   @BeforeHook('/sign-up/email')
 *   async validateBeforeSignUp(ctx: AuthHookContext) {
 *     const { email } = ctx.body as { email: string };
 *     if (email.endsWith('@blocked-domain.com')) {
 *       throw new Error('This email domain is not allowed');
 *     }
 *   }
 *
 *   // Send welcome email after sign-up
 *   @AfterHook('/sign-up/email')
 *   async sendWelcomeEmail(ctx: AuthHookContext) {
 *     const user = ctx.context?.user;
 *     if (user) {
 *       await this.emailService.sendWelcome(user.email);
 *     }
 *   }
 * }
 *
 * // app.module.ts
 * @Module({
 *   imports: [AuthModule.forRoot({ auth })],
 *   providers: [SignUpHook],  // Register Hook Provider
 * })
 * export class AppModule {}
 * ```
 */
export const Hook = (): ClassDecorator => SetMetadata(HOOK_KEY, true);

/**
 * Execute before a specified authentication route is processed
 * Useful for data validation, preprocessing, permission checks, etc.
 *
 * @param path - Authentication route path; matches all routes if not specified
 *
 * Common paths:
 * - `/sign-up/email` - Email sign-up
 * - `/sign-in/email` - Email sign-in
 * - `/sign-out` - Sign out
 * - `/forget-password` - Forgot password
 * - `/reset-password` - Reset password
 * - `/verify-email` - Email verification
 *
 * @example
 * ```typescript
 * // Match specific route
 * @BeforeHook('/sign-up/email')
 * async beforeSignUp(ctx: AuthHookContext) {
 *   // Executes only before email sign-up
 * }
 *
 * // Match all authentication routes
 * @BeforeHook()
 * async beforeAllAuth(ctx: AuthHookContext) {
 *   console.log('Auth request:', ctx.path);
 * }
 * ```
 */
export const BeforeHook = (path?: `/${string}`): CustomDecorator<symbol> =>
  SetMetadata(BEFORE_HOOK_KEY, path);

/**
 * Execute after a specified authentication route is processed
 * Useful for sending notifications, logging, data synchronization, etc.
 *
 * @param path - Authentication route path; matches all routes if not specified
 *
 * @example
 * ```typescript
 * // Log after sign-in
 * @AfterHook('/sign-in/email')
 * async afterSignIn(ctx: AuthHookContext) {
 *   const user = ctx.context?.user;
 *   await this.auditService.log('user_login', { userId: user?.id });
 * }
 *
 * // Sync to third-party service after sign-up
 * @AfterHook('/sign-up/email')
 * async afterSignUp(ctx: AuthHookContext) {
 *   const user = ctx.context?.user;
 *   await this.crmService.createContact(user);
 * }
 * ```
 */
export const AfterHook = (path?: `/${string}`): CustomDecorator<symbol> =>
  SetMetadata(AFTER_HOOK_KEY, path);

// ============================================
// Compatibility Aliases (Optional)
// ============================================

/** @deprecated Use AllowAnonymous instead */
export const Public = AllowAnonymous;

/** @deprecated Use OptionalAuth instead */
export const Optional = OptionalAuth;
