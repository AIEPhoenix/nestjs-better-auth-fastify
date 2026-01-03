import { Controller, Get, Post, Req, Headers, Param } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiHeader,
} from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import {
  AllowAnonymous,
  OptionalAuth,
  Session,
  CurrentUser,
  UserProperty,
  AuthService,
} from '@sapix/nestjs-better-auth-fastify';
import type { UserSession, AdminUser } from '@sapix/nestjs-better-auth-fastify';
import { AppService } from './app.service';

/**
 * Main Application Controller
 * Demonstrates basic usage patterns and AuthService usage
 */
@ApiTags('App')
@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly authService: AuthService,
  ) {}

  @Get()
  @AllowAnonymous()
  @ApiOperation({
    summary: 'Health check',
    description: 'Public health check endpoint',
  })
  @ApiResponse({ status: 200, description: 'Returns Hello World' })
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('info')
  @AllowAnonymous()
  @ApiOperation({
    summary: 'API information',
    description:
      'Lists all available decorators, endpoints, and module options',
  })
  @ApiResponse({ status: 200, description: 'API information object' })
  getApiInfo() {
    return {
      name: 'NestJS Better Auth Fastify Example',
      version: '1.0.0',
      description:
        'Complete usage demonstration of @sapix/nestjs-better-auth-fastify',
      endpoints: {
        auth: '/api/auth/*',
        users: '/users/*',
        admin: '/admin/*',
        organizations: '/organizations/*',
        apiKeys: '/api-keys/*',
      },
      decorators: {
        accessControl: [
          '@AllowAnonymous() - Allow unauthenticated access',
          '@OptionalAuth() - Authentication optional, session attached if available',
          '@Roles(roles, options?) - Require specific user roles',
          '@Permissions(permissions, options?) - Require specific permissions',
          '@RequireFreshSession(options?) - Require recently created session',
          '@AdminOnly(message?) - Admin role required',
          '@SecureAdminOnly() - Admin + fresh session + no impersonation',
          '@BanCheck() - Check if user is banned',
          '@DisallowImpersonation(message?) - Prevent access during impersonation',
          '@BearerAuth() - Require Bearer token authentication',
          '@ApiKeyAuth(options?) - Require API key authentication',
        ],
        organization: [
          '@OrgRequired() - Require active organization context',
          '@OrgRoles(roles, options?) - Require specific organization role',
          '@OrgPermission(options) - Require specific organization permission',
        ],
        parameters: [
          '@Session() - Get full session object (user + session)',
          '@CurrentUser() - Get current user object',
          '@UserProperty(property) - Get specific user property',
          '@ApiKey() - Get API key info (when using API key auth)',
          '@CurrentOrg() - Get current organization info',
          '@OrgMember() - Get organization membership info',
          '@IsImpersonating() - Check if session is impersonated',
          '@ImpersonatedBy() - Get admin ID who is impersonating',
        ],
        hooks: [
          '@Hook() - Mark class as hook provider',
          '@BeforeHook(path?) - Execute before auth route',
          '@AfterHook(path?) - Execute after auth route',
        ],
      },
      moduleOptions: [
        'auth - Better Auth instance (required)',
        'basePath - Auth routes base path (default: /api/auth)',
        'disableGlobalGuard - Disable global auth guard',
        'debug - Enable debug logging',
        'errorMessages - Custom error messages (i18n support)',
        'orgRolePermissions - Custom org role permission mapping',
        'middleware - Custom middleware wrapper',
      ],
      authServiceMethods: {
        session: [
          'getSessionFromRequest(request) - Get session from request',
          'validateSession(request) - Validate and return session',
          'revokeSession(sessionToken, request) - Revoke specific session',
          'revokeAllSessions(request) - Revoke all user sessions',
          'listUserSessions(request) - List all user sessions',
          'isSessionFresh(session, maxAge?) - Check session freshness',
        ],
        roleAndPermission: [
          'hasRole(session, roles) - Check user roles',
          'hasPermission(session, permissions) - Check user permissions',
        ],
        admin: [
          'isUserBanned(user) - Check if user is banned (takes AdminUser)',
          'isImpersonating(session) - Check impersonation status',
          'getImpersonatedBy(session) - Get impersonator admin ID',
        ],
        apiKey: ['verifyApiKey(key) - Verify API key programmatically'],
        organization: [
          'getActiveOrganization(request) - Get active organization',
          'hasOrgPermission(request, { resource, action }) - Check org permission',
        ],
        utility: [
          'instance - Get Better Auth instance',
          'api - Get Better Auth API object',
          'basePath - Get auth routes base path',
          '$Infer - Type inference helper (compile-time only)',
          'getJwtToken(request) - Get JWT token (requires JWT plugin)',
        ],
      },
    };
  }

  @Get('profile')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get user profile',
    description:
      'Protected route - requires authentication. Uses @Session() decorator.',
  })
  @ApiResponse({ status: 200, description: 'User profile with session info' })
  @ApiResponse({ status: 401, description: 'Unauthorized - no valid session' })
  getProfile(@Session() session: UserSession) {
    return {
      message: 'This is a protected route',
      session: {
        user: {
          id: session.user.id,
          email: session.user.email,
          name: session.user.name,
        },
        sessionId: session.session.id,
        createdAt: session.session.createdAt,
        expiresAt: session.session.expiresAt,
      },
    };
  }

  @Get('me')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get current user',
    description:
      'Returns current user information using @CurrentUser() decorator',
  })
  @ApiResponse({ status: 200, description: 'Current user object' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMe(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Current user information',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        emailVerified: user.emailVerified,
        image: user.image,
        role: user.role,
      },
    };
  }

  @Get('my-email')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get user email',
    description: 'Demonstrates @UserProperty() decorator to get a single field',
  })
  @ApiResponse({ status: 200, description: 'User email address' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMyEmail(@UserProperty('email') email: string) {
    return {
      message: 'Your email address',
      email,
    };
  }

  @Get('my-role')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get user role',
    description: 'Returns user role using @UserProperty() decorator',
  })
  @ApiResponse({ status: 200, description: 'User role' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMyRole(@UserProperty('role') role: string | undefined) {
    return {
      message: 'Your role',
      role: role ?? 'user',
    };
  }

  @Get('greeting')
  @OptionalAuth()
  @ApiOperation({
    summary: 'Get greeting',
    description:
      'Optional auth - returns personalized or guest greeting based on auth status',
  })
  @ApiResponse({
    status: 200,
    description: 'Greeting message (personalized if authenticated)',
  })
  getGreeting(@CurrentUser() user: UserSession['user'] | null) {
    if (user) {
      return {
        message: `Hello, ${user.name || user.email}!`,
        authenticated: true,
        userId: user.id,
      };
    }
    return {
      message: 'Hello, Guest!',
      authenticated: false,
      hint: 'Log in to see personalized greeting',
    };
  }

  // ============================================
  // AuthService Usage Examples
  // ============================================

  @Get('session-via-service')
  @OptionalAuth()
  @ApiOperation({
    summary: 'Get session via AuthService',
    description:
      'Demonstrates programmatic session retrieval using AuthService.getSessionFromRequest()',
  })
  @ApiResponse({
    status: 200,
    description: 'Session info or not authenticated message',
  })
  async getSessionViaService(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return {
        message: 'Not authenticated',
        authenticated: false,
      };
    }

    return {
      message: 'Session retrieved via AuthService',
      authenticated: true,
      user: {
        id: session.user.id,
        email: session.user.email,
      },
      sessionId: session.session.id,
    };
  }

  @Get('check-admin')
  @OptionalAuth()
  @ApiOperation({
    summary: 'Check admin status',
    description:
      'Programmatically check user roles using AuthService.hasRole()',
  })
  @ApiResponse({ status: 200, description: 'Admin and moderator status' })
  async checkAdmin(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { isAdmin: false, reason: 'Not authenticated' };
    }

    const isAdmin = this.authService.hasRole(session, ['admin']);
    const isModerator = this.authService.hasRole(session, [
      'moderator',
      'admin',
    ]);

    return {
      userId: session.user.id,
      isAdmin,
      isModerator,
      currentRole: session.user.role ?? 'user',
    };
  }

  @Get('check-session-fresh')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check session freshness',
    description:
      'Check if session was recently created using AuthService.isSessionFresh()',
  })
  @ApiResponse({ status: 200, description: 'Session freshness info' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async checkSessionFresh(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { isFresh: false, reason: 'Not authenticated' };
    }

    const isFreshOneHour = this.authService.isSessionFresh(session, 3600);
    const isFreshDefault = this.authService.isSessionFresh(session);

    return {
      sessionCreatedAt: session.session.createdAt,
      isFreshOneHour,
      isFreshDefault,
    };
  }

  @Get('check-impersonation')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check impersonation status',
    description: 'Check if current session is being impersonated by an admin',
  })
  @ApiResponse({ status: 200, description: 'Impersonation status' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async checkImpersonation(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { isImpersonating: false, reason: 'Not authenticated' };
    }

    const isImpersonating = this.authService.isImpersonating(session);
    const impersonatedBy = this.authService.getImpersonatedBy(session);

    return {
      userId: session.user.id,
      isImpersonating,
      impersonatedBy,
    };
  }

  @Get('my-sessions')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'List user sessions',
    description: 'Get all active sessions for the current user',
  })
  @ApiResponse({ status: 200, description: 'List of active sessions' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async listMySessions(@Req() request: FastifyRequest) {
    const sessions = await this.authService.listUserSessions(request);

    return {
      message: 'Your active sessions',
      count: sessions.length,
      sessions: sessions.map((s) => ({
        id: s.session?.id,
        createdAt: s.session?.createdAt,
        expiresAt: s.session?.expiresAt,
      })),
    };
  }

  @Post('logout-all')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Logout from all devices',
    description: 'Revoke all sessions for the current user',
  })
  @ApiResponse({ status: 201, description: 'All sessions revoked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logoutAll(@Req() request: FastifyRequest) {
    const success = await this.authService.revokeAllSessions(request);

    return {
      message: success
        ? 'All sessions revoked successfully'
        : 'Failed to revoke sessions',
      success,
    };
  }

  @Get('jwt')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get JWT token',
    description: 'Get JWT token for the current session (requires JWT plugin)',
  })
  @ApiResponse({
    status: 200,
    description: 'JWT token or not available message',
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getJwt(@Req() request: FastifyRequest) {
    const token = await this.authService.getJwtToken(request);

    if (!token) {
      return {
        message: 'JWT token not available',
        note: 'JWT plugin may not be enabled',
      };
    }

    return {
      message: 'JWT token retrieved',
      token,
      note: 'Use this token for stateless authentication',
    };
  }

  @Get('auth-api-info')
  @AllowAnonymous()
  @ApiOperation({
    summary: 'Better Auth API info',
    description: 'Shows how to access Better Auth API directly via AuthService',
  })
  @ApiResponse({ status: 200, description: 'API usage examples' })
  getAuthApiInfo() {
    return {
      message: 'AuthService provides direct access to Better Auth API',
      usage: 'this.authService.api.<methodName>({ headers, body })',
      examples: [
        'authService.api.getSession({ headers }) - Get session',
        'authService.api.signOut({ headers }) - Sign out',
        'authService.api.listSessions({ headers }) - List sessions',
        'authService.api.verifyApiKey({ body: { key } }) - Verify API key',
        'authService.api.getFullOrganization({ headers }) - Get organization',
      ],
      note: 'The API methods depend on which Better Auth plugins are enabled',
      basePath: this.authService.basePath,
    };
  }

  // ============================================
  // Additional AuthService Methods Examples
  // ============================================

  @Get('check-permissions')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check user permissions',
    description:
      'Programmatically check permissions using AuthService.hasPermission()',
  })
  @ApiResponse({ status: 200, description: 'Permission check results' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async checkPermissions(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { hasPermission: false, reason: 'Not authenticated' };
    }

    const canReadReports = this.authService.hasPermission(session, [
      'read:reports',
    ]);
    const canAccessAnalytics = this.authService.hasPermission(session, [
      'read:analytics',
      'read:reports',
    ]);

    const userWithPerms = session.user as { permissions?: string | string[] };

    return {
      userId: session.user.id,
      permissions: {
        canReadReports,
        canAccessAnalytics,
      },
      userPermissions: userWithPerms.permissions ?? [],
    };
  }

  @Get('validate-session')
  @OptionalAuth()
  @ApiOperation({
    summary: 'Validate session',
    description:
      'Validate and get full session info using AuthService.validateSession()',
  })
  @ApiResponse({ status: 200, description: 'Session validation result' })
  async validateSession(@Req() request: FastifyRequest) {
    const validationResult = await this.authService.validateSession(request);

    if (!validationResult) {
      return {
        valid: false,
        reason: 'No session found or session invalid',
      };
    }

    return {
      valid: true,
      session: {
        id: validationResult.session.id,
        userId: validationResult.user.id,
        expiresAt: validationResult.session.expiresAt,
      },
    };
  }

  @Post('revoke-session/:sessionId')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Revoke specific session',
    description:
      'Revoke a specific session by ID (logout from specific device)',
  })
  @ApiParam({ name: 'sessionId', description: 'Session ID to revoke' })
  @ApiResponse({ status: 201, description: 'Session revoked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async revokeSession(
    @Param('sessionId') sessionId: string,
    @Req() request: FastifyRequest,
  ) {
    const success = await this.authService.revokeSession(sessionId, request);

    return {
      message: success
        ? 'Session revoked successfully'
        : 'Failed to revoke session',
      success,
      revokedSessionId: sessionId,
    };
  }

  @Get('check-ban-status')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check ban status',
    description:
      'Check if current user is banned using AuthService.isUserBanned()',
  })
  @ApiResponse({ status: 200, description: 'Ban status' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async checkBanStatus(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { isBanned: false, reason: 'Not authenticated' };
    }

    const adminUser = session.user as AdminUser;
    const isBanned = this.authService.isUserBanned(adminUser);

    return {
      userId: session.user.id,
      isBanned,
    };
  }

  @Get('verify-api-key')
  @AllowAnonymous()
  @ApiOperation({
    summary: 'Verify API key',
    description:
      'Programmatically verify an API key using AuthService.verifyApiKey()',
  })
  @ApiHeader({
    name: 'x-api-key',
    description: 'API key to verify',
    required: false,
  })
  @ApiResponse({ status: 200, description: 'API key validation result' })
  async verifyApiKey(@Headers('x-api-key') apiKey: string) {
    if (!apiKey) {
      return {
        valid: false,
        reason: 'No API key provided. Send via x-api-key header.',
      };
    }

    const result = await this.authService.verifyApiKey(apiKey);

    if (!result.valid || !result.key) {
      return {
        valid: false,
        reason: 'Invalid API key',
      };
    }

    return {
      valid: true,
      apiKey: {
        id: result.key.id,
        name: result.key.name,
        permissions: result.key.permissions,
      },
    };
  }

  @Get('active-organization')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get active organization',
    description:
      'Get the currently active organization using AuthService.getActiveOrganization()',
  })
  @ApiResponse({ status: 200, description: 'Active organization or null' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getActiveOrganization(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { organization: null, reason: 'Not authenticated' };
    }

    const organization = await this.authService.getActiveOrganization(request);

    if (!organization) {
      return {
        organization: null,
        reason:
          'No active organization set. Set x-org-id header or activeOrganizationId.',
      };
    }

    return {
      organization: {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
      },
    };
  }

  @Get('check-org-role')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check organization role',
    description: 'Check user role in active organization',
  })
  @ApiResponse({ status: 200, description: 'Organization role info' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async checkOrgRole(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { hasRole: false, reason: 'Not authenticated' };
    }

    const organization = await this.authService.getActiveOrganization(request);

    if (!organization) {
      return { hasRole: false, reason: 'No organization context' };
    }

    const member = request.organizationMember;

    return {
      organizationId: organization.id,
      currentRole: member?.role ?? 'unknown',
      note: 'Use @OrgRoles() decorator for role-based access control',
    };
  }

  @Get('check-org-permission')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check organization permission',
    description:
      'Check permissions in active organization using AuthService.hasOrgPermission()',
  })
  @ApiResponse({ status: 200, description: 'Organization permission results' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async checkOrgPermission(@Req() request: FastifyRequest) {
    const session = await this.authService.getSessionFromRequest(request);

    if (!session) {
      return { hasPermission: false, reason: 'Not authenticated' };
    }

    const organization = await this.authService.getActiveOrganization(request);

    if (!organization) {
      return { hasPermission: false, reason: 'No organization context' };
    }

    const canReadOrg = await this.authService.hasOrgPermission(request, {
      resource: 'organization',
      action: 'read',
    });
    const canUpdateOrg = await this.authService.hasOrgPermission(request, {
      resource: 'organization',
      action: 'update',
    });
    const canManageMembers = await this.authService.hasOrgPermission(request, {
      resource: 'member',
      action: 'create',
    });

    return {
      organizationId: organization.id,
      permissions: {
        canReadOrg,
        canUpdateOrg,
        canManageMembers,
      },
      note: 'Permissions are checked via Better Auth organization plugin',
    };
  }

  @Get('auth-instance-info')
  @AllowAnonymous()
  @ApiOperation({
    summary: 'Get Better Auth instance info',
    description: 'Access underlying Better Auth instance via AuthService',
  })
  @ApiResponse({
    status: 200,
    description: 'Instance availability and usage info',
  })
  getAuthInstanceInfo() {
    const instance = this.authService.instance;

    return {
      message: 'Direct access to Better Auth instance',
      available: !!instance,
      basePath: this.authService.basePath,
      usage: [
        'authService.instance - Get Better Auth instance',
        'authService.api - Get Better Auth API object',
        'authService.$Infer - Type inference helper (compile-time only)',
      ],
    };
  }
}
