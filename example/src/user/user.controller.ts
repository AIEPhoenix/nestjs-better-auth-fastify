import { Controller, Get, Post, Body } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiBody,
} from '@nestjs/swagger';
import {
  AllowAnonymous,
  OptionalAuth,
  Roles,
  Permissions,
  RequireFreshSession,
  BanCheck,
  DisallowImpersonation,
  Session,
  CurrentUser,
  UserProperty,
  IsImpersonating,
  ImpersonatedBy,
} from '@sapix/nestjs-better-auth-fastify';
import type { UserSession } from '@sapix/nestjs-better-auth-fastify';

/**
 * User Controller
 * Demonstrates usage of various authentication and authorization decorators
 */
@ApiTags('Users')
@Controller('users')
@BanCheck()
export class UserController {
  @Get('public-info')
  @AllowAnonymous()
  @ApiOperation({
    summary: 'Get public info',
    description: 'Public route accessible without authentication',
  })
  @ApiResponse({ status: 200, description: 'Public information' })
  getPublicInfo() {
    return {
      message: 'This is public information, accessible without login',
      serverTime: new Date().toISOString(),
    };
  }

  @Get('optional-profile')
  @OptionalAuth()
  @ApiOperation({
    summary: 'Get optional profile',
    description: 'Optional auth - logged-in users get more information',
  })
  @ApiResponse({ status: 200, description: 'Profile or guest message' })
  getOptionalProfile(@CurrentUser() user: UserSession['user'] | null) {
    if (user) {
      return {
        message: 'Welcome back!',
        user: { id: user.id, name: user.name, email: user.email },
      };
    }
    return {
      message: 'You are not logged in. Log in to see more information',
      isGuest: true,
    };
  }

  @Get('profile')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get user profile',
    description: 'Protected route - requires authentication',
  })
  @ApiResponse({ status: 200, description: 'User profile' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getProfile(@Session() session: UserSession) {
    return {
      message: 'Your profile',
      session: {
        userId: session.user.id,
        email: session.user.email,
        name: session.user.name,
        createdAt: session.session.createdAt,
        expiresAt: session.session.expiresAt,
      },
    };
  }

  @Get('me')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get current user',
    description: 'Returns user object without session info',
  })
  @ApiResponse({ status: 200, description: 'Current user' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMe(@CurrentUser() user: UserSession['user']) {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      emailVerified: user.emailVerified,
      image: user.image,
    };
  }

  @Get('moderator-area')
  @Roles(['moderator', 'admin'])
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Moderator area',
    description: 'Role-based access - requires moderator or admin role',
  })
  @ApiResponse({ status: 200, description: 'Moderator content' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - insufficient role' })
  getModeratorArea(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Welcome to the moderator area',
      user: user.name,
      accessLevel: 'moderator',
    };
  }

  @Get('reports')
  @Permissions(['read:reports'])
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get reports',
    description: 'Permission-based access - requires read:reports permission',
  })
  @ApiResponse({ status: 200, description: 'Report list' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - missing permission' })
  getReports(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Report list',
      user: user.name,
      reports: [
        { id: 1, title: 'Monthly Report', date: '2025-01-01' },
        { id: 2, title: 'Quarterly Report', date: '2025-01-15' },
      ],
    };
  }

  @Get('analytics')
  @Permissions(['read:analytics', 'read:reports'])
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get analytics',
    description: 'Requires any of: read:analytics or read:reports permission',
  })
  @ApiResponse({ status: 200, description: 'Analytics data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getAnalytics() {
    return {
      message: 'Analytics data',
      visitors: 1234,
      pageViews: 5678,
    };
  }

  @Post('change-password')
  @RequireFreshSession({ maxAge: 300 })
  @DisallowImpersonation()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Change password',
    description: 'Requires fresh session (5 min) and disallows impersonation',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        currentPassword: { type: 'string' },
        newPassword: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'Password change initiated' })
  @ApiResponse({ status: 401, description: 'Unauthorized or session not fresh' })
  changePassword(
    @CurrentUser() user: UserSession['user'],
    @Body() body: { currentPassword: string; newPassword: string },
  ) {
    return {
      message: 'Password change request received',
      user: user.email,
    };
  }

  @Get('session-info')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get session info',
    description: 'Returns session details including impersonation status',
  })
  @ApiResponse({ status: 200, description: 'Session information' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getSessionInfo(
    @Session() session: UserSession,
    @IsImpersonating() isImpersonating: boolean,
    @ImpersonatedBy() impersonatorId: string | null,
  ) {
    return {
      user: {
        id: session.user.id,
        email: session.user.email,
        name: session.user.name,
      },
      session: {
        id: session.session.id,
        createdAt: session.session.createdAt,
        expiresAt: session.session.expiresAt,
      },
      impersonation: {
        isImpersonating,
        impersonatedByAdminId: impersonatorId,
      },
    };
  }

  @Get('security-settings')
  @DisallowImpersonation()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get security settings',
    description: 'Only accessible by real users (not impersonated)',
  })
  @ApiResponse({ status: 200, description: 'Security settings' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - impersonation active' })
  getSecuritySettings(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Security settings (only accessible by real users)',
      user: user.email,
      twoFactorEnabled: false,
      lastPasswordChange: '2025-01-01',
    };
  }

  @Post('sensitive-action')
  @Roles(['admin', 'moderator'])
  @Permissions(['execute:sensitive-action'])
  @RequireFreshSession({ maxAge: 600 })
  @DisallowImpersonation()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Perform sensitive action',
    description: 'Requires: admin/moderator role + permission + fresh session + no impersonation',
  })
  @ApiBody({ schema: { type: 'object', properties: { action: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Action executed' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  performSensitiveAction(
    @CurrentUser() user: UserSession['user'],
    @Body() body: { action: string },
  ) {
    return {
      message: 'Sensitive action executed',
      user: user.email,
      action: body.action,
      timestamp: new Date().toISOString(),
    };
  }

  @Get('my-id')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get user ID',
    description: 'Demonstrates @UserProperty() decorator',
  })
  @ApiResponse({ status: 200, description: 'User ID' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMyId(@UserProperty('id') userId: string) {
    return { message: 'Your user ID', userId };
  }

  @Get('my-email')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get user email',
    description: 'Demonstrates @UserProperty() decorator',
  })
  @ApiResponse({ status: 200, description: 'User email' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMyEmail(@UserProperty('email') email: string) {
    return { message: 'Your email address', email };
  }

  @Get('email-verified')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Check email verification',
    description: 'Returns email verification status',
  })
  @ApiResponse({ status: 200, description: 'Verification status' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getEmailVerified(@UserProperty('emailVerified') verified: boolean) {
    return {
      emailVerified: verified,
      message: verified ? 'Your email is verified' : 'Please verify your email',
    };
  }

  @Get('any-role-check')
  @Roles(['admin', 'moderator', 'vip'], { mode: 'any' })
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Any role check',
    description: 'Requires ANY of: admin, moderator, or vip role',
  })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  anyRoleCheck(@UserProperty('role') role: string) {
    return {
      message: 'You have access with any of: admin, moderator, or vip',
      yourRole: role,
    };
  }

  @Get('all-roles-check')
  @Roles(['verified', 'premium'], { mode: 'all' })
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'All roles check',
    description: 'Requires ALL of: verified AND premium roles',
  })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  allRolesCheck(@UserProperty('role') role: string) {
    return {
      message: 'You have both verified AND premium roles',
      yourRoles: role,
    };
  }

  @Get('premium-content')
  @Roles(['premium', 'vip'], { mode: 'any', message: 'Premium subscription required' })
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get premium content',
    description: 'Requires premium or vip role',
  })
  @ApiResponse({ status: 200, description: 'Premium content' })
  @ApiResponse({ status: 403, description: 'Premium subscription required' })
  getPremiumContent(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Premium content',
      user: user.name,
      content: 'This is exclusive premium content!',
    };
  }

  @Get('read-any')
  @Permissions(['read:posts', 'read:comments', 'read:users'], { mode: 'any' })
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Read any resource',
    description: 'Requires ANY of the read permissions',
  })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  readAny(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'You can read at least one resource',
      user: user.email,
    };
  }

  @Get('full-access')
  @Permissions(['read:posts', 'write:posts', 'delete:posts'], { mode: 'all' })
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Full posts access',
    description: 'Requires ALL of: read, write, and delete posts permissions',
  })
  @ApiResponse({ status: 200, description: 'Full access granted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  fullAccess(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'You have full access to posts',
      user: user.email,
    };
  }

  @Post('publish')
  @Permissions(['write:posts', 'publish:posts'], {
    mode: 'all',
    message: 'Publishing requires both write and publish permissions',
  })
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Publish post',
    description: 'Requires both write:posts and publish:posts permissions',
  })
  @ApiBody({ schema: { type: 'object', properties: { title: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Post published' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  publishPost(
    @CurrentUser() user: UserSession['user'],
    @Body() body: { title: string },
  ) {
    return {
      message: 'Post published',
      author: user.email,
      title: body.title,
      publishedAt: new Date().toISOString(),
    };
  }

  @Get('account-settings')
  @RequireFreshSession()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get account settings',
    description: 'Requires fresh session (uses config default)',
  })
  @ApiResponse({ status: 200, description: 'Account settings' })
  @ApiResponse({ status: 401, description: 'Session not fresh' })
  getAccountSettings(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Account settings (requires fresh session)',
      user: user.email,
      settings: { notifications: true, newsletter: false, twoFactor: false },
    };
  }

  @Post('delete-account')
  @RequireFreshSession({
    maxAge: 60,
    message: 'For security, please re-login before deleting your account',
  })
  @DisallowImpersonation()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Delete account',
    description: 'Requires very fresh session (1 min) and no impersonation',
  })
  @ApiResponse({ status: 201, description: 'Deletion initiated' })
  @ApiResponse({ status: 401, description: 'Please re-login' })
  deleteAccount(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Account deletion initiated',
      user: user.email,
      note: 'Your account will be deleted in 30 days',
      timestamp: new Date().toISOString(),
    };
  }
}
