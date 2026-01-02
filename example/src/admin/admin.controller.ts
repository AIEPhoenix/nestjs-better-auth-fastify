import { Controller, Get, Post, Param, Body, Delete } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiBody,
} from '@nestjs/swagger';
import {
  AdminOnly,
  SecureAdminOnly,
  Roles,
  Permissions,
  RequireFreshSession,
  DisallowImpersonation,
  CurrentUser,
  Session,
} from '@sapix/nestjs-better-auth-fastify';
import type { UserSession } from '@sapix/nestjs-better-auth-fastify';

/**
 * Admin Controller
 * Demonstrates usage of admin-specific decorators
 */
@ApiTags('Admin')
@ApiBearerAuth('bearer')
@Controller('admin')
@AdminOnly()
export class AdminController {
  @Get('dashboard')
  @ApiOperation({
    summary: 'Admin dashboard',
    description: 'Admin dashboard with statistics (inherits @AdminOnly)',
  })
  @ApiResponse({ status: 200, description: 'Dashboard stats' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Admin role required' })
  getDashboard(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'Admin dashboard',
      admin: user.email,
      stats: {
        totalUsers: 1234,
        activeUsers: 567,
        newUsersToday: 23,
        pendingReports: 5,
      },
    };
  }

  @Get('users')
  @Permissions(['read:users'])
  @ApiOperation({
    summary: 'List all users',
    description: 'Requires admin role + read:users permission',
  })
  @ApiResponse({ status: 200, description: 'User list' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  getAllUsers(@CurrentUser() admin: UserSession['user']) {
    return {
      message: 'User list',
      requestedBy: admin.email,
      users: [
        { id: '1', email: 'user1@example.com', name: 'User One', role: 'user' },
        { id: '2', email: 'user2@example.com', name: 'User Two', role: 'moderator' },
        { id: '3', email: 'admin@example.com', name: 'Admin User', role: 'admin' },
      ],
    };
  }

  @Get('users/:id')
  @Permissions(['read:users'])
  @ApiOperation({
    summary: 'Get user by ID',
    description: 'Get detailed user information',
  })
  @ApiParam({ name: 'id', description: 'User ID' })
  @ApiResponse({ status: 200, description: 'User details' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  getUserById(
    @Param('id') id: string,
    @CurrentUser() admin: UserSession['user'],
  ) {
    return {
      message: 'User details',
      requestedBy: admin.email,
      user: {
        id,
        email: `user${id}@example.com`,
        name: `User ${id}`,
        role: 'user',
        createdAt: '2025-01-01T00:00:00Z',
        lastLogin: '2025-01-15T12:00:00Z',
      },
    };
  }

  @Post('users/:id/ban')
  @Permissions(['write:users'])
  @DisallowImpersonation()
  @ApiOperation({
    summary: 'Ban user',
    description: 'Ban a user - disallowed during impersonation',
  })
  @ApiParam({ name: 'id', description: 'User ID to ban' })
  @ApiBody({ schema: { type: 'object', properties: { reason: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'User banned' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  banUser(
    @Param('id') id: string,
    @Body() body: { reason: string },
    @CurrentUser() admin: UserSession['user'],
  ) {
    return {
      message: 'User has been banned',
      userId: id,
      bannedBy: admin.email,
      reason: body.reason,
      bannedAt: new Date().toISOString(),
    };
  }

  @Post('users/:id/unban')
  @Permissions(['write:users'])
  @DisallowImpersonation()
  @ApiOperation({
    summary: 'Unban user',
    description: 'Remove ban from a user',
  })
  @ApiParam({ name: 'id', description: 'User ID to unban' })
  @ApiResponse({ status: 201, description: 'User unbanned' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  unbanUser(
    @Param('id') id: string,
    @CurrentUser() admin: UserSession['user'],
  ) {
    return {
      message: 'User has been unbanned',
      userId: id,
      unbannedBy: admin.email,
      unbannedAt: new Date().toISOString(),
    };
  }

  @Delete('users/:id')
  @SecureAdminOnly()
  @Permissions(['delete:users'])
  @ApiOperation({
    summary: 'Delete user',
    description: 'Highly sensitive - requires @SecureAdminOnly (admin + fresh session + no impersonation)',
  })
  @ApiParam({ name: 'id', description: 'User ID to delete' })
  @ApiResponse({ status: 200, description: 'User deleted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  deleteUser(
    @Param('id') id: string,
    @CurrentUser() admin: UserSession['user'],
  ) {
    return {
      message: 'User has been deleted',
      userId: id,
      deletedBy: admin.email,
      deletedAt: new Date().toISOString(),
    };
  }

  @Get('system/config')
  @Roles(['super_admin'])
  @DisallowImpersonation()
  @ApiOperation({
    summary: 'Get system config',
    description: 'Super admin only - system configuration',
  })
  @ApiResponse({ status: 200, description: 'System configuration' })
  @ApiResponse({ status: 403, description: 'Super admin required' })
  getSystemConfig(@CurrentUser() admin: UserSession['user']) {
    return {
      message: 'System configuration',
      requestedBy: admin.email,
      config: {
        maintenanceMode: false,
        maxUploadSize: '10MB',
        allowedFileTypes: ['jpg', 'png', 'pdf'],
        rateLimit: { windowMs: 60000, maxRequests: 100 },
      },
    };
  }

  @Post('system/config')
  @Roles(['super_admin'])
  @RequireFreshSession({ maxAge: 300 })
  @DisallowImpersonation()
  @ApiOperation({
    summary: 'Update system config',
    description: 'Super admin only - requires fresh session (5 min)',
  })
  @ApiBody({ schema: { type: 'object', additionalProperties: true } })
  @ApiResponse({ status: 201, description: 'Config updated' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  updateSystemConfig(
    @Body() config: Record<string, unknown>,
    @CurrentUser() admin: UserSession['user'],
  ) {
    return {
      message: 'System configuration updated',
      updatedBy: admin.email,
      updatedAt: new Date().toISOString(),
      config,
    };
  }

  @Get('audit-logs')
  @Permissions(['read:audit-logs'])
  @ApiOperation({
    summary: 'Get audit logs',
    description: 'View system audit logs',
  })
  @ApiResponse({ status: 200, description: 'Audit logs' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  getAuditLogs(@CurrentUser() admin: UserSession['user']) {
    return {
      message: 'Audit logs',
      requestedBy: admin.email,
      logs: [
        { id: '1', action: 'user.login', userId: 'user-123', timestamp: '2025-01-15T10:00:00Z', ip: '192.168.1.1' },
        { id: '2', action: 'user.update', userId: 'user-456', timestamp: '2025-01-15T11:00:00Z', ip: '192.168.1.2' },
        { id: '3', action: 'admin.ban_user', userId: 'user-789', adminId: 'admin-001', timestamp: '2025-01-15T12:00:00Z', ip: '192.168.1.3' },
      ],
    };
  }

  @Post('impersonate/:userId')
  @SecureAdminOnly()
  @Permissions(['impersonate:users'])
  @ApiOperation({
    summary: 'Impersonate user',
    description: 'Start impersonating a user (requires SecureAdminOnly)',
  })
  @ApiParam({ name: 'userId', description: 'User ID to impersonate' })
  @ApiResponse({ status: 201, description: 'Impersonation guide' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  impersonateUser(
    @Param('userId') userId: string,
    @CurrentUser() admin: UserSession['user'],
    @Session() session: UserSession,
  ) {
    return {
      message: 'Impersonation feature guide',
      note: 'Actual impersonation requires Better Auth impersonation plugin API',
      targetUserId: userId,
      adminId: admin.id,
      adminEmail: admin.email,
      currentSessionId: session.session.id,
      instructions: {
        endpoint: 'POST /api/auth/impersonate',
        body: { userId },
        description: 'Calling this API will create an impersonation session',
      },
    };
  }
}
