import { Controller, Get, Post, Param, Body, Delete } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiBody,
  ApiHeader,
} from '@nestjs/swagger';
import {
  AllowAnonymous,
  OrgRequired,
  OrgRoles,
  OrgPermission,
  CurrentUser,
  CurrentOrg,
  OrgMember,
} from '@sapix/nestjs-better-auth-fastify';
import type {
  UserSession,
  Organization,
  OrganizationMember,
} from '@sapix/nestjs-better-auth-fastify';

/**
 * Organization Controller
 * Demonstrates usage of organization-related decorators
 */
@ApiTags('Organizations')
@Controller('organizations')
export class OrganizationController {
  @Get()
  @AllowAnonymous()
  @ApiOperation({
    summary: 'List public organizations',
    description: 'Get list of public organizations (no auth required)',
  })
  @ApiResponse({ status: 200, description: 'Public organization list' })
  listPublicOrganizations() {
    return {
      message: 'Public organization list',
      organizations: [
        { id: '1', name: 'Acme Corp', slug: 'acme-corp', memberCount: 50 },
        { id: '2', name: 'Tech Startup', slug: 'tech-startup', memberCount: 15 },
        { id: '3', name: 'Design Studio', slug: 'design-studio', memberCount: 8 },
      ],
    };
  }

  @Get('my')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get my organizations',
    description: 'Get organizations the current user belongs to',
  })
  @ApiResponse({ status: 200, description: 'User organizations' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getMyOrganizations(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'My organizations',
      userId: user.id,
      organizations: [
        { id: '1', name: 'Acme Corp', slug: 'acme-corp', role: 'owner', joinedAt: '2024-01-01' },
        { id: '2', name: 'Tech Startup', slug: 'tech-startup', role: 'member', joinedAt: '2024-06-15' },
      ],
    };
  }

  @Post()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Create organization',
    description: 'Create a new organization',
  })
  @ApiBody({ schema: { type: 'object', properties: { name: { type: 'string' }, slug: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Organization created' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  createOrganization(
    @Body() body: { name: string; slug: string },
    @CurrentUser() user: UserSession['user'],
  ) {
    return {
      message: 'Organization created',
      organization: {
        id: 'new-org-id',
        name: body.name,
        slug: body.slug,
        ownerId: user.id,
        createdAt: new Date().toISOString(),
      },
    };
  }

  // ============================================
  // Routes requiring organization context
  // ============================================

  @Get('current')
  @OrgRequired()
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Get current organization',
    description: 'Get details of the active organization (set via x-org-id header)',
  })
  @ApiResponse({ status: 200, description: 'Organization details' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'No organization context' })
  getCurrentOrganization(@CurrentOrg() org: Organization) {
    return {
      message: 'Current organization details',
      organization: org,
    };
  }

  @Get('current/members')
  @OrgRequired()
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Get organization members',
    description: 'List members of the current organization',
  })
  @ApiResponse({ status: 200, description: 'Member list' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getOrganizationMembers(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Organization member list',
      organization: org.name,
      currentMember: { role: member.role },
      members: [
        { id: '1', name: 'Alice', email: 'alice@example.com', role: 'owner', joinedAt: '2024-01-01' },
        { id: '2', name: 'Bob', email: 'bob@example.com', role: 'admin', joinedAt: '2024-02-15' },
        { id: '3', name: 'Charlie', email: 'charlie@example.com', role: 'member', joinedAt: '2024-03-20' },
      ],
    };
  }

  @Get('current/settings')
  @OrgRequired()
  @OrgRoles(['owner', 'admin'])
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Get organization settings',
    description: 'Get settings (requires owner or admin role)',
  })
  @ApiResponse({ status: 200, description: 'Organization settings' })
  @ApiResponse({ status: 403, description: 'Insufficient role' })
  getOrganizationSettings(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Organization settings',
      organization: org.name,
      memberRole: member.role,
      settings: {
        allowPublicProjects: true,
        defaultMemberRole: 'member',
        requireTwoFactor: false,
        allowedDomains: ['@acme.com', '@acme.io'],
      },
    };
  }

  @Post('current/settings')
  @OrgRequired()
  @OrgRoles(['owner'])
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Update organization settings',
    description: 'Update settings (owner only)',
  })
  @ApiBody({ schema: { type: 'object', additionalProperties: true } })
  @ApiResponse({ status: 201, description: 'Settings updated' })
  @ApiResponse({ status: 403, description: 'Owner role required' })
  updateOrganizationSettings(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() settings: Record<string, unknown>,
  ) {
    return {
      message: 'Organization settings updated',
      organization: org.name,
      updatedBy: member.userId,
      updatedAt: new Date().toISOString(),
      settings,
    };
  }

  @Get('current/billing')
  @OrgRequired()
  @OrgPermission({ resource: 'organization', action: 'read' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Get billing info',
    description: 'Get billing information (permission-based)',
  })
  @ApiResponse({ status: 200, description: 'Billing information' })
  @ApiResponse({ status: 403, description: 'Missing permission' })
  getOrganizationBilling(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Organization billing information',
      organization: org.name,
      memberRole: member.role,
      billing: {
        plan: 'pro',
        status: 'active',
        nextBillingDate: '2025-02-01',
        amount: 99.99,
        currency: 'USD',
      },
    };
  }

  @Post('current/billing')
  @OrgRequired()
  @OrgPermission({ resource: 'organization', action: 'update' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Update billing info',
    description: 'Update payment method (requires update permission)',
  })
  @ApiBody({ schema: { type: 'object', properties: { paymentMethodId: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Billing updated' })
  @ApiResponse({ status: 403, description: 'Missing permission' })
  updateOrganizationBilling(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() billingInfo: { paymentMethodId: string },
  ) {
    return {
      message: 'Billing information updated',
      organization: org.name,
      updatedBy: member.userId,
      paymentMethodId: billingInfo.paymentMethodId,
    };
  }

  @Post('current/invites')
  @OrgRequired()
  @OrgRoles(['owner', 'admin'])
  @OrgPermission({ resource: 'invitation', action: 'create' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Invite member',
    description: 'Invite a new member (owner/admin + invitation:create permission)',
  })
  @ApiBody({ schema: { type: 'object', properties: { email: { type: 'string' }, role: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Invitation sent' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  inviteMember(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() body: { email: string; role: string },
  ) {
    return {
      message: 'Invitation sent',
      organization: org.name,
      invitedBy: member.userId,
      invite: {
        email: body.email,
        role: body.role,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
      },
    };
  }

  @Delete('current/members/:memberId')
  @OrgRequired()
  @OrgRoles(['owner'])
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiParam({ name: 'memberId', description: 'Member ID to remove' })
  @ApiOperation({
    summary: 'Remove member',
    description: 'Remove a member from organization (owner only)',
  })
  @ApiResponse({ status: 200, description: 'Member removed' })
  @ApiResponse({ status: 403, description: 'Owner role required' })
  removeMember(
    @Param('memberId') memberId: string,
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Member removed',
      organization: org.name,
      removedMemberId: memberId,
      removedBy: member.userId,
      removedAt: new Date().toISOString(),
    };
  }

  @Post('current/projects')
  @OrgRequired()
  @OrgRoles(['owner', 'admin'])
  @OrgPermission({ resource: 'organization', action: 'update' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Create project',
    description: 'Create a project within organization (admin+ with update permission)',
  })
  @ApiBody({ schema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Project created' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  createProject(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() body: { name: string; description: string },
  ) {
    return {
      message: 'Project created',
      organization: org.name,
      createdBy: member.userId,
      project: {
        id: 'new-project-id',
        name: body.name,
        description: body.description,
        createdAt: new Date().toISOString(),
      },
    };
  }

  @Delete('current')
  @OrgRequired()
  @OrgRoles(['owner'])
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Delete organization',
    description: 'Delete organization (owner only)',
  })
  @ApiResponse({ status: 200, description: 'Deletion scheduled' })
  @ApiResponse({ status: 403, description: 'Owner role required' })
  deleteOrganization(
    @CurrentOrg() org: Organization,
    @OrgMember() _member: OrganizationMember,
    @CurrentUser() user: UserSession['user'],
  ) {
    return {
      message: 'Organization deletion request received',
      note: 'Organization will be permanently deleted in 30 days',
      organization: org.name,
      deletedBy: user.email,
      scheduledDeletionDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    };
  }

  // ============================================
  // OrgRoles Mode Examples
  // ============================================

  @Get('current/any-role')
  @OrgRequired()
  @OrgRoles(['owner', 'admin', 'billing'], { mode: 'any' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Any role check',
    description: 'Requires ANY of: owner, admin, or billing role',
  })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  anyOrgRole(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'You have owner, admin, or billing role in this organization',
      organization: org.name,
      yourRole: member.role,
    };
  }

  @Get('current/all-roles')
  @OrgRequired()
  @OrgRoles(['admin', 'billing'], { mode: 'all' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'All roles check',
    description: 'Requires ALL of: admin AND billing roles',
  })
  @ApiResponse({ status: 200, description: 'Access granted' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  allOrgRoles(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'You have both admin AND billing roles',
      organization: org.name,
      yourRole: member.role,
    };
  }

  @Get('current/owner-only')
  @OrgRequired()
  @OrgRoles(['owner'], { message: 'Only organization owners can access this resource' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Owner only',
    description: 'Owner role required with custom error message',
  })
  @ApiResponse({ status: 200, description: 'Owner section' })
  @ApiResponse({ status: 403, description: 'Only organization owners can access this resource' })
  ownerOnly(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Owner-only section',
      organization: org.name,
      yourRole: member.role,
      ownerActions: ['Transfer ownership', 'Delete organization', 'Manage billing'],
    };
  }

  @Get('current/can-manage-members')
  @OrgRequired()
  @OrgPermission({ resource: 'member', action: 'create' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Check member management permission',
    description: 'Requires member:create permission',
  })
  @ApiResponse({ status: 200, description: 'Can manage members' })
  @ApiResponse({ status: 403, description: 'Missing permission' })
  canManageMembers(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'You can manage members in this organization',
      organization: org.name,
      yourRole: member.role,
    };
  }

  @Delete('current/invitations/:inviteId')
  @OrgRequired()
  @OrgPermission({ resource: 'invitation', action: 'delete' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiParam({ name: 'inviteId', description: 'Invitation ID' })
  @ApiOperation({
    summary: 'Cancel invitation',
    description: 'Cancel pending invitation (requires invitation:delete permission)',
  })
  @ApiResponse({ status: 200, description: 'Invitation cancelled' })
  @ApiResponse({ status: 403, description: 'Missing permission' })
  cancelInvitation(
    @Param('inviteId') inviteId: string,
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Invitation cancelled',
      organization: org.name,
      inviteId,
      cancelledBy: member.userId,
      cancelledAt: new Date().toISOString(),
    };
  }

  @Post('current/audit-export')
  @OrgRequired()
  @OrgRoles(['owner', 'admin'])
  @OrgPermission({ resource: 'organization', action: 'read' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Export audit logs',
    description: 'Export organization audit logs (admin+ with read permission)',
  })
  @ApiBody({ schema: { type: 'object', properties: { startDate: { type: 'string' }, endDate: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Export initiated' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  exportAuditLogs(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() body: { startDate: string; endDate: string },
  ) {
    return {
      message: 'Audit log export initiated',
      organization: org.name,
      exportedBy: member.userId,
      dateRange: { start: body.startDate, end: body.endDate },
      exportId: `export-${Date.now()}`,
      status: 'processing',
      estimatedTime: '5 minutes',
    };
  }

  @Get('current/analytics')
  @OrgRequired()
  @OrgPermission({ resource: 'organization', action: 'read' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Get organization analytics',
    description: 'View organization analytics (requires organization:read)',
  })
  @ApiResponse({ status: 200, description: 'Analytics data' })
  @ApiResponse({ status: 403, description: 'Missing permission' })
  getAnalytics(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
  ) {
    return {
      message: 'Organization analytics',
      organization: org.name,
      viewedBy: member.userId,
      analytics: {
        totalMembers: 25,
        activeMembers: 20,
        projectsCount: 10,
        storageUsed: '15.5 GB',
        apiCallsThisMonth: 150000,
        lastActivityAt: new Date().toISOString(),
      },
    };
  }

  @Post('current/teams')
  @OrgRequired()
  @OrgRoles(['owner', 'admin'])
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiOperation({
    summary: 'Create team',
    description: 'Create a team within the organization (admin+)',
  })
  @ApiBody({ schema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Team created' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  createTeam(
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() body: { name: string; description?: string },
  ) {
    return {
      message: 'Team created',
      organization: org.name,
      team: {
        id: `team-${Date.now()}`,
        name: body.name,
        description: body.description,
        createdBy: member.userId,
        createdAt: new Date().toISOString(),
      },
    };
  }

  @Post('current/members/:memberId/role')
  @OrgRequired()
  @OrgRoles(['owner'])
  @OrgPermission({ resource: 'member', action: 'update' })
  @ApiBearerAuth('bearer')
  @ApiHeader({ name: 'x-org-id', description: 'Organization ID', required: true })
  @ApiParam({ name: 'memberId', description: 'Member ID' })
  @ApiOperation({
    summary: 'Update member role',
    description: 'Update member role (owner only with member:update permission)',
  })
  @ApiBody({ schema: { type: 'object', properties: { newRole: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Role updated' })
  @ApiResponse({ status: 403, description: 'Owner role required' })
  updateMemberRole(
    @Param('memberId') memberId: string,
    @CurrentOrg() org: Organization,
    @OrgMember() member: OrganizationMember,
    @Body() body: { newRole: string },
  ) {
    return {
      message: 'Member role updated',
      organization: org.name,
      memberId,
      newRole: body.newRole,
      updatedBy: member.userId,
      updatedAt: new Date().toISOString(),
    };
  }
}
