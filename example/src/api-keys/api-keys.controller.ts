import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Body,
  Headers,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiSecurity,
  ApiParam,
  ApiBody,
  ApiHeader,
} from '@nestjs/swagger';
import {
  ApiKeyAuth,
  BearerAuth,
  ApiKey,
  CurrentUser,
  Permissions,
} from 'nestjs-better-auth-fastify';
import type { UserSession, ApiKeyValidation } from 'nestjs-better-auth-fastify';

type ApiKeyInfo = NonNullable<ApiKeyValidation['key']>;

/**
 * API Keys Controller
 * Demonstrates usage of API Key and Bearer Token authentication
 */
@ApiTags('API Keys')
@Controller('api-keys')
export class ApiKeysController {
  // ============================================
  // API Key Management Routes (requires session)
  // ============================================

  @Get()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'List my API keys',
    description: 'Get all API keys for current user (session auth required)',
  })
  @ApiResponse({ status: 200, description: 'List of API keys' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  listApiKeys(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'My API Keys',
      userId: user.id,
      apiKeys: [
        { id: 'key-1', name: 'Production API Key', prefix: 'pk_live_', permissions: ['read:data', 'write:data'], createdAt: '2024-01-01', expiresAt: null },
        { id: 'key-2', name: 'Development API Key', prefix: 'pk_test_', permissions: ['read:data'], createdAt: '2024-06-01', expiresAt: '2025-12-31' },
      ],
    };
  }

  @Post()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Create API key',
    description: 'Create a new API key for current user',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        permissions: { type: 'array', items: { type: 'string' } },
        expiresIn: { type: 'number', description: 'Seconds until expiration' },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'API key created (save it now!)' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  createApiKey(
    @CurrentUser() user: UserSession['user'],
    @Body() body: { name: string; permissions: string[]; expiresIn?: number },
  ) {
    return {
      message: 'API Key created',
      warning: 'Please save this key, it will not be shown again',
      apiKey: {
        id: 'new-key-id',
        name: body.name,
        key: 'pk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        prefix: 'pk_live_',
        permissions: body.permissions,
        userId: user.id,
        createdAt: new Date().toISOString(),
        expiresAt: body.expiresIn
          ? new Date(Date.now() + body.expiresIn * 1000).toISOString()
          : null,
      },
    };
  }

  @Delete(':id')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Delete API key',
    description: 'Delete an API key by ID',
  })
  @ApiParam({ name: 'id', description: 'API key ID' })
  @ApiResponse({ status: 200, description: 'API key deleted' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  deleteApiKey(
    @Param('id') id: string,
    @CurrentUser() user: UserSession['user'],
  ) {
    return {
      message: 'API Key deleted',
      deletedKeyId: id,
      deletedBy: user.id,
      deletedAt: new Date().toISOString(),
    };
  }

  // ============================================
  // Routes using API Key authentication
  // ============================================

  @Get('external/data')
  @ApiKeyAuth()
  @ApiSecurity('api-key')
  @ApiOperation({
    summary: 'Get external data',
    description: 'API Key authentication only (no session allowed)',
  })
  @ApiResponse({ status: 200, description: 'External data' })
  @ApiResponse({ status: 401, description: 'Invalid or missing API key' })
  getExternalData(@ApiKey() apiKey: ApiKeyInfo) {
    return {
      message: 'External API data',
      authenticatedVia: 'API Key',
      apiKey: { id: apiKey.id, name: apiKey.name, permissions: apiKey.permissions },
      data: {
        items: [{ id: 1, name: 'Item 1', value: 100 }, { id: 2, name: 'Item 2', value: 200 }],
        total: 2,
        timestamp: new Date().toISOString(),
      },
    };
  }

  @Post('external/data')
  @ApiKeyAuth()
  @Permissions(['write:data'])
  @ApiSecurity('api-key')
  @ApiOperation({
    summary: 'Create external data',
    description: 'API Key auth + write:data permission required',
  })
  @ApiBody({ schema: { type: 'object', properties: { name: { type: 'string' }, value: { type: 'number' } } } })
  @ApiResponse({ status: 201, description: 'Data created' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Missing permission' })
  createExternalData(
    @ApiKey() apiKey: ApiKeyInfo,
    @Body() body: { name: string; value: number },
  ) {
    return {
      message: 'Data created',
      authenticatedVia: 'API Key',
      apiKeyId: apiKey.id,
      created: {
        id: Math.floor(Math.random() * 1000),
        name: body.name,
        value: body.value,
        createdAt: new Date().toISOString(),
      },
    };
  }

  // ============================================
  // Routes using Bearer Token authentication
  // ============================================

  @Get('external/profile')
  @BearerAuth()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get external profile',
    description: 'Bearer Token authentication only (no cookies)',
  })
  @ApiResponse({ status: 200, description: 'User profile' })
  @ApiResponse({ status: 401, description: 'Invalid or missing Bearer token' })
  getExternalProfile(@CurrentUser() user: UserSession['user']) {
    return {
      message: 'User profile retrieved via Bearer Token',
      authenticatedVia: 'Bearer Token',
      user: { id: user.id, email: user.email, name: user.name },
    };
  }

  // ============================================
  // Webhook Endpoint Example
  // ============================================

  @Post('webhooks/payment')
  @ApiKeyAuth()
  @Permissions(['webhook:payment'])
  @ApiSecurity('api-key')
  @ApiOperation({
    summary: 'Payment webhook',
    description: 'Webhook endpoint for payment callbacks (API Key required)',
  })
  @ApiHeader({ name: 'x-webhook-signature', description: 'Webhook signature', required: false })
  @ApiBody({ schema: { type: 'object', properties: { event: { type: 'string' }, data: { type: 'object' } } } })
  @ApiResponse({ status: 201, description: 'Webhook received' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  handlePaymentWebhook(
    @ApiKey() apiKey: ApiKeyInfo,
    @Body() payload: { event: string; data: Record<string, unknown> },
    @Headers('x-webhook-signature') signature: string,
  ) {
    return {
      message: 'Webhook received',
      apiKeyId: apiKey.id,
      event: payload.event,
      signature: signature ? 'provided' : 'missing',
      receivedAt: new Date().toISOString(),
    };
  }

  @Get('integrations/status')
  @ApiKeyAuth()
  @Permissions(['read:integrations'])
  @ApiSecurity('api-key')
  @ApiOperation({
    summary: 'Get integration status',
    description: 'Check third-party integration status',
  })
  @ApiResponse({ status: 200, description: 'Integration status' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getIntegrationStatus(@ApiKey() apiKey: ApiKeyInfo) {
    return {
      message: 'Integration status',
      apiKey: { id: apiKey.id, name: apiKey.name },
      integrations: [
        { name: 'Stripe', status: 'connected', lastSync: '2025-01-15T10:00:00Z' },
        { name: 'Slack', status: 'connected', lastSync: '2025-01-15T09:30:00Z' },
        { name: 'GitHub', status: 'disconnected', lastSync: null },
      ],
    };
  }

  // ============================================
  // Hybrid Authentication Examples
  // ============================================

  @Get('universal/data')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get universal data',
    description: 'Accepts both session and API Key authentication',
  })
  @ApiResponse({ status: 200, description: 'Universal data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getUniversalData(
    @CurrentUser() user: UserSession['user'],
    @ApiKey() apiKey: ApiKeyInfo | null,
  ) {
    const authMethod = apiKey ? 'API Key' : 'Session';
    return {
      message: 'Universal data endpoint',
      authenticatedVia: authMethod,
      user: apiKey
        ? { apiKeyId: apiKey.id, apiKeyName: apiKey.name }
        : { userId: user.id, email: user.email },
      data: { timestamp: new Date().toISOString(), items: ['item1', 'item2', 'item3'] },
    };
  }

  @Get('flexible/data')
  @ApiKeyAuth({ allowSession: true })
  @ApiSecurity('api-key')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get flexible data',
    description: 'API Key auth with session fallback (@ApiKeyAuth({ allowSession: true }))',
  })
  @ApiResponse({ status: 200, description: 'Flexible data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getFlexibleData(
    @CurrentUser() user: UserSession['user'] | null,
    @ApiKey() apiKey: ApiKeyInfo | null,
  ) {
    const authMethod = apiKey ? 'API Key' : user ? 'Session' : 'Unknown';
    return {
      message: 'Flexible authentication endpoint',
      authenticatedVia: authMethod,
      identity: apiKey
        ? { type: 'apiKey', id: apiKey.id, name: apiKey.name }
        : user
          ? { type: 'user', id: user.id, email: user.email }
          : null,
      data: { timestamp: new Date().toISOString(), value: Math.random() },
    };
  }

  @Post('external/batch-create')
  @ApiKeyAuth({
    permissions: {
      permissions: { data: ['read', 'write', 'delete'] },
      message: 'This endpoint requires data:read, data:write, and data:delete permissions',
    },
  })
  @ApiSecurity('api-key')
  @ApiOperation({
    summary: 'Batch create',
    description: 'API Key with specific permission requirements',
  })
  @ApiBody({ schema: { type: 'object', properties: { items: { type: 'array', items: { type: 'object' } } } } })
  @ApiResponse({ status: 201, description: 'Batch created' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Missing required permissions' })
  batchCreate(
    @ApiKey() apiKey: ApiKeyInfo,
    @Body() body: { items: Array<{ name: string; value: number }> },
  ) {
    return {
      message: 'Batch creation successful',
      apiKeyId: apiKey.id,
      created: body.items.map((item, index) => ({
        id: `item-${Date.now()}-${index}`,
        ...item,
        createdAt: new Date().toISOString(),
      })),
    };
  }

  // ============================================
  // CLI / Automation Examples
  // ============================================

  @Post('cli/deploy')
  @ApiKeyAuth()
  @Permissions(['deploy:application'])
  @ApiSecurity('api-key')
  @ApiOperation({
    summary: 'Deploy application',
    description: 'CLI endpoint for deployments (API Key required)',
  })
  @ApiBody({ schema: { type: 'object', properties: { environment: { type: 'string' }, version: { type: 'string' } } } })
  @ApiResponse({ status: 201, description: 'Deployment initiated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  deployApplication(
    @ApiKey() apiKey: ApiKeyInfo,
    @Body() body: { environment: string; version: string },
  ) {
    return {
      message: 'Deployment initiated',
      deployment: {
        id: `deploy-${Date.now()}`,
        environment: body.environment,
        version: body.version,
        initiatedBy: { apiKeyId: apiKey.id, apiKeyName: apiKey.name },
        status: 'pending',
        startedAt: new Date().toISOString(),
      },
    };
  }

  @Get('ci/status')
  @ApiKeyAuth({ allowSession: true })
  @ApiSecurity('api-key')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get CI/CD status',
    description: 'Pipeline status (API Key or session)',
  })
  @ApiResponse({ status: 200, description: 'Pipeline status' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getCiStatus(@ApiKey() apiKey: ApiKeyInfo | null) {
    return {
      message: 'CI/CD pipeline status',
      requestedBy: apiKey ? { apiKeyId: apiKey.id } : { type: 'session' },
      pipelines: [
        { id: 'pipeline-1', name: 'Build & Test', status: 'success', lastRun: '2025-01-15T10:00:00Z' },
        { id: 'pipeline-2', name: 'Deploy to Staging', status: 'running', lastRun: '2025-01-15T11:00:00Z' },
        { id: 'pipeline-3', name: 'Deploy to Production', status: 'pending', lastRun: null },
      ],
    };
  }

  @Get('rate-limited/data')
  @ApiKeyAuth({ allowSession: true })
  @ApiSecurity('api-key')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get rate-limited data',
    description: 'Endpoint with different rate limits based on auth method',
  })
  @ApiResponse({ status: 200, description: 'Rate-limited data with limit info' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  getRateLimitedData(@ApiKey() apiKey: ApiKeyInfo | null) {
    const rateLimitInfo = apiKey
      ? { limit: 1000, remaining: 950, resetAt: '2025-01-15T12:00:00Z' }
      : { limit: 100, remaining: 95, resetAt: '2025-01-15T12:00:00Z' };

    return {
      message: 'Rate limited data endpoint',
      authenticationType: apiKey ? 'API Key' : 'Session',
      rateLimit: rateLimitInfo,
      data: { timestamp: new Date().toISOString(), items: ['item1', 'item2'] },
    };
  }
}
