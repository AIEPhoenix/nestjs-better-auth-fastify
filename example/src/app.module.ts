import { Module } from '@nestjs/common';
import { AuthModule } from '@sapix/nestjs-better-auth-fastify';
import type {
  AuthModuleOptions,
  OrgRolePermissions,
} from '@sapix/nestjs-better-auth-fastify';
import { auth } from './auth/auth.config';
import { AuthHooksService } from './auth/auth-hooks.service';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserController } from './user/user.controller';
import { AdminController } from './admin/admin.controller';
import { OrganizationController } from './organization/organization.controller';
import { ApiKeysController } from './api-keys/api-keys.controller';

/**
 * Custom organization role permissions
 * Define what permissions each organization role has
 */
const orgRolePermissions: OrgRolePermissions = {
  owner: {
    // Owner has all permissions for all resources
    organization: 'all',
    member: 'all',
    invitation: 'all',
    project: 'all',
    billing: 'all',
  },
  admin: {
    organization: ['read', 'update'],
    member: ['read', 'create', 'update'],
    invitation: ['read', 'create', 'delete'],
    project: 'all',
    billing: ['read'],
  },
  member: {
    organization: ['read'],
    member: ['read'],
    invitation: [],
    project: ['read', 'create', 'update'],
    billing: [],
  },
};

/**
 * Auth module configuration options
 */
const authModuleOptions: AuthModuleOptions = {
  // Better Auth instance
  auth,

  // Authentication route base path
  basePath: '/api/auth',

  // Enable debug mode for detailed logging (disable in production)
  debug: process.env.NODE_ENV !== 'production',

  // Global authentication guard is enabled by default
  // Set to true to disable global guard
  // disableGlobalGuard: false,

  // Custom error messages (useful for i18n)
  // Uncomment to use custom messages
  // errorMessages: {
  //   unauthorized: 'Please log in first',
  //   forbidden: 'Insufficient permissions',
  //   sessionNotFresh: 'Please re-login to perform this action',
  //   sessionExpired: 'Session expired, please log in again',
  //   userBanned: 'Your account has been banned',
  //   orgRequired: 'Please select an organization first',
  //   orgRoleRequired: 'Insufficient organization role permissions',
  //   orgPermissionRequired: 'You do not have permission for this operation',
  //   apiKeyRequired: 'Valid API Key required',
  //   apiKeyInvalidPermissions: 'API Key has insufficient permissions',
  // },

  // Custom organization role permissions
  orgRolePermissions,

  // Custom API key pattern (for distinguishing API keys from Bearer tokens)
  // Default: /^[a-z0-9_]+_[A-Za-z0-9]+$/
  // Example: Matches patterns like "pk_live_abc123", "sk_test_xyz789"
  apiKeyPattern: /^[a-z0-9_]+_[A-Za-z0-9]+$/,

  // Skip session expiration check in guard
  // Default: false (recommended to keep false for security)
  // skipSessionExpirationCheck: false,

  // Custom middleware wrapper
  // Useful for logging, rate limiting, etc.
  // middleware: async (req, reply, next) => {
  //   console.log(`Auth request: ${req.method} ${req.url}`);
  //   await next();
  // },
};

@Module({
  imports: [
    /**
     * AuthModule configuration
     * Using forRoot() for synchronous configuration
     */
    AuthModule.forRoot(authModuleOptions),

    /**
     * Async configuration example (commented out, for reference only)
     * Use when configuration depends on other services
     */
    // AuthModule.forRootAsync({
    //   imports: [ConfigModule],
    //   inject: [ConfigService],
    //   useFactory: async (configService: ConfigService) => ({
    //     auth: createAuth(configService),
    //     basePath: configService.get('AUTH_BASE_PATH', '/api/auth'),
    //     debug: configService.get('NODE_ENV') !== 'production',
    //     errorMessages: {
    //       unauthorized: configService.get('AUTH_ERROR_UNAUTHORIZED', 'Please log in'),
    //     },
    //     orgRolePermissions,
    //   }),
    // }),

    /**
     * Using useClass for configuration factory (commented out)
     */
    // AuthModule.forRootAsync({
    //   useClass: AuthConfigService, // Must implement AuthModuleOptionsFactory
    // }),
  ],
  controllers: [
    // Main controller
    AppController,

    // User controller - Demonstrates basic auth decorators
    UserController,

    // Admin controller - Demonstrates admin-only decorators
    AdminController,

    // Organization controller - Demonstrates organization decorators
    OrganizationController,

    // API Keys controller - Demonstrates API Key authentication
    ApiKeysController,
  ],
  providers: [
    AppService,

    // Authentication hooks service - Demonstrates hook decorators
    AuthHooksService,
  ],
})
export class AppModule {}
