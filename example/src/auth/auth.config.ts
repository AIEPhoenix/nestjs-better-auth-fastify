import { betterAuth } from 'better-auth';
import {
  admin,
  organization,
  twoFactor,
  bearer,
  apiKey,
} from 'better-auth/plugins';
import Database from 'better-sqlite3';

/**
 * Better Auth Configuration
 * Enables all plugins to demonstrate complete functionality
 * Uses in-memory database for development and testing
 */
export const auth = betterAuth({
  basePath: '/api/auth',

  // In-memory database (for development/testing)
  database: new Database(':memory:'),

  // Secret key (use environment variable in production)
  secret: 'your-secret-key-change-in-production',

  // Email and password authentication
  emailAndPassword: {
    enabled: true,
    // Whether email verification is required
    requireEmailVerification: false,
  },

  // Trusted origins
  trustedOrigins: ['http://localhost:3000'],

  // Session configuration
  session: {
    // Session expiration time (7 days)
    expiresIn: 60 * 60 * 24 * 7,
    // Session update threshold (1 day)
    updateAge: 60 * 60 * 24,
    // Fresh session window (for @RequireFreshSession)
    freshAge: 60 * 60 * 24, // 1 day
  },

  // User configuration
  user: {
    additionalFields: {
      // User permissions list
      permissions: {
        type: 'string[]',
        defaultValue: [],
      },
    },
  },

  // Hooks configuration (enables @Hook decorator)
  hooks: {},

  // Enable all plugins
  plugins: [
    // ============================================
    // Admin Plugin - Administrator functionality
    // Provides: @AdminOnly, @BanCheck, @DisallowImpersonation
    //           @SecureAdminOnly, @IsImpersonating, @ImpersonatedBy
    // ============================================
    admin({
      // Default user role
      defaultRole: 'user',
      // Admin role name
      adminRole: 'admin',
      // Allow impersonation
      impersonationSessionDuration: 60 * 60, // 1 hour
    }),

    // ============================================
    // Organization Plugin - Organization/team functionality
    // Provides: @OrgRequired, @OrgRoles, @OrgPermission
    //           @CurrentOrg, @OrgMember
    // ============================================
    organization({
      // Allow users to create organizations
      allowUserToCreateOrganization: true,
      // Creator role
      creatorRole: 'owner',
      // Default member role
      memberRole: 'member',
      // Organization invitation expiration (7 days)
      invitationExpiresIn: 60 * 60 * 24 * 7,
    }),

    // ============================================
    // Two Factor Plugin - Two-factor authentication
    // Supports TOTP (e.g., Google Authenticator)
    // ============================================
    twoFactor({
      // Issuer name (displayed in authenticator app)
      issuer: 'NestJS Better Auth Example',
      // Number of backup codes
      backupCodeCount: 10,
    }),

    // ============================================
    // Bearer Plugin - Bearer Token authentication
    // Enables session auth via Authorization header (no decorator needed)
    // Suitable for mobile apps, CLI, and other cookie-less scenarios
    // ============================================
    bearer(),

    // ============================================
    // API Key Plugin - API Key authentication
    // Provides: @ApiKeyAuth, @ApiKey
    // Suitable for server integrations, CI/CD, automation scripts
    // ============================================
    apiKey(),
  ],
});

export type Auth = typeof auth;
