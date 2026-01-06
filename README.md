<p align="center">
  <img src="https://nestjs.com/img/logo-small.svg" width="50" alt="NestJS Logo" />
  <span style="font-size: 40px; margin: 0 20px;">+</span>
  <img src="https://www.better-auth.com/logo.png" width="50" alt="Better Auth Logo" />
</p>

<h1 align="center">nestjs-better-auth-fastify</h1>

<p align="center">
  A comprehensive <a href="https://www.better-auth.com">Better Auth</a> integration for <a href="https://nestjs.com">NestJS</a> with <a href="https://fastify.dev">Fastify</a> adapter.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@sapix/nestjs-better-auth-fastify"><img src="https://img.shields.io/npm/v/@sapix/nestjs-better-auth-fastify.svg" alt="NPM Version" /></a>
  <a href="https://www.npmjs.com/package/@sapix/nestjs-better-auth-fastify"><img src="https://img.shields.io/npm/l/@sapix/nestjs-better-auth-fastify.svg" alt="Package License" /></a>
  <a href="https://www.npmjs.com/package/@sapix/nestjs-better-auth-fastify"><img src="https://img.shields.io/npm/dm/@sapix/nestjs-better-auth-fastify.svg" alt="NPM Downloads" /></a>
</p>

## Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Decorators Reference](#-decorators-reference)
  - [Access Control](#access-control-decorators)
  - [Admin Plugin](#admin-plugin-decorators)
  - [Alternative Auth Methods](#alternative-auth-methods)
  - [Organization Plugin](#organization-plugin-decorators)
  - [Parameter Decorators](#parameter-decorators)
  - [Custom Auth Context Decorators](#custom-auth-context-decorators)
- [Hook System](#-hook-system)
- [AuthService API](#-authservice-api)
- [Type Inference](#-type-inference)
- [Configuration](#%EF%B8%8F-configuration)
- [Multi-Context Support](#-multi-context-support)
- [Utility Functions](#-utility-functions)
- [Request Extension](#-request-extension)
- [Testing](#-testing)
- [Requirements](#-requirements)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

- 🔐 **Seamless Integration** - Drop-in Better Auth support for NestJS + Fastify
- 🎯 **Decorator-based** - Intuitive decorators for authentication & authorization
- 📦 **Plugin Support** - Full support for Better Auth plugins (Admin, Organization, API Key, Bearer, etc.)
- 🔄 **Multi-Context** - Works with HTTP, GraphQL, and WebSocket
- 🪝 **Hook System** - NestJS-native hooks for auth lifecycle events
- 🎨 **Type-Safe** - Full TypeScript support with type inference from your auth config
- ⚡ **Performance** - Optimized with lazy loading for optional dependencies
- 🌍 **i18n Ready** - Customizable error messages for internationalization

## 📦 Installation

```bash
# npm
npm install @sapix/nestjs-better-auth-fastify better-auth

# pnpm
pnpm add @sapix/nestjs-better-auth-fastify better-auth

# yarn
yarn add @sapix/nestjs-better-auth-fastify better-auth
```

### Optional Dependencies

Install these based on your needs:

```bash
# For GraphQL support
pnpm add @nestjs/graphql graphql

# For WebSocket support
pnpm add @nestjs/websockets @nestjs/platform-socket.io
```

## 🚀 Quick Start

### 1. Create Better Auth Configuration

```typescript
// src/auth/auth.config.ts
import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from '../db';

export const auth = betterAuth({
  basePath: '/api/auth',
  database: drizzleAdapter(db, { provider: 'postgresql' }),
  emailAndPassword: { enabled: true },
  // Add more plugins as needed
});

// Export type for type inference
export type Auth = typeof auth;
```

### 2. Import AuthModule

```typescript
// src/app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@sapix/nestjs-better-auth-fastify';
import { auth } from './auth/auth.config';

@Module({
  imports: [
    AuthModule.forRoot({
      auth,
      // basePath is optional - reads from auth.options.basePath by default
    }),
  ],
})
export class AppModule {}
```

### 3. Use Decorators in Controllers

```typescript
// src/user/user.controller.ts
import { Controller, Get, Post } from '@nestjs/common';
import {
  AllowAnonymous,
  Session,
  CurrentUser,
  Roles,
  UserSession,
} from '@sapix/nestjs-better-auth-fastify';

@Controller('user')
export class UserController {
  // All routes are protected by default
  @Get('profile')
  getProfile(@Session() session: UserSession) {
    return session;
  }

  // Public route - no authentication required
  @Get('public')
  @AllowAnonymous()
  getPublicData() {
    return { message: 'This is public' };
  }

  // Role-based access control
  @Get('admin')
  @Roles(['admin'])
  getAdminData(@CurrentUser() user: UserSession['user']) {
    return { message: `Hello admin ${user.name}` };
  }
}
```

## 📚 Decorators Reference

### Access Control Decorators

| Decorator                | Description                                | Example                 |
| ------------------------ | ------------------------------------------ | ----------------------- |
| `@AllowAnonymous()`      | Skip authentication check                  | Public endpoints        |
| `@OptionalAuth()`        | Auth optional, session injected if present | Mixed-access endpoints  |
| `@Roles(['admin'])`      | Require specific roles                     | Admin-only routes       |
| `@Permissions(['read'])` | Require specific permissions               | Permission-based access |
| `@RequireFreshSession()` | Require recently authenticated session     | Sensitive operations    |

#### Roles & Permissions Examples

```typescript
// OR logic (default): user needs ANY of the roles
@Roles(['admin', 'moderator'])

// AND logic: user needs ALL roles
@Roles(['admin', 'verified'], { mode: 'all' })

// Custom error message
@Roles(['admin'], { message: 'Administrator access required' })

// Permission-based (same options available)
@Permissions(['user:read', 'user:write'], { mode: 'any' })
@Permissions(['read:posts', 'write:posts', 'delete:posts'], { mode: 'all' })
```

#### Fresh Session Examples

```typescript
// Use default freshAge (from auth config, defaults to 1 day)
@RequireFreshSession()
@Post('change-password')
changePassword() {}

// Custom freshAge (5 minutes = 300 seconds)
@RequireFreshSession({ maxAge: 300 })
@Post('enable-2fa')
enable2FA() {}

// Custom error message
@RequireFreshSession({ message: 'Please re-authenticate to continue' })
@Delete('account')
deleteAccount() {}
```

### Admin Plugin Decorators

> Requires `admin()` plugin from `better-auth/plugins`

```typescript
import { admin } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [admin()],
});
```

| Decorator                  | Description                                                       |
| -------------------------- | ----------------------------------------------------------------- |
| `@AdminOnly()`             | Admin role required                                               |
| `@BanCheck()`              | Real-time ban check (Better Auth only checks at session creation) |
| `@DisallowImpersonation()` | Block impersonated sessions                                       |
| `@SecureAdminOnly()`       | Combined: Admin + Fresh + No Impersonation                        |

```typescript
// High-security admin operation
@SecureAdminOnly()
@Delete('admin/users/:id')
deleteUser() {
  // Only real admins with fresh sessions can execute
}

// Real-time ban check - useful for users banned after session creation
@BanCheck()
@Post('comments')
createComment() {}

// Prevent impersonated sessions from sensitive operations
@DisallowImpersonation()
@Post('transfer-funds')
transferFunds() {}

// Custom error message
@AdminOnly('Administrator privileges required')
@Get('admin/dashboard')
getDashboard() {}
```

### Alternative Auth Methods

#### Bearer Token Authentication

> Requires `bearer()` plugin from `better-auth/plugins`

```typescript
import { bearer } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [bearer()],
});
```

```typescript
// Enable Bearer token authentication
@BearerAuth()
@Get('api/mobile/data')
getMobileData() {}
```

Client usage:

```bash
curl -H "Authorization: Bearer <session-token>" /api/mobile/data
```

#### API Key Authentication

> Requires `apiKey()` plugin from `better-auth/plugins`

```typescript
import { apiKey } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [apiKey()],
});
```

```typescript
// API Key only
@ApiKeyAuth()
@Get('api/external')
externalApi(@ApiKey() apiKey: ApiKeyValidation['key']) {
  return { keyId: apiKey.id, permissions: apiKey.permissions };
}

// API Key or Session (flexible mode)
@ApiKeyAuth({ allowSession: true })
@Get('api/flexible')
flexibleApi() {}

// With permission requirements
@ApiKeyAuth({
  permissions: {
    permissions: { files: ['read', 'write'] },
    message: 'Requires files read/write permissions',
  },
})
@Post('api/files')
uploadFile() {}
```

Client usage:

```bash
curl -H "x-api-key: <api-key>" /api/external
```

> **Note**: API keys must be sent via dedicated headers (default: `x-api-key`). Custom headers can be configured via Better Auth's `apiKey` plugin `apiKeyHeaders` option. Do NOT use `Authorization: Bearer` for API keys - that's reserved for session tokens.

### Organization Plugin Decorators

> Requires `organization()` plugin from `better-auth/plugins`

```typescript
import { organization } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [
    organization({
      roles: {
        owner: { inherit: ['admin'] },
        admin: { inherit: ['member'] },
        member: { permissions: ['read'] },
      },
    }),
  ],
});
```

| Decorator               | Description                      |
| ----------------------- | -------------------------------- |
| `@OrgRequired()`        | Require organization context     |
| `@OrgRoles(['owner'])`  | Require organization roles       |
| `@OrgPermission({...})` | Require organization permissions |

```typescript
// Require organization context
@OrgRequired()
@Get('org/dashboard')
getOrgDashboard(@CurrentOrg() org: Organization) {
  return { name: org.name };
}

// Require owner or admin role
@OrgRoles(['owner', 'admin'])
@Put('org/settings')
updateOrgSettings() {}

// Multiple roles with AND logic
@OrgRoles(['admin', 'billing'], { mode: 'all' })
@Post('org/billing')
manageBilling() {}

// Fine-grained permission check
@OrgPermission({ resource: 'member', action: 'create' })
@Post('org/members')
inviteMember() {}

// Multiple actions with AND logic
@OrgPermission({ resource: 'member', action: ['read', 'update'], mode: 'all' })
@Put('org/members/:id')
updateMember() {}

// Custom error message
@OrgPermission({
  resource: 'invite',
  action: 'create',
  message: 'You do not have permission to invite members',
})
@Post('org/invitations')
createInvitation() {}
```

Client usage (must include organization ID):

```bash
curl -H "x-organization-id: <org-id>" /org/dashboard
```

### Parameter Decorators

| Decorator             | Description             | Type                      |
| --------------------- | ----------------------- | ------------------------- |
| `@Session()`          | Full session object     | `UserSession`             |
| `@CurrentUser()`      | Current user            | `UserSession['user']`     |
| `@UserProperty('id')` | Specific user property  | `string`                  |
| `@ApiKey()`           | API Key info            | `ApiKeyValidation['key']` |
| `@CurrentOrg()`       | Current organization    | `Organization`            |
| `@OrgMember()`        | Organization membership | `OrganizationMember`      |
| `@IsImpersonating()`  | Impersonation status    | `boolean`                 |
| `@ImpersonatedBy()`   | Impersonator admin ID   | `string \| null`          |

```typescript
@Get('me')
getMe(
  @CurrentUser() user: UserSession['user'],
  @UserProperty('email') email: string,
  @UserProperty('id') userId: string,
  @IsImpersonating() isImpersonating: boolean,
  @ImpersonatedBy() adminId: string | null,
) {
  return { user, email, userId, isImpersonating, adminId };
}

@OrgRequired()
@Get('org/context')
getOrgContext(
  @CurrentOrg() org: Organization,
  @OrgMember() member: OrganizationMember,
) {
  return { org, member };
}
```

### Custom Auth Context Decorators

Create reusable parameter decorators with `createAuthParamDecorator` to reduce boilerplate and standardize auth context extraction across your application.

**Before** - repetitive parameter injection:

```typescript
@Get(':id')
findOne(
  @Session() session: UserSession,
  @CurrentOrg() org: Organization | null,
  @OrgMember() member: OrganizationMember | null,
  @Param('id') id: string,
) {
  const ctx = this.buildContext(session, org, member); // manual mapping every time
  return this.resourceService.findOne(id, ctx);
}
```

**After** - clean and reusable:

```typescript
@Get(':id')
findOne(@RequestCtx() ctx: RequestContext, @Param('id') id: string) {
  return this.resourceService.findOne(id, ctx);
}
```

#### Basic Usage

```typescript
import {
  createAuthParamDecorator,
  AuthContext,
} from '@sapix/nestjs-better-auth-fastify';

// Define your context interface
interface RequestContext {
  userId: string;
  userEmail: string;
  isAdmin: boolean;
  organizationId: string | null;
}

// Create a reusable decorator
const RequestCtx = createAuthParamDecorator<RequestContext>(
  (auth: AuthContext) => ({
    userId: auth.user?.id ?? 'anonymous',
    userEmail: auth.user?.email ?? '',
    isAdmin: (auth.user as any)?.role === 'admin',
    organizationId: auth.organization?.id ?? null,
  }),
);

// Use in controllers - clean and consistent
@Controller('resources')
export class ResourceController {
  @Get(':id')
  findOne(@RequestCtx() ctx: RequestContext, @Param('id') id: string) {
    return this.resourceService.findOne(id, ctx);
  }

  @Post()
  create(@RequestCtx() ctx: RequestContext, @Body() dto: CreateDto) {
    return this.resourceService.create(dto, ctx);
  }
}
```

#### AuthContext Properties

The `AuthContext` object provides access to all auth-related data:

```typescript
interface AuthContext {
  session: UserSession | null;
  user: UserSession['user'] | null;
  organization: Organization | null;
  orgMember: OrganizationMember | null;
  isImpersonating: boolean;
  impersonatedBy: string | null;
  apiKey: ApiKeyValidation['key'] | null;
}
```

#### Real-World Examples

**Multi-Tenant Context:**

```typescript
interface TenantContext {
  userId: string;
  tenantId: string | null;
  tenantRole: string;
  isTenantAdmin: boolean;
}

const TenantCtx = createAuthParamDecorator<TenantContext>((auth) => ({
  userId: auth.user?.id ?? 'anonymous',
  tenantId: auth.organization?.id ?? null,
  tenantRole: auth.orgMember?.role ?? 'none',
  isTenantAdmin:
    auth.orgMember?.role === 'owner' || auth.orgMember?.role === 'admin',
}));
```

**Audit Context:**

```typescript
interface AuditContext {
  actorId: string;
  actorType: 'user' | 'apiKey' | 'system';
  impersonatorId: string | null;
  timestamp: string;
}

const AuditCtx = createAuthParamDecorator<AuditContext>((auth) => ({
  actorId: auth.apiKey?.userId ?? auth.user?.id ?? 'system',
  actorType: auth.apiKey ? 'apiKey' : auth.user ? 'user' : 'system',
  impersonatorId: auth.impersonatedBy,
  timestamp: new Date().toISOString(),
}));
```

**Service Layer Context:**

```typescript
interface ServiceContext {
  requesterId: string;
  scope: {
    orgId: string | null;
    permissions: string[];
  };
}

const ServiceCtx = createAuthParamDecorator<ServiceContext>((auth) => {
  const permissions = ['read'];
  if ((auth.user as any)?.role === 'admin') {
    permissions.push('write', 'delete');
  }
  return {
    requesterId: auth.user?.id ?? 'anonymous',
    scope: {
      orgId: auth.organization?.id ?? null,
      permissions,
    },
  };
});
```

#### Combining Multiple Decorators

```typescript
@Get('dashboard')
getDashboard(
  @RequestCtx() request: RequestContext,
  @AuditCtx() audit: AuditContext,
) {
  this.logger.log('Dashboard accessed', audit);
  return this.dashboardService.getData(request);
}
```

## 🪝 Hook System

The hook system allows you to execute custom logic before and after Better Auth processes authentication requests.

### Creating a Hook Provider

```typescript
// src/hooks/sign-up.hook.ts
import { Injectable } from '@nestjs/common';
import {
  Hook,
  BeforeHook,
  AfterHook,
  AuthHookContext,
} from '@sapix/nestjs-better-auth-fastify';

@Hook()
@Injectable()
export class SignUpHook {
  constructor(
    private readonly emailService: EmailService,
    private readonly crmService: CrmService,
  ) {}

  // Validate before sign-up
  @BeforeHook('/sign-up/email')
  async validateBeforeSignUp(ctx: AuthHookContext) {
    const { email } = ctx.body as { email: string };
    if (email.endsWith('@blocked-domain.com')) {
      throw new Error('This email domain is not allowed');
    }
  }

  // Send welcome email after sign-up
  @AfterHook('/sign-up/email')
  async sendWelcomeEmail(ctx: AuthHookContext) {
    const user = ctx.context?.user;
    if (user) {
      await this.emailService.sendWelcome(user.email);
      await this.crmService.createContact(user);
    }
  }

  // Log all auth requests (no path = matches all routes)
  @BeforeHook()
  async logAuthRequest(ctx: AuthHookContext) {
    console.log('Auth request:', ctx.path);
  }
}
```

### Registering Hook Providers

```typescript
// src/app.module.ts
@Module({
  imports: [AuthModule.forRoot({ auth })],
  providers: [SignUpHook], // Register hook provider
})
export class AppModule {}
```

### Common Hook Paths

| Path               | Description        |
| ------------------ | ------------------ |
| `/sign-up/email`   | Email sign-up      |
| `/sign-in/email`   | Email sign-in      |
| `/sign-out`        | Sign out           |
| `/forget-password` | Forgot password    |
| `/reset-password`  | Reset password     |
| `/verify-email`    | Email verification |

## 🛠 AuthService API

`AuthService` provides programmatic access to Better Auth functionality.

### Basic Usage

```typescript
import { Injectable } from '@nestjs/common';
import { AuthService, UserSession } from '@sapix/nestjs-better-auth-fastify';
import type { Auth } from './auth/auth.config';

@Injectable()
export class MyService {
  constructor(private readonly authService: AuthService<Auth>) {}

  async someMethod(request: FastifyRequest) {
    // Get session from request
    const session = await this.authService.getSessionFromRequest(request);

    // Validate session (throws UnauthorizedException if invalid)
    const validSession = await this.authService.validateSession(request);

    // Check roles
    if (this.authService.hasRole(session, ['admin'])) {
      // User is admin
    }

    // Check permissions
    if (
      this.authService.hasPermission(
        session,
        ['user:read', 'user:write'],
        'all',
      )
    ) {
      // User has all required permissions
    }

    // Check session freshness
    if (!this.authService.isSessionFresh(session)) {
      // Require re-authentication
    }

    // Access Better Auth API directly
    const accounts = await this.authService.api.listUserAccounts({
      headers: getWebHeadersFromRequest(request),
    });
  }
}
```

### Session Management

```typescript
// Revoke a specific session
await this.authService.revokeSession(sessionToken, request);

// Revoke all user sessions
await this.authService.revokeAllSessions(request);

// List all user sessions
const sessions = await this.authService.listUserSessions(request);
```

### Admin Features

```typescript
// Check if user is banned
if (this.authService.isUserBanned(session.user)) {
  throw new ForbiddenException('User is banned');
}

// Check impersonation status
if (this.authService.isImpersonating(session)) {
  const adminId = this.authService.getImpersonatedBy(session);
  // Log for audit
}
```

### API Key Verification

```typescript
const result = await this.authService.verifyApiKey(apiKey);
if (result.valid) {
  console.log('Key belongs to user:', result.key?.userId);
  console.log('Permissions:', result.key?.permissions);
}

// With permission requirements
const result = await this.authService.verifyApiKey(apiKey, {
  files: ['read', 'write'],
});
```

### Organization Features

```typescript
// Get active organization
const org = await this.authService.getActiveOrganization(request);

// Check organization permission
const hasPermission = await this.authService.hasOrgPermission(request, {
  resource: 'member',
  action: 'create',
});
```

### JWT Token (Requires JWT Plugin)

```typescript
const jwt = await this.authService.getJwtToken(request);
if (jwt) {
  // Use JWT for service-to-service communication
}
```

### Accessing the Auth Instance

```typescript
// Get the complete Better Auth instance
const authInstance = this.authService.instance;

// Get the configured basePath
const basePath = this.authService.basePath;
```

## 🎨 Type Inference

The library supports full type inference from your Better Auth configuration.

### Using $Infer Pattern

```typescript
import { AuthService } from '@sapix/nestjs-better-auth-fastify';
import type { Auth } from './auth/auth.config';

@Injectable()
export class MyService {
  constructor(private readonly authService: AuthService<Auth>) {}

  async getUser(request: FastifyRequest) {
    // Session type is automatically inferred from your auth config
    const session = await this.authService.getSessionFromRequest(request);
    // session.user includes all fields from your auth config
  }
}

// Get types directly (compile-time only)
type Session = typeof authService.$Infer.Session;
type User = typeof authService.$Infer.User;
```

### Using InferSession and InferUser

```typescript
import { InferSession, InferUser } from '@sapix/nestjs-better-auth-fastify';
import type { Auth } from './auth/auth.config';

type MySession = InferSession<Auth>;
type MyUser = InferUser<Auth>;
```

### Custom User Types

```typescript
interface CustomUser extends BaseUser {
  role: string;
  permissions: string[];
  department: string;
}

@Get('profile')
getProfile(@Session() session: UserSession<CustomUser>) {
  return session.user.department; // Type-safe
}
```

## ⚙️ Configuration

### Full Configuration Options

```typescript
AuthModule.forRoot({
  // Required: Better Auth instance
  auth,

  // Optional: Authentication route prefix
  // Defaults to auth.options.basePath or '/api/auth'
  basePath: '/api/auth',

  // Optional: Disable global AuthGuard
  // Set true to manually apply guards on specific routes
  disableGlobalGuard: false,

  // Optional: Enable debug logging
  debug: false,

  // Optional: Custom middleware wrapping the auth handler
  // Useful for ORM contexts (e.g., MikroORM RequestContext)
  middleware: async (req, reply, next) => {
    await next();
  },

  // Optional: Custom error messages (useful for i18n)
  errorMessages: {
    unauthorized: 'Please log in first',
    forbidden: 'Insufficient permissions',
    sessionNotFresh: 'Please re-login to perform this action',
    userBanned: 'Your account has been banned',
    orgRequired: 'Please select an organization first',
    orgRoleRequired: 'Insufficient organization role permissions',
    orgPermissionRequired: 'You do not have permission for this operation',
    apiKeyRequired: 'Valid API Key required',
    apiKeyInvalidPermissions: 'API Key has insufficient permissions',
  },

  // Optional: Custom organization role permissions
  // Override the default role-permission mapping
  orgRolePermissions: {
    owner: { organization: 'all', member: 'all' },
    admin: { organization: ['read', 'update'], member: ['read', 'create'] },
    member: { organization: ['read'] },
  },
});
```

### Asynchronous Configuration

```typescript
// Using useFactory
AuthModule.forRootAsync({
  imports: [ConfigModule],
  useFactory: (config: ConfigService) => ({
    auth: createAuth(config.get('AUTH_SECRET')),
    basePath: config.get('AUTH_BASE_PATH'),
  }),
  inject: [ConfigService],
});

// Using useClass
AuthModule.forRootAsync({
  useClass: AuthConfigService,
});

// Using useExisting
AuthModule.forRootAsync({
  imports: [ConfigModule],
  useExisting: ConfigService,
});
```

### Disable Global Guard

If you prefer to apply auth on specific routes only:

```typescript
AuthModule.forRoot({
  auth,
  disableGlobalGuard: true,
});
```

Then use `@UseGuards(AuthGuard)` on specific routes:

```typescript
import { UseGuards } from '@nestjs/common';
import { AuthGuard } from '@sapix/nestjs-better-auth-fastify';

@Controller('protected')
@UseGuards(AuthGuard)
export class ProtectedController {
  @Get()
  getData() {
    return { protected: true };
  }
}
```

## 🔌 Multi-Context Support

### HTTP (Default)

Works out of the box with Fastify HTTP adapter.

### GraphQL

```typescript
// Install dependencies
pnpm add @nestjs/graphql graphql

// Decorators work the same way in resolvers
@Resolver()
export class UserResolver {
  @Query(() => User)
  @Roles(['admin'])
  async users(@CurrentUser() user: UserSession['user']) {
    return this.userService.findAll();
  }
}
```

### WebSocket

```typescript
// Install dependencies
pnpm add @nestjs/websockets @nestjs/platform-socket.io

// Decorators work in gateways
@WebSocketGateway()
export class EventsGateway {
  @SubscribeMessage('events')
  handleEvent(@Session() session: UserSession) {
    return { user: session.user };
  }
}
```

## 🔧 Utility Functions

The library exports utility functions for working with Fastify and Web standard APIs:

```typescript
import {
  toWebHeaders,
  toWebRequest,
  getHeadersFromRequest,
  getWebHeadersFromRequest,
  writeWebResponseToReply,
  normalizeBasePath,
  getRequestFromContext,
} from '@sapix/nestjs-better-auth-fastify';

// Convert Fastify headers to Web standard Headers
const webHeaders = toWebHeaders(request.headers);

// Get Web standard Headers from Fastify Request
const headers = getWebHeadersFromRequest(request);

// Build Web standard Request from Fastify Request
const webRequest = toWebRequest(request);

// Write Web Response to Fastify Reply
await writeWebResponseToReply(response, reply);

// Normalize basePath (ensures starts with /, no trailing /)
const path = normalizeBasePath('api/auth/'); // '/api/auth'

// Get FastifyRequest from NestJS ExecutionContext (supports HTTP, GraphQL, WebSocket)
const request = getRequestFromContext(context);
```

## 📝 Request Extension

The library extends `FastifyRequest` with auth-related properties:

```typescript
declare module 'fastify' {
  interface FastifyRequest {
    session: UserSession | null;
    user: UserSession['user'] | null;
    apiKey?: ApiKeyValidation['key'] | null;
    organization?: Organization | null;
    organizationMember?: OrganizationMember | null;
    isImpersonating?: boolean;
    impersonatedBy?: string | null;
  }
}
```

Access directly in route handlers:

```typescript
@Get('profile')
getProfile(@Req() request: FastifyRequest) {
  return {
    user: request.user,
    session: request.session,
    org: request.organization,
    isImpersonating: request.isImpersonating,
  };
}
```

## 🧪 Testing

### Unit Testing

```typescript
import { Test } from '@nestjs/testing';
import {
  AuthModule,
  AuthService,
  AUTH_MODULE_OPTIONS,
} from '@sapix/nestjs-better-auth-fastify';

const module = await Test.createTestingModule({
  imports: [AuthModule.forRoot({ auth, disableGlobalGuard: true })],
}).compile();

const authService = module.get(AuthService);
```

### Mocking AuthService

```typescript
const mockAuthService = {
  getSessionFromRequest: jest.fn().mockResolvedValue(mockSession),
  validateSession: jest.fn().mockResolvedValue(mockSession),
  hasRole: jest.fn().mockReturnValue(true),
  hasPermission: jest.fn().mockReturnValue(true),
  isSessionFresh: jest.fn().mockReturnValue(true),
  isUserBanned: jest.fn().mockReturnValue(false),
  isImpersonating: jest.fn().mockReturnValue(false),
};

const module = await Test.createTestingModule({
  providers: [MyService, { provide: AuthService, useValue: mockAuthService }],
}).compile();
```

## 📋 Requirements

- Node.js >= 18.0.0
- NestJS >= 10.0.0
- Fastify >= 4.0.0
- Better Auth >= 1.0.0

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

MIT

## 🔗 Links

- [Better Auth Documentation](https://www.better-auth.com/docs)
- [NestJS Documentation](https://docs.nestjs.com)
- [Fastify Documentation](https://fastify.dev/docs)

---

<p align="center">
  Made with ❤️ for the NestJS community
</p>
