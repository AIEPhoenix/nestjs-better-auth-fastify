<p align="center">
  <img src="https://nestjs.com/img/logo-small.svg" width="50" alt="NestJS Logo" />
  <span style="font-size: 40px; margin: 0 15px;">+</span>
  <img src="https://www.better-auth.com/logo.png" width="50" alt="Better Auth Logo" />
  <span style="font-size: 40px; margin: 0 15px;">+</span>
  <img src="https://github.com/fastify/graphics/raw/HEAD/fastify-landscape-outlined.svg" width="140" alt="Fastify Logo" />
</p>

<h1 align="center">nestjs-better-auth-fastify</h1>

<p align="center">
  为 <a href="https://nestjs.com">NestJS</a> + <a href="https://fastify.dev">Fastify</a> 提供的 <a href="https://www.better-auth.com">Better Auth</a> 集成库
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@sapix/nestjs-better-auth-fastify"><img src="https://img.shields.io/npm/v/@sapix/nestjs-better-auth-fastify.svg" alt="NPM Version" /></a>
  <a href="https://www.npmjs.com/package/@sapix/nestjs-better-auth-fastify"><img src="https://img.shields.io/npm/l/@sapix/nestjs-better-auth-fastify.svg" alt="Package License" /></a>
  <a href="https://www.npmjs.com/package/@sapix/nestjs-better-auth-fastify"><img src="https://img.shields.io/npm/dm/@sapix/nestjs-better-auth-fastify.svg" alt="NPM Downloads" /></a>
</p>

<p align="center">
  <a href="./README.md">English</a> | 中文
</p>

## 目录

- [特性](#-特性)
- [安装](#-安装)
- [快速开始](#-快速开始)
- [装饰器参考](#-装饰器参考)
  - [访问控制](#访问控制装饰器)
  - [Admin 插件](#admin-插件装饰器)
  - [替代认证方式](#替代认证方式)
  - [Organization 插件](#organization-插件装饰器)
  - [参数装饰器](#参数装饰器)
  - [自定义认证上下文装饰器](#自定义认证上下文装饰器)
- [Hook 系统](#-hook-系统)
- [AuthService API](#-authservice-api)
- [类型推断](#-类型推断)
- [配置选项](#%EF%B8%8F-配置选项)
- [多上下文支持](#-多上下文支持)
- [工具函数](#-工具函数)
- [Request 扩展](#-request-扩展)
- [测试](#-测试)
- [环境要求](#-环境要求)
- [贡献](#-贡献)
- [许可证](#-许可证)

## ✨ 特性

- 🔐 **无缝集成** - 为 NestJS + Fastify 提供开箱即用的 Better Auth 支持
- 🎯 **装饰器驱动** - 直观的装饰器实现认证和授权
- 📦 **插件支持** - 完整支持 Better Auth 插件（Admin、Organization、API Key、Bearer 等）
- 🔄 **多上下文** - 支持 HTTP、GraphQL 和 WebSocket
- 🪝 **Hook 系统** - NestJS 原生的认证生命周期钩子
- 🎨 **类型安全** - 完整的 TypeScript 支持，从认证配置自动推断类型
- ⚡ **高性能** - 可选依赖懒加载优化
- 🌍 **国际化就绪** - 可自定义错误消息

## 📦 安装

```bash
# npm
npm install @sapix/nestjs-better-auth-fastify better-auth

# pnpm
pnpm add @sapix/nestjs-better-auth-fastify better-auth

# yarn
yarn add @sapix/nestjs-better-auth-fastify better-auth
```

### 可选依赖

根据需要安装：

```bash
# GraphQL 支持
pnpm add @nestjs/graphql graphql

# WebSocket 支持
pnpm add @nestjs/websockets @nestjs/platform-socket.io
```

## 🚀 快速开始

### 1. 创建 Better Auth 配置

```typescript
// src/auth/auth.config.ts
import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from '../db';

export const auth = betterAuth({
  basePath: '/api/auth',
  database: drizzleAdapter(db, { provider: 'postgresql' }),
  emailAndPassword: { enabled: true },
  // 按需添加更多插件
});

// 导出类型用于类型推断
export type Auth = typeof auth;
```

### 2. 导入 AuthModule

```typescript
// src/app.module.ts
import { Module } from '@nestjs/common';
import { AuthModule } from '@sapix/nestjs-better-auth-fastify';
import { auth } from './auth/auth.config';

@Module({
  imports: [
    AuthModule.forRoot({ auth }),
  ],
})
export class AppModule {}
```

### 3. 在控制器中使用装饰器

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
  // 默认所有路由都需要认证
  @Get('profile')
  getProfile(@Session() session: UserSession) {
    return session;
  }

  // 公开路由 - 无需认证
  @Get('public')
  @AllowAnonymous()
  getPublicData() {
    return { message: '这是公开内容' };
  }

  // 基于角色的访问控制
  @Get('admin')
  @Roles(['admin'])
  getAdminData(@CurrentUser() user: UserSession['user']) {
    return { message: `你好，管理员 ${user.name}` };
  }
}
```

## 📚 装饰器参考

### 访问控制装饰器

| 装饰器                   | 描述                                       | 示例             |
| ------------------------ | ------------------------------------------ | ---------------- |
| `@AllowAnonymous()`      | 标记为公开路由（覆盖 defaultAuthBehavior） | 公开端点         |
| `@RequireAuth()`         | 要求认证（覆盖 defaultAuthBehavior）       | 受保护端点       |
| `@OptionalAuth()`        | 可选认证，有 session 时注入                | 混合访问端点     |
| `@Roles(['admin'])`      | 要求特定角色                               | 管理员专用路由   |
| `@Permissions(['read'])` | 要求特定权限                               | 基于权限的访问   |
| `@RequireFreshSession()` | 要求最近认证的 session                     | 敏感操作         |

#### 角色和权限示例

```typescript
// OR 逻辑（默认）：用户拥有任一角色即可
@Roles(['admin', 'moderator'])

// AND 逻辑：用户必须拥有所有角色
@Roles(['admin', 'verified'], { mode: 'all' })

// 自定义错误消息
@Roles(['admin'], { message: '需要管理员权限' })

// 基于权限（支持相同选项）
@Permissions(['user:read', 'user:write'], { mode: 'any' })
@Permissions(['read:posts', 'write:posts', 'delete:posts'], { mode: 'all' })
```

#### Session 新鲜度示例

```typescript
// 使用默认 freshAge（来自 auth 配置，默认 1 天）
@RequireFreshSession()
@Post('change-password')
changePassword() {}

// 自定义 freshAge（5 分钟 = 300 秒）
@RequireFreshSession({ maxAge: 300 })
@Post('enable-2fa')
enable2FA() {}

// 自定义错误消息
@RequireFreshSession({ message: '请重新登录以继续' })
@Delete('account')
deleteAccount() {}
```

### Admin 插件装饰器

> 需要 `better-auth/plugins` 中的 `admin()` 插件

```typescript
import { admin } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [admin()],
});
```

| 装饰器                     | 描述                                      |
| -------------------------- | ----------------------------------------- |
| `@AdminOnly()`             | 要求管理员角色                            |
| `@BanCheck()`              | 实时封禁检查（Better Auth 仅在创建时检查）|
| `@DisallowImpersonation()` | 阻止模拟 session                          |
| `@SecureAdminOnly()`       | 组合：Admin + Fresh + 禁止模拟            |

```typescript
// 高安全性管理员操作
@SecureAdminOnly()
@Delete('admin/users/:id')
deleteUser() {
  // 只有真正的管理员且 session 新鲜才能执行
}

// 实时封禁检查 - 适用于 session 创建后被封禁的用户
@BanCheck()
@Post('comments')
createComment() {}

// 阻止模拟 session 执行敏感操作
@DisallowImpersonation()
@Post('transfer-funds')
transferFunds() {}

// 自定义错误消息
@AdminOnly('需要管理员权限')
@Get('admin/dashboard')
getDashboard() {}
```

### 替代认证方式

#### Bearer Token 认证

> 需要 `better-auth/plugins` 中的 `bearer()` 插件

当添加 `bearer()` 插件后，Bearer Token 认证**自动支持**。无需特殊装饰器 - 默认的 session 认证会接受 `Authorization` 头中的 Bearer Token。

```typescript
import { bearer } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [bearer()],
});
```

客户端使用：

```bash
curl -H "Authorization: Bearer <session-token>" /api/mobile/data
```

#### API Key 认证

> 需要 `better-auth/plugins` 中的 `apiKey()` 插件

```typescript
import { apiKey } from 'better-auth/plugins';

export const auth = betterAuth({
  plugins: [apiKey()],
});
```

```typescript
// 仅 API Key
@ApiKeyAuth()
@Get('api/external')
externalApi(@ApiKey() apiKey: ApiKeyValidation['key']) {
  return { keyId: apiKey.id, permissions: apiKey.permissions };
}

// API Key 或 Session（灵活模式）
@ApiKeyAuth({ allowSession: true })
@Get('api/flexible')
flexibleApi() {}

// 带权限要求
@ApiKeyAuth({
  permissions: {
    permissions: { files: ['read', 'write'] },
    message: '需要文件读写权限',
  },
})
@Post('api/files')
uploadFile() {}
```

客户端使用：

```bash
curl -H "x-api-key: <api-key>" /api/external
```

> **注意**：API key 必须通过专用头发送（默认：`x-api-key`）。自定义头可通过 Better Auth 的 `apiKey` 插件的 `apiKeyHeaders` 选项配置。请勿使用 `Authorization: Bearer` 发送 API key - 那是为 session token 保留的。

### Organization 插件装饰器

> 需要 `better-auth/plugins` 中的 `organization()` 插件

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

| 装饰器                  | 描述                           |
| ----------------------- | ------------------------------ |
| `@OrgRequired()`        | 要求组织上下文                 |
| `@OptionalOrg()`        | 加载组织（如可用，非必需）     |
| `@OrgRoles(['owner'])`  | 要求组织角色                   |
| `@OrgPermission({...})` | 要求组织权限                   |

```typescript
// 要求组织上下文
@OrgRequired()
@Get('org/dashboard')
getOrgDashboard(@CurrentOrg() org: Organization) {
  return { name: org.name };
}

// 要求 owner 或 admin 角色
@OrgRoles(['owner', 'admin'])
@Put('org/settings')
updateOrgSettings() {}

// 多角色 AND 逻辑
@OrgRoles(['admin', 'billing'], { mode: 'all' })
@Post('org/billing')
manageBilling() {}

// 细粒度权限检查
@OrgPermission({ resource: 'member', action: 'create' })
@Post('org/members')
inviteMember() {}

// 多操作 AND 逻辑
@OrgPermission({ resource: 'member', action: ['read', 'update'], mode: 'all' })
@Put('org/members/:id')
updateMember() {}

// 自定义错误消息
@OrgPermission({
  resource: 'invite',
  action: 'create',
  message: '你没有邀请成员的权限',
})
@Post('org/invitations')
createInvitation() {}
```

客户端使用（必须包含组织 ID）：

```bash
curl -H "x-organization-id: <org-id>" /org/dashboard
```

### 参数装饰器

| 装饰器                   | 描述               | 类型                      |
| ------------------------ | ------------------ | ------------------------- |
| `@Session()`             | 完整 session 对象  | `UserSession`             |
| `@SessionProperty('id')` | 特定 session 属性  | `string`                  |
| `@CurrentUser()`         | 当前用户           | `UserSession['user']`     |
| `@UserProperty('id')`    | 特定用户属性       | `string`                  |
| `@ApiKey()`              | API Key 信息       | `ApiKeyValidation['key']` |
| `@CurrentOrg()`          | 当前组织           | `Organization`            |
| `@OrgMember()`           | 组织成员身份       | `OrganizationMember`      |
| `@IsImpersonating()`     | 模拟状态           | `boolean`                 |
| `@ImpersonatedBy()`      | 模拟者管理员 ID    | `string \| null`          |

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

### 自定义认证上下文装饰器

使用 `createAuthParamDecorator` 创建可复用的参数装饰器，减少样板代码并标准化认证上下文提取。

**之前** - 重复的参数注入：

```typescript
@Get(':id')
findOne(
  @Session() session: UserSession,
  @CurrentOrg() org: Organization | null,
  @OrgMember() member: OrganizationMember | null,
  @Param('id') id: string,
) {
  const ctx = this.buildContext(session, org, member); // 每次手动映射
  return this.resourceService.findOne(id, ctx);
}
```

**之后** - 简洁可复用：

```typescript
@Get(':id')
findOne(@RequestCtx() ctx: RequestContext, @Param('id') id: string) {
  return this.resourceService.findOne(id, ctx);
}
```

#### 基本用法

```typescript
import {
  createAuthParamDecorator,
  AuthContext,
} from '@sapix/nestjs-better-auth-fastify';

// 定义上下文接口
interface RequestContext {
  userId: string;
  userEmail: string;
  isAdmin: boolean;
  organizationId: string | null;
}

// 创建可复用装饰器
const RequestCtx = createAuthParamDecorator<RequestContext>(
  (auth: AuthContext) => ({
    userId: auth.user?.id ?? 'anonymous',
    userEmail: auth.user?.email ?? '',
    isAdmin: (auth.user as any)?.role === 'admin',
    organizationId: auth.organization?.id ?? null,
  }),
);

// 在控制器中使用 - 简洁一致
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

#### AuthContext 属性

`AuthContext` 对象提供所有认证相关数据：

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

#### 装饰器数据可用性

**重要**：并非所有 `AuthContext` 属性默认都会填充。数据可用性取决于认证方式和使用的装饰器：

**Session 认证**（默认）：

| AuthContext 属性     | 可用性              | 说明                                     |
| -------------------- | ------------------- | ---------------------------------------- |
| `session`            | ✅ 始终可用         | 完整 session 对象                        |
| `user`               | ✅ 始终可用         | 来自 session 的用户                      |
| `isImpersonating`    | ✅ 始终可用         | 来自 session 数据                        |
| `impersonatedBy`     | ✅ 始终可用         | 模拟时的管理员 ID                        |
| `organization`       | ⚠️ 需要装饰器       | 使用 `@OrgRequired()` 或 `@OptionalOrg()` |
| `orgMember`          | ⚠️ 需要装饰器       | 使用 `@OrgRequired()` 或 `@OptionalOrg()` |
| `apiKey`             | ❌ `null`           | 不适用于 session 认证                    |

**API Key 认证**（`@ApiKeyAuth()`）：

| AuthContext 属性     | 可用性              | 说明                                     |
| -------------------- | ------------------- | ---------------------------------------- |
| `session`            | ❌ `null`           | API Key 没有 session                     |
| `user`               | ✅ 始终可用         | 通过 `key.userId` 加载                   |
| `isImpersonating`    | ❌ `false`          | 不适用于 API Key                         |
| `impersonatedBy`     | ❌ `null`           | 不适用于 API Key                         |
| `organization`       | ❌ `null`           | API Key 认证不加载                       |
| `orgMember`          | ❌ `null`           | API Key 认证不加载                       |
| `apiKey`             | ✅ 始终可用         | 完整 API Key 信息                        |

#### 创建配套装饰器

当创建使用组织数据的自定义参数装饰器时，需要创建**配套**的方法装饰器来确保数据正确加载。命名约定：

- `XxxAuth` - 方法装饰器：声明**授权要求**（需要什么认证/权限）
- `XxxAuthState` - 参数装饰器：提取**授权状态**（提取认证上下文数据）
- `XxxAuthStateInfo` - 接口：定义状态类型（添加 `Info` 后缀避免与装饰器命名冲突）

```typescript
import { applyDecorators } from '@nestjs/common';
import {
  createAuthParamDecorator,
  OptionalOrg,
  OrgRequired,
  OrgRoles,
  RequireAuth,
} from '@sapix/nestjs-better-auth-fastify';

// 1. 定义授权状态接口（使用 "Info" 后缀避免与装饰器命名冲突）
interface ResourceAuthStateInfo {
  userId: string;
  organizationId: string | null;
  orgRole: string | null;
  isOrgAdmin: boolean;
}

// 2. 创建参数装饰器：@ResourceAuthState() - 提取授权状态
export const ResourceAuthState = createAuthParamDecorator<ResourceAuthStateInfo>(
  (auth) => ({
    userId: auth.user?.id ?? '',
    organizationId: auth.organization?.id ?? null,
    orgRole: auth.orgMember?.role ?? null,
    isOrgAdmin:
      auth.orgMember?.role === 'owner' || auth.orgMember?.role === 'admin',
  }),
);

// 3. 创建配套方法装饰器：@ResourceAuth() - 声明授权要求
export interface ResourceAuthOptions {
  requireOrg?: boolean;
  orgRoles?: string[];
}

export function ResourceAuth(options: ResourceAuthOptions = {}) {
  const { requireOrg = false, orgRoles } = options;

  // 指定组织角色 -> 需要组织 + 特定角色
  if (orgRoles?.length) {
    return applyDecorators(OrgRequired(), OrgRoles(orgRoles));
  }

  // 需要组织上下文
  if (requireOrg) {
    return OrgRequired();
  }

  // 默认：需要认证，如可用则加载组织
  // RequireAuth() 确保即使 defaultAuthBehavior 为 'public' 也需要认证
  return applyDecorators(RequireAuth(), OptionalOrg());
}
```

**用法 - 始终将 `@ResourceAuth()` 与 `@ResourceAuthState()` 配套使用：**

```typescript
@Controller('resources')
export class ResourceController {
  // 默认：需要认证，如可用则加载组织
  @ResourceAuth()
  @Get('my')
  getMyResources(@ResourceAuthState() state: ResourceAuthStateInfo) {
    if (state.organizationId) {
      return this.service.getOrgResources(state.organizationId);
    }
    return this.service.getUserResources(state.userId);
  }

  // 需要认证 + 组织上下文
  @ResourceAuth({ requireOrg: true })
  @Get('org')
  getOrgResources(@ResourceAuthState() state: ResourceAuthStateInfo) {
    return this.service.getOrgResources(state.organizationId!);
  }

  // 需要认证 + 组织 + 管理员角色
  @ResourceAuth({ orgRoles: ['owner', 'admin'] })
  @Put('org/settings')
  updateOrgSettings(@ResourceAuthState() state: ResourceAuthStateInfo) {
    return this.service.updateSettings(state.organizationId!);
  }
}
```

> **注意**：默认的 `@ResourceAuth()` 使用 `RequireAuth()` 确保认证，不受 `defaultAuthBehavior` 设置影响。这使装饰器行为可预测且独立于全局配置。

#### 实际示例

**多租户：**

```typescript
// 状态接口
interface TenantAuthStateInfo {
  userId: string;
  tenantId: string | null;
  tenantRole: string;
  isTenantAdmin: boolean;
}

// 参数装饰器：提取租户状态
const TenantAuthState = createAuthParamDecorator<TenantAuthStateInfo>((auth) => ({
  userId: auth.user?.id ?? 'anonymous',
  tenantId: auth.organization?.id ?? null,
  tenantRole: auth.orgMember?.role ?? 'none',
  isTenantAdmin:
    auth.orgMember?.role === 'owner' || auth.orgMember?.role === 'admin',
}));

// 方法装饰器：声明租户授权要求
interface TenantAuthOptions {
  requireTenant?: boolean;
  roles?: string[];
}

function TenantAuth(options: TenantAuthOptions = {}) {
  const { requireTenant = true, roles } = options;
  if (roles?.length) {
    return applyDecorators(OrgRequired(), OrgRoles(roles));
  }
  return requireTenant ? OrgRequired() : applyDecorators(RequireAuth(), OptionalOrg());
}

// 用法
@TenantAuth()
@Get('tenant/dashboard')
getDashboard(@TenantAuthState() tenant: TenantAuthStateInfo) { ... }
```

**审计追踪：**

```typescript
// 状态接口
interface AuditAuthStateInfo {
  actorId: string;
  actorType: 'user' | 'apiKey' | 'system';
  impersonatorId: string | null;
  timestamp: string;
}

// 参数装饰器：提取审计上下文
const AuditAuthState = createAuthParamDecorator<AuditAuthStateInfo>((auth) => ({
  actorId: auth.apiKey?.userId ?? auth.user?.id ?? 'system',
  actorType: auth.apiKey ? 'apiKey' : auth.user ? 'user' : 'system',
  impersonatorId: auth.impersonatedBy,
  timestamp: new Date().toISOString(),
}));

// 方法装饰器：审计路由允许可选认证（系统操作也需要审计）
function AuditAuth() {
  return OptionalAuth();
}

// 用法
@AuditAuth()
@Post('events')
logEvent(@AuditAuthState() audit: AuditAuthStateInfo) { ... }
```

**服务层：**

```typescript
// 状态接口
interface ServiceAuthStateInfo {
  requesterId: string;
  scope: {
    orgId: string | null;
    permissions: string[];
  };
}

// 参数装饰器：提取服务上下文
const ServiceAuthState = createAuthParamDecorator<ServiceAuthStateInfo>((auth) => {
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

// 方法装饰器：服务路由需要认证并可选加载组织
function ServiceAuth() {
  return applyDecorators(RequireAuth(), OptionalOrg());
}

// 用法
@ServiceAuth()
@Get('data')
getData(@ServiceAuthState() ctx: ServiceAuthStateInfo) { ... }
```

## 🪝 Hook 系统

Hook 系统允许你在 Better Auth 处理认证请求前后执行自定义逻辑。

### 创建 Hook Provider

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

  // 注册前验证
  @BeforeHook('/sign-up/email')
  async validateBeforeSignUp(ctx: AuthHookContext) {
    const { email } = ctx.body as { email: string };
    if (email.endsWith('@blocked-domain.com')) {
      throw new Error('此邮箱域名不被允许');
    }
  }

  // 注册后发送欢迎邮件
  @AfterHook('/sign-up/email')
  async sendWelcomeEmail(ctx: AuthHookContext) {
    const user = ctx.context?.user;
    if (user) {
      await this.emailService.sendWelcome(user.email);
      await this.crmService.createContact(user);
    }
  }

  // 记录所有认证请求（无路径 = 匹配所有路由）
  @BeforeHook()
  async logAuthRequest(ctx: AuthHookContext) {
    console.log('认证请求:', ctx.path);
  }
}
```

### 注册 Hook Provider

```typescript
// src/app.module.ts
@Module({
  imports: [AuthModule.forRoot({ auth })],
  providers: [SignUpHook], // 注册 hook provider
})
export class AppModule {}
```

### 常用 Hook 路径

| 路径               | 描述         |
| ------------------ | ------------ |
| `/sign-up/email`   | 邮箱注册     |
| `/sign-in/email`   | 邮箱登录     |
| `/sign-out`        | 登出         |
| `/forget-password` | 忘记密码     |
| `/reset-password`  | 重置密码     |
| `/verify-email`    | 邮箱验证     |

## 🛠 AuthService API

`AuthService` 提供对 Better Auth 功能的程序化访问。

### 基本用法

```typescript
import { Injectable } from '@nestjs/common';
import { AuthService, UserSession } from '@sapix/nestjs-better-auth-fastify';
import type { Auth } from './auth/auth.config';

@Injectable()
export class MyService {
  constructor(private readonly authService: AuthService<Auth>) {}

  async someMethod(request: FastifyRequest) {
    // 从请求获取 session
    const session = await this.authService.getSessionFromRequest(request);

    // 验证 session（无效时抛出 UnauthorizedException）
    const validSession = await this.authService.validateSession(request);

    // 检查角色
    if (this.authService.hasRole(session, ['admin'])) {
      // 用户是管理员
    }

    // 检查权限
    if (
      this.authService.hasPermission(
        session,
        ['user:read', 'user:write'],
        'all',
      )
    ) {
      // 用户拥有所有必需权限
    }

    // 检查 session 新鲜度
    if (!this.authService.isSessionFresh(session)) {
      // 要求重新认证
    }

    // 直接访问 Better Auth API
    const accounts = await this.authService.api.listUserAccounts({
      headers: getWebHeadersFromRequest(request),
    });
  }
}
```

### Session 管理

```typescript
// 撤销特定 session
await this.authService.revokeSession(sessionToken, request);

// 撤销所有用户 session
await this.authService.revokeAllSessions(request);

// 列出所有用户 session
const sessions = await this.authService.listUserSessions(request);
```

### Admin 功能

```typescript
// 检查用户是否被封禁
if (this.authService.isUserBanned(session.user)) {
  throw new ForbiddenException('用户已被封禁');
}

// 检查模拟状态
if (this.authService.isImpersonating(session)) {
  const adminId = this.authService.getImpersonatedBy(session);
  // 记录审计日志
}
```

### API Key 验证

```typescript
const result = await this.authService.verifyApiKey(apiKey);
if (result.valid) {
  console.log('Key 属于用户:', result.key?.userId);
  console.log('权限:', result.key?.permissions);
}

// 带权限要求
const result = await this.authService.verifyApiKey(apiKey, {
  files: ['read', 'write'],
});
```

### Organization 功能

```typescript
// 获取活动组织
const org = await this.authService.getActiveOrganization(request);

// 检查组织权限
const hasPermission = await this.authService.hasOrgPermission(request, {
  resource: 'member',
  action: 'create',
});
```

### JWT Token（需要 JWT 插件）

```typescript
const jwt = await this.authService.getJwtToken(request);
if (jwt) {
  // 使用 JWT 进行服务间通信
}
```

### 访问 Auth 实例

```typescript
// 获取完整的 Better Auth 实例
const authInstance = this.authService.instance;

// 获取配置的 basePath
const basePath = this.authService.basePath;
```

## 🎨 类型推断

该库支持从 Better Auth 配置完全推断类型。

### 使用 $Infer 模式

```typescript
import { AuthService } from '@sapix/nestjs-better-auth-fastify';
import type { Auth } from './auth/auth.config';

@Injectable()
export class MyService {
  constructor(private readonly authService: AuthService<Auth>) {}

  async getUser(request: FastifyRequest) {
    // Session 类型自动从你的 auth 配置推断
    const session = await this.authService.getSessionFromRequest(request);
    // session.user 包含你 auth 配置中的所有字段
  }
}

// 直接获取类型（仅编译时）
type Session = typeof authService.$Infer.Session;
type User = typeof authService.$Infer.User;
```

### 使用 InferSession 和 InferUser

```typescript
import { InferSession, InferUser } from '@sapix/nestjs-better-auth-fastify';
import type { Auth } from './auth/auth.config';

type MySession = InferSession<Auth>;
type MyUser = InferUser<Auth>;
```

### 自定义用户类型

```typescript
interface CustomUser extends BaseUser {
  role: string;
  permissions: string[];
  department: string;
}

@Get('profile')
getProfile(@Session() session: UserSession<CustomUser>) {
  return session.user.department; // 类型安全
}
```

## ⚙️ 配置选项

### 完整配置选项

```typescript
AuthModule.forRoot({
  // 必需：Better Auth 实例
  // 认证路由路径从 auth.options.basePath 读取（默认 '/api/auth'）
  auth,

  // 可选：默认认证行为
  // - 'require'（默认）：所有路由需要认证。使用 @AllowAnonymous() 设为公开。
  // - 'optional'：所有路由可选认证。有 session 时注入。
  // - 'public'：所有路由默认公开。使用 @RequireAuth() 要求认证。
  defaultAuthBehavior: 'require',

  // 可选：启用调试日志
  debug: false,

  // 可选：自定义中间件包装认证处理器
  // 适用于 ORM 上下文（如 MikroORM RequestContext）
  middleware: async (req, reply, next) => {
    await next();
  },

  // 可选：自定义错误消息（用于国际化）
  errorMessages: {
    unauthorized: '请登录后继续',
    forbidden: '你没有权限执行此操作',
    sessionNotFresh: '请重新登录后继续',
    userBanned: '你的账户已被暂停使用',
    orgRequired: '请选择一个组织后继续',
    orgRoleRequired: '你的组织角色无法执行此操作',
    orgPermissionRequired: '你缺少所需的组织权限',
    apiKeyRequired: '需要提供有效的 API Key',
    apiKeyInvalidPermissions: '你的 API Key 缺少所需权限',
    adminRequired: '此操作需要管理员权限',
    impersonationNotAllowed: '模拟登录时无法执行此操作',
    roleRequired: '你的角色无法执行此操作',
    permissionRequired: '你缺少所需的权限',
    orgMembershipRequired: '你必须是此组织的成员',
  },

  // 可选：自定义组织角色权限
  // 覆盖默认的角色-权限映射
  orgRolePermissions: {
    owner: { organization: 'all', member: 'all' },
    admin: { organization: ['read', 'update'], member: ['read', 'create'] },
    member: { organization: ['read'] },
  },
});
```

### 异步配置

```typescript
// 使用 useFactory
AuthModule.forRootAsync({
  imports: [ConfigModule],
  useFactory: (config: ConfigService) => ({
    auth: createAuth(config.get('AUTH_SECRET')),
  }),
  inject: [ConfigService],
});

// 使用 useClass
AuthModule.forRootAsync({
  useClass: AuthConfigService,
});

// 使用 useExisting
AuthModule.forRootAsync({
  imports: [ConfigModule],
  useExisting: ConfigService,
});
```

### 默认认证行为

控制路由的默认行为：

#### `'require'`（默认）- 默认安全

所有路由需要认证。使用 `@AllowAnonymous()` 设为公开：

```typescript
@Controller('api')
export class ApiController {
  @Get('protected')
  protectedRoute() {} // 需要认证

  @AllowAnonymous()
  @Get('public')
  publicRoute() {} // 无需认证
}
```

#### `'public'` - 默认开放

所有路由默认公开。使用 `@RequireAuth()` 要求认证：

```typescript
AuthModule.forRoot({
  auth,
  defaultAuthBehavior: 'public',
});

@Controller('api')
export class ApiController {
  @Get('public')
  publicRoute() {} // 无需认证

  @RequireAuth()
  @Get('protected')
  protectedRoute() {} // 需要认证
}
```

#### `'optional'` - 灵活认证

所有路由同时接受已认证和匿名请求：

```typescript
AuthModule.forRoot({
  auth,
  defaultAuthBehavior: 'optional',
});

@Controller('api')
export class ApiController {
  @Get('greeting')
  greet(@CurrentUser() user: User | null) {
    return user ? `你好 ${user.name}` : '你好访客';
  }
}
```

## 🔌 多上下文支持

### HTTP（默认）

开箱即用，适配 Fastify HTTP 适配器。

### GraphQL

```typescript
// 安装依赖
pnpm add @nestjs/graphql graphql

// 装饰器在 resolver 中同样工作
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
// 安装依赖
pnpm add @nestjs/websockets @nestjs/platform-socket.io

// 装饰器在 gateway 中工作
@WebSocketGateway()
export class EventsGateway {
  @SubscribeMessage('events')
  handleEvent(@Session() session: UserSession) {
    return { user: session.user };
  }
}
```

## 🔧 工具函数

该库导出用于 Fastify 和 Web 标准 API 的工具函数：

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

// 将 Fastify headers 转换为 Web 标准 Headers
const webHeaders = toWebHeaders(request.headers);

// 从 Fastify Request 获取 Web 标准 Headers
const headers = getWebHeadersFromRequest(request);

// 从 Fastify Request 构建 Web 标准 Request
const webRequest = toWebRequest(request);

// 将 Web Response 写入 Fastify Reply
await writeWebResponseToReply(response, reply);

// 标准化 basePath（确保以 / 开头，无尾随 /）
const path = normalizeBasePath('api/auth/'); // '/api/auth'

// 从 NestJS ExecutionContext 获取 FastifyRequest（支持 HTTP、GraphQL、WebSocket）
const request = getRequestFromContext(context);
```

## 📝 Request 扩展

该库为 `FastifyRequest` 扩展了认证相关属性：

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

在路由处理器中直接访问：

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

## 🧪 测试

### 单元测试

```typescript
import { Test } from '@nestjs/testing';
import {
  AuthModule,
  AuthService,
  AUTH_MODULE_OPTIONS,
} from '@sapix/nestjs-better-auth-fastify';

const module = await Test.createTestingModule({
  imports: [AuthModule.forRoot({ auth })],
}).compile();

const authService = module.get(AuthService);
```

### Mock AuthService

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

## 📋 环境要求

- Node.js >= 18.0.0
- NestJS >= 10.0.0
- Fastify >= 4.0.0
- Better Auth >= 1.0.0

## 🤝 贡献

欢迎贡献！请随时提交 Pull Request。

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

## 📄 许可证

MIT

## 🔗 链接

- [Better Auth 文档](https://www.better-auth.com/docs)
- [NestJS 文档](https://docs.nestjs.com)
- [Fastify 文档](https://fastify.dev/docs)

---

<p align="center">
  为 NestJS 社区用 ❤️ 制作
</p>
