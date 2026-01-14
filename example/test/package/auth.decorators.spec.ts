import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import {
  AllowAnonymous,
  OptionalAuth,
  RequireAuth,
  Roles,
  Permissions,
  RequireFreshSession,
  AdminOnly,
  BanCheck,
  DisallowImpersonation,
  ApiKeyAuth,
  OrgRequired,
  OptionalOrg,
  OrgRoles,
  OrgPermission,
  SecureAdminOnly,
  Hook,
  BeforeHook,
  AfterHook,
  getRequestFromContext,
  createAuthParamDecorator,
  Session,
  SessionProperty,
  CurrentUser,
  UserProperty,
  CurrentOrg,
  OrgMember,
  IsImpersonating,
  ImpersonatedBy,
  ApiKey,
  type AuthContext,
  ALLOW_ANONYMOUS_KEY,
  OPTIONAL_AUTH_KEY,
  REQUIRE_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  API_KEY_AUTH_KEY,
  DISALLOW_IMPERSONATION_KEY,
  ORG_REQUIRED_KEY,
  LOAD_ORG_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  HOOK_KEY,
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
} from '@sapix/nestjs-better-auth-fastify';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants';

describe('auth.decorators', () => {
  describe('Metadata Keys', () => {
    it('should export all metadata keys', () => {
      expect(ALLOW_ANONYMOUS_KEY).toBe('auth:allowAnonymous');
      expect(OPTIONAL_AUTH_KEY).toBe('auth:optional');
      expect(REQUIRE_AUTH_KEY).toBe('auth:requireAuth');
      expect(ROLES_KEY).toBe('auth:roles');
      expect(PERMISSIONS_KEY).toBe('auth:permissions');
      expect(FRESH_SESSION_KEY).toBe('auth:freshSession');
      expect(ADMIN_ONLY_KEY).toBe('auth:adminOnly');
      expect(BAN_CHECK_KEY).toBe('auth:banCheck');
      expect(API_KEY_AUTH_KEY).toBe('auth:apiKeyAuth');
      expect(DISALLOW_IMPERSONATION_KEY).toBe('auth:disallowImpersonation');
      expect(ORG_REQUIRED_KEY).toBe('auth:orgRequired');
      expect(ORG_ROLES_KEY).toBe('auth:orgRoles');
      expect(ORG_PERMISSIONS_KEY).toBe('auth:orgPermissions');
    });
  });

  describe('Route Decorators', () => {
    class TestController {
      @AllowAnonymous()
      allowAnonymousMethod() {}

      @OptionalAuth()
      optionalAuthMethod() {}

      @RequireAuth()
      requireAuthMethod() {}

      @Roles(['admin', 'moderator'])
      rolesMethod() {}

      @Roles(['admin', 'verified'], { mode: 'all', message: 'Custom message' })
      rolesAllModeMethod() {}

      @Permissions(['user:read', 'user:write'])
      permissionsMethod() {}

      @Permissions(['read', 'write'], { mode: 'all' })
      permissionsAllModeMethod() {}

      @RequireFreshSession()
      freshSessionMethod() {}

      @RequireFreshSession({ maxAge: 300, message: 'Re-auth required' })
      freshSessionCustomMethod() {}

      @AdminOnly()
      adminOnlyMethod() {}

      @AdminOnly('Custom admin message')
      adminOnlyCustomMethod() {}

      @BanCheck()
      banCheckMethod() {}

      @DisallowImpersonation()
      disallowImpersonationMethod() {}

      @DisallowImpersonation('No impersonation allowed')
      disallowImpersonationCustomMethod() {}

      @ApiKeyAuth()
      apiKeyAuthMethod() {}

      @ApiKeyAuth({ allowSession: true })
      apiKeyAuthWithSessionMethod() {}

      @ApiKeyAuth({
        permissions: {
          permissions: { files: ['read'] },
          message: 'Need files:read',
        },
      })
      apiKeyAuthWithPermissionsMethod() {}

      @OrgRequired()
      orgRequiredMethod() {}

      @OptionalOrg()
      optionalOrgMethod() {}

      @OrgRoles(['owner', 'admin'])
      orgRolesMethod() {}

      @OrgRoles(['admin', 'billing'], { mode: 'all' })
      orgRolesAllModeMethod() {}

      @OrgPermission({ resource: 'member', action: 'create' })
      orgPermissionMethod() {}

      @SecureAdminOnly()
      secureAdminOnlyMethod() {}
    }

    let reflector: Reflector;

    beforeEach(() => {
      reflector = new Reflector();
    });

    it('@AllowAnonymous should set metadata to true', () => {
      const metadata = reflector.get(
        ALLOW_ANONYMOUS_KEY,
        TestController.prototype.allowAnonymousMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@OptionalAuth should set metadata to true', () => {
      const metadata = reflector.get(
        OPTIONAL_AUTH_KEY,
        TestController.prototype.optionalAuthMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@RequireAuth should set metadata to true', () => {
      const metadata = reflector.get(
        REQUIRE_AUTH_KEY,
        TestController.prototype.requireAuthMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@Roles should set roles metadata with default options', () => {
      const metadata = reflector.get(
        ROLES_KEY,
        TestController.prototype.rolesMethod,
      );
      expect(metadata).toEqual({
        roles: ['admin', 'moderator'],
        options: { mode: 'any' },
      });
    });

    it('@Roles should set roles metadata with custom options', () => {
      const metadata = reflector.get(
        ROLES_KEY,
        TestController.prototype.rolesAllModeMethod,
      );
      expect(metadata).toEqual({
        roles: ['admin', 'verified'],
        options: { mode: 'all', message: 'Custom message' },
      });
    });

    it('@Permissions should set permissions metadata with default options', () => {
      const metadata = reflector.get(
        PERMISSIONS_KEY,
        TestController.prototype.permissionsMethod,
      );
      expect(metadata).toEqual({
        permissions: ['user:read', 'user:write'],
        options: { mode: 'any' },
      });
    });

    it('@Permissions should set permissions metadata with custom options', () => {
      const metadata = reflector.get(
        PERMISSIONS_KEY,
        TestController.prototype.permissionsAllModeMethod,
      );
      expect(metadata).toEqual({
        permissions: ['read', 'write'],
        options: { mode: 'all' },
      });
    });

    it('@RequireFreshSession should set metadata with default options', () => {
      const metadata = reflector.get(
        FRESH_SESSION_KEY,
        TestController.prototype.freshSessionMethod,
      );
      expect(metadata).toEqual({ options: {} });
    });

    it('@RequireFreshSession should set metadata with custom options', () => {
      const metadata = reflector.get(
        FRESH_SESSION_KEY,
        TestController.prototype.freshSessionCustomMethod,
      );
      expect(metadata).toEqual({
        options: { maxAge: 300, message: 'Re-auth required' },
      });
    });

    it('@AdminOnly should set metadata', () => {
      const metadata = reflector.get(
        ADMIN_ONLY_KEY,
        TestController.prototype.adminOnlyMethod,
      );
      expect(metadata).toEqual({ message: undefined });
    });

    it('@AdminOnly should set metadata with custom message', () => {
      const metadata = reflector.get(
        ADMIN_ONLY_KEY,
        TestController.prototype.adminOnlyCustomMethod,
      );
      expect(metadata).toEqual({ message: 'Custom admin message' });
    });

    it('@BanCheck should set metadata to true', () => {
      const metadata = reflector.get(
        BAN_CHECK_KEY,
        TestController.prototype.banCheckMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@DisallowImpersonation should set metadata', () => {
      const metadata = reflector.get(
        DISALLOW_IMPERSONATION_KEY,
        TestController.prototype.disallowImpersonationMethod,
      );
      expect(metadata).toEqual({ message: undefined });
    });

    it('@DisallowImpersonation should set metadata with custom message', () => {
      const metadata = reflector.get(
        DISALLOW_IMPERSONATION_KEY,
        TestController.prototype.disallowImpersonationCustomMethod,
      );
      expect(metadata).toEqual({ message: 'No impersonation allowed' });
    });

    it('@ApiKeyAuth should set metadata with default options', () => {
      const metadata = reflector.get(
        API_KEY_AUTH_KEY,
        TestController.prototype.apiKeyAuthMethod,
      );
      expect(metadata).toEqual({});
    });

    it('@ApiKeyAuth should set metadata with allowSession option', () => {
      const metadata = reflector.get(
        API_KEY_AUTH_KEY,
        TestController.prototype.apiKeyAuthWithSessionMethod,
      );
      expect(metadata).toEqual({ allowSession: true });
    });

    it('@ApiKeyAuth should set metadata with permissions option', () => {
      const metadata = reflector.get(
        API_KEY_AUTH_KEY,
        TestController.prototype.apiKeyAuthWithPermissionsMethod,
      );
      expect(metadata).toEqual({
        permissions: {
          permissions: { files: ['read'] },
          message: 'Need files:read',
        },
      });
    });

    it('@OrgRequired should set metadata to true', () => {
      const metadata = reflector.get(
        ORG_REQUIRED_KEY,
        TestController.prototype.orgRequiredMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@OptionalOrg should set metadata to true', () => {
      const metadata = reflector.get(
        LOAD_ORG_KEY,
        TestController.prototype.optionalOrgMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@OrgRoles should set metadata with default options', () => {
      const metadata = reflector.get(
        ORG_ROLES_KEY,
        TestController.prototype.orgRolesMethod,
      );
      expect(metadata).toEqual({
        roles: ['owner', 'admin'],
        options: { mode: 'any' },
      });
    });

    it('@OrgRoles should set metadata with custom options', () => {
      const metadata = reflector.get(
        ORG_ROLES_KEY,
        TestController.prototype.orgRolesAllModeMethod,
      );
      expect(metadata).toEqual({
        roles: ['admin', 'billing'],
        options: { mode: 'all' },
      });
    });

    it('@OrgPermission should set metadata', () => {
      const metadata = reflector.get(
        ORG_PERMISSIONS_KEY,
        TestController.prototype.orgPermissionMethod,
      );
      expect(metadata).toEqual({
        options: { resource: 'member', action: 'create' },
      });
    });

    it('@SecureAdminOnly should apply multiple decorators', () => {
      const adminOnly = reflector.get(
        ADMIN_ONLY_KEY,
        TestController.prototype.secureAdminOnlyMethod,
      );
      const freshSession = reflector.get(
        FRESH_SESSION_KEY,
        TestController.prototype.secureAdminOnlyMethod,
      );
      const disallowImpersonation = reflector.get(
        DISALLOW_IMPERSONATION_KEY,
        TestController.prototype.secureAdminOnlyMethod,
      );

      expect(adminOnly).toBeDefined();
      expect(freshSession).toBeDefined();
      expect(disallowImpersonation).toBeDefined();
    });
  });

  describe('Hook Decorators', () => {
    @Hook()
    class TestHook {
      @BeforeHook('/sign-up/email')
      beforeSignUp() {}

      @AfterHook('/sign-in/email')
      afterSignIn() {}

      @BeforeHook()
      beforeAll() {}
    }

    let reflector: Reflector;

    beforeEach(() => {
      reflector = new Reflector();
    });

    it('@Hook should set class metadata', () => {
      const metadata = reflector.get(HOOK_KEY, TestHook);
      expect(metadata).toBe(true);
    });

    it('@BeforeHook should set method metadata with path', () => {
      const metadata = reflector.get(
        BEFORE_HOOK_KEY,
        TestHook.prototype.beforeSignUp,
      );
      expect(metadata).toBe('/sign-up/email');
    });

    it('@AfterHook should set method metadata with path', () => {
      const metadata = reflector.get(
        AFTER_HOOK_KEY,
        TestHook.prototype.afterSignIn,
      );
      expect(metadata).toBe('/sign-in/email');
    });

    it('@BeforeHook without path should set undefined', () => {
      const metadata = reflector.get(
        BEFORE_HOOK_KEY,
        TestHook.prototype.beforeAll,
      );
      expect(metadata).toBeUndefined();
    });
  });

  describe('getRequestFromContext', () => {
    it('should return HTTP request for http context', () => {
      const mockRequest = { url: '/test' };
      const mockContext = {
        getType: jest.fn().mockReturnValue('http'),
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      } as unknown as ExecutionContext;

      const request = getRequestFromContext(mockContext);

      expect(request).toBe(mockRequest);
      expect(mockContext.switchToHttp).toHaveBeenCalled();
    });

    it('should return minimal request from WebSocket handshake headers', () => {
      const mockClient = { handshake: { headers: { cookie: 'session=abc' } } };
      const mockContext = {
        getType: jest.fn().mockReturnValue('ws'),
        switchToWs: jest.fn().mockReturnValue({
          getData: jest.fn().mockReturnValue(undefined), // No data available
          getClient: jest.fn().mockReturnValue(mockClient),
        }),
      } as unknown as ExecutionContext;

      const request = getRequestFromContext(mockContext);

      // Returns a minimal request-like object with headers from handshake
      expect(request.headers).toEqual({ cookie: 'session=abc' });
      expect(request.session).toBeNull();
      expect(request.user).toBeNull();
      expect(mockContext.switchToWs).toHaveBeenCalled();
    });

    it('should return request from WsData if available', () => {
      const mockRequest = { url: '/test', headers: {} };
      const mockContext = {
        getType: jest.fn().mockReturnValue('ws'),
        switchToWs: jest.fn().mockReturnValue({
          getData: jest.fn().mockReturnValue({ request: mockRequest }),
          getClient: jest.fn(),
        }),
      } as unknown as ExecutionContext;

      const request = getRequestFromContext(mockContext);

      expect(request).toBe(mockRequest);
    });

    it('should fallback to HTTP request when no WebSocket data available', () => {
      const mockHttpRequest = { url: '/http-fallback', headers: {} };
      const mockContext = {
        getType: jest.fn().mockReturnValue('ws'),
        switchToWs: jest.fn().mockReturnValue({
          getData: jest.fn().mockReturnValue(undefined),
          getClient: jest.fn().mockReturnValue({}), // No handshake headers
        }),
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockHttpRequest),
        }),
      } as unknown as ExecutionContext;

      const request = getRequestFromContext(mockContext);

      expect(request).toBe(mockHttpRequest);
    });

    it('should fallback to HTTP for unknown context type', () => {
      const mockRequest = { url: '/test' };
      const mockContext = {
        getType: jest.fn().mockReturnValue('unknown'),
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(mockRequest),
        }),
      } as unknown as ExecutionContext;

      const request = getRequestFromContext(mockContext);

      expect(request).toBe(mockRequest);
    });
  });

  describe('Parameter Decorators - Factory Functions', () => {
    const createMockContext = (request: any): ExecutionContext =>
      ({
        getType: jest.fn().mockReturnValue('http'),
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(request),
        }),
      }) as unknown as ExecutionContext;

    describe('IsImpersonating', () => {
      it('should return true when request.isImpersonating is true', () => {
        const mockRequest = { isImpersonating: true };
        const mockContext = createMockContext(mockRequest);

        // Get the actual request from context and check isImpersonating
        const request = getRequestFromContext(mockContext);
        const result = request.isImpersonating ?? false;

        expect(result).toBe(true);
      });

      it('should return false when request.isImpersonating is undefined', () => {
        const mockRequest = {};
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.isImpersonating ?? false;

        expect(result).toBe(false);
      });

      it('should return false when request.isImpersonating is false', () => {
        const mockRequest = { isImpersonating: false };
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.isImpersonating ?? false;

        expect(result).toBe(false);
      });
    });

    describe('ImpersonatedBy', () => {
      it('should return admin ID when request.impersonatedBy is set', () => {
        const mockRequest = { impersonatedBy: 'admin-123' };
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.impersonatedBy ?? null;

        expect(result).toBe('admin-123');
      });

      it('should return null when request.impersonatedBy is undefined', () => {
        const mockRequest = {};
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.impersonatedBy ?? null;

        expect(result).toBeNull();
      });

      it('should return null when request.impersonatedBy is null', () => {
        const mockRequest = { impersonatedBy: null };
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.impersonatedBy ?? null;

        expect(result).toBeNull();
      });
    });

    describe('SessionProperty', () => {
      it('should return session property when session exists', () => {
        const mockRequest = {
          session: {
            id: 'session-123',
            expiresAt: new Date('2024-12-31'),
            token: 'token-abc',
          },
        };
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.session?.['id' as keyof typeof request.session];

        expect(result).toBe('session-123');
      });

      it('should return undefined when session is null', () => {
        const mockRequest = { session: null };
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result = request.session?.['id' as keyof typeof request.session];

        expect(result).toBeUndefined();
      });

      it('should return undefined when property does not exist', () => {
        const mockRequest = {
          session: { id: 'session-123' },
        };
        const mockContext = createMockContext(mockRequest);

        const request = getRequestFromContext(mockContext);
        const result =
          request.session?.['nonExistent' as keyof typeof request.session];

        expect(result).toBeUndefined();
      });
    });
  });

  describe('createAuthParamDecorator', () => {
    const createMockContext = (request: any): ExecutionContext =>
      ({
        getType: jest.fn().mockReturnValue('http'),
        switchToHttp: jest.fn().mockReturnValue({
          getRequest: jest.fn().mockReturnValue(request),
        }),
      }) as unknown as ExecutionContext;

    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      name: 'Test User',
      role: 'admin',
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const mockSession = {
      id: 'session-123',
      userId: 'user-123',
      token: 'token-abc',
      expiresAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const mockOrganization = {
      id: 'org-123',
      name: 'Test Org',
      slug: 'test-org',
      createdAt: new Date(),
    };

    const mockOrgMember = {
      id: 'member-123',
      userId: 'user-123',
      organizationId: 'org-123',
      role: 'owner',
      createdAt: new Date(),
    };

    const mockApiKey = {
      id: 'apikey-123',
      name: 'Test API Key',
      userId: 'user-123',
      permissions: { files: ['read', 'write'] },
      createdAt: new Date(),
    };

    describe('factory function', () => {
      it('should be a function', () => {
        expect(typeof createAuthParamDecorator).toBe('function');
      });

      it('should return a decorator factory', () => {
        const CustomContext = createAuthParamDecorator((auth) => ({
          userId: auth.user?.id ?? null,
        }));
        expect(typeof CustomContext).toBe('function');
      });
    });

    describe('AuthContext extraction', () => {
      it('should extract all auth properties from request', () => {
        const mockRequest = {
          session: { session: mockSession, user: mockUser },
          user: mockUser,
          organization: mockOrganization,
          organizationMember: mockOrgMember,
          isImpersonating: true,
          impersonatedBy: 'admin-456',
          apiKey: mockApiKey,
        };

        const ctx = createMockContext(mockRequest);
        const request = getRequestFromContext(ctx);

        expect(request.session).toEqual({
          session: mockSession,
          user: mockUser,
        });
        expect(request.user).toEqual(mockUser);
        expect(request.organization).toEqual(mockOrganization);
        expect(request.organizationMember).toEqual(mockOrgMember);
        expect(request.isImpersonating).toBe(true);
        expect(request.impersonatedBy).toBe('admin-456');
        expect(request.apiKey).toEqual(mockApiKey);
      });

      it('should handle null session', () => {
        const mockRequest = {
          session: null,
          user: null,
        };

        const ctx = createMockContext(mockRequest);
        const request = getRequestFromContext(ctx);

        expect(request.session).toBeNull();
        expect(request.user).toBeNull();
      });

      it('should handle missing optional properties', () => {
        const mockRequest = {
          session: { session: mockSession, user: mockUser },
          user: mockUser,
        };

        const ctx = createMockContext(mockRequest);
        const request = getRequestFromContext(ctx);

        expect(request.organization).toBeUndefined();
        expect(request.organizationMember).toBeUndefined();
        expect(request.apiKey).toBeUndefined();
        expect(request.isImpersonating).toBeUndefined();
        expect(request.impersonatedBy).toBeUndefined();
      });
    });

    describe('mapper function', () => {
      it('should map auth context to custom shape', () => {
        interface ConnectionContext {
          userId: string;
          isAdmin: boolean;
          organizationId: string | null;
          orgRole: string | null;
        }

        const ConnectionCtx = createAuthParamDecorator<ConnectionContext>(
          (auth: AuthContext) => ({
            userId: auth.user!.id,
            isAdmin: (auth.user as any)?.role === 'admin',
            organizationId: auth.organization?.id ?? null,
            orgRole: auth.orgMember?.role ?? null,
          }),
        );

        expect(ConnectionCtx).toBeDefined();
        expect(typeof ConnectionCtx).toBe('function');
      });

      it('should support returning primitive values', () => {
        const UserIdOnly = createAuthParamDecorator<string | null>(
          (auth) => auth.user?.id ?? null,
        );
        expect(UserIdOnly).toBeDefined();
      });

      it('should support returning boolean values', () => {
        const IsAuthenticated = createAuthParamDecorator<boolean>(
          (auth) => auth.session !== null,
        );
        expect(IsAuthenticated).toBeDefined();
      });

      it('should support returning arrays', () => {
        const UserRoles = createAuthParamDecorator<string[]>((auth) => {
          const roles: string[] = [];
          if (auth.user) {
            const userRole = (auth.user as any).role;
            if (userRole) roles.push(userRole);
          }
          if (auth.orgMember?.role) {
            roles.push(`org:${auth.orgMember.role}`);
          }
          return roles;
        });
        expect(UserRoles).toBeDefined();
      });
    });

    describe('null safety', () => {
      it('should provide default values for missing properties', () => {
        const SafeContext = createAuthParamDecorator((auth) => ({
          hasSession: auth.session !== null,
          hasUser: auth.user !== null,
          hasOrg: auth.organization !== null,
          hasOrgMember: auth.orgMember !== null,
          isImpersonating: auth.isImpersonating,
          hasApiKey: auth.apiKey !== null,
        }));

        expect(SafeContext).toBeDefined();
      });

      it('should handle partial org context', () => {
        const OrgContext = createAuthParamDecorator((auth) => ({
          orgId: auth.organization?.id ?? 'no-org',
          orgName: auth.organization?.name ?? 'Unknown',
          memberRole: auth.orgMember?.role ?? 'guest',
        }));

        expect(OrgContext).toBeDefined();
      });
    });

    describe('complex mapping logic', () => {
      it('should support conditional logic based on user role', () => {
        const PermissionContext = createAuthParamDecorator((auth) => {
          const permissions: string[] = ['read'];
          const userRole = (auth.user as any)?.role;

          if (userRole === 'admin') {
            permissions.push('write', 'delete', 'admin');
          } else if (userRole === 'moderator') {
            permissions.push('write');
          }

          return {
            userId: auth.user?.id ?? null,
            permissions,
            isAdmin: userRole === 'admin',
          };
        });

        expect(PermissionContext).toBeDefined();
      });

      it('should support combining multiple auth sources', () => {
        const CombinedContext = createAuthParamDecorator((auth) => ({
          userId: auth.user?.id ?? null,
          orgId: auth.organization?.id ?? null,
          apiKeyId: auth.apiKey?.id ?? null,
          authMethod: auth.apiKey
            ? 'apiKey'
            : auth.session
              ? 'session'
              : 'anonymous',
          impersonation: {
            active: auth.isImpersonating,
            by: auth.impersonatedBy,
          },
        }));

        expect(CombinedContext).toBeDefined();
      });

      it('should support deriving permissions from API key', () => {
        const ApiKeyContext = createAuthParamDecorator((auth) => {
          const apiKeyPerms = auth.apiKey?.permissions ?? {};
          return {
            keyId: auth.apiKey?.id ?? null,
            canReadFiles: apiKeyPerms['files']?.includes('read') ?? false,
            canWriteFiles: apiKeyPerms['files']?.includes('write') ?? false,
            allPermissions: apiKeyPerms,
          };
        });

        expect(ApiKeyContext).toBeDefined();
      });
    });

    describe('type inference', () => {
      it('should infer return type from mapper', () => {
        const TypedContext = createAuthParamDecorator((auth) => ({
          id: auth.user?.id ?? '',
          count: 42,
          active: true,
          tags: ['a', 'b'],
        }));

        expect(TypedContext).toBeDefined();
      });

      it('should support explicit generic type parameter', () => {
        interface StrictContext {
          userId: string;
          timestamp: number;
        }

        const StrictTypedContext = createAuthParamDecorator<StrictContext>(
          (auth) => ({
            userId: auth.user?.id ?? 'anonymous',
            timestamp: Date.now(),
          }),
        );

        expect(StrictTypedContext).toBeDefined();
      });
    });

    describe('real-world use cases', () => {
      it('should support multi-tenant context', () => {
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
            auth.orgMember?.role === 'owner' ||
            auth.orgMember?.role === 'admin',
        }));

        expect(TenantCtx).toBeDefined();
      });

      it('should support audit context', () => {
        interface AuditContext {
          actorId: string;
          actorType: 'user' | 'apiKey' | 'system';
          impersonatorId: string | null;
          organizationId: string | null;
        }

        const AuditCtx = createAuthParamDecorator<AuditContext>((auth) => ({
          actorId: auth.apiKey?.userId ?? auth.user?.id ?? 'system',
          actorType: auth.apiKey ? 'apiKey' : auth.user ? 'user' : 'system',
          impersonatorId: auth.impersonatedBy,
          organizationId: auth.organization?.id ?? null,
        }));

        expect(AuditCtx).toBeDefined();
      });

      it('should support service layer context', () => {
        interface ServiceContext {
          requesterId: string;
          requesterEmail: string | null;
          scope: {
            orgId: string | null;
            role: string;
            permissions: string[];
          };
        }

        const ServiceCtx = createAuthParamDecorator<ServiceContext>((auth) => {
          const basePermissions = ['read'];
          if ((auth.user as any)?.role === 'admin') {
            basePermissions.push('write', 'delete');
          }

          return {
            requesterId: auth.user?.id ?? 'anonymous',
            requesterEmail: auth.user?.email ?? null,
            scope: {
              orgId: auth.organization?.id ?? null,
              role: auth.orgMember?.role ?? 'none',
              permissions: basePermissions,
            },
          };
        });

        expect(ServiceCtx).toBeDefined();
      });
    });
  });

  describe('Parameter Decorators Execution', () => {
    // Type for param decorator factories
    type ParamDecoratorFactory = (...args: any[]) => ParameterDecorator;

    // Helper to extract the factory function from a param decorator
    function getParamDecoratorFactory(decorator: ParamDecoratorFactory) {
      class TestClass {
        testMethod(@decorator() _param: any) {}
      }
      const metadata = Reflect.getMetadata(
        ROUTE_ARGS_METADATA,
        TestClass,
        'testMethod',
      );
      const key = Object.keys(metadata)[0];
      return metadata[key].factory;
    }

    // Helper to extract factory with data parameter
    function getParamDecoratorFactoryWithData(
      decorator: ParamDecoratorFactory,
      data: string,
    ) {
      class TestClass {
        testMethod(@decorator(data) _param: any) {}
      }
      const metadata = Reflect.getMetadata(
        ROUTE_ARGS_METADATA,
        TestClass,
        'testMethod',
      );
      const key = Object.keys(metadata)[0];
      return metadata[key];
    }

    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      name: 'Test User',
      role: 'admin',
      emailVerified: true,
    };

    const mockSessionData = {
      id: 'session-456',
      userId: 'user-123',
      createdAt: '2025-01-01T00:00:00Z',
      expiresAt: '2025-01-08T00:00:00Z',
    };

    const mockOrganization = {
      id: 'org-789',
      name: 'Test Org',
      slug: 'test-org',
    };

    const mockOrgMember = {
      id: 'member-001',
      organizationId: 'org-789',
      userId: 'user-123',
      role: 'owner',
    };

    const mockApiKey = {
      id: 'apikey-111',
      name: 'Test Key',
      userId: 'user-123',
      permissions: { files: ['read', 'write'] },
    };

    function createMockExecutionContext(requestData: any): ExecutionContext {
      return {
        switchToHttp: () => ({
          getRequest: () => requestData,
          getResponse: () => ({}),
          getNext: () => () => {},
        }),
        getType: () => 'http',
        getClass: () => class {},
        getHandler: () => () => {},
        getArgs: () => [requestData, {}, () => {}],
        getArgByIndex: (index: number) => [requestData, {}, () => {}][index],
        switchToRpc: () => ({
          getData: () => ({}),
          getContext: () => ({}),
        }),
        switchToWs: () => ({
          getData: () => ({}),
          getClient: () => ({}),
        }),
      } as ExecutionContext;
    }

    describe('@Session()', () => {
      it('should return full session object', () => {
        const factory = getParamDecoratorFactory(Session);
        const mockRequest = {
          session: { session: mockSessionData, user: mockUser },
          user: mockUser,
        };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toEqual({ session: mockSessionData, user: mockUser });
      });

      it('should return undefined when no session', () => {
        const factory = getParamDecoratorFactory(Session);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBeUndefined();
      });
    });

    describe('@SessionProperty()', () => {
      it('should return specific session property', () => {
        const metadata = getParamDecoratorFactoryWithData(
          SessionProperty,
          'id',
        );
        const mockRequest = {
          session: { session: mockSessionData, user: mockUser },
        };
        const ctx = createMockExecutionContext(mockRequest);
        const result = metadata.factory('id', ctx);
        expect(result).toBe('session-456');
      });

      it('should return undefined for missing property', () => {
        const metadata = getParamDecoratorFactoryWithData(
          SessionProperty,
          'nonexistent',
        );
        const mockRequest = {
          session: { session: mockSessionData, user: mockUser },
        };
        const ctx = createMockExecutionContext(mockRequest);
        const result = metadata.factory('nonexistent', ctx);
        expect(result).toBeUndefined();
      });
    });

    describe('@CurrentUser()', () => {
      it('should return user object', () => {
        const factory = getParamDecoratorFactory(CurrentUser);
        const mockRequest = { user: mockUser };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toEqual(mockUser);
      });

      it('should return undefined when no user', () => {
        const factory = getParamDecoratorFactory(CurrentUser);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBeUndefined();
      });
    });

    describe('@UserProperty()', () => {
      it('should return specific user property', () => {
        const metadata = getParamDecoratorFactoryWithData(
          UserProperty,
          'email',
        );
        const mockRequest = { user: mockUser };
        const ctx = createMockExecutionContext(mockRequest);
        const result = metadata.factory('email', ctx);
        expect(result).toBe('test@example.com');
      });

      it('should return role property', () => {
        const metadata = getParamDecoratorFactoryWithData(UserProperty, 'role');
        const mockRequest = { user: mockUser };
        const ctx = createMockExecutionContext(mockRequest);
        const result = metadata.factory('role', ctx);
        expect(result).toBe('admin');
      });
    });

    describe('@CurrentOrg()', () => {
      it('should return organization object', () => {
        const factory = getParamDecoratorFactory(CurrentOrg);
        const mockRequest = { organization: mockOrganization };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toEqual(mockOrganization);
      });

      it('should return undefined when no organization', () => {
        const factory = getParamDecoratorFactory(CurrentOrg);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBeUndefined();
      });
    });

    describe('@OrgMember()', () => {
      it('should return organization member object', () => {
        const factory = getParamDecoratorFactory(OrgMember);
        const mockRequest = { organizationMember: mockOrgMember };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toEqual(mockOrgMember);
      });

      it('should return undefined when no org member', () => {
        const factory = getParamDecoratorFactory(OrgMember);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBeUndefined();
      });
    });

    describe('@IsImpersonating()', () => {
      it('should return true when impersonating', () => {
        const factory = getParamDecoratorFactory(IsImpersonating);
        const mockRequest = { isImpersonating: true };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBe(true);
      });

      it('should return false when not impersonating', () => {
        const factory = getParamDecoratorFactory(IsImpersonating);
        const mockRequest = { isImpersonating: false };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBe(false);
      });

      it('should return false when property is undefined', () => {
        const factory = getParamDecoratorFactory(IsImpersonating);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBe(false);
      });
    });

    describe('@ImpersonatedBy()', () => {
      it('should return impersonator ID', () => {
        const factory = getParamDecoratorFactory(ImpersonatedBy);
        const mockRequest = { impersonatedBy: 'admin-user-id' };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBe('admin-user-id');
      });

      it('should return null when not impersonated', () => {
        const factory = getParamDecoratorFactory(ImpersonatedBy);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBeNull();
      });
    });

    describe('@ApiKey()', () => {
      it('should return API key object', () => {
        const factory = getParamDecoratorFactory(ApiKey);
        const mockRequest = { apiKey: mockApiKey };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toEqual(mockApiKey);
      });

      it('should return undefined when no API key', () => {
        const factory = getParamDecoratorFactory(ApiKey);
        const mockRequest = {};
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);
        expect(result).toBeUndefined();
      });
    });

    describe('createAuthParamDecorator execution', () => {
      it('should execute mapper with full auth context', () => {
        const CustomDecorator = createAuthParamDecorator(
          (auth: AuthContext) => ({
            userId: auth.user?.id ?? 'none',
            orgId: auth.organization?.id ?? 'none',
            isAdmin: (auth.user as any)?.role === 'admin',
          }),
        );

        const factory = getParamDecoratorFactory(CustomDecorator);
        const mockRequest = {
          session: { session: mockSessionData, user: mockUser },
          user: mockUser,
          organization: mockOrganization,
          organizationMember: mockOrgMember,
          isImpersonating: false,
          impersonatedBy: null,
          apiKey: null,
        };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);

        expect(result).toEqual({
          userId: 'user-123',
          orgId: 'org-789',
          isAdmin: true,
        });
      });

      it('should handle missing optional fields with defaults', () => {
        const SafeDecorator = createAuthParamDecorator((auth: AuthContext) => ({
          hasSession: auth.session !== null && auth.session !== undefined,
          hasOrg: auth.organization !== null,
          isImpersonating: auth.isImpersonating,
          hasApiKey: auth.apiKey !== null,
        }));

        const factory = getParamDecoratorFactory(SafeDecorator);
        const mockRequest = {
          session: null,
          user: null,
        };
        const ctx = createMockExecutionContext(mockRequest);
        const result = factory(undefined, ctx);

        expect(result).toEqual({
          hasSession: false,
          hasOrg: false,
          isImpersonating: false,
          hasApiKey: false,
        });
      });
    });
  });
});
