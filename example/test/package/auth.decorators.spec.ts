import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import {
  AllowAnonymous,
  OptionalAuth,
  Roles,
  Permissions,
  RequireFreshSession,
  AdminOnly,
  BanCheck,
  DisallowImpersonation,
  BearerAuth,
  ApiKeyAuth,
  OrgRequired,
  OrgRoles,
  OrgPermission,
  SecureAdminOnly,
  Hook,
  BeforeHook,
  AfterHook,
  Public,
  Optional,
  getRequestFromContext,
  ALLOW_ANONYMOUS_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  BEARER_AUTH_KEY,
  API_KEY_AUTH_KEY,
  DISALLOW_IMPERSONATION_KEY,
  ORG_REQUIRED_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  HOOK_KEY,
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
} from '@sapix/nestjs-better-auth-fastify';

describe('auth.decorators', () => {
  describe('Metadata Keys', () => {
    it('should export all metadata keys', () => {
      expect(ALLOW_ANONYMOUS_KEY).toBe('auth:allowAnonymous');
      expect(OPTIONAL_AUTH_KEY).toBe('auth:optional');
      expect(ROLES_KEY).toBe('auth:roles');
      expect(PERMISSIONS_KEY).toBe('auth:permissions');
      expect(FRESH_SESSION_KEY).toBe('auth:freshSession');
      expect(ADMIN_ONLY_KEY).toBe('auth:adminOnly');
      expect(BAN_CHECK_KEY).toBe('auth:banCheck');
      expect(BEARER_AUTH_KEY).toBe('auth:bearerAuth');
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

      @BearerAuth()
      bearerAuthMethod() {}

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
    let controller: TestController;

    beforeEach(() => {
      reflector = new Reflector();
      controller = new TestController();
    });

    it('@AllowAnonymous should set metadata to true', () => {
      const metadata = reflector.get(
        ALLOW_ANONYMOUS_KEY,
        controller.allowAnonymousMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@OptionalAuth should set metadata to true', () => {
      const metadata = reflector.get(
        OPTIONAL_AUTH_KEY,
        controller.optionalAuthMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@Roles should set roles metadata with default options', () => {
      const metadata = reflector.get(ROLES_KEY, controller.rolesMethod);
      expect(metadata).toEqual({
        roles: ['admin', 'moderator'],
        options: { mode: 'any' },
      });
    });

    it('@Roles should set roles metadata with custom options', () => {
      const metadata = reflector.get(ROLES_KEY, controller.rolesAllModeMethod);
      expect(metadata).toEqual({
        roles: ['admin', 'verified'],
        options: { mode: 'all', message: 'Custom message' },
      });
    });

    it('@Permissions should set permissions metadata with default options', () => {
      const metadata = reflector.get(
        PERMISSIONS_KEY,
        controller.permissionsMethod,
      );
      expect(metadata).toEqual({
        permissions: ['user:read', 'user:write'],
        options: { mode: 'any' },
      });
    });

    it('@Permissions should set permissions metadata with custom options', () => {
      const metadata = reflector.get(
        PERMISSIONS_KEY,
        controller.permissionsAllModeMethod,
      );
      expect(metadata).toEqual({
        permissions: ['read', 'write'],
        options: { mode: 'all' },
      });
    });

    it('@RequireFreshSession should set metadata with default options', () => {
      const metadata = reflector.get(
        FRESH_SESSION_KEY,
        controller.freshSessionMethod,
      );
      expect(metadata).toEqual({ options: {} });
    });

    it('@RequireFreshSession should set metadata with custom options', () => {
      const metadata = reflector.get(
        FRESH_SESSION_KEY,
        controller.freshSessionCustomMethod,
      );
      expect(metadata).toEqual({
        options: { maxAge: 300, message: 'Re-auth required' },
      });
    });

    it('@AdminOnly should set metadata', () => {
      const metadata = reflector.get(
        ADMIN_ONLY_KEY,
        controller.adminOnlyMethod,
      );
      expect(metadata).toEqual({ message: undefined });
    });

    it('@AdminOnly should set metadata with custom message', () => {
      const metadata = reflector.get(
        ADMIN_ONLY_KEY,
        controller.adminOnlyCustomMethod,
      );
      expect(metadata).toEqual({ message: 'Custom admin message' });
    });

    it('@BanCheck should set metadata to true', () => {
      const metadata = reflector.get(BAN_CHECK_KEY, controller.banCheckMethod);
      expect(metadata).toBe(true);
    });

    it('@DisallowImpersonation should set metadata', () => {
      const metadata = reflector.get(
        DISALLOW_IMPERSONATION_KEY,
        controller.disallowImpersonationMethod,
      );
      expect(metadata).toEqual({ message: undefined });
    });

    it('@DisallowImpersonation should set metadata with custom message', () => {
      const metadata = reflector.get(
        DISALLOW_IMPERSONATION_KEY,
        controller.disallowImpersonationCustomMethod,
      );
      expect(metadata).toEqual({ message: 'No impersonation allowed' });
    });

    it('@BearerAuth should set metadata to true', () => {
      const metadata = reflector.get(
        BEARER_AUTH_KEY,
        controller.bearerAuthMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@ApiKeyAuth should set metadata with default options', () => {
      const metadata = reflector.get(
        API_KEY_AUTH_KEY,
        controller.apiKeyAuthMethod,
      );
      expect(metadata).toEqual({});
    });

    it('@ApiKeyAuth should set metadata with allowSession option', () => {
      const metadata = reflector.get(
        API_KEY_AUTH_KEY,
        controller.apiKeyAuthWithSessionMethod,
      );
      expect(metadata).toEqual({ allowSession: true });
    });

    it('@ApiKeyAuth should set metadata with permissions option', () => {
      const metadata = reflector.get(
        API_KEY_AUTH_KEY,
        controller.apiKeyAuthWithPermissionsMethod,
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
        controller.orgRequiredMethod,
      );
      expect(metadata).toBe(true);
    });

    it('@OrgRoles should set metadata with default options', () => {
      const metadata = reflector.get(ORG_ROLES_KEY, controller.orgRolesMethod);
      expect(metadata).toEqual({
        roles: ['owner', 'admin'],
        options: { mode: 'any' },
      });
    });

    it('@OrgRoles should set metadata with custom options', () => {
      const metadata = reflector.get(
        ORG_ROLES_KEY,
        controller.orgRolesAllModeMethod,
      );
      expect(metadata).toEqual({
        roles: ['admin', 'billing'],
        options: { mode: 'all' },
      });
    });

    it('@OrgPermission should set metadata', () => {
      const metadata = reflector.get(
        ORG_PERMISSIONS_KEY,
        controller.orgPermissionMethod,
      );
      expect(metadata).toEqual({
        options: { resource: 'member', action: 'create' },
      });
    });

    it('@SecureAdminOnly should apply multiple decorators', () => {
      const adminOnly = reflector.get(
        ADMIN_ONLY_KEY,
        controller.secureAdminOnlyMethod,
      );
      const freshSession = reflector.get(
        FRESH_SESSION_KEY,
        controller.secureAdminOnlyMethod,
      );
      const disallowImpersonation = reflector.get(
        DISALLOW_IMPERSONATION_KEY,
        controller.secureAdminOnlyMethod,
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

  describe('Deprecated Aliases', () => {
    it('Public should be an alias for AllowAnonymous', () => {
      expect(Public).toBe(AllowAnonymous);
    });

    it('Optional should be an alias for OptionalAuth', () => {
      expect(Optional).toBe(OptionalAuth);
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

    // Helper to get the factory function from a param decorator
    const getDecoratorFactory = (decorator: any) => {
      const metadata = Reflect.getMetadata('custom:paramtype', decorator);
      return (
        decorator.factory ||
        (() => {
          // For createParamDecorator, the factory is stored differently
          // We need to call the decorator to get the factory
          const testTarget = {};
          const testKey = 'testMethod';
          decorator(testTarget, testKey, 0);
          return Reflect.getMetadata(
            'self:paramtypes',
            testTarget,
            testKey,
          )?.[0];
        })
      );
    };

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
  });
});
