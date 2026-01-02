import { Test, TestingModule } from '@nestjs/testing';
import { Reflector } from '@nestjs/core';
import {
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { AuthGuard, AUTH_MODULE_OPTIONS } from 'nestjs-better-auth-fastify';
import type { FastifyRequest } from 'fastify';

// FastifyRequest is already extended by the main package (auth.types.ts)
// with organization and organizationMember properties

describe('AuthGuard', () => {
  let guard: AuthGuard;
  let reflector: Reflector;
  let mockAuth: any;
  let mockRequest: Partial<FastifyRequest>;

  const createMockContext = (
    request: Partial<FastifyRequest> = mockRequest,
    type: string = 'http',
  ): ExecutionContext => {
    return {
      getType: jest.fn().mockReturnValue(type),
      getHandler: jest.fn().mockReturnValue(() => {}),
      getClass: jest.fn().mockReturnValue(class {}),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue(request),
      }),
      switchToWs: jest.fn().mockReturnValue({
        getClient: jest.fn().mockReturnValue(request),
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(async () => {
    mockAuth = {
      api: {
        getSession: jest.fn(),
        verifyApiKey: jest.fn(),
      },
      options: {
        session: {
          freshAge: 86400,
        },
      },
    };

    mockRequest = {
      headers: {
        cookie: 'session=test',
      },
      session: null,
      user: null,
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthGuard,
        Reflector,
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: { auth: mockAuth },
        },
      ],
    }).compile();

    guard = module.get<AuthGuard>(AuthGuard);
    reflector = module.get<Reflector>(Reflector);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Basic Authentication', () => {
    it('should allow access when @AllowAnonymous is set', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:allowAnonymous') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when no session and no @AllowAnonymous', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
      mockAuth.api.getSession.mockResolvedValue(null);

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should allow access with valid session', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', email: 'test@example.com' },
      });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(mockRequest.session).not.toBeNull();
      expect(mockRequest.user).not.toBeNull();
    });

    it('should allow access with @OptionalAuth when no session', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:optional') return true;
          return undefined;
        });
      mockAuth.api.getSession.mockResolvedValue(null);

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('Role-based Authorization', () => {
    beforeEach(() => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', email: 'test@example.com', role: 'admin' },
      });
    });

    it('should allow access when user has required role (any mode)', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:roles') {
            return {
              roles: ['admin', 'moderator'],
              options: { mode: 'any' },
            };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when user lacks required role', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', email: 'test@example.com', role: 'user' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:roles') {
            return {
              roles: ['admin'],
              options: { mode: 'any' },
            };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it("should check all roles in 'all' mode", async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'admin,verified' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:roles') {
            return {
              roles: ['admin', 'verified'],
              options: { mode: 'all' },
            };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('Permission-based Authorization', () => {
    it('should allow access when user has required permission', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['user:read', 'user:write'] },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:permissions') {
            return {
              permissions: ['user:read'],
              options: { mode: 'any' },
            };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when user lacks required permission', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['user:read'] },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:permissions') {
            return {
              permissions: ['admin:access'],
              options: { mode: 'any' },
            };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('Admin Only', () => {
    it('should allow access for admin users', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'admin' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:adminOnly') return { message: undefined };
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access for non-admin users', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'user' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:adminOnly') return { message: 'Admin required' };
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('Session Freshness', () => {
    it('should allow access for fresh session', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:freshSession') {
            return { options: { maxAge: 3600 } };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access for stale session', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 2);

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: oldDate },
        user: { id: 'user-1' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:freshSession') {
            return { options: { maxAge: 3600 } };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow();
    });
  });

  describe('Ban Check', () => {
    it('should allow access for non-banned users', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', banned: false },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:banCheck') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access for banned users', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: {
          id: 'user-1',
          banned: true,
          banReason: 'Violation',
          banExpires: null,
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:banCheck') return true;
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should allow access if ban has expired', async () => {
      const expiredDate = new Date();
      expiredDate.setDate(expiredDate.getDate() - 1);

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: {
          id: 'user-1',
          banned: true,
          banExpires: expiredDate.toISOString(),
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:banCheck') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('Impersonation', () => {
    it('should detect impersonation', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: {
          id: 'sess-1',
          createdAt: new Date(),
          impersonatedBy: 'admin-1',
        },
        user: { id: 'user-1' },
      });

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext();
      await guard.canActivate(context);

      expect(mockRequest.isImpersonating).toBe(true);
      expect(mockRequest.impersonatedBy).toBe('admin-1');
    });

    it('should deny access when @DisallowImpersonation and impersonating', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: {
          id: 'sess-1',
          createdAt: new Date(),
          impersonatedBy: 'admin-1',
        },
        user: { id: 'user-1' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:disallowImpersonation')
            return { message: undefined };
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('API Key Authentication', () => {
    it('should authenticate with valid API key', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-api-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: {
          id: 'key-1',
          userId: 'user-1',
          permissions: { files: ['read'] },
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return {};
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(mockApiKeyRequest.apiKey).toBeDefined();
    });

    it('should reject invalid API key when session not allowed', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'invalid-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: false,
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return { allowSession: false };
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);

      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should check API key permissions', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-api-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: {
          id: 'key-1',
          permissions: { files: ['read'] },
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') {
            return {
              permissions: {
                permissions: { files: ['write'] },
                message: 'Need write permission',
              },
            };
          }
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });

  describe('Bearer Token Authentication', () => {
    it('should authenticate with Bearer token when enabled', async () => {
      const mockBearerRequest = {
        ...mockRequest,
        headers: {
          authorization: 'Bearer test-token',
        },
      } as any;

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:bearerAuth') return true;
          return undefined;
        });

      const context = createMockContext(mockBearerRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('Context Types', () => {
    beforeEach(() => {
      mockAuth.api.getSession.mockResolvedValue(null);
    });

    it('should handle HTTP context', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext(mockRequest, 'http');

      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should handle WebSocket context', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext(mockRequest, 'ws');

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it('should handle GraphQL context', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext(mockRequest, 'graphql');

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it('should handle RPC context', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext(mockRequest, 'rpc');

      await expect(guard.canActivate(context)).rejects.toThrow();
    });
  });

  describe('Error Types for Different Contexts', () => {
    describe('HTTP Context Errors', () => {
      it('should throw ForbiddenException for banned user', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', banned: true },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:banCheck') return true;
            return undefined;
          });

        const context = createMockContext(mockRequest, 'http');

        await expect(guard.canActivate(context)).rejects.toThrow(
          ForbiddenException,
        );
      });
    });

    describe('GraphQL Context Errors', () => {
      it('should throw GraphQL error for unauthorized in graphql context', async () => {
        mockAuth.api.getSession.mockResolvedValue(null);
        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

        const context = createMockContext(mockRequest, 'graphql');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should throw GraphQL error for forbidden in graphql context', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', role: 'user' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:adminOnly') return { message: 'Admin required' };
            return undefined;
          });

        const context = createMockContext(mockRequest, 'graphql');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should throw GraphQL error for banned user in graphql context', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', banned: true, banReason: 'Spam' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:banCheck') return true;
            return undefined;
          });

        const context = createMockContext(mockRequest, 'graphql');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should throw GraphQL error for stale session in graphql context', async () => {
        const oldDate = new Date();
        oldDate.setDate(oldDate.getDate() - 2);

        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: oldDate },
          user: { id: 'user-1' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:freshSession') {
              return { options: { maxAge: 3600 } };
            }
            return undefined;
          });

        const context = createMockContext(mockRequest, 'graphql');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });
    });

    describe('RPC Context Errors', () => {
      it('should throw Error for unauthorized in rpc context', async () => {
        mockAuth.api.getSession.mockResolvedValue(null);
        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

        const context = createMockContext(mockRequest, 'rpc');

        await expect(guard.canActivate(context)).rejects.toThrow(Error);
      });

      it('should throw Error for forbidden in rpc context', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', role: 'user' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:adminOnly') return { message: 'Admin required' };
            return undefined;
          });

        const context = createMockContext(mockRequest, 'rpc');

        await expect(guard.canActivate(context)).rejects.toThrow(Error);
      });

      it('should throw Error for banned user in rpc context', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', banned: true },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:banCheck') return true;
            return undefined;
          });

        const context = createMockContext(mockRequest, 'rpc');

        await expect(guard.canActivate(context)).rejects.toThrow(Error);
      });

      it('should throw Error for stale session in rpc context', async () => {
        const oldDate = new Date();
        oldDate.setDate(oldDate.getDate() - 2);

        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: oldDate },
          user: { id: 'user-1' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:freshSession') {
              return { options: { maxAge: 3600 } };
            }
            return undefined;
          });

        const context = createMockContext(mockRequest, 'rpc');

        await expect(guard.canActivate(context)).rejects.toThrow(Error);
      });
    });

    describe('WebSocket Context Errors', () => {
      it('should throw WsException for forbidden in ws context', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', role: 'user' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:adminOnly') return { message: 'Admin required' };
            return undefined;
          });

        const context = createMockContext(mockRequest, 'ws');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should throw WsException for banned user in ws context', async () => {
        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: new Date() },
          user: { id: 'user-1', banned: true },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:banCheck') return true;
            return undefined;
          });

        const context = createMockContext(mockRequest, 'ws');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });

      it('should throw WsException for stale session in ws context', async () => {
        const oldDate = new Date();
        oldDate.setDate(oldDate.getDate() - 2);

        mockAuth.api.getSession.mockResolvedValue({
          session: { id: 'sess-1', createdAt: oldDate },
          user: { id: 'user-1' },
        });

        jest
          .spyOn(reflector, 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:freshSession') {
              return { options: { maxAge: 3600 } };
            }
            return undefined;
          });

        const context = createMockContext(mockRequest, 'ws');

        await expect(guard.canActivate(context)).rejects.toThrow();
      });
    });
  });

  describe('API Key Edge Cases', () => {
    it('should handle API key from Authorization header', async () => {
      // Use API key format that matches default pattern: prefix_randomString
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          authorization: 'Bearer test_abc123XYZ',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: { id: 'key-1', permissions: {} },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return {};
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should handle API key from api-key header', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'api-key': 'api-key-123',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: { id: 'key-1', permissions: {} },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return {};
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should return null when no API key provided', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {},
      } as any;

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return { allowSession: true };
          return undefined;
        });

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should handle API key verification failure gracefully', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockRejectedValue(
        new Error('Verification failed'),
      );

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return { allowSession: true };
          return undefined;
        });

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should return null when verifyApiKey is not available', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-key',
        },
      } as any;

      delete mockAuth.api.verifyApiKey;

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') return { allowSession: true };
          return undefined;
        });

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('Session Handling Edge Cases', () => {
    it('should handle getSession error gracefully', async () => {
      mockAuth.api.getSession.mockRejectedValue(new Error('Network error'));

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:optional') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should handle impersonation session data', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: {
          id: 'sess-1',
          createdAt: new Date(),
          impersonatedBy: 'admin-1',
        },
        user: { id: 'user-1' },
      });

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(mockRequest.isImpersonating).toBe(true);
      expect(mockRequest.impersonatedBy).toBe('admin-1');
    });

    it('should attach session with impersonation for optional auth', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: {
          id: 'sess-1',
          createdAt: new Date(),
          impersonatedBy: 'admin-1',
        },
        user: { id: 'user-1' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:optional') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(mockRequest.isImpersonating).toBe(true);
      expect(mockRequest.impersonatedBy).toBe('admin-1');
    });

    it('should attach session without impersonation for optional auth', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:optional') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(mockRequest.session).toBeDefined();
      expect(mockRequest.user).toBeDefined();
    });
  });

  describe('API Key Permission Checks', () => {
    it('should reject API key with missing required resource permissions', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: {
          id: 'key-1',
          permissions: { users: ['read'] }, // Only has users:read
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') {
            return {
              permissions: {
                permissions: { files: ['read', 'write'] }, // Requires files:read,write
                message: 'Needs files permissions',
              },
            };
          }
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it('should reject API key with missing required action permissions', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: {
          id: 'key-1',
          permissions: { files: ['read'] }, // Only has files:read
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') {
            return {
              permissions: {
                permissions: { files: ['read', 'write'] }, // Requires files:read,write
                message: 'Needs files:write permission',
              },
            };
          }
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it('should accept API key with all required permissions', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: {
          id: 'key-1',
          permissions: { files: ['read', 'write', 'delete'] },
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') {
            return {
              permissions: {
                permissions: { files: ['read', 'write'] },
              },
            };
          }
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should reject API key with undefined permissions', async () => {
      const mockApiKeyRequest = {
        ...mockRequest,
        headers: {
          'x-api-key': 'test-key',
        },
      } as any;

      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: {
          id: 'key-1',
          // No permissions defined
        },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:apiKeyAuth') {
            return {
              permissions: {
                permissions: { files: ['read'] },
                message: 'Needs permissions',
              },
            };
          }
          return undefined;
        });

      const context = createMockContext(mockApiKeyRequest);

      await expect(guard.canActivate(context)).rejects.toThrow();
    });
  });

  describe('Session Expiration', () => {
    it('should deny access for expired session', async () => {
      const expiredDate = new Date();
      expiredDate.setDate(expiredDate.getDate() - 1);

      mockAuth.api.getSession.mockResolvedValue({
        session: {
          id: 'sess-1',
          createdAt: new Date(),
          expiresAt: expiredDate,
        },
        user: { id: 'user-1' },
      });

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should allow access for non-expired session', async () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 1);

      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date(), expiresAt: futureDate },
        user: { id: 'user-1' },
      });

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should allow access when session has no expiration', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });
  });

  describe('Role and Permission Edge Cases', () => {
    it('should reject when user has no role defined', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' }, // No role property
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:roles') {
            return { roles: ['admin'], options: { mode: 'any' } };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it('should reject when user has no permissions defined', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' }, // No permissions property
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:permissions') {
            return { permissions: ['read:users'], options: { mode: 'any' } };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it("should check permissions with mode 'all'", async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['read:users', 'write:users'] },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:permissions') {
            return {
              permissions: ['read:users', 'write:users'],
              options: { mode: 'all' },
            };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it("should reject when user missing some permissions in mode 'all'", async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['read:users'] }, // Missing write:users
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:permissions') {
            return {
              permissions: ['read:users', 'write:users'],
              options: { mode: 'all' },
            };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow();
    });
  });

  describe('Lazy Loading Edge Cases', () => {
    it('should handle GraphQL error factory with string args', async () => {
      mockAuth.api.getSession.mockResolvedValue(null);

      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const context = createMockContext(mockRequest, 'graphql');

      await expect(guard.canActivate(context)).rejects.toThrow();
    });

    it('should handle GraphQL error factory with object args', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'user' },
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:adminOnly') {
            return { message: { extensions: { code: 'FORBIDDEN' } } };
          }
          return undefined;
        });

      const context = createMockContext(mockRequest, 'graphql');

      await expect(guard.canActivate(context)).rejects.toThrow();
    });
  });

  describe('Custom Configuration Options', () => {
    describe('skipSessionExpirationCheck', () => {
      it('should allow expired session when skipSessionExpirationCheck is true', async () => {
        const expiredDate = new Date();
        expiredDate.setDate(expiredDate.getDate() - 1);

        mockAuth.api.getSession.mockResolvedValue({
          session: {
            id: 'sess-1',
            createdAt: new Date(),
            expiresAt: expiredDate,
          },
          user: { id: 'user-1' },
        });

        jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

        // Create guard with skipSessionExpirationCheck
        const moduleWithSkip: TestingModule = await Test.createTestingModule({
          providers: [
            AuthGuard,
            Reflector,
            {
              provide: AUTH_MODULE_OPTIONS,
              useValue: {
                auth: mockAuth,
                skipSessionExpirationCheck: true,
              },
            },
          ],
        }).compile();

        const guardWithSkip = moduleWithSkip.get<AuthGuard>(AuthGuard);
        const context = createMockContext();
        const result = await guardWithSkip.canActivate(context);

        expect(result).toBe(true);
      });
    });

    describe('apiKeyPattern', () => {
      it('should use custom apiKeyPattern for API key detection', async () => {
        const mockApiKeyRequest = {
          ...mockRequest,
          headers: {
            authorization: 'Bearer sk-custom-api-key-12345',
          },
        } as any;

        mockAuth.api.verifyApiKey.mockResolvedValue({
          valid: true,
          key: { id: 'key-1', permissions: {} },
        });

        // Create guard with custom apiKeyPattern
        const moduleWithPattern: TestingModule = await Test.createTestingModule(
          {
            providers: [
              AuthGuard,
              Reflector,
              {
                provide: AUTH_MODULE_OPTIONS,
                useValue: {
                  auth: mockAuth,
                  apiKeyPattern: /^sk-[a-z-]+-[0-9]+$/,
                },
              },
            ],
          },
        ).compile();

        const guardWithPattern = moduleWithPattern.get<AuthGuard>(AuthGuard);
        jest
          .spyOn(moduleWithPattern.get(Reflector), 'getAllAndOverride')
          .mockImplementation((key: any) => {
            if (key === 'auth:apiKeyAuth') return {};
            return undefined;
          });

        const context = createMockContext(mockApiKeyRequest);
        const result = await guardWithPattern.canActivate(context);

        expect(result).toBe(true);
      });
    });
  });

  describe('Organization Checks', () => {
    beforeEach(() => {
      mockAuth.api.getSession.mockResolvedValue({
        session: {
          id: 'sess-1',
          createdAt: new Date(),
          activeOrganizationId: 'org-1',
        },
        user: { id: 'user-1' },
      });

      // Mock getFullOrganization API
      mockAuth.api.getFullOrganization = jest.fn().mockResolvedValue({
        organization: { id: 'org-1', name: 'Test Org' },
        members: [
          {
            userId: 'user-1',
            role: 'admin',
            id: 'member-1',
            organizationId: 'org-1',
          },
        ],
      });
    });

    it('should allow access when @OrgRequired and user has active org', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:orgRequired') return true;
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
      expect(mockRequest.organization).toBeDefined();
      expect(mockRequest.organizationMember).toBeDefined();
    });

    it('should deny access when @OrgRequired and user has no active org', async () => {
      mockAuth.api.getSession.mockResolvedValue({
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      });

      mockAuth.api.getFullOrganization = undefined;

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:orgRequired') return true;
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should allow access when @OrgRoles matches user role', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:orgRoles') {
            return { roles: ['admin', 'owner'], options: { mode: 'any' } };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when @OrgRoles does not match user role', async () => {
      mockAuth.api.getFullOrganization.mockResolvedValue({
        organization: { id: 'org-1', name: 'Test Org' },
        members: [
          {
            userId: 'user-1',
            role: 'member',
            id: 'member-1',
            organizationId: 'org-1',
          },
        ],
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:orgRoles') {
            return { roles: ['owner'], options: { mode: 'any' } };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should allow access when @OrgPermission matches', async () => {
      mockAuth.api.getFullOrganization.mockResolvedValue({
        organization: { id: 'org-1', name: 'Test Org' },
        members: [
          {
            userId: 'user-1',
            role: 'owner',
            id: 'member-1',
            organizationId: 'org-1',
          },
        ],
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:orgPermissions') {
            return { options: { resource: 'member', action: 'create' } };
          }
          return undefined;
        });

      const context = createMockContext();
      const result = await guard.canActivate(context);

      expect(result).toBe(true);
    });

    it('should deny access when @OrgPermission does not match', async () => {
      mockAuth.api.getFullOrganization.mockResolvedValue({
        organization: { id: 'org-1', name: 'Test Org' },
        members: [
          {
            userId: 'user-1',
            role: 'member',
            id: 'member-1',
            organizationId: 'org-1',
          },
        ],
      });

      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockImplementation((key: any) => {
          if (key === 'auth:orgPermissions') {
            return { options: { resource: 'invitation', action: 'create' } };
          }
          return undefined;
        });

      const context = createMockContext();

      await expect(guard.canActivate(context)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });
});
