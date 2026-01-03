import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import {
  AuthService,
  AUTH_MODULE_OPTIONS,
} from '@sapix/nestjs-better-auth-fastify';
import type { FastifyRequest } from 'fastify';

describe('AuthService', () => {
  let service: AuthService;
  let mockAuth: any;
  let mockRequest: Partial<FastifyRequest>;

  beforeEach(async () => {
    mockAuth = {
      api: {
        getSession: jest.fn(),
        revokeSession: jest.fn(),
        revokeSessions: jest.fn(),
        listSessions: jest.fn(),
        getToken: jest.fn(),
        verifyApiKey: jest.fn(),
        getFullOrganization: jest.fn(),
        hasPermission: jest.fn(),
      },
      options: {
        basePath: '/api/auth',
        session: {
          freshAge: 86400,
        },
      },
    };

    mockRequest = {
      headers: {
        cookie: 'session=test',
        host: 'localhost:3000',
      },
      protocol: 'http',
      url: '/test',
      method: 'GET',
    } as any;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: { auth: mockAuth },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('api getter', () => {
    it('should return the auth API', () => {
      expect(service.api).toBe(mockAuth.api);
    });
  });

  describe('instance getter', () => {
    it('should return the auth instance', () => {
      expect(service.instance).toBe(mockAuth);
    });
  });

  describe('$Infer getter', () => {
    it('should throw error when accessed at runtime', () => {
      expect(() => service.$Infer).toThrow(
        '$Infer is a compile-time type helper and should not be accessed at runtime.',
      );
    });
  });

  describe('basePath getter', () => {
    it('should return basePath from auth options', () => {
      expect(service.basePath).toBe('/api/auth');
    });

    it('should use default basePath when not configured', async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: AUTH_MODULE_OPTIONS,
            useValue: { auth: { api: {}, options: {} } },
          },
        ],
      }).compile();

      const svc = module.get<AuthService>(AuthService);
      expect(svc.basePath).toBe('/api/auth');
    });

    it('should prefer module basePath over auth options', async () => {
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          AuthService,
          {
            provide: AUTH_MODULE_OPTIONS,
            useValue: {
              auth: mockAuth,
              basePath: '/custom/auth',
            },
          },
        ],
      }).compile();

      const svc = module.get<AuthService>(AuthService);
      expect(svc.basePath).toBe('/custom/auth');
    });
  });

  describe('getSessionFromRequest', () => {
    it('should return session from request', async () => {
      const mockSession = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', email: 'test@example.com' },
      };
      mockAuth.api.getSession.mockResolvedValue(mockSession);

      const session = await service.getSessionFromRequest(
        mockRequest as FastifyRequest,
      );

      expect(session).toEqual(mockSession);
      expect(mockAuth.api.getSession).toHaveBeenCalled();
    });

    it('should return null when no session', async () => {
      mockAuth.api.getSession.mockResolvedValue(null);

      const session = await service.getSessionFromRequest(
        mockRequest as FastifyRequest,
      );

      expect(session).toBeNull();
    });

    it('should return null on error', async () => {
      mockAuth.api.getSession.mockRejectedValue(new Error('Network error'));

      const session = await service.getSessionFromRequest(
        mockRequest as FastifyRequest,
      );

      expect(session).toBeNull();
    });
  });

  describe('getSessionFromHeaders', () => {
    it('should return session from headers', async () => {
      const mockSession = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      };
      mockAuth.api.getSession.mockResolvedValue(mockSession);

      const headers = new Headers({ cookie: 'session=test' });
      const session = await service.getSessionFromHeaders(headers);

      expect(session).toEqual(mockSession);
    });
  });

  describe('validateSession', () => {
    it('should return session when valid', async () => {
      const mockSession = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      };
      mockAuth.api.getSession.mockResolvedValue(mockSession);

      const session = await service.validateSession(
        mockRequest as FastifyRequest,
      );

      expect(session).toEqual(mockSession);
    });

    it('should throw UnauthorizedException when no session', async () => {
      mockAuth.api.getSession.mockResolvedValue(null);

      await expect(
        service.validateSession(mockRequest as FastifyRequest),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('hasRole', () => {
    it('should return true when user has role (any mode)', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'admin' },
      };

      const result = service.hasRole(session as any, ['admin', 'moderator']);

      expect(result).toBe(true);
    });

    it('should return false when user lacks role', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'user' },
      };

      const result = service.hasRole(session as any, ['admin']);

      expect(result).toBe(false);
    });

    it('should return true when user has all roles (all mode)', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'admin,verified' },
      };

      const result = service.hasRole(
        session as any,
        ['admin', 'verified'],
        'all',
      );

      expect(result).toBe(true);
    });

    it('should return false when user lacks some roles (all mode)', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: 'admin' },
      };

      const result = service.hasRole(
        session as any,
        ['admin', 'verified'],
        'all',
      );

      expect(result).toBe(false);
    });

    it('should handle array roles', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', role: ['admin', 'verified'] },
      };

      const result = service.hasRole(session as any, ['admin']);

      expect(result).toBe(true);
    });

    it('should return false when role is undefined', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      };

      const result = service.hasRole(session as any, ['admin']);

      expect(result).toBe(false);
    });
  });

  describe('hasPermission', () => {
    it('should return true when user has permission', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['user:read', 'user:write'] },
      };

      const result = service.hasPermission(session as any, ['user:read']);

      expect(result).toBe(true);
    });

    it('should return false when user lacks permission', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['user:read'] },
      };

      const result = service.hasPermission(session as any, ['admin:access']);

      expect(result).toBe(false);
    });

    it('should handle string permissions (comma-separated)', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: 'user:read,user:write' },
      };

      const result = service.hasPermission(session as any, ['user:read']);

      expect(result).toBe(true);
    });

    it('should return false when permissions is undefined', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      };

      const result = service.hasPermission(session as any, ['user:read']);

      expect(result).toBe(false);
    });

    it('should return true when user has all permissions (all mode)', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['user:read', 'user:write'] },
      };

      const result = service.hasPermission(
        session as any,
        ['user:read', 'user:write'],
        'all',
      );

      expect(result).toBe(true);
    });

    it('should return false when user lacks some permissions (all mode)', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1', permissions: ['user:read'] },
      };

      const result = service.hasPermission(
        session as any,
        ['user:read', 'user:write'],
        'all',
      );

      expect(result).toBe(false);
    });
  });

  describe('isSessionFresh', () => {
    it('should return true for fresh session', () => {
      const session = {
        session: { id: 'sess-1', createdAt: new Date() },
        user: { id: 'user-1' },
      };

      const result = service.isSessionFresh(session as any);

      expect(result).toBe(true);
    });

    it('should return false for stale session', () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 2);

      const session = {
        session: { id: 'sess-1', createdAt: oldDate },
        user: { id: 'user-1' },
      };

      const result = service.isSessionFresh(session as any, 3600);

      expect(result).toBe(false);
    });

    it('should use custom maxAge', () => {
      const recentDate = new Date();
      recentDate.setMinutes(recentDate.getMinutes() - 10);

      const session = {
        session: { id: 'sess-1', createdAt: recentDate },
        user: { id: 'user-1' },
      };

      const result = service.isSessionFresh(session as any, 900);

      expect(result).toBe(true);
    });
  });

  describe('revokeSession', () => {
    it('should revoke session successfully', async () => {
      mockAuth.api.revokeSession.mockResolvedValue({ success: true });

      const result = await service.revokeSession(
        'token-123',
        mockRequest as FastifyRequest,
      );

      expect(result).toBe(true);
      expect(mockAuth.api.revokeSession).toHaveBeenCalled();
    });

    it('should return false on error', async () => {
      mockAuth.api.revokeSession.mockRejectedValue(new Error('Failed'));

      const result = await service.revokeSession(
        'token-123',
        mockRequest as FastifyRequest,
      );

      expect(result).toBe(false);
    });
  });

  describe('revokeAllSessions', () => {
    it('should revoke all sessions successfully', async () => {
      mockAuth.api.revokeSessions.mockResolvedValue({ success: true });

      const result = await service.revokeAllSessions(
        mockRequest as FastifyRequest,
      );

      expect(result).toBe(true);
    });

    it('should return false on error', async () => {
      mockAuth.api.revokeSessions.mockRejectedValue(new Error('Failed'));

      const result = await service.revokeAllSessions(
        mockRequest as FastifyRequest,
      );

      expect(result).toBe(false);
    });
  });

  describe('listUserSessions', () => {
    it('should return list of sessions', async () => {
      const mockSessions = [
        { id: 'sess-1', userAgent: 'Chrome' },
        { id: 'sess-2', userAgent: 'Firefox' },
      ];
      mockAuth.api.listSessions.mockResolvedValue(mockSessions);

      const sessions = await service.listUserSessions(
        mockRequest as FastifyRequest,
      );

      expect(sessions).toEqual(mockSessions);
    });

    it('should return empty array on error', async () => {
      mockAuth.api.listSessions.mockRejectedValue(new Error('Failed'));

      const sessions = await service.listUserSessions(
        mockRequest as FastifyRequest,
      );

      expect(sessions).toEqual([]);
    });
  });

  describe('getJwtToken', () => {
    it('should return JWT token when available', async () => {
      mockAuth.api.getToken.mockResolvedValue({ token: 'jwt-token-123' });

      const token = await service.getJwtToken(mockRequest as FastifyRequest);

      expect(token).toBe('jwt-token-123');
    });

    it('should return null when JWT plugin not available', async () => {
      delete mockAuth.api.getToken;

      const token = await service.getJwtToken(mockRequest as FastifyRequest);

      expect(token).toBeNull();
    });

    it('should return null on error', async () => {
      mockAuth.api.getToken.mockRejectedValue(new Error('Failed'));

      const token = await service.getJwtToken(mockRequest as FastifyRequest);

      expect(token).toBeNull();
    });
  });

  describe('verifyApiKey', () => {
    it('should return valid result for valid API key', async () => {
      mockAuth.api.verifyApiKey.mockResolvedValue({
        valid: true,
        key: { id: 'key-1', name: 'Test Key' },
      });

      const result = await service.verifyApiKey('test-api-key');

      expect(result.valid).toBe(true);
      expect(result.key).toBeDefined();
    });

    it('should return error when plugin not enabled', async () => {
      delete mockAuth.api.verifyApiKey;

      const result = await service.verifyApiKey('test-api-key');

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('PLUGIN_NOT_ENABLED');
    });

    it('should return error on verification failure', async () => {
      mockAuth.api.verifyApiKey.mockRejectedValue(new Error('Invalid key'));

      const result = await service.verifyApiKey('invalid-key');

      expect(result.valid).toBe(false);
      expect(result.error?.code).toBe('VERIFICATION_FAILED');
    });
  });

  describe('isUserBanned', () => {
    it('should return false for non-banned user', () => {
      const user = { id: 'user-1', banned: false } as any;

      const result = service.isUserBanned(user);

      expect(result).toBe(false);
    });

    it('should return true for banned user', () => {
      const user = { id: 'user-1', banned: true } as any;

      const result = service.isUserBanned(user);

      expect(result).toBe(true);
    });

    it('should return false if ban has expired', () => {
      const expiredDate = new Date();
      expiredDate.setDate(expiredDate.getDate() - 1);

      const user = {
        id: 'user-1',
        banned: true,
        banExpires: expiredDate.toISOString(),
      } as any;

      const result = service.isUserBanned(user);

      expect(result).toBe(false);
    });

    it('should return true if ban has not expired', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 1);

      const user = {
        id: 'user-1',
        banned: true,
        banExpires: futureDate.toISOString(),
      } as any;

      const result = service.isUserBanned(user);

      expect(result).toBe(true);
    });
  });

  describe('isImpersonating', () => {
    it('should return true when session is impersonated', () => {
      const session = {
        session: { id: 'sess-1', impersonatedBy: 'admin-1' },
        user: { id: 'user-1' },
      };

      const result = service.isImpersonating(session as any);

      expect(result).toBe(true);
    });

    it('should return false when session is not impersonated', () => {
      const session = {
        session: { id: 'sess-1' },
        user: { id: 'user-1' },
      };

      const result = service.isImpersonating(session as any);

      expect(result).toBe(false);
    });
  });

  describe('getImpersonatedBy', () => {
    it('should return admin ID when impersonated', () => {
      const session = {
        session: { id: 'sess-1', impersonatedBy: 'admin-1' },
        user: { id: 'user-1' },
      };

      const result = service.getImpersonatedBy(session as any);

      expect(result).toBe('admin-1');
    });

    it('should return null when not impersonated', () => {
      const session = {
        session: { id: 'sess-1' },
        user: { id: 'user-1' },
      };

      const result = service.getImpersonatedBy(session as any);

      expect(result).toBeNull();
    });
  });

  describe('getActiveOrganization', () => {
    it('should return organization when available', async () => {
      const mockOrg = { id: 'org-1', name: 'Test Org' };
      mockAuth.api.getFullOrganization.mockResolvedValue(mockOrg);

      const org = await service.getActiveOrganization(
        mockRequest as FastifyRequest,
      );

      expect(org).toEqual(mockOrg);
    });

    it('should return null when plugin not available', async () => {
      delete mockAuth.api.getFullOrganization;

      const org = await service.getActiveOrganization(
        mockRequest as FastifyRequest,
      );

      expect(org).toBeNull();
    });

    it('should return null on error', async () => {
      mockAuth.api.getFullOrganization.mockRejectedValue(new Error('Failed'));

      const org = await service.getActiveOrganization(
        mockRequest as FastifyRequest,
      );

      expect(org).toBeNull();
    });
  });

  describe('hasOrgPermission', () => {
    it('should return true when user has permission', async () => {
      mockAuth.api.hasPermission.mockResolvedValue({ hasPermission: true });

      const result = await service.hasOrgPermission(
        mockRequest as FastifyRequest,
        {
          resource: 'member',
          action: 'create',
        },
      );

      expect(result).toBe(true);
    });

    it('should return false when user lacks permission', async () => {
      mockAuth.api.hasPermission.mockResolvedValue({ hasPermission: false });

      const result = await service.hasOrgPermission(
        mockRequest as FastifyRequest,
        {
          resource: 'member',
          action: 'delete',
        },
      );

      expect(result).toBe(false);
    });

    it('should return false when plugin not available', async () => {
      delete mockAuth.api.hasPermission;

      const result = await service.hasOrgPermission(
        mockRequest as FastifyRequest,
        {
          resource: 'member',
          action: 'create',
        },
      );

      expect(result).toBe(false);
    });

    it('should return false on error', async () => {
      mockAuth.api.hasPermission.mockRejectedValue(new Error('Failed'));

      const result = await service.hasOrgPermission(
        mockRequest as FastifyRequest,
        {
          resource: 'member',
          action: 'create',
        },
      );

      expect(result).toBe(false);
    });
  });
});
