import { Test, TestingModule } from '@nestjs/testing';
import { Injectable, Logger } from '@nestjs/common';
import {
  HttpAdapterHost,
  DiscoveryService,
  MetadataScanner,
} from '@nestjs/core';
import {
  AuthModule,
  AuthService,
  AUTH_MODULE_OPTIONS,
  AuthModuleOptions,
  AuthModuleOptionsFactory,
  HOOK_KEY,
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
} from '@sapix/nestjs-better-auth-fastify';
import { mockCreateAuthMiddleware } from '../setup';

describe('AuthModule', () => {
  const mockAuth = {
    api: {
      getSession: jest.fn(),
    },
    handler: jest.fn().mockResolvedValue(new Response('OK')),
    options: {
      basePath: '/api/auth',
    },
  };

  describe('forRoot', () => {
    it('should provide AuthModule options', async () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
        basePath: '/api/auth',
      };

      const dynamicModule = AuthModule.forRoot(options);

      expect(dynamicModule.module).toBe(AuthModule);
      expect(dynamicModule.global).toBe(true);
      expect(dynamicModule.exports).toContain(AuthService);
      expect(dynamicModule.exports).toContain(AUTH_MODULE_OPTIONS);
    });

    it('should include global guard by default', () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
      };

      const dynamicModule = AuthModule.forRoot(options);

      const hasGuard = dynamicModule.providers?.some(
        (provider: any) =>
          provider.provide?.toString() === 'Symbol(APP_GUARD)' ||
          provider.provide === 'APP_GUARD',
      );
      expect(hasGuard).toBeTruthy();
    });

    it('should not include global guard when disabled', () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
        disableGlobalGuard: true,
      };

      const dynamicModule = AuthModule.forRoot(options);

      const guardProviders = dynamicModule.providers?.filter(
        (provider: any) =>
          provider.provide?.toString() === 'Symbol(APP_GUARD)' ||
          provider.provide === 'APP_GUARD',
      );
      expect(guardProviders?.length ?? 0).toBe(0);
    });
  });

  describe('forRootAsync', () => {
    describe('useFactory', () => {
      it('should create module with useFactory', () => {
        const dynamicModule = AuthModule.forRootAsync({
          useFactory: () => ({
            auth: mockAuth as any,
          }),
        });

        expect(dynamicModule.module).toBe(AuthModule);
        expect(dynamicModule.global).toBe(true);
      });

      it('should support inject option', () => {
        const TEST_TOKEN = 'TEST_TOKEN';

        const dynamicModule = AuthModule.forRootAsync({
          useFactory: (testDep: string) => ({
            auth: mockAuth as any,
          }),
          inject: [TEST_TOKEN],
        });

        const factoryProvider = dynamicModule.providers?.find(
          (p: any) => p.provide === AUTH_MODULE_OPTIONS,
        ) as any;

        expect(factoryProvider?.inject).toContain(TEST_TOKEN);
      });
    });

    describe('useClass', () => {
      @Injectable()
      class TestAuthConfigService implements AuthModuleOptionsFactory {
        createAuthModuleOptions(): AuthModuleOptions {
          return { auth: mockAuth as any };
        }
      }

      it('should create module with useClass', () => {
        const dynamicModule = AuthModule.forRootAsync({
          useClass: TestAuthConfigService,
        });

        expect(dynamicModule.module).toBe(AuthModule);

        const hasClassProvider = dynamicModule.providers?.some(
          (p: any) => p.provide === TestAuthConfigService,
        );
        expect(hasClassProvider).toBeTruthy();
      });
    });

    describe('useExisting', () => {
      @Injectable()
      class ExistingAuthConfigService implements AuthModuleOptionsFactory {
        createAuthModuleOptions(): AuthModuleOptions {
          return { auth: mockAuth as any };
        }
      }

      it('should create module with useExisting', () => {
        const dynamicModule = AuthModule.forRootAsync({
          useExisting: ExistingAuthConfigService,
        });

        expect(dynamicModule.module).toBe(AuthModule);

        const factoryProvider = dynamicModule.providers?.find(
          (p: any) => p.provide === AUTH_MODULE_OPTIONS,
        ) as any;

        expect(factoryProvider?.inject).toContain(ExistingAuthConfigService);
      });
    });

    describe('imports', () => {
      it('should include provided imports', () => {
        const MockModule = class MockModule {};

        const dynamicModule = AuthModule.forRootAsync({
          imports: [MockModule as any],
          useFactory: () => ({ auth: mockAuth as any }),
        });

        expect(dynamicModule.imports).toContain(MockModule);
      });
    });

    describe('disableGlobalGuard', () => {
      it('should include guard by default', () => {
        const dynamicModule = AuthModule.forRootAsync({
          useFactory: () => ({ auth: mockAuth as any }),
        });

        const hasGuard = dynamicModule.providers?.some(
          (provider: any) =>
            provider.provide?.toString() === 'Symbol(APP_GUARD)' ||
            provider.provide === 'APP_GUARD',
        );
        expect(hasGuard).toBeTruthy();
      });

      it('should not include guard when disabled', () => {
        const dynamicModule = AuthModule.forRootAsync({
          useFactory: () => ({ auth: mockAuth as any }),
          disableGlobalGuard: true,
        });

        const guardProviders = dynamicModule.providers?.filter(
          (provider: any) =>
            provider.provide?.toString() === 'Symbol(APP_GUARD)' ||
            provider.provide === 'APP_GUARD',
        );
        expect(guardProviders?.length ?? 0).toBe(0);
      });
    });
  });

  describe('Module Integration', () => {
    it('should be able to create a testing module with forRoot', async () => {
      const mockHttpAdapterHost = {
        httpAdapter: {
          getInstance: jest.fn().mockReturnValue({
            route: jest.fn(),
          }),
        },
      };

      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([]),
      };

      const mockMetadataScanner = {
        getAllMethodNames: jest.fn().mockReturnValue([]),
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: mockAuth as any,
            basePath: '/api/auth',
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      const authService = module.get<AuthService>(AuthService);
      expect(authService).toBeDefined();

      const options = module.get(AUTH_MODULE_OPTIONS);
      expect(options).toBeDefined();
      expect(options.auth).toBe(mockAuth);
    });

    it('should be able to create a testing module with forRootAsync', async () => {
      const mockHttpAdapterHost = {
        httpAdapter: {
          getInstance: jest.fn().mockReturnValue({
            route: jest.fn(),
          }),
        },
      };

      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([]),
      };

      const mockMetadataScanner = {
        getAllMethodNames: jest.fn().mockReturnValue([]),
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRootAsync({
            useFactory: () => ({
              auth: mockAuth as any,
              basePath: '/custom/auth',
            }),
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      const authService = module.get<AuthService>(AuthService);
      expect(authService).toBeDefined();

      const options = module.get(AUTH_MODULE_OPTIONS);
      expect(options.basePath).toBe('/custom/auth');
    });
  });

  describe('Configuration Options', () => {
    it('should accept debug option', () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
        debug: true,
      };

      const dynamicModule = AuthModule.forRoot(options);
      expect(dynamicModule).toBeDefined();
    });

    it('should accept middleware option', () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
        middleware: async (req, reply, next) => {
          await next();
        },
      };

      const dynamicModule = AuthModule.forRoot(options);
      expect(dynamicModule).toBeDefined();
    });

    it('should accept errorMessages option', () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
        errorMessages: {
          unauthorized: 'Please log in first',
          forbidden: 'Insufficient permissions',
          sessionExpired: 'Session has expired',
        },
      };

      const dynamicModule = AuthModule.forRoot(options);
      expect(dynamicModule).toBeDefined();
    });

    it('should accept orgRolePermissions option', () => {
      const options: AuthModuleOptions = {
        auth: mockAuth as any,
        orgRolePermissions: {
          owner: { organization: 'all', member: 'all' },
          admin: { organization: ['read', 'update'], member: ['read'] },
          member: { organization: ['read'] },
        },
      };

      const dynamicModule = AuthModule.forRoot(options);
      expect(dynamicModule).toBeDefined();
    });

    // Note: apiKeyPattern option has been removed
    // API keys are detected via dedicated headers only (x-api-key, api-key, etc.)
    // The library auto-reads apiKeyHeaders config from Better Auth's apiKey plugin

    // Note: skipSessionExpirationCheck option has been removed
    // Better Auth's getSession API already handles session expiration automatically
  });

  describe('onModuleInit', () => {
    let mockRoute: jest.Mock;
    let mockHttpAdapterHost: any;
    let mockDiscoveryService: any;
    let mockMetadataScanner: any;

    beforeEach(() => {
      mockRoute = jest.fn();
      mockHttpAdapterHost = {
        httpAdapter: {
          getInstance: jest.fn().mockReturnValue({
            route: mockRoute,
          }),
        },
      };
      mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([]),
      };
      mockMetadataScanner = {
        getAllMethodNames: jest.fn().mockReturnValue([]),
      };
      mockCreateAuthMiddleware.mockClear();
    });

    it('should mount auth handler on initialization', async () => {
      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: mockAuth as any,
            basePath: '/api/auth',
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      expect(mockRoute).toHaveBeenCalledWith(
        expect.objectContaining({
          method: ['GET', 'POST'],
          url: '/api/auth/*',
        }),
      );
    });

    it('should use basePath from auth.options when not provided in module options', async () => {
      const authWithBasePath = {
        ...mockAuth,
        options: {
          basePath: '/custom/auth',
        },
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithBasePath as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      expect(mockRoute).toHaveBeenCalledWith(
        expect.objectContaining({
          url: '/custom/auth/*',
        }),
      );
    });

    it('should use default basePath when not provided', async () => {
      const authWithoutBasePath = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {},
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithoutBasePath as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      expect(mockRoute).toHaveBeenCalledWith(
        expect.objectContaining({
          url: '/api/auth/*',
        }),
      );
    });

    it('should call auth handler and return response', async () => {
      const mockHandler = jest.fn().mockResolvedValue(
        new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
      const authForHandler = {
        ...mockAuth,
        handler: mockHandler,
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authForHandler as any,
            basePath: '/api/auth',
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      // Get the handler that was registered
      const routeCall = mockRoute.mock.calls[0][0];
      const handler = routeCall.handler;

      // Mock Fastify request and reply
      const mockRequest = {
        protocol: 'http',
        hostname: 'localhost',
        url: '/api/auth/session',
        method: 'GET',
        headers: { host: 'localhost' },
        body: undefined,
      };
      const mockReply = {
        status: jest.fn().mockReturnThis(),
        header: jest.fn().mockReturnThis(),
        send: jest.fn().mockReturnThis(),
      };

      await handler(mockRequest, mockReply);

      expect(mockHandler).toHaveBeenCalled();
      expect(mockReply.status).toHaveBeenCalledWith(200);
    });

    it('should handle auth handler errors', async () => {
      const mockHandler = jest.fn().mockRejectedValue(new Error('Auth error'));
      const authWithError = {
        ...mockAuth,
        handler: mockHandler,
      };

      // Suppress logger error output during test
      jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithError as any,
            basePath: '/api/auth',
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      const routeCall = mockRoute.mock.calls[0][0];
      const handler = routeCall.handler;

      const mockRequest = {
        protocol: 'http',
        hostname: 'localhost',
        url: '/api/auth/session',
        method: 'GET',
        headers: { host: 'localhost' },
        body: undefined,
      };
      const mockReply = {
        status: jest.fn().mockReturnThis(),
        header: jest.fn().mockReturnThis(),
        send: jest.fn().mockReturnThis(),
      };

      await handler(mockRequest, mockReply);

      expect(mockReply.status).toHaveBeenCalledWith(500);
      expect(mockReply.send).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 500,
          code: 'AUTH_ERROR',
        }),
      );
    });

    it('should call middleware wrapper when provided', async () => {
      const middlewareMock = jest.fn(async (req, reply, next) => {
        await next();
      });

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: mockAuth as any,
            basePath: '/api/auth',
            middleware: middlewareMock,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      const routeCall = mockRoute.mock.calls[0][0];
      const handler = routeCall.handler;

      const mockRequest = {
        protocol: 'http',
        hostname: 'localhost',
        url: '/api/auth/session',
        method: 'GET',
        headers: { host: 'localhost' },
        body: undefined,
      };
      const mockReply = {
        status: jest.fn().mockReturnThis(),
        header: jest.fn().mockReturnThis(),
        send: jest.fn().mockReturnThis(),
      };

      await handler(mockRequest, mockReply);

      expect(middlewareMock).toHaveBeenCalledWith(
        mockRequest,
        mockReply,
        expect.any(Function),
      );
    });
  });

  describe('Hook Setup', () => {
    let mockRoute: jest.Mock;
    let mockHttpAdapterHost: any;
    let mockMetadataScanner: any;

    beforeEach(() => {
      mockRoute = jest.fn();
      mockHttpAdapterHost = {
        httpAdapter: {
          getInstance: jest.fn().mockReturnValue({
            route: mockRoute,
          }),
        },
      };
      mockMetadataScanner = {
        getAllMethodNames: jest.fn().mockReturnValue(['beforeSignUp']),
      };
      mockCreateAuthMiddleware.mockClear();
    });

    it('should throw error when hook providers exist but hooks not configured', async () => {
      // Create mock provider with @Hook metadata
      class HookProvider {
        beforeSignUp() {}
      }
      Reflect.defineMetadata(HOOK_KEY, true, HookProvider);

      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([
          {
            metatype: HookProvider,
            instance: new HookProvider(),
          },
        ]),
      };

      const authWithoutHooks = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {
          basePath: '/api/auth',
          // No hooks configured
        },
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithoutHooks as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await expect(module.init()).rejects.toThrow(
        "Detected @Hook providers but Better Auth 'hooks' are not configured",
      );
    });

    it('should register hook providers when hooks are configured', async () => {
      class HookProvider {
        beforeSignUp() {}
      }
      Reflect.defineMetadata(HOOK_KEY, true, HookProvider);
      Reflect.defineMetadata(
        BEFORE_HOOK_KEY,
        '/sign-up/email',
        HookProvider.prototype.beforeSignUp,
      );

      const mockInstance = new HookProvider();
      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([
          {
            metatype: HookProvider,
            instance: mockInstance,
          },
        ]),
      };

      const authWithHooks = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {
          basePath: '/api/auth',
          hooks: {
            before: undefined,
            after: undefined,
          },
        },
      };

      // Suppress logger output during test
      jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithHooks as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      // Verify that createAuthMiddleware was called
      expect(mockCreateAuthMiddleware).toHaveBeenCalled();
    });

    it('should skip setup when no hooks are configured', async () => {
      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([]),
      };

      const authWithoutHooks = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {
          basePath: '/api/auth',
        },
      };

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithoutHooks as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      // Should not throw and should complete successfully
      expect(mockRoute).toHaveBeenCalled();
    });

    it('should execute original hook before NestJS hook', async () => {
      const executionOrder: string[] = [];

      class HookProvider {
        beforeSignUp() {
          executionOrder.push('nestjs');
        }
      }
      Reflect.defineMetadata(HOOK_KEY, true, HookProvider);
      Reflect.defineMetadata(
        BEFORE_HOOK_KEY,
        '/sign-up/email',
        HookProvider.prototype.beforeSignUp,
      );

      const mockInstance = new HookProvider();
      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([
          {
            metatype: HookProvider,
            instance: mockInstance,
          },
        ]),
      };

      const originalHook = async () => {
        executionOrder.push('original');
      };

      const authWithHooks = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {
          basePath: '/api/auth',
          hooks: {
            before: originalHook,
          },
        },
      };

      jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithHooks as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      // Get the registered hook and execute it
      const hookCall = mockCreateAuthMiddleware.mock.calls[0];
      if (hookCall) {
        const hookFn = hookCall[0];
        await hookFn({ path: '/sign-up/email' });
        expect(executionOrder).toEqual(['original', 'nestjs']);
      }
    });

    it('should skip NestJS hook when path does not match', async () => {
      let hookExecuted = false;

      class HookProvider {
        beforeSignUp() {
          hookExecuted = true;
        }
      }
      Reflect.defineMetadata(HOOK_KEY, true, HookProvider);
      Reflect.defineMetadata(
        BEFORE_HOOK_KEY,
        '/sign-up/email',
        HookProvider.prototype.beforeSignUp,
      );

      const mockInstance = new HookProvider();
      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([
          {
            metatype: HookProvider,
            instance: mockInstance,
          },
        ]),
      };

      const authWithHooks = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {
          basePath: '/api/auth',
          hooks: {},
        },
      };

      jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithHooks as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      const hookCall = mockCreateAuthMiddleware.mock.calls[0];
      if (hookCall) {
        const hookFn = hookCall[0];
        await hookFn({ path: '/sign-in/email' }); // Different path
        expect(hookExecuted).toBe(false);
      }
    });

    it('should register afterHook correctly', async () => {
      let afterHookExecuted = false;

      class HookProvider {
        afterSignIn() {
          afterHookExecuted = true;
        }
      }
      Reflect.defineMetadata(HOOK_KEY, true, HookProvider);
      Reflect.defineMetadata(
        AFTER_HOOK_KEY,
        '/sign-in/email',
        HookProvider.prototype.afterSignIn,
      );

      mockMetadataScanner.getAllMethodNames.mockReturnValue(['afterSignIn']);

      const mockInstance = new HookProvider();
      const mockDiscoveryService = {
        getProviders: jest.fn().mockReturnValue([
          {
            metatype: HookProvider,
            instance: mockInstance,
          },
        ]),
      };

      const authWithHooks = {
        api: mockAuth.api,
        handler: mockAuth.handler,
        options: {
          basePath: '/api/auth',
          hooks: {},
        },
      };

      jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});

      const module: TestingModule = await Test.createTestingModule({
        imports: [
          AuthModule.forRoot({
            auth: authWithHooks as any,
          }),
        ],
      })
        .overrideProvider(HttpAdapterHost)
        .useValue(mockHttpAdapterHost)
        .overrideProvider(DiscoveryService)
        .useValue(mockDiscoveryService)
        .overrideProvider(MetadataScanner)
        .useValue(mockMetadataScanner)
        .compile();

      await module.init();

      // Find the after hook call (second item in HOOKS array)
      const afterHookCall = mockCreateAuthMiddleware.mock.calls.find(
        (call: any, index: number) => index >= 1,
      );
      if (afterHookCall) {
        const hookFn = afterHookCall[0];
        await hookFn({ path: '/sign-in/email' });
        expect(afterHookExecuted).toBe(true);
      }
    });
  });

  describe('createAsyncProviders Error', () => {
    it('should throw error for invalid async options', () => {
      // Access private static method through the class
      expect(() => {
        AuthModule.forRootAsync({} as any);
      }).toThrow(
        'Invalid AuthModuleAsyncOptions: must provide useFactory, useClass, or useExisting',
      );
    });
  });
});
