import {
  Module,
  DynamicModule,
  Provider,
  FactoryProvider,
  ClassProvider,
} from '@nestjs/common';
import { APP_GUARD, DiscoveryModule } from '@nestjs/core';
import {
  AUTH_MODULE_OPTIONS,
  AuthModuleOptions,
  AuthModuleAsyncOptions,
  AuthModuleOptionsFactory,
} from './auth.types';
import { AuthService } from './auth.service';
import { AuthGuard } from './auth.guard';
import { AuthBootstrapService } from './auth.bootstrap';

/**
 * Validate Better Auth instance
 * Ensures the auth instance has required properties
 */
function validateAuthInstance(auth: unknown): void {
  if (!auth || typeof auth !== 'object') {
    throw new Error(
      'AuthModule: Invalid auth instance. Expected a Better Auth instance.',
    );
  }

  const authObj = auth as Record<string, unknown>;

  if (typeof authObj.handler !== 'function') {
    throw new Error(
      'AuthModule: Invalid auth instance. Missing "handler" function. ' +
        'Make sure you are passing a Better Auth instance created with betterAuth().',
    );
  }

  if (!authObj.api || typeof authObj.api !== 'object') {
    throw new Error(
      'AuthModule: Invalid auth instance. Missing "api" object. ' +
        'Make sure you are passing a Better Auth instance created with betterAuth().',
    );
  }
}

/**
 * Better Auth Module
 *
 * Provides Better Auth integration for NestJS + Fastify applications
 *
 * Features:
 * - Automatically mounts Better Auth handler to specified basePath
 * - Global AuthGuard (can be disabled)
 * - Supports HTTP, GraphQL, WebSocket
 * - Supports @Hook, @BeforeHook, @AfterHook decorators
 * - Supports custom middleware wrapping
 *
 * @example
 * ```typescript
 * // Synchronous configuration
 * @Module({
 *   imports: [
 *     AuthModule.forRoot({
 *       auth,
 *       basePath: '/api/auth',
 *     }),
 *   ],
 * })
 * export class AppModule {}
 *
 * // Asynchronous configuration
 * @Module({
 *   imports: [
 *     AuthModule.forRootAsync({
 *       useFactory: (config: ConfigService) => ({
 *         auth: createAuth(config.get('AUTH_SECRET')),
 *       }),
 *       inject: [ConfigService],
 *     }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({
  imports: [DiscoveryModule],
})
export class AuthModule {
  /**
   * Synchronous configuration
   */
  static forRoot(options: AuthModuleOptions): DynamicModule {
    // Validate auth instance at configuration time
    validateAuthInstance(options.auth);

    const providers: Provider[] = [
      {
        provide: AUTH_MODULE_OPTIONS,
        useValue: options,
      },
      AuthService,
      AuthBootstrapService,
    ];

    if (!options.disableGlobalGuard) {
      providers.push({
        provide: APP_GUARD,
        useClass: AuthGuard,
      });
    }

    return {
      module: AuthModule,
      global: true,
      providers,
      exports: [AuthService, AUTH_MODULE_OPTIONS],
    };
  }

  /**
   * Asynchronous configuration
   *
   * Supports three modes:
   * - useFactory: Create configuration with factory function
   * - useClass: Use configuration factory class
   * - useExisting: Use existing configuration factory
   *
   * @example
   * ```typescript
   * // useFactory mode
   * AuthModule.forRootAsync({
   *   useFactory: (config: ConfigService) => ({
   *     auth: createAuth(config.get('AUTH_SECRET')),
   *   }),
   *   inject: [ConfigService],
   * })
   *
   * // useClass mode
   * AuthModule.forRootAsync({
   *   useClass: AuthConfigService, // Must implement AuthModuleOptionsFactory
   * })
   *
   * // useExisting mode
   * AuthModule.forRootAsync({
   *   imports: [ConfigModule],
   *   useExisting: AuthConfigService, // Use service from imported module
   * })
   * ```
   */
  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const providers: Provider[] = [
      ...this.createAsyncProviders(options),
      AuthService,
      AuthBootstrapService,
    ];

    if (!options.disableGlobalGuard) {
      providers.push({
        provide: APP_GUARD,
        useClass: AuthGuard,
      });
    }

    return {
      module: AuthModule,
      global: true,
      imports: options.imports || [],
      providers,
      exports: [AuthService, AUTH_MODULE_OPTIONS],
    };
  }

  /**
   * Create async configuration providers
   */
  private static createAsyncProviders(
    options: AuthModuleAsyncOptions,
  ): Provider[] {
    // Wrapper to validate auth instance after async creation
    const validateAndReturn = async (
      result: AuthModuleOptions | Promise<AuthModuleOptions>,
    ): Promise<AuthModuleOptions> => {
      const resolved = await result;
      validateAuthInstance(resolved.auth);
      return resolved;
    };

    // useFactory mode
    if ('useFactory' in options) {
      const originalFactory = options.useFactory;
      const factoryProvider: FactoryProvider<Promise<AuthModuleOptions>> = {
        provide: AUTH_MODULE_OPTIONS,
        useFactory: (...args: unknown[]) =>
          validateAndReturn(originalFactory(...args)),
        inject: options.inject || [],
      };
      return [factoryProvider];
    }

    // useClass mode
    if ('useClass' in options) {
      const classProvider: ClassProvider<AuthModuleOptionsFactory> = {
        provide: options.useClass,
        useClass: options.useClass,
      };
      const factoryProvider: FactoryProvider<Promise<AuthModuleOptions>> = {
        provide: AUTH_MODULE_OPTIONS,
        useFactory: (optionsFactory: AuthModuleOptionsFactory) =>
          validateAndReturn(optionsFactory.createAuthModuleOptions()),
        inject: [options.useClass],
      };
      return [classProvider, factoryProvider];
    }

    // useExisting mode
    if ('useExisting' in options) {
      const factoryProvider: FactoryProvider<Promise<AuthModuleOptions>> = {
        provide: AUTH_MODULE_OPTIONS,
        useFactory: (optionsFactory: AuthModuleOptionsFactory) =>
          validateAndReturn(optionsFactory.createAuthModuleOptions()),
        inject: [options.useExisting],
      };
      return [factoryProvider];
    }

    throw new Error(
      'Invalid AuthModuleAsyncOptions: must provide useFactory, useClass, or useExisting',
    );
  }
}
