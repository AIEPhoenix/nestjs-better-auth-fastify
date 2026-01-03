import { Injectable, Inject, Logger, OnModuleInit } from '@nestjs/common';
import {
  HttpAdapterHost,
  DiscoveryService,
  MetadataScanner,
} from '@nestjs/core';
import type { HookEndpointContext, BetterAuthOptions } from 'better-auth';
import type { AuthMiddleware } from 'better-auth/api';
import { createAuthMiddleware } from 'better-auth/plugins';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import {
  AUTH_MODULE_OPTIONS,
  AuthModuleOptions,
  HOOK_KEY,
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
} from './auth.types';
import {
  toWebRequest,
  writeWebResponseToReply,
  normalizeBasePath,
} from './auth.utils';

/**
 * Hook handler function type
 */
type HookHandler = (ctx: HookEndpointContext) => void | Promise<void>;

/**
 * Better Auth hooks configuration type
 */
interface AuthHooksConfig {
  before?: AuthMiddleware;
  after?: AuthMiddleware;
}

/**
 * Hook configuration
 */
const HOOKS: Array<{
  metadataKey: symbol;
  hookType: keyof AuthHooksConfig;
}> = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: 'before' },
  { metadataKey: AFTER_HOOK_KEY, hookType: 'after' },
];

/**
 * AuthBootstrapService
 *
 * Responsible for Better Auth initialization:
 * - Mount Better Auth handler to Fastify
 * - Set up NestJS Hooks
 */
@Injectable()
export class AuthBootstrapService implements OnModuleInit {
  private readonly logger = new Logger(AuthBootstrapService.name);

  constructor(
    private readonly httpAdapterHost: HttpAdapterHost,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
    private readonly discoveryService: DiscoveryService,
    private readonly metadataScanner: MetadataScanner,
  ) {}

  /**
   * Module initialization
   */
  onModuleInit(): void {
    // 1. Set up Hooks
    this.setupHooks();

    // 2. Mount Better Auth handler
    this.mountAuthHandler();
  }

  /**
   * Set up NestJS Hooks
   */
  private setupHooks(): void {
    const providers = this.discoveryService
      .getProviders()
      .filter(
        ({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype),
      );

    const hasHookProviders = providers.length > 0;
    const authOptions = this.options.auth.options as
      | (BetterAuthOptions & { hooks?: AuthHooksConfig })
      | undefined;
    const hooksConfigured = typeof authOptions?.hooks === 'object';

    // Check if Hook Providers exist but hooks are not configured
    if (hasHookProviders && !hooksConfigured) {
      throw new Error(
        "Detected @Hook providers but Better Auth 'hooks' are not configured. " +
          "Add 'hooks: {}' to your betterAuth(...) options.",
      );
    }

    if (!hooksConfigured || !authOptions?.hooks) return;

    // Register all Hooks
    for (const provider of providers) {
      const providerInstance = provider.instance as Record<string, HookHandler>;
      const providerPrototype = Object.getPrototypeOf(
        providerInstance,
      ) as Record<string, HookHandler>;
      const methods = this.metadataScanner.getAllMethodNames(providerPrototype);
      // Get provider name from metatype (guaranteed to exist by filter above)
      const providerName = provider.metatype?.name ?? 'UnknownProvider';

      for (const method of methods) {
        const providerMethod = providerPrototype[method];
        if (typeof providerMethod === 'function') {
          this.registerHook(
            providerMethod,
            providerInstance,
            authOptions.hooks,
            providerName,
            method,
          );
        }
      }
    }

    if (providers.length > 0) {
      this.logger.log(`Registered ${providers.length} auth hook provider(s)`);
    }
  }

  /**
   * Hook method registration
   * Wraps hooks with error handling to prevent one hook from breaking others
   */
  private registerHook(
    providerMethod: HookHandler,
    providerInstance: Record<string, HookHandler>,
    hooks: AuthHooksConfig,
    providerName: string,
    methodName: string,
  ): void {
    for (const { metadataKey, hookType } of HOOKS) {
      const hasHook = Reflect.hasMetadata(metadataKey, providerMethod);
      if (!hasHook) continue;

      const hookPath = Reflect.getMetadata(metadataKey, providerMethod) as
        | string
        | undefined;
      const originalHook = hooks[hookType];

      hooks[hookType] = createAuthMiddleware(async (ctx) => {
        // Execute original hook first with error handling
        if (originalHook) {
          try {
            await (originalHook as (ctx: HookEndpointContext) => Promise<void>)(
              ctx,
            );
          } catch (error) {
            // Log but don't rethrow - allow other hooks to execute
            this.logHookError('original', hookType, ctx.path, error);
          }
        }

        // If path is specified, only execute when matching
        if (hookPath && hookPath !== ctx.path) return;

        // Execute NestJS hook with error handling
        try {
          await providerMethod.apply(providerInstance, [ctx]);
        } catch (error) {
          // Log with context but sanitize error details
          this.logHookError(
            `${providerName}.${methodName}`,
            hookType,
            ctx.path,
            error,
          );
          // Re-throw for NestJS hooks since they may be critical
          throw error;
        }
      });
    }
  }

  /**
   * Log hook errors safely without exposing sensitive information
   */
  private logHookError(
    hookName: string,
    hookType: string,
    path: string,
    error: unknown,
  ): void {
    // Only log error message, not full stack trace in production
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error';

    if (this.options.debug) {
      // In debug mode, log full error
      this.logger.error(
        `Hook error [${hookType}] ${hookName} for path ${path}`,
        error instanceof Error ? error.stack : error,
      );
    } else {
      // In production, only log minimal info
      this.logger.error(
        `Hook error [${hookType}] ${hookName} for path ${path}: ${errorMessage}`,
      );
    }
  }

  /**
   * Get normalized basePath
   * Priority: options.basePath > auth.options.basePath > default value
   */
  private getBasePath(): string {
    const authOptions = this.options.auth.options as
      | { basePath?: string }
      | undefined;
    const rawBasePath =
      this.options.basePath ?? authOptions?.basePath ?? '/api/auth';
    return normalizeBasePath(rawBasePath);
  }

  /**
   * Mount Better Auth handler to Fastify
   */
  private mountAuthHandler() {
    const basePath = this.getBasePath();
    const fastify: FastifyInstance =
      this.httpAdapterHost.httpAdapter.getInstance();

    // Mount Better Auth handler
    fastify.route({
      method: ['GET', 'POST'],
      url: `${basePath}/*`,
      handler: this.createAuthHandler(),
    });

    this.logger.log(`Better Auth mounted on ${basePath}/*`);
  }

  /**
   * Create Better Auth request handler
   *
   * Converts Fastify request to Web standard Request,
   * calls Better Auth handler,
   * converts Web Response back to Fastify Reply
   */
  private createAuthHandler() {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const handleRequest = async () => {
        try {
          // 1. Convert to Web standard Request
          const webRequest = toWebRequest(request);

          // 2. Call Better Auth handler
          const response = await this.options.auth.handler(webRequest);

          // 3. Write Web Response to Fastify Reply
          await writeWebResponseToReply(response, reply);
        } catch (error) {
          // Log error safely without exposing sensitive details
          this.logAuthError(error);

          return reply.status(500).send({
            statusCode: 500,
            code: 'AUTH_ERROR',
            message: 'Internal authentication error',
          });
        }
      };

      // Support custom middleware wrapping
      if (this.options.middleware) {
        return this.options.middleware(request, reply, handleRequest);
      }

      return handleRequest();
    };
  }

  /**
   * Log auth handler errors safely
   */
  private logAuthError(error: unknown): void {
    if (this.options.debug) {
      // In debug mode, log full error
      this.logger.error(
        'Auth handler error:',
        error instanceof Error ? error.stack : error,
      );
    } else {
      // In production, only log error type and message
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(`Auth handler error: ${errorMessage}`);
    }
  }
}
