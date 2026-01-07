import { ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import {
  RolesOptions,
  PermissionsOptions,
  FreshSessionOptions,
  OrgPermissionOptions,
  ApiKeyPermissionOptions,
} from '../auth.types';

interface GqlContext {
  req: FastifyRequest;
}

interface GqlExecutionContextClass {
  create(context: ExecutionContext): {
    getContext<T = object>(): T;
  };
}

let cachedGqlExecutionContext: GqlExecutionContextClass | null = null;

function getGqlExecutionContext(): GqlExecutionContextClass {
  if (cachedGqlExecutionContext) {
    return cachedGqlExecutionContext;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const graphqlModule = require('@nestjs/graphql') as {
      GqlExecutionContext: GqlExecutionContextClass;
    };
    cachedGqlExecutionContext = graphqlModule.GqlExecutionContext;
    return cachedGqlExecutionContext;
  } catch {
    throw new Error(
      'GraphQL context detected but @nestjs/graphql is not installed. ' +
        'Please install it: pnpm add @nestjs/graphql graphql',
    );
  }
}

export const ALLOW_ANONYMOUS_KEY = 'auth:allowAnonymous';
export const OPTIONAL_AUTH_KEY = 'auth:optional';
export const ROLES_KEY = 'auth:roles';
export const PERMISSIONS_KEY = 'auth:permissions';
export const FRESH_SESSION_KEY = 'auth:freshSession';
export const ADMIN_ONLY_KEY = 'auth:adminOnly';
export const BAN_CHECK_KEY = 'auth:banCheck';
export const API_KEY_AUTH_KEY = 'auth:apiKeyAuth';
export const DISALLOW_IMPERSONATION_KEY = 'auth:disallowImpersonation';
export const ORG_REQUIRED_KEY = 'auth:orgRequired';
export const LOAD_ORG_KEY = 'auth:loadOrg';
export const ORG_ROLES_KEY = 'auth:orgRoles';
export const ORG_PERMISSIONS_KEY = 'auth:orgPermissions';
export const HOOK_KEY = Symbol('auth:hook');
export const BEFORE_HOOK_KEY = Symbol('auth:beforeHook');
export const AFTER_HOOK_KEY = Symbol('auth:afterHook');

export interface RolesMetadata {
  roles: string[];
  options: RolesOptions;
}

export interface PermissionsMetadata {
  permissions: string[];
  options: PermissionsOptions;
}

export interface FreshSessionMetadata {
  options: FreshSessionOptions;
}

export interface ApiKeyAuthMetadata {
  allowSession?: boolean;
  permissions?: ApiKeyPermissionOptions;
}

export interface OrgRolesMetadata {
  roles: string[];
  options: RolesOptions;
}

export interface OrgPermissionsMetadata {
  options: OrgPermissionOptions;
}

interface WsData {
  request?: FastifyRequest;
  req?: FastifyRequest;
  handshake?: {
    headers?: Record<string, string | string[] | undefined>;
  };
}

/**
 * Extract FastifyRequest from NestJS ExecutionContext.
 * Supports HTTP, GraphQL, and WebSocket contexts.
 *
 * @throws Error if GraphQL context detected but @nestjs/graphql not installed
 */
export function getRequestFromContext(ctx: ExecutionContext): FastifyRequest {
  const contextType = ctx.getType<string>();

  if (contextType === 'graphql') {
    const GqlExecutionContext = getGqlExecutionContext();
    const gqlContext = GqlExecutionContext.create(ctx).getContext<GqlContext>();
    return gqlContext.req;
  }

  if (contextType === 'ws') {
    const wsContext = ctx.switchToWs();

    const data = wsContext.getData<WsData>();
    if (data?.request) {
      return data.request;
    }
    if (data?.req) {
      return data.req;
    }

    const client = wsContext.getClient<{ handshake?: WsData['handshake'] }>();
    if (client?.handshake?.headers) {
      return {
        method: 'GET',
        url: '/ws',
        protocol: 'ws',
        headers: client.handshake.headers,
        session: null,
        user: null,
        apiKey: null,
        organization: null,
        organizationMember: null,
        isImpersonating: false,
        impersonatedBy: null,
      } as unknown as FastifyRequest;
    }

    return ctx.switchToHttp().getRequest<FastifyRequest>();
  }

  return ctx.switchToHttp().getRequest<FastifyRequest>();
}
