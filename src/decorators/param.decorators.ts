import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { getRequestFromContext } from './common';
import type { AuthContext } from '../auth.types';

export type { AuthContext };

// ============================================
// Factory
// ============================================

export type AuthContextMapper<T> = (auth: AuthContext) => T;

export function createAuthParamDecorator<T>(
  mapper: AuthContextMapper<T>,
): () => ParameterDecorator {
  return createParamDecorator((_data: unknown, ctx: ExecutionContext): T => {
    const request = getRequestFromContext(ctx);
    const authContext: AuthContext = {
      session: request.session,
      user: request.user,
      organization: request.organization ?? null,
      orgMember: request.organizationMember ?? null,
      isImpersonating: request.isImpersonating ?? false,
      impersonatedBy: request.impersonatedBy ?? null,
      apiKey: request.apiKey ?? null,
    };
    return mapper(authContext);
  });
}

// ============================================
// Session
// ============================================

export const Session = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.session;
  },
);

export const SessionProperty = createParamDecorator(
  (property: string, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.session?.session?.[
      property as keyof typeof request.session.session
    ];
  },
);

// ============================================
// User
// ============================================

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.user;
  },
);

export const UserProperty = createParamDecorator(
  (property: string, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.user?.[property as keyof typeof request.user];
  },
);

// ============================================
// Organization
// ============================================

export const CurrentOrg = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.organization;
  },
);

export const OrgMember = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.organizationMember;
  },
);

// ============================================
// Admin / Impersonation
// ============================================

export const IsImpersonating = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.isImpersonating ?? false;
  },
);

export const ImpersonatedBy = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.impersonatedBy ?? null;
  },
);

// ============================================
// API Key
// ============================================

export const ApiKey = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.apiKey;
  },
);
