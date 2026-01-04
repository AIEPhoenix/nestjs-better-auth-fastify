import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { getRequestFromContext } from './common';

export const Session = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.session;
  },
);

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

export const ApiKey = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const request = getRequestFromContext(ctx);
    return request.apiKey;
  },
);

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
