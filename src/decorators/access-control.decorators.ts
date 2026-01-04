import { SetMetadata, CustomDecorator } from '@nestjs/common';
import {
  RolesOptions,
  PermissionsOptions,
  FreshSessionOptions,
} from '../auth.types';
import {
  ALLOW_ANONYMOUS_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  RolesMetadata,
  PermissionsMetadata,
  FreshSessionMetadata,
} from './common';

export const AllowAnonymous = (): CustomDecorator<string> =>
  SetMetadata(ALLOW_ANONYMOUS_KEY, true);

export const OptionalAuth = (): CustomDecorator<string> =>
  SetMetadata(OPTIONAL_AUTH_KEY, true);

export function Roles(
  roles: string[],
  options: RolesOptions = {},
): CustomDecorator<string> {
  const metadata: RolesMetadata = {
    roles,
    options: { mode: 'any', ...options },
  };
  return SetMetadata(ROLES_KEY, metadata);
}

export function Permissions(
  permissions: string[],
  options: PermissionsOptions = {},
): CustomDecorator<string> {
  const metadata: PermissionsMetadata = {
    permissions,
    options: { mode: 'any', ...options },
  };
  return SetMetadata(PERMISSIONS_KEY, metadata);
}

export function RequireFreshSession(
  options: FreshSessionOptions = {},
): CustomDecorator<string> {
  const metadata: FreshSessionMetadata = { options };
  return SetMetadata(FRESH_SESSION_KEY, metadata);
}

/** @deprecated Use AllowAnonymous instead */
export const Public = AllowAnonymous;

/** @deprecated Use OptionalAuth instead */
export const Optional = OptionalAuth;
