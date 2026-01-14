import { SetMetadata, CustomDecorator } from '@nestjs/common';
import {
  RolesOptions,
  PermissionsOptions,
  FreshSessionOptions,
} from '../auth.types';
import {
  ALLOW_ANONYMOUS_KEY,
  REQUIRE_AUTH_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  RolesMetadata,
  PermissionsMetadata,
  FreshSessionMetadata,
} from './common';

/**
 * Mark route as public (no authentication required).
 * Session will still be attached to request if available.
 *
 * @example
 * ```typescript
 * @AllowAnonymous()
 * @Get('public')
 * publicRoute() {
 *   return 'Anyone can access this';
 * }
 * ```
 */
export const AllowAnonymous = (): CustomDecorator<string> =>
  SetMetadata(ALLOW_ANONYMOUS_KEY, true);

/**
 * Explicitly require authentication for this route.
 * Useful when defaultAuthBehavior is 'public' or 'optional'.
 *
 * @example
 * ```typescript
 * // In app.module.ts: defaultAuthBehavior: 'public'
 *
 * @RequireAuth()
 * @Get('protected')
 * protectedRoute(@CurrentUser() user: User) {
 *   return `Hello ${user.name}`;
 * }
 * ```
 */
export const RequireAuth = (): CustomDecorator<string> =>
  SetMetadata(REQUIRE_AUTH_KEY, true);

/**
 * Mark route as having optional authentication.
 * Session will be attached if available, but route is accessible without auth.
 *
 * @example
 * ```typescript
 * @OptionalAuth()
 * @Get('greeting')
 * greet(@CurrentUser() user: User | null) {
 *   return user ? `Hello ${user.name}` : 'Hello guest';
 * }
 * ```
 */
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
