import { SetMetadata, CustomDecorator } from '@nestjs/common';
import { RolesOptions, OrgPermissionOptions } from '../auth.types';
import {
  ORG_REQUIRED_KEY,
  LOAD_ORG_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  OrgRolesMetadata,
  OrgPermissionsMetadata,
} from './common';

export const OrgRequired = (): CustomDecorator<string> =>
  SetMetadata(ORG_REQUIRED_KEY, true);

/**
 * Optionally load organization context if available, but don't require it.
 * Use this when you need to access org data but the route should be accessible
 * to users without an active organization.
 *
 * @example
 * ```typescript
 * @OptionalOrg()
 * @Get('resources')
 * getResources(@CurrentUser() user, @CurrentOrg() org) {
 *   if (org) {
 *     return this.getOrgResources(org.id);
 *   }
 *   return this.getUserResources(user.id);
 * }
 * ```
 */
export const OptionalOrg = (): CustomDecorator<string> =>
  SetMetadata(LOAD_ORG_KEY, true);

export function OrgRoles(
  roles: string[],
  options: RolesOptions = {},
): CustomDecorator<string> {
  const metadata: OrgRolesMetadata = {
    roles,
    options: { mode: 'any', ...options },
  };
  return SetMetadata(ORG_ROLES_KEY, metadata);
}

export function OrgPermission(
  options: OrgPermissionOptions,
): CustomDecorator<string> {
  const metadata: OrgPermissionsMetadata = { options };
  return SetMetadata(ORG_PERMISSIONS_KEY, metadata);
}
