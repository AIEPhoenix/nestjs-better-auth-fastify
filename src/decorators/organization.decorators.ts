import { SetMetadata, CustomDecorator } from '@nestjs/common';
import { RolesOptions, OrgPermissionOptions } from '../auth.types';
import {
  ORG_REQUIRED_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  OrgRolesMetadata,
  OrgPermissionsMetadata,
} from './common';

export const OrgRequired = (): CustomDecorator<string> =>
  SetMetadata(ORG_REQUIRED_KEY, true);

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
