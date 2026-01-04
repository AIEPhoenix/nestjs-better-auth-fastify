import { SetMetadata, CustomDecorator, applyDecorators } from '@nestjs/common';
import {
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  DISALLOW_IMPERSONATION_KEY,
} from './common';
import { RequireFreshSession } from './access-control.decorators';

export function AdminOnly(message?: string): CustomDecorator<string> {
  return SetMetadata(ADMIN_ONLY_KEY, { message });
}

export const BanCheck = (): CustomDecorator<string> =>
  SetMetadata(BAN_CHECK_KEY, true);

export function DisallowImpersonation(
  message?: string,
): CustomDecorator<string> {
  return SetMetadata(DISALLOW_IMPERSONATION_KEY, { message });
}

export function SecureAdminOnly() {
  return applyDecorators(
    AdminOnly(),
    RequireFreshSession(),
    DisallowImpersonation(),
  );
}
