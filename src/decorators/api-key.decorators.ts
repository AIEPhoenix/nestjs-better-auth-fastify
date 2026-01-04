import { SetMetadata, CustomDecorator } from '@nestjs/common';
import {
  BEARER_AUTH_KEY,
  API_KEY_AUTH_KEY,
  ApiKeyAuthMetadata,
} from './common';

export const BearerAuth = (): CustomDecorator<string> =>
  SetMetadata(BEARER_AUTH_KEY, true);

export function ApiKeyAuth(
  options: ApiKeyAuthMetadata = {},
): CustomDecorator<string> {
  return SetMetadata(API_KEY_AUTH_KEY, options);
}
