import { SetMetadata, CustomDecorator } from '@nestjs/common';
import { API_KEY_AUTH_KEY, ApiKeyAuthMetadata } from './common';

export function ApiKeyAuth(
  options: ApiKeyAuthMetadata = {},
): CustomDecorator<string> {
  return SetMetadata(API_KEY_AUTH_KEY, options);
}
