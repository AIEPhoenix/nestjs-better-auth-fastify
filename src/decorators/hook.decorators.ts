import { SetMetadata, CustomDecorator } from '@nestjs/common';
import { HOOK_KEY, BEFORE_HOOK_KEY, AFTER_HOOK_KEY } from './common';

export const Hook = (): ClassDecorator => SetMetadata(HOOK_KEY, true);

export const BeforeHook = (path?: `/${string}`): CustomDecorator<symbol> =>
  SetMetadata(BEFORE_HOOK_KEY, path);

export const AfterHook = (path?: `/${string}`): CustomDecorator<symbol> =>
  SetMetadata(AFTER_HOOK_KEY, path);
