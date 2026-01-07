// Ensure reflect-metadata is loaded first
import 'reflect-metadata';

// ============================================
// Module
// ============================================
export { AuthModule } from './auth.module';

// ============================================
// Service
// ============================================
export { AuthService, type InferSession, type InferUser } from './auth.service';

// ============================================
// Guard
// ============================================
export { AuthGuard } from './auth.guard';

// ============================================
// Decorators - Access Control
// ============================================
export {
  AllowAnonymous,
  OptionalAuth,
  Roles,
  Permissions,
  RequireFreshSession,
} from './auth.decorators';

// ============================================
// Decorators - Admin Plugin
// ============================================
export {
  AdminOnly,
  BanCheck,
  DisallowImpersonation,
  SecureAdminOnly,
} from './auth.decorators';

// ============================================
// Decorators - API Key
// ============================================
export { ApiKeyAuth, ApiKey } from './auth.decorators';

// ============================================
// Decorators - Organization Plugin
// ============================================
export {
  OrgRequired,
  OptionalOrg,
  OrgRoles,
  OrgPermission,
  CurrentOrg,
  OrgMember,
} from './auth.decorators';

// ============================================
// Decorators - Session
// ============================================
export { Session, SessionProperty } from './auth.decorators';

// ============================================
// Decorators - User
// ============================================
export { CurrentUser, UserProperty } from './auth.decorators';

// ============================================
// Decorators - Admin / Impersonation
// ============================================
export { IsImpersonating, ImpersonatedBy } from './auth.decorators';

// ============================================
// Decorators - Factory
// ============================================
export {
  createAuthParamDecorator,
  type AuthContext,
  type AuthContextMapper,
} from './auth.decorators';

// ============================================
// Decorators - Hooks
// ============================================
export { Hook, BeforeHook, AfterHook } from './auth.decorators';

// ============================================
// Decorators - Utilities
// ============================================
export { getRequestFromContext } from './auth.decorators';

// ============================================
// Decorators - Metadata Keys
// ============================================
export {
  ALLOW_ANONYMOUS_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  API_KEY_AUTH_KEY,
  DISALLOW_IMPERSONATION_KEY,
  ORG_REQUIRED_KEY,
  LOAD_ORG_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
} from './auth.decorators';

// ============================================
// Decorators - Metadata Types
// ============================================
export type {
  RolesMetadata,
  PermissionsMetadata,
  FreshSessionMetadata,
  ApiKeyAuthMetadata,
  OrgRolesMetadata,
  OrgPermissionsMetadata,
} from './auth.decorators';

// ============================================
// Types - Module Options
// ============================================
export {
  AUTH_MODULE_OPTIONS,
  type AuthModuleOptions,
  type AuthModuleAsyncOptions,
  type AuthModuleOptionsFactory,
  type AuthErrorMessages,
  type OrgRolePermissions,
} from './auth.types';

// ============================================
// Types - Session & User
// ============================================
export {
  type UserSession,
  type BaseUser,
  type AdminUser,
  type BaseSession,
  type AdminSession,
} from './auth.types';

// ============================================
// Types - Hooks
// ============================================
export {
  type AuthHookContext,
  type EnhancedAuthHookContext,
} from './auth.types';

export { HOOK_KEY, BEFORE_HOOK_KEY, AFTER_HOOK_KEY } from './auth.decorators';

// ============================================
// Types - Decorator Options
// ============================================
export {
  type RolesOptions,
  type PermissionsOptions,
  type FreshSessionOptions,
  type OrgPermissionOptions,
  type ApiKeyPermissionOptions,
} from './auth.types';

// ============================================
// Types - Organization Plugin
// ============================================
export { type Organization, type OrganizationMember } from './auth.types';

// ============================================
// Types - API Key Plugin
// ============================================
export { type ApiKeyValidation } from './auth.types';

// ============================================
// Types - Auth Methods
// ============================================
export { type AuthMethod, type AuthResult } from './auth.types';

// ============================================
// Utilities
// ============================================
export {
  toWebHeaders,
  toWebRequest,
  getHeadersFromRequest,
  getWebHeadersFromRequest,
  writeWebResponseToReply,
  normalizeBasePath,
  parseStringToArray,
} from './auth.utils';
