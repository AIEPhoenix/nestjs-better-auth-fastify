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
// Decorators - Route
// ============================================
export {
  // Basic auth decorators
  AllowAnonymous,
  OptionalAuth,
  Roles,
  Permissions,
  // Session freshness
  RequireFreshSession,
  // Admin plugin decorators
  AdminOnly,
  BanCheck,
  DisallowImpersonation,
  // Alternative auth methods
  BearerAuth,
  ApiKeyAuth,
  // Organization plugin decorators
  OrgRequired,
  OrgRoles,
  OrgPermission,
  // Composite decorators
  SecureAdminOnly,
  // Parameter decorators
  Session,
  CurrentUser,
  UserProperty,
  ApiKey,
  CurrentOrg,
  OrgMember,
  IsImpersonating,
  ImpersonatedBy,
  // Hook decorators
  Hook,
  BeforeHook,
  AfterHook,
  // Utility
  getRequestFromContext,
  // Metadata keys (for advanced use)
  ALLOW_ANONYMOUS_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  BEARER_AUTH_KEY,
  API_KEY_AUTH_KEY,
  DISALLOW_IMPERSONATION_KEY,
  ORG_REQUIRED_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  // Metadata types
  type RolesMetadata,
  type PermissionsMetadata,
  type FreshSessionMetadata,
  type ApiKeyAuthMetadata,
  type OrgRolesMetadata,
  type OrgPermissionsMetadata,
  // Deprecated aliases
  Public,
  Optional,
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
  HOOK_KEY,
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
  type AuthHookContext,
  type EnhancedAuthHookContext,
} from './auth.types';

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
} from './auth.utils';
