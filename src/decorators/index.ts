// ============================================
// Common / Utilities
// ============================================
export { getRequestFromContext } from './common';

// ============================================
// Metadata Keys
// ============================================
export {
  ALLOW_ANONYMOUS_KEY,
  REQUIRE_AUTH_KEY,
  OPTIONAL_AUTH_KEY,
  ROLES_KEY,
  PERMISSIONS_KEY,
  FRESH_SESSION_KEY,
  ADMIN_ONLY_KEY,
  BAN_CHECK_KEY,
  DISALLOW_IMPERSONATION_KEY,
  API_KEY_AUTH_KEY,
  ORG_REQUIRED_KEY,
  LOAD_ORG_KEY,
  ORG_ROLES_KEY,
  ORG_PERMISSIONS_KEY,
  HOOK_KEY,
  BEFORE_HOOK_KEY,
  AFTER_HOOK_KEY,
} from './common';

// ============================================
// Metadata Types
// ============================================
export type {
  RolesMetadata,
  PermissionsMetadata,
  FreshSessionMetadata,
  ApiKeyAuthMetadata,
  OrgRolesMetadata,
  OrgPermissionsMetadata,
} from './common';

// ============================================
// Access Control Decorators
// ============================================
export {
  AllowAnonymous,
  RequireAuth,
  OptionalAuth,
  Roles,
  Permissions,
  RequireFreshSession,
} from './access-control.decorators';

// ============================================
// Admin Plugin Decorators
// ============================================
export {
  AdminOnly,
  BanCheck,
  DisallowImpersonation,
  SecureAdminOnly,
} from './admin.decorators';

// ============================================
// API Key Decorators
// ============================================
export { ApiKeyAuth } from './api-key.decorators';

// ============================================
// Organization Plugin Decorators
// ============================================
export {
  OrgRequired,
  OptionalOrg,
  OrgRoles,
  OrgPermission,
} from './organization.decorators';

// ============================================
// Parameter Decorators - Factory
// ============================================
export {
  createAuthParamDecorator,
  type AuthContext,
  type AuthContextMapper,
} from './param.decorators';

// ============================================
// Parameter Decorators - Session
// ============================================
export { Session, SessionProperty } from './param.decorators';

// ============================================
// Parameter Decorators - User
// ============================================
export { CurrentUser, UserProperty } from './param.decorators';

// ============================================
// Parameter Decorators - Organization
// ============================================
export { CurrentOrg, OrgMember } from './param.decorators';

// ============================================
// Parameter Decorators - Admin / Impersonation
// ============================================
export { IsImpersonating, ImpersonatedBy } from './param.decorators';

// ============================================
// Parameter Decorators - API Key
// ============================================
export { ApiKey } from './param.decorators';

// ============================================
// Hook Decorators
// ============================================
export { Hook, BeforeHook, AfterHook } from './hook.decorators';
