import { Injectable, Logger } from '@nestjs/common';
import { Hook, BeforeHook, AfterHook } from '@sapix/nestjs-better-auth-fastify';
import type { EnhancedAuthHookContext } from '@sapix/nestjs-better-auth-fastify';

/**
 * Authentication Hooks Service
 * Demonstrates usage of @Hook, @BeforeHook, @AfterHook decorators
 * to listen for various Better Auth authentication route events
 *
 * Common paths:
 * - /sign-up/email - Email registration
 * - /sign-in/email - Email login
 * - /sign-out - Sign out
 * - /forget-password - Forgot password
 * - /reset-password - Reset password
 * - /verify-email - Email verification
 * - /session - Get session
 */
@Hook()
@Injectable()
export class AuthHooksService {
  private readonly logger = new Logger(AuthHooksService.name);

  // ============================================
  // User Registration Hooks
  // ============================================

  /**
   * Before user registration hook
   * Can validate or modify data before user creation
   */
  @BeforeHook('/sign-up/email')
  async beforeSignUp(ctx: EnhancedAuthHookContext) {
    const body = ctx.body as {
      email?: string;
      name?: string;
      password?: string;
    };
    this.logger.log(`[BeforeHook] Before user registration: ${body.email}`);

    // Example: Check if email domain is allowed
    if (body.email) {
      const blockedDomains = ['spam.com', 'temp-mail.com'];
      const domain = body.email.split('@')[1];

      if (blockedDomains.includes(domain)) {
        this.logger.warn(
          `[BeforeHook] Registration blocked - forbidden email domain: ${domain}`,
        );
        // Can throw error to prevent registration
        // throw new Error('This email domain is not allowed for registration');
      }
    }
  }

  /**
   * After user registration hook
   * Can perform follow-up actions like sending welcome emails
   */
  @AfterHook('/sign-up/email')
  async afterSignUp(ctx: EnhancedAuthHookContext) {
    const newSession = ctx.context?.newSession;
    if (newSession) {
      this.logger.log(
        `[AfterHook] User registration successful: ${newSession.user.email} (ID: ${newSession.user.id})`,
      );

      // Example: Send welcome email
      // await this.emailService.sendWelcomeEmail(newSession.user.email, newSession.user.name);

      // Example: Track in analytics
      // await this.analyticsService.track('user.signup', { userId: newSession.user.id });
    }
  }

  // ============================================
  // User Login Hooks
  // ============================================

  /**
   * Before user login hook
   */
  @BeforeHook('/sign-in/email')
  async beforeSignIn(ctx: EnhancedAuthHookContext) {
    const body = ctx.body as { email?: string };
    this.logger.log(`[BeforeHook] Before user login: ${body.email}`);

    // Example: Check rate limiting
    // const attempts = await this.rateLimitService.getLoginAttempts(body.email);
    // if (attempts > 5) {
    //   throw new Error('Too many login attempts, please try again later');
    // }
  }

  /**
   * After user login hook
   */
  @AfterHook('/sign-in/email')
  async afterSignIn(ctx: EnhancedAuthHookContext) {
    const newSession = ctx.context?.newSession;
    if (newSession) {
      this.logger.log(
        `[AfterHook] User login successful: ${newSession.user.email} (Session: ${newSession.session.id})`,
      );

      // Example: Update last login time
      // await this.userService.updateLastLogin(newSession.user.id);

      // Example: Record login audit log
      // await this.auditLogService.log({
      //   action: 'user.login',
      //   userId: newSession.user.id,
      //   sessionId: newSession.session.id,
      //   timestamp: new Date(),
      // });
    }
  }

  // ============================================
  // Session Hooks
  // ============================================

  /**
   * Get session hook
   */
  @AfterHook('/session')
  async afterGetSession(ctx: EnhancedAuthHookContext) {
    const newSession = ctx.context?.newSession;
    if (newSession) {
      this.logger.debug(
        `[AfterHook] Session retrieved: ${newSession.session.id} (User: ${newSession.user.id})`,
      );
    }
  }

  /**
   * User sign out hook
   */
  @AfterHook('/sign-out')
  async afterSignOut(_ctx: EnhancedAuthHookContext) {
    this.logger.log(`[AfterHook] User signed out`);

    // Example: Clear session-related cache
    // await this.cacheService.clearUserCache(userId);
  }

  // ============================================
  // Password Hooks
  // ============================================

  /**
   * Forgot password request hook
   */
  @AfterHook('/forget-password')
  async afterForgetPassword(ctx: EnhancedAuthHookContext) {
    const body = ctx.body as { email?: string };
    this.logger.log(`[AfterHook] Password reset requested: ${body.email}`);

    // Example: Send password reset email (Better Auth may handle this)
    // await this.emailService.sendPasswordResetEmail(body.email, token);
  }

  /**
   * Password reset completed hook
   */
  @AfterHook('/reset-password')
  async afterResetPassword(_ctx: EnhancedAuthHookContext) {
    this.logger.log(`[AfterHook] Password reset completed`);

    // Example: Revoke all existing sessions
    // await this.sessionService.revokeAllSessions(userId);

    // Example: Send password change notification
    // await this.emailService.sendPasswordChangedNotification(email);
  }

  /**
   * Password change hook
   */
  @AfterHook('/change-password')
  async afterChangePassword(_ctx: EnhancedAuthHookContext) {
    this.logger.log(`[AfterHook] Password changed`);

    // Example: Record audit log
    // await this.auditLogService.log({
    //   action: 'password.change',
    //   userId: userId,
    //   timestamp: new Date(),
    // });
  }

  // ============================================
  // Email Verification Hooks
  // ============================================

  /**
   * Email verification completed hook
   */
  @AfterHook('/verify-email')
  async afterVerifyEmail(_ctx: EnhancedAuthHookContext) {
    this.logger.log(`[AfterHook] Email verification completed`);

    // Example: Unlock certain features
    // await this.userService.unlockVerifiedFeatures(userId);
  }

  // ============================================
  // Generic Hooks
  // ============================================

  /**
   * Generic Before hook - Matches all auth routes
   * Suitable for global logging
   */
  @BeforeHook()
  async beforeAllAuth(ctx: EnhancedAuthHookContext) {
    this.logger.debug(`[BeforeHook] Auth request: ${ctx.path}`);
  }

  /**
   * Generic After hook - Matches all auth routes
   * Suitable for global logging
   */
  @AfterHook()
  async afterAllAuth(ctx: EnhancedAuthHookContext) {
    this.logger.debug(`[AfterHook] Auth response: ${ctx.path}`);
  }

  // ============================================
  // Two-Factor Authentication Hooks (requires twoFactor plugin)
  // ============================================

  /**
   * Two-factor authentication enabled hook
   */
  @AfterHook('/two-factor/enable')
  async afterEnable2FA(_ctx: EnhancedAuthHookContext) {
    this.logger.log(`[AfterHook] Two-factor authentication enabled`);

    // Example: Send notification
    // await this.notificationService.send2FAEnabledNotification(userId);
  }

  /**
   * Two-factor authentication disabled hook
   */
  @AfterHook('/two-factor/disable')
  async afterDisable2FA(_ctx: EnhancedAuthHookContext) {
    this.logger.log(`[AfterHook] Two-factor authentication disabled`);

    // Example: Security audit
    // await this.auditLogService.log({
    //   action: '2fa.disabled',
    //   userId: userId,
    //   timestamp: new Date(),
    // });
  }

  // ============================================
  // Organization Hooks (requires organization plugin)
  // ============================================

  /**
   * Organization created hook
   */
  @AfterHook('/organization/create')
  async afterCreateOrganization(ctx: EnhancedAuthHookContext) {
    const body = ctx.body as { name?: string };
    this.logger.log(`[AfterHook] Organization created: ${body.name}`);

    // Example: Initialize organization resources
    // await this.organizationService.initializeResources(orgId);
  }

  /**
   * Member invitation hook
   */
  @AfterHook('/organization/invite-member')
  async afterInviteMember(ctx: EnhancedAuthHookContext) {
    const body = ctx.body as { email?: string };
    this.logger.log(`[AfterHook] Member invitation sent: ${body.email}`);

    // Example: Send invitation email (Better Auth may handle this)
    // await this.emailService.sendOrgInvitation(email, orgName);
  }
}
