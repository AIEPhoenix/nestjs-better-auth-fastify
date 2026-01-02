/**
 * UserController E2E Tests
 *
 * Tests using real better-auth
 * Covers roles, permissions, session freshness, and more
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  createTestUser,
  createUserWithRole,
  createUserWithPermissions,
  generateTestEmail,
  authenticatedRequest,
  setUserPermissions,
  banUser,
} from './setup/test-utils';

describe('UserController (e2e) - Real better-auth', () => {
  let app: NestFastifyApplication;
  let userCookies: string[];
  let userEmail: string;
  let userId: string;

  beforeAll(async () => {
    app = await createTestApp();

    // Create a test user
    userEmail = generateTestEmail('user');
    const { cookies, user } = await createTestUser(app, {
      email: userEmail,
      password: 'Test123!',
      name: 'Test User',
    });
    userCookies = cookies;
    userId = user.id;
  });

  afterAll(async () => {
    await closeTestApp();
  });

  describe('Public and Optional Auth Routes', () => {
    it('GET /users/public-info - should return 200 without auth (@AllowAnonymous)', async () => {
      const response = await request(app.getHttpServer())
        .get('/users/public-info')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('serverTime');
    });

    it('GET /users/optional-profile - should return 200 without auth (@OptionalAuth)', async () => {
      const response = await request(app.getHttpServer())
        .get('/users/optional-profile')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.isGuest).toBe(true);
    });

    it('GET /users/optional-profile - should return user info when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/optional-profile')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(userEmail);
      expect(response.body.isGuest).toBeUndefined();
    });
  });

  describe('Protected Routes', () => {
    it('GET /users/profile - should return 401 without auth', async () => {
      await request(app.getHttpServer()).get('/users/profile').expect(401);
    });

    it('GET /users/profile - should return profile with valid session', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/profile')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('session');
      expect(response.body.session.email).toBe(userEmail);
    });

    it('GET /users/me - should return 401 without auth', async () => {
      await request(app.getHttpServer()).get('/users/me').expect(401);
    });

    it('GET /users/me - should return current user info', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/me')
        .expect(200);

      expect(response.body.email).toBe(userEmail);
      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('name');
    });
  });

  describe('Role-Based Access Control (@Roles)', () => {
    it('GET /users/moderator-area - should return 403 for regular user (no moderator role)', async () => {
      // Regular user role is 'user', moderator-area requires 'moderator' or 'admin'
      const response = await authenticatedRequest(app, userCookies).get(
        '/users/moderator-area',
      );

      expect(response.status).toBe(403);
    });

    it('GET /users/moderator-area - should return 200 for moderator user', async () => {
      const { cookies } = await createUserWithRole(app, {
        email: generateTestEmail('moderator'),
        password: 'Test123!',
        name: 'Moderator User',
        role: 'moderator',
      });

      const response = await authenticatedRequest(app, cookies).get(
        '/users/moderator-area',
      );

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message');
    });

    it('GET /users/moderator-area - should return 200 for admin user', async () => {
      const { cookies } = await createUserWithRole(app, {
        email: generateTestEmail('admin-mod'),
        password: 'Test123!',
        name: 'Admin User',
        role: 'admin',
      });

      const response = await authenticatedRequest(app, cookies).get(
        '/users/moderator-area',
      );

      expect(response.status).toBe(200);
    });
  });

  describe('Permission-Based Access Control (@Permissions)', () => {
    it('GET /users/reports - should return 403 without read:reports permission', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/users/reports')
        .expect(403);
    });

    it('GET /users/reports - should return 200 with read:reports permission', async () => {
      const { cookies } = await createUserWithPermissions(app, {
        email: generateTestEmail('reports'),
        password: 'Test123!',
        name: 'Reports User',
        permissions: ['read:reports'],
      });

      const response = await authenticatedRequest(app, cookies).get(
        '/users/reports',
      );

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message');
    });

    it('GET /users/analytics - should return 403 without required permissions', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/users/analytics')
        .expect(403);
    });

    it('GET /users/analytics - should return 200 with all required permissions', async () => {
      const { cookies } = await createUserWithPermissions(app, {
        email: generateTestEmail('analytics'),
        password: 'Test123!',
        name: 'Analytics User',
        permissions: ['read:analytics', 'read:reports'],
      });

      const response = await authenticatedRequest(app, cookies).get(
        '/users/analytics',
      );

      expect(response.status).toBe(200);
    });
  });

  describe('Fresh Session Requirement (@RequireFreshSession)', () => {
    it('POST /users/change-password - should work with fresh session', async () => {
      // Creating new user gets a fresh session
      const email = generateTestEmail('fresh');
      const { cookies } = await createTestUser(app, {
        email,
        password: 'Test123!',
        name: 'Fresh Session User',
      });

      // Fresh session should be accepted
      const response = await authenticatedRequest(app, cookies)
        .post('/users/change-password')
        .send({
          currentPassword: 'Test123!',
          newPassword: 'NewPass123!',
        });

      // Accept 200 or 201
      expect([200, 201]).toContain(response.status);
      expect(response.body).toHaveProperty('message');
      expect(response.body.user).toBe(email);
    });
  });

  describe('Impersonation Checks', () => {
    it('GET /users/session-info - should return impersonation info', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/session-info')
        .expect(200);

      expect(response.body).toHaveProperty('user');
      expect(response.body).toHaveProperty('session');
      expect(response.body).toHaveProperty('impersonation');
      expect(response.body.impersonation.isImpersonating).toBe(false);
      expect(response.body.impersonation.impersonatedByAdminId).toBeNull();
    });

    it('GET /users/security-settings - should return 200 when not impersonating', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/security-settings')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.user).toBe(userEmail);
    });
  });

  describe('Combined Guards', () => {
    it('POST /users/sensitive-action - should return 403 for regular user (missing role)', async () => {
      await authenticatedRequest(app, userCookies)
        .post('/users/sensitive-action')
        .send({ action: 'test' })
        .expect(403);
    });

    it('POST /users/sensitive-action - should return 403 for admin without permission', async () => {
      const { cookies } = await createUserWithRole(app, {
        email: generateTestEmail('admin-no-perm'),
        password: 'Test123!',
        name: 'Admin No Perm',
        role: 'admin',
      });

      await authenticatedRequest(app, cookies)
        .post('/users/sensitive-action')
        .send({ action: 'test' })
        .expect(403);
    });

    it('POST /users/sensitive-action - should return 200/201 for admin with permission', async () => {
      const email = generateTestEmail('admin-perm');
      const { user } = await createUserWithRole(app, {
        email,
        password: 'Test123!',
        name: 'Admin With Perm',
        role: 'admin',
      });

      // Add correct permission (controller requires execute:sensitive-action)
      setUserPermissions(user.id, ['execute:sensitive-action']);

      // Re-login to get session with new permissions
      const loginResponse = await request(app.getHttpServer())
        .post('/api/auth/sign-in/email')
        .send({ email, password: 'Test123!' })
        .expect(200);

      const setCookieHeader = loginResponse.headers['set-cookie'];
      const cookieArray = Array.isArray(setCookieHeader)
        ? setCookieHeader
        : setCookieHeader
          ? [setCookieHeader]
          : [];
      const newCookies = cookieArray.map((c: string) => c.split(';')[0]);

      const response = await authenticatedRequest(app, newCookies)
        .post('/users/sensitive-action')
        .send({ action: 'test' });

      expect([200, 201]).toContain(response.status);
    });
  });

  describe('Ban Check (@BanCheck)', () => {
    it('should allow access for non-banned users', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/users/profile')
        .expect(200);
    });

    it('should deny access for banned users', async () => {
      const email = generateTestEmail('banned');
      const { cookies, user } = await createTestUser(app, {
        email,
        password: 'Test123!',
        name: 'Banned User',
      });

      // Ban user
      banUser(user.id, 'Test ban');

      // Try to access protected route
      const response = await authenticatedRequest(app, cookies).get(
        '/users/profile',
      );

      // Banned user should be rejected
      expect(response.status).toBe(403);
    });
  });

  describe('@UserProperty() Decorator Examples', () => {
    it('GET /users/my-id - should return user ID', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/my-id')
        .expect(200);

      expect(response.body).toHaveProperty('userId');
      expect(response.body.userId).toBe(userId);
    });

    it('GET /users/my-email - should return user email', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/my-email')
        .expect(200);

      expect(response.body).toHaveProperty('email');
      expect(response.body.email).toBe(userEmail);
    });

    it('GET /users/email-verified - should return email verification status', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/users/email-verified')
        .expect(200);

      expect(response.body).toHaveProperty('emailVerified');
      expect(response.body).toHaveProperty('message');
    });
  });

  describe('Roles Mode Options', () => {
    it('GET /users/any-role-check - should return 403 without matching role', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/users/any-role-check')
        .expect(403);
    });

    it('GET /users/any-role-check - should return 200 with vip role', async () => {
      const { cookies } = await createUserWithRole(app, {
        email: generateTestEmail('vip'),
        password: 'Test123!',
        name: 'VIP User',
        role: 'vip',
      });

      await authenticatedRequest(app, cookies)
        .get('/users/any-role-check')
        .expect(200);
    });

    it('GET /users/premium-content - should return 403 without premium role', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/users/premium-content')
        .expect(403);
    });

    it('GET /users/premium-content - should return 200 with premium role', async () => {
      const { cookies } = await createUserWithRole(app, {
        email: generateTestEmail('premium'),
        password: 'Test123!',
        name: 'Premium User',
        role: 'premium',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/users/premium-content')
        .expect(200);

      expect(response.body).toHaveProperty('content');
    });
  });

  describe('Permissions Mode Options', () => {
    it('GET /users/read-any - should return 403 without any read permission', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/users/read-any')
        .expect(403);
    });

    it('GET /users/read-any - should return 200 with any read permission', async () => {
      const { cookies } = await createUserWithPermissions(app, {
        email: generateTestEmail('read-any'),
        password: 'Test123!',
        name: 'Read Any User',
        permissions: ['read:comments'],
      });

      await authenticatedRequest(app, cookies)
        .get('/users/read-any')
        .expect(200);
    });

    it('GET /users/full-access - should return 403 without all required permissions', async () => {
      const { cookies } = await createUserWithPermissions(app, {
        email: generateTestEmail('partial-access'),
        password: 'Test123!',
        name: 'Partial Access User',
        permissions: ['read:posts', 'write:posts'], // Missing delete:posts
      });

      await authenticatedRequest(app, cookies)
        .get('/users/full-access')
        .expect(403);
    });

    it('GET /users/full-access - should return 200 with all required permissions', async () => {
      const { cookies } = await createUserWithPermissions(app, {
        email: generateTestEmail('full-access'),
        password: 'Test123!',
        name: 'Full Access User',
        permissions: ['read:posts', 'write:posts', 'delete:posts'],
      });

      await authenticatedRequest(app, cookies)
        .get('/users/full-access')
        .expect(200);
    });

    it('POST /users/publish - should require both write and publish permissions', async () => {
      // Only write permission
      const { cookies: writeOnly } = await createUserWithPermissions(app, {
        email: generateTestEmail('write-only'),
        password: 'Test123!',
        name: 'Write Only User',
        permissions: ['write:posts'],
      });

      await authenticatedRequest(app, writeOnly)
        .post('/users/publish')
        .send({ title: 'Test Post' })
        .expect(403);

      // Both permissions
      const { cookies: fullPerms } = await createUserWithPermissions(app, {
        email: generateTestEmail('full-publish'),
        password: 'Test123!',
        name: 'Full Publish User',
        permissions: ['write:posts', 'publish:posts'],
      });

      const response = await authenticatedRequest(app, fullPerms)
        .post('/users/publish')
        .send({ title: 'Test Post' });

      expect([200, 201]).toContain(response.status);
    });
  });

  describe('Fresh Session Options', () => {
    it('GET /users/account-settings - should work with fresh session', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('account-settings'),
        password: 'Test123!',
        name: 'Account Settings User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/users/account-settings')
        .expect(200);

      expect(response.body).toHaveProperty('settings');
    });

    it('POST /users/delete-account - should require very fresh session', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('delete-account'),
        password: 'Test123!',
        name: 'Delete Account User',
      });

      // Immediately after login, session should be fresh enough
      const response = await authenticatedRequest(app, cookies).post(
        '/users/delete-account',
      );

      // Should work with fresh session (created within 1 minute)
      expect([200, 201]).toContain(response.status);
    });
  });
});
