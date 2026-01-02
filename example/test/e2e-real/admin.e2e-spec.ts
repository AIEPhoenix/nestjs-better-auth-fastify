/**
 * AdminController E2E Tests
 *
 * Tests using real better-auth
 * Tests admin-related functionality
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  createTestUser,
  createAdminUser,
  generateTestEmail,
  authenticatedRequest,
  setUserPermissions,
  loginUser,
} from './setup/test-utils';

describe('AdminController (e2e) - Real better-auth', () => {
  let app: NestFastifyApplication;
  let userCookies: string[];
  let adminCookies: string[];
  let adminUserId: string;

  beforeAll(async () => {
    app = await createTestApp();

    // Create regular user
    const userResult = await createTestUser(app, {
      email: generateTestEmail('regular-user'),
      password: 'Test123!',
      name: 'Regular User',
    });
    userCookies = userResult.cookies;

    // Create admin user
    const adminResult = await createAdminUser(app, {
      email: generateTestEmail('admin'),
      password: 'Admin123!',
      name: 'Admin User',
    });
    adminCookies = adminResult.cookies;
    adminUserId = adminResult.user.id;
  });

  afterAll(async () => {
    await closeTestApp();
  });

  describe('Admin Access Control (@AdminOnly)', () => {
    it('GET /admin/dashboard - should return 401 without auth', async () => {
      await request(app.getHttpServer()).get('/admin/dashboard').expect(401);
    });

    it('GET /admin/dashboard - should return 403 for regular user', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/admin/dashboard')
        .expect(403);
    });

    it('GET /admin/dashboard - should return 200 for admin user', async () => {
      const response = await authenticatedRequest(app, adminCookies)
        .get('/admin/dashboard')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('stats');
    });
  });

  describe('Admin with Permissions (@AdminOnly + @Permissions)', () => {
    it('GET /admin/users - should return 401 without auth', async () => {
      await request(app.getHttpServer()).get('/admin/users').expect(401);
    });

    it('GET /admin/users - should return 403 for regular user', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/admin/users')
        .expect(403);
    });

    it('GET /admin/users - should return 403 for admin without read:users permission', async () => {
      // Admin doesn't have read:users permission
      await authenticatedRequest(app, adminCookies)
        .get('/admin/users')
        .expect(403);
    });

    it('GET /admin/users - should return 200 for admin with read:users permission', async () => {
      // Add permission to admin
      setUserPermissions(adminUserId, ['read:users']);

      // Re-login to refresh session
      const loginResult = await loginUser(app, {
        email: (
          await authenticatedRequest(app, adminCookies).get('/admin/dashboard')
        ).body.admin,
        password: 'Admin123!',
      }).catch(() => null);

      // Use original cookies (permissions updated in database)
      const response = await authenticatedRequest(app, adminCookies)
        .get('/admin/users')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('users');
    });
  });

  describe('System Config (super_admin role required)', () => {
    it('GET /admin/system/config - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .get('/admin/system/config')
        .expect(401);
    });

    it('GET /admin/system/config - should return 403 for regular user', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/admin/system/config')
        .expect(403);
    });

    it('GET /admin/system/config - should return 403 for admin (not super_admin)', async () => {
      // admin role is not super_admin, should return 403
      await authenticatedRequest(app, adminCookies)
        .get('/admin/system/config')
        .expect(403);
    });
  });

  describe('User Ban Management (@AdminOnly + @Permissions)', () => {
    it('POST /admin/users/:userId/ban - should return 403 for regular user', async () => {
      await authenticatedRequest(app, userCookies)
        .post('/admin/users/some-user-id/ban')
        .send({ reason: 'test' })
        .expect(403);
    });

    it('POST /admin/users/:userId/ban - should return 403 for admin without write:users permission', async () => {
      // Create new admin without write:users permission
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-no-write'),
        password: 'Admin123!',
        name: 'Admin No Write',
      });

      await authenticatedRequest(app, newAdmin.cookies)
        .post('/admin/users/some-user-id/ban')
        .send({ reason: 'test' })
        .expect(403);
    });

    it('POST /admin/users/:userId/ban - should work for admin with write:users permission', async () => {
      // Create admin and add permission
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-with-write'),
        password: 'Admin123!',
        name: 'Admin With Write',
      });
      setUserPermissions(newAdmin.user.id, ['write:users']);

      // Create user to be banned
      const { user } = await createTestUser(app, {
        email: generateTestEmail('to-ban'),
        password: 'Test123!',
        name: 'To Ban User',
      });

      const response = await authenticatedRequest(app, newAdmin.cookies)
        .post(`/admin/users/${user.id}/ban`)
        .send({ reason: 'Test ban' });

      expect([200, 201]).toContain(response.status);
      expect(response.body).toHaveProperty('message');
      expect(response.body.userId).toBe(user.id);
    });
  });

  describe('Impersonation Management (@SecureAdminOnly + @Permissions)', () => {
    it('POST /admin/impersonate/:userId - should return 403 for regular user', async () => {
      await authenticatedRequest(app, userCookies)
        .post('/admin/impersonate/some-user-id')
        .expect(403);
    });

    it('POST /admin/impersonate/:userId - should return 403 for admin without impersonate:users permission', async () => {
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-no-impersonate'),
        password: 'Admin123!',
        name: 'Admin No Impersonate',
      });

      await authenticatedRequest(app, newAdmin.cookies)
        .post('/admin/impersonate/some-user-id')
        .expect(403);
    });

    it('POST /admin/impersonate/:userId - should work for admin with impersonate:users permission', async () => {
      // Create admin and add permission
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-impersonate'),
        password: 'Admin123!',
        name: 'Admin Impersonate',
      });
      setUserPermissions(newAdmin.user.id, ['impersonate:users']);

      // Create user to impersonate
      const { user } = await createTestUser(app, {
        email: generateTestEmail('to-impersonate'),
        password: 'Test123!',
        name: 'To Impersonate User',
      });

      const response = await authenticatedRequest(app, newAdmin.cookies).post(
        `/admin/impersonate/${user.id}`,
      );

      expect([200, 201]).toContain(response.status);
      expect(response.body).toHaveProperty('message');
    });
  });

  describe('Audit Logs (@AdminOnly + @Permissions)', () => {
    it('GET /admin/audit-logs - should return 401 without auth', async () => {
      await request(app.getHttpServer()).get('/admin/audit-logs').expect(401);
    });

    it('GET /admin/audit-logs - should return 403 for regular user', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/admin/audit-logs')
        .expect(403);
    });

    it('GET /admin/audit-logs - should return 403 for admin without read:audit-logs permission', async () => {
      await authenticatedRequest(app, adminCookies)
        .get('/admin/audit-logs')
        .expect(403);
    });

    it('GET /admin/audit-logs - should return 200 for admin with read:audit-logs permission', async () => {
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-audit'),
        password: 'Admin123!',
        name: 'Admin Audit',
      });
      setUserPermissions(newAdmin.user.id, ['read:audit-logs']);

      const response = await authenticatedRequest(app, newAdmin.cookies)
        .get('/admin/audit-logs')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('logs');
    });
  });
});
