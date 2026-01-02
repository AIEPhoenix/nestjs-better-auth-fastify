import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  createTestUser,
  createAdminUser,
  generateTestEmail,
  authenticatedRequest,
  setUserPermissions,
} from './setup/test-utils';

describe('AdminController (e2e)', () => {
  let app: NestFastifyApplication;
  let regularUserCookies: string[];
  let regularUserEmail: string;
  let adminCookies: string[];
  let adminUserId: string;

  beforeAll(async () => {
    app = await createTestApp();

    // Create a regular user for testing access denial
    regularUserEmail = generateTestEmail('regular');
    const { cookies } = await createTestUser(app, {
      email: regularUserEmail,
      password: 'Test123!',
      name: 'Regular User',
    });
    regularUserCookies = cookies;

    // Create an admin user
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

  describe('Admin Only Access (@AdminOnly)', () => {
    it('GET /admin/dashboard - should return 401 without auth', () => {
      return request(app.getHttpServer()).get('/admin/dashboard').expect(401);
    });

    it('GET /admin/dashboard - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
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

    it('GET /admin/users - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .get('/admin/users')
        .expect(403);
    });

    it('GET /admin/users/:id - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .get('/admin/users/some-user-id')
        .expect(403);
    });
  });

  describe('Admin with Permissions (@AdminOnly + @Permissions)', () => {
    it('GET /admin/users - should return 403 for admin without read:users permission', async () => {
      await authenticatedRequest(app, adminCookies)
        .get('/admin/users')
        .expect(403);
    });

    it('GET /admin/users - should return 200 for admin with read:users permission', async () => {
      setUserPermissions(adminUserId, ['read:users']);

      const response = await authenticatedRequest(app, adminCookies)
        .get('/admin/users')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('users');
    });
  });

  describe('User Ban Operations', () => {
    it('POST /admin/users/:id/ban - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .post('/admin/users/some-user-id/ban')
        .send({ reason: 'Test ban' })
        .expect(403);
    });

    it('POST /admin/users/:id/ban - should return 403 for admin without write:users permission', async () => {
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-no-write'),
        password: 'Admin123!',
        name: 'Admin No Write',
      });

      await authenticatedRequest(app, newAdmin.cookies)
        .post('/admin/users/some-user-id/ban')
        .send({ reason: 'Test ban' })
        .expect(403);
    });

    it('POST /admin/users/:id/ban - should work for admin with write:users permission', async () => {
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-with-write'),
        password: 'Admin123!',
        name: 'Admin With Write',
      });
      setUserPermissions(newAdmin.user.id, ['write:users']);

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

    it('POST /admin/users/:id/unban - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .post('/admin/users/some-user-id/unban')
        .expect(403);
    });
  });

  describe('Secure Admin Only (@SecureAdminOnly)', () => {
    it('DELETE /admin/users/:id - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .delete('/admin/users/some-user-id')
        .expect(403);
    });
  });

  describe('Super Admin Operations (@Roles["super_admin"])', () => {
    it('GET /admin/system/config - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .get('/admin/system/config')
        .expect(403);
    });

    it('GET /admin/system/config - should return 403 for admin (not super_admin)', async () => {
      await authenticatedRequest(app, adminCookies)
        .get('/admin/system/config')
        .expect(403);
    });

    it('POST /admin/system/config - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
        .post('/admin/system/config')
        .send({ maintenanceMode: true })
        .expect(403);
    });
  });

  describe('Audit Logs (@AdminOnly + @Permissions)', () => {
    it('GET /admin/audit-logs - should return 401 without auth', async () => {
      await request(app.getHttpServer()).get('/admin/audit-logs').expect(401);
    });

    it('GET /admin/audit-logs - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
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

  describe('Impersonation (@SecureAdminOnly + @Permissions)', () => {
    it('POST /admin/impersonate/:userId - should return 403 for regular user', async () => {
      await authenticatedRequest(app, regularUserCookies)
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
      const newAdmin = await createAdminUser(app, {
        email: generateTestEmail('admin-impersonate'),
        password: 'Admin123!',
        name: 'Admin Impersonate',
      });
      setUserPermissions(newAdmin.user.id, ['impersonate:users']);

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
});
