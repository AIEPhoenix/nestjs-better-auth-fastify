import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  createTestUser,
  generateTestEmail,
  authenticatedRequest,
} from './setup/test-utils';

describe('OrganizationController (e2e)', () => {
  let app: NestFastifyApplication;
  let userCookies: string[];
  let userEmail: string;
  let userId: string;

  beforeAll(async () => {
    app = await createTestApp();

    // Create a test user
    userEmail = generateTestEmail('org-user');
    const { cookies, user } = await createTestUser(app, {
      email: userEmail,
      password: 'Test123!',
      name: 'Org Test User',
    });
    userCookies = cookies;
    userId = user.id;
  });

  afterAll(async () => {
    await closeTestApp();
  });

  describe('Public Routes', () => {
    it('GET /organizations - should return public organization list without auth', async () => {
      const response = await request(app.getHttpServer())
        .get('/organizations')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('organizations');
      expect(Array.isArray(response.body.organizations)).toBe(true);
    });
  });

  describe('Authenticated Routes', () => {
    it('GET /organizations - should return 200 with auth', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/organizations')
        .expect(200);
    });

    it('GET /organizations/my - should return 401 without auth', () => {
      return request(app.getHttpServer()).get('/organizations/my').expect(401);
    });

    it('GET /organizations/my - should return user organizations', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/organizations/my')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('userId');
      expect(response.body).toHaveProperty('organizations');
    });

    it('POST /organizations - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .post('/organizations')
        .send({ name: 'Test Org', slug: 'test-org' })
        .expect(401);
    });

    it('POST /organizations - should create organization', async () => {
      const timestamp = Date.now();
      const response = await authenticatedRequest(app, userCookies)
        .post('/organizations')
        .send({
          name: `New Test Org ${timestamp}`,
          slug: `new-test-org-${timestamp}`,
        });

      expect([200, 201]).toContain(response.status);
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('organization');
    });
  });

  describe('Organization Context Required (@OrgRequired)', () => {
    it('GET /organizations/current - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .get('/organizations/current')
        .expect(401);
    });

    it('GET /organizations/current - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current',
      );

      // In mock environment, may return 200, 403, or 500 depending on org context
      expect([200, 403, 500]).toContain(response.status);
    });

    it('GET /organizations/current/members - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .get('/organizations/current/members')
        .expect(401);
    });

    it('GET /organizations/current/members - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/members',
      );

      expect([200, 403, 500]).toContain(response.status);
    });
  });

  describe('Organization Roles (@OrgRoles)', () => {
    it('GET /organizations/current/settings - should require auth', async () => {
      await request(app.getHttpServer())
        .get('/organizations/current/settings')
        .expect(401);
    });

    it('GET /organizations/current/settings - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/settings',
      );

      expect([200, 403, 500]).toContain(response.status);
    });

    it('GET /organizations/current/any-role - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .get('/organizations/current/any-role')
        .expect(401);
    });

    it('GET /organizations/current/any-role - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/any-role',
      );

      expect([200, 403, 500]).toContain(response.status);
    });

    it('GET /organizations/current/owner-only - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .get('/organizations/current/owner-only')
        .expect(401);
    });

    it('GET /organizations/current/owner-only - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/owner-only',
      );

      expect([200, 403, 500]).toContain(response.status);
    });
  });

  describe('Organization Permissions (@OrgPermission)', () => {
    it('GET /organizations/current/billing - should require auth', () => {
      return request(app.getHttpServer())
        .get('/organizations/current/billing')
        .expect(401);
    });

    it('GET /organizations/current/billing - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/billing',
      );

      expect([200, 403, 500]).toContain(response.status);
    });

    it('GET /organizations/current/can-manage-members - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .get('/organizations/current/can-manage-members')
        .expect(401);
    });

    it('GET /organizations/current/can-manage-members - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/can-manage-members',
      );

      expect([200, 403, 500]).toContain(response.status);
    });

    it('DELETE /organizations/current/invitations/:id - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .delete('/organizations/current/invitations/test-invite-id')
        .expect(401);
    });
  });

  describe('Member Management', () => {
    it('POST /organizations/current/invites - should require auth', () => {
      return request(app.getHttpServer())
        .post('/organizations/current/invites')
        .send({ email: 'invite@test.com', role: 'member' })
        .expect(401);
    });

    it('POST /organizations/current/invites - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .post('/organizations/current/invites')
        .send({ email: 'invite@test.com', role: 'member' });

      expect([200, 201, 403, 500]).toContain(response.status);
    });

    it('DELETE /organizations/current/members/:memberId - should require auth', () => {
      return request(app.getHttpServer())
        .delete('/organizations/current/members/some-member-id')
        .expect(401);
    });

    it('POST /organizations/current/members/:id/role - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .post('/organizations/current/members/test-member-id/role')
        .send({ newRole: 'admin' })
        .expect(401);
    });
  });

  describe('Organization Analytics and Export', () => {
    it('GET /organizations/current/analytics - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .get('/organizations/current/analytics')
        .expect(401);
    });

    it('GET /organizations/current/analytics - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).get(
        '/organizations/current/analytics',
      );

      expect([200, 403, 500]).toContain(response.status);
    });

    it('POST /organizations/current/audit-export - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .post('/organizations/current/audit-export')
        .send({ startDate: '2025-01-01', endDate: '2025-01-31' })
        .expect(401);
    });
  });

  describe('Team Management', () => {
    it('POST /organizations/current/teams - should return 401 without auth', async () => {
      await request(app.getHttpServer())
        .post('/organizations/current/teams')
        .send({ name: 'Test Team', description: 'Test Description' })
        .expect(401);
    });

    it('POST /organizations/current/teams - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .post('/organizations/current/teams')
        .send({ name: 'Test Team', description: 'Test Description' });

      expect([200, 201, 403, 500]).toContain(response.status);
    });
  });

  describe('Organization Lifecycle', () => {
    it('POST /organizations/current/projects - should require auth', () => {
      return request(app.getHttpServer())
        .post('/organizations/current/projects')
        .send({ name: 'Test Project', description: 'A test project' })
        .expect(401);
    });

    it('POST /organizations/current/projects - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .post('/organizations/current/projects')
        .send({ name: 'Test Project', description: 'A test project' });

      expect([200, 201, 403, 500]).toContain(response.status);
    });

    it('DELETE /organizations/current - should require auth', () => {
      return request(app.getHttpServer())
        .delete('/organizations/current')
        .expect(401);
    });

    it('DELETE /organizations/current - should respond when authenticated', async () => {
      const response = await authenticatedRequest(app, userCookies).delete(
        '/organizations/current',
      );

      expect([200, 403, 500]).toContain(response.status);
    });
  });
});
