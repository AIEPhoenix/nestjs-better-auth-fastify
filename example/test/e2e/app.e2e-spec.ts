import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  createTestUser,
  generateTestEmail,
  authenticatedRequest,
} from './setup/test-utils';

describe('AppController (e2e)', () => {
  let app: NestFastifyApplication;

  beforeAll(async () => {
    app = await createTestApp();
  });

  afterAll(async () => {
    await closeTestApp();
  });

  describe('Public Routes', () => {
    it('GET / - should return Hello World', () => {
      return request(app.getHttpServer())
        .get('/')
        .expect(200)
        .expect('Hello World!');
    });

    it('GET /info - should return API information', async () => {
      const response = await request(app.getHttpServer())
        .get('/info')
        .expect(200);

      expect(response.body).toHaveProperty('name');
      expect(response.body).toHaveProperty('version');
      expect(response.body).toHaveProperty('endpoints');
      expect(response.body).toHaveProperty('decorators');
      expect(response.body).toHaveProperty('moduleOptions');
    });

    it('GET /session-via-service - should return session info or not authenticated', async () => {
      const response = await request(app.getHttpServer())
        .get('/session-via-service')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('authenticated');
      expect(response.body.authenticated).toBe(false);
    });

    it('GET /auth-api-info - should return API info (public)', async () => {
      const response = await request(app.getHttpServer())
        .get('/auth-api-info')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('usage');
      expect(response.body).toHaveProperty('examples');
    });
  });

  describe('Protected Routes', () => {
    it('GET /profile - should return 401 without authentication', () => {
      return request(app.getHttpServer()).get('/profile').expect(401);
    });

    it('GET /profile - should return profile with valid session', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('profile'),
        password: 'Test123!',
        name: 'Profile Test User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/profile')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('session');
      expect(response.body.session).toHaveProperty('user');
    });

    it('GET /me - should return 401 without authentication', () => {
      return request(app.getHttpServer()).get('/me').expect(401);
    });

    it('GET /me - should return current user with valid session', async () => {
      const { cookies, user } = await createTestUser(app, {
        email: generateTestEmail('me'),
        password: 'Test123!',
        name: 'Me Test User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/me')
        .expect(200);

      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(user.email);
    });
  });

  describe('@UserProperty() Decorator', () => {
    it('GET /my-email - should return 401 without authentication', () => {
      return request(app.getHttpServer()).get('/my-email').expect(401);
    });

    it('GET /my-email - should return user email', async () => {
      const { cookies, user } = await createTestUser(app, {
        email: generateTestEmail('email-prop'),
        password: 'Test123!',
        name: 'Email Property User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/my-email')
        .expect(200);

      expect(response.body).toHaveProperty('email');
      expect(response.body.email).toBe(user.email);
    });

    it('GET /my-role - should return user role', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('role-prop'),
        password: 'Test123!',
        name: 'Role Property User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/my-role')
        .expect(200);

      expect(response.body).toHaveProperty('role');
    });
  });

  describe('@OptionalAuth() Decorator', () => {
    it('GET /greeting - should return guest greeting without auth', async () => {
      const response = await request(app.getHttpServer())
        .get('/greeting')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.authenticated).toBe(false);
      expect(response.body).toHaveProperty('hint');
    });

    it('GET /greeting - should return personalized greeting with auth', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('greeting'),
        password: 'Test123!',
        name: 'Greeting User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/greeting')
        .expect(200);

      expect(response.body.authenticated).toBe(true);
      expect(response.body).toHaveProperty('userId');
    });
  });

  describe('AuthService Programmatic Usage', () => {
    it('GET /session-via-service - should return authenticated info with session', async () => {
      const { cookies, user } = await createTestUser(app, {
        email: generateTestEmail('service-session'),
        password: 'Test123!',
        name: 'Service Session User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/session-via-service')
        .expect(200);

      expect(response.body.authenticated).toBe(true);
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(user.email);
    });

    it('GET /check-admin - should return admin status', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-admin'),
        password: 'Test123!',
        name: 'Check Admin User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-admin')
        .expect(200);

      expect(response.body).toHaveProperty('isAdmin');
      expect(response.body).toHaveProperty('isModerator');
      expect(response.body.isAdmin).toBe(false);
    });

    it('GET /check-session-fresh - should return session freshness info', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-fresh'),
        password: 'Test123!',
        name: 'Check Fresh User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-session-fresh')
        .expect(200);

      expect(response.body).toHaveProperty('sessionCreatedAt');
      expect(response.body).toHaveProperty('isFreshOneHour');
      expect(response.body.isFreshOneHour).toBe(true);
    });

    it('GET /check-impersonation - should return impersonation status', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-impersonate'),
        password: 'Test123!',
        name: 'Check Impersonate User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-impersonation')
        .expect(200);

      expect(response.body).toHaveProperty('isImpersonating');
      expect(response.body.isImpersonating).toBe(false);
    });

    it('GET /my-sessions - should return user sessions', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('my-sessions'),
        password: 'Test123!',
        name: 'My Sessions User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/my-sessions')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('sessions');
    });
  });

  describe('Additional AuthService Methods', () => {
    it('GET /check-permissions - should return 401 without auth', () => {
      return request(app.getHttpServer()).get('/check-permissions').expect(401);
    });

    it('GET /check-permissions - should return permission checks with auth', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-perms'),
        password: 'Test123!',
        name: 'Check Permissions User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-permissions')
        .expect(200);

      expect(response.body).toHaveProperty('userId');
      expect(response.body).toHaveProperty('permissions');
      expect(response.body.permissions).toHaveProperty('canReadReports');
      expect(response.body.permissions).toHaveProperty('canAccessAnalytics');
    });

    it('GET /validate-session - should return valid session info with auth', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('validate-session'),
        password: 'Test123!',
        name: 'Validate Session User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/validate-session')
        .expect(200);

      expect(response.body.valid).toBe(true);
      expect(response.body).toHaveProperty('session');
      expect(response.body.session).toHaveProperty('id');
      expect(response.body.session).toHaveProperty('userId');
    });

    it('POST /revoke-session/:sessionId - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .post('/revoke-session/some-session-id')
        .expect(401);
    });

    it('POST /revoke-session/:sessionId - should attempt to revoke session', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('revoke-session'),
        password: 'Test123!',
        name: 'Revoke Session User',
      });

      const response = await authenticatedRequest(app, cookies)
        .post('/revoke-session/non-existent-session')
        .expect(201); // NestJS returns 201 for POST by default

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('success');
      expect(response.body).toHaveProperty('revokedSessionId');
    });

    it('GET /check-ban-status - should return 401 without auth', () => {
      return request(app.getHttpServer()).get('/check-ban-status').expect(401);
    });

    it('GET /check-ban-status - should return ban status with auth', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-ban'),
        password: 'Test123!',
        name: 'Check Ban User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-ban-status')
        .expect(200);

      expect(response.body).toHaveProperty('userId');
      expect(response.body).toHaveProperty('isBanned');
      expect(response.body.isBanned).toBe(false);
    });

    it('GET /verify-api-key - should return invalid without API key', async () => {
      const response = await request(app.getHttpServer())
        .get('/verify-api-key')
        .expect(200);

      expect(response.body.valid).toBe(false);
      expect(response.body).toHaveProperty('reason');
    });

    it('GET /verify-api-key - should return invalid for bad API key', async () => {
      const response = await request(app.getHttpServer())
        .get('/verify-api-key')
        .set('x-api-key', 'invalid-api-key')
        .expect(200);

      expect(response.body.valid).toBe(false);
    });

    it('GET /active-organization - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .get('/active-organization')
        .expect(401);
    });

    it('GET /active-organization - should return no org without org context', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('active-org'),
        password: 'Test123!',
        name: 'Active Org User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/active-organization')
        .expect(200);

      expect(response.body.organization).toBeNull();
      expect(response.body).toHaveProperty('reason');
    });

    it('GET /check-org-role - should return 401 without auth', () => {
      return request(app.getHttpServer()).get('/check-org-role').expect(401);
    });

    it('GET /check-org-role - should return no role without org context', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-org-role'),
        password: 'Test123!',
        name: 'Check Org Role User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-org-role')
        .expect(200);

      expect(response.body.hasRole).toBe(false);
      expect(response.body.reason).toBe('No organization context');
    });

    it('GET /check-org-permission - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .get('/check-org-permission')
        .expect(401);
    });

    it('GET /check-org-permission - should return no permission without org context', async () => {
      const { cookies } = await createTestUser(app, {
        email: generateTestEmail('check-org-perm'),
        password: 'Test123!',
        name: 'Check Org Perm User',
      });

      const response = await authenticatedRequest(app, cookies)
        .get('/check-org-permission')
        .expect(200);

      expect(response.body.hasPermission).toBe(false);
      expect(response.body.reason).toBe('No organization context');
    });

    it('GET /auth-instance-info - should return instance info (public)', async () => {
      const response = await request(app.getHttpServer())
        .get('/auth-instance-info')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('available');
      expect(response.body.available).toBe(true);
      expect(response.body).toHaveProperty('basePath');
      expect(response.body).toHaveProperty('usage');
    });
  });
});
