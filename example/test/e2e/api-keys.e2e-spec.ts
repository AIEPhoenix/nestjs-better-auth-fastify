import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  createTestUser,
  generateTestEmail,
  authenticatedRequest,
} from './setup/test-utils';

describe('ApiKeysController (e2e)', () => {
  let app: NestFastifyApplication;
  let userCookies: string[];
  let userEmail: string;
  let userId: string;

  beforeAll(async () => {
    app = await createTestApp();

    // Create a test user
    userEmail = generateTestEmail('apikey-user');
    const { cookies, user } = await createTestUser(app, {
      email: userEmail,
      password: 'Test123!',
      name: 'API Key Test User',
    });
    userCookies = cookies;
    userId = user.id;
  });

  afterAll(async () => {
    await closeTestApp();
  });

  describe('API Key Management (Session Auth)', () => {
    it('GET /api-keys - should return 401 without auth', () => {
      return request(app.getHttpServer()).get('/api-keys').expect(401);
    });

    it('GET /api-keys - should return user API keys', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/api-keys')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('userId');
      expect(response.body).toHaveProperty('apiKeys');
      expect(Array.isArray(response.body.apiKeys)).toBe(true);
    });

    it('POST /api-keys - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .post('/api-keys')
        .send({ name: 'Test Key', permissions: ['read:data'] })
        .expect(401);
    });

    it('POST /api-keys - should create a new API key', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .post('/api-keys')
        .send({
          name: 'Test API Key',
          permissions: ['read:data', 'write:data'],
        })
        .expect(201);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('apiKey');
      expect(response.body.apiKey).toHaveProperty('id');
      expect(response.body.apiKey).toHaveProperty('key');
      expect(response.body.apiKey.name).toBe('Test API Key');
    });

    it('DELETE /api-keys/:id - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .delete('/api-keys/some-key-id')
        .expect(401);
    });

    it('DELETE /api-keys/:id - should delete an API key', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .delete('/api-keys/test-key-id')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body.deletedKeyId).toBe('test-key-id');
    });
  });

  describe('API Key Authentication (@ApiKeyAuth)', () => {
    it('GET /api-keys/external/data - should return 401 without API key', () => {
      return request(app.getHttpServer())
        .get('/api-keys/external/data')
        .expect(401);
    });

    it('GET /api-keys/external/data - should return 401 with session auth (API key required)', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/api-keys/external/data')
        .expect(401);
    });

    it('GET /api-keys/external/data - should return 401 with invalid API key', () => {
      return request(app.getHttpServer())
        .get('/api-keys/external/data')
        .set('X-API-Key', 'invalid-api-key')
        .expect(401);
    });

    it('POST /api-keys/external/data - should return 401 without API key', () => {
      return request(app.getHttpServer())
        .post('/api-keys/external/data')
        .send({ name: 'Test Item', value: 100 })
        .expect(401);
    });

    it('POST /api-keys/external/batch-create - should return 401 without API key', async () => {
      await request(app.getHttpServer())
        .post('/api-keys/external/batch-create')
        .send({ items: [{ name: 'Test', value: 100 }] })
        .expect(401);
    });

    it('POST /api-keys/external/batch-create - should return 401 with session auth', async () => {
      await authenticatedRequest(app, userCookies)
        .post('/api-keys/external/batch-create')
        .send({ items: [{ name: 'Test', value: 100 }] })
        .expect(401);
    });
  });

  describe('Session Auth with Bearer Token support', () => {
    it('GET /api-keys/external/profile - should return 401 without auth', () => {
      return request(app.getHttpServer())
        .get('/api-keys/external/profile')
        .expect(401);
    });

    it('GET /api-keys/external/profile - should work with session auth', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/api-keys/external/profile')
        .expect(200);

      expect(response.body).toHaveProperty('authenticatedVia');
    });

    it('GET /api-keys/external/profile - should return 401 with invalid Bearer token', () => {
      return request(app.getHttpServer())
        .get('/api-keys/external/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });
  });

  describe('Flexible Data (@ApiKeyAuth with allowSession)', () => {
    it('GET /api-keys/flexible/data - should return 401 without any auth', async () => {
      await request(app.getHttpServer())
        .get('/api-keys/flexible/data')
        .expect(401);
    });

    it('GET /api-keys/flexible/data - should return 200 with session auth (allowSession=true)', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/api-keys/flexible/data')
        .expect(200);

      expect(response.body).toHaveProperty('authenticatedVia');
      expect(response.body.authenticatedVia).toBe('Session');
      expect(response.body).toHaveProperty('identity');
      expect(response.body.identity.type).toBe('user');
    });
  });

  describe('Webhook Handling (@ApiKeyAuth with Permissions)', () => {
    it('POST /api-keys/webhooks/payment - should return 401 without API key', () => {
      return request(app.getHttpServer())
        .post('/api-keys/webhooks/payment')
        .send({ event: 'payment.completed', data: {} })
        .expect(401);
    });
  });

  describe('Integration Status (@ApiKeyAuth with Permissions)', () => {
    it('GET /api-keys/integrations/status - should return 401 without API key', () => {
      return request(app.getHttpServer())
        .get('/api-keys/integrations/status')
        .expect(401);
    });

    it('GET /api-keys/integrations/status - should return 401 with session auth', async () => {
      await authenticatedRequest(app, userCookies)
        .get('/api-keys/integrations/status')
        .expect(401);
    });
  });

  describe('Universal Data (Session or API Key)', () => {
    it('GET /api-keys/universal/data - should return 401 without any auth', () => {
      return request(app.getHttpServer())
        .get('/api-keys/universal/data')
        .expect(401);
    });

    it('GET /api-keys/universal/data - should return 200 with session auth', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/api-keys/universal/data')
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('authenticatedVia');
      expect(response.body.authenticatedVia).toBe('Session');
      expect(response.body).toHaveProperty('data');
    });
  });

  describe('CI/CD Integration Routes', () => {
    it('POST /api-keys/cli/deploy - should return 401 without API key', async () => {
      await request(app.getHttpServer())
        .post('/api-keys/cli/deploy')
        .send({ environment: 'staging', version: '1.0.0' })
        .expect(401);
    });

    it('POST /api-keys/cli/deploy - should return 401 with session auth (API key required)', async () => {
      await authenticatedRequest(app, userCookies)
        .post('/api-keys/cli/deploy')
        .send({ environment: 'staging', version: '1.0.0' })
        .expect(401);
    });

    it('GET /api-keys/ci/status - should return 401 without any auth', async () => {
      await request(app.getHttpServer()).get('/api-keys/ci/status').expect(401);
    });

    it('GET /api-keys/ci/status - should return 200 with session auth (allowSession=true)', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/api-keys/ci/status')
        .expect(200);

      expect(response.body).toHaveProperty('pipelines');
      expect(Array.isArray(response.body.pipelines)).toBe(true);
    });
  });

  describe('Rate Limited Endpoint', () => {
    it('GET /api-keys/rate-limited/data - should return 401 without any auth', async () => {
      await request(app.getHttpServer())
        .get('/api-keys/rate-limited/data')
        .expect(401);
    });

    it('GET /api-keys/rate-limited/data - should return 200 with session auth', async () => {
      const response = await authenticatedRequest(app, userCookies)
        .get('/api-keys/rate-limited/data')
        .expect(200);

      expect(response.body).toHaveProperty('authenticationType');
      expect(response.body.authenticationType).toBe('Session');
      expect(response.body).toHaveProperty('rateLimit');
    });
  });
});
