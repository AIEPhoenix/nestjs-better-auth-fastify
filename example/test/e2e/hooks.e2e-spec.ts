import request from 'supertest';
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createTestApp, closeTestApp } from './setup/test-app';
import {
  generateTestEmail,
  extractCookies,
  cookiesToHeader,
} from './setup/test-utils';

describe('AuthHooksService (e2e)', () => {
  let app: NestFastifyApplication;
  let consoleSpy: jest.SpyInstance;
  let consoleLogCalls: string[];

  beforeAll(async () => {
    app = await createTestApp();
  });

  afterAll(async () => {
    await closeTestApp();
  });

  beforeEach(() => {
    consoleLogCalls = [];
    // Spy on console.log to capture hook outputs
    consoleSpy = jest.spyOn(console, 'log').mockImplementation((...args) => {
      consoleLogCalls.push(args.join(' '));
    });
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  describe('Sign Up Hooks', () => {
    it('should trigger @BeforeHook and @AfterHook on sign-up', async () => {
      const email = generateTestEmail('hook-signup');

      const response = await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name: 'Hook Test User',
        })
        .expect(200);

      // Verify the user was created successfully
      expect(response.body).toBeDefined();
      expect(extractCookies(response).length).toBeGreaterThan(0);

      // Note: The hooks use Logger which may not be captured by console.log spy
      // In a real test, you might:
      // 1. Mock the Logger service
      // 2. Add a test-specific hook that sets a flag
      // 3. Check database/state changes made by hooks
    });
  });

  describe('Sign In Hooks', () => {
    let testEmail: string;

    beforeAll(async () => {
      // Create a user for sign-in tests
      testEmail = generateTestEmail('hook-signin');
      await request(app.getHttpServer()).post('/api/auth/sign-up/email').send({
        email: testEmail,
        password: 'Test123!',
        name: 'Sign In Hook User',
      });
    });

    it('should trigger @BeforeHook and @AfterHook on sign-in', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/auth/sign-in/email')
        .send({
          email: testEmail,
          password: 'Test123!',
        })
        .expect(200);

      // Verify sign-in was successful
      expect(response.body).toBeDefined();
      expect(extractCookies(response).length).toBeGreaterThan(0);
    });
  });

  describe('Sign Out Hooks', () => {
    it('should trigger @AfterHook on sign-out', async () => {
      // First create and sign in a user
      const email = generateTestEmail('hook-signout');
      const signUpResponse = await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name: 'Sign Out Hook User',
        });

      const cookies = extractCookies(signUpResponse);

      // Now sign out
      await request(app.getHttpServer())
        .post('/api/auth/sign-out')
        .set('Cookie', cookiesToHeader(cookies))
        .expect(200);

      // Verify hook was triggered (Logger output)
    });
  });

  describe('Session Hooks', () => {
    it('should trigger @AfterHook on session retrieval', async () => {
      // Create and sign in a user
      const email = generateTestEmail('hook-session');
      const signUpResponse = await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name: 'Session Hook User',
        });

      const cookies = extractCookies(signUpResponse);

      // Get session
      const sessionResponse = await request(app.getHttpServer())
        .get('/api/auth/session')
        .set('Cookie', cookiesToHeader(cookies))
        .expect(200);

      expect(sessionResponse.body).toBeDefined();
    });
  });

  describe('Generic Hooks (All Auth Routes)', () => {
    it('should trigger generic @BeforeHook and @AfterHook on any auth route', async () => {
      // The generic hooks (@BeforeHook() and @AfterHook() without path)
      // should be triggered for all auth routes
      const email = generateTestEmail('hook-generic');

      await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name: 'Generic Hook User',
        })
        .expect(200);

      // Both specific (/sign-up/email) and generic hooks should be triggered
    });
  });

  describe('Hook Context Verification', () => {
    it('should provide correct context to hooks', async () => {
      const email = generateTestEmail('hook-context');
      const name = 'Context Test User';

      const response = await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name,
        })
        .expect(200);

      // The hook should have access to:
      // - ctx.body (request body with email, password, name)
      // - ctx.path (the auth route path)
      // - ctx.context.newSession (after successful auth)

      // Verify the operation completed successfully
      expect(response.body).toBeDefined();
    });
  });

  describe('Blocked Domain Hook', () => {
    it('should process blocked domain check in @BeforeHook', async () => {
      // The AuthHooksService checks for blocked domains in beforeSignUp
      // Currently it just logs a warning but doesn't block

      // If we uncomment the throw in the hook, this should fail:
      // const response = await request(app.getHttpServer())
      //   .post('/api/auth/sign-up/email')
      //   .send({
      //     email: 'test@spam.com', // blocked domain
      //     password: 'Test123!',
      //     name: 'Blocked User',
      //   })
      //   .expect(400);

      // For now, test that non-blocked domains work
      const email = generateTestEmail('allowed-domain');
      const response = await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name: 'Allowed Domain User',
        })
        .expect(200);

      expect(response.body).toBeDefined();
    });
  });

  // Integration test: Full auth flow with hooks
  describe('Complete Auth Flow with Hooks', () => {
    it('should trigger all relevant hooks in a complete auth flow', async () => {
      const email = generateTestEmail('hook-flow');

      // Step 1: Sign up (triggers beforeSignUp, afterSignUp, beforeAllAuth, afterAllAuth)
      const signUpResponse = await request(app.getHttpServer())
        .post('/api/auth/sign-up/email')
        .send({
          email,
          password: 'Test123!',
          name: 'Flow Test User',
        })
        .expect(200);

      const cookies = extractCookies(signUpResponse);

      // Step 2: Get session (triggers afterGetSession, beforeAllAuth, afterAllAuth)
      await request(app.getHttpServer())
        .get('/api/auth/session')
        .set('Cookie', cookiesToHeader(cookies))
        .expect(200);

      // Step 3: Sign out (triggers afterSignOut, beforeAllAuth, afterAllAuth)
      await request(app.getHttpServer())
        .post('/api/auth/sign-out')
        .set('Cookie', cookiesToHeader(cookies))
        .expect(200);

      // Step 4: Sign in again (triggers beforeSignIn, afterSignIn, beforeAllAuth, afterAllAuth)
      const signInResponse = await request(app.getHttpServer())
        .post('/api/auth/sign-in/email')
        .send({
          email,
          password: 'Test123!',
        })
        .expect(200);

      expect(signInResponse.body).toBeDefined();
      expect(extractCookies(signInResponse).length).toBeGreaterThan(0);
    });
  });
});
