/**
 * E2E Test Utility Functions
 *
 * Provides real user creation, login, API Key creation, etc.
 * All operations go through the real better-auth API
 */
import { NestFastifyApplication } from '@nestjs/platform-fastify';
import request from 'supertest';
import { getTestDb } from './test-auth.config';

/**
 * Extract cookies from response
 */
export function extractCookies(response: request.Response): string[] {
  const setCookieHeader = response.headers['set-cookie'];
  if (!setCookieHeader) return [];
  return Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
}

/**
 * Convert cookie array to request header string
 */
export function cookiesToHeader(cookies: string[]): string {
  return cookies.map((cookie) => cookie.split(';')[0]).join('; ');
}

// ============================================
// User Related
// ============================================

interface CreateUserOptions {
  email: string;
  password: string;
  name: string;
}

interface CreateUserResult {
  cookies: string[];
  user: {
    id: string;
    email: string;
    name: string;
    role?: string;
  };
}

/**
 * Create test user (through real better-auth API)
 */
export async function createTestUser(
  app: NestFastifyApplication,
  options: CreateUserOptions,
): Promise<CreateUserResult> {
  const response = await request(app.getHttpServer())
    .post('/api/auth/sign-up/email')
    .send({
      email: options.email,
      password: options.password,
      name: options.name,
    })
    .expect(200);

  const cookies = extractCookies(response);

  return {
    cookies,
    user: response.body.user || {
      id: response.body.id,
      email: options.email,
      name: options.name,
    },
  };
}

interface LoginUserOptions {
  email: string;
  password: string;
}

interface LoginResult {
  cookies: string[];
  session: {
    user: {
      id: string;
      email: string;
      name: string;
      role?: string;
    };
    session: {
      id: string;
      userId: string;
      createdAt: string;
      expiresAt: string;
    };
  };
}

/**
 * User login
 */
export async function loginUser(
  app: NestFastifyApplication,
  options: LoginUserOptions,
): Promise<LoginResult> {
  const response = await request(app.getHttpServer())
    .post('/api/auth/sign-in/email')
    .send({
      email: options.email,
      password: options.password,
    })
    .expect(200);

  const cookies = extractCookies(response);

  return {
    cookies,
    session: response.body,
  };
}

/**
 * User logout
 */
export async function logoutUser(
  app: NestFastifyApplication,
  cookies: string[],
): Promise<void> {
  await request(app.getHttpServer())
    .post('/api/auth/sign-out')
    .set('Cookie', cookiesToHeader(cookies))
    .expect(200);
}

/**
 * Get current session
 */
export async function getSession(
  app: NestFastifyApplication,
  cookies: string[],
): Promise<LoginResult['session'] | null> {
  const response = await request(app.getHttpServer())
    .get('/api/auth/session')
    .set('Cookie', cookiesToHeader(cookies));

  if (response.status !== 200 || !response.body?.user) {
    return null;
  }

  return response.body;
}

// ============================================
// Admin Related
// ============================================

/**
 * Promote user to admin
 * Directly operates on database (simulates admin operation)
 */
export function promoteToAdmin(userId: string): void {
  const db = getTestDb();
  if (!db) {
    throw new Error('Test database not initialized');
  }

  try {
    db.prepare('UPDATE user SET role = ? WHERE id = ?').run('admin', userId);
  } catch (error) {
    console.warn('Failed to promote user to admin:', error);
    throw error;
  }
}

/**
 * Set user role
 */
export function setUserRole(userId: string, role: string): void {
  const db = getTestDb();
  if (!db) {
    throw new Error('Test database not initialized');
  }

  try {
    db.prepare('UPDATE user SET role = ? WHERE id = ?').run(role, userId);
  } catch (error) {
    console.warn(`Failed to set user role to ${role}:`, error);
    throw error;
  }
}

/**
 * Set user permissions
 */
export function setUserPermissions(
  userId: string,
  permissions: string[],
): void {
  const db = getTestDb();
  if (!db) {
    throw new Error('Test database not initialized');
  }

  try {
    const permissionsJson = JSON.stringify(permissions);
    db.prepare('UPDATE user SET permissions = ? WHERE id = ?').run(
      permissionsJson,
      userId,
    );
  } catch (error) {
    console.warn('Failed to set user permissions:', error);
    throw error;
  }
}

/**
 * Ban user
 */
export function banUser(userId: string, reason?: string): void {
  const db = getTestDb();
  if (!db) {
    throw new Error('Test database not initialized');
  }

  try {
    const banReason = reason || 'Banned by test';
    db.prepare(
      'UPDATE user SET banned = 1, banReason = ?, banExpires = NULL WHERE id = ?',
    ).run(banReason, userId);
  } catch (error) {
    console.warn('Failed to ban user:', error);
    throw error;
  }
}

/**
 * Create admin user
 */
export async function createAdminUser(
  app: NestFastifyApplication,
  options: CreateUserOptions = {
    email: 'admin@test.com',
    password: 'Admin123!',
    name: 'Admin User',
  },
): Promise<CreateUserResult> {
  const result = await createTestUser(app, options);
  promoteToAdmin(result.user.id);
  result.user.role = 'admin';
  return result;
}

/**
 * Create user with specific role
 */
export async function createUserWithRole(
  app: NestFastifyApplication,
  options: CreateUserOptions & { role: string },
): Promise<CreateUserResult> {
  const { role, ...userOptions } = options;
  const result = await createTestUser(app, userOptions);
  setUserRole(result.user.id, role);
  result.user.role = role;
  return result;
}

/**
 * Create user with specific permissions
 */
export async function createUserWithPermissions(
  app: NestFastifyApplication,
  options: CreateUserOptions & { permissions: string[] },
): Promise<CreateUserResult> {
  const { permissions, ...userOptions } = options;
  const result = await createTestUser(app, userOptions);
  setUserPermissions(result.user.id, permissions);
  return result;
}

// ============================================
// Organization Related
// ============================================

interface CreateOrganizationOptions {
  name: string;
  slug: string;
}

interface CreateOrganizationResult {
  organization: {
    id: string;
    name: string;
    slug: string;
  };
}

/**
 * Create organization
 */
export async function createOrganization(
  app: NestFastifyApplication,
  cookies: string[],
  options: CreateOrganizationOptions,
): Promise<CreateOrganizationResult> {
  const response = await request(app.getHttpServer())
    .post('/api/auth/organization/create')
    .set('Cookie', cookiesToHeader(cookies))
    .send({
      name: options.name,
      slug: options.slug,
    })
    .expect(200);

  return {
    organization: response.body,
  };
}

/**
 * Set active organization
 */
export async function setActiveOrganization(
  app: NestFastifyApplication,
  cookies: string[],
  organizationId: string,
): Promise<string[]> {
  const response = await request(app.getHttpServer())
    .post('/api/auth/organization/set-active')
    .set('Cookie', cookiesToHeader(cookies))
    .send({ organizationId })
    .expect(200);

  return extractCookies(response) || cookies;
}

// ============================================
// API Key Related
// ============================================

interface CreateApiKeyOptions {
  name: string;
  permissions?: string[];
  expiresIn?: number;
}

interface CreateApiKeyResult {
  apiKey: {
    id: string;
    key: string;
    name: string;
  };
}

/**
 * Create API Key (through better-auth API)
 */
export async function createApiKey(
  app: NestFastifyApplication,
  cookies: string[],
  options: CreateApiKeyOptions,
): Promise<CreateApiKeyResult> {
  const response = await request(app.getHttpServer())
    .post('/api/auth/api-key/create')
    .set('Cookie', cookiesToHeader(cookies))
    .send({
      name: options.name,
      permissions: options.permissions || [],
      expiresIn: options.expiresIn,
    })
    .expect(200);

  return {
    apiKey: response.body,
  };
}

/**
 * List user's API Keys
 */
export async function listApiKeys(
  app: NestFastifyApplication,
  cookies: string[],
): Promise<any[]> {
  const response = await request(app.getHttpServer())
    .get('/api/auth/api-key/list')
    .set('Cookie', cookiesToHeader(cookies))
    .expect(200);

  return response.body;
}

/**
 * Delete API Key
 */
export async function deleteApiKey(
  app: NestFastifyApplication,
  cookies: string[],
  keyId: string,
): Promise<void> {
  await request(app.getHttpServer())
    .post('/api/auth/api-key/delete')
    .set('Cookie', cookiesToHeader(cookies))
    .send({ keyId })
    .expect(200);
}

// ============================================
// Bearer Token Related
// ============================================

/**
 * Create Bearer Token (through better-auth API)
 */
export async function createBearerToken(
  app: NestFastifyApplication,
  cookies: string[],
): Promise<{ token: string }> {
  const response = await request(app.getHttpServer())
    .post('/api/auth/token')
    .set('Cookie', cookiesToHeader(cookies))
    .expect(200);

  return {
    token: response.body.token,
  };
}

// ============================================
// Utility Functions
// ============================================

/**
 * Generate unique test email
 */
export function generateTestEmail(prefix: string = 'test'): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  return `${prefix}-${timestamp}-${random}@test.com`;
}

/**
 * Wait for specified time
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create authenticated request helper
 */
export function authenticatedRequest(
  app: NestFastifyApplication,
  cookies: string[],
) {
  return {
    get: (url: string) =>
      request(app.getHttpServer())
        .get(url)
        .set('Cookie', cookiesToHeader(cookies)),
    post: (url: string) =>
      request(app.getHttpServer())
        .post(url)
        .set('Cookie', cookiesToHeader(cookies)),
    put: (url: string) =>
      request(app.getHttpServer())
        .put(url)
        .set('Cookie', cookiesToHeader(cookies)),
    delete: (url: string) =>
      request(app.getHttpServer())
        .delete(url)
        .set('Cookie', cookiesToHeader(cookies)),
    patch: (url: string) =>
      request(app.getHttpServer())
        .patch(url)
        .set('Cookie', cookiesToHeader(cookies)),
  };
}

/**
 * Create API Key authenticated request helper
 */
export function apiKeyRequest(app: NestFastifyApplication, apiKey: string) {
  return {
    get: (url: string) =>
      request(app.getHttpServer()).get(url).set('X-API-Key', apiKey),
    post: (url: string) =>
      request(app.getHttpServer()).post(url).set('X-API-Key', apiKey),
    put: (url: string) =>
      request(app.getHttpServer()).put(url).set('X-API-Key', apiKey),
    delete: (url: string) =>
      request(app.getHttpServer()).delete(url).set('X-API-Key', apiKey),
    patch: (url: string) =>
      request(app.getHttpServer()).patch(url).set('X-API-Key', apiKey),
  };
}

/**
 * Create Bearer Token authenticated request helper
 */
export function bearerRequest(app: NestFastifyApplication, token: string) {
  return {
    get: (url: string) =>
      request(app.getHttpServer())
        .get(url)
        .set('Authorization', `Bearer ${token}`),
    post: (url: string) =>
      request(app.getHttpServer())
        .post(url)
        .set('Authorization', `Bearer ${token}`),
    put: (url: string) =>
      request(app.getHttpServer())
        .put(url)
        .set('Authorization', `Bearer ${token}`),
    delete: (url: string) =>
      request(app.getHttpServer())
        .delete(url)
        .set('Authorization', `Bearer ${token}`),
    patch: (url: string) =>
      request(app.getHttpServer())
        .patch(url)
        .set('Authorization', `Bearer ${token}`),
  };
}
