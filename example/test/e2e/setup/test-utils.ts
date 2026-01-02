import { NestFastifyApplication } from '@nestjs/platform-fastify';
import request from 'supertest';
import {
  setUserRole as mockSetUserRole,
  setUserPermissions as mockSetUserPermissions,
  banUser as mockBanUser,
  createMockApiKey as mockCreateApiKey,
} from './jest-setup';

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
  };
}

/**
 * Create a test user (registration)
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
  session: any;
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
 * Create an admin user
 * Creates a regular user and then promotes them to admin role
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
  mockSetUserRole(result.user.id, 'admin');
  return result;
}

/**
 * Create a user with a specific role
 */
export async function createUserWithRole(
  app: NestFastifyApplication,
  options: CreateUserOptions & { role: string },
): Promise<CreateUserResult> {
  const { role, ...userOptions } = options;
  const result = await createTestUser(app, userOptions);
  mockSetUserRole(result.user.id, role);
  return result;
}

/**
 * Create a user with specific permissions
 */
export async function createUserWithPermissions(
  app: NestFastifyApplication,
  options: CreateUserOptions & { permissions: string[] },
): Promise<CreateUserResult> {
  const { permissions, ...userOptions } = options;
  const result = await createTestUser(app, userOptions);
  mockSetUserPermissions(result.user.id, permissions);
  return result;
}

/**
 * Set user permissions directly
 */
export function setUserPermissions(
  userId: string,
  permissions: string[],
): void {
  mockSetUserPermissions(userId, permissions);
}

/**
 * Ban a user
 */
export function banUser(userId: string, reason?: string): void {
  mockBanUser(userId, reason);
}

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
 * Create an organization
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
    permissions: string[];
  };
}

/**
 * Create an API Key via Better Auth API
 * Note: In mock environment, this may not work as expected
 * Use createMockApiKeyForUser for testing
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
 * Create an API Key directly in mock storage for testing
 * This bypasses Better Auth API and directly creates a usable key
 */
export function createMockApiKeyForUser(
  userId: string,
  options: {
    name: string;
    permissions?: Record<string, string[]>;
  },
): { key: string; keyData: CreateApiKeyResult['apiKey'] } {
  // Generate a realistic-looking API key
  const key = `pk_test_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`;

  const keyData = mockCreateApiKey({
    key,
    userId,
    name: options.name,
    permissions: options.permissions,
  });

  return {
    key,
    keyData: {
      id: keyData.id,
      key,
      name: keyData.name,
      permissions: Object.entries(keyData.permissions).flatMap(
        ([resource, actions]) =>
          actions.map((action) => `${resource}:${action}`),
      ),
    },
  };
}

/**
 * Generate a unique test email address
 */
export function generateTestEmail(prefix: string = 'test'): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  return `${prefix}-${timestamp}-${random}@test.com`;
}

/**
 * Wait for a specified duration (useful for testing fresh session scenarios)
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create an authenticated request
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
  };
}
