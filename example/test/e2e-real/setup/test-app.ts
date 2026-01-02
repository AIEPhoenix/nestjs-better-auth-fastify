/**
 * E2E Test Application Factory
 *
 * Creates test application using real better-auth
 */
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Module } from '@nestjs/common';
import { AuthModule } from '@sapix/nestjs-better-auth-fastify';
import {
  createTestAuth,
  closeTestDb,
  clearTestData,
  type TestAuth,
} from './test-auth.config';

// Import controllers from example
import { AppController } from '../../../src/app.controller';
import { AppService } from '../../../src/app.service';
import { UserController } from '../../../src/user/user.controller';
import { AdminController } from '../../../src/admin/admin.controller';
import { ApiKeysController } from '../../../src/api-keys/api-keys.controller';
import { OrganizationController } from '../../../src/organization/organization.controller';
import { AuthHooksService } from '../../../src/auth/auth-hooks.service';

let app: NestFastifyApplication | null = null;
let testAuth: TestAuth | null = null;

/**
 * Create test AppModule
 * Uses test-specific auth configuration
 */
function createTestAppModule(auth: TestAuth) {
  @Module({
    imports: [
      AuthModule.forRoot({
        auth,
      }),
    ],
    controllers: [
      AppController,
      UserController,
      AdminController,
      ApiKeysController,
      OrganizationController,
    ],
    providers: [AppService, AuthHooksService],
  })
  class TestAppModule {}

  return TestAppModule;
}

/**
 * Create and initialize test application
 * Uses real better-auth
 */
export async function createTestApp(): Promise<NestFastifyApplication> {
  // Create new auth instance (with new in-memory database including table migrations)
  testAuth = await createTestAuth();

  const TestAppModule = createTestAppModule(testAuth);

  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [TestAppModule],
  }).compile();

  app = moduleFixture.createNestApplication<NestFastifyApplication>(
    new FastifyAdapter(),
  );

  await app.init();
  await app.getHttpAdapter().getInstance().ready();

  return app;
}

/**
 * Get current test application instance
 */
export function getTestApp(): NestFastifyApplication | null {
  return app;
}

/**
 * Get current test auth instance
 */
export function getTestAuth(): TestAuth | null {
  return testAuth;
}

/**
 * Close test application
 */
export async function closeTestApp(): Promise<void> {
  if (app) {
    await app.close();
    app = null;
  }
  closeTestDb();
  testAuth = null;
}

/**
 * Reset test data (keep table structure)
 * Used to clean up data between tests
 */
export function resetTestData(): void {
  clearTestData();
}
