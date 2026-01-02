import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { AppModule } from '../../../src/app.module';

let app: NestFastifyApplication;

/**
 * Create and initialize the test application
 */
export async function createTestApp(): Promise<NestFastifyApplication> {
  const moduleFixture: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleFixture.createNestApplication<NestFastifyApplication>(
    new FastifyAdapter(),
  );

  await app.init();
  await app.getHttpAdapter().getInstance().ready();

  return app;
}

/**
 * Get the current test application instance
 */
export function getTestApp(): NestFastifyApplication {
  return app;
}

/**
 * Close the test application
 */
export async function closeTestApp(): Promise<void> {
  if (app) {
    await app.close();
  }
}
