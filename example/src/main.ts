import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
  );

  // Swagger configuration
  const config = new DocumentBuilder()
    .setTitle('NestJS Better Auth Fastify Example')
    .setDescription(
      'API documentation for @sapix/nestjs-better-auth-fastify example application. ' +
        'This demonstrates integration of Better Auth with NestJS + Fastify.',
    )
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Enter your Bearer token or session token',
      },
      'bearer',
    )
    .addCookieAuth(
      'better-auth.session_token',
      {
        type: 'apiKey',
        in: 'cookie',
        description: 'Session cookie set by Better Auth',
      },
      'session',
    )
    .addApiKey(
      {
        type: 'apiKey',
        in: 'header',
        name: 'x-api-key',
        description: 'API Key for programmatic access',
      },
      'api-key',
    )
    .addTag('App', 'Basic application routes and AuthService examples')
    .addTag('Auth', 'Better Auth authentication routes')
    .addTag('Users', 'User management and profile routes')
    .addTag('Admin', 'Administrative operations (requires admin role)')
    .addTag('API Keys', 'API key management and authentication')
    .addTag('Organizations', 'Organization management (requires org plugin)')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      tagsSorter: 'alpha',
      operationsSorter: 'alpha',
    },
  });

  await app.listen(process.env.PORT ?? 3000);
  console.log(`Application is running on: ${await app.getUrl()}`);
  console.log(`Swagger docs available at: ${await app.getUrl()}/docs`);
}

bootstrap();
