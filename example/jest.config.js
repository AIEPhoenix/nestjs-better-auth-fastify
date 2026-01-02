/** @type {import('jest').Config} */
module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: '..',
  roots: ['<rootDir>/example/src', '<rootDir>/example/test/package'],
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': [
      'ts-jest',
      {
        tsconfig: '<rootDir>/example/tsconfig.json',
        diagnostics: {
          ignoreCodes: [151002],
        },
      },
    ],
  },
  setupFilesAfterEnv: ['<rootDir>/example/test/setup.ts'],
  moduleNameMapper: {
    '^@sapix/nestjs-better-auth-fastify$': '<rootDir>/src/index.ts',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  collectCoverageFrom: [
    '<rootDir>/src/**/*.ts',
  ],
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '\\.spec\\.ts$',
    '\\.d\\.ts$',
  ],
  coverageDirectory: '<rootDir>/example/coverage',
  testEnvironment: 'node',
};
