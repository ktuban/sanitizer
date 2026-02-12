module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!**/node_modules/**',
    '!**/dist/**',
    '!**/tests/**'
  ],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: {
          module: 'ESNext',
          target: 'ES2022'
        }
      }
    ]
  },
  transformIgnorePatterns: [
    'node_modules/(?!(@exodus\\/bytes|jsdom|dompurify|html-encoding-sniffer|whatwg-encoding)/)'
  ],
  moduleFileExtensions: ['ts', 'js', 'json', 'node']
};
