module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transformIgnorePatterns: ['node_modules/(?!(@ethereumjs|@noble)/)'],
  transform: {
    '^.+\\.[jt]sx?$': 'ts-jest',
  },
  globalSetup: './jest/globalsetup.ts',
  globalTeardown: './jest/globalteardown.ts',
  setupFilesAfterEnv: ['./jest/setup.ts'],
  reporters: ['default', ['summary', { summaryThreshold: 1 }]],
}
