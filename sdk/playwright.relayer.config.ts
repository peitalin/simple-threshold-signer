export default {
  testDir: '../tests',
  testMatch: [
    '**/relayer/**/*.test.ts',
  ],
  fullyParallel: false,
  retries: 0,
  workers: 1,
  timeout: 30_000,
  reporter: 'html',
};
