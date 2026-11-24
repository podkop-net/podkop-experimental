import { expect, it, vi } from 'vitest';

// what the program prints
let stdout = '';
const executeShellCommand = vi.fn(() =>
  Promise.resolve({ stdout, stderr: '', code: 0 }),
);
vi.mock('../../../../helpers', () => ({ executeShellCommand }));

const { PodkopShellMethods } = await import('../index');

it.each([
  ['0.8.23\n', '0.8.23'],
  ['v0.8.23\n', 'v0.8.23'],
  // a build by date is a number to JSON (0.1112203)
  ['0.11122030\n', '0.11122030'],
  // nothing answered
  ['', ''],
])('showVersion of %j', async (printed, version) => {
  stdout = printed;
  expect(await PodkopShellMethods.showVersion()).toBe(version);
  expect(executeShellCommand).toHaveBeenLastCalledWith({
    command: '/usr/bin/podkop',
    args: ['show_version'],
  });
});
