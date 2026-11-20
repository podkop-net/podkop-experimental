import { describe, expect, it } from 'vitest';
import { compareVersions, isRelease, releaseNumbers } from '../compareVersions';

describe('releaseNumbers', () => {
  it.each([
    ['v0.8.20', [0, 8, 20]],
    ['0.8.20', [0, 8, 20]],
    [' 0.8.20 ', [0, 8, 20]],
    ['0.8.19.3', [0, 8, 19, 3]],
    ['0.20112026', [0, 20112026]],
    ['0.8.20-r1', [0, 8, 20]],
  ])('%s gives its numbers', (version, numbers) => {
    expect(releaseNumbers(version)).toEqual(numbers);
  });

  it.each(['dev', '0.8.0-dev', 'unknown', '', 'v', '0.8.', '0..8', 'x0.8.20'])(
    '%j is not a version',
    (version) => {
      expect(releaseNumbers(version)).toBeUndefined();
    },
  );
});

describe('isRelease', () => {
  it.each([
    ['v0.8.20', true],
    ['0.8.20', true],
    ['0.8.20-r1', true],
    ['0.8.20.1', false],
    ['0.20112026', false],
    ['0.8.0-dev', false],
    ['dev', false],
  ])('%s: %s', (version, release) => {
    expect(isRelease(version)).toBe(release);
  });
});

describe('compareVersions', () => {
  it.each([
    ['v0.8.20', '0.8.20', 0],
    ['0.8.20', 'v0.8.20', 0],
    ['0.8.20-r1', 'v0.8.20', 0],
    ['0.8.20.0', '0.8.20', 0],
    ['0.8.9', '0.8.10', -1],
    ['0.8.10', '0.8.9', 1],
    ['0.8.19', 'v0.8.20', -1],
    ['0.8.19.3', 'v0.8.20', -1],
    ['0.8.20.1', 'v0.8.20', 1],
    ['0.20112026', 'v0.8.20', 1],
    ['v0.9.0', 'v0.8.20', 1],
    ['v1.0.0', 'v0.99.99', 1],
  ])('%s to %s: %d', (a, b, order) => {
    expect(compareVersions(a, b)).toBe(order);
  });

  it.each([
    ['dev', 'v0.8.20'],
    ['0.8.0-dev', 'v0.8.20'],
    ['unknown', 'v0.8.20'],
    ['', 'v0.8.20'],
    ['0.8.20', ''],
    ['0.8.20', 'unknown'],
  ])('%j to %j: not known', (a, b) => {
    expect(compareVersions(a, b)).toBeUndefined();
  });
});
