// Versions of podkop-exp as the packages and the releases write them: v0.8.20 (a tag, and the
// version of an opkg package), 0.8.20 (an apk package), 0.8.19.3 (a candidate of a release),
// 0.20112026 (a build without a tag, named by its date). A package release (-r1) is dropped.
const VERSION = /^v?(\d+(?:\.\d+)*)(?:-r\d+)?$/;

// releaseNumbers gives the numbers of a version, or undefined for what is not one: 'dev',
// '0.8.0-dev' (a backend built without a version), 'unknown'.
export function releaseNumbers(version: string): number[] | undefined {
  const match = VERSION.exec(version.trim());
  return match ? match[1].split('.').map(Number) : undefined;
}

// isRelease: a version of a release has three numbers (0.8.20); a candidate (0.8.20.1) or a
// build by date (0.20112026) does not.
export function isRelease(version: string): boolean {
  return releaseNumbers(version)?.length === 3;
}

// compareVersions orders two versions number by number, a missing number counted as 0: -1 when
// a is older, 1 when it is newer, 0 when they are the same; undefined when either is not a
// version.
export function compareVersions(a: string, b: string): -1 | 0 | 1 | undefined {
  const left = releaseNumbers(a);
  const right = releaseNumbers(b);
  if (!left || !right) return undefined;
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const x = left[i] ?? 0;
    const y = right[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
