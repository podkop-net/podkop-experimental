import { normalizeCompiledVersion } from './normalizeCompiledVersion';

// The tag of the latest release of podkop-exp, asked of GitHub by the browser (its API allows
// any origin) and kept for an hour: the router asks nothing outside, and the limit of the API
// (60 requests an hour from one address) is not spent at every opening of a tab. A failed
// request is kept too, for 10 minutes, so that a browser that cannot reach GitHub does not
// wait for it at every opening. The tag is kept for the version of the page that asked
// (luci-app-podkop-exp, the version its package wrote into it): after an upgrade or a
// downgrade the new page asks again. A page of the sources (its version not written) keeps
// nothing. Empty when it is not known.
const RELEASE_URL =
  'https://api.github.com/repos/podkop-net/podkop-experimental/releases/latest';
const CACHE_KEY = 'podkop-latest-release';
const CACHE_MS = 60 * 60 * 1000;
const FAILURE_MS = 10 * 60 * 1000;

interface Cached {
  tag: string;
  at: number;
  // the version of the page that asked
  page: string;
}

// readCachedRelease gives the kept tag ('' for a kept failure), or undefined when nothing
// usable is kept for the page of this version: nothing, something broken, a tag asked by a
// page of another version or by an older page (no version kept), or one asked too long ago.
export function readCachedRelease(
  now: number,
  raw: string | null,
  page: string,
): string | undefined {
  if (!raw) return undefined;
  try {
    const cached = JSON.parse(raw) as Cached;
    if (typeof cached.tag !== 'string' || typeof cached.at !== 'number') {
      return undefined;
    }
    if (cached.page !== page) return undefined;
    if (now - cached.at < (cached.tag ? CACHE_MS : FAILURE_MS)) {
      return cached.tag;
    }
  } catch {
    // a broken value is asked again
  }
  return undefined;
}

function keep(tag: string, page: string) {
  try {
    const cached: Cached = { tag, at: Date.now(), page };
    localStorage.setItem(CACHE_KEY, JSON.stringify(cached));
  } catch {
    // no storage
  }
}

async function ask(): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    // no-cache: the browser's own copy of the answer is used only when GitHub says it is
    // still the current one
    const response = await fetch(RELEASE_URL, {
      signal: controller.signal,
      cache: 'no-cache',
    });
    if (!response.ok) return '';
    const tag = ((await response.json()) as { tag_name?: string }).tag_name;
    return typeof tag === 'string' ? tag : '';
  } catch {
    return '';
  } finally {
    clearTimeout(timer);
  }
}

// getLatestRelease gives the tag of the latest release for the page of version page
// (PODKOP_LUCI_APP_VERSION).
export async function getLatestRelease(page: string): Promise<string> {
  if (normalizeCompiledVersion(page) === 'dev') return ask();
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(CACHE_KEY);
  } catch {
    // no storage: asked every time
  }
  const cached = readCachedRelease(Date.now(), stored, page);
  if (cached !== undefined) return cached;
  const tag = await ask();
  keep(tag, page);
  return tag;
}
