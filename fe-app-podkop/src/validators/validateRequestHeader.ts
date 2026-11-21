import { ValidationResult } from './types';

// The User-Agent and the extra headers a subscription is asked with. The rules are those of the
// backend (src/backend/subscription/request.go, ParseCustom): a change goes into both, and into
// the tables of both tests (tests/validateRequestHeader.test.ts, request_test.go).

export const MAX_AGENT = 256;
export const MAX_NAME = 64;
export const MAX_VALUE = 1024;
export const MAX_HEADERS = 8;
export const MAX_CUSTOM = 4096;

// a line the backend leaves out of the request: its number among the header lines (0: the
// User-Agent), the name when it is one a header can have, and why (the code of the backend)
export interface RequestProblem {
  line: number;
  code: string;
  name?: string;
  args?: string[];
  text?: string;
}

export interface RequestField {
  name: string;
  value: string;
}

export interface ParsedRequest {
  userAgent: string;
  headers: RequestField[];
  problems: RequestProblem[];
}

// what the page sends the backend with an address (subscription_load, group_check): the preset
// of the User-Agent, the User-Agent of custom, the header lines
export interface ListRequest {
  user_agent_preset?: string;
  user_agent?: string;
  headers?: string[];
}

// The User-Agent a subscription is asked as (option user_agent_preset): podkop's own (none, or
// podkop), an app whose User-Agent the backend sends (src/backend/subscription, the presets), or
// another one, typed in the option user_agent (custom). The backend turns a preset into the
// header at request time.
export const AGENT_PRESETS = ['podkop', 'happ', 'incy', 'sing-box', 'custom'];

// agentPreset is the preset a subscription is asked as: the one set, else custom when a
// User-Agent is set (a file written by hand), else podkop
export function agentPreset(preset: unknown, agent: unknown): string {
  const chosen = trimmed(preset);
  if (chosen) return chosen;
  return trimmed(agent) ? 'custom' : 'podkop';
}

// customAgent is the User-Agent of the option user_agent that is sent: only that of custom
export function customAgent(preset: unknown, agent: unknown): string {
  return agentPreset(preset, agent) === 'custom' ? trimmed(agent) : '';
}

// presetName is how the page names a preset; one it does not know, as it is
export function presetName(preset: unknown): string {
  const chosen = trimmed(preset);
  switch (chosen) {
    case '':
    case 'podkop':
      return 'podkop';
    case 'happ':
      return 'Happ';
    case 'incy':
      return 'INCY';
    case 'sing-box':
      return 'sing-box (SFA)';
    case 'custom':
      return _('Another User-Agent');
  }
  return chosen;
}

// the headers of the connection itself: Go writes them, ignores them or refuses them over
// HTTP/2; with an Accept-Encoding of its own Go would not unpack the body
const CONNECTION_NAMES = [
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'proxy-connection',
  'upgrade',
  'te',
  'trailer',
  'expect',
  'accept-encoding',
];

// the headers that ask for a part of the list or none
const PARTIAL_NAMES = [
  'range',
  'if-range',
  'if-match',
  'if-none-match',
  'if-modified-since',
  'if-unmodified-since',
];

// the names of a device's identity (x-hwid, Device-Id, X-Hardware-Id…) and of the address of the
// client (X-Forwarded-For, CF-Connecting-IPv6, X-Azure-ClientIP, X-Envoy-External-Address…)
const DEVICE_PARTS = ['hwid', 'device-id', 'deviceid', 'hardware-id'];
const CLIENT_PARTS = ['forwarded', 'clientip', 'socketip'];
const CLIENT_ENDS = ['-ip', '-ipv4', '-ipv6', '-ip6', '-addr', '-address'];

// deniedHeader is why a header of this name is not sent, '' when it may be: the identity of
// the router (it sends its own and takes its own place among the devices), the address of the
// client, the User-Agent (it is chosen in Ask as), the connection, a part of the list, a proxy
export function deniedHeader(name: string): string {
  const lower = name.toLowerCase();
  if (
    DEVICE_PARTS.some((part) => lower.includes(part)) ||
    lower.startsWith('x-device') ||
    lower === 'x-ver-os'
  )
    return 'device';
  if (
    CLIENT_PARTS.some((part) => lower.includes(part)) ||
    CLIENT_ENDS.some((end) => lower.endsWith(end))
  )
    return 'client';
  if (lower === 'user-agent') return 'agent';
  if (CONNECTION_NAMES.includes(lower)) return 'connection';
  if (PARTIAL_NAMES.includes(lower)) return 'partial';
  if (lower.startsWith('proxy-')) return 'proxy';
  return '';
}

// the white space Go's strings.TrimSpace takes off (JavaScript's trim takes U+FEFF too)
const SPACE =
  /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g;

function trimmed(text: unknown): string {
  return String(text ?? '').replace(SPACE, '');
}

// printable ASCII only: no line break or NUL that would put another header into the request
function printable(text: string): boolean {
  return /^[\x20-\x7e]*$/.test(text);
}

// the items of the option header: a list, or one line an option holds
export function headerLines(value: unknown): string[] {
  if (value == null) return [];
  return (Array.isArray(value) ? value : [value]).map((item) =>
    String(item ?? ''),
  );
}

// parseRequest reads the User-Agent and the header lines as the backend does: what cannot be
// sent is left out, each with its problem, and the rest is sent
export function parseRequest(agent: unknown, lines: unknown): ParsedRequest {
  const problems: RequestProblem[] = [];
  let userAgent = '';
  const text = trimmed(agent);
  if (text) {
    if (!printable(text)) problems.push({ line: 0, code: 'chars' });
    else if (text.length > MAX_AGENT)
      problems.push({ line: 0, code: 'long', args: [String(MAX_AGENT)] });
    else userAgent = text;
  }
  const headers: RequestField[] = [];
  const seen = new Set<string>();
  let size = 0;
  headerLines(lines).forEach((raw, index) => {
    const item = trimmed(raw);
    if (!item) return;
    const line = index + 1;
    const colon = item.indexOf(':');
    const name = colon < 0 ? '' : trimmed(item.slice(0, colon));
    const value = colon < 0 ? '' : trimmed(item.slice(colon + 1));
    const left = (code: string, named: boolean, limit?: number) =>
      problems.push({
        line,
        code,
        ...(named ? { name } : {}),
        ...(limit ? { args: [String(limit)] } : {}),
      });
    if (colon < 0 || !name) return left('syntax', false);
    if (!/^[A-Za-z0-9-]+$/.test(name)) return left('name', false);
    if (name.length > MAX_NAME) return left('name-long', false, MAX_NAME);
    const denied = deniedHeader(name);
    if (denied) return left(denied, true);
    const lower = name.toLowerCase();
    if (!value) return left('empty', true);
    if (!printable(value)) return left('chars', true);
    if (value.length > MAX_VALUE) return left('long', true, MAX_VALUE);
    if (seen.has(lower)) return left('twice', true);
    if (headers.length >= MAX_HEADERS) return left('count', true, MAX_HEADERS);
    if (size + name.length + 2 + value.length > MAX_CUSTOM)
      return left('size', true, MAX_CUSTOM);
    seen.add(lower);
    size += name.length + 2 + value.length;
    headers.push({ name, value });
  });
  return { userAgent, headers, problems };
}

// requestProblemText is why a line is not sent, as the field's check says it
export function requestProblemText(problem: RequestProblem): string {
  const name = problem.name || '';
  const limit = Number(problem.args?.[0]) || 0;
  switch (problem.code) {
    case 'device':
      return _(
        'The router sends the device identifier itself: %s cannot be set',
      ).format(name);
    case 'client':
      return _(
        "The address of the client is the router's own: %s cannot be set",
      ).format(name);
    case 'agent':
      return _('The User-Agent is chosen in Ask as');
    case 'connection':
      return _('%s belongs to the connection: podkop sets it itself').format(
        name,
      );
    case 'partial':
      return _(
        'With %s the provider would send a part of the list or none: podkop needs the whole list',
      ).format(name);
    case 'proxy':
      return _(
        '%s is for a proxy on the way: the router has none, and the value would go to the provider',
      ).format(name);
    case 'syntax':
      return _('Name: value is expected');
    case 'name':
      return _('A header name has Latin letters, digits and dashes only');
    case 'name-long':
      return _('The name is longer than %d characters').format(limit);
    case 'empty':
      return _('The value is empty');
    case 'chars':
      return _(
        'Only Latin letters, digits, spaces and the signs of the keyboard',
      );
    case 'long':
      return _('At most %d characters').format(limit);
    case 'twice':
      return _('%s is given twice').format(name);
    case 'count':
      return _('At most %d headers').format(limit);
    case 'size':
      return _('The headers together are longer than %d bytes').format(limit);
  }
  return problem.text || '';
}

// requestProblemLine names the line and tells why: "Header 2: …", "User-Agent: …"
export function requestProblemLine(problem: RequestProblem): string {
  const where =
    problem.line > 0 ? _('Header %d').format(problem.line) : 'User-Agent';
  return where + ': ' + requestProblemText(problem);
}

// requestProblem is the first line of a request that cannot be sent, '' when all can
export function requestProblem(agent: unknown, lines: unknown): string {
  const first = parseRequest(agent, lines).problems[0];
  return first ? requestProblemLine(first) : '';
}

export function validateUserAgent(value: unknown): ValidationResult {
  const problem = parseRequest(value, []).problems[0];
  return problem
    ? { valid: false, message: requestProblemText(problem) }
    : { valid: true, message: '' };
}

// validateRequestHeader checks the header being typed against the items added already: LuCI
// checks only the text being typed, and that text is in the value of the list too once it is
// valid, so the others are given apart
export function validateRequestHeader(
  value: unknown,
  added: unknown,
): ValidationResult {
  if (!trimmed(value)) return { valid: true, message: '' };
  const lines = headerLines(added).concat(String(value));
  const problem = parseRequest('', lines).problems.find(
    (item) => item.line === lines.length,
  );
  return problem
    ? { valid: false, message: requestProblemText(problem) }
    : { valid: true, message: '' };
}

// listRequest is what the page sends with an address: the preset, the User-Agent of custom and
// the header lines as the form or the settings have them (the backend reads them as it reads the
// settings). podkop's own User-Agent is sent as nothing, a preset by its name, custom with its
// User-Agent (one left empty is podkop's own); a User-Agent of the form or the settings under
// another preset is not sent.
export function listRequest(
  agent: unknown,
  lines: unknown,
  preset?: unknown,
): ListRequest {
  const request: ListRequest = {};
  const chosen = agentPreset(preset, agent);
  const userAgent = customAgent(preset, agent);
  const headers = headerLines(lines);
  if (chosen === 'custom') {
    if (userAgent) {
      request.user_agent_preset = chosen;
      request.user_agent = userAgent;
    }
  } else if (chosen !== 'podkop') {
    request.user_agent_preset = chosen;
  }
  if (headers.some((line) => trimmed(line))) request.headers = headers;
  return request;
}

// sameRequest tells whether two requests are the same, as listRequest makes them: none, '' and
// [] alike, the lines trimmed and the empty ones left out, a User-Agent alone as custom, the
// User-Agent of another preset left out
export function sameRequest(
  agent: unknown,
  lines: unknown,
  otherAgent: unknown,
  otherLines: unknown,
  preset?: unknown,
  otherPreset?: unknown,
): boolean {
  const normal = (value: unknown) =>
    headerLines(value).map(trimmed).filter(Boolean).join('\n');
  const asked = (chosen: unknown, text: unknown) => {
    const request = listRequest(text, [], chosen);
    return (
      (request.user_agent_preset ?? '') + '\n' + (request.user_agent ?? '')
    );
  };
  return (
    asked(preset, agent) === asked(otherPreset, otherAgent) &&
    normal(lines) === normal(otherLines)
  );
}

// loadArguments are the arguments of a download of a list for the page: the address, and the
// request as JSON when it has anything (a backend before requests takes the address alone, and
// ignores the argument after it)
export function loadArguments(
  address: string,
  request?: ListRequest,
): string[] {
  const asked =
    request?.user_agent_preset ||
    request?.user_agent ||
    request?.headers?.length;
  return asked ? [address, JSON.stringify(request)] : [address];
}
