import { describe, expect, it } from 'vitest';
import {
  listRequest,
  loadArguments,
  parseRequest,
  requestProblem,
  sameRequest,
  validateRequestHeader,
  validateUserAgent,
} from '../validateRequestHeader';

// The tables are those of the backend (src/backend/subscription/request_test.go): a row added
// here goes there too, with the same verdict.

const DENIED: [string, string][] = [
  ['x-hwid', 'device'],
  ['X-HWID', 'device'],
  ['hwid', 'device'],
  ['x-hwid-limit', 'device'],
  ['x-device-os', 'device'],
  ['X-Device-Model', 'device'],
  ['x-device-locale', 'device'],
  ['x-ver-os', 'device'],
  ['Device-Id', 'device'],
  ['X-App-Device-Id', 'device'],
  ['X-Client-Device-Id', 'device'],
  ['X-Hardware-Id', 'device'],
  ['X-Forwarded-For', 'client'],
  ['X-Real-IP', 'client'],
  ['Forwarded', 'client'],
  ['True-Client-IP', 'client'],
  ['CF-Connecting-IP', 'client'],
  ['X-Client-IP', 'client'],
  ['X-Cluster-Client-IP', 'client'],
  ['X-Forwarded-Host', 'client'],
  ['CF-Connecting-IPv6', 'client'],
  ['X-Envoy-External-Address', 'client'],
  ['X-Azure-ClientIP', 'client'],
  ['X-Azure-SocketIP', 'client'],
  ['X-Client-Address', 'client'],
  ['User-Agent', 'agent'],
  ['user-agent', 'agent'],
  ['Host', 'connection'],
  ['Content-Length', 'connection'],
  ['Transfer-Encoding', 'connection'],
  ['Connection', 'connection'],
  ['Keep-Alive', 'connection'],
  ['Proxy-Connection', 'connection'],
  ['Upgrade', 'connection'],
  ['TE', 'connection'],
  ['Trailer', 'connection'],
  ['Expect', 'connection'],
  ['Accept-Encoding', 'connection'],
  ['Range', 'partial'],
  ['If-Range', 'partial'],
  ['If-Match', 'partial'],
  ['If-None-Match', 'partial'],
  ['If-Modified-Since', 'partial'],
  ['If-Unmodified-Since', 'partial'],
  ['Proxy-Authorization', 'proxy'],
];

const ALLOWED = [
  'Authorization',
  'Cookie',
  'Accept',
  'Referer',
  'X-Api-Key',
  'X-Age-Public-Key',
  'Accept-Language',
];

const repeat = (char: string, count: number) => char.repeat(count);

const SYNTAX: [string, string[], string, number][] = [
  ['no colon', ['Authorization Bearer s3cret'], 'syntax', 1],
  ['no name', [': s3cret'], 'syntax', 1],
  ['a space in the name', ['Bad Name: s3cret'], 'name', 1],
  ['a NUL in the name', ['X-A\u0000b: s3cret'], 'name', 1],
  ['a quote in the name', ["X'Key: s3cret"], 'name', 1],
  ['a token sign in the name', ['X_Key: s3cret'], 'name', 1],
  ['a Cyrillic name', ['Ключ: s3cret'], 'name', 1],
  ['a line break in the value', ['N: a\r\nX-Inject: s3cret'], 'chars', 1],
  ['an empty value', ['X-A:  '], 'empty', 1],
  ['a Cyrillic value', ['X-A: s3cret-ключ'], 'chars', 1],
  ['a name of 65', [repeat('n', 65) + ': s3cret'], 'name-long', 1],
  ['a value of 1025', ['X-A: s3cret' + repeat('v', 1019)], 'long', 1],
  ['a name twice', ['X-A: 1', 'x-a: s3cret'], 'twice', 2],
  [
    'a ninth header',
    [
      'H1: 1',
      'H2: 2',
      'H3: 3',
      'H4: 4',
      'H5: 5',
      'H6: 6',
      'H7: 7',
      'H8: 8',
      'H9: s3cret',
    ],
    'count',
    9,
  ],
  [
    'over 4096 bytes',
    [
      'H1: ' + repeat('a', 1000),
      'H2: ' + repeat('b', 1000),
      'H3: ' + repeat('c', 1000),
      'H4: ' + repeat('d', 1000),
      'H5: s3cret' + repeat('e', 100),
    ],
    'size',
    5,
  ],
];

describe('parseRequest', () => {
  it('reads the User-Agent and the header lines as the backend does', () => {
    const parsed = parseRequest('  INCY  ', [
      'Authorization: Bearer t',
      ' Accept : application/octet-stream ',
      '',
      'X-Api-Key:k:1',
    ]);
    expect(parsed.problems).toEqual([]);
    expect(parsed.userAgent).toBe('INCY');
    expect(parsed.headers).toEqual([
      { name: 'Authorization', value: 'Bearer t' },
      { name: 'Accept', value: 'application/octet-stream' },
      { name: 'X-Api-Key', value: 'k:1' },
    ]);
  });

  it.each(DENIED)('leaves out %s (%s)', (name, code) => {
    const parsed = parseRequest('', [name + ': s3cret-value', 'X-Kept: 1']);
    expect(parsed.problems).toEqual([{ line: 1, code, name }]);
    expect(parsed.headers.map((field) => field.name)).toEqual(['X-Kept']);
  });

  it.each(ALLOWED)('sends %s', (name) => {
    expect(parseRequest('', [name + ': v']).problems).toEqual([]);
  });

  it.each(SYNTAX)('refuses %s', (_desc, lines, code, line) => {
    const parsed = parseRequest('', lines);
    expect(parsed.problems).toHaveLength(1);
    expect(parsed.problems[0].code).toBe(code);
    expect(parsed.problems[0].line).toBe(line);
    expect(JSON.stringify(parsed.problems)).not.toContain('s3cret');
    expect(parsed.headers.some((field) => field.value.includes('s3cret'))).toBe(
      false,
    );
    expect(parsed.headers.some((field) => field.name === 'X-Inject')).toBe(
      false,
    );
  });

  it('takes what is at the limits', () => {
    expect(
      parseRequest('', [repeat('n', 64) + ': ' + repeat('v', 1024)]).problems,
    ).toEqual([]);
    expect(
      parseRequest('', [
        'H1: 1',
        'H2: 2',
        'H3: 3',
        'H4: 4',
        'H5: 5',
        'H6: 6',
        'H7: 7',
        'H8: 8',
      ]).problems,
    ).toEqual([]);
    const full = parseRequest('', [
      'H1: ' + repeat('a', 1000),
      'H2: ' + repeat('b', 1000),
      'H3: ' + repeat('c', 1000),
      'H4: ' + repeat('d', 1000),
      'H5: ' + repeat('e', 76),
    ]);
    expect(full.problems).toEqual([]);
    expect(full.headers).toHaveLength(5);
  });

  it('keeps the first of a name; a line left out is not counted twice', () => {
    const parsed = parseRequest('', ['X-A:', 'X-A: 1', 'x-a: 2']);
    expect(parsed.problems).toEqual([
      { line: 1, code: 'empty', name: 'X-A' },
      { line: 3, code: 'twice', name: 'x-a' },
    ]);
    expect(parsed.headers).toEqual([{ name: 'X-A', value: '1' }]);
  });

  it.each([
    ['a\nb', 'chars'],
    ['INCY\u0000', 'chars'],
    ['ИНСИ', 'chars'],
    [repeat('a', 257), 'long'],
  ])('leaves podkop its own User-Agent for %j', (agent, code) => {
    const parsed = parseRequest(agent, []);
    expect(parsed.userAgent).toBe('');
    expect(parsed.problems).toHaveLength(1);
    expect(parsed.problems[0]).toMatchObject({ line: 0, code });
  });

  it('takes a User-Agent of 256 characters', () => {
    expect(parseRequest(repeat('a', 256), []).problems).toEqual([]);
  });

  it('trims as Go does: a byte order mark is no white space', () => {
    expect(parseRequest('', ['X-A: \ufeffv']).problems[0].code).toBe('chars');
    expect(parseRequest('', ['X-A: v\u00a0']).problems).toEqual([]);
  });
});

describe('the checks of the fields', () => {
  it('tells why a User-Agent cannot be sent', () => {
    expect(validateUserAgent('INCY').valid).toBe(true);
    expect(validateUserAgent('').valid).toBe(true);
    expect(validateUserAgent(repeat('a', 300))).toEqual({
      valid: false,
      message: 'At most %d characters'.format(256),
    });
    expect(validateUserAgent('ИНСИ').valid).toBe(false);
  });

  it('checks the header typed against the items added, not against itself', () => {
    // the value LuCI gives holds the typed text too once it is valid: it is not given twice
    expect(validateRequestHeader('X-A: 1', []).valid).toBe(true);
    expect(validateRequestHeader('X-A: 1', ['X-B: 2']).valid).toBe(true);
    expect(validateRequestHeader('x-a: 2', ['X-A: 1'])).toEqual({
      valid: false,
      message: '%s is given twice'.format('x-a'),
    });
    expect(validateRequestHeader('', ['X-A: 1']).valid).toBe(true);
    expect(validateRequestHeader('x-hwid: a', []).message).toBe(
      'The router sends the device identifier itself: %s cannot be set'.format(
        'x-hwid',
      ),
    );
    expect(validateRequestHeader('Bad name: v', []).valid).toBe(false);
    // the ninth: eight are added
    const eight = [
      'H1: 1',
      'H2: 2',
      'H3: 3',
      'H4: 4',
      'H5: 5',
      'H6: 6',
      'H7: 7',
      'H8: 8',
    ];
    expect(validateRequestHeader('H9: 9', eight)).toEqual({
      valid: false,
      message: 'At most %d headers'.format(8),
    });
    expect(validateRequestHeader('H8: 9', eight.slice(0, 7)).valid).toBe(true);
    // an item left out by hand does not make the typed one invalid
    expect(validateRequestHeader('X-A: 1', ['x-hwid: fake']).valid).toBe(true);
  });

  it('names the first line that cannot be sent', () => {
    expect(requestProblem('INCY', ['X-A: 1'])).toBe('');
    expect(requestProblem('INCY', ['X-A: 1', 'x-hwid: s3cret'])).toBe(
      'Header %d'.format(2) +
        ': ' +
        'The router sends the device identifier itself: %s cannot be set'.format(
          'x-hwid',
        ),
    );
    expect(requestProblem('a\nb', [])).toBe(
      'User-Agent: Only Latin letters, digits, spaces and the signs of the keyboard',
    );
  });
});

describe('the request of the form', () => {
  it('is sent only when it has something, the lines as they are', () => {
    expect(listRequest(undefined, undefined)).toEqual({});
    expect(listRequest('', [])).toEqual({});
    expect(listRequest(' INCY ', [])).toEqual({ user_agent: 'INCY' });
    expect(listRequest('', 'X-Api-Key: k 1')).toEqual({
      headers: ['X-Api-Key: k 1'],
    });
    expect(listRequest('', ['x-hwid: fake', ' '])).toEqual({
      headers: ['x-hwid: fake', ' '],
    });
    expect(loadArguments('https://a.example/sub', {})).toEqual([
      'https://a.example/sub',
    ]);
    expect(
      loadArguments('https://a.example/sub', { user_agent: 'INCY' }),
    ).toEqual(['https://a.example/sub', '{"user_agent":"INCY"}']);
  });

  // requestPending of the window: the form against the settings
  it('is the same whatever the empty value of LuCI is', () => {
    // a field never set (uci.get: undefined), an empty text field, an empty list
    expect(sameRequest('', [], undefined, undefined)).toBe(true);
    expect(sameRequest(null, '', undefined, [])).toBe(true);
    expect(sameRequest(' INCY ', ['A: 1 ', ''], 'INCY', ['A: 1'])).toBe(true);
    // an option of one line against the list of the form
    expect(sameRequest('', ['X-Api-Key: k 1'], '', 'X-Api-Key: k 1')).toBe(
      true,
    );
    expect(sameRequest('INCY', [], '', undefined)).toBe(false);
    expect(sameRequest('', ['A: 1'], '', undefined)).toBe(false);
    expect(sameRequest('', ['A: 1', 'B: 2'], '', ['B: 2', 'A: 1'])).toBe(false);
  });
});
