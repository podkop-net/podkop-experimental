import { beforeEach, describe, expect, it, vi } from 'vitest';
import { forceDetect, getVerdicts } from '../getVerdicts';
import { logger } from '../../../services/logger.service';

const calls: Record<string, { call: ReturnType<typeof vi.fn> }> = {};
const declare = vi.fn(({ method }: { method: string }) => {
  calls[method] = { call: vi.fn() };
  return (...args: unknown[]) => calls[method].call(...args);
});
vi.stubGlobal('rpc', { declare });

const REPLY = {
  verdicts: { 'sub: DE': { block: 'freeze', source: 'active', age: 42 } },
  probing: 'sub: IT',
  queued: ['sub: ES'],
  noprobe: ['prov: X via own'],
  fallback: true,
};

describe('getVerdicts', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    // the declaration is made once: the first call of the first test
    if (calls.detect) calls.detect.call = vi.fn();
    if (calls.force_detect) calls.force_detect.call = vi.fn();
  });

  it('declares the methods once, on the first call', async () => {
    await getVerdicts();
    await getVerdicts();
    await forceDetect('sub: DE');
    await forceDetect('sub: NL');
    const declared = declare.mock.calls.map(([options]) => options);
    expect(declared).toEqual([
      { object: 'podkop', method: 'detect', nobatch: true },
      {
        object: 'podkop',
        method: 'force_detect',
        params: ['tag', 'cancel'],
        nobatch: true,
      },
    ]);
  });

  it('passes a report on', async () => {
    calls.detect.call.mockResolvedValue(REPLY);
    expect(await getVerdicts()).toEqual(REPLY);
  });

  it('fills what a report lacks', async () => {
    calls.detect.call.mockResolvedValue({ fallback: true });
    expect(await getVerdicts()).toEqual({
      verdicts: {},
      probing: '',
      queued: [],
      noprobe: [],
      fallback: true,
    });
  });

  it('takes a bare ubus status for an empty report', async () => {
    calls.detect.call.mockResolvedValue(3);
    expect((await getVerdicts())?.verdicts).toEqual({});
  });

  it('keeps a denial visible in the console, once while it lasts', async () => {
    const warn = vi.spyOn(logger, 'warn');
    const denied = new Error(
      'RPC call to podkop/detect failed with error -32002: Access denied',
    );
    calls.detect.call.mockRejectedValue(denied);
    expect((await getVerdicts())?.verdicts).toEqual({});
    await getVerdicts();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0].join(' ')).toContain('Access denied');

    // an answer ends it: the same denial later is told again
    calls.detect.call.mockResolvedValue(REPLY);
    await getVerdicts();
    calls.detect.call.mockRejectedValue(denied);
    await getVerdicts();
    expect(warn).toHaveBeenCalledTimes(2);
  });

  it('leaves the page as it is when no answer came', async () => {
    calls.detect.call.mockRejectedValue(new Error('XHR request timed out'));
    expect(await getVerdicts()).toBeUndefined();
  });
});

describe('forceDetect', () => {
  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    calls.force_detect.call = vi.fn();
  });

  it('sends the tag and the cancel', async () => {
    calls.force_detect.call.mockResolvedValue({ state: 'started' });
    expect(await forceDetect('sub: DE')).toEqual({ state: 'started' });
    expect(calls.force_detect.call).toHaveBeenLastCalledWith('sub: DE', false);
    calls.force_detect.call.mockResolvedValue({ state: 'canceled' });
    expect(await forceDetect('', true)).toEqual({ state: 'canceled' });
    expect(calls.force_detect.call).toHaveBeenLastCalledWith('', true);
  });

  it('says undefined for a status and for a failure, and logs them', async () => {
    const error = vi.spyOn(logger, 'error');
    calls.force_detect.call.mockResolvedValue(2);
    expect(await forceDetect('sub: DE')).toBeUndefined();
    calls.force_detect.call.mockRejectedValue(new Error('Access denied'));
    expect(await forceDetect('sub: DE')).toBeUndefined();
    expect(error).toHaveBeenCalledTimes(2);
  });

  it('tells a call the ACL of the session refused', async () => {
    calls.force_detect.call.mockRejectedValue(
      new Error(
        'RPC call to podkop/force_detect failed with error -32002: Access denied',
      ),
    );
    expect(await forceDetect('sub: DE')).toEqual({ state: 'denied' });
    calls.force_detect.call.mockRejectedValue(
      new Error(
        'RPC call to podkop/force_detect failed with HTTP error 502: Bad Gateway',
      ),
    );
    expect(await forceDetect('sub: DE')).toBeUndefined();
  });
});
