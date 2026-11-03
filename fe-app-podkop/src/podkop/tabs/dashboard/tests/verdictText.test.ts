import { describe, expect, it } from 'vitest';
import {
  checkedAgo,
  forceDetectProblem,
  isWeakVerdict,
  stopsChecks,
  verdictChip,
  verdictLines,
} from '../helpers/verdictText';
import type { Podkop } from '../../../types';

const verdict = (
  block: Podkop.Block,
  source: 'passive' | 'active',
  extra: Partial<Podkop.Verdict> = {},
): Podkop.Verdict => ({ block, source, ...extra });

describe('verdictChip', () => {
  it.each<
    [Podkop.Block, 'passive' | 'active', Podkop.VerdictNote[], string, string]
  >([
    ['none', 'active', [], 'ok', 'ok'],
    ['limit', 'passive', [], 'limit?', 'warn'],
    ['limit', 'active', [], 'limit', 'warn'],
    ['freeze', 'active', ['cured'], 'freeze', 'warn'],
    ['freeze', 'active', ['fallback_off'], 'freeze', 'error'],
    ['freeze', 'active', ['stand_in'], 'freeze', 'warn'],
    ['freeze', 'active', ['stand_in', 'cured'], 'freeze', 'warn'],
    ['wrongparams', 'active', [], 'settings', 'error'],
    ['rejected', 'active', [], 'refused', 'error'],
    ['hellodrop', 'passive', [], 'no TLS', 'error'],
    ['hellodrop', 'active', [], 'no TLS', 'error'],
    ['pathblock', 'active', [], 'no path', 'error'],
    ['dead', 'active', [], 'no answer', 'muted'],
    ['unreachable', 'active', [], 'no answer', 'muted'],
    ['unreachable', 'active', ['relay_silent'], 'no answer', 'muted'],
    ['unreachable', 'passive', [], 'test failed', 'muted'],
    ['unknown', 'active', ['inconclusive'], 'details', 'neutral'],
    ['unknown', 'active', ['probe_hello_refused'], 'details', 'neutral'],
    ['unknown', 'passive', ['handshake_failed'], 'details', 'neutral'],
    [
      'unknown',
      'passive',
      ['handshake_failed', 'needs_mlkem'],
      'details',
      'neutral',
    ],
    ['hellodrop', 'passive', ['needs_mlkem'], 'no TLS', 'error'],
    ['wrongparams', 'active', ['tls_cert'], 'certificate', 'error'],
    ['hellodrop', 'active', ['upgrade_in_dial'], 'no answer', 'error'],
    ['unknown', 'active', ['server_silent'], 'no answer', 'error'],
    [
      'hellodrop',
      'active',
      ['upgrade_in_dial', 'relay_silent'],
      'no answer',
      'error',
    ],
    ['hellodrop', 'active', ['relay_silent'], 'no TLS', 'error'],
  ])('%s from %s with %j', (block, source, notes, label, tone) => {
    expect(verdictChip(verdict(block, source, { notes }))).toEqual({
      label,
      tone,
    });
  });

  it('has no chip for what has nothing to tell', () => {
    expect(verdictChip(undefined)).toBeUndefined();
    expect(verdictChip(verdict('none', 'passive'))).toBeUndefined();
    expect(
      verdictChip(verdict('none', 'passive', { notes: ['needs_mlkem'] })),
    ).toBeUndefined();
    expect(verdictChip(verdict('unknown', 'passive'))).toBeUndefined();
  });

  it.each<[Podkop.Block, Podkop.VerdictNote[]]>([
    ['unknown', ['needs_mlkem']],
    ['unknown', ['fp_switched']],
    ['unknown', ['needs_mlkem', 'fp_switched']],
    ['none', ['fp_switched']],
    ['none', ['needs_mlkem', 'fp_switched']],
  ])('has no chip for a passive %s with only %j', (block, notes) => {
    expect(verdictChip(verdict(block, 'passive', { notes }))).toBeUndefined();
  });

  it('never draws a freeze from what the traffic shows', () => {
    expect(verdictChip(verdict('freeze', 'passive'))).toBeUndefined();
  });

  it.each<[Podkop.Block, Podkop.VerdictNote[]]>([
    ['unknown', ['inconclusive']],
    ['unknown', ['target_failed']],
    ['unknown', ['probe_hello_refused']],
    ['unreachable', ['uplink_down']],
    ['unreachable', ['dns_failed']],
  ])('has the neutral chip for a weak %s with %j', (block, notes) => {
    const weak = verdict(block, 'active', { notes });
    expect(isWeakVerdict(weak)).toBe(true);
    expect(verdictChip(weak)).toEqual({ label: 'details', tone: 'neutral' });
  });

  it('keeps the chip of wrong parameters when the clock is suspect', () => {
    const clock = verdict('wrongparams', 'active', {
      notes: ['clock_suspect'],
    });
    expect(isWeakVerdict(clock)).toBe(true);
    expect(verdictChip(clock)).toEqual({ label: 'settings', tone: 'error' });
    const cert = verdict('wrongparams', 'active', {
      notes: ['clock_suspect', 'tls_cert'],
    });
    expect(isWeakVerdict(cert)).toBe(true);
    expect(verdictChip(cert)).toEqual({ label: 'certificate', tone: 'error' });
  });

  it('takes as weak only what a probe said with one of those notes', () => {
    expect(
      isWeakVerdict(verdict('unknown', 'active', { notes: ['server_silent'] })),
    ).toBe(true);
    expect(isWeakVerdict(undefined)).toBe(false);
    expect(isWeakVerdict(verdict('wrongparams', 'active'))).toBe(false);
    expect(
      isWeakVerdict(verdict('wrongparams', 'active', { notes: ['tls_cert'] })),
    ).toBe(false);
    expect(
      isWeakVerdict(verdict('unknown', 'passive', { notes: ['inconclusive'] })),
    ).toBe(false);
  });
});

describe('verdictLines', () => {
  const ALL_NOTES: Podkop.VerdictNote[] = [
    'needs_mlkem',
    'fp_switched',
    'handshake_failed',
    'clock_suspect',
    'burst_any_fp',
    'uplink_down',
    'dns_failed',
    'target_failed',
    'inconclusive',
    'server_silent',
    'some_lost',
    'through_detour',
    'not_applicable',
    'probe_hello_refused',
    'stand_in',
  ];

  it.each(ALL_NOTES)('has a line of the note %s', (note) => {
    const lines = verdictLines(verdict('unknown', 'active', { notes: [note] }));
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toMatch(/%[sd]/);
  });

  it.each<
    [Podkop.Block, 'passive' | 'active', Partial<Podkop.Verdict>, string]
  >([
    ['limit', 'passive', { kb: 18 }, 'cut at about 18 KB, and none'],
    ['limit', 'active', { kb: 18 }, 'cut at about 18 KB: this is'],
    [
      'freeze',
      'active',
      { fp: 'chrome', notes: ['cured'] },
      'Fingerprint chrome',
    ],
    ['wrongparams', 'active', {}, 'the fault is on the server'],
    ['rejected', 'active', {}, 'closed the requests without an answer'],
    ['rejected', 'active', {}, 'a server with no way out looks the same'],
    ['hellodrop', 'active', {}, 'gets no answer. It looks like a block'],
    ['pathblock', 'active', {}, 'through another server'],
    ['dead', 'active', { n: 2 }, 'other servers (2)'],
    ['unreachable', 'active', {}, 'does not answer from this router'],
    ['unreachable', 'passive', {}, 'The URL test of this server failed'],
    ['none', 'active', {}, 'went through in full'],
  ])('tells %s from %s', (block, source, extra, text) => {
    expect(verdictLines(verdict(block, source, extra)).join(' ')).toContain(
      text,
    );
  });

  it('tells the lost test connections beside a working server', () => {
    const lines = verdictLines(
      verdict('none', 'active', { notes: ['some_lost'] }),
    );
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('went through in full');
    expect(lines[1]).toContain('Some of the test connections');
  });

  it('tells what to do with a freeze by the fallback', () => {
    const cured = verdict('freeze', 'active', {
      fp: 'chrome',
      notes: ['cured'],
    });
    const off = verdict('freeze', 'active', {
      fp: 'chrome',
      notes: ['fallback_off'],
    });
    expect(verdictLines(cured).join(' ')).toContain('nothing needs changing');
    expect(verdictLines(cured)).toHaveLength(1);
    expect(verdictLines(off).join(' ')).toContain('Turn on the uTLS fallback');
    expect(verdictLines(off)).toHaveLength(1);
  });

  it('gives no advice on the fallback when another fingerprint stood in', () => {
    const lines = verdictLines(
      verdict('freeze', 'active', { fp: 'chrome', notes: ['stand_in'] }),
    );
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('It looks like a DPI block');
    expect(lines[0]).not.toContain('fallback in the settings');
    expect(lines[1]).toContain('stood in for it');
    const cured = verdictLines(
      verdict('freeze', 'active', {
        fp: 'chrome',
        notes: ['stand_in', 'cured'],
      }),
    );
    expect(cured).toHaveLength(2);
    expect(cured[0]).toContain('nothing needs changing');
    expect(cured[1]).toContain('stood in for it');
  });

  it('tells a certificate apart from REALITY', () => {
    const reality = verdictLines(verdict('wrongparams', 'active'));
    expect(reality).toHaveLength(1);
    expect(reality[0]).toContain('REALITY check failed');
    const cert = verdictLines(
      verdict('wrongparams', 'active', { notes: ['tls_cert'] }),
    );
    expect(cert).toHaveLength(1);
    expect(cert[0]).toContain('certificate did not pass');
    expect(cert[0]).not.toContain('REALITY');
    const clock = verdictLines(
      verdict('wrongparams', 'active', {
        notes: ['clock_suspect', 'tls_cert'],
      }),
    );
    expect(clock).toHaveLength(2);
    expect(clock[0]).toContain('certificate did not pass');
    expect(clock[1]).toContain('clock');
  });

  it('replaces the line of a hello drop by what was found', () => {
    const line = (notes: Podkop.VerdictNote[]) => {
      const lines = verdictLines(
        verdict('hellodrop', 'active', { notes, n: 2 }),
      );
      expect(lines).toHaveLength(1);
      return lines[0];
    };
    // the line of what was found, then the one of the relay
    const relaySilent = (notes: Podkop.VerdictNote[]) => {
      const lines = verdictLines(
        verdict('hellodrop', 'active', { notes, n: 2 }),
      );
      expect(lines).toHaveLength(2);
      return lines[0];
    };
    expect(relaySilent(['relay_silent'])).toContain(
      'through another server either',
    );
    expect(relaySilent(['relay_silent'])).not.toContain('SNI');
    expect(line(['upgrade_in_dial'])).toContain('WebSocket/HTTP upgrade');
    expect(line(['upgrade_in_dial'])).not.toContain('SNI');
    // both: the relay says more
    expect(relaySilent(['upgrade_in_dial', 'relay_silent'])).toBe(
      relaySilent(['relay_silent']),
    );
  });

  it('tells the four cases of a passive limit, with a button or without', () => {
    const line = (notes: Podkop.VerdictNote[]) =>
      verdictLines(verdict('limit', 'passive', { kb: 18, notes }))[0];
    expect(line([])).toContain('Several connections were cut at about 18 KB');
    expect(line([])).toContain('Check server');
    expect(line(['through_detour'])).toContain('Several connections');
    expect(line(['through_detour'])).not.toContain('Check server');
    expect(line(['download_test'])).toContain('download test of the group');
    expect(line(['download_test'])).not.toContain('short responses');
    expect(line(['download_test'])).toContain('Check server');
    const both = verdictLines(
      verdict('limit', 'passive', {
        kb: 18,
        notes: ['download_test', 'through_detour'],
      }),
    );
    expect(both[0]).toContain('stopped at about 18 KB');
    expect(both[0]).not.toContain('Check server');
    expect(both[1]).toContain('reached through another one');
    expect(both).toHaveLength(2);
  });

  it('says a block is no block only where there is none', () => {
    const text = 'This is not a block';
    const line = (block: Podkop.Block) =>
      verdictLines(verdict(block, 'passive', { notes: ['needs_mlkem'] })).join(
        ' ',
      );
    expect(line('unknown')).toContain(text);
    expect(line('none')).toContain(text);
    for (const block of ['hellodrop', 'unreachable', 'limit'] as const) {
      expect(line(block)).toContain('only connections with ML-KEM');
      expect(line(block)).not.toContain(text);
    }
  });

  it('tells a relay may show the address where one was used', () => {
    for (const block of ['pathblock', 'dead'] as const) {
      expect(verdictLines(verdict(block, 'active')).join(' ')).toContain(
        'whose operator can see',
      );
    }
    expect(
      verdictLines(
        verdict('hellodrop', 'active', { notes: ['relay_silent'] }),
      ).join(' '),
    ).toContain('whose operator can see');
    expect(
      verdictLines(verdict('hellodrop', 'active')).join(' '),
    ).not.toContain('whose operator can see');
  });

  it('does not call a server off for one server that gets no answer from it', () => {
    const lines = verdictLines(
      verdict('unreachable', 'active', { notes: ['relay_silent'], n: 1 }),
    );
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('through another server of yours');
    expect(lines[0]).toContain('may itself be unstable');
    expect(lines[0]).not.toMatch(/ off|blocked|%[sd]/);
    expect(lines[1]).toContain('whose operator can see');
    expect(
      isWeakVerdict(
        verdict('unreachable', 'active', { notes: ['relay_silent'] }),
      ),
    ).toBe(false);
  });

  it('names no fault of a server that TCP reaches, for one relay', () => {
    const line = (n: number, notes: Podkop.VerdictNote[] = ['relay_silent']) =>
      verdictLines(verdict('hellodrop', 'active', { notes, n }));
    for (const lines of [
      line(1),
      line(1, ['upgrade_in_dial', 'relay_silent']),
    ]) {
      expect(lines).toHaveLength(2);
      expect(lines[0]).toContain('through another server of yours either');
      expect(lines[0]).toContain('may itself be unstable');
      expect(lines[0]).not.toContain('fault');
      expect(lines[1]).toContain('whose operator can see');
    }
    expect(line(2)[0]).toContain('It looks like a fault of the server');
    expect(line(2)[0]).not.toContain('unstable');
    // the chip stays: the hello did get no answer
    expect(
      verdictChip(
        verdict('hellodrop', 'active', { notes: ['relay_silent'], n: 1 }),
      )?.label,
    ).toBe('no TLS');
  });

  it('keeps it open that a dead server works from another network', () => {
    const line = verdictLines(verdict('dead', 'active', { n: 2 }))[0];
    expect(line).toBe(
      'The server does not answer from here or through your other servers (2). It may be off, or its address may be closed to these networks; from another network it may work.',
    );
    expect(line).not.toContain('blocked');
  });

  it('tells a failed URL test by what the backend measures', () => {
    expect(verdictLines(verdict('unreachable', 'passive'))).toEqual([
      'The URL test of this server failed, and no connection opened since then has received data. Press “Check server” to learn why.',
    ]);
  });

  it('says the server works on the fallback only where no fault is told', () => {
    const line = (block: Podkop.Block, source: 'passive' | 'active') =>
      verdictLines(
        verdict(block, source, { fp: 'firefox', notes: ['fp_switched'] }),
      ).join(' ');
    for (const [block, source] of [
      ['none', 'passive'],
      ['none', 'active'],
      ['unknown', 'passive'],
    ] as const) {
      expect(line(block, source)).toContain(
        'The server works through the fallback fingerprint firefox.',
      );
    }
    for (const [block, source] of [
      ['unreachable', 'passive'],
      ['limit', 'passive'],
    ] as const) {
      expect(line(block, source)).toContain(
        'The server is reached through the fallback fingerprint firefox.',
      );
      expect(line(block, source)).not.toContain('works through');
    }
  });

  it('adds the clock to wrong parameters', () => {
    const lines = verdictLines(
      verdict('wrongparams', 'active', { notes: ['clock_suspect'] }),
    );
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('clock');
  });

  it('leaves the unknown cause out when the cause is known', () => {
    for (const note of ['uplink_down', 'dns_failed'] as const) {
      const lines = verdictLines(
        verdict('unreachable', 'active', { notes: [note] }),
      );
      expect(lines).toHaveLength(1);
      expect(lines[0]).not.toContain('cannot be told');
    }
  });

  it('never tells the English why of the backend', () => {
    const lines = verdictLines({
      ...verdict('limit', 'passive', { kb: 18 }),
      why: '3 flows cut, none larger',
    } as Podkop.Verdict);
    expect(lines.join(' ')).not.toContain('flows cut');
  });
});

describe('checkedAgo', () => {
  it('counts whole minutes', () => {
    expect(checkedAgo(0)).toBe('Checked just now');
    expect(checkedAgo(59.9)).toBe('Checked just now');
    expect(checkedAgo(60)).toBe('Checked 1 min ago');
    expect(checkedAgo(1799)).toBe('Checked 29 min ago');
  });
});

describe('forceDetectProblem', () => {
  it('has nothing to say of what was taken', () => {
    for (const state of ['started', 'queued', 'running', 'canceled'] as const) {
      expect(forceDetectProblem({ state })).toBeUndefined();
    }
  });

  it('says when to try again', () => {
    expect(forceDetectProblem({ state: 'throttled', retry_after: 170 })).toBe(
      'A check is not possible now: this address was checked recently or is waiting in the queue, or the queue is full. Try again in 170 s.',
    );
  });

  it('tells a server that is gone, a stopped backend and a failed call apart', () => {
    const texts = [
      forceDetectProblem({ state: 'unknown' }),
      forceDetectProblem({ state: 'not_running' }),
      forceDetectProblem(undefined),
    ];
    expect(new Set(texts).size).toBe(3);
    texts.forEach((text) => expect(text).toBeTruthy());
  });

  it('tells an account that may only read', () => {
    expect(forceDetectProblem({ state: 'denied' })).toBe(
      'Your account may view this page but may not start a check.',
    );
  });
});

describe('stopsChecks', () => {
  it('stops a batch on what the rest would get as well', () => {
    expect(stopsChecks({ state: 'denied' })).toBe(true);
    expect(stopsChecks({ state: 'not_running' })).toBe(true);
    expect(stopsChecks(undefined)).toBe(true);
  });

  it('goes on past what is of one server', () => {
    for (const state of ['throttled', 'unknown', 'started'] as const) {
      expect(stopsChecks({ state })).toBe(false);
    }
  });
});
