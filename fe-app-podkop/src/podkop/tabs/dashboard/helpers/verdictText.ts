import type { Podkop } from '../../../types';

export type ChipTone = 'ok' | 'warn' | 'error' | 'muted' | 'neutral';

export interface VerdictChip {
  label: string;
  tone: ChipTone;
}

// What only says how a server that works is reached: no chip on what the traffic shows, the lines
// of these notes are read in the window of another chip.
const QUIET_PASSIVE_NOTES: Podkop.VerdictNote[] = [
  'needs_mlkem',
  'fp_switched',
];

// The notes of a probe that does not name what is wrong with the server: it found nothing clear, or
// something of the state of the router or of its own hello. The same as weak() in
// supervisor/diagnose.go of the backend.
const WEAK_NOTES: Podkop.VerdictNote[] = [
  'inconclusive',
  'target_failed',
  'uplink_down',
  'dns_failed',
  'clock_suspect',
  'probe_hello_refused',
  'server_silent',
];

// isWeakVerdict tells the answer to a press that lasts no longer than it: the backend shows it for as long
// as the next press has to wait, whatever the traffic showed before.
export function isWeakVerdict(verdict: Podkop.Verdict | undefined): boolean {
  return (
    verdict?.source === 'active' &&
    (verdict.notes ?? []).some((note) => WEAK_NOTES.includes(note))
  );
}

// verdictChip is the chip of a verdict on its tile, none for a server with nothing to tell. A
// freeze is only ever found by a probe: what the traffic shows of a total drop is hellodrop. A weak
// verdict has one neutral chip, whatever its block: the report does not tell what lies under it,
// which may be a working server with no chip of its own.
export function verdictChip(
  verdict: Podkop.Verdict | undefined,
): VerdictChip | undefined {
  if (!verdict) return undefined;
  const notes = verdict.notes ?? [];
  // the one weak verdict that does say what the server does: it does not answer
  if (notes.includes('server_silent')) {
    return { label: _('no answer'), tone: 'error' };
  }
  if (isWeakVerdict(verdict) && verdict.block !== 'wrongparams') {
    return { label: _('details'), tone: 'neutral' };
  }
  const active = verdict.source === 'active';
  switch (verdict.block) {
    case 'none':
      return active ? { label: _('ok'), tone: 'ok' } : undefined;
    case 'limit':
      return active
        ? { label: _('limit'), tone: 'warn' }
        : { label: _('limit?'), tone: 'warn' };
    case 'freeze':
      if (!active) return undefined;
      return {
        label: _('freeze'),
        tone:
          notes.includes('cured') || notes.includes('stand_in')
            ? 'warn'
            : 'error',
      };
    case 'wrongparams':
      // the certificate is of the server, the settings of the user do not cause it
      return notes.includes('tls_cert')
        ? { label: _('certificate'), tone: 'error' }
        : { label: _('settings'), tone: 'error' };
    case 'rejected':
      return { label: _('refused'), tone: 'error' };
    case 'hellodrop':
      // no answer in the dial does not say TLS failed: the upgrade after it may be what got none
      return notes.includes('upgrade_in_dial')
        ? { label: _('no answer'), tone: 'error' }
        : { label: _('no TLS'), tone: 'error' };
    case 'pathblock':
      return { label: _('no path'), tone: 'error' };
    case 'dead':
      return { label: _('no answer'), tone: 'muted' };
    case 'unreachable':
      // passive: a URL test failed, which says nothing of the port
      return active
        ? { label: _('no answer'), tone: 'muted' }
        : { label: _('test failed'), tone: 'muted' };
    default:
      return notes.some((note) => active || !QUIET_PASSIVE_NOTES.includes(note))
        ? { label: _('details'), tone: 'neutral' }
        : undefined;
  }
}

// What a check may show to another server of the user: said where a window comes up anyway, a
// press on a tile that is not in use starts at once.
export function relayNotice(): string {
  return _(
    'If the server does not answer, it is tried through another server of yours, whose operator can see the address of this one.',
  );
}

// a server behind another one gets no check, so there is nothing to press
function passiveLimitLine(notes: Podkop.VerdictNote[], kb: number): string {
  const test = notes.includes('download_test');
  if (notes.includes('through_detour')) {
    return (
      test
        ? _(
            'The download test of the group stopped at about %d KB. It looks like the DPI limit.',
          )
        : _(
            'Several connections were cut at about %d KB, and none went further. It looks like the DPI limit, but short responses of sites look the same.',
          )
    ).format(kb);
  }
  return (
    test
      ? _(
          'The download test of the group stopped at about %d KB. It looks like the DPI limit. Press “Check server”.',
        )
      : _(
          'Several connections were cut at about %d KB, and none went further. It looks like the DPI limit, but short responses of sites look the same. Press “Check server”.',
        )
  ).format(kb);
}

// with a stand-in the configured fingerprint was not tried, so the fallback is not advised
function freezeLine(notes: Podkop.VerdictNote[], fp: string): string {
  if (notes.includes('cured')) {
    return _(
      'Fingerprint %s does not pass or hangs with several connections at once, the fallback one passes. It looks like a DPI block by fingerprint. The uTLS fallback already gets around it, nothing needs changing.',
    ).format(fp);
  }
  if (notes.includes('stand_in')) {
    return _(
      'Fingerprint %s does not pass or hangs with several connections at once, the fallback one passes. It looks like a DPI block by fingerprint.',
    ).format(fp);
  }
  return _(
    'Fingerprint %s does not pass or hangs with several connections at once, the fallback one passes. It looks like a DPI block by fingerprint. Turn on the uTLS fallback in the settings.',
  ).format(fp);
}

// relay_silent says more of the two: it was asked through other servers, past the upgrade too. One
// such server may itself be unstable, as deadRelays of detect/stages.go has it for a server without
// TCP, so it is no ground to name a fault.
function helloDropLine(notes: Podkop.VerdictNote[], relays: number): string {
  if (notes.includes('relay_silent')) {
    return relays >= 2
      ? _(
          'TCP connects from here, but the server does not answer through another server either. It looks like a fault of the server or its cover.',
        )
      : _(
          'TCP connects from here, but the server does not answer through another server of yours either, which may itself be unstable. The cause cannot be told from this one try.',
        );
  }
  if (notes.includes('upgrade_in_dial')) {
    return _(
      'TCP connects, but TLS or the WebSocket/HTTP upgrade gets no answer.',
    );
  }
  return _(
    'The port is open, but the TLS hello gets no answer. It looks like a block by SNI or address.',
  );
}

// verdictLines is what the window of a chip says: the verdict, then its notes
export function verdictLines(verdict: Podkop.Verdict): string[] {
  const notes = verdict.notes ?? [];
  const active = verdict.source === 'active';
  const lines: string[] = [];
  switch (verdict.block) {
    case 'none':
      if (active) {
        lines.push(_('The test download went through in full.'));
      }
      break;
    case 'limit':
      lines.push(
        active
          ? _(
              'Connections are cut at about %d KB: this is the DPI limit. Sites open partly. Another server or a disguise as a whitelisted site may help; where the network also limits by address, the disguise will not.',
            ).format(verdict.kb ?? 0)
          : passiveLimitLine(notes, verdict.kb ?? 0),
      );
      break;
    case 'freeze':
      lines.push(freezeLine(notes, verdict.fp ?? ''));
      break;
    case 'wrongparams':
      lines.push(
        notes.includes('tls_cert')
          ? _(
              'The server answered, but its certificate did not pass the check: expired, for another name, or from an unknown issuer.',
            )
          : _(
              'The server answered, but the REALITY check failed: a wrong key or shortId in the link, a name the server does not list, or the server has changed. Update the link or the subscription; if that does not help, the fault is on the server.',
            ),
      );
      break;
    case 'rejected':
      lines.push(
        _(
          'The server closed the requests without an answer. The usual reason is a user or password it does not know; a server with no way out looks the same from here.',
        ),
      );
      break;
    case 'hellodrop':
      lines.push(helloDropLine(notes, verdict.n ?? 0));
      // relay_silent: a relay was asked, so its operator may have seen the address
      if (notes.includes('relay_silent')) lines.push(relayNotice());
      break;
    case 'pathblock':
      lines.push(
        _(
          'It does not connect from here, but the handshake passes through another server of yours. The server is on; the provider cuts the path or the server does not accept your network.',
        ),
        relayNotice(),
      );
      break;
    case 'dead':
      lines.push(
        _(
          'The server does not answer from here or through your other servers (%d). It may be off, or its address may be closed to these networks; from another network it may work.',
        ).format(verdict.n ?? 0),
        relayNotice(),
      );
      break;
    case 'unreachable':
      if (!active) {
        lines.push(
          _(
            'The URL test of this server failed, and no connection opened since then has received data. Press “Check server” to learn why.',
          ),
        );
      } else if (notes.includes('relay_silent')) {
        // one server was asked: too few to say more of this one, and its operator may have seen the
        // address
        lines.push(
          _(
            'The server does not answer from here or through another server of yours, which may itself be unstable. The cause cannot be told from this one try.',
          ),
          relayNotice(),
        );
      } else if (
        // these two know the cause
        !notes.includes('uplink_down') &&
        !notes.includes('dns_failed')
      ) {
        lines.push(
          _(
            'The port of the server does not answer from this router. The cause cannot be told from here.',
          ),
        );
      }
      break;
    default:
      break;
  }
  notes.forEach((note) => {
    const line = noteLine(note, verdict);
    if (line) lines.push(line);
  });
  return lines;
}

function noteLine(
  note: Podkop.VerdictNote,
  verdict: Podkop.Verdict,
): string | undefined {
  switch (note) {
    case 'clock_suspect':
      return _('Also check the clock of the router.');
    case 'uplink_down':
      return _(
        'The router seems to have no internet connection: the uplink check failed.',
      );
    case 'dns_failed':
      return _('The address of the server could not be resolved by its name.');
    case 'needs_mlkem':
      // beside a verdict of a block "not a block" would contradict it
      return verdict.block === 'none' || verdict.block === 'unknown'
        ? _(
            'The server accepts only connections with ML-KEM (Xray ≥ 26.9.8). This is not a block.',
          )
        : _('The server accepts only connections with ML-KEM (Xray ≥ 26.9.8).');
    case 'fp_switched':
      // beside a verdict of a fault "works" would contradict it
      return (
        verdict.block === 'none' || verdict.block === 'unknown'
          ? _(
              'The server works through the fallback fingerprint %s. Sometimes this is the trace of a block; a check will tell for sure.',
            )
          : _(
              'The server is reached through the fallback fingerprint %s. Sometimes this is the trace of a block; a check will tell for sure.',
            )
      ).format(verdict.fp ?? '');
    case 'handshake_failed':
      return _(
        'The server answers, but the handshake does not complete with any fingerprint.',
      );
    case 'burst_any_fp':
      return _(
        'One request passes, the requests after it do not. It looks like a limit of the server or the line.',
      );
    case 'inconclusive':
      return _('The check gave no clear answer, repeat it later.');
    case 'server_silent':
      return _(
        'The handshake with the server completes, but it did not answer a request during the check. The cause may be on the server or on the way to it, a check from here cannot tell. Try the server from another network, or ask whoever runs it.',
      );
    case 'target_failed':
      return _(
        'The address of the check did not answer, the server is not at fault.',
      );
    case 'some_lost':
      return _('Some of the test connections were lost, the rest passed.');
    case 'through_detour':
      return _(
        'The server is reached through another one: the cause may be there.',
      );
    case 'not_applicable':
      return _('The check does not apply to a server behind a tunnel.');
    case 'probe_hello_refused':
      return _(
        "The check's hello was refused, but the running connection through this server works. Nothing needs changing.",
      );
    case 'stand_in':
      return _(
        'The fingerprint of the link was not tested: this one stood in for it, so real connections may not be affected.',
      );
    // the line of the verdict tells these
    default:
      return undefined;
  }
}

// checkedAgo tells the time of a probe by the seconds the backend counts: the clock of the router
// may be wrong, and it is not the one of the phone.
export function checkedAgo(seconds: number): string {
  if (seconds < 60) return _('Checked just now');
  return _('Checked %d min ago').format(Math.floor(seconds / 60));
}

// forceDetectProblem is what to tell of an answer of force_detect that started nothing
export function forceDetectProblem(
  reply: Podkop.ForceDetectReply | undefined,
): string | undefined {
  switch (reply?.state) {
    case 'started':
    case 'queued':
    case 'running':
    case 'canceled':
      return undefined;
    case 'throttled':
      return _(
        'A check is not possible now: this address was checked recently or is waiting in the queue, or the queue is full. Try again in %d s.',
      ).format(reply.retry_after ?? 180);
    case 'unknown':
      return _('This server is no longer in the running configuration.');
    case 'not_running':
      return _('Podkop is not running.');
    case 'denied':
      return _('Your account may view this page but may not start a check.');
    default:
      return _('Failed to execute!');
  }
}

// stopsChecks tells an answer the rest of a batch would get as well
export function stopsChecks(
  reply: Podkop.ForceDetectReply | undefined,
): boolean {
  return !reply || reply.state === 'not_running' || reply.state === 'denied';
}
