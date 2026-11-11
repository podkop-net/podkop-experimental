import type { Podkop } from '../../../types';
import type { IDetectWidget } from '../../../services';
import { type VerdictChip, isWeakVerdict, verdictChip } from './verdictText';

// a server asked of that the backend never told (it can drop one at its turn) is let go of
const REQUESTED_TIMEOUT_MS = 30000;
// how long a press waits for what the Clash API says is in use
const USED_READ_MS = 3000;
// the queue of the backend (diagnoseQueueLimit): the rest would only be refused
export const CHECK_QUEUE_LIMIT = 64;

// the Clash API types of what is no server of the detector (engine.ServersOf)
const NOT_SERVERS = [
  '',
  'Selector',
  'URLTest',
  'Direct',
  'Block',
  'Reject',
  'DNS',
];

// the Clash API types of the servers a check sends no burst to, so their connections do not hang
const NO_BURST = ['Hysteria', 'Hysteria2', 'TUIC'];

export function canCheck(
  outbound: Podkop.Outbound,
  noprobe: string[],
): boolean {
  return (
    !NOT_SERVERS.includes(outbound.type) && !noprobe.includes(outbound.code)
  );
}

// the check of the server is on its way, in the backend or to it
export function isChecking(tag: string, detect: IDetectWidget): boolean {
  return (
    detect.probing === tag ||
    detect.queued.includes(tag) ||
    detect.requested[tag] !== undefined
  );
}

// tileChip is the chip of a tile: the check under way, else the verdict
export function tileChip(
  tag: string,
  detect: IDetectWidget,
): VerdictChip | undefined {
  if (detect.probing === tag) return { label: _('checking…'), tone: 'neutral' };
  if (isChecking(tag, detect)) return { label: _('queued'), tone: 'neutral' };
  return verdictChip(detect.verdicts[tag]);
}

// problemTiles are the tiles a check of the section goes to: those with a chip of a problem or
// without a delay. A server a probe has just found to work has no problem, delay or not, and a weak
// verdict accuses nothing and is as old as the next press has to wait. The tiles no probe has an
// answer of come first: a second press goes on to them, where the same first ones would fill the
// queue again.
export function problemTiles(
  section: Podkop.OutboundGroup,
  detect: IDetectWidget,
): Podkop.Outbound[] {
  const probed = (outbound: Podkop.Outbound) =>
    detect.verdicts[outbound.code]?.source === 'active' ? 1 : 0;
  return section.outbounds
    .filter((outbound) => {
      if (!canCheck(outbound, detect.noprobe)) return false;
      const verdict = detect.verdicts[outbound.code];
      if (isWeakVerdict(verdict)) return false;
      const chip = verdictChip(verdict);
      return chip ? chip.tone !== 'ok' : !outbound.latency;
    })
    .sort((one, other) => probed(one) - probed(other));
}

// problemServers are the problem tiles the queue of the backend takes
export function problemServers(
  section: Podkop.OutboundGroup,
  detect: IDetectWidget,
): Podkop.Outbound[] {
  return problemTiles(section, detect).slice(0, CHECK_QUEUE_LIMIT);
}

// mayHang tells that a check of the server may hang what goes through it: its burst may freeze the
// destination for the real connections too. used is what they go through as read at the press;
// without an answer of the Clash API, what the grid knows.
export function mayHang(
  outbound: Podkop.Outbound,
  used: Set<string> | undefined,
): boolean {
  if (NO_BURST.includes(outbound.type)) return false;
  return used ? used.has(outbound.code) : outbound.inUse;
}

// oncePerControl makes what reads before a press takes effect: a press of a control while its read
// is pending is ignored, nothing on the page has changed yet to stop it. The read is bounded, and
// one that fails, or has not answered in time, gives undefined: it never holds or loses the press.
export function oncePerControl(wait = USED_READ_MS) {
  const pending = new Set<string>();
  return async <T>(
    control: string,
    read: () => Promise<T>,
    then: (value: T | undefined) => void,
  ): Promise<void> => {
    if (pending.has(control)) return;
    pending.add(control);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const value = await Promise.race([
      (async () => read())().catch(() => undefined),
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), wait);
      }),
    ]);
    clearTimeout(timer);
    pending.delete(control);
    then(value);
  };
}

// batchProgress counts what the backend no longer has of a check of a section, not its answers: a
// server it drops at its turn ends with no verdict.
export function batchProgress(detect: IDetectWidget): {
  done: number;
  total: number;
} {
  const tags = detect.batch?.tags ?? [];
  return {
    done: tags.filter((tag) => !isChecking(tag, detect)).length,
    total: tags.length,
  };
}

// settleRequested lets go of the servers the report tells of, or that a probe has finished by now
export function settleRequested(
  requested: Record<string, number>,
  report: Podkop.DetectReport,
  now: number,
): Record<string, number> {
  return Object.fromEntries(
    Object.entries(requested).filter(([tag, at]) => {
      if (report.probing === tag || report.queued.includes(tag)) return false;
      const verdict = report.verdicts[tag];
      if (
        verdict?.source === 'active' &&
        (verdict.age ?? 0) * 1000 <= now - at
      ) {
        return false;
      }
      return now - at < REQUESTED_TIMEOUT_MS;
    }),
  );
}

// widgetOfReport is the next state of the store. The age and the why stay out of it, see
// IDetectWidget.
export function widgetOfReport(
  previous: IDetectWidget,
  report: Podkop.DetectReport,
  now: number,
): IDetectWidget {
  const verdicts: Record<string, Podkop.Verdict> = {};
  for (const [tag, reply] of Object.entries(report.verdicts)) {
    const verdict = { ...reply };
    delete verdict.age;
    delete verdict.why;
    verdicts[tag] = verdict;
  }
  const next: IDetectWidget = {
    ...previous,
    verdicts,
    servers: report.servers ?? {},
    staleCures: report.stale_cures ?? 0,
    requested: settleRequested(previous.requested, report, now),
    probing: report.probing,
    queued: report.queued,
    noprobe: report.noprobe,
  };
  const { done, total } = batchProgress(next);
  if (done === total) next.batch = null;
  return next;
}

// a poll is quick while a check is under way
export function detectIsBusy(detect: IDetectWidget): boolean {
  return Boolean(
    detect.probing ||
      detect.queued.length ||
      detect.batch ||
      Object.keys(detect.requested).length,
  );
}
