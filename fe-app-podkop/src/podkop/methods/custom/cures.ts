import { logger } from '../../services/logger.service';
import { Podkop } from '../../types';

// The write methods of the object podkop on ubus for the per-server cure. They mirror
// getVerdicts.ts forceDetect: declared once, nobatch; an object answer is returned as is, a status
// or null is a failure (undefined), and the access error of rpc.js (-32002, the ACL of the session)
// becomes the state denied so the page can say so instead of failing silently.

let backendSetCure:
  | ((
      tag: string,
      kind: string,
      sni: string,
      hash: string,
    ) => Promise<Podkop.CureReply | number>)
  | undefined;
let backendClearCure:
  | ((tag: string) => Promise<Podkop.CureReply | number>)
  | undefined;
let backendDropStaleCures:
  | (() => Promise<Podkop.CureReply | number>)
  | undefined;
let backendSuggestMask:
  | ((tag: string) => Promise<Podkop.SuggestMaskReply | number>)
  | undefined;

function errorText(err: unknown): string {
  return (err as Error)?.message ?? String(err);
}

// the words of rpc.js when the ACL of the session refuses the call
function denied(err: unknown): boolean {
  return /failed with error -32002\b/.test(errorText(err));
}

// setCure sets the treatment of a server by its tag. hash is the identity the page drew: the
// backend refuses with unknown if the server changed since (an optimistic guard).
export async function setCure(
  tag: string,
  kind: Podkop.CureKind,
  sni = '',
  hash = '',
): Promise<Podkop.CureReply | undefined> {
  backendSetCure ??= rpc.declare<Podkop.CureReply | number>({
    object: 'podkop',
    method: Podkop.CureMethods.SET_CURE,
    params: ['tag', 'kind', 'sni', 'hash'],
    nobatch: true,
  });
  try {
    const reply = await backendSetCure(tag, kind, sni, hash);
    if (typeof reply === 'object' && reply !== null) return reply;
    logger.error('[DASHBOARD]', 'set_cure failed: status', reply);
  } catch (err) {
    logger.error('[DASHBOARD]', 'set_cure failed:', errorText(err));
    if (denied(err)) return { state: 'denied' };
  }
  return undefined;
}

// clearCure removes the treatment of a server by its tag.
export async function clearCure(
  tag: string,
): Promise<Podkop.CureReply | undefined> {
  backendClearCure ??= rpc.declare<Podkop.CureReply | number>({
    object: 'podkop',
    method: Podkop.CureMethods.CLEAR_CURE,
    params: ['tag'],
    nobatch: true,
  });
  try {
    const reply = await backendClearCure(tag);
    if (typeof reply === 'object' && reply !== null) return reply;
    logger.error('[DASHBOARD]', 'clear_cure failed: status', reply);
  } catch (err) {
    logger.error('[DASHBOARD]', 'clear_cure failed:', errorText(err));
    if (denied(err)) return { state: 'denied' };
  }
  return undefined;
}

// dropStaleCures removes the stored treatments of servers no longer in use.
export async function dropStaleCures(): Promise<Podkop.CureReply | undefined> {
  backendDropStaleCures ??= rpc.declare<Podkop.CureReply | number>({
    object: 'podkop',
    method: Podkop.CureMethods.DROP_STALE_CURES,
    params: [],
    nobatch: true,
  });
  try {
    const reply = await backendDropStaleCures();
    if (typeof reply === 'object' && reply !== null) return reply;
    logger.error('[DASHBOARD]', 'drop_stale_cures failed: status', reply);
  } catch (err) {
    logger.error('[DASHBOARD]', 'drop_stale_cures failed:', errorText(err));
    if (denied(err)) return { state: 'denied' };
  }
  return undefined;
}

// suggestMask asks the in-engine white-SNI search of a server for its result. The backend waits up
// to 15 s (under the 20 s of rpc.js) and answers running while the search goes on: the caller asks
// again (handleSuggestMask). The first hit is ~1 s.
export async function suggestMask(
  tag: string,
): Promise<Podkop.SuggestMaskReply | undefined> {
  backendSuggestMask ??= rpc.declare<Podkop.SuggestMaskReply | number>({
    object: 'podkop',
    method: Podkop.CureMethods.SUGGEST_MASK,
    params: ['tag'],
    nobatch: true,
  });
  try {
    const reply = await backendSuggestMask(tag);
    if (typeof reply === 'object' && reply !== null) return reply;
    logger.error('[DASHBOARD]', 'suggest_mask failed: status', reply);
  } catch (err) {
    logger.error('[DASHBOARD]', 'suggest_mask failed:', errorText(err));
    if (denied(err)) return { state: 'denied' };
  }
  return undefined;
}
