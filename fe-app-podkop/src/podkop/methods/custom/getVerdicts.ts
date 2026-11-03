import { logger } from '../../services/logger.service';
import { Podkop } from '../../types';

let backendDetect: (() => Promise<Podkop.DetectReport | number>) | undefined;
let backendForceDetect:
  | ((
      tag: string,
      cancel: boolean,
    ) => Promise<Podkop.ForceDetectReply | number>)
  | undefined;
let lastFailure = '';

function emptyReport(): Podkop.DetectReport {
  return {
    verdicts: {},
    probing: '',
    queued: [],
    noprobe: [],
    fallback: false,
  };
}

// A failure stays in the console, once while it lasts: the poll goes on every 15 s. A denial of
// the method by the ACL of the session looks like any other error here and leaves no chip on the
// page, so this line is all that tells it.
function noteFailure(message: string) {
  if (message === lastFailure) return;
  lastFailure = message;
  logger.warn('[DASHBOARD]', 'detect failed:', message);
}

function errorText(err: unknown): string {
  return (err as Error)?.message ?? String(err);
}

// getVerdicts asks the backend what its detector knows of the servers (the method detect of its
// object on ubus). An answer that says nothing (no object, a denial, a status) is an empty report:
// nothing runs that can be told about. No answer at all is undefined, and what the page shows
// stays until the next poll: LuCI gave up waiting, or the network did.
export async function getVerdicts(): Promise<Podkop.DetectReport | undefined> {
  backendDetect ??= rpc.declare<Podkop.DetectReport | number>({
    object: 'podkop',
    method: 'detect',
    nobatch: true,
  });
  try {
    const reply = await backendDetect();
    if (typeof reply !== 'object' || reply === null) {
      noteFailure(`status ${reply}`);
      return emptyReport();
    }
    lastFailure = '';
    return { ...emptyReport(), ...reply };
  } catch (err) {
    const message = errorText(err);
    noteFailure(message);
    // the errors of rpc.js for an answer that came: "RPC call to podkop/detect failed with ..."
    return /^RPC call to /.test(message) ? emptyReport() : undefined;
  }
}

// forceDetect asks for a probe of a server by its tag, or with cancel empties the queue of them.
// It answers at once, the verdict comes in a later detect. undefined when the call failed, the
// state denied when the ACL of the session refused it: an account that may only read.
export async function forceDetect(
  tag: string,
  cancel = false,
): Promise<Podkop.ForceDetectReply | undefined> {
  backendForceDetect ??= rpc.declare<Podkop.ForceDetectReply | number>({
    object: 'podkop',
    method: 'force_detect',
    params: ['tag', 'cancel'],
    nobatch: true,
  });
  try {
    const reply = await backendForceDetect(tag, cancel);
    if (typeof reply === 'object' && reply !== null) return reply;
    logger.error('[DASHBOARD]', 'force_detect failed: status', reply);
  } catch (err) {
    const message = errorText(err);
    logger.error('[DASHBOARD]', 'force_detect failed:', message);
    // the words of rpc.js for the access error of ubus
    if (/failed with error -32002\b/.test(message)) return { state: 'denied' };
  }
  return undefined;
}
