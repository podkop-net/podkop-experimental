import { validateProxyUrl } from '../validators/validateProxyUrl';
import { linkParts, readAddress } from '../validators/linkAddress';
import { PodkopShellMethods } from './methods';
import { logger } from './services';
import { sourceKind, sourceLabel, sourceLinks } from './sources';
import type { Podkop } from './types';

// Before the settings are saved, the proxy links of every source are asked of the router:
// the engine of its build takes each as the configuration would (check_links), so that a
// link it cannot use (a transport or a kind of outbound this build has not) is told by its
// source here, and not by the log after the apply, where it would keep the whole
// configuration from running. One request for the links (more for many long ones:
// linkBatches), at the save only: the window of a source checks the form of a link itself as
// it is typed. The sources are read as the page staged them (each window saves its source),
// so their links are known without their windows open. An outbound JSON is no link: the
// engine is not asked about it.

export interface LinkPlace {
  // the name of the source in the settings, and the name it is shown by
  section: string;
  label: string;
  option: string;
  // the place of the link in its source, from 1, and how many the source has
  index: number;
  count: number;
  link: string;
}

export interface LinkProblem extends LinkPlace {
  error: string;
}

// linkPlaces lists the links of the sources of links
export function linkPlaces(sources: Podkop.ConfigSource[]): LinkPlace[] {
  const places: LinkPlace[] = [];
  for (const source of sources ?? []) {
    if (sourceKind(source) !== 'links') continue;
    const links = sourceLinks(source);
    links.forEach((link, index) =>
      places.push({
        section: source['.name'],
        label: sourceLabel(source),
        option: 'link',
        index: index + 1,
        count: links.length,
        link,
      }),
    );
  }
  return places;
}

// linkLabel names a link without its secrets: its name, its kind and its server
export function linkLabel(link: string): string {
  const scheme = link.includes('://') ? link.slice(0, link.indexOf('://')) : '';
  let name = '';
  const hash = link.indexOf('#');
  if (hash >= 0) {
    try {
      name = decodeURIComponent(link.slice(hash + 1)).trim();
    } catch (_e) {
      name = link.slice(hash + 1).trim();
    }
  }
  const address = readAddress(linkParts(link).address);
  const server =
    typeof address === 'string'
      ? ''
      : (address.host.includes(':') ? `[${address.host}]` : address.host) +
        (address.port ? `:${address.port}` : '');
  const kind = server ? `${scheme}, ${server}` : scheme;
  return name ? `«${name}» (${kind})` : kind;
}

// checkLinksBeforeSave asks the router about the links of the sources and returns those its
// engine refuses. A link of a wrong form is left to the window of its source (LuCI refuses
// to save it there); when the router does not answer, nothing is refused.
export async function checkLinksBeforeSave(
  sources: Podkop.ConfigSource[],
): Promise<LinkProblem[]> {
  const places = linkPlaces(sources);
  if (!places.length) return [];
  if (places.some((place) => !validateProxyUrl(place.link).valid)) return [];
  const links = [...new Set(places.map((place) => place.link))];
  try {
    const results = new Map<string, Podkop.LinkCheck>();
    for (const part of linkBatches(links)) {
      const answer = await PodkopShellMethods.checkLinks(part);
      if (
        !answer.success ||
        !Array.isArray(answer.data) ||
        answer.data.length !== part.length
      ) {
        logger.warn('[LINKS]', 'the router did not check the links');
        return [];
      }
      part.forEach((link, index) => results.set(link, answer.data[index]));
    }
    return places
      .filter((place) => !results.get(place.link)?.ok)
      .map((place) => ({
        ...place,
        error:
          results.get(place.link)?.error || _('the engine refuses this link'),
      }));
  } catch (err) {
    logger.warn('[LINKS]', 'the router did not check the links:', err);
    return [];
  }
}

// uhttpd takes no more than 64 KB of a request to /ubus (UH_UBUS_MAX_POST_SIZE) and answers
// a larger one with an error: the links are asked in parts well below that
const PART_BYTES = 40000;

// linkBatches splits the links into parts of PART_BYTES of JSON at most, a link that is longer
// alone
export function linkBatches(links: string[]): string[][] {
  const parts: string[][] = [];
  let part: string[] = [];
  let size = 0;
  for (const link of links) {
    const bytes = JSON.stringify(link).length + 1;
    if (part.length && size + bytes > PART_BYTES) {
      parts.push(part);
      part = [];
      size = 0;
    }
    part.push(link);
    size += bytes;
  }
  if (part.length) parts.push(part);
  return parts;
}

// A thing that keeps the settings from being saved, with the window that fixes it
export interface SaveProblem {
  heading: string;
  lines: string[];
  show?: () => void;
}

// showSaveProblems tells what keeps the settings from being saved, each with a button that
// opens the window where it is fixed
export function showSaveProblems(
  title: string,
  intro: string,
  problems: SaveProblem[],
) {
  ui.showModal(title, [
    E('p', {}, [intro]),
    E(
      'ul',
      {},
      problems.map((problem) =>
        E('li', {}, [
          E('strong', {}, [problem.heading]),
          ...problem.lines.map((line) => E('div', {}, [line])),
          problem.show
            ? E('div', {}, [
                E(
                  'button',
                  {
                    class: 'cbi-button cbi-button-action',
                    click: () => {
                      ui.hideModal();
                      problem.show?.();
                    },
                  },
                  [_('Show')],
                ),
              ])
            : '',
        ]),
      ),
    ),
    E('div', { class: 'right' }, [
      E('button', { class: 'cbi-button', click: () => ui.hideModal() }, [
        _('Close'),
      ]),
    ]),
  ]);
}

// showLinkProblems tells which links keep the settings from being saved, and why; show opens
// the window of a source
export function showLinkProblems(
  problems: LinkProblem[],
  show?: (source: string) => void,
) {
  showSaveProblems(
    _('Some proxy links cannot be used'),
    _(
      'The settings are not saved. The engine of the router refuses these links:',
    ),
    problems.map((problem) => ({
      heading:
        problem.label +
        (problem.count > 1 ? ` · ${problem.index}/${problem.count}` : ''),
      lines: [linkLabel(problem.link), problem.error],
      show: show ? () => show(problem.section) : undefined,
    })),
  );
}
