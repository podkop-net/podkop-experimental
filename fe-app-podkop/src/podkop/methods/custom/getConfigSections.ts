import { Podkop } from '../../types';

// The settings and the rules of the file: the sources and the rows of the rules are what the
// rules take their servers from, not sections themselves (getConfigModel reads them).
export async function getConfigSections(): Promise<Podkop.ConfigSection[]> {
  return uci
    .load('podkop')
    .then(() =>
      (uci.sections('podkop') as unknown as Podkop.ConfigSection[]).filter(
        (section) =>
          section['.type'] === 'settings' || section['.type'] === 'section',
      ),
    );
}
