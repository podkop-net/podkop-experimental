import { Podkop } from '../../types';

// The rules, the sources and the rows of the rules of the file, each in the order of the
// file: the order of the rows of a rule is the order of its servers and fallbacks.
export async function getConfigModel(): Promise<Podkop.ConfigModel> {
  await uci.load('podkop');
  const all = uci.sections('podkop') as unknown as Array<
    Record<string, unknown> & { '.type': string }
  >;
  const ofType = <T>(type: string) =>
    all.filter((section) => section['.type'] === type) as unknown as T[];
  return {
    rules: ofType<Podkop.ConfigRule>('section'),
    sources: ofType<Podkop.ConfigSource>('source'),
    members: ofType<Podkop.ConfigMember>('member'),
  };
}
