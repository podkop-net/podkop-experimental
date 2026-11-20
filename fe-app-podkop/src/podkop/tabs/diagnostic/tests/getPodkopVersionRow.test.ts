import { describe, expect, it } from 'vitest';
import { getPodkopVersionRow } from '../helpers/getPodkopVersionRow';
import type { StoreType } from '../../../services/store.service';

function makeDiagnosticsSystemInfo(
  patch: Partial<StoreType['diagnosticsSystemInfo']> = {},
): StoreType['diagnosticsSystemInfo'] {
  return {
    loading: false,
    podkop_version: '1.2.3',
    podkop_latest_version: '1.2.3',
    luci_app_version: '1.0.0',
    sing_box_version: '1.11.0',
    openwrt_version: 'OpenWrt 25.12',
    device_model: 'Test Router',
    ...patch,
  };
}

describe('getPodkopVersionRow', () => {
  it('returns Latest when versions differ only by leading v', () => {
    const row = getPodkopVersionRow(
      makeDiagnosticsSystemInfo({
        podkop_version: 'v1.2.3',
        podkop_latest_version: '1.2.3',
      }),
    );

    expect(row).toEqual({
      key: 'Podkop',
      value: 'v1.2.3',
      tag: {
        label: 'Latest',
        kind: 'success',
      },
    });
  });

  it.each([
    // installed older: the release to get is named
    ['0.8.19', 'v0.8.20', 'Update available: v0.8.20', 'warning'],
    ['0.8.9', 'v0.8.10', 'Update available: v0.8.10', 'warning'],
    // a candidate of 0.8.20 is older than 0.8.20
    ['0.8.19.3', 'v0.8.20', 'Update available: v0.8.20', 'warning'],
    // the same
    ['v0.8.20', 'v0.8.20', 'Latest', 'success'],
    ['0.8.20', 'v0.8.20', 'Latest', 'success'],
    // a newer release: GitHub still answers the previous tag, or the kept tag is older
    ['0.8.20', 'v0.8.19', 'Latest', 'success'],
    ['v0.8.21', 'v0.8.20', 'Latest', 'success'],
    // newer, not a release: a candidate or a build by date
    ['0.8.20.1', 'v0.8.20', 'Test build', 'neutral'],
    ['0.20112026', 'v0.8.20', 'Test build', 'neutral'],
  ])('%s next to %s: %s', (installed, latest, label, kind) => {
    const row = getPodkopVersionRow(
      makeDiagnosticsSystemInfo({
        podkop_version: installed,
        podkop_latest_version: latest,
      }),
    );

    expect(row).toEqual({
      key: 'Podkop',
      value: installed,
      tag: { label, kind },
    });
  });

  it.each([
    // a backend built without a version
    ['0.8.0-dev', 'v0.8.20'],
    ['unknown', 'v0.8.20'],
    // GitHub not asked or not answered
    ['0.8.20', 'unknown'],
    ['0.8.20', ''],
  ])('%s next to %j: no tag', (installed, latest) => {
    const row = getPodkopVersionRow(
      makeDiagnosticsSystemInfo({
        podkop_version: installed,
        podkop_latest_version: latest,
      }),
    );

    expect(row).toEqual({ key: 'Podkop', value: installed });
  });

  it('returns no tag while loading', () => {
    const row = getPodkopVersionRow(
      makeDiagnosticsSystemInfo({
        loading: true,
        podkop_version: '0.8.19',
        podkop_latest_version: 'v0.8.20',
      }),
    );

    expect(row).toEqual({ key: 'Podkop', value: '0.8.19' });
  });

  it('returns plain row without tag for dev build', () => {
    const row = getPodkopVersionRow(
      makeDiagnosticsSystemInfo({
        podkop_version: 'COMPILED_VERSION',
      }),
    );

    expect(row).toEqual({
      key: 'Podkop',
      value: 'dev',
    });
  });
});
