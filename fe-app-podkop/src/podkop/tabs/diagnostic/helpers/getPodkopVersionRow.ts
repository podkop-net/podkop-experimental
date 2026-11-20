import { normalizeCompiledVersion } from '../../../../helpers/normalizeCompiledVersion';
import {
  compareVersions,
  isRelease,
} from '../../../../helpers/compareVersions';
import type { StoreType } from '../../../services/store.service';
import type { IRenderSystemInfoRow } from '../partials';

function isUnknownVersion(version?: string | null): boolean {
  return version === 'unknown' || version === _('unknown');
}

// getPodkopVersionRow: the installed version of podkop-exp, and beside it what it is to the
// latest release: the same, older (the release to get named), or newer. A newer release is
// latest (GitHub may still answer the previous tag for a while after a release); a newer
// candidate or build by date is a test build. No tag while either version is not known or is
// not a version (a backend built without one).
export function getPodkopVersionRow(
  diagnosticsSystemInfo: StoreType['diagnosticsSystemInfo'],
): IRenderSystemInfoRow {
  const loading = diagnosticsSystemInfo.loading;
  const unknown = isUnknownVersion(diagnosticsSystemInfo.podkop_version);
  const latest = diagnosticsSystemInfo.podkop_latest_version;
  const hasActualVersion = Boolean(latest) && !isUnknownVersion(latest);
  const version = normalizeCompiledVersion(
    diagnosticsSystemInfo.podkop_version,
  );
  const isDevVersion = version === 'dev';
  const order =
    loading || unknown || !hasActualVersion || isDevVersion
      ? undefined
      : compareVersions(version, latest);

  if (order === undefined) {
    return {
      key: 'Podkop',
      value: version,
    };
  }

  if (order < 0) {
    return {
      key: 'Podkop',
      value: version,
      tag: {
        label: _('Update available: %s').format(latest),
        kind: 'warning',
      },
    };
  }

  if (order > 0 && !isRelease(version)) {
    return {
      key: 'Podkop',
      value: version,
      tag: {
        label: _('Test build'),
        kind: 'neutral',
      },
    };
  }

  return {
    key: 'Podkop',
    value: version,
    tag: {
      label: _('Latest'),
      kind: 'success',
    },
  };
}
