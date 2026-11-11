import { getConfigSections } from './getConfigSections';
import { getConfigModel } from './getConfigModel';
import { getDashboardSections, getUsedTags } from './getDashboardSections';
import { getClashApiSecret } from './getClashApiSecret';
import { getSingBoxFeatures } from './getSingBoxFeatures';
import { forceDetect, getVerdicts } from './getVerdicts';
import { clearCure, dropStaleCures, setCure, suggestMask } from './cures';

export const CustomPodkopMethods = {
  getConfigSections,
  getConfigModel,
  getDashboardSections,
  getUsedTags,
  getClashApiSecret,
  getSingBoxFeatures,
  getVerdicts,
  forceDetect,
  setCure,
  clearCure,
  dropStaleCures,
  suggestMask,
};
