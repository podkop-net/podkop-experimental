import { getConfigSections } from './getConfigSections';
import { getConfigModel } from './getConfigModel';
import { getDashboardSections, getUsedTags } from './getDashboardSections';
import { getClashApiSecret } from './getClashApiSecret';
import { getSingBoxFeatures } from './getSingBoxFeatures';
import { forceDetect, getVerdicts } from './getVerdicts';

export const CustomPodkopMethods = {
  getConfigSections,
  getConfigModel,
  getDashboardSections,
  getUsedTags,
  getClashApiSecret,
  getSingBoxFeatures,
  getVerdicts,
  forceDetect,
};
