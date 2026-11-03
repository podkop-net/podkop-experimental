// the controls of the grid: each rebuild replaces them, and the focus falls to the body with them
const CONTROLS = [
  'pdk_dashboard-page__outbound-grid__item__block',
  'pdk_dashboard-page__outbound-grid__item__check-button',
  'dashboard-sections-grid-item-check-problems',
  'dashboard-sections-grid-item-check-cancel',
  'dashboard-sections-grid-item-test-latency',
];

// one tag can be in two sections, so the place of a control is told by both
function placeOf(element: Element): string {
  return JSON.stringify([
    element.closest('[data-section]')?.getAttribute('data-section') ?? null,
    element.closest('[data-tag]')?.getAttribute('data-tag') ?? null,
  ]);
}

// keepFocus runs a rebuild of the grid and gives the focus back to the same control of the same
// tile and section, if it is still there and enabled. The scroll is not its business.
export function keepFocus(container: Element, rebuild: () => void) {
  const focused = document.activeElement;
  const control =
    focused && container.contains(focused)
      ? CONTROLS.find((name) => focused.classList.contains(name))
      : undefined;
  const place = control ? placeOf(focused as Element) : '';

  rebuild();

  if (!control) return;
  const same = Array.from(container.getElementsByClassName(control)).find(
    (element) => placeOf(element) === place,
  ) as HTMLButtonElement | undefined;
  if (same && !same.disabled) same.focus({ preventScroll: true });
}
