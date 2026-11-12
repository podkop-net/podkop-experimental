// language=CSS
export const styles = `
#cbi-podkop-dashboard-_mount_node > div {
    width: 100%;
}

#cbi-podkop-dashboard > h3 {
    display: none;
}
    
.pdk_dashboard-page {
    width: 100%;
    --dashboard-grid-columns: 4;
}

@media (max-width: 900px) {
    .pdk_dashboard-page {
        --dashboard-grid-columns: 2;
    }
}

.pdk_dashboard-page__widgets-section {
    margin-top: 10px;
    display: grid;
    grid-template-columns: repeat(var(--dashboard-grid-columns), 1fr);
    grid-gap: 10px;
}

.pdk_dashboard-page__widgets-section__item {
    border: 2px var(--background-color-low, lightgray) solid;
    border-radius: 4px;
    padding: 10px;
}

.pdk_dashboard-page__widgets-section__item__title {}

.pdk_dashboard-page__widgets-section__item__row {}

.pdk_dashboard-page__widgets-section__item__row--success .pdk_dashboard-page__widgets-section__item__row__value {
    color: var(--success-color-medium, green);
}

.pdk_dashboard-page__widgets-section__item__row--error .pdk_dashboard-page__widgets-section__item__row__value {
    color: var(--error-color-medium, red);
}

.pdk_dashboard-page__widgets-section__item__row__key {}

.pdk_dashboard-page__widgets-section__item__row__value {}

.pdk_dashboard-page__outbound-section {
    margin-top: 10px;
    border: 2px var(--background-color-low, lightgray) solid;
    border-radius: 4px;
    padding: 10px;
}

.pdk_dashboard-page__outbound-section__title-section {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 6px 10px;
}

.pdk_dashboard-page__outbound-section__title-section__actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 10px;
    margin-left: auto;
}

/* how the rule chose where its connections go, beside its name */
.pdk_dashboard-page__outbound-section__route {
    color: var(--text-color-high, inherit);
    font-size: 13px;
    min-width: 0;
    overflow-wrap: anywhere;
}

/* A pinned server, or a fallback in use: the servers of the rule do not decide. The text keeps
   its colour and the tint under it tells: the warn colour of the light theme is too pale for text. */
.pdk_dashboard-page__outbound-section__route--warning,
.pdk_dashboard-page__outbound-section__route--error {
    padding: 1px 6px;
    border-radius: 4px;
    background: rgba(240, 160, 0, 0.22);
}

/* a block fallback in use: the connections of the rule are refused */
.pdk_dashboard-page__outbound-section__route--error {
    background: rgba(220, 40, 30, 0.22);
}

.pdk_dashboard-page__outbound-section__title-section__title {
    color: var(--text-color-high);
    font-weight: 700;
}

.pdk_dashboard-page__outbound-grid {
    margin-top: 5px;
    display: grid;
    grid-template-columns: repeat(var(--dashboard-grid-columns), 1fr);
    grid-gap: 10px;
}

/* With fallbacks the tiles of a tier sit on its tint, two tints in turn: a cell of the grid per
   tile, the tint in its padding, which joins the tiles of a tier. The padding replaces the gap,
   and the margin keeps the tiles where the gap put them. */
.pdk_dashboard-page__outbound-grid--tiers {
    grid-gap: 0;
    margin-left: -5px;
    margin-right: -5px;
}

.pdk_dashboard-page__outbound-grid__cell {
    position: relative;
    display: flex;
    flex-direction: column;
    min-width: 0;
    padding: 18px 5px 5px;
}

.pdk_dashboard-page__outbound-grid__cell > .pdk_dashboard-page__outbound-grid__item {
    flex: 1;
}

.pdk_dashboard-page__outbound-grid__cell--tint-0 {
    background: rgba(127, 127, 127, 0.1);
}

.pdk_dashboard-page__outbound-grid__cell--tint-1 {
    background: rgba(30, 144, 255, 0.12);
}

/* the name of a tier, over its first tile */
.pdk_dashboard-page__outbound-grid__tier {
    position: absolute;
    top: 2px;
    left: 7px;
    right: 5px;
    font-size: 11px;
    font-weight: 600;
    line-height: 14px;
    color: var(--text-color-high, inherit);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.pdk_dashboard-page__outbound-grid__item {
    border: 2px var(--background-color-low, lightgray) solid;
    border-radius: 4px;
    padding: 10px;
    min-width: 0;
    overflow-wrap: anywhere;
    transition: border 0.2s ease;
}

.pdk_dashboard-page__outbound-grid__item--selectable {
    cursor: pointer;
}

.pdk_dashboard-page__outbound-grid__item--selectable:hover {
    border-color: var(--primary-color-high, dodgerblue);
}

/* the marks stay under the pointer: a tile just clicked shows it is in use */
.pdk_dashboard-page__outbound-grid__item--active,
.pdk_dashboard-page__outbound-grid__item--active:hover {
    border-color: var(--success-color-medium, green);
}

/* the choice of a fallback of several servers, for when its turn comes */
.pdk_dashboard-page__outbound-grid__item--pick,
.pdk_dashboard-page__outbound-grid__item--pick:hover {
    border-style: dashed;
    border-color: var(--success-color-medium, green);
}

.pdk_dashboard-page__outbound-grid__item__footer {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 4px 8px;
    margin-top: 10px;
}

.pdk_dashboard-page__outbound-grid__item__check {
    container-type: inline-size;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 4px 8px;
    margin-top: 6px;
}

button.pdk_dashboard-page__outbound-grid__item__check-button {
    min-height: 28px;
    padding: 2px 8px;
    font-size: 12px;
    line-height: normal;
}

/* Wraps between words only, whatever the tile above allows. A word wider than the tile (the longest
   label has 10 letters, about 0.6 em each) takes a smaller font; where the browser has no cqi, the
   12px stays. At the very least it is cut, not out of the tile. The theme on a phone sets
   button { font-size: 14px !important } (mobile.css), hence the !important here. */
button.pdk_dashboard-page__outbound-grid__item__block {
    min-height: 28px;
    max-width: 100%;
    padding: 2px 8px;
    border: 1px solid currentColor;
    border-radius: 4px;
    background: transparent;
    box-shadow: none;
    text-shadow: none;
    font-size: 12px !important;
    font-size: clamp(9px, calc((100cqi - 18px) / 6.5), 12px) !important;
    font-weight: 600;
    line-height: normal;
    white-space: normal;
    overflow-wrap: normal;
    word-break: normal;
    overflow: hidden;
    cursor: pointer;
}

button.pdk_dashboard-page__outbound-grid__item__block--ok {
    color: var(--success-color-medium, green);
}

button.pdk_dashboard-page__outbound-grid__item__block--warn {
    color: var(--warn-color-medium, orange);
}

button.pdk_dashboard-page__outbound-grid__item__block--error {
    color: var(--error-color-medium, red);
}

button.pdk_dashboard-page__outbound-grid__item__block--muted {
    color: var(--text-color-low, gray);
}

button.pdk_dashboard-page__outbound-grid__item__block--neutral {
    color: var(--text-color-high, inherit);
}

.pdk_dashboard-page__outbound-grid__item__type {}

.pdk_dashboard-page__outbound-grid__item__loss--ok {
  color: var(--text-color-medium, inherit);
}

.pdk_dashboard-page__outbound-grid__item__loss--warn {
  color: var(--warn-color-medium, orange);
}

.pdk_dashboard-page__outbound-grid__item__loss--error {
  color: var(--error-color-medium, red);
}

.pdk_dashboard-page__outbound-grid__item__loss--preliminary {
  opacity: 0.55;
}

.pdk_dashboard-page__outbound-section__legend {
  font-size: 0.85em;
  opacity: 0.75;
  margin-top: 4px;
  overflow-wrap: anywhere;
}

.pdk_dashboard-page__outbound-grid__item__latency--empty {
    color: var(--primary-color-low, lightgray);
}

.pdk_dashboard-page__outbound-grid__item__latency--green {
    color: var(--success-color-medium, green);
}

.pdk_dashboard-page__outbound-grid__item__latency--yellow {
    color: var(--warn-color-medium, orange);
}

.pdk_dashboard-page__outbound-grid__item__latency--red {
    color: var(--error-color-medium, red);
}

/* what the last "Test latency" found, under the median: small and muted, in the colour of text */
.pdk_dashboard-page__outbound-grid__item__latency-now {
    font-size: 0.8em;
    opacity: 0.8;
    color: var(--text-color-medium, inherit);
    text-align: right;
    white-space: nowrap;
}

/* the cure line: small and muted, wraps between words, a too-wide word shrinks and is cut, so it
   never widens the tile (the same rule as the chip above). As a button (it opens the window of the
   server) it keeps the look of the line. */
.pdk_dashboard-page__outbound-grid__item__cure {
    display: block;
    padding: 0;
    border: 0;
    background: none;
    color: inherit;
    text-align: left;
    cursor: pointer;
    margin-top: 4px;
    max-width: 100%;
    font-size: 11px;
    font-size: clamp(9px, calc((100cqi - 12px) / 9), 11px);
    opacity: 0.7;
    white-space: normal;
    overflow-wrap: normal;
    word-break: normal;
    overflow: hidden;
}

/* the treatment fieldset in the verdict window */
.pdk-cure {
    margin: 10px 0;
    padding: 8px 10px;
    border: 1px solid var(--border-color-medium, rgba(128, 128, 128, 0.3));
    border-radius: 4px;
}

.pdk-cure__option {
    display: block;
    margin: 4px 0;
}

.pdk-cure__option--disabled {
    opacity: 0.5;
}

.pdk-cure__hint {
    opacity: 0.6;
    font-size: 0.9em;
}

.pdk-cure__sni {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin: 6px 0 2px 22px;
}

.pdk-cure__sni input {
    flex: 1 1 10em;
    min-width: 8em;
}

/* the line above the sections about treatments stored for servers not in use */
.pdk-cure-stale {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin: 0 0 10px;
    padding: 6px 10px;
    border: 1px solid var(--border-color-medium, rgba(128, 128, 128, 0.3));
    border-radius: 4px;
}

`;
