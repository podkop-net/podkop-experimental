// language=CSS
export const styles = `
/* The setup wizard: a window of its own, with its own layout. Every colour is one of LuCI's theme
   (the variables of luci-theme-bootstrap, which differ between its light and its dark mode), so
   the window follows the mode of the page. The value after the comma is the light one, for a theme
   without these variables. A tint is the colour of the theme mixed into the surface. */
body.pdk-wizard-open { overflow: hidden; }

.pdk-wizard {
    --pdk-surface: var(--background-color-high, #fff);
    --pdk-surface-low: var(--background-color-low, #f5f5f5);
    --pdk-ink: var(--text-color-high, #404040);
    --pdk-mute: var(--text-color-medium, #808080);
    --pdk-faint: var(--text-color-low, #bfbfbf);
    --pdk-line: var(--border-color-medium, #ddd);
    --pdk-line-soft: var(--border-color-low, #eee);
    --pdk-line-strong: var(--border-color-high, #ccc);
    --pdk-primary: var(--primary-color-medium, #1564c0);
    --pdk-primary-strong: var(--primary-color-low, #0d46a1);
    --pdk-primary-light: var(--primary-color-high, #1976d2);
    --pdk-on-primary: var(--on-primary-color, #fff);
    --pdk-ok: var(--success-color-medium, #009a4c);
    --pdk-warn: var(--warn-color-high, #efbd0b);
    --pdk-bad: var(--error-color-medium, #e8210d);
    --pdk-primary-tint: color-mix(in srgb, var(--pdk-primary-light) 14%, var(--pdk-surface));
    --pdk-ok-tint: color-mix(in srgb, var(--pdk-ok) 14%, var(--pdk-surface));
    --pdk-warn-tint: color-mix(in srgb, var(--pdk-warn) 20%, var(--pdk-surface));
    --pdk-bad-tint: color-mix(in srgb, var(--pdk-bad) 13%, var(--pdk-surface));
    position: fixed;
    inset: 0;
    z-index: 10000;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding: 64px 16px 32px;
    overflow-y: auto;
    background: rgba(0, 0, 0, .6);
    box-sizing: border-box;
    color: var(--pdk-ink);
    font-size: 13px;
    line-height: 1.4;
    text-align: left;
}
.pdk-wizard *, .pdk-wizard *::before, .pdk-wizard *::after { box-sizing: border-box; }

.pdk-wizard__window {
    width: 100%;
    max-width: 760px;
    background: var(--pdk-surface);
    border: 1px solid var(--pdk-line-soft);
    border-radius: 12px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, .35);
    overflow: hidden;
}

.pdk-wizard__icon { display: inline-flex; flex: none; }
.pdk-wizard__icon svg { display: block; }
.pdk-wizard__icon--loader svg { animation: pdk-wizard-spin .9s linear infinite; }
@keyframes pdk-wizard-spin { to { transform: rotate(360deg); } }

.pdk-wizard__head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 24px 16px;
}
.pdk-wizard__title { font-size: 18px; font-weight: 700; }

.pdk-wizard button {
    font: inherit;
    margin: 0;
    background-image: none;
    box-shadow: none;
    text-shadow: none;
    cursor: pointer;
}
.pdk-wizard .pdk-wizard__close {
    display: inline-flex;
    padding: 4px;
    border: 0;
    border-radius: 6px;
    background: none;
    color: var(--pdk-mute);
}
.pdk-wizard .pdk-wizard__close:hover { background: var(--pdk-surface-low); color: var(--pdk-ink); }

.pdk-wizard__steps {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 24px 18px;
    border-bottom: 1px solid var(--pdk-line-soft);
}
.pdk-wizard__steps-line { flex: 1; height: 1px; background: var(--pdk-line); }
.pdk-wizard__step { display: flex; align-items: center; gap: 8px; color: var(--pdk-mute); }
.pdk-wizard__step-number {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    width: 24px;
    height: 24px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 50%;
    font-size: 12px;
    font-weight: 700;
    color: var(--pdk-mute);
}
.pdk-wizard__step--active { color: var(--pdk-ink); font-weight: 700; }
.pdk-wizard__step--active .pdk-wizard__step-number {
    border-color: var(--pdk-primary);
    background: var(--pdk-primary);
    color: var(--pdk-on-primary);
}

.pdk-wizard__body { display: flex; flex-direction: column; gap: 16px; padding: 22px 24px; }
.pdk-wizard__heading { font-size: 20px; font-weight: 700; line-height: 1.25; }
.pdk-wizard__lead { margin-top: 4px; color: var(--pdk-mute); }

.pdk-wizard__import { display: flex; flex-direction: column; gap: 10px; }
.pdk-wizard__field {
    display: flex;
    align-items: center;
    gap: 12px;
    height: 56px;
    margin: 0;
    padding: 0 16px 0 14px;
    border: 1.5px solid var(--pdk-primary-light);
    border-radius: 10px;
    background: var(--pdk-surface);
    box-shadow: 0 0 0 3px var(--pdk-primary-tint);
    cursor: text;
}
.pdk-wizard__field:focus-within { border-color: var(--pdk-primary); }
.pdk-wizard__field--busy {
    border-color: var(--pdk-line-strong);
    box-shadow: none;
    background: var(--pdk-surface-low);
}
.pdk-wizard__field-icon {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    flex: none;
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: var(--pdk-primary-tint);
    color: var(--pdk-primary-light);
}
.pdk-wizard .pdk-wizard__input {
    flex: 1;
    min-width: 0;
    width: auto;
    height: auto;
    margin: 0;
    padding: 0;
    border: 0;
    border-radius: 0;
    outline: 0;
    background: none;
    box-shadow: none;
    color: var(--pdk-ink);
    font: inherit;
    font-size: 15px;
}
.pdk-wizard .pdk-wizard__input::placeholder { color: var(--pdk-mute); opacity: 1; }

.pdk-wizard__schemes { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; padding: 0 2px; }
.pdk-wizard__schemes-label { font-size: 12px; color: var(--pdk-mute); }
.pdk-wizard__scheme {
    padding: 3px 8px;
    border-radius: 10px;
    background: var(--pdk-surface-low);
    color: var(--pdk-mute);
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
    font-size: 11px;
}

.pdk-wizard__alert {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    color: var(--pdk-ink);
}
.pdk-wizard__alert-text { flex: 1; min-width: 0; }
.pdk-wizard__alert-title { font-weight: 700; }
.pdk-wizard__alert-detail { overflow-wrap: anywhere; }
.pdk-wizard__alert--ok { background: var(--pdk-ok-tint); }
.pdk-wizard__alert--ok .pdk-wizard__icon { color: var(--pdk-ok); }
.pdk-wizard__alert--warn { background: var(--pdk-warn-tint); }
.pdk-wizard__alert--warn .pdk-wizard__icon { color: var(--pdk-warn); }
.pdk-wizard__alert--bad { background: var(--pdk-bad-tint); }
.pdk-wizard__alert--bad .pdk-wizard__icon,
.pdk-wizard__alert--bad .pdk-wizard__alert-title { color: var(--pdk-bad); }
.pdk-wizard .pdk-wizard__alert-button {
    flex: none;
    height: 32px;
    padding: 0 14px;
    border: 1px solid var(--pdk-bad);
    border-radius: 6px;
    background: var(--pdk-surface);
    color: var(--pdk-bad);
    font-weight: 700;
}

.pdk-wizard__sources { display: flex; flex-direction: column; gap: 8px; }
.pdk-wizard__list-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-top: 4px;
    margin-bottom: 4px;
}
.pdk-wizard__list-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 700; }
.pdk-wizard__count {
    padding: 1px 8px;
    border-radius: 9px;
    background: var(--pdk-surface-low);
    color: var(--pdk-mute);
    font-size: 12px;
}
.pdk-wizard .pdk-wizard__ghost-button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 30px;
    padding: 0 10px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 6px;
    background: var(--pdk-surface);
    color: var(--pdk-primary-light);
    font-weight: 700;
}
.pdk-wizard .pdk-wizard__ghost-button:hover {
    border-color: var(--pdk-primary-light);
    background: var(--pdk-primary-tint);
}

.pdk-wizard__empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 26px 14px;
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    color: var(--pdk-mute);
    text-align: center;
}
.pdk-wizard__empty .pdk-wizard__icon { color: var(--pdk-faint); }

.pdk-wizard__source {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 10px 11px 14px;
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    background: var(--pdk-surface);
}
.pdk-wizard__source-kind {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    flex: none;
    width: 36px;
    height: 36px;
    border-radius: 8px;
    background: var(--pdk-surface-low);
    color: var(--pdk-mute);
}
.pdk-wizard__source-kind--subscription {
    background: var(--pdk-primary-tint);
    color: var(--pdk-primary-light);
}
.pdk-wizard__source-text { flex: 1; min-width: 0; }
.pdk-wizard__source-title { font-size: 14px; font-weight: 700; overflow-wrap: anywhere; }
.pdk-wizard__source-subtitle {
    margin-top: 2px;
    font-size: 12px;
    color: var(--pdk-mute);
    overflow-wrap: anywhere;
}
.pdk-wizard .pdk-wizard__icon-button {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    flex: none;
    width: 30px;
    height: 30px;
    padding: 0;
    border: 0;
    border-radius: 6px;
    background: none;
    color: var(--pdk-mute);
}
.pdk-wizard .pdk-wizard__icon-button:hover { background: var(--pdk-surface-low); color: var(--pdk-ink); }

.pdk-wizard__foot {
    display: flex;
    justify-content: flex-end;
    padding: 14px 24px;
    border-top: 1px solid var(--pdk-line-soft);
}
.pdk-wizard .pdk-wizard__next {
    height: 36px;
    padding: 0 16px;
    border: 0;
    border-radius: 6px;
    background: var(--pdk-primary);
    color: var(--pdk-on-primary);
    font-size: 14px;
    font-weight: 700;
}
.pdk-wizard .pdk-wizard__next:hover { background: var(--pdk-primary-strong); }
.pdk-wizard .pdk-wizard__next:disabled {
    background: var(--pdk-surface-low);
    color: var(--pdk-mute);
    cursor: default;
}

.pdk-wizard button:focus-visible { outline: 2px solid var(--pdk-primary-light); outline-offset: 2px; }

/* The manual form */
.pdk-wizard .pdk-wizard__back {
    display: inline-flex;
    align-items: center;
    align-self: flex-start;
    gap: 6px;
    padding: 0;
    border: 0;
    background: none;
    color: var(--pdk-primary-light);
}
.pdk-wizard .pdk-wizard__back:hover { text-decoration: underline; }

.pdk-wizard__kinds { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
.pdk-wizard .pdk-wizard__kind {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
    padding: 12px;
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    background: var(--pdk-surface);
    color: var(--pdk-mute);
    text-align: left;
}
.pdk-wizard .pdk-wizard__kind:hover { border-color: var(--pdk-line-strong); }
.pdk-wizard .pdk-wizard__kind--active {
    border-color: var(--pdk-primary-light);
    box-shadow: inset 0 0 0 1px var(--pdk-primary-light);
    background: var(--pdk-primary-tint);
    color: var(--pdk-primary-light);
}
.pdk-wizard__kind-label { color: var(--pdk-ink); font-weight: 700; }
.pdk-wizard__kind-note { color: var(--pdk-mute); font-size: 12px; }

.pdk-wizard__row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
.pdk-wizard__control { display: flex; flex-direction: column; gap: 6px; margin: 0; min-width: 0; }
.pdk-wizard__control-label { color: var(--pdk-mute); font-size: 12px; font-weight: 700; }
.pdk-wizard__control-help { color: var(--pdk-mute); font-size: 12px; font-weight: 400; }
.pdk-wizard .pdk-wizard__text {
    display: block;
    width: 100%;
    min-width: 0;
    height: 36px;
    margin: 0;
    padding: 0 12px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 6px;
    outline: 0;
    background: var(--pdk-surface);
    box-shadow: none;
    color: var(--pdk-ink);
    font: inherit;
}
.pdk-wizard .pdk-wizard__text--area {
    height: auto;
    padding: 8px 12px;
    resize: vertical;
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
    font-size: 12px;
    line-height: 1.5;
}
.pdk-wizard .pdk-wizard__text:focus {
    border-color: var(--pdk-primary-light);
    box-shadow: 0 0 0 3px var(--pdk-primary-tint);
}
.pdk-wizard .pdk-wizard__text::placeholder { color: var(--pdk-mute); opacity: .8; }

.pdk-wizard__secret { position: relative; display: block; }
.pdk-wizard .pdk-wizard__secret .pdk-wizard__text { padding-right: 40px; }
.pdk-wizard .pdk-wizard__eye {
    position: absolute;
    top: 3px;
    right: 3px;
    display: inline-flex;
    justify-content: center;
    align-items: center;
    width: 30px;
    height: 30px;
    padding: 0;
    border: 0;
    border-radius: 5px;
    background: none;
    color: var(--pdk-mute);
}
.pdk-wizard .pdk-wizard__eye:hover { background: var(--pdk-surface-low); color: var(--pdk-ink); }

.pdk-wizard__select { position: relative; display: block; }
.pdk-wizard .pdk-wizard__select select {
    -webkit-appearance: none;
    appearance: none;
    padding-right: 36px;
    background-image: none;
    line-height: 34px;
    text-overflow: ellipsis;
    cursor: pointer;
}
.pdk-wizard .pdk-wizard__select option { background: var(--pdk-surface); color: var(--pdk-ink); }
.pdk-wizard__select .pdk-wizard__icon {
    position: absolute;
    top: 50%;
    right: 12px;
    transform: translateY(-50%);
    color: var(--pdk-mute);
    pointer-events: none;
}

.pdk-wizard__check { display: flex; align-items: flex-start; gap: 10px; margin: 0; cursor: pointer; }
.pdk-wizard .pdk-wizard__check input { flex: none; margin: 2px 0 0; }
.pdk-wizard__check-text { display: flex; flex-direction: column; gap: 2px; }
.pdk-wizard__check-label { font-weight: 700; }

.pdk-wizard__preview { display: flex; flex-direction: column; gap: 12px; }
.pdk-wizard__preview:empty { display: none; }
.pdk-wizard__preview--loading .pdk-wizard__servers { opacity: .45; }
.pdk-wizard__loading {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--pdk-primary-tint);
}
.pdk-wizard__loading .pdk-wizard__icon { color: var(--pdk-primary-light); }

.pdk-wizard__servers { display: flex; flex-direction: column; gap: 8px; }
.pdk-wizard__servers-head { display: flex; align-items: center; gap: 8px; }
.pdk-wizard__servers-title { font-size: 14px; font-weight: 700; }
.pdk-wizard__servers-list { display: flex; flex-wrap: wrap; gap: 6px; }
.pdk-wizard__server {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 100%;
    padding: 5px 6px 5px 10px;
    border: 1px solid var(--pdk-line);
    border-radius: 14px;
    background: var(--pdk-surface);
}
.pdk-wizard__server-name { overflow-wrap: anywhere; }
.pdk-wizard__server-scheme {
    padding: 1px 7px;
    border-radius: 9px;
    background: var(--pdk-surface-low);
    color: var(--pdk-mute);
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
    font-size: 11px;
}
.pdk-wizard__server--off { border-style: dashed; }
.pdk-wizard__server--off .pdk-wizard__server-name {
    color: var(--pdk-mute);
    text-decoration: line-through;
}
.pdk-wizard .pdk-wizard__server-more {
    padding: 5px 12px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 14px;
    background: var(--pdk-surface);
    color: var(--pdk-primary-light);
    font-weight: 700;
}
.pdk-wizard .pdk-wizard__server-more:hover {
    border-color: var(--pdk-primary-light);
    background: var(--pdk-primary-tint);
}

.pdk-wizard__divider { height: 1px; background: var(--pdk-line-soft); }

.pdk-wizard__alert:has(.pdk-wizard__details) { align-items: flex-start; }
.pdk-wizard__details {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 2px 12px;
    margin: 6px 0 0;
    padding: 0;
}
.pdk-wizard__details dt { margin: 0; color: var(--pdk-mute); font-weight: 400; }
.pdk-wizard__details dd { margin: 0; overflow-wrap: anywhere; }

@media (max-width: 600px) {
    .pdk-wizard__kinds { grid-template-columns: 1fr 1fr; }
    .pdk-wizard__row { grid-template-columns: 1fr; }
}

@media (max-width: 600px) {
    .pdk-wizard { padding: 12px 8px; }
    .pdk-wizard__body { padding: 18px 16px; }
    .pdk-wizard__head { padding: 16px 16px 12px; }
    .pdk-wizard__steps { padding: 0 16px 14px; }
    .pdk-wizard__step-label { display: none; }
    .pdk-wizard__step--active .pdk-wizard__step-label { display: inline; }
    .pdk-wizard__foot { padding: 12px 16px; }
}

@media (prefers-reduced-motion: reduce) {
    .pdk-wizard__icon--loader svg { animation: none; }
}

/* The dashboard of a router that is not set up yet: one block, one button */
/* Step 2: the rules */
.pdk-wizard__step--done { color: var(--pdk-ink); }
.pdk-wizard__step--done .pdk-wizard__step-number {
    border-color: var(--pdk-ok);
    background: var(--pdk-ok);
    color: var(--pdk-on-primary);
}

.pdk-route { display: flex; flex-direction: column; gap: 8px; }
.pdk-route__rule {
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    background: var(--pdk-surface);
}
.pdk-route__rule--dragging {
    position: relative;
    z-index: 2;
    border-color: var(--pdk-primary-light);
    box-shadow: 0 8px 24px rgba(0, 0, 0, .35);
}
.pdk-route__rule--before { box-shadow: 0 -3px 0 0 var(--pdk-primary-light); }
.pdk-route__rule--after { box-shadow: 0 3px 0 0 var(--pdk-primary-light); }
.pdk-route__head { display: flex; align-items: center; gap: 10px; padding: 11px 10px; cursor: pointer; }
.pdk-route__grip {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    flex: none;
    width: 20px;
    height: 32px;
    border-radius: 4px;
    color: var(--pdk-faint);
    cursor: grab;
    touch-action: none;
    user-select: none;
}
.pdk-route__grip:focus-visible { outline: 2px solid var(--pdk-primary-light); }
.pdk-route__grip:hover { color: var(--pdk-mute); }
.pdk-route__number {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    flex: none;
    width: 32px;
    height: 32px;
    border-radius: 8px;
    background: var(--pdk-primary-tint);
    color: var(--pdk-primary-light);
    font-size: 14px;
    font-weight: 700;
}
.pdk-route__text { flex: 1; min-width: 0; }
.pdk-route__title { font-size: 14px; font-weight: 700; overflow-wrap: anywhere; }
.pdk-route__subtitle {
    margin-top: 2px;
    overflow: hidden;
    color: var(--pdk-mute);
    font-size: 12px;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.pdk-route__rule--off .pdk-route__number { background: var(--pdk-surface-low); color: var(--pdk-mute); }
.pdk-route__rule--off .pdk-route__title { color: var(--pdk-mute); }
.pdk-wizard .pdk-route__switch {
    flex: none;
    width: 34px;
    height: 20px;
    padding: 2px;
    border: 0;
    border-radius: 10px;
    background: var(--pdk-line-strong);
    transition: background .15s;
}
.pdk-route__switch::after {
    content: '';
    display: block;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--pdk-on-primary);
    transition: transform .15s;
}
.pdk-wizard .pdk-route__switch[aria-checked="true"] { background: var(--pdk-primary); }
.pdk-route__switch[aria-checked="true"]::after { transform: translateX(14px); }
.pdk-route__fold[aria-expanded="true"] .pdk-wizard__icon,
.pdk-route__count--open .pdk-wizard__icon { transform: rotate(180deg); }
.pdk-route__body {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding: 16px;
    border-top: 1px solid var(--pdk-line-soft);
}
.pdk-route__group { display: flex; flex-direction: column; gap: 10px; }
.pdk-route__tags { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.pdk-route__tag {
    display: inline-flex;
    align-items: center;
    gap: 2px;
    height: 28px;
    padding: 0 3px 0 11px;
    border: 1px solid color-mix(in srgb, var(--pdk-primary-light) 55%, var(--pdk-surface));
    border-radius: 14px;
    background: var(--pdk-primary-tint);
    font-weight: 700;
}
.pdk-wizard .pdk-route__tag-x,
.pdk-wizard .pdk-route__word-x {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: none;
    color: var(--pdk-mute);
}
.pdk-wizard .pdk-route__tag-x:hover { background: var(--pdk-line); color: var(--pdk-ink); }
.pdk-wizard .pdk-route__pick {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 11px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 14px;
    background: var(--pdk-surface);
    color: var(--pdk-ink);
    font-size: 12px;
}
.pdk-wizard .pdk-route__pick:hover { border-color: var(--pdk-primary-light); }
.pdk-wizard .pdk-route__pick--on { border-color: var(--pdk-primary); background: var(--pdk-primary); color: var(--pdk-on-primary); font-weight: 700; }
.pdk-wizard .pdk-route__pick--on .pdk-wizard__icon { color: inherit; }
.pdk-wizard .pdk-route__pick--off { border-style: dashed; border-color: var(--pdk-line); color: var(--pdk-mute); }
.pdk-wizard .pdk-route__pick--add, .pdk-wizard .pdk-route__pick--add.pdk-route__pick--on { background: var(--pdk-surface); border-color: var(--pdk-line-strong); }
.pdk-wizard .pdk-route__pick--add.pdk-route__pick--on { border-color: var(--pdk-primary-light); }
.pdk-wizard .pdk-route__pick--add { color: var(--pdk-primary-light); font-size: 13px; font-weight: 700; }
.pdk-wizard .pdk-route__pick:disabled { opacity: .45; cursor: default; border-color: var(--pdk-line); }
/* The lists of a rule are chosen in a window of their own, over the wizard: its height is that
   of the screen at most, and the lists scroll inside it. */
.pdk-route__shade {
    position: fixed;
    inset: 0;
    z-index: 10;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 24px 16px;
    background: rgba(0, 0, 0, .55);
    cursor: default;
}
.pdk-route__sheet {
    display: flex;
    flex-direction: column;
    width: 100%;
    max-width: 560px;
    max-height: 100%;
    border: 1px solid var(--pdk-line-soft);
    border-radius: 12px;
    background: var(--pdk-surface);
    box-shadow: 0 12px 40px rgba(0, 0, 0, .45);
}
.pdk-route__sheet-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 16px 12px 20px;
}
.pdk-route__sheet-title { display: flex; align-items: center; gap: 8px; font-size: 16px; font-weight: 700; }
.pdk-route__sheet-search { padding: 0 20px 14px; }
.pdk-route__sheet-body {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: 16px;
    min-height: 0;
    padding: 2px 20px 18px;
    overflow-y: auto;
    overscroll-behavior: contain;
}
.pdk-route__sheet-foot {
    display: flex;
    justify-content: flex-end;
    padding: 12px 20px;
    border-top: 1px solid var(--pdk-line-soft);
}
.pdk-route__step { font-size: 14px; font-weight: 700; }
.pdk-route__step-number { margin-right: 6px; color: var(--pdk-mute); }
.pdk-route__note { color: var(--pdk-mute); }
.pdk-route__modes { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
.pdk-wizard .pdk-route__mode {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 11px 12px;
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    background: var(--pdk-surface);
    color: var(--pdk-ink);
    text-align: left;
    white-space: normal;
    word-break: normal;
    overflow-wrap: normal;
}
.pdk-wizard .pdk-route__mode:hover { border-color: var(--pdk-line-strong); }
.pdk-wizard .pdk-route__mode[aria-checked="true"] {
    border-color: var(--pdk-primary-light);
    background: var(--pdk-primary-tint);
    box-shadow: inset 0 0 0 1px var(--pdk-primary-light);
}
.pdk-route__radio {
    flex: none;
    width: 18px;
    height: 18px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 50%;
    background: var(--pdk-surface);
}
.pdk-route__mode[aria-checked="true"] .pdk-route__radio {
    border: 5px solid var(--pdk-primary-light);
    background: var(--pdk-on-primary);
}
.pdk-route__mode-text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.pdk-route__mode-name { font-size: 14px; font-weight: 700; }
.pdk-route__mode-note { color: var(--pdk-mute); }
.pdk-route__source {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 9px 10px 9px 12px;
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    background: var(--pdk-surface);
}
.pdk-route__source--open { border-color: var(--pdk-primary-light); }
.pdk-route__source-row { display: flex; align-items: center; gap: 10px; cursor: pointer; outline: 0; }
.pdk-route__source-row:focus-visible .pdk-route__box { outline: 2px solid var(--pdk-primary-light); outline-offset: 2px; }
.pdk-route__source--off .pdk-wizard__source-title { color: var(--pdk-mute); font-weight: 400; }
.pdk-route__source .pdk-wizard__source-kind { width: 32px; height: 32px; }
.pdk-route__box {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    flex: none;
    width: 18px;
    height: 18px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 4px;
    background: var(--pdk-surface);
    color: var(--pdk-on-primary);
}
.pdk-route__box--on { border-color: var(--pdk-primary); background: var(--pdk-primary); }
.pdk-wizard .pdk-route__count {
    display: inline-flex;
    align-items: center;
    flex: none;
    gap: 4px;
    height: 28px;
    padding: 0 8px;
    border: 0;
    border-radius: 6px;
    background: none;
    color: var(--pdk-primary-light);
    font-size: 12px;
    font-weight: 700;
}
.pdk-wizard .pdk-route__count:hover,
.pdk-wizard .pdk-route__count--open { background: var(--pdk-primary-tint); }
.pdk-wizard .pdk-route__count--zero { color: var(--pdk-bad); }
.pdk-route__filter { display: flex; flex-direction: column; gap: 12px; }
.pdk-route__filter-fields { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.pdk-route__words {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    min-height: 36px;
    padding: 5px 8px;
    border: 1px solid var(--pdk-line-strong);
    border-radius: 6px;
    background: var(--pdk-surface);
    cursor: text;
}
.pdk-route__words:focus-within { border-color: var(--pdk-primary); }
.pdk-route__word {
    display: inline-flex;
    align-items: center;
    height: 24px;
    padding: 0 1px 0 8px;
    border-radius: 5px;
    background: var(--pdk-primary-tint);
    color: var(--pdk-primary-light);
    font-weight: 700;
}
.pdk-wizard .pdk-route__word-x { color: inherit; }
.pdk-wizard .pdk-route__words input {
    flex: 1;
    width: auto;
    min-width: 60px;
    height: 24px;
    margin: 0;
    padding: 0 4px;
    border: 0;
    outline: 0;
    background: none;
    box-shadow: none;
    color: var(--pdk-ink);
    font: inherit;
}
.pdk-wizard .pdk-route__words input::placeholder { color: var(--pdk-mute); opacity: .8; }
@media (max-width: 600px) {
    .pdk-route__filter-fields { grid-template-columns: 1fr; }
    .pdk-route__modes { grid-template-columns: 1fr; }
    .pdk-route__head { gap: 8px; }
}
/* Step 3: the DNS */
.pdk-wizard__list-head .pdk-route__step { display: flex; align-items: center; }
.pdk-dns__count { margin-left: 8px; font-weight: 400; }
.pdk-dns__bootstrap { max-width: 360px; }
.pdk-dns__address { display: block; flex: 1; min-width: 0; }
.pdk-dns__server {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px;
    border: 1px solid var(--pdk-line);
    border-radius: 8px;
    background: var(--pdk-surface);
}
.pdk-dns__type { flex: none; width: 230px; }
.pdk-dns__provider { flex: 1; min-width: 0; color: var(--pdk-mute); }
.pdk-wizard .pdk-wizard__icon-button:disabled { opacity: .35; cursor: default; }
.pdk-dns__mode { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding-top: 4px; }
.pdk-dns__mode-label { font-weight: 700; }
.pdk-dns__switch { display: inline-flex; gap: 2px; padding: 3px; border-radius: 8px; background: var(--pdk-surface-low); }
.pdk-wizard .pdk-dns__switch button {
    height: 28px;
    padding: 0 14px;
    border: 0;
    border-radius: 6px;
    background: none;
    color: var(--pdk-mute);
    white-space: nowrap;
}
.pdk-wizard .pdk-dns__switch button[aria-checked="true"] {
    background: var(--pdk-surface);
    box-shadow: 0 1px 2px rgba(0, 0, 0, .2);
    color: var(--pdk-ink);
    font-weight: 700;
}
.pdk-wizard .pdk-dns__more { font-weight: 700; }
.pdk-dns__more[aria-expanded="true"] .pdk-wizard__icon { transform: rotate(180deg); }
.pdk-dns__fields { display: grid; grid-template-columns: 1fr 200px; gap: 16px; }
@media (max-width: 600px) {
    .pdk-dns__server { flex-wrap: wrap; }
    .pdk-dns__type { flex: 1; width: auto; }
    .pdk-dns__address, .pdk-dns__provider { flex: 1 1 100%; order: 5; }
    .pdk-dns__bootstrap { max-width: none; }
    .pdk-dns__fields { grid-template-columns: 1fr; }
    .pdk-wizard .pdk-dns__switch button { height: 38px; }
}

/* A phone, or any screen that is touched: what is pressed is at least 40px, a field does not make
   the browser zoom (16px), and the way out of the step stays at the bottom of the screen. */
@media (pointer: coarse), (max-width: 600px) {
    .pdk-route__grip { width: 32px; height: 44px; margin: 0 -6px 0 -8px; }
    .pdk-route__head { padding: 10px 8px; }
    .pdk-wizard .pdk-wizard__icon-button { width: 40px; height: 40px; }
    .pdk-wizard .pdk-route__switch { width: 44px; height: 26px; padding: 3px; border-radius: 13px; }
    .pdk-route__switch::after { width: 20px; height: 20px; }
    .pdk-route__switch[aria-checked="true"]::after { transform: translateX(18px); }
    .pdk-route__tags { gap: 8px; }
    .pdk-route__tag { height: 38px; padding: 0 4px 0 13px; border-radius: 19px; }
    .pdk-wizard .pdk-route__tag-x { width: 32px; height: 32px; }
    .pdk-wizard .pdk-route__pick { height: 38px; padding: 0 14px; border-radius: 19px; font-size: 14px; }
    .pdk-route__words { min-height: 44px; }
    .pdk-route__word { height: 32px; }
    .pdk-wizard .pdk-route__word-x { width: 30px; height: 30px; }
    .pdk-wizard .pdk-route__words input { height: 32px; font-size: 16px; }
    .pdk-wizard .pdk-wizard__text { height: 44px; font-size: 16px; }
    .pdk-wizard .pdk-route__count { height: 40px; padding: 0 10px; font-size: 13px; }
    .pdk-route__box { width: 22px; height: 22px; }
    .pdk-route__source { padding: 12px; }
    .pdk-wizard .pdk-wizard__ghost-button { height: 40px; }
    .pdk-wizard .pdk-wizard__next { height: 44px; }
}
@media (max-width: 600px) {
    .pdk-route__body { padding: 12px; }
    .pdk-route__shade { align-items: flex-end; padding: 40px 0 0; }
    .pdk-route__sheet { max-width: none; border-width: 1px 0 0; border-radius: 16px 16px 0 0; }
    .pdk-route__sheet-foot .pdk-wizard__next { width: 100%; }
    .pdk-wizard__window { overflow: clip; }
    .pdk-wizard__foot {
        position: sticky;
        bottom: 0;
        z-index: 3;
        border-radius: 0 0 12px 12px;
        background: var(--pdk-surface);
    }
}
@media (prefers-reduced-motion: reduce) {
    .pdk-route__switch, .pdk-route__switch::after { transition: none; }
}

.pdk-dashboard-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    padding: 56px 20px;
    border: 1px solid var(--border-color-medium, #ddd);
    border-radius: 4px;
    text-align: center;
}
.pdk-dashboard-empty__title { font-size: 18px; font-weight: 700; }
.pdk-dashboard-empty__text { max-width: 560px; }
`;
