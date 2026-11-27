// language=CSS
import { DashboardTab, DiagnosticTab } from './podkop';
import { PartialStyles } from './partials';
import { styles as WizardStyles } from './podkop/wizard/styles';

export const GlobalStyles = `
${DashboardTab.styles}
${DiagnosticTab.styles}
${PartialStyles}
${WizardStyles}


/* A row of the provider's DNS has no address: no title of the hidden cell on a phone. LuCI
   marks the cell inactive only when the field is hidden later, not when the row is drawn so */
#cbi-podkop-dns_server .td.cbi-value-field.inactive,
#cbi-podkop-dns_server .td.cbi-value-field:has(> [data-field].hidden) {
    padding: 0;
}

#cbi-podkop-dns_server .td.cbi-value-field.inactive::before,
#cbi-podkop-dns_server .td.cbi-value-field:has(> [data-field].hidden)::before {
    content: none;
}

/* The apply bar (podkop/applyBar.ts) and the version bar under it (podkop/versionBar.ts): LuCI's
   alert-message, the text and the buttons in a row that wraps on a phone. Argon gives
   .alert-message a fixed width of 20rem (made for its centred notices), and the first div of
   #view a column (#view > div:first-child:not(.cbi-map, .Dashboard), stronger than one id: the
   text took 18em of height there): a bar takes the width of the page, in a row, by two ids. */
#view > #podkop-apply-bar,
#view > #podkop-version-bar,
#podkop-apply-bar,
#podkop-version-bar {
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
    align-items: center;
    gap: .5em 1em;
    width: auto;
    max-width: 100%;
    box-sizing: border-box;
}

#podkop-apply-bar .podkop-apply-text,
#podkop-version-bar .podkop-apply-text {
    flex: 1 1 18em;
    min-width: 0;
    margin: 0;
    overflow-wrap: anywhere;
}

#podkop-apply-bar .podkop-apply-actions,
#podkop-version-bar .podkop-apply-actions {
    display: flex;
    flex-wrap: wrap;
    gap: .5em;
}

#podkop-apply-bar .podkop-apply-actions .btn,
#podkop-version-bar .podkop-apply-actions .btn {
    margin: 0;
}

/* Centered class helper */
.centered {
    display: flex;
    align-items: center;
    justify-content: center;
}

/* Rotate class helper */
.rotate {
    animation: spin 1s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

/* Skeleton styles*/
.skeleton {
    background-color: var(--background-color-low, rgba(128, 128, 128, 0.2));
    border-radius: 4px;
    position: relative;
    overflow: hidden;
}

.skeleton::after {
    content: '';
    position: absolute;
    top: 0;
    left: -150%;
    width: 150%;
    height: 100%;
    background: linear-gradient(
            90deg,
            transparent,
            rgba(160, 160, 160, 0.25),
            transparent
    );
    animation: skeleton-shimmer 1.6s infinite;
}

@keyframes skeleton-shimmer {
    100% {
        left: 150%;
    }
}
/* Toast */
.toast-container {
    position: fixed;
    bottom: 30px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    z-index: 9999;
    font-family: system-ui, sans-serif;
}

.toast {
    opacity: 0;
    transform: translateY(10px);
    transition: opacity 0.3s ease, transform 0.3s ease;
    padding: 10px 16px;
    border-radius: 6px;
    color: #fff;
    font-size: 14px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    min-width: 220px;
    max-width: 340px;
    text-align: center;
}

.toast-success {
    background-color: #28a745;
}

.toast-error {
    background-color: #dc3545;
}

.toast.visible {
    opacity: 1;
    transform: translateY(0);
}
`;
