// language=CSS
import { DashboardTab, DiagnosticTab } from './podkop';
import { PartialStyles } from './partials';

export const GlobalStyles = `
${DashboardTab.styles}
${DiagnosticTab.styles}
${PartialStyles}


/* Hide extra H3 for settings tab */
#cbi-podkop-settings > h3 {
    display: none;
}

/* Hide extra H3 for sections tab */
#cbi-podkop-section > h3:nth-child(1) {
    display: none;
}

/* Hide extra H3 for the tabs of the subscriptions and the groups */
#cbi-podkop-subscription > h3:nth-child(1),
#cbi-podkop-group > h3:nth-child(1) {
    display: none;
}

/* Vertical align for remove section action button */
#cbi-podkop-section > .cbi-section-remove,
#cbi-podkop-subscription > .cbi-section-remove,
#cbi-podkop-group > .cbi-section-remove {
    margin-bottom: -32px;
}

/* The servers of a subscription and of a group (subscription.js, group.js) */
.pdk-sub-result {
    margin-top: 8px;
}

.pdk-sub-list ul {
    list-style: none;
    margin: 4px 0 0;
    padding: 0;
    max-height: 420px;
    overflow-y: auto;
}

.pdk-sub-list li {
    padding: 4px 0;
    border-bottom: 1px solid var(--border-color-medium, #ddd);
    overflow-wrap: anywhere;
}

.pdk-sub-endpoint,
.pdk-sub-notes {
    opacity: 0.7;
}

.pdk-sub-unusable strong {
    text-decoration: line-through;
}

.pdk-sub-reason,
.pdk-sub-error {
    color: var(--error-color-high, #c0392b);
}

.pdk-sub-state div,
.pdk-sub-provider div {
    margin: 1px 0;
}

.pdk-sub-provider {
    margin-top: 6px;
    padding-top: 4px;
    border-top: 1px solid var(--border-color-medium, #ddd);
}

.pdk-sub-provider .cbi-progressbar {
    max-width: 320px;
    margin: 2px 0 4px;
}

/* the line above the bar has the numbers: the label a theme draws over a bar would cover it */
.pdk-sub-provider .cbi-progressbar::before,
.pdk-sub-provider .cbi-progressbar::after {
    content: none;
}

.pdk-sub-announce {
    white-space: pre-line;
    opacity: 0.85;
}

.pdk-sub-warn {
    color: var(--warn-color-high, #b9770e);
}

.pdk-sub-tries {
    margin: 4px 0;
    padding-left: 1em;
    opacity: 0.85;
}

.pdk-sub-load-actions button {
    margin-right: 6px;
}

.pdk-sub-link code {
    display: block;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.85em;
}

/* The links the router refuses at a save (linkCheck.ts) */
.pdk-link-problems {
    list-style: none;
    margin: 0;
    padding: 0;
}

.pdk-link-problems li {
    display: grid;
    gap: 4px;
    padding: 8px 0;
    border-bottom: 1px solid var(--border-color-medium, #ddd);
    overflow-wrap: anywhere;
}

.pdk-link-problems li button {
    justify-self: start;
}

.pdk-link-problem-error {
    color: var(--error-color-high, #c0392b);
}

.pdk-link-problem {
    outline: 2px solid var(--error-color-high, #c0392b);
    outline-offset: 2px;
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
    background-color: var(--background-color-low, #e0e0e0);
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
            rgba(255, 255, 255, 0.4),
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
