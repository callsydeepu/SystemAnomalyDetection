import json
from typing import Optional

def get_toast_html(
    sse_port: int,
    direct_event: Optional[dict] = None,
    enable_sound: bool = True,
    enable_browser_push: bool = True
) -> str:
    """
    Generates self-contained HTML, CSS, and JavaScript for the real-time bottom-right
    toast notification system. Connects via Server-Sent Events (SSE) to receive
    anomalies in real time without refreshing the page.
    """
    direct_evt_json = json.dumps(direct_event) if direct_event else "null"
    sound_flag = "true" if enable_sound else "false"
    push_flag = "true" if enable_browser_push else "false"
    
    return f"""
<div id="sentinel-toast-anchor" style="display:none;"></div>
<script>
(function() {{
    const SSE_PORT = {sse_port};
    const DIRECT_EVENT = {direct_evt_json};
    const ENABLE_SOUND = {sound_flag};
    const ENABLE_BROWSER_PUSH = {push_flag};

    let targetDoc = document;
    try {{
        if (window.parent && window.parent.document) {{
            targetDoc = window.parent.document;
        }}
    }} catch(e) {{
        targetDoc = document;
    }}

    function escapeHtml(str) {{
        if (str === null || str === undefined) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }}

    // 1. Inject Styles into target document head if not present
    if (!targetDoc.getElementById("sentinel-toast-styles")) {{
        const style = targetDoc.createElement("style");
        style.id = "sentinel-toast-styles";
        style.textContent = `
            #sentinel-toast-container {{
                position: fixed !important;
                bottom: 24px !important;
                right: 24px !important;
                z-index: 99999999 !important;
                display: flex !important;
                flex-direction: column-reverse !important;
                gap: 12px !important;
                max-width: 440px !important;
                width: calc(100vw - 48px) !important;
                pointer-events: none !important;
                font-family: 'Outfit', sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
            }}

            .sentinel-toast-card {{
                pointer-events: auto !important;
                position: relative !important;
                border-radius: 12px !important;
                padding: 16px 18px !important;
                color: #f8fafc !important;
                box-shadow: 0 12px 36px rgba(0, 0, 0, 0.7), 0 0 1px rgba(255, 255, 255, 0.25) !important;
                display: flex !important;
                flex-direction: column !important;
                gap: 8px !important;
                transform: translateX(120%) !important;
                opacity: 0 !important;
                transition: transform 0.38s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.38s ease !important;
                backdrop-filter: blur(16px) !important;
                -webkit-backdrop-filter: blur(16px) !important;
                overflow: hidden !important;
            }}

            .sentinel-toast-card.visible {{
                transform: translateX(0) !important;
                opacity: 1 !important;
            }}

            .sentinel-toast-card.dismissing {{
                transform: translateX(120%) !important;
                opacity: 0 !important;
            }}

            /* Critical Severity (Red Alert) */
            .sentinel-toast-critical {{
                background: linear-gradient(135deg, rgba(30, 10, 10, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%) !important;
                border-left: 6px solid #ef4444 !important;
                border-top: 1px solid rgba(239, 68, 68, 0.4) !important;
                border-right: 1px solid rgba(239, 68, 68, 0.2) !important;
                border-bottom: 1px solid rgba(239, 68, 68, 0.2) !important;
            }}

            /* Warning Severity (Orange / Amber Alert) */
            .sentinel-toast-warning {{
                background: linear-gradient(135deg, rgba(35, 22, 10, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%) !important;
                border-left: 6px solid #f59e0b !important;
                border-top: 1px solid rgba(245, 158, 11, 0.4) !important;
                border-right: 1px solid rgba(245, 158, 11, 0.2) !important;
                border-bottom: 1px solid rgba(245, 158, 11, 0.2) !important;
            }}

            .sentinel-toast-top {{
                display: flex !important;
                align-items: flex-start !important;
                justify-content: space-between !important;
                gap: 8px !important;
            }}

            .sentinel-toast-title-box {{
                display: flex !important;
                align-items: center !important;
                gap: 8px !important;
                font-weight: 700 !important;
                font-size: 14.5px !important;
                line-height: 1.3 !important;
            }}

            .sentinel-toast-badge {{
                padding: 3px 8px !important;
                border-radius: 4px !important;
                font-size: 11px !important;
                font-weight: 700 !important;
                letter-spacing: 0.5px !important;
                text-transform: uppercase !important;
                white-space: nowrap !important;
            }}

            .sentinel-badge-critical {{
                background: #ef4444 !important;
                color: #ffffff !important;
            }}

            .sentinel-badge-warning {{
                background: #f59e0b !important;
                color: #000000 !important;
            }}

            .sentinel-toast-close {{
                background: transparent !important;
                border: none !important;
                color: #94a3b8 !important;
                cursor: pointer !important;
                font-size: 20px !important;
                line-height: 1 !important;
                padding: 0 4px !important;
                transition: color 0.2s !important;
            }}

            .sentinel-toast-close:hover {{
                color: #f8fafc !important;
            }}

            .sentinel-toast-meta {{
                display: flex !important;
                align-items: center !important;
                justify-content: space-between !important;
                font-size: 11.5px !important;
                color: #94a3b8 !important;
            }}

            .sentinel-toast-body {{
                font-size: 13px !important;
                color: #e2e8f0 !important;
                line-height: 1.45 !important;
                background: rgba(0, 0, 0, 0.25) !important;
                padding: 8px 10px !important;
                border-radius: 6px !important;
                border: 1px solid rgba(255, 255, 255, 0.05) !important;
            }}

            .sentinel-toast-progress-bar {{
                position: absolute !important;
                bottom: 0 !important;
                left: 0 !important;
                height: 3px !important;
                background: rgba(255, 255, 255, 0.35) !important;
                width: 100% !important;
                animation: sentinelToastCountdown 6s linear forwards !important;
            }}

            @keyframes sentinelToastCountdown {{
                from {{ width: 100%; }}
                to {{ width: 0%; }}
            }}
        `;
        targetDoc.head.appendChild(style);
    }}

    // 2. Ensure container exists in target document
    let container = targetDoc.getElementById("sentinel-toast-container");
    if (!container) {{
        container = targetDoc.createElement("div");
        container.id = "sentinel-toast-container";
        targetDoc.body.appendChild(container);
    }}

    // Deduplication Set in window (bounded to prevent memory growth)
    window._sentinelDisplayedEvents = window._sentinelDisplayedEvents || new Set();
    if (window._sentinelDisplayedEvents.size > 200) {{
        const arr = Array.from(window._sentinelDisplayedEvents);
        window._sentinelDisplayedEvents = new Set(arr.slice(-100));
    }}

    // 3. Toast Display Function
    function renderToast(event) {{
        if (!event || !event.id) return;
        if (window._sentinelDisplayedEvents.has(event.id)) return;
        window._sentinelDisplayedEvents.add(event.id);

        const isCritical = (event.severity === "CRITICAL");
        const card = targetDoc.createElement("div");
        card.className = "sentinel-toast-card " + (isCritical ? "sentinel-toast-critical" : "sentinel-toast-warning");

        const icon = isCritical ? "🚨" : "⚠️";
        const badgeClass = isCritical ? "sentinel-badge-critical" : "sentinel-badge-warning";
        const msg = escapeHtml(event.message || "⚠️ Anomaly Detected! Unusual activity has been identified.");
        const typeStr = escapeHtml(event.type || "System Anomaly");
        const tsStr = escapeHtml(event.timestamp || "");
        const descStr = escapeHtml(event.description || `Unusual activity in '${{event.process || "Unknown"}}' (Score: ${{event.score}})`);
        const sevStr = escapeHtml(event.severity || "CRITICAL");

        card.innerHTML = `
            <div class="sentinel-toast-top">
                <div class="sentinel-toast-title-box">
                    <span>${{icon}}</span>
                    <span>${{msg}}</span>
                </div>
                <div style="display:flex; align-items:center; gap:6px;">
                    <span class="sentinel-toast-badge ${{badgeClass}}">${{sevStr}}</span>
                    <button class="sentinel-toast-close" title="Dismiss">&times;</button>
                </div>
            </div>
            <div class="sentinel-toast-meta">
                <span><strong>Type:</strong> ${{typeStr}}</span>
                <span>${{tsStr}}</span>
            </div>
            <div class="sentinel-toast-body">
                ${{descStr}}
            </div>
            <div class="sentinel-toast-progress-bar"></div>
        `;

        container.appendChild(card);

        // Slide in
        requestAnimationFrame(() => {{
            card.classList.add("visible");
        }});

        // Play audio chime if enabled
        if (ENABLE_SOUND) {{
            try {{
                const AudioCtx = window.AudioContext || window.webkitAudioContext;
                if (AudioCtx) {{
                    const ctx = new AudioCtx();
                    const osc = ctx.createOscillator();
                    const gain = ctx.createGain();
                    osc.type = 'triangle';
                    osc.frequency.setValueAtTime(440, ctx.currentTime);
                    osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.15);
                    gain.gain.setValueAtTime(0.2, ctx.currentTime);
                    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.4);
                    osc.connect(gain);
                    gain.connect(ctx.destination);
                    osc.start();
                    osc.stop(ctx.currentTime + 0.41);
                }}
            }} catch(e) {{}}
        }}

        // Browser Desktop Push Notification
        if (ENABLE_BROWSER_PUSH && ("Notification" in window)) {{
            try {{
                if (Notification.permission === "granted") {{
                    new Notification("🚨 AI Sentinel: Anomaly Detected!", {{
                        body: "Suspect Process: " + (event.process || "Unknown") + " | ML Score: " + (event.score !== undefined ? event.score : ""),
                        icon: "🛡️"
                    }});
                }} else if (Notification.permission === "default") {{
                    Notification.requestPermission();
                }}
            }} catch(e) {{}}
        }}

        let timer = null;
        const startTimer = () => {{
            timer = setTimeout(dismiss, 6000);
        }};

        const dismiss = () => {{
            clearTimeout(timer);
            card.classList.remove("visible");
            card.classList.add("dismissing");
            setTimeout(() => {{
                if (card.parentNode) {{
                    card.parentNode.removeChild(card);
                }}
            }}, 400);
        }};

        startTimer();

        // Close button click handler
        const closeBtn = card.querySelector(".sentinel-toast-close");
        if (closeBtn) {{
            closeBtn.addEventListener("click", (e) => {{
                e.stopPropagation();
                dismiss();
            }});
        }}

        // Hover pause
        card.addEventListener("mouseenter", () => {{
            clearTimeout(timer);
            const bar = card.querySelector(".sentinel-toast-progress-bar");
            if (bar) bar.style.animationPlayState = "paused";
        }});
        card.addEventListener("mouseleave", () => {{
            const bar = card.querySelector(".sentinel-toast-progress-bar");
            if (bar) bar.style.animationPlayState = "running";
            startTimer();
        }});
    }}

    // Direct event dispatch if provided
    if (DIRECT_EVENT) {{
        renderToast(DIRECT_EVENT);
    }}

    // 4. Connect persistent Server-Sent Events (SSE) listener
    if (!window._sentinelSseConnected && SSE_PORT > 0) {{
        window._sentinelSseConnected = true;
        const host = (window.location && window.location.hostname) ? window.location.hostname : "127.0.0.1";
        const sseUrl = "http://" + host + ":" + SSE_PORT + "/api/anomaly-events";

        function setupEventSource() {{
            try {{
                const es = new EventSource(sseUrl);
                es.onmessage = function(e) {{
                    try {{
                        const data = JSON.parse(e.data);
                        renderToast(data);
                    }} catch(err) {{
                        console.error("[Sentinel Toast] Failed to parse SSE event:", err);
                    }}
                }};
                es.onerror = function() {{
                    es.close();
                    setTimeout(setupEventSource, 4000);
                }};
            }} catch(err) {{
                setTimeout(setupEventSource, 6000);
            }}
        }}

        setupEventSource();
    }}

    window.sentinelTriggerToast = renderToast;
}})();
</script>
"""
