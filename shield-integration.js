(async () => {
    const {
        assess: e,
        assessAndProtect: t,
        ContentProtector: o
    } = await (import("https://esm.sh/@tindalabs/shield@latest")), n = await e({
        devtools: !0,
        extensions: !0,
        timeout: 600
    }), {
        risk: r,
        signals: s
    } = n;
    if (s["shield.frame.embedded"]) {
        try {
            window.top.location.href = window.location.href
        } catch (e) {
            document.documentElement.innerHTML = '<body style="background:#000;margin:0"></body>'
        }
        return
    }
    if (s["shield.devtools.open"]) {
        const e = document.createElement("div");
        e.id = "bw-devtools-notice", e.style.cssText = ["position:fixed", "bottom:16px", "right:16px", "z-index:9999", "background:rgba(255,255,255,0.04)", "border:1px solid rgba(255,255,255,0.08)", "border-radius:6px", "padding:10px 14px", "font-family:monospace", "font-size:11px", "color:rgba(255,255,255,0.35)", "letter-spacing:0.03em", "pointer-events:none", "backdrop-filter:blur(4px)"].join(";"), e.textContent = "session monitored", document.body.appendChild(e)
    }
    const a = document.getElementById("productSelector") || document.getElementById("site") || document.body,
        {
            assessment: i,
            protector: d
        } = await t(a, {
            assessOptions: {
                devtools: !1,
                extensions: !1
            },
            policies: [{
                when: {
                    riskScore: {
                        gte: .2
                    }
                },
                enable: ["enableWatermark"],
                watermarkOptions: e => ({
                    text: `BW-${Math.round(100*e.risk.score)}-${Date.now().toString(36).toUpperCase()}`,
                    opacity: .03,
                    fontSize: 13,
                    color: "rgba(255,255,255,0.03)",
                    angle: -28,
                    gap: [140, 80]
                })
            }, {
                when: {
                    riskScore: {
                        gte: .5
                    }
                },
                enable: ["preventSelection", "preventClipboard", "preventKeyboardShortcuts"]
            }, {
                when: {
                    riskScore: {
                        gte: .7
                    }
                },
                enable: ["preventScreenshots", "preventContextMenu"]
            }, {
                when: {
                    signals: {
                        "shield.automation.headless": !0
                    }
                },
                enable: ["enableWatermark", "preventSelection", "preventClipboard", "preventKeyboardShortcuts", "preventScreenshots", "preventContextMenu"],
                watermarkOptions: e => ({
                    text: `BW-HEADLESS-${Math.round(100*e.risk.score)}-${Date.now().toString(36).toUpperCase()}`,
                    opacity: .05,
                    fontSize: 14,
                    color: "rgba(255,255,255,0.05)",
                    angle: -28,
                    gap: [120, 70]
                })
            }, {
                when: {
                    signals: {
                        "shield.automation.webdriver": !0
                    }
                },
                enable: ["enableWatermark", "preventSelection", "preventClipboard", "preventKeyboardShortcuts", "preventScreenshots"],
                watermarkOptions: e => ({
                    text: `BW-WD-${Math.round(100*e.risk.score)}-${Date.now().toString(36).toUpperCase()}`,
                    opacity: .05,
                    fontSize: 14,
                    color: "rgba(255,255,255,0.05)",
                    angle: -28,
                    gap: [120, 70]
                })
            }]
        }),
        p = new o({
            preventDevTools: !0,
            preventPrinting: !0,
            preventKeyboardShortcuts: !1
        });
    p.protect(), s["shield.extension.detected"], window.__bwShield = {
        assessment: i,
        dispose: () => {
            d?.dispose(), p?.dispose()
        }
    }
})();
