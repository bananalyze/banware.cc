<script type="module">
(async () => {
  try {
    const {
      assess,
      assessAndProtect
    } = await import(
      'https://esm.sh/@tindalabs/shield@latest'
    );

    /*
     * BANWARE SHIELD
     *
     * Normal users:
     * - right click: allowed
     * - copy/paste: allowed
     * - text selection: allowed
     * - screenshots: allowed
     * - browser navigation: allowed
     *
     * Suspicious users:
     * - forensic watermark
     *
     * DevTools:
     * - redirect to Google
     */

    // ─────────────────────────────────────────────
    // 1. INITIAL ASSESSMENT
    // ─────────────────────────────────────────────

    const assessment = await assess({
      devtools: true,
      extensions: true,
      timeout: 600
    });

    const { risk, signals } = assessment;

    // ─────────────────────────────────────────────
    // 2. BLOCK IFRAME EMBEDDING
    // ─────────────────────────────────────────────

    if (signals['shield.frame.embedded']) {
      try {
        window.top.location.href = window.location.href;
      } catch {
        document.documentElement.innerHTML = `
          <body style="
            margin:0;
            background:#000;
          "></body>
        `;
      }

      return;
    }

    // ─────────────────────────────────────────────
    // 3. DEVTOOLS DETECTION
    // ─────────────────────────────────────────────

    if (signals['shield.devtools.open']) {
      window.location.replace('https://www.google.com/');
      return;
    }

    // ─────────────────────────────────────────────
    // 4. CONTENT TARGET
    // ─────────────────────────────────────────────

    const contentTarget =
      document.getElementById('productSelector') ||
      document.getElementById('site') ||
      document.body;

    // ─────────────────────────────────────────────
    // 5. RISK-BASED PROTECTION
    // ─────────────────────────────────────────────

    const {
      assessment: finalAssessment,
      protector
    } = await assessAndProtect(
      contentTarget,
      {
        // Don't run the detectors twice.
        assessOptions: {
          devtools: false,
          extensions: false
        },

        policies: [

          // Slightly suspicious:
          // only add a forensic watermark.
          {
            when: {
              riskScore: {
                gte: 0.2
              }
            },

            enable: [
              'enableWatermark'
            ],

            watermarkOptions: a => ({
              text:
                `BW-${Math.round(a.risk.score * 100)}-${Date.now()
                  .toString(36)
                  .toUpperCase()}`,

              opacity: 0.025,
              fontSize: 13,
              color: 'rgba(255,255,255,0.025)',
              angle: -28,
              gap: [140, 80]
            })
          },

          // Headless browsers:
          // watermark only.
          //
          // We deliberately DON'T block:
          // - copying
          // - selection
          // - screenshots
          // - right click
          // - keyboard
          {
            when: {
              signals: {
                'shield.automation.headless': true
              }
            },

            enable: [
              'enableWatermark'
            ],

            watermarkOptions: a => ({
              text:
                `BW-HEADLESS-${Math.round(a.risk.score * 100)}-${Date.now()
                  .toString(36)
                  .toUpperCase()}`,

              opacity: 0.04,
              fontSize: 14,
              color: 'rgba(255,255,255,0.04)',
              angle: -28,
              gap: [120, 70]
            })
          },

          // WebDriver / Selenium:
          // watermark only.
          {
            when: {
              signals: {
                'shield.automation.webdriver': true
              }
            },

            enable: [
              'enableWatermark'
            ],

            watermarkOptions: a => ({
              text:
                `BW-WD-${Math.round(a.risk.score * 100)}-${Date.now()
                  .toString(36)
                  .toUpperCase()}`,

              opacity: 0.04,
              fontSize: 14,
              color: 'rgba(255,255,255,0.04)',
              angle: -28,
              gap: [120, 70]
            })
          }
        ]
      }
    );

    // ─────────────────────────────────────────────
    // 6. EXTENSION DETECTION
    // ─────────────────────────────────────────────

    if (signals['shield.extension.detected']) {
      console.log(
        '[Banware Shield] Suspicious extension detected.'
      );
    }

    // ─────────────────────────────────────────────
    // 7. OPTIONAL DEBUG INFO
    // ─────────────────────────────────────────────

    console.log(
      '[Banware Shield] Session assessed.',
      {
        risk: risk.score,
        signals
      }
    );

    // ─────────────────────────────────────────────
    // 8. GLOBAL HANDLE
    // ─────────────────────────────────────────────

    window.__bwShield = {
      assessment: finalAssessment,

      dispose: () => {
        protector?.dispose();
      }
    };

  } catch (error) {
    // Don't break the website if Shield fails to load.
    console.warn(
      '[Banware Shield] Failed to initialize:',
      error
    );
  }
})();
</script>
