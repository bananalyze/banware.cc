(async () => {
  try {
    const {
      assess,
      assessAndProtect
    } = await import(
      'https://esm.sh/@tindalabs/shield@latest'
    );


    const assessment = await assess({
      devtools: true,
      extensions: true,
      timeout: 600
    });

    const { risk, signals } = assessment;


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


    if (signals['shield.devtools.open']) {
      window.location.replace('https://www.google.com/');
      return;
    }

    const contentTarget =
      document.getElementById('productSelector') ||
      document.getElementById('site') ||
      document.body;

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
    if (signals['shield.extension.detected']) {
      console.log(
        '[Banware Shield] Suspicious extension detected.'
      );
    }
    console.log(
      '[Banware Shield] Session assessed.',
      {
        risk: risk.score,
        signals
      }
    );
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
