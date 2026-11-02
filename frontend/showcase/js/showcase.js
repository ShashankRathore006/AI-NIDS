/**
 * AI-NIDS // Applied Cybersecurity Engineering Showcase
 * Client-Side Technical Utilities & Interaction Logic
 * Swiss Editorial Design System
 */

(function () {
  'use strict';

  // Global configuration hook for deployment overrides
  window.AI_NIDS_CONFIG = window.AI_NIDS_CONFIG || {
    dashboardUrl: 'http://localhost:3000',
    apiBaseUrl: 'http://localhost:8000'
  };

  document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initBackendStatusBeacon();
    initCodeCopyButtons();
    initDashboardLinks();
  });

  /**
   * Mobile menu toggle with proper ARIA state management
   */
  function initNavigation() {
    const toggleBtn = document.querySelector('.nav-toggle');
    const menu = document.querySelector('.nav-menu');

    if (!toggleBtn || !menu) return;

    toggleBtn.addEventListener('click', () => {
      const isExpanded = toggleBtn.getAttribute('aria-expanded') === 'true';
      toggleBtn.setAttribute('aria-expanded', String(!isExpanded));
      menu.classList.toggle('open');
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
      if (!toggleBtn.contains(e.target) && !menu.contains(e.target) && menu.classList.contains('open')) {
        menu.classList.remove('open');
        toggleBtn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  /**
   * Configurable live backend status heartbeat
   * Non-blocking, passive check that sets beacon state
   */
  function initBackendStatusBeacon() {
    const beacon = document.querySelector('.live-beacon');
    if (!beacon) return;

    const apiBase = window.AI_NIDS_CONFIG.apiBaseUrl || 'http://localhost:8000';

    const checkBackend = async () => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 2000);
        const res = await fetch(`${apiBase}/`, {
          signal: controller.signal,
          mode: 'cors'
        });
        clearTimeout(timeout);

        if (res.ok) {
          beacon.style.backgroundColor = '#10B981';
          beacon.setAttribute('title', `FastAPI backend online at ${apiBase}`);
        } else {
          beacon.style.backgroundColor = '#84898F';
          beacon.setAttribute('title', 'FastAPI backend responding with error');
        }
      } catch {
        // Backend offline — gracefully mute indicator without console flooding
        beacon.style.backgroundColor = '#84898F';
        beacon.setAttribute('title', 'FastAPI backend offline (Click Live SOC to launch dashboard)');
      }
    };

    checkBackend();
    // Refresh heartbeat every 30 seconds
    setInterval(checkBackend, 30000);
  }

  /**
   * Intelligently sets the Live SOC Dashboard href based on runtime environment
   */
  function initDashboardLinks() {
    const dashboardUrl = window.AI_NIDS_CONFIG.dashboardUrl || 'http://localhost:3000';
    document.querySelectorAll('.dashboard-link, .btn-console').forEach((el) => {
      el.setAttribute('href', dashboardUrl);
    });
  }

  /**
   * Clipboard helper for technical reproduction snippets
   */
  function initCodeCopyButtons() {
    document.querySelectorAll('.btn-copy').forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const targetEl = document.getElementById(targetId);
        if (!targetEl) return;

        const codeText = targetEl.innerText.replace(/^\$\s*/gm, '');
        navigator.clipboard.writeText(codeText).then(() => {
          const originalText = btn.innerText;
          btn.innerText = 'COPIED';
          btn.style.color = 'var(--accent-blue)';
          btn.style.borderColor = 'var(--accent-blue)';
          setTimeout(() => {
            btn.innerText = originalText;
            btn.style.color = '';
            btn.style.borderColor = '';
          }, 2000);
        }).catch((err) => {
          console.error('Clipboard copy failed:', err);
        });
      });
    });
  }
})();
