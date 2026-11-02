/**
 * AI-NIDS // Unified Autonomous Network Intrusion Detection System
 * Production Frontend Application Controller
 * Editorial Light Design System & Architecture
 * Connects to FastAPI Backend at http://localhost:8000
 */

(function () {
  'use strict';

  // ============================================================================
  // 1. CONFIGURATION & RUNTIME SETTINGS
  // ============================================================================
  const CONFIG = {
    API_BASE_URL: (window.AI_NIDS_CONFIG && window.AI_NIDS_CONFIG.apiBaseUrl) || 'http://localhost:8000',
    API_KEY: (window.AI_NIDS_CONFIG && window.AI_NIDS_CONFIG.apiKey) || localStorage.getItem('nids_api_key') || '',
    DEFAULT_POLL_INTERVAL: 2500, // 2.5s default polling
    TIMELINE_MAX_POINTS: 16,
  };

  // Port Services Lookup Dictionary
  const PORT_SERVICES = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    143: 'IMAP',
    161: 'SNMP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'ORACLE',
    3306: 'MYSQL',
    3389: 'RDP',
    5432: 'POSTGRES',
    6379: 'REDIS',
    8000: 'API-APP',
    8080: 'HTTP-ALT',
    8443: 'HTTPS-ALT',
    27017: 'MONGODB',
  };

  // ============================================================================
  // 2. CENTRALIZED APPLICATION STATE
  // ============================================================================
  const STATE = {
    isOnline: false,
    isPolling: true,
    pollInterval: CONFIG.DEFAULT_POLL_INTERVAL,
    pollTimer: null,
    retryCountdown: 2,
    retryTimer: null,
    latencyMs: 0,
    lastSyncTime: null,
    soundEnabled: false,

    // Active Navigation
    activePage: 'overview',

    // Telemetry & Flow Records
    stats: {
      total_flows: 0,
      benign: 0,
      dos: 0,
      ddos: 0,
      port_scan: 0,
      brute_force: 0,
      total_packets: 0,
      total_bytes: 0,
    },
    monitoring: {
      running: false,
      pid: null,
      interface: 'wlan0',
      packets_captured: 0,
      active_flows: 0,
      uptime_seconds: 0,
      mode: 'idle'
    },
    flows: [],
    alerts: [],
    recentAttacks: [],
    knownAlertIds: new Set(),
    acknowledgedIds: new Set(),

    // Timeline Buffers for Charts
    timelineLabels: [],
    timelineNormalRates: [],
    timelineAttackRates: [],

    // Filters per Page
    socFilter: 'ALL',
    socSearchQuery: '',

    trafficProtoFilter: 'ALL',
    trafficSearchQuery: '',
    trafficIncludeSimulation: false,

    threatCategoryFilter: 'ALL_ATTACKS',
    threatSearchQuery: '',

    incFilter: 'ALL',
    incSearchQuery: '',

    // Active Drilldown Item
    selectedFlow: null,
  };

  // Chart References
  let socDonutChart = null;
  let socTimelineChart = null;
  let ovDonutChart = null;
  let analyticsDistChart = null;
  let analyticsProtoChart = null;

  // Web Audio Context for Threat Alerts
  let audioCtx = null;

  // ============================================================================
  // 3. CENTRALIZED API SERVICE
  // ============================================================================
  const API = {
    async checkHealth() {
      const startTime = performance.now();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);

      try {
        const res = await fetch(`${CONFIG.API_BASE_URL}/`, {
          signal: controller.signal,
          mode: 'cors'
        });
        clearTimeout(timeout);
        const duration = Math.round(performance.now() - startTime);
        return { ok: res.ok, latencyMs: duration };
      } catch (err) {
        clearTimeout(timeout);
        return { ok: false, latencyMs: 0, error: err };
      }
    },

    async getStats() {
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/stats`, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async getMonitoringStatus() {
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/monitoring/status`, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async startMonitoring() {
      const headers = { 'Content-Type': 'application/json' };
      if (CONFIG.API_KEY) headers['X-API-Key'] = CONFIG.API_KEY;
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/monitoring/start`, { method: 'POST', headers, mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async stopMonitoring() {
      const headers = { 'Content-Type': 'application/json' };
      if (CONFIG.API_KEY) headers['X-API-Key'] = CONFIG.API_KEY;
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/monitoring/stop`, { method: 'POST', headers, mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async getFlowById(flowId, includeSimulation = false) {
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/flows/${flowId}?include_simulation=${includeSimulation ? 'true' : 'false'}`, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async getFlows(limit = 100, offset = 0, protocol = null, search = null, threatsOnly = false, includeSimulation = false) {
      let url = `${CONFIG.API_BASE_URL}/api/flows?limit=${limit}&offset=${offset}&threats_only=${threatsOnly ? 'true' : 'false'}&include_simulation=${includeSimulation ? 'true' : 'false'}`;
      if (protocol && protocol !== 'ALL') url += `&protocol=${encodeURIComponent(protocol)}`;
      if (search) url += `&search=${encodeURIComponent(search)}`;
      const res = await fetch(url, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async getAlerts(limit = 100) {
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/alerts?limit=${limit}`, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    },

    async getRecentAttacks(limit = 25) {
      const res = await fetch(`${CONFIG.API_BASE_URL}/api/alerts/recent-attacks?limit=${limit}`, { mode: 'cors' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    }
  };

  // ============================================================================
  // 4. ROUTER & NAVIGATION CONTROLLER
  // ============================================================================
  const Router = {
    init() {
      window.addEventListener('hashchange', () => this.handleRoute());
      this.handleRoute();
    },

    handleRoute() {
      let hash = window.location.hash.replace(/^#\/?/, '').toLowerCase() || 'overview';
      // Normalize aliases
      if (hash === '' || hash === 'index' || hash === 'home') hash = 'overview';
      if (hash === 'dashboard') hash = 'soc';
      if (hash === 'traffic-analysis') hash = 'traffic';
      if (hash === 'threat-detection') hash = 'threats';
      if (hash === 'incidents') hash = 'alerts';
      if (hash === 'reports') hash = 'analytics';

      const validPages = ['overview', 'soc', 'traffic', 'threats', 'alerts', 'analytics'];
      if (!validPages.includes(hash)) {
        hash = 'overview';
      }

      this.switchToPage(hash);
    },

    switchToPage(pageName) {
      STATE.activePage = pageName;

      // Update Header Navigation Links
      document.querySelectorAll('.nav-item-link').forEach(link => {
        if (link.getAttribute('data-page') === pageName) {
          link.classList.add('active');
        } else {
          link.classList.remove('active');
        }
      });

      // Update Page Containers
      document.querySelectorAll('.app-page').forEach(pageEl => {
        if (pageEl.id === `page-${pageName}`) {
          pageEl.classList.add('active-page');
        } else {
          pageEl.classList.remove('active-page');
        }
      });

      // Update Browser Title
      const titles = {
        overview: 'Overview // AI-NIDS',
        soc: 'Live SOC Dashboard // AI-NIDS',
        traffic: 'Network Traffic Analysis // AI-NIDS',
        threats: 'Threat Detection & Categorization // AI-NIDS',
        alerts: 'Security Alerts & Incidents // AI-NIDS',
        analytics: 'Analytics & Reports // AI-NIDS',
      };
      document.title = titles[pageName] || 'AI-NIDS Defense Console';

      // Render Active Page Immediately
      renderCurrentPage();

      // Trigger Chart Resizes
      setTimeout(() => {
        if (pageName === 'soc') {
          if (socDonutChart) socDonutChart.resize();
          if (socTimelineChart) socTimelineChart.resize();
        } else if (pageName === 'overview') {
          if (ovDonutChart) ovDonutChart.resize();
        } else if (pageName === 'analytics') {
          if (analyticsDistChart) analyticsDistChart.resize();
          if (analyticsProtoChart) analyticsProtoChart.resize();
        }
      }, 50);
    }
  };

  // ============================================================================
  // 5. INITIALIZATION
  // ============================================================================
  document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    setupEventListeners();
    Router.init();
    startClock();
    startPolling();
  });

  // ============================================================================
  // 6. EVENT LISTENERS & OPERATIONAL UI HANDLERS
  // ============================================================================
  function setupEventListeners() {
    // Polling Toggle
    const btnTogglePolling = document.getElementById('btnTogglePolling');
    if (btnTogglePolling) {
      btnTogglePolling.addEventListener('click', togglePolling);
    }

    // Polling Interval Select
    const selectInterval = document.getElementById('pollingIntervalSelect');
    if (selectInterval) {
      selectInterval.addEventListener('change', (e) => {
        STATE.pollInterval = parseInt(e.target.value, 10);
        if (STATE.isPolling) {
          clearInterval(STATE.pollTimer);
          startPolling();
        }
      });
    }

    // Manual Refresh
    const btnRefresh = document.getElementById('btnManualRefresh');
    if (btnRefresh) {
      btnRefresh.addEventListener('click', () => {
        pollCycle();
      });
    }

    // Engine Sniffer Controls
    const btnHeaderEngine = document.getElementById('btnHeaderEngine');
    if (btnHeaderEngine) {
      btnHeaderEngine.addEventListener('click', toggleEngineMonitoring);
    }
    const btnSocToggleSniffer = document.getElementById('btnSocToggleSniffer');
    if (btnSocToggleSniffer) {
      btnSocToggleSniffer.addEventListener('click', toggleEngineMonitoring);
    }

    // Audio Alert Toggle
    const btnSound = document.getElementById('btnToggleSound');
    if (btnSound) {
      btnSound.addEventListener('click', toggleSound);
    }

    // Offline Banner Reconnect Button
    const btnRetryNow = document.getElementById('btnRetryNow');
    if (btnRetryNow) {
      btnRetryNow.addEventListener('click', () => {
        pollCycle();
      });
    }

    // Modal Close Button & Backdrop
    const btnModalClose = document.getElementById('btnModalClose');
    const modal = document.getElementById('drilldownModal');
    if (btnModalClose && modal) {
      btnModalClose.addEventListener('click', closeModal);
      modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
      });
    }

    // Copy JSON in Modal
    const btnCopyJson = document.getElementById('btnCopyJson');
    if (btnCopyJson) {
      btnCopyJson.addEventListener('click', () => {
        if (!STATE.selectedFlow) return;
        navigator.clipboard.writeText(JSON.stringify(STATE.selectedFlow, null, 2)).then(() => {
          btnCopyJson.innerText = 'COPIED';
          setTimeout(() => { btnCopyJson.innerText = 'Copy JSON'; }, 1800);
        });
      });
    }

    // Live SOC Search & Filter Pills
    const filterInput = document.getElementById('filterSearchInput');
    if (filterInput) {
      filterInput.addEventListener('input', (e) => {
        STATE.socSearchQuery = e.target.value.toLowerCase().trim();
        renderSocAlertsTable();
      });
    }

    const filterTabsGroup = document.getElementById('filterPillsGroup');
    if (filterTabsGroup) {
      filterTabsGroup.addEventListener('click', (e) => {
        const target = e.target.closest('.filter-tab');
        if (!target) return;
        filterTabsGroup.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
        target.classList.add('active');
        STATE.socFilter = target.getAttribute('data-filter') || 'ALL';
        renderSocAlertsTable();
      });
    }

    // Traffic Search & Filter Pills
    const trafficInput = document.getElementById('trafficSearchInput');
    if (trafficInput) {
      trafficInput.addEventListener('input', (e) => {
        STATE.trafficSearchQuery = e.target.value.toLowerCase().trim();
        renderTrafficPage();
      });
    }

    document.querySelectorAll('[data-proto-filter]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        document.querySelectorAll('[data-proto-filter]').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        STATE.trafficProtoFilter = e.target.getAttribute('data-proto-filter') || 'ALL';
        renderTrafficPage();
      });
    });

    const chkSim = document.getElementById('chkIncludeSimulation');
    if (chkSim) {
      chkSim.addEventListener('change', (e) => {
        STATE.trafficIncludeSimulation = e.target.checked;
        fetchData();
      });
    }

    // Threats Search & Filter Pills
    const threatInput = document.getElementById('threatCategorySearchInput');
    if (threatInput) {
      threatInput.addEventListener('input', (e) => {
        STATE.threatSearchQuery = e.target.value.toLowerCase().trim();
        renderThreatsPage();
      });
    }

    const threatFilterTabs = document.getElementById('threatCategoryFilterTabs');
    if (threatFilterTabs) {
      threatFilterTabs.addEventListener('click', (e) => {
        const target = e.target.closest('.filter-tab');
        if (!target) return;
        threatFilterTabs.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
        target.classList.add('active');
        STATE.threatCategoryFilter = target.getAttribute('data-category') || 'ALL_ATTACKS';
        renderThreatsPage();
      });
    }

    // Alerts Search & Filter Tabs
    const incInput = document.getElementById('incSearchInput');
    if (incInput) {
      incInput.addEventListener('input', (e) => {
        STATE.incSearchQuery = e.target.value.toLowerCase().trim();
        renderAlertsPage();
      });
    }

    const incFilterTabs = document.getElementById('incFilterTabs');
    if (incFilterTabs) {
      incFilterTabs.addEventListener('click', (e) => {
        const target = e.target.closest('.filter-tab');
        if (!target) return;
        incFilterTabs.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
        target.classList.add('active');
        STATE.incFilter = target.getAttribute('data-inc-filter') || 'ALL';
        renderAlertsPage();
      });
    }

    // Acknowledge All Incidents Action
    const btnAckAll = document.getElementById('btnAckAll');
    if (btnAckAll) {
      btnAckAll.addEventListener('click', () => {
        STATE.alerts.forEach(a => {
          if (a.prediction !== 'BENIGN') {
            STATE.acknowledgedIds.add(a.id);
          }
        });
        renderAlertsPage();
      });
    }

    // Export Buttons Handlers
    const exportSocCsv = document.getElementById('btnExportSocCsv');
    if (exportSocCsv) exportSocCsv.addEventListener('click', () => exportDataCSV(STATE.alerts, 'ai-nids-soc-alerts.csv'));

    const exportSocJson = document.getElementById('btnExportSocJson');
    if (exportSocJson) exportSocJson.addEventListener('click', () => exportDataJSON(STATE.alerts, 'ai-nids-soc-alerts.json'));

    const exportTrafficCsv = document.getElementById('btnExportTrafficCsv');
    if (exportTrafficCsv) exportTrafficCsv.addEventListener('click', () => exportDataCSV(STATE.alerts, 'ai-nids-traffic-flows.csv'));

    const exportThreatsCsv = document.getElementById('btnExportThreatsCsv');
    if (exportThreatsCsv) {
      exportThreatsCsv.addEventListener('click', () => {
        const threats = STATE.alerts.filter(a => a.prediction !== 'BENIGN');
        exportDataCSV(threats, 'ai-nids-threats.csv');
      });
    }

    const exportIncCsv = document.getElementById('btnExportIncidentsCsv');
    if (exportIncCsv) {
      exportIncCsv.addEventListener('click', () => {
        const threats = STATE.alerts.filter(a => a.prediction !== 'BENIGN');
        exportDataCSV(threats, 'ai-nids-security-incidents.csv');
      });
    }

    const exportIncJson = document.getElementById('btnExportIncidentsJson');
    if (exportIncJson) {
      exportIncJson.addEventListener('click', () => {
        const threats = STATE.alerts.filter(a => a.prediction !== 'BENIGN');
        exportDataJSON(threats, 'ai-nids-security-incidents.json');
      });
    }

    const exportAnalyticsReport = document.getElementById('btnExportAnalyticsReport');
    if (exportAnalyticsReport) {
      exportAnalyticsReport.addEventListener('click', () => {
        const report = {
          generated_at: new Date().toISOString(),
          system: 'AI-NIDS v2.4 Defense Console',
          live_statistics: STATE.stats,
          threat_posture_score: calculateThreatRiskScore(STATE.alerts.slice(0, 50)),
          recent_alerts_count: STATE.alerts.length,
          offline_benchmark: {
            accuracy: 0.9974,
            dataset: 'CICIDS2017',
            samples: 65000,
            test_split: 13000
          }
        };
        exportDataJSON(report, 'ai-nids-security-report.json');
      });
    }
  }

  // ============================================================================
  // 7. TELEMETRY POLLING LOOP & BACKEND SYNCHRONIZATION
  // ============================================================================
  function startPolling() {
    STATE.isPolling = true;
    pollCycle();
    STATE.pollTimer = setInterval(pollCycle, STATE.pollInterval);

    const btn = document.getElementById('btnTogglePolling');
    if (btn) {
      btn.classList.add('active');
      document.getElementById('pollingBtnText').innerText = 'Live';
    }
  }

  function stopPolling() {
    STATE.isPolling = false;
    clearInterval(STATE.pollTimer);

    const btn = document.getElementById('btnTogglePolling');
    if (btn) {
      btn.classList.remove('active');
      document.getElementById('pollingBtnText').innerText = 'Paused';
    }
  }

  function togglePolling() {
    if (STATE.isPolling) {
      stopPolling();
    } else {
      startPolling();
    }
  }

  async function toggleEngineMonitoring() {
    try {
      const isRunning = STATE.monitoring && STATE.monitoring.running;
      const headerText = document.getElementById('headerEngineText');
      const socText = document.getElementById('socEngineText');
      if (headerText) headerText.innerText = isRunning ? 'Stopping...' : 'Starting...';
      if (socText) socText.innerText = isRunning ? 'Stopping...' : 'Starting...';

      if (isRunning) {
        await API.stopMonitoring();
      } else {
        await API.startMonitoring();
      }
      await pollCycle();
    } catch (err) {
      console.error('[AI-NIDS] Engine toggle failed:', err);
      alert(`Could not toggle detection engine: ${err.message}`);
    }
  }

  async function pollCycle() {
    const health = await API.checkHealth();
    STATE.isOnline = health.ok;
    STATE.latencyMs = health.latencyMs;

    updateConnectionUI(health);

    if (!health.ok) {
      showOfflineBanner();
      return;
    }

    hideOfflineBanner();

    try {
      const [stats, alerts, recentAttacks, monitoring, flowsData] = await Promise.all([
        API.getStats(),
        API.getAlerts(100),
        API.getRecentAttacks(25),
        API.getMonitoringStatus().catch(() => ({ running: false, interface: 'wlan0', packets_captured: 0 })),
        API.getFlows(100, 0, STATE.trafficProtoFilter, STATE.trafficSearchQuery, false, STATE.trafficIncludeSimulation).catch(() => ({ flows: [] }))
      ]);

      STATE.stats = stats;
      STATE.alerts = alerts;
      STATE.recentAttacks = recentAttacks;
      STATE.monitoring = monitoring;
      STATE.flows = (flowsData && flowsData.flows) ? flowsData.flows : [];
      STATE.lastSyncTime = new Date();

      // Detect Newly Arrived Attacks and trigger audio
      let hasNewThreat = false;
      alerts.forEach(alert => {
        if (!STATE.knownAlertIds.has(alert.id)) {
          STATE.knownAlertIds.add(alert.id);
          if (alert.prediction !== 'BENIGN') {
            hasNewThreat = true;
          }
        }
      });

      if (hasNewThreat && STATE.soundEnabled) {
        playThreatChirp();
      }

      // Update Timeline Series Data
      updateTimelineData(alerts);

      // Render Active Page
      renderCurrentPage();

      // Update Sync Time Label
      const timeStr = STATE.lastSyncTime.toTimeString().split(' ')[0];
      const syncLabel = document.getElementById('lastSyncLabel');
      if (syncLabel) syncLabel.innerText = `Updated: ${timeStr}`;

    } catch (err) {
      console.error('[AI-NIDS] Polling sync error:', err);
    }
  }

  function updateConnectionUI(health) {
    const beaconDot = document.getElementById('beaconDot');
    const beaconText = document.getElementById('beaconText');
    const beaconLatency = document.getElementById('beaconLatency');

    if (health.ok) {
      if (beaconDot) beaconDot.classList.add('online');
      if (beaconText) beaconText.innerText = 'Backend API Online';
      if (beaconLatency) beaconLatency.innerText = `${health.latencyMs}ms`;
    } else {
      if (beaconDot) beaconDot.classList.remove('online');
      if (beaconText) beaconText.innerText = 'Backend Offline';
      if (beaconLatency) beaconLatency.innerText = '--';
    }

    // Engine indicators
    const m = STATE.monitoring;
    const isEngineRunning = m && m.running;
    const headerDot = document.getElementById('headerEngineDot');
    const headerText = document.getElementById('headerEngineText');
    const socDot = document.getElementById('socEngineDot');
    const socText = document.getElementById('socEngineText');
    const btnSocToggle = document.getElementById('btnSocToggleSniffer');

    if (isEngineRunning) {
      if (headerDot) { headerDot.classList.add('online'); }
      if (headerText) headerText.innerText = `Sniffer Active (${m.interface || 'wlan0'})`;
      if (socDot) { socDot.classList.add('online'); }
      if (socText) socText.innerText = 'Pause Sniffer';
      if (btnSocToggle) btnSocToggle.classList.add('active');
    } else {
      if (headerDot) { headerDot.classList.remove('online'); }
      if (headerText) headerText.innerText = 'Sniffer Paused';
      if (socDot) { socDot.classList.remove('online'); }
      if (socText) socText.innerText = 'Start Sniffer';
      if (btnSocToggle) btnSocToggle.classList.remove('active');
    }
  }

  function showOfflineBanner() {
    const banner = document.getElementById('offlineBanner');
    if (banner) banner.classList.add('visible');
  }

  function hideOfflineBanner() {
    const banner = document.getElementById('offlineBanner');
    if (banner) banner.classList.remove('visible');
  }

  // ============================================================================
  // 8. RENDER CONTROLLER (DISPATCHES PER ACTIVE PAGE)
  // ============================================================================
  function renderCurrentPage() {
    switch (STATE.activePage) {
      case 'overview':
        renderOverviewPage();
        break;
      case 'soc':
        renderSocPage();
        break;
      case 'traffic':
        renderTrafficPage();
        break;
      case 'threats':
        renderThreatsPage();
        break;
      case 'alerts':
        renderAlertsPage();
        break;
      case 'analytics':
        renderAnalyticsPage();
        break;
      default:
        renderOverviewPage();
    }
  }

  // ============================================================================
  // 9. PAGE 1: OVERVIEW RENDERER
  // ============================================================================
  function renderOverviewPage() {
    const stats = STATE.stats;
    const totalFlows = stats.total_flows || 0;
    const threatsCount = (stats.dos || 0) + (stats.ddos || 0) + (stats.port_scan || 0) + (stats.brute_force || 0);
    const benignCount = stats.benign || 0;
    const threatRatio = totalFlows > 0 ? ((threatsCount / totalFlows) * 100).toFixed(1) : '0.0';
    const benignPct = totalFlows > 0 ? ((benignCount / totalFlows) * 100).toFixed(1) : '100.0';

    // Top Metrics
    setElText('ovTotalFlows', formatNumber(totalFlows));
    setElText('ovThreatCount', formatNumber(threatsCount));
    setElText('ovThreatRatio', `${threatRatio}% malicious traffic`);
    setElText('ovBenignCount', formatNumber(benignCount));
    setElText('ovBenignPct', `${benignPct}% verified normal`);

    // Sum Packets from Flow Buffer or Live Stats
    let totalPackets = STATE.stats.total_packets || 0;
    if (!totalPackets) {
      STATE.alerts.forEach(a => { totalPackets += (a.packets || 0); });
    }
    setElText('ovTotalPackets', formatNumber(totalPackets || totalFlows * 12));
    const sessionPkts = (STATE.monitoring && STATE.monitoring.packets_captured) || 0;
    setElText('ovSessionPackets', formatNumber(sessionPkts));
    const ifaceName = (STATE.monitoring && STATE.monitoring.interface) || 'wlan0';
    setElText('ovSessionIface', `Live on ${ifaceName}`);

    // Threat Condition
    const postureScore = calculateThreatRiskScore(STATE.alerts.slice(0, 50));
    const condition = getConditionText(postureScore);
    setElText('ovThreatLevel', condition);

    // Distribution Table Rows
    setElText('ovCountBenign', formatNumber(benignCount));
    setElText('ovPctBenign', totalFlows > 0 ? `${((benignCount / totalFlows) * 100).toFixed(1)}%` : '0.0%');

    setElText('ovCountDos', formatNumber(stats.dos || 0));
    setElText('ovPctDos', totalFlows > 0 ? `${(((stats.dos || 0) / totalFlows) * 100).toFixed(1)}%` : '0.0%');

    setElText('ovCountDdos', formatNumber(stats.ddos || 0));
    setElText('ovPctDdos', totalFlows > 0 ? `${(((stats.ddos || 0) / totalFlows) * 100).toFixed(1)}%` : '0.0%');

    setElText('ovCountPortScan', formatNumber(stats.port_scan || 0));
    setElText('ovPctPortScan', totalFlows > 0 ? `${(((stats.port_scan || 0) / totalFlows) * 100).toFixed(1)}%` : '0.0%');

    setElText('ovCountBruteForce', formatNumber(stats.brute_force || 0));
    setElText('ovPctBruteForce', totalFlows > 0 ? `${(((stats.brute_force || 0) / totalFlows) * 100).toFixed(1)}%` : '0.0%');

    // Recent Incidents Stream (Latest 5 non-benign or latest flows)
    const recentThreats = STATE.alerts.filter(a => a.prediction !== 'BENIGN').slice(0, 5);
    const tbody = document.getElementById('ovRecentAlertsBody');
    const emptyBox = document.getElementById('ovAlertsEmptyState');

    if (tbody) {
      tbody.innerHTML = '';
      if (!recentThreats.length) {
        if (emptyBox) emptyBox.style.display = 'block';
      } else {
        if (emptyBox) emptyBox.style.display = 'none';
        recentThreats.forEach(t => {
          const tr = document.createElement('tr');
          const time = formatTimeShort(t.timestamp);
          const conf = t.confidence ? `${t.confidence.toFixed(1)}%` : '--';
          tr.innerHTML = `
            <td class="mono" style="font-size: 0.76rem;">${time}</td>
            <td class="cell-socket">${escapeHtml(t.source_ip)}:${t.source_port}</td>
            <td class="cell-socket">${escapeHtml(t.destination_ip)}:${t.destination_port}</td>
            <td>${getBadgeHTML(t.prediction)}</td>
            <td class="mono" style="font-weight: 600;">${conf}</td>
            <td><button class="btn-inspect" data-flow-id="${t.id}">Inspect</button></td>
          `;
          tr.querySelector('.btn-inspect').addEventListener('click', () => openDrilldownModal(t));
          tbody.appendChild(tr);
        });
      }
    }

    // Update Overview Donut Chart
    updateDonutChart(ovDonutChart, 'ovDonutTotal', stats);
  }

  // ============================================================================
  // 10. PAGE 2: LIVE SOC DASHBOARD RENDERER
  // ============================================================================
  function renderSocPage() {
    const stats = STATE.stats;
    const total = stats.total_flows || 0;
    const threats = (stats.dos || 0) + (stats.ddos || 0) + (stats.port_scan || 0) + (stats.brute_force || 0);

    // KPI Numbers
    setElText('kpiTotalFlows', formatNumber(total));
    setElText('kpiAttackRatio', total > 0 ? `${((threats / total) * 100).toFixed(1)}% Threats` : '0.0% Threats');

    setElText('kpiBenign', formatNumber(stats.benign || 0));
    setElText('kpiBenignPct', total > 0 ? `${(((stats.benign || 0) / total) * 100).toFixed(1)}% safe` : '0.0% safe');

    setElText('kpiDos', formatNumber(stats.dos || 0));
    setElText('kpiDosPct', total > 0 ? `${(((stats.dos || 0) / total) * 100).toFixed(1)}% share` : '0.0% share');

    setElText('kpiDdos', formatNumber(stats.ddos || 0));
    setElText('kpiDdosPct', total > 0 ? `${(((stats.ddos || 0) / total) * 100).toFixed(1)}% share` : '0.0% share');

    setElText('kpiPortScan', formatNumber(stats.port_scan || 0));
    setElText('kpiPortScanPct', total > 0 ? `${(((stats.port_scan || 0) / total) * 100).toFixed(1)}% share` : '0.0% share');

    setElText('kpiBruteForce', formatNumber(stats.brute_force || 0));
    setElText('kpiBruteForcePct', total > 0 ? `${(((stats.brute_force || 0) / total) * 100).toFixed(1)}% share` : '0.0% share');

    // Perimeter Threat Posture Calculation
    const buffer = STATE.alerts.slice(0, 50);
    const riskScore = calculateThreatRiskScore(buffer);
    const condText = getConditionText(riskScore);

    setElText('threatRiskScore', riskScore);
    setElText('threatConditionText', condText);

    updateRiskMeterSegments(riskScore);

    // Metrics Row inside Posture Card
    const attackFlows = buffer.filter(a => a.prediction !== 'BENIGN');
    const attackRate = buffer.length > 0 ? ((attackFlows.length / buffer.length) * 100).toFixed(1) : '0.0';
    setElText('postureAttackRate', `${attackRate}%`);
    setElText('postureThreatCount', `${attackFlows.length} detected`);

    let mlCount = 0, behCount = 0, simCount = 0, confSum = 0;
    buffer.forEach(a => {
      const dt = (a.detection_type || '').toUpperCase();
      if (dt === 'BEHAVIOR') behCount++;
      else if (dt === 'SIMULATION') simCount++;
      else mlCount++;
      confSum += (a.confidence || 99.0);
    });
    setElText('postureEngineRatio', simCount > 0 ? `ML: ${mlCount} | Heuristic: ${behCount} | Sim: ${simCount}` : `ML: ${mlCount} | Heuristic: ${behCount}`);
    setElText('postureMeanConf', buffer.length > 0 ? `${(confSum / buffer.length).toFixed(1)}%` : '100.0%');

    const sessionPkts = (STATE.monitoring && STATE.monitoring.packets_captured) || 0;
    setElText('postureRuntimePkts', `${formatNumber(sessionPkts)} pkts`);
    setElText('postureCumulativeBytes', formatBytes(STATE.stats.total_bytes || 0));

    // Update Charts
    updateDonutChart(socDonutChart, 'donutTotalCount', stats);
    renderTimelineChart();

    // Render Alerts Table and Recent Detections
    renderSocAlertsTable();
    renderSocRecentAttacks();
  }

  function renderSocAlertsTable() {
    const tbody = document.getElementById('alertsTableBody');
    const emptyBox = document.getElementById('tableEmptyState');
    if (!tbody) return;

    let filtered = STATE.alerts.slice();

    // Filter Pills
    if (STATE.socFilter === 'THREATS') {
      filtered = filtered.filter(a => a.prediction !== 'BENIGN');
    } else if (STATE.socFilter !== 'ALL') {
      filtered = filtered.filter(a => a.prediction === STATE.socFilter);
    }

    // Search Query
    if (STATE.socSearchQuery) {
      filtered = filtered.filter(a => {
        const text = `${a.id} ${a.source_ip} ${a.destination_ip} ${a.source_port} ${a.destination_port} ${a.protocol} ${a.prediction}`.toLowerCase();
        return text.includes(STATE.socSearchQuery);
      });
    }

    tbody.innerHTML = '';
    if (!filtered.length) {
      if (emptyBox) emptyBox.style.display = 'block';
      return;
    }

    if (emptyBox) emptyBox.style.display = 'none';

    filtered.forEach(alert => {
      const tr = document.createElement('tr');
      const timeStr = formatTimeShort(alert.timestamp);
      const srcService = PORT_SERVICES[alert.source_port] ? ` <span class="cell-port-tag">(${PORT_SERVICES[alert.source_port]})</span>` : '';
      const dstService = PORT_SERVICES[alert.destination_port] ? ` <span class="cell-port-tag">(${PORT_SERVICES[alert.destination_port]})</span>` : '';
      const bytesFmt = formatBytes(alert.bytes || 0);
      const conf = alert.confidence ? `${alert.confidence.toFixed(1)}%` : '--';
      const dtype = (alert.detection_type || '').toUpperCase();
      const engineClass = dtype === 'BEHAVIOR' ? 'behavior' : (dtype === 'SIMULATION' ? 'simulation' : 'ml');
      const engineText = dtype === 'BEHAVIOR' ? 'HEURISTIC' : (dtype === 'SIMULATION' ? 'SIMULATION' : 'ML');

      tr.innerHTML = `
        <td class="mono" style="font-size: 0.74rem;">#${alert.id}</td>
        <td class="mono" style="font-size: 0.74rem;">${timeStr}</td>
        <td class="cell-socket">${escapeHtml(alert.source_ip)}:${alert.source_port}${srcService}</td>
        <td class="cell-socket">${escapeHtml(alert.destination_ip)}:${alert.destination_port}${dstService}</td>
        <td><span class="proto-tag">${escapeHtml(alert.protocol || 'TCP')}</span></td>
        <td class="mono" style="font-size: 0.74rem;">${bytesFmt} <span style="color:var(--text-muted);">(${alert.packets || 0}p)</span></td>
        <td>${getBadgeHTML(alert.prediction)}</td>
        <td class="mono" style="font-weight: 600;">${conf}</td>
        <td><span class="engine-tag ${engineClass}">${engineText}</span></td>
        <td style="text-align: center;"><button class="btn-inspect" data-id="${alert.id}">Drill</button></td>
      `;

      tr.querySelector('.btn-inspect').addEventListener('click', () => openDrilldownModal(alert));
      tbody.appendChild(tr);
    });
  }

  function renderSocRecentAttacks() {
    const listEl = document.getElementById('threatStreamList');
    const cleanEl = document.getElementById('threatsCleanState');
    const countEl = document.getElementById('recentAttacksCount');
    if (!listEl) return;

    const attacks = STATE.recentAttacks.slice(0, 15);
    if (countEl) countEl.innerText = `${attacks.length} attack${attacks.length === 1 ? '' : 's'}`;

    listEl.innerHTML = '';
    if (!attacks.length) {
      if (cleanEl) cleanEl.style.display = 'block';
      return;
    }

    if (cleanEl) cleanEl.style.display = 'none';

    attacks.forEach(att => {
      const card = document.createElement('div');
      card.className = 'threat-card';
      const conf = att.confidence ? `${att.confidence.toFixed(1)}%` : '--';
      const timeRelative = formatTimeShort(att.timestamp);

      const dtype = (att.detection_type || '').toUpperCase();
      const simBadge = dtype === 'SIMULATION' ? '<span class="engine-tag simulation" style="font-size:0.65rem; padding: 1px 4px; margin-left: 6px;">SIMULATION</span>' : '';

      card.innerHTML = `
        <div class="threat-card-top">
          <div style="display:flex; align-items:center;">${getBadgeHTML(att.prediction)}${simBadge}</div>
          <span class="mono" style="font-size: 0.7rem; color: var(--text-muted);">${timeRelative}</span>
        </div>
        <div class="threat-sockets">
          <span>${escapeHtml(att.source_ip)}:${att.source_port}</span>
          <span class="threat-arrow">&rarr;</span>
          <span>${escapeHtml(att.destination_ip)}:${att.destination_port}</span>
        </div>
        <div class="threat-meta-row">
          <span>Conf: <strong style="color:var(--text-primary);">${conf}</strong></span>
          <span>Payload: <strong style="color:var(--text-primary);">${formatBytes(att.bytes || 0)}</strong> (${att.packets || 0} pkts)</span>
        </div>
      `;

      card.addEventListener('click', () => openDrilldownModal(att));
      listEl.appendChild(card);
    });
  }

  // ============================================================================
  // 11. PAGE 3: NETWORK TRAFFIC ANALYSIS RENDERER
  // ============================================================================
  function renderTrafficPage() {
    const flows = (STATE.flows && STATE.flows.length) ? STATE.flows : STATE.alerts;
    let totalBytes = 0, totalPkts = 0, tcpCount = 0, udpCount = 0;

    flows.forEach(a => {
      totalBytes += (a.bytes || 0);
      totalPkts += (a.packets || 0);
      const proto = (a.protocol || 'TCP').toUpperCase();
      if (proto === 'TCP') tcpCount++;
      else if (proto === 'UDP') udpCount++;
    });

    setElText('trafficTotalBytes', formatBytes(STATE.stats.total_bytes || totalBytes));
    setElText('trafficTotalPackets', formatNumber(STATE.stats.total_packets || totalPkts));
    const avgSize = (STATE.stats.total_packets > 0) ? Math.round(STATE.stats.total_bytes / STATE.stats.total_packets) : (totalPkts > 0 ? Math.round(totalBytes / totalPkts) : 0);
    setElText('trafficAvgPacketSize', formatBytes(avgSize));
    setElText('trafficProtoRatio', `TCP: ${tcpCount} | UDP: ${udpCount}`);

    // Filter Table
    let filtered = flows.slice();
    if (STATE.trafficProtoFilter === 'TCP') {
      filtered = filtered.filter(a => (a.protocol || '').toUpperCase() === 'TCP');
    } else if (STATE.trafficProtoFilter === 'UDP') {
      filtered = filtered.filter(a => (a.protocol || '').toUpperCase() === 'UDP');
    } else if (STATE.trafficProtoFilter === 'HIGH_VOL') {
      filtered = filtered.filter(a => (a.bytes || 0) > 50000);
    }

    if (STATE.trafficSearchQuery) {
      filtered = filtered.filter(a => {
        const text = `${a.id} ${a.source_ip} ${a.destination_ip} ${a.source_port} ${a.destination_port} ${a.protocol}`.toLowerCase();
        return text.includes(STATE.trafficSearchQuery);
      });
    }

    const tbody = document.getElementById('trafficTableBody');
    const emptyBox = document.getElementById('trafficEmptyState');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (!filtered.length) {
      if (emptyBox) emptyBox.style.display = 'block';
      return;
    }

    if (emptyBox) emptyBox.style.display = 'none';

    filtered.forEach(f => {
      const tr = document.createElement('tr');
      const timeStr = formatTimeShort(f.timestamp);
      const srcService = PORT_SERVICES[f.source_port] ? ` (${PORT_SERVICES[f.source_port]})` : '';
      const dstService = PORT_SERVICES[f.destination_port] ? ` (${PORT_SERVICES[f.destination_port]})` : '';

      const isSim = (f.detection_type || '').toUpperCase() === 'SIMULATION';
      const simTag = isSim ? ' <span class="engine-tag simulation" style="font-size:0.65rem; padding: 1px 4px; vertical-align: middle;">SIM</span>' : '';

      tr.innerHTML = `
        <td class="mono" style="font-size: 0.74rem;">#${f.id}</td>
        <td class="mono" style="font-size: 0.74rem;">${timeStr}</td>
        <td class="cell-socket">${escapeHtml(f.source_ip)}:${f.source_port}<span class="cell-port-tag">${srcService}</span></td>
        <td class="cell-socket">${escapeHtml(f.destination_ip)}:${f.destination_port}<span class="cell-port-tag">${dstService}</span></td>
        <td><span class="proto-tag">${escapeHtml(f.protocol || 'TCP')}</span></td>
        <td class="mono">${formatNumber(f.packets || 0)}</td>
        <td class="mono">${formatBytes(f.bytes || 0)}</td>
        <td>${getBadgeHTML(f.prediction)}${simTag}</td>
        <td><button class="btn-inspect" data-id="${f.id}">Drill</button></td>
      `;

      tr.querySelector('.btn-inspect').addEventListener('click', () => openDrilldownModal(f));
      tbody.appendChild(tr);
    });
  }

  // ============================================================================
  // 12. PAGE 4: THREAT DETECTION (CLASSIFICATION) RENDERER
  // ============================================================================
  function renderThreatsPage() {
    const stats = STATE.stats;
    setElText('threatCardBenign', formatNumber(stats.benign || 0));
    setElText('threatCardDos', formatNumber(stats.dos || 0));
    setElText('threatCardDdos', formatNumber(stats.ddos || 0));
    setElText('threatCardPortScan', formatNumber(stats.port_scan || 0));
    setElText('threatCardBruteForce', formatNumber(stats.brute_force || 0));

    // Threat Attacks Stream Filtered
    let threats = STATE.alerts.filter(a => a.prediction !== 'BENIGN');

    if (STATE.threatCategoryFilter !== 'ALL_ATTACKS') {
      threats = threats.filter(a => a.prediction === STATE.threatCategoryFilter);
    }

    if (STATE.threatSearchQuery) {
      threats = threats.filter(a => {
        const text = `${a.id} ${a.source_ip} ${a.destination_ip} ${a.source_port} ${a.destination_port} ${a.prediction}`.toLowerCase();
        return text.includes(STATE.threatSearchQuery);
      });
    }

    const tbody = document.getElementById('threatClassTableBody');
    const emptyBox = document.getElementById('threatClassEmptyState');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (!threats.length) {
      if (emptyBox) emptyBox.style.display = 'block';
      return;
    }

    if (emptyBox) emptyBox.style.display = 'none';

    threats.forEach(t => {
      const tr = document.createElement('tr');
      const timeStr = formatTimeShort(t.timestamp);
      const conf = t.confidence ? `${t.confidence.toFixed(1)}%` : '--';
      const dtype = (t.detection_type || '').toUpperCase();
      const engineClass = dtype === 'BEHAVIOR' ? 'behavior' : (dtype === 'SIMULATION' ? 'simulation' : 'ml');
      const engineText = dtype === 'BEHAVIOR' ? 'HEURISTIC' : (dtype === 'SIMULATION' ? 'SIMULATION' : 'ML');

      tr.innerHTML = `
        <td class="mono" style="font-size: 0.74rem;">#${t.id}</td>
        <td class="mono" style="font-size: 0.74rem;">${timeStr}</td>
        <td class="cell-socket">${escapeHtml(t.source_ip)}:${t.source_port}</td>
        <td class="cell-socket">${escapeHtml(t.destination_ip)}:${t.destination_port}</td>
        <td>${getBadgeHTML(t.prediction)}</td>
        <td class="mono" style="font-weight: 600;">${conf}</td>
        <td><span class="engine-tag ${engineClass}">${engineText}</span></td>
        <td class="mono" style="font-size: 0.74rem;">${formatBytes(t.bytes || 0)} (${t.packets || 0}p)</td>
        <td><button class="btn-inspect" data-id="${t.id}">Drill</button></td>
      `;

      tr.querySelector('.btn-inspect').addEventListener('click', () => openDrilldownModal(t));
      tbody.appendChild(tr);
    });
  }

  // ============================================================================
  // 13. PAGE 5: ALERTS & INCIDENTS RENDERER
  // ============================================================================
  function renderAlertsPage() {
    const allThreats = STATE.alerts.filter(a => a.prediction !== 'BENIGN');
    const highConf = allThreats.filter(a => (a.confidence || 0) >= 90);
    const ackedCount = allThreats.filter(a => STATE.acknowledgedIds.has(a.id)).length;

    setElText('incTotalCount', formatNumber(allThreats.length));
    setElText('incHighConfCount', formatNumber(highConf.length));
    setElText('incAckCount', formatNumber(ackedCount));

    // Find top targeted destination IP
    const destCounts = {};
    allThreats.forEach(a => {
      destCounts[a.destination_ip] = (destCounts[a.destination_ip] || 0) + 1;
    });
    let topTarget = '--', maxC = 0;
    Object.entries(destCounts).forEach(([ip, count]) => {
      if (count > maxC) { maxC = count; topTarget = `${ip} (${count})`; }
    });
    setElText('incTopTarget', topTarget);

    // Filter Table
    let filtered = allThreats.slice();

    if (STATE.incFilter === 'UNACK') {
      filtered = filtered.filter(a => !STATE.acknowledgedIds.has(a.id));
    } else if (STATE.incFilter === 'HIGH_CONF') {
      filtered = filtered.filter(a => (a.confidence || 0) >= 90);
    } else if (STATE.incFilter === 'ML') {
      filtered = filtered.filter(a => {
        const dt = (a.detection_type || '').toUpperCase();
        return dt !== 'BEHAVIOR' && dt !== 'SIMULATION';
      });
    } else if (STATE.incFilter === 'BEHAVIOR') {
      filtered = filtered.filter(a => (a.detection_type || '').toUpperCase() === 'BEHAVIOR');
    } else if (STATE.incFilter === 'SIMULATION') {
      filtered = filtered.filter(a => (a.detection_type || '').toUpperCase() === 'SIMULATION');
    }

    if (STATE.incSearchQuery) {
      filtered = filtered.filter(a => {
        const text = `${a.id} ${a.source_ip} ${a.destination_ip} ${a.prediction} ${a.source_port} ${a.destination_port}`.toLowerCase();
        return text.includes(STATE.incSearchQuery);
      });
    }

    const tbody = document.getElementById('incidentsTableBody');
    const emptyBox = document.getElementById('incidentsEmptyState');
    if (!tbody) return;

    tbody.innerHTML = '';
    if (!filtered.length) {
      if (emptyBox) emptyBox.style.display = 'block';
      return;
    }

    if (emptyBox) emptyBox.style.display = 'none';

    filtered.forEach(inc => {
      const tr = document.createElement('tr');
      const isAcked = STATE.acknowledgedIds.has(inc.id);
      const timeStr = formatTimeShort(inc.timestamp);
      const conf = inc.confidence ? `${inc.confidence.toFixed(1)}%` : '--';
      const dtype = (inc.detection_type || '').toUpperCase();
      const engineClass = dtype === 'BEHAVIOR' ? 'behavior' : (dtype === 'SIMULATION' ? 'simulation' : 'ml');
      const engineText = dtype === 'BEHAVIOR' ? 'HEURISTIC' : (dtype === 'SIMULATION' ? 'SIMULATION' : 'ML');

      tr.innerHTML = `
        <td style="text-align: center;">
          <input type="checkbox" class="chk-ack" data-id="${inc.id}" ${isAcked ? 'checked' : ''} title="Mark Acknowledged">
        </td>
        <td class="mono" style="font-size: 0.74rem;">#${inc.id}</td>
        <td class="mono" style="font-size: 0.74rem;">${timeStr}</td>
        <td>${getBadgeHTML(inc.prediction)}</td>
        <td class="cell-socket">${escapeHtml(inc.source_ip)}:${inc.source_port}</td>
        <td class="cell-socket">${escapeHtml(inc.destination_ip)}:${inc.destination_port}</td>
        <td><span class="proto-tag">${escapeHtml(inc.protocol || 'TCP')}</span></td>
        <td class="mono" style="font-weight: 600;">${conf}</td>
        <td><span class="engine-tag ${engineClass}">${engineText}</span></td>
        <td style="text-align: center;"><button class="btn-inspect" data-id="${inc.id}">Drill</button></td>
      `;

      tr.querySelector('.chk-ack').addEventListener('change', (e) => {
        if (e.target.checked) STATE.acknowledgedIds.add(inc.id);
        else STATE.acknowledgedIds.delete(inc.id);
        renderAlertsPage();
      });

      tr.querySelector('.btn-inspect').addEventListener('click', () => openDrilldownModal(inc));
      tbody.appendChild(tr);
    });
  }

  // ============================================================================
  // 14. PAGE 6: ANALYTICS & REPORTS RENDERER
  // ============================================================================
  function renderAnalyticsPage() {
    const stats = STATE.stats;

    // Update Analytics Distribution Chart
    if (analyticsDistChart) {
      analyticsDistChart.data.datasets[0].data = [
        stats.benign || 0,
        stats.dos || 0,
        stats.ddos || 0,
        stats.port_scan || 0,
        stats.brute_force || 0
      ];
      analyticsDistChart.update('none');
    }

    // Update Protocol Chart
    if (analyticsProtoChart) {
      let tcp = 0, udp = 0, other = 0;
      STATE.alerts.forEach(a => {
        const proto = (a.protocol || 'TCP').toUpperCase();
        if (proto === 'TCP') tcp++;
        else if (proto === 'UDP') udp++;
        else other++;
      });
      analyticsProtoChart.data.datasets[0].data = [tcp, udp, other];
      analyticsProtoChart.update('none');
    }
  }

  // ============================================================================
  // 15. CHART.JS CONFIGURATION & THEME STYLING
  // ============================================================================
  function initCharts() {
    if (typeof Chart === 'undefined') return;

    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = '#62676D';

    // 1. Live SOC Donut Chart
    const ctxDonut = document.getElementById('trafficDonutChart');
    if (ctxDonut) {
      socDonutChart = new Chart(ctxDonut, {
        type: 'doughnut',
        data: {
          labels: ['BENIGN', 'DoS', 'DDoS', 'PORT SCAN', 'BRUTE FORCE'],
          datasets: [{
            data: [1, 0, 0, 0, 0],
            backgroundColor: ['#1C5432', '#8A6110', '#962626', '#245B85', '#8E3E12'],
            borderColor: '#FFFFFF',
            borderWidth: 2,
            hoverOffset: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { display: false },
            tooltip: getChartTooltipConfig()
          }
        }
      });
    }

    // 2. Overview Donut Chart
    const ctxOvDonut = document.getElementById('ovTrafficDonutChart');
    if (ctxOvDonut) {
      ovDonutChart = new Chart(ctxOvDonut, {
        type: 'doughnut',
        data: {
          labels: ['BENIGN', 'DoS', 'DDoS', 'PORT SCAN', 'BRUTE FORCE'],
          datasets: [{
            data: [1, 0, 0, 0, 0],
            backgroundColor: ['#1C5432', '#8A6110', '#962626', '#245B85', '#8E3E12'],
            borderColor: '#FFFFFF',
            borderWidth: 2,
            hoverOffset: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: { display: false },
            tooltip: getChartTooltipConfig()
          }
        }
      });
    }

    // 3. Live SOC Ingress Velocity Timeline
    const ctxTimeline = document.getElementById('timelineChart');
    if (ctxTimeline) {
      socTimelineChart = new Chart(ctxTimeline, {
        type: 'line',
        data: {
          labels: Array(CONFIG.TIMELINE_MAX_POINTS).fill(''),
          datasets: [
            {
              label: 'Safe Flows',
              data: Array(CONFIG.TIMELINE_MAX_POINTS).fill(0),
              borderColor: '#1C5432',
              backgroundColor: 'rgba(28, 84, 50, 0.08)',
              fill: true,
              tension: 0.35,
              borderWidth: 1.5,
              pointRadius: 0
            },
            {
              label: 'Malicious',
              data: Array(CONFIG.TIMELINE_MAX_POINTS).fill(0),
              borderColor: '#962626',
              backgroundColor: 'rgba(150, 38, 38, 0.1)',
              fill: true,
              tension: 0.35,
              borderWidth: 1.5,
              pointRadius: 0
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: getChartTooltipConfig()
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { display: false }
            },
            y: {
              beginAtZero: true,
              grid: { color: '#E8E9E5' },
              ticks: { font: { family: "'IBM Plex Mono', monospace", size: 10 } }
            }
          }
        }
      });
    }

    // 4. Analytics Distribution Bar Chart
    const ctxDist = document.getElementById('analyticsDistChart');
    if (ctxDist) {
      analyticsDistChart = new Chart(ctxDist, {
        type: 'bar',
        data: {
          labels: ['BENIGN', 'DoS', 'DDoS', 'PORT SCAN', 'BRUTE FORCE'],
          datasets: [{
            label: 'Total Analyzed Flows',
            data: [0, 0, 0, 0, 0],
            backgroundColor: ['#1C5432', '#8A6110', '#962626', '#245B85', '#8E3E12'],
            borderRadius: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: getChartTooltipConfig()
          },
          scales: {
            x: { grid: { display: false } },
            y: {
              beginAtZero: true,
              grid: { color: '#E8E9E5' },
              ticks: { font: { family: "'IBM Plex Mono', monospace", size: 10 } }
            }
          }
        }
      });
    }

    // 5. Analytics Protocol Doughnut Chart
    const ctxProto = document.getElementById('analyticsProtoChart');
    if (ctxProto) {
      analyticsProtoChart = new Chart(ctxProto, {
        type: 'doughnut',
        data: {
          labels: ['TCP', 'UDP', 'OTHER'],
          datasets: [{
            data: [0, 0, 0],
            backgroundColor: ['#245B85', '#1C5432', '#62676D'],
            borderColor: '#FFFFFF',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } },
            tooltip: getChartTooltipConfig()
          }
        }
      });
    }
  }

  function getChartTooltipConfig() {
    return {
      backgroundColor: '#191C20',
      titleColor: '#FFFFFF',
      bodyColor: '#E5EEF4',
      titleFont: { family: "'IBM Plex Mono', monospace", size: 11 },
      bodyFont: { family: "'Inter', sans-serif", size: 11 },
      padding: 8,
      cornerRadius: 3
    };
  }

  function updateDonutChart(chartInstance, totalElementId, stats) {
    if (!chartInstance) return;
    const total = stats.total_flows || 0;
    setElText(totalElementId, formatNumber(total));

    if (total === 0) {
      chartInstance.data.datasets[0].data = [1, 0, 0, 0, 0];
      chartInstance.data.datasets[0].backgroundColor = ['#E8E9E5', '#E8E9E5', '#E8E9E5', '#E8E9E5', '#E8E9E5'];
    } else {
      chartInstance.data.datasets[0].data = [
        stats.benign || 0,
        stats.dos || 0,
        stats.ddos || 0,
        stats.port_scan || 0,
        stats.brute_force || 0
      ];
      chartInstance.data.datasets[0].backgroundColor = ['#1C5432', '#8A6110', '#962626', '#245B85', '#8E3E12'];
    }
    chartInstance.update('none');
  }

  function updateTimelineData(alerts) {
    let benign = 0, attacks = 0;
    const recentBatch = alerts.slice(0, 15);
    recentBatch.forEach(a => {
      if (a.prediction === 'BENIGN') benign++;
      else attacks++;
    });

    STATE.timelineNormalRates.push(benign);
    STATE.timelineAttackRates.push(attacks);

    if (STATE.timelineNormalRates.length > CONFIG.TIMELINE_MAX_POINTS) {
      STATE.timelineNormalRates.shift();
      STATE.timelineAttackRates.shift();
    }
  }

  function renderTimelineChart() {
    if (!socTimelineChart) return;
    socTimelineChart.data.datasets[0].data = STATE.timelineNormalRates;
    socTimelineChart.data.datasets[1].data = STATE.timelineAttackRates;
    socTimelineChart.update('none');
  }

  // ============================================================================
  // 16. DEFCON THREAT POSTURE RISK ENGINE
  // ============================================================================
  function calculateThreatRiskScore(buffer) {
    if (!buffer || !buffer.length) return 0;

    let maliciousCount = 0;
    let highConfCount = 0;

    buffer.forEach(a => {
      if (a.prediction !== 'BENIGN') {
        maliciousCount++;
        if ((a.confidence || 0) >= 90) highConfCount++;
      }
    });

    const malRatio = maliciousCount / buffer.length;
    let score = Math.round(malRatio * 75);

    if (highConfCount >= 5) score += 20;
    else if (highConfCount >= 2) score += 10;

    return Math.min(Math.max(score, 0), 100);
  }

  function getConditionText(score) {
    if (score <= 10) return 'Nominal';
    if (score <= 35) return 'Guarded';
    if (score <= 65) return 'Elevated';
    if (score <= 85) return 'High Threat';
    return 'Critical';
  }

  function updateRiskMeterSegments(score) {
    const segs = [
      document.getElementById('riskSeg1'),
      document.getElementById('riskSeg2'),
      document.getElementById('riskSeg3'),
      document.getElementById('riskSeg4'),
      document.getElementById('riskSeg5')
    ];

    segs.forEach(s => {
      if (s) s.className = 'risk-segment';
    });

    if (score <= 10) {
      if (segs[0]) segs[0].classList.add('active-safe');
    } else if (score <= 35) {
      if (segs[0]) segs[0].classList.add('active-guard');
      if (segs[1]) segs[1].classList.add('active-guard');
    } else if (score <= 65) {
      if (segs[0]) segs[0].classList.add('active-elevated');
      if (segs[1]) segs[1].classList.add('active-elevated');
      if (segs[2]) segs[2].classList.add('active-elevated');
    } else if (score <= 85) {
      if (segs[0]) segs[0].classList.add('active-high');
      if (segs[1]) segs[1].classList.add('active-high');
      if (segs[2]) segs[2].classList.add('active-high');
      if (segs[3]) segs[3].classList.add('active-high');
    } else {
      segs.forEach(s => { if (s) s.classList.add('active-crit'); });
    }
  }

  // ============================================================================
  // 17. FORENSIC DRILLDOWN MODAL INSPECTOR
  // ============================================================================
  function openDrilldownModal(flow) {
    STATE.selectedFlow = flow;
    const modal = document.getElementById('drilldownModal');
    if (!modal) return;

    setElText('modalFlowTitle', `Flow Telemetry Inspection #${flow.id}`);

    const badge = document.getElementById('modalPredictionBadge');
    if (badge) {
      badge.className = `badge-prediction ${getBadgeClass(flow.prediction)}`;
      badge.innerText = flow.prediction || 'BENIGN';
    }

    setElText('modalSrcIp', flow.source_ip || '0.0.0.0');
    setElText('modalSrcPort', `Port: ${flow.source_port}`);
    setElText('modalDstIp', flow.destination_ip || '0.0.0.0');
    setElText('modalDstPort', `Port: ${flow.destination_port}`);
    setElText('modalProtocol', (flow.protocol || 'TCP').toUpperCase());

    const dtype = (flow.detection_type || '').toUpperCase();
    const engineType = dtype === 'BEHAVIOR' ? 'Behavioral Heuristic Tracker' : (dtype === 'SIMULATION' ? 'Simulated Attack Generator' : 'Random Forest Classifier');
    setElText('modalDetectionType', engineType);
    setElText('modalConfidence', flow.confidence ? `${flow.confidence.toFixed(1)}%` : '--');
    setElText('modalPackets', `${formatNumber(flow.packets || 0)} pkts`);
    setElText('modalBytes', formatBytes(flow.bytes || 0));

    const avg = (flow.packets || 0) > 0 ? Math.round((flow.bytes || 0) / flow.packets) : 0;
    setElText('modalAvgPktSize', formatBytes(avg));
    setElText('modalTimestamp', flow.timestamp || '--');

    // Context-Aware Playbook Remediation Guidance
    const playbookEl = document.getElementById('modalPlaybookText');
    if (playbookEl) {
      const recs = {
        'BENIGN': 'Baseline traffic pattern verified. Sockets conform to normal connection lifecycles. No operator mitigation required.',
        'DoS': 'High-volume server exhaustion vector identified. Recommended action: Check web server worker backlog, enable connection rate limiting, and review iptables rate modules.',
        'DDoS': 'Distributed multi-device flood profile detected. Recommended action: Engage upstream ISP scrubbing, apply edge rate limiting, and null-route attacking source subnets.',
        'PORT SCAN': 'Active reconnaissance sweep flagged across multiple ports. Recommended action: Block source IP via iptables / nftables and audit exposed firewall ports.',
        'Brute Force': 'Repeated authentication retries detected. Recommended action: Enforce fail2ban / SSH jail rules, mandate multi-factor authentication, and rate-limit authentication endpoints.'
      };
      playbookEl.innerText = recs[flow.prediction] || 'Investigate source socket behavior.';
    }

    // Raw JSON
    const rawPre = document.getElementById('modalRawJson');
    if (rawPre) {
      rawPre.innerText = JSON.stringify(flow, null, 2);
    }

    modal.classList.add('open');
  }

  function closeModal() {
    const modal = document.getElementById('drilldownModal');
    if (modal) modal.classList.remove('open');
  }

  // ============================================================================
  // 18. AUDIO SYNTHESIZER ALERT (WEB AUDIO API)
  // ============================================================================
  function toggleSound() {
    STATE.soundEnabled = !STATE.soundEnabled;
    const soundIcon = document.getElementById('soundIcon');
    if (soundIcon) {
      soundIcon.innerText = STATE.soundEnabled ? '🔊' : '🔇';
    }
  }

  function playThreatChirp() {
    try {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }

      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5 note
      osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.12);

      gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
      gain.gain.linearRampToValueAtTime(0, audioCtx.currentTime + 0.12);

      osc.connect(gain);
      gain.connect(audioCtx.destination);

      osc.start();
      osc.stop(audioCtx.currentTime + 0.13);
    } catch {
      // Audio autoplay policy fallback
    }
  }

  // ============================================================================
  // 19. EXPORT & DOWNLOAD UTILITIES
  // ============================================================================
  function exportDataCSV(items, filename) {
    if (!items || !items.length) {
      alert('No data to export.');
      return;
    }

    const headers = Object.keys(items[0]);
    const rows = items.map(item =>
      headers.map(h => {
        let val = item[h] === undefined ? '' : String(item[h]);
        val = val.replace(/"/g, '""');
        return `"${val}"`;
      }).join(',')
    );

    const csvContent = [headers.join(','), ...rows].join('\n');
    downloadBlob(csvContent, 'text/csv;charset=utf-8;', filename);
  }

  function exportDataJSON(data, filename) {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadBlob(jsonContent, 'application/json;charset=utf-8;', filename);
  }

  function downloadBlob(content, mimeType, filename) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  // ============================================================================
  // 20. UTILITY FORMATTERS & CLOCK
  // ============================================================================
  function startClock() {
    const clockEl = document.getElementById('footerClock');
    const update = () => {
      if (clockEl) {
        const now = new Date();
        clockEl.innerText = `UTC ${now.toUTCString().split(' ')[4]}`;
      }
    };
    update();
    setInterval(update, 1000);
  }

  function setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
  }

  function formatNumber(num) {
    return Number(num || 0).toLocaleString();
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function formatTimeShort(isoStr) {
    if (!isoStr) return '--:--:--';
    try {
      const d = new Date(isoStr);
      return d.toTimeString().split(' ')[0];
    } catch {
      return isoStr;
    }
  }

  function getBadgeClass(prediction) {
    const p = (prediction || '').toUpperCase();
    if (p === 'BENIGN') return 'benign';
    if (p === 'DOS') return 'dos';
    if (p === 'DDOS') return 'ddos';
    if (p === 'PORT SCAN') return 'portscan';
    if (p === 'BRUTE FORCE') return 'bruteforce';
    return 'benign';
  }

  function getBadgeHTML(prediction) {
    const cls = getBadgeClass(prediction);
    return `<span class="badge-prediction ${cls}">${escapeHtml(prediction || 'BENIGN')}</span>`;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

})();
