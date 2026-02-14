const ipRangeInput = document.getElementById('ipRange');
const scanIntervalSelect = document.getElementById('scanInterval');
const autoScanCheckbox = document.getElementById('autoScanEnabled');
const saveConfigBtn = document.getElementById('saveConfigBtn');
const scanNowBtn = document.getElementById('scanNowBtn');
const searchInput = document.getElementById('search');
const resultsBody = document.getElementById('resultsBody');
const summary = document.getElementById('summary');

let allItems = [];
let autoRefreshTimer = null;

function formatDate(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleTimeString();
}

function renderTable(items) {
  const filter = searchInput.value.trim().toLowerCase();
  const filtered = items.filter((item) => {
    const host = (item.hostname || '').toLowerCase();
    return item.ip.toLowerCase().includes(filter) || host.includes(filter);
  });

  resultsBody.innerHTML = filtered
    .map(
      (item) => `
      <tr>
        <td>${item.hostname || ''}</td>
        <td>${item.ip}</td>
        <td><span class="badge ${item.status === 'Online' ? 'online' : 'offline'}">${item.status}</span></td>
        <td>${item.latency_ms ?? '-'}</td>
        <td>${formatDate(item.last_scan)}</td>
      </tr>
    `
    )
    .join('');
}

async function fetchConfig() {
  const res = await fetch('/api/config');
  const config = await res.json();
  ipRangeInput.value = config.ip_range;
  scanIntervalSelect.value = String(config.auto_scan_interval_seconds);
  autoScanCheckbox.checked = config.auto_scan_enabled;
  setupAutoRefresh();
}

async function fetchResults() {
  const res = await fetch('/api/results');
  const payload = await res.json();
  allItems = payload.items || [];
  summary.textContent = `Online: ${payload.online || 0} / Total: ${payload.total || 0}`;
  renderTable(allItems);
}

async function saveConfig() {
  const payload = {
    ip_range: ipRangeInput.value.trim(),
    auto_scan_enabled: autoScanCheckbox.checked,
    auto_scan_interval_seconds: Number(scanIntervalSelect.value),
  };

  const res = await fetch('/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    alert('Configuración inválida');
    return;
  }

  setupAutoRefresh();
}

async function runScan() {
  scanNowBtn.disabled = true;
  scanNowBtn.textContent = 'Escaneando...';
  try {
    const res = await fetch('/api/scan', { method: 'POST' });
    if (!res.ok) {
      alert('Error al escanear');
      return;
    }
    const payload = await res.json();
    allItems = payload.items || [];
    summary.textContent = `Online: ${payload.online || 0} / Total: ${payload.total || 0}`;
    renderTable(allItems);
  } finally {
    scanNowBtn.disabled = false;
    scanNowBtn.textContent = 'Escanear ahora';
  }
}

function setupAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }

  if (autoScanCheckbox.checked) {
    const intervalMs = Number(scanIntervalSelect.value) * 1000;
    autoRefreshTimer = setInterval(() => {
      runScan();
    }, intervalMs);
  }
}

searchInput.addEventListener('input', () => renderTable(allItems));
autoScanCheckbox.addEventListener('change', setupAutoRefresh);
scanIntervalSelect.addEventListener('change', setupAutoRefresh);
saveConfigBtn.addEventListener('click', saveConfig);
scanNowBtn.addEventListener('click', runScan);

(async function init() {
  await fetchConfig();
  await fetchResults();
})();
