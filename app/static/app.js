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
let livePollTimer = null;

function formatDate(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleTimeString();
}

function escapeHtml(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function cleanHostname(hostname) {
  const value = (hostname || '').trim();
  if (!value) return '';
  return value.endsWith('.fritz.box') ? value.slice(0, -'.fritz.box'.length) : value;
}

function renderTable(items) {
  const filter = searchInput.value.trim().toLowerCase();
  const filtered = items.filter((item) => {
    const host = (item.hostname || '').toLowerCase();
    const manual = (item.manual_name || '').toLowerCase();
    return item.ip.toLowerCase().includes(filter) || host.includes(filter) || manual.includes(filter);
  });

  resultsBody.innerHTML = filtered
    .map(
      (item) => `
      <tr>
        <td>${escapeHtml(item.hostname || '')}</td>
        <td>
          <div class="manual-name-wrap">
            <input class="manual-name-input" data-ip="${item.ip}" value="${escapeHtml(item.manual_name || '')}" placeholder="Nombre manual" maxlength="64" />
            <button class="btn tiny copy-hostname-btn" data-ip="${item.ip}" data-hostname="${escapeHtml(item.hostname || '')}" type="button">Usar hostname</button>
          </div>
        </td>
        <td>${item.ip}</td>
        <td><span class="badge ${item.status === 'Online' ? 'online' : 'offline'}">${item.status}</span></td>
        <td>${item.latency_ms ?? '-'}</td>
        <td>${formatDate(item.last_scan)}</td>
      </tr>
    `
    )
    .join('');
}

function updateSummary(payload) {
  const online = payload.online || 0;
  const total = payload.total || 0;
  const completed = payload.completed || 0;

  if (payload.scanning) {
    summary.textContent = `Escaneando... ${completed}/${total} | Online: ${online}`;
  } else {
    summary.textContent = `Online: ${online} / Total: ${total}`;
  }
}

function updateLocalManualName(ip, name) {
  allItems = allItems.map((item) => (item.ip === ip ? { ...item, manual_name: name } : item));
}

async function saveDeviceName(ip, name) {
  const res = await fetch('/api/device-name', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, name }),
  });

  if (!res.ok) {
    alert('No se pudo guardar el nombre manual');
    return false;
  }

  updateLocalManualName(ip, name.trim());
  return true;
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
  updateSummary(payload);
  renderTable(allItems);
  return payload;
}

function startLivePolling() {
  if (livePollTimer) {
    clearInterval(livePollTimer);
    livePollTimer = null;
  }

  livePollTimer = setInterval(async () => {
    try {
      const payload = await fetchResults();
      if (!payload.scanning) {
        clearInterval(livePollTimer);
        livePollTimer = null;
      }
    } catch (_err) {
      // no-op para no romper el loop visual
    }
  }, 700);
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
  startLivePolling();

  try {
    const res = await fetch('/api/scan', { method: 'POST' });
    if (!res.ok) {
      alert('Error al escanear');
      return;
    }
    const payload = await res.json();
    allItems = payload.items || [];
    updateSummary(payload);
    renderTable(allItems);
  } finally {
    if (livePollTimer) {
      clearInterval(livePollTimer);
      livePollTimer = null;
    }
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

resultsBody.addEventListener('focusout', async (event) => {
  if (!event.target.classList.contains('manual-name-input')) return;
  const ip = event.target.dataset.ip;
  const name = event.target.value;
  await saveDeviceName(ip, name);
});

resultsBody.addEventListener('keydown', async (event) => {
  if (!event.target.classList.contains('manual-name-input')) return;
  if (event.key !== 'Enter') return;
  event.preventDefault();
  const ip = event.target.dataset.ip;
  const name = event.target.value;
  await saveDeviceName(ip, name);
  event.target.blur();
});

resultsBody.addEventListener('click', async (event) => {
  const button = event.target.closest('.copy-hostname-btn');
  if (!button) return;

  const ip = button.dataset.ip;
  const cleanName = cleanHostname(button.dataset.hostname || '');
  const input = resultsBody.querySelector(`.manual-name-input[data-ip="${ip}"]`);
  if (input) {
    input.value = cleanName;
  }
  await saveDeviceName(ip, cleanName);
  renderTable(allItems);
});

searchInput.addEventListener('input', () => renderTable(allItems));
autoScanCheckbox.addEventListener('change', setupAutoRefresh);
scanIntervalSelect.addEventListener('change', setupAutoRefresh);
saveConfigBtn.addEventListener('click', saveConfig);
scanNowBtn.addEventListener('click', runScan);

(async function init() {
  await fetchConfig();
  await fetchResults();
})();
