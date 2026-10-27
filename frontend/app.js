const state = {
  token: localStorage.getItem('dma.session'),
  user: null,
  scans: [],
  uploadSessions: new Map()
};

const $ = (id) => document.getElementById(id);
const authHeader = () => state.token ? { Authorization: `Bearer ${state.token}` } : {};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...authHeader(), ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

function showAuthMessage(message = '') { $('authMessage').textContent = message; }
function setAuthenticated(value) {
  $('authView').classList.toggle('hidden', value);
  $('appView').classList.toggle('hidden', !value);
  $('sessionState').textContent = value && state.user ? state.user.email : 'Nicht angemeldet';
}

async function loadSession() {
  if (!state.token) return setAuthenticated(false);
  try {
    state.user = await api('/api/v1/auth/me');
    setAuthenticated(true);
    await Promise.all([loadScans(), loadVersion()]);
  } catch {
    localStorage.removeItem('dma.session');
    state.token = null;
    setAuthenticated(false);
  }
}

async function loadVersion() {
  const version = await api('/api/v1/scanner/version');
  $('scannerVersion').textContent = version.latest_version;
  $('scannerIntegrity').textContent = version.sha256
    ? `SHA-256 ${version.sha256} · Signatur: ${version.signature_status}`
    : 'Scanner-EXE ist auf dem Server nicht verfügbar.';
}

async function loadScans() {
  state.scans = await api('/api/v1/scans');
  $('scanCount').textContent = state.scans.length;
  $('completedCount').textContent = state.scans.filter((scan) => scan.status === 'COMPLETED').length;
  const list = $('scanList');
  if (!state.scans.length) {
    list.innerHTML = '<div class="empty">Noch keine Scans vorhanden.</div>';
    return;
  }
  list.innerHTML = state.scans.map((scan) => `
    <div class="scan-row">
      <span class="scan-id">${escapeHtml(scan.scan_id)}</span>
      <span class="scan-meta">${escapeHtml(scan.scan_mode)}</span>
      <span class="badge">${escapeHtml(scan.status)}</span>
      <button class="row-action" data-scan="${escapeHtml(scan.scan_id)}">Report öffnen</button>
    </div>`).join('');
  list.querySelectorAll('[data-scan]').forEach((button) => button.addEventListener('click', () => loadReport(button.dataset.scan)));
}

async function loadReport(scanId) {
  const [report, findings] = await Promise.all([
    api(`/api/v1/scans/${encodeURIComponent(scanId)}/report`),
    api(`/api/v1/scans/${encodeURIComponent(scanId)}/findings`)
  ]);
  $('reportPanel').classList.remove('hidden');
  $('reportTitle').textContent = scanId;
  $('reportStatus').textContent = report.status || 'CREATED';
  $('reportSummary').innerHTML = `<div><strong>${report.finding_count || 0}</strong><br>Findings</div><div><strong>${report.timeline_count || 0}</strong><br>Timeline events</div>`;
  $('findingList').innerHTML = findings.findings.length ? findings.findings.map((finding) => `<div class="finding"><strong>${escapeHtml(finding.title || finding.category || 'Unbenanntes Finding')}</strong><span>${escapeHtml(finding.description || finding.severity || 'Evidence requires review')}</span></div>`).join('') : '<div class="empty">Keine Findings gespeichert.</div>';
  const timeline = report.timeline || [];
  $('timelineList').innerHTML = timeline.length ? timeline.slice(0, 100).map((event) => `<div class="timeline-row"><time>${escapeHtml(event.Timestamp || event.timestamp || '')}</time><strong>${escapeHtml(event.Category || event.category || 'EVENT')}</strong><span>${escapeHtml(event.Event || event.event || event.Source || event.source || '')}</span></div>`).join('') : '<div class="empty">Keine Timeline-Ereignisse gespeichert.</div>';
}

async function downloadScanner() {
  const response = await fetch('/api/v1/scanner/download', { headers: authHeader() });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.detail || `Download fehlgeschlagen (${response.status})`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'DmaForensicsScanner.exe';
  link.click();
  URL.revokeObjectURL(url);
}

function toUploadPayload(localScan, scanId) {
  const artifacts = localScan.Artifacts || [];
  return {
    schema_version: 1,
    scan: {
      scan_id: scanId,
      local_scan_id: localScan.ScanId,
      scanner_version: localScan.ToolVersion,
      scan_mode: localScan.ScanMode,
      started_at: localScan.StartTimeUtc,
      completed_at: localScan.EndTimeUtc,
      computer_name: localScan.ComputerName
    },
    system: { computer_name: localScan.ComputerName },
    security: (artifacts.find((item) => item.Category === 'SECURITY_POSTURE') || {}).Data || {},
    pci_devices: artifacts.filter((item) => item.Category === 'PCI_DEVICE').map((item) => item.Data),
    drivers: artifacts.filter((item) => item.Category === 'DRIVER_FILE').map((item) => item.Data),
    device_history: artifacts.filter((item) => item.Category === 'DEVICE_INSTALLATION').map((item) => item.Data),
    timeline: (localScan.Timeline || []).map((event) => ({
      timestamp: event.Timestamp,
      category: event.Category,
      source: event.Source,
      event: event.Event,
      device: event.Device,
      file: event.File,
      confidence: event.Confidence
    })),
    findings: (localScan.Findings || []).map((finding) => ({
      category: finding.Category,
      severity: finding.Severity,
      title: finding.Artifact,
      description: finding.WhyFlagged,
      confidence: finding.Confidence,
      source: finding.Source,
      possible_legitimate_explanation: finding.PossibleLegitimateExplanation,
      path: finding.Path
    })),
    statistics: localScan.Summary || {}
  };
}

async function uploadLocalReport(file, scanId, uploadToken, statusElement) {
  statusElement.textContent = 'Report wird geprüft und hochgeladen …';
  try {
    const localScan = JSON.parse(await file.text());
    if (!localScan || !Array.isArray(localScan.Artifacts) || !localScan.ScanId) {
      throw new Error('Das JSON ist kein unterstützter DMA Forensics Report.');
    }
    const result = await api(`/api/v1/scans/${encodeURIComponent(scanId)}/results`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${uploadToken}` },
      body: JSON.stringify(toUploadPayload(localScan, scanId))
    });
    statusElement.textContent = `Ergebnis gespeichert · Hash ${result.result_hash}`;
    await loadScans();
    await loadReport(scanId);
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
}

$('authToggle').addEventListener('click', () => {
  const registerMode = $('authTitle').textContent === 'Anmelden';
  $('authTitle').textContent = registerMode ? 'Konto erstellen' : 'Anmelden';
  $('authSubmit').textContent = registerMode ? 'Registrieren' : 'Anmelden';
  $('authToggle').textContent = registerMode ? 'Bereits registriert' : 'Konto erstellen';
  $('authForm').dataset.mode = registerMode ? 'register' : 'login';
  showAuthMessage();
});

$('authForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  showAuthMessage('');
  const mode = $('authForm').dataset.mode || 'login';
  try {
    const data = await api(`/api/v1/auth/${mode}`, { method: 'POST', body: JSON.stringify({ email: $('email').value, password: $('password').value }) });
    state.token = data.access_token;
    localStorage.setItem('dma.session', state.token);
    state.user = { email: data.email, role: data.role, user_id: data.user_id };
    setAuthenticated(true);
    await Promise.all([loadScans(), loadVersion()]);
  } catch (error) { showAuthMessage(error.message); }
});

$('logoutButton').addEventListener('click', () => {
  localStorage.removeItem('dma.session');
  state.token = null;
  state.user = null;
  setAuthenticated(false);
});
$('downloadScanner').addEventListener('click', async () => {
  try { await downloadScanner(); }
  catch (error) { window.alert(error.message); }
});
$('refreshScans').addEventListener('click', loadScans);
$('createScan').addEventListener('click', async () => {
  const button = $('createScan');
  button.disabled = true;
  try {
    const scan = await api('/api/v1/scans', { method: 'POST', body: JSON.stringify({ scan_mode: 'QUICK', platform: 'windows' }) });
    state.uploadSessions.set(scan.scan_id, scan.upload_token);
    $('createdScan').classList.remove('hidden');
    $('createdScan').innerHTML = `Session <strong>${escapeHtml(scan.scan_id)}</strong> erstellt.<div class="session-actions"><button class="row-action download-session">EXE herunterladen</button><label class="upload-report">Lokalen JSON-Report hochladen<input class="report-file" type="file" accept="application/json,.json"></label></div><p class="upload-status" role="status">Nach dem lokalen Scan den JSON-Report auswählen.</p>`;
    $('createdScan').querySelector('.download-session').addEventListener('click', async () => {
      try { await downloadScanner(); }
      catch (error) { $('createdScan').querySelector('.upload-status').textContent = error.message; }
    });
    $('createdScan').querySelector('.report-file').addEventListener('change', (event) => {
      const file = event.target.files[0];
      if (file) uploadLocalReport(file, scan.scan_id, scan.upload_token, $('createdScan').querySelector('.upload-status'));
    });
    await loadScans();
  } catch (error) { $('createdScan').classList.remove('hidden'); $('createdScan').textContent = error.message; }
  finally { button.disabled = false; }
});

loadSession();
