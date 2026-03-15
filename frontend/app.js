const API_URL = 'http://52.62.241.203:8080';
const SCAN_OPTIONS = {
  domain: [['whois', 'WHOIS'], ['dns', 'DNS'], ['subdomain', 'Subdomain'], ['cert_trans', 'Cert Transparency'], ['ssl', 'SSL/TLS'], ['tech', 'Technology'], ['all', 'Quét tất cả']],
  ip: [['ip', 'IP Info'], ['asn', 'ASN Lookup'], ['port', 'Port Scan'], ['all', 'Quét tất cả']],
};

async function api(path, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (!res.ok) {
    let detail = 'Request failed';
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  const type = res.headers.get('content-type') || '';
  if (type.includes('application/json')) return res.json();
  if (type.includes('text/csv')) return res.text();
  return res.blob();
}

const esc = (v) => String(v ?? '-').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
const formatDate = (v) => !v ? '-' : (isNaN(new Date(v)) ? esc(v) : new Date(v).toLocaleString('vi-VN'));
const tagsToList = (value) => value.split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
const chip = (text, tone='default') => `<span class="badge ${tone}">${esc(text)}</span>`;
function setMessage(msg, type='warn') { const el = document.getElementById('message'); el.textContent = msg || ''; el.className = type === 'ok' ? 'ok' : ''; }
function formatKV(label, value) { return `<div><strong>${esc(label)}:</strong> ${esc(value)}</div>`; }
function pick(obj, keys, fallback='-') { for (const k of keys) if (obj && obj[k] != null && obj[k] !== '') return obj[k]; return fallback; }

function renderResult(scanType, results) {
  if (!results || results.length === 0) return '<div class="small">Chưa có dữ liệu.</div>';
  if (scanType === 'all') return results.map(group => `<div class="job nested"><div><strong>${esc((group.scan_type||'').toUpperCase())}</strong> ${group.error ? chip('Lỗi','danger') : chip(`${group.count||0} kết quả`, 'ok')}</div>${group.error ? `<div class="small">${esc(group.error)}</div>` : ''}${renderResult(group.scan_type, group.results||[])}</div>`).join('');
  if (scanType === 'dns') return `<table class="table"><thead><tr><th>Host</th><th>Record</th><th>Value</th><th>TTL</th></tr></thead><tbody>${results.map(r => `<tr><td>${esc(pick(r,['host','domain']))}</td><td>${esc(pick(r,['record_type','type']))}</td><td>${esc(pick(r,['value']))}</td><td>${esc(pick(r,['ttl'],300))}</td></tr>`).join('')}</tbody></table>`;
  if (scanType === 'whois') { const r=results[0]; return `<div class="result-grid"><div class="info-card">${formatKV('Domain', pick(r,['domain']))}${formatKV('Registrar', pick(r,['registrar']))}${formatKV('Created', formatDate(pick(r,['created_date'],'')))}${formatKV('Updated', formatDate(pick(r,['updated_date'],'')))}${formatKV('Expires', formatDate(pick(r,['expiration_date'],'')))}${formatKV('Name Servers', (r.name_servers||[]).join(', ')||'-')}</div><div class="info-card"><strong>WHOIS Raw</strong><pre class="raw-box">${esc(r.raw_text || 'Không có raw whois')}</pre></div></div>`; }
  if (scanType === 'subdomain') return `<table class="table"><thead><tr><th>Subdomain</th><th>Source</th></tr></thead><tbody>${results.map(r => `<tr><td>${esc(pick(r,['subdomain','name','common_name']))}</td><td>${esc(pick(r,['source'],'-'))}</td></tr>`).join('')}</tbody></table>`;
  if (scanType === 'cert_trans') return `<table class="table"><thead><tr><th>Common Name</th><th>Issuer</th><th>Logged At</th></tr></thead><tbody>${results.map(r => `<tr><td>${esc(pick(r,['common_name','subdomain','name']))}</td><td>${esc(pick(r,['issuer_name','issuer']))}</td><td>${formatDate(pick(r,['entry_timestamp','created_at']))}</td></tr>`).join('')}</tbody></table>`;
  if (scanType === 'ip') return results.map(r => `<div class="result-grid"><div class="info-card">${formatKV('IP', r.ip_address)}${formatKV('Country', r.geolocation?.country)}${formatKV('City', r.geolocation?.city)}${formatKV('Region', r.geolocation?.region)}${formatKV('ISP', r.geolocation?.isp)}${formatKV('Reverse DNS', r.reverse_dns)}</div><div class="info-card">${formatKV('ASN', r.asn?.number ? `AS${r.asn.number}` : '-')}${formatKV('ASN Name', r.asn?.name)}${formatKV('ASN Description', r.asn?.description)}${formatKV('Latitude', r.geolocation?.latitude)}${formatKV('Longitude', r.geolocation?.longitude)}</div></div>`).join('');
  if (scanType === 'asn') return results.map(r => `<div class="info-card">${formatKV('IP', r.ip_address)}${formatKV('ASN Number', r.asn?.number ? `AS${r.asn.number}` : '-')}${formatKV('ASN Name', r.asn?.name)}${formatKV('Description', r.asn?.description)}${formatKV('Network', r.network)}${formatKV('Country', r.country)}</div>`).join('');
  if (scanType === 'port') return results.map(r => `${formatKV('IP', r.ip_address)}${formatKV('Total scanned', r.total_scanned)}${formatKV('Closed ports', r.closed_ports)}${formatKV('Duration (ms)', r.scan_duration_ms)}<table class="table"><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>${(r.open_ports||[]).map(p => `<tr><td>${esc(p.port)}</td><td>${esc(p.protocol)}</td><td>${esc(p.state)}</td><td>${esc(p.service)}</td><td>${esc(p.version||'-')}</td></tr>`).join('') || '<tr><td colspan="5">Không có cổng mở.</td></tr>'}</tbody></table>`).join('');
  if (scanType === 'ssl') return results.map(r => `<div class="result-grid"><div class="info-card">${formatKV('Domain', r.domain)}${formatKV('Subject', r.certificate?.subject)}${formatKV('Issuer', r.certificate?.issuer)}${formatKV('Valid From', formatDate(r.certificate?.valid_from))}${formatKV('Valid Until', formatDate(r.certificate?.valid_until))}${formatKV('Days Until Expiry', r.certificate?.days_until_expiry)}</div><div class="info-card">${formatKV('TLS Version', r.connection?.tls_version)}${formatKV('Cipher Suite', r.connection?.cipher_suite)}${formatKV('Grade', r.grade)}${formatKV('SAN', (r.certificate?.san||[]).join(', ') || '-')} ${formatKV('Issues', (r.issues||[]).join(' | ') || 'Không có')}</div></div>`).join('');
  if (scanType === 'tech') return results.map(r => `${formatKV('Domain', r.domain)}<table class="table"><thead><tr><th>Name</th><th>Category</th><th>Version</th><th>Confidence</th></tr></thead><tbody>${(r.technologies||[]).map(t => `<tr><td>${esc(t.name)}</td><td>${esc(t.category)}</td><td>${esc(t.version||'-')}</td><td>${esc(t.confidence)}</td></tr>`).join('')}</tbody></table>`).join('');
  return `<pre>${esc(JSON.stringify(results, null, 2))}</pre>`;
}

function assetCard(asset, scans, schedules) {
  return `<div class="asset"><div class="asset-head"><div><h3>${esc(asset.name)}</h3>${chip(asset.type)} ${(asset.tags||[]).map(tag => chip(tag,'ok')).join(' ')}<span class="small">${formatDate(asset.created_at)}</span></div><div class="row"><button class="secondary export-csv" data-export-csv="${asset.id}">Export CSV</button><button class="secondary export-pdf" data-export-pdf="${asset.id}">Export PDF</button><button class="danger" data-delete="${asset.id}">Xóa</button></div></div><div class="scan-actions" id="actions-${asset.id}"></div><div class="tool-grid"><div class="panel compact"><h4>Scheduled Scans</h4><form class="schedule-form" data-asset-id="${asset.id}"><select name="scan_type">${(SCAN_OPTIONS[asset.type]||[]).map(([k,l]) => `<option value="${k}">${l}</option>`).join('')}</select><input name="interval_minutes" type="number" min="1" value="60" /><button type="submit">Tạo lịch</button></form><div>${(schedules||[]).map(s => `<div class="list-row"><span>${esc(s.scan_type)} / ${esc(s.interval_minutes)} phút</span><button class="danger small-btn" data-delete-schedule="${s.id}">Xóa</button></div>`).join('') || '<div class="small">Chưa có lịch quét.</div>'}</div></div><div class="panel compact"><h4>Scan Comparison</h4><div class="row"><select id="compare-type-${asset.id}">${(SCAN_OPTIONS[asset.type]||[]).filter(([k]) => k !== 'all').map(([k,l]) => `<option value="${k}">${l}</option>`).join('')}</select><button class="secondary" data-compare="${asset.id}">So sánh 2 lần gần nhất</button></div><div id="compare-result-${asset.id}" class="small"></div></div></div><div class="jobs">${scans.slice().reverse().map(job => `<div class="job"><div><strong>${esc((job.scan_type||'').toUpperCase())}</strong> ${chip(job.status, job.status === 'completed' ? 'ok' : job.status === 'failed' ? 'danger' : 'warn')}</div><div class="job-meta">Started: ${formatDate(job.started_at)} | Results: ${job.results} | Trigger: ${esc(job.triggered_by || 'manual')}</div>${job.error ? `<div class="small">Lỗi: ${esc(job.error)}</div>` : ''}<div class="result-box" data-results-for="${job.id}"><div class="small">Đang tải kết quả...</div></div></div>`).join('')}</div></div>`;
}

async function fillJobResults(scans) {
  for (const job of scans) {
    const box = document.querySelector(`[data-results-for="${job.id}"]`);
    if (!box) continue;
    const results = await api(`/scan-jobs/${job.id}/results`).catch(() => ({ results: [] }));
    box.innerHTML = renderResult(job.scan_type, results.results);
  }
}

function renderDashboard(assets, scanMap, summary, alerts) {
  const jobs = [...scanMap.values()].flat();
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="small">Tổng assets</div><div><strong>${summary.total_assets || assets.length}</strong></div></div>
    <div class="stat"><div class="small">Domain assets</div><div><strong>${summary.domain_assets || 0}</strong></div></div>
    <div class="stat"><div class="small">IP assets</div><div><strong>${summary.ip_assets || 0}</strong></div></div>
    <div class="stat"><div class="small">Scheduled scans</div><div><strong>${summary.scheduled_scans || 0}</strong></div></div>
    <div class="stat"><div class="small">Alerts</div><div><strong>${summary.alerts || alerts.length}</strong></div></div>`;
  const status = summary.job_status || {};
  document.getElementById('job-status-stats').innerHTML = ['completed','running','pending','partial','failed'].map(k => `<div class="stat"><div class="small">${k}</div><div><strong>${status[k] || 0}</strong></div></div>`).join('');
  const scanTypes = Object.entries(summary.scan_types || {}).sort((a,b) => b[1]-a[1]);
  document.getElementById('scan-type-stats').innerHTML = scanTypes.length ? scanTypes.map(([type,count]) => `<div class="list-row"><span class="mono">${esc(type)}</span><strong>${count}</strong></div>`).join('') : '<div class="empty-state">Chưa có scan job nào.</div>';
  document.getElementById('tag-stats').innerHTML = (summary.tags || []).length ? summary.tags.map(item => `<div class="list-row"><span>${esc(item.tag)}</span><strong>${item.count}</strong></div>`).join('') : '<div class="empty-state">Chưa có tags.</div>';
  document.getElementById('alerts-list').innerHTML = alerts.length ? alerts.slice(0, 8).map(a => `<div class="list-row"><span>${chip(a.severity, a.severity === 'high' ? 'danger' : a.severity === 'warning' ? 'warn' : 'ok')} ${esc(a.message)}</span><span class="small">${formatDate(a.created_at)}</span></div>`).join('') : '<div class="empty-state">Chưa có alerts.</div>';
  const recent = [...jobs].sort((a,b) => new Date(b.created_at || b.started_at || 0) - new Date(a.created_at || a.started_at || 0)).slice(0, 10);
  document.getElementById('recent-jobs').innerHTML = recent.length ? `<table class="table"><thead><tr><th>Asset</th><th>Type</th><th>Status</th><th>Kết quả</th><th>Trigger</th><th>Bắt đầu</th></tr></thead><tbody>${recent.map(job => { const asset = assets.find(a => a.id === job.asset_id); return `<tr><td>${esc(asset?.name || job.asset_id)}</td><td>${esc(job.scan_type)}</td><td>${esc(job.status)}</td><td>${esc(job.results)}</td><td>${esc(job.triggered_by || 'manual')}</td><td>${formatDate(job.started_at || job.created_at)}</td></tr>`; }).join('')}</tbody></table>` : '<div class="empty-state">Chưa có dữ liệu scan.</div>';
}

async function loadAssets() {
  const [assets, summary, alerts] = await Promise.all([api('/assets'), api('/dashboard').catch(() => ({})), api('/alerts').catch(() => ([]))]);
  const scanMap = new Map(); const scheduleMap = new Map();
  for (const asset of assets) {
    const [scans, schedules] = await Promise.all([api(`/assets/${asset.id}/scans`).catch(() => []), api(`/assets/${asset.id}/schedules`).catch(() => [])]);
    scanMap.set(asset.id, scans); scheduleMap.set(asset.id, schedules);
  }
  renderDashboard(assets, scanMap, summary, alerts);
  const container = document.getElementById('assets');
  container.innerHTML = assets.length ? assets.map(asset => assetCard(asset, scanMap.get(asset.id)||[], scheduleMap.get(asset.id)||[])).join('') : '<div class="empty-state">Chưa có asset nào.</div>';

  for (const asset of assets) {
    const actions = document.getElementById(`actions-${asset.id}`);
    for (const [key, label] of (SCAN_OPTIONS[asset.type] || [])) {
      const btn = document.createElement('button'); btn.textContent = label; if (key === 'all') btn.className = 'warn';
      btn.onclick = async () => { try { setMessage('Đang chạy scan...', 'ok'); await api(`/assets/${asset.id}/scan`, { method: 'POST', body: JSON.stringify({ scan_type: key }) }); setMessage(`Đã khởi tạo scan ${label}`, 'ok'); await loadAssets(); } catch (err) { setMessage(err.message); } };
      actions.appendChild(btn);
    }
    await fillJobResults((scanMap.get(asset.id)||[]).slice().reverse());
  }

  document.querySelectorAll('[data-delete]').forEach(btn => btn.onclick = async () => { await api(`/assets/${btn.dataset.delete}`, { method: 'DELETE' }); setMessage('Đã xóa asset', 'ok'); await loadAssets(); });
  document.querySelectorAll('.schedule-form').forEach(form => form.onsubmit = async (e) => { e.preventDefault(); try { const assetId = form.dataset.assetId; const formData = new FormData(form); await api(`/assets/${assetId}/schedules`, { method:'POST', body: JSON.stringify({ scan_type: formData.get('scan_type'), interval_minutes: Number(formData.get('interval_minutes')) }) }); setMessage('Đã tạo lịch quét', 'ok'); await loadAssets(); } catch (err) { setMessage(err.message); } });
  document.querySelectorAll('[data-delete-schedule]').forEach(btn => btn.onclick = async () => { await api(`/schedules/${btn.dataset.deleteSchedule}`, { method:'DELETE' }); setMessage('Đã xóa lịch quét', 'ok'); await loadAssets(); });
  document.querySelectorAll('[data-compare]').forEach(btn => btn.onclick = async () => {
    const assetId = btn.dataset.compare; const select = document.getElementById(`compare-type-${assetId}`); const root = document.getElementById(`compare-result-${assetId}`);
    const data = await api(`/assets/${assetId}/compare?scan_type=${select.value}`).catch(err => ({ message: err.message }));
    root.innerHTML = data.message ? esc(data.message) : `Trước: ${data.previous_count} | Hiện tại: ${data.current_count} | Added: ${data.added_count} | Removed: ${data.removed_count}`;
  });
  document.querySelectorAll('[data-export-csv]').forEach(btn => btn.onclick = async () => downloadFile(`/assets/${btn.dataset.exportCsv}/export.csv`, 'text/csv', `asset-${btn.dataset.exportCsv}.csv`));
  document.querySelectorAll('[data-export-pdf]').forEach(btn => btn.onclick = async () => downloadFile(`/assets/${btn.dataset.exportPdf}/export.pdf`, 'application/pdf', `asset-${btn.dataset.exportPdf}.pdf`));
}

async function downloadFile(path, mime, filename) {
  try {
    const blob = await api(path);
    const url = URL.createObjectURL(blob instanceof Blob ? blob : new Blob([blob], { type: mime }));
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    setMessage(`Đã export ${filename}`, 'ok');
  } catch (err) { setMessage(err.message); }
}

document.getElementById('asset-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('asset-name').value.trim();
  const type = document.getElementById('asset-type').value;
  const tags = tagsToList(document.getElementById('asset-tags').value.trim());
  try { await api('/assets', { method:'POST', body: JSON.stringify({ name, type, tags }) }); e.target.reset(); document.getElementById('asset-type').value='domain'; setMessage('Đã thêm asset', 'ok'); await loadAssets(); } catch (err) { setMessage(err.message); }
});
document.getElementById('refresh-btn').addEventListener('click', () => loadAssets().then(() => setMessage('Đã làm mới dữ liệu', 'ok')).catch(err => setMessage(err.message)));
document.getElementById('delete-all-btn').addEventListener('click', async () => { if (!confirm('Xóa tất cả assets và scan jobs?')) return; await api('/assets', { method:'DELETE' }); setMessage('Đã xóa tất cả assets', 'ok'); await loadAssets(); });
loadAssets().catch(err => setMessage(err.message));
