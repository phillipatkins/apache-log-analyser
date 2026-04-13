<?php
if (!file_exists(__DIR__ . '/config.php')) {
    header('Location: install.php');
    exit;
}
require __DIR__ . '/config.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Apache Log Security Analyser</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>

<div class="topbar">
  <div>
    <h1>Apache Log Security Analyser</h1>
    <div class="sub">Upload any Apache or Nginx access log — get a security report instantly</div>
  </div>
  <a href="install.php" class="text-muted" style="font-size:12px">Setup</a>
</div>

<div class="container">

  <div class="card" id="upload-card">
    <h2>Upload Log File</h2>
    <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
      <div class="icon">📄</div>
      <strong id="file-label">Click or drag a log file here</strong>
      <p>Supports .log and .log.gz — Apache or Nginx combined format</p>
    </div>
    <input type="file" id="file-input" accept=".log,.gz,.txt">

    <div class="form-row" style="margin-top:16px">
      <button class="btn btn-primary" id="analyse-btn" disabled onclick="runAnalysis()">Analyse Log</button>
      <button class="btn btn-secondary" onclick="loadSample()">Try Sample Log</button>
    </div>
  </div>

  <div class="spinner" id="spinner">
    ⏳ Analysing log file...
  </div>

  <div id="results">
    <div class="stat-grid" id="stats"></div>
    <div id="findings-card"></div>
    <div id="recommendations-card"></div>
  </div>

</div>

<script>
let selectedFile = null;

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const analyseBtn = document.getElementById('analyse-btn');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

function setFile(file) {
  selectedFile = file;
  document.getElementById('file-label').textContent = file.name + ' (' + formatBytes(file.size) + ')';
  analyseBtn.disabled = false;
}

function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

function loadSample() {
  fetch('process.php?sample=1')
    .then(r => r.json())
    .then(data => renderResults(data))
    .catch(e => alert('Error: ' + e.message));
  showSpinner();
}

function runAnalysis() {
  if (!selectedFile) return;
  const form = new FormData();
  form.append('logfile', selectedFile);
  showSpinner();
  fetch('process.php', { method: 'POST', body: form })
    .then(r => r.json())
    .then(data => renderResults(data))
    .catch(e => { hideSpinner(); alert('Error: ' + e.message); });
}

function showSpinner() {
  document.getElementById('spinner').classList.add('show');
  document.getElementById('results').classList.remove('show');
}

function hideSpinner() {
  document.getElementById('spinner').classList.remove('show');
}

function renderResults(d) {
  hideSpinner();
  if (d.error) { alert('Error: ' + d.error); return; }

  const erColour = d.error_rate > 10 ? 'text-red' : 'text-green';

  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="val">${d.total_requests.toLocaleString()}</div><div class="lbl">Total Requests</div></div>
    <div class="stat"><div class="val">${d.unique_ips}</div><div class="lbl">Unique IPs</div></div>
    <div class="stat"><div class="val ${erColour}">${d.error_rate}%</div><div class="lbl">Error Rate</div></div>
    <div class="stat"><div class="val text-red">${d.suspicious_ips.length}</div><div class="lbl">Suspicious IPs</div></div>
    <div class="stat"><div class="val text-muted" style="font-size:14px">${d.peak_window}</div><div class="lbl">Peak Window</div></div>
  `;

  let findingsHtml = '';
  if (d.suspicious_ips.length === 0) {
    findingsHtml = '<div class="alert alert-ok">No suspicious IPs detected in this log file.</div>';
  } else {
    let rows = '';
    d.suspicious_ips.forEach(ip => {
      const threats = ip.threats.map(t => {
        const cls = t === 'BRUTE_FORCE' ? 'badge-red' : t === 'SCANNER' ? 'badge-orange' : 'badge-amber';
        return `<span class="badge ${cls}">${t}</span>`;
      }).join(' ');
      const paths = ip.attack_paths.slice(0, 5).map(p => `<span class="mono text-red">${p}</span>`).join(', ')
                   + (ip.attack_paths.length > 5 ? ` <span class="text-muted">+${ip.attack_paths.length-5} more</span>` : '');
      const brute = ip.brute_force_attempts > 0 ? `<br><span class="text-muted" style="font-size:11px">${ip.brute_force_attempts} login POST requests</span>` : '';
      rows += `<tr class="row-red">
        <td class="mono">${ip.ip}</td>
        <td>${threats}</td>
        <td>${ip.total_requests} <span class="text-muted">(${ip.error_pct}% errors)</span></td>
        <td>${paths}${brute}</td>
      </tr>`;
    });
    findingsHtml = `<div class="card">
      <h2>Suspicious IPs</h2>
      <table><thead><tr><th>IP Address</th><th>Threat Type</th><th>Requests</th><th>Attack Paths</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  }
  document.getElementById('findings-card').innerHTML = findingsHtml;

  // Recommendations
  const ips = d.suspicious_ips.map(i => i.ip);
  let recs = '';
  if (ips.length > 0) {
    const cmds = ips.slice(0,10).map(ip => `<div class="cmd-block">iptables -A INPUT -s ${ip} -j DROP</div>`).join('');
    recs += `<div style="margin-bottom:14px"><strong class="text-red">Block these IPs:</strong>${cmds}</div>`;
  }
  if (d.suspicious_ips.some(i => i.threats.includes('BRUTE_FORCE'))) {
    recs += `<div class="alert alert-warn">⚠ Brute force detected — enable login rate limiting (fail2ban recommended)</div>`;
  }
  if (d.error_rate > 10) {
    recs += `<div class="alert alert-warn">⚠ High error rate (${d.error_rate}%) — server may be under strain</div>`;
  }
  recs += `<div class="alert alert-info">Also check: <a href="https://abuseipdb.com" target="_blank">abuseipdb.com</a> — cross-reference flagged IPs against known bad actors</div>`;

  document.getElementById('recommendations-card').innerHTML = `<div class="card"><h2>Recommendations</h2>${recs}</div>`;
  document.getElementById('results').classList.add('show');
}
</script>
</body>
</html>
