// Must match SampleRepository / SampleRequirementId in scalpel.config.json so the
// server can answer from its pre-generated sample report.
const SAMPLE_REQUEST = {
  requirementIds: ['REQ-123'],
  repositories: ['https://github.com/ShaheryarKhan728/EnterpriseScalpel'],
  format: 'html',
  requirementPattern: '(?i)REQ-\\d+',
  pmPlatform: 'clickup'
};

const statusEl = document.getElementById('status');
const loaderEl = document.getElementById('loaderContainer');
const form = document.getElementById('reportForm');
const allActionButtons = () => document.querySelectorAll('#generate, .js-sample-report');

function setStatus(type, message) {
  statusEl.classList.remove('loading', 'success', 'error');
  if (type) statusEl.classList.add(type);
  statusEl.textContent = message || '';
}

// One busy state for every action: full-screen loader + all action buttons disabled.
function setBusy(busy) {
  loaderEl.classList.toggle('active', busy);
  loaderEl.setAttribute('aria-hidden', busy ? 'false' : 'true');
  document.body.setAttribute('aria-busy', busy ? 'true' : 'false');
  allActionButtons().forEach(b => { b.disabled = busy; });
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function filenameFor(res, format, fallbackBase) {
  const disposition = res.headers.get('content-disposition');
  const fromHeader = disposition ? (disposition.split('filename=')[1] || '') : '';
  const cleaned = fromHeader.replace(/[^a-zA-Z0-9._-]/g, '');
  return cleaned || `${fallbackBase}.${format}`;
}

async function generateReport(body, fallbackBase) {
  setBusy(true);
  setStatus('loading', 'Generating report…');
  try {
    const res = await fetch('/api/generate-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      const text = await res.text();
      setStatus('error', 'Error: ' + text.substring(0, 200));
      statusEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }

    const format = (body.format || 'json').toLowerCase();
    const blob = await res.blob();
    const filename = filenameFor(res, format, fallbackBase);
    downloadBlob(blob, filename);
    setStatus('success', 'Downloaded ' + filename);
  } catch (err) {
    setStatus('error', 'Error: ' + err.message);
    statusEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } finally {
    setBusy(false);
  }
}

// Every "Generate a sample report" button (hero, below the use cases, and in the form).
document.querySelectorAll('.js-sample-report').forEach(btn => {
  btn.addEventListener('click', e => {
    e.preventDefault();
    generateReport(SAMPLE_REQUEST, 'traceability-report-sample');
  });
});

// Handle the form's submit event (not the button click) so the browser never
// performs a real form submission that reloads the page mid-request.
form.addEventListener('submit', e => {
  e.preventDefault();

  const split = raw => raw ? raw.split(/[,\n]+/).map(s => s.trim()).filter(Boolean) : [];
  const body = {
    requirementIds: split(document.getElementById('reqs').value.trim()),
    repositories: split(document.getElementById('repos').value.trim()),
    format: document.getElementById('format').value,
    requirementPattern: document.getElementById('pattern').value.trim() || null,
    pmPlatform: document.getElementById('pmPlatform').value || null
  };

  generateReport(body, 'traceability-report');
});
