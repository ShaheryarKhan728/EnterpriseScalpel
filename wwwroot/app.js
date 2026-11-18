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
const allActionButtons = () => document.querySelectorAll('#generate, .js-sample-report, #impactSubmit, #impactSample');

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

// fixedBase (optional) always names the file, e.g. so the sample doesn't overwrite a real report.
async function generateReport(body, fallbackBase, fixedBase) {
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
    const filename = fixedBase ? `${fixedBase}.${format}` : filenameFor(res, format, fallbackBase);
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
    generateReport(SAMPLE_REQUEST, 'traceability-report-sample', 'traceability-report-sample');
  });
});

// ---------------------------------------------------------------------------
// "What will my change affect?"
// ---------------------------------------------------------------------------
const impactForm = document.getElementById('impactForm');
const impactResults = document.getElementById('impactResults');
const SAMPLE_IMPACT_TARGET = 'ReportService.cs';

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text; // textContent: repo data is never parsed as HTML
  return node;
}

function requirementChip(req) {
  const safeUrl = req.url && /^https?:\/\//i.test(req.url) ? req.url : null;
  const chip = el(safeUrl ? 'a' : 'span', 'req-chip', req.id);
  if (safeUrl) {
    chip.href = safeUrl;
    chip.target = '_blank';
    chip.rel = 'noopener noreferrer';
    chip.title = 'Open ' + req.id + ' in your PM tool';
  }
  return chip;
}

function renderImpact(data) {
  impactResults.replaceChildren();

  const count = data.requirements.length;
  impactResults.appendChild(el('p', 'impact-summary', count === 0
    ? 'No requirements found for these files or methods.'
    : `Retest ${count} requirement${count === 1 ? '' : 's'}:`));

  if (count > 0) {
    const chips = el('div', 'req-chips');
    data.requirements.forEach(r => chips.appendChild(requirementChip(r)));
    impactResults.appendChild(chips);

    const detail = el('div', 'impact-detail');
    detail.appendChild(el('h3', null, 'Where they come from'));
    const list = el('ul');
    data.targets.forEach(t => t.matches.forEach(m => {
      const item = el('li');
      item.appendChild(el('code', null, m.method ? `${m.file} :: ${m.method}` : m.file));
      item.appendChild(document.createTextNode(' : ' + m.requirements.join(', ')));
      list.appendChild(item);
    }));
    detail.appendChild(list);
    impactResults.appendChild(detail);
  }

  if (data.unmatched.length > 0) {
    impactResults.appendChild(el('p', 'impact-unmatched',
      'Not found: ' + data.unmatched.join(', ') +
      '. Check the spelling, or no commit with a requirement ID has changed it yet.'));
  }
}

async function runImpact(body) {
  setBusy(true);
  impactResults.replaceChildren(el('p', 'impact-detail', 'Checking…'));
  try {
    const res = await fetch('/api/impact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      const text = await res.text();
      impactResults.replaceChildren(el('p', 'impact-error', 'Error: ' + text.substring(0, 200)));
      return;
    }
    renderImpact(await res.json());
  } catch (err) {
    impactResults.replaceChildren(el('p', 'impact-error', 'Error: ' + err.message));
  } finally {
    setBusy(false);
    impactResults.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

const splitList = raw => raw ? raw.split(/[,\n]+/).map(s => s.trim()).filter(Boolean) : [];

impactForm.addEventListener('submit', e => {
  e.preventDefault();
  runImpact({
    repositories: splitList(document.getElementById('impactRepos').value.trim()),
    targets: splitList(document.getElementById('impactTargets').value.trim())
  });
});

document.getElementById('impactSample').addEventListener('click', () => {
  document.getElementById('impactRepos').value = SAMPLE_REQUEST.repositories[0];
  document.getElementById('impactTargets').value = SAMPLE_IMPACT_TARGET;
  runImpact({ repositories: SAMPLE_REQUEST.repositories, targets: [SAMPLE_IMPACT_TARGET] });
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
