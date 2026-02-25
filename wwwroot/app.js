async function postGenerate(body) {
  const res = await fetch('/api/generate-report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res;
}

document.getElementById('generate').addEventListener('click', async () => {
  const btn = document.getElementById('generate');
  const status = document.getElementById('status');
  btn.disabled = true; status.textContent = 'Working...';

  const reqsRaw = document.getElementById('reqs').value.trim();
  const reposRaw = document.getElementById('repos').value.trim();
  const format = document.getElementById('format').value;
  const requirementPattern = document.getElementById('pattern')?.value?.trim();

  const requirementIds = reqsRaw ? reqsRaw.split(/[,\n]+/).map(s => s.trim()).filter(Boolean) : [];
  const repositories = reposRaw ? reposRaw.split(/[,\n]+/).map(s => s.trim()).filter(Boolean) : [];

  try {
    const res = await postGenerate({ requirementIds, repositories, format, requirementPattern });

    if (!res.ok) {
      const text = await res.text();
      status.textContent = 'Error: ' + text.substring(0, 200);
      btn.disabled = false; return;
    }

    if (format === 'html') {
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      status.textContent = 'Opened report in new tab';
    } else if (format === 'json' || format === 'csv') {
      const blob = await res.blob();
      const ok = res.headers.get('content-disposition');
      const filename = ok ? ok.split('filename=')[1] || 'report' : (format === 'json' ? 'traceability-report.json' : 'traceability-report.csv');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = filename.replace(/[^a-zA-Z0-9._-]/g,'');
      document.body.appendChild(a);
      a.click();
      a.remove();
      status.textContent = 'Downloaded ' + a.download;
    }
  } catch (err) {
    status.textContent = 'Error: ' + err.message;
  } finally {
    btn.disabled = false;
  }
});
