'use strict';
const $ = id => document.getElementById(id);
let token = location.hash.slice(1);
if (/^[a-f0-9]{64}$/.test(token)) {
  sessionStorage.setItem('tbcryptToken', token);
  history.replaceState(null, '', location.pathname + location.search);
} else token = sessionStorage.getItem('tbcryptToken') || '';
let state = null, prefilled = false, backupRequired = false;
let jobId = '', jobOutput = '', pollTimer = null, idleTimer = null;
function showError(message) { $('error').textContent = message || ''; $('error').hidden = !message; $('error').className = 'notice error'; $('error').setAttribute('role', 'alert'); }
function showSuccess(message) { showError(message); $('error').className = 'notice success'; $('error').setAttribute('role', 'status'); }
function showView(view) { for (const id of ['connect', 'create', 'unlock', 'backup', 'workspace']) $(id).hidden = id !== view; }
function armIdleCheck() {
  clearTimeout(idleTimer);
  if (state?.unlocked) idleTimer = setTimeout(() => refreshState().catch(e => showError(e.message)), 15 * 60 * 1000 + 250);
}
async function api(path, body) {
  const options = {headers: {'X-TBCrypt-Token': token}, cache: 'no-store'};
  if (body !== undefined) { options.method = 'POST'; options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body); }
  const response = await fetch('/api/' + path, options);
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 423) { if (state) state.unlocked = false; showView('unlock'); }
    if (response.status === 401 && path !== 'unlock' && path !== 'change-password') showView('connect');
    const error = new Error(data.error || 'Something went wrong. Please try again.'); error.status = response.status; throw error;
  }
  armIdleCheck(); return data;
}
async function refreshState() {
  state = await api('state');
  if (!state.hasKey) showView('create');
  else if (!state.unlocked) showView('unlock');
  else if (backupRequired) showView('backup');
  else {
    showView('workspace'); $('metadataBanner').hidden = state.exiftool;
    if (!prefilled) {
      $('encryptSource').value = state.last.encryptSrc || ''; $('encryptOutput').value = state.last.encryptOut || '';
      $('decryptSource').value = state.last.decryptSrc || ''; $('decryptOutput').value = state.last.decryptOut || ''; prefilled = true;
    }
  }
  armIdleCheck();
}
function cleanPath(path) { path = path.trim(); return path.startsWith('"') && path.endsWith('"') ? path.slice(1, -1) : path; }
async function submitting(form, work) {
  const button = form.querySelector('button[type=submit]'); button.disabled = true; showError('');
  try { await work(); } catch (error) { showError(error.message); } finally { button.disabled = Boolean(jobId); }
}
$('setupForm').addEventListener('submit', event => {
  event.preventDefault(); submitting(event.currentTarget, async () => {
    const password = $('setupPassword').value;
    if (password !== $('setupConfirm').value) throw new Error('The passwords don’t match. Please type them again.');
    try {
      const result = await api('setup', {password}); backupRequired = true; $('keyfilePath').textContent = 'Your keyfile: ' + result.keyfile; await refreshState();
    } finally { $('setupForm').reset(); }
  });
});
$('unlockForm').addEventListener('submit', event => {
  event.preventDefault(); submitting(event.currentTarget, async () => {
    try { await api('unlock', {password: $('unlockPassword').value}); await refreshState(); }
    finally { $('unlockForm').reset(); }
  });
});
async function exportKey() {
  showError('');
  try { const result = await api('export-key', {}); if (!result.canceled) { $('keyfilePath').textContent = 'Backup saved: ' + result.path; if (!backupRequired) showSuccess('Keyfile backup saved. Keep its password safe too.'); } }
  catch (error) { showError(error.message); }
}
$('firstBackup').addEventListener('click', exportKey); $('exportKey').addEventListener('click', exportKey);
$('backupAcknowledged').addEventListener('change', () => { $('continue').disabled = !$('backupAcknowledged').checked; });
$('continue').addEventListener('click', () => { backupRequired = false; refreshState().catch(e => showError(e.message)); });
function tab(which) {
  for (const name of ['encrypt', 'decrypt']) { const active = name === which; $(name + 'Panel').hidden = !active; $(name + 'Tab').classList.toggle('active', active); $(name + 'Tab').setAttribute('aria-selected', String(active)); }
}
$('encryptTab').addEventListener('click', () => tab('encrypt')); $('decryptTab').addEventListener('click', () => tab('decrypt'));
for (const button of document.querySelectorAll('.picker')) button.addEventListener('click', async () => {
  button.disabled = true; showError('');
  try { const result = await api('pick', {kind: button.dataset.kind, title: 'tbcrypt — ' + (button.dataset.kind === 'files' ? 'choose encrypted files' : 'choose a folder')}); if (!result.canceled) $(button.dataset.target).value = result.paths.join('\n'); }
  catch (error) { showError(error.message); } finally { button.disabled = false; }
});
function busy(value) { $('encryptButton').disabled = value; $('decryptButton').disabled = value; }
async function startJob(kind, body) {
  const result = await api(kind, body); jobId = result.jobId; jobOutput = body.output;
  sessionStorage.setItem('tbcryptJob', JSON.stringify({id: jobId, output: jobOutput})); busy(true); $('progressPanel').hidden = false;
  await pollJob();
}
$('encryptForm').addEventListener('submit', event => {
  event.preventDefault(); submitting(event.currentTarget, () => startJob('encrypt', {source: cleanPath($('encryptSource').value), output: cleanPath($('encryptOutput').value), moveOriginals: $('moveOriginals').checked}));
});
$('decryptForm').addEventListener('submit', event => {
  event.preventDefault(); submitting(event.currentTarget, () => startJob('decrypt', {sources: $('decryptSource').value.split('\n').map(cleanPath).filter(Boolean), output: cleanPath($('decryptOutput').value)}));
});
async function pollJob() {
  clearTimeout(pollTimer); if (!jobId) return;
  try {
    const job = await api('jobs/' + jobId);
    $('progressPanel').hidden = false; const running = job.state === 'running';
    const verb = job.kind === 'encrypt' ? 'encrypted' : 'decrypted';
    $('progressTitle').textContent = running ? (job.kind === 'encrypt' ? 'Encrypting your files…' : 'Restoring your files…') : job.state === 'canceled' ? 'Job canceled' : job.failed ? 'Finished with some problems' : 'Your files are ready';
    $('progressBar').max = Math.max(job.total, 1); $('progressBar').value = job.done + job.failed;
    $('progressCount').textContent = `${job.done} of ${job.total} files ${verb}${job.failed ? ` · ${job.failed} failed` : ''}`;
    $('currentFile').textContent = running ? job.current || 'Finding your files…' : '';
    $('cancelJob').hidden = !running; $('cancelJob').disabled = false; $('openOutput').hidden = running || !jobOutput;
    $('resultMessage').textContent = running ? '' : job.state === 'canceled' ? 'Canceled. Completed files are kept; unfinished files have not been moved.' : job.kind === 'encrypt' ? `${job.failed ? 'Finished' : 'Done'} — ${job.done} files encrypted. Upload the contents of ${jobOutput} to TeraBox.` : `${job.failed ? 'Finished' : 'Done'} — ${job.done} files decrypted into ${jobOutput}.`;
    $('fileMessages').replaceChildren();
    for (const item of job.items) for (const field of ['error', 'warning']) if (item[field]) { const li = document.createElement('li'); li.textContent = (item.path ? item.path + ': ' : '') + item[field]; $('fileMessages').appendChild(li); }
    if (running) pollTimer = setTimeout(pollJob, 500);
    else { jobId = ''; busy(false); sessionStorage.removeItem('tbcryptJob'); armIdleCheck(); }
  } catch (error) {
    showError(error.message);
    if (error.status === 404 || error.status === 401) { jobId = ''; busy(false); sessionStorage.removeItem('tbcryptJob'); }
    else pollTimer = setTimeout(pollJob, 1500);
  }
}
$('cancelJob').addEventListener('click', async () => {
  $('cancelJob').disabled = true;
  try { await api('jobs/' + jobId + '/cancel', {}); await pollJob(); } catch (error) { showError(error.message); $('cancelJob').disabled = false; }
});
$('openOutput').addEventListener('click', () => api('open', {path: jobOutput}).catch(e => showError(e.message)));
$('lockButton').addEventListener('click', async () => {
  showError('');
  try { await api('lock', {}); clearTimeout(pollTimer); jobId = ''; busy(false); await refreshState(); } catch (error) { showError(error.message); }
});
$('changePassword').addEventListener('click', () => { $('passwordForm').reset(); $('passwordError').textContent = ''; $('passwordDialog').showModal(); });
$('closePassword').addEventListener('click', () => { $('passwordForm').reset(); $('passwordDialog').close(); });
$('passwordDialog').addEventListener('cancel', () => $('passwordForm').reset());
$('passwordForm').addEventListener('submit', async event => {
  event.preventDefault(); const button = event.currentTarget.querySelector('button[type=submit]'); button.disabled = true;
  try {
    if ($('newPassword').value !== $('confirmNew').value) throw new Error('The new passwords don’t match.');
    await api('change-password', {old: $('oldPassword').value, new: $('newPassword').value}); $('passwordDialog').close(); showSuccess('Password changed. Please save a fresh keyfile backup.');
  } catch (error) { $('passwordError').textContent = error.message; } finally { $('passwordForm').reset(); button.disabled = false; }
});
window.addEventListener('focus', () => { if (!backupRequired) refreshState().catch(e => showError(e.message)); });
(async () => {
  if (!token) { showView('connect'); return; }
  try {
    await refreshState();
    const saved = JSON.parse(sessionStorage.getItem('tbcryptJob') || 'null');
    if (state.unlocked && (state.activeJob || saved)) { jobId = state.activeJob || saved.id; jobOutput = state.activeOutput || saved.output; busy(true); await pollJob(); }
  } catch (error) { showError(error.message); }
})();
