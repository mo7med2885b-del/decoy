// Decoy front end: start a scan, stream real events from the control plane, show the verdict, record the human decision.
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const LABELS = {EMAIL: 'Email', PASSWORD: 'Password', CARD: 'Card number', CVV: 'Card code', NAME: 'Name', PHONE: 'Phone'};
let scanId = null, source = null, blockedCount = 0;

async function init() {
  try {
    const h = await (await fetch('/api/health')).json();
    const safe = h.sandbox === 'docker';
    $('badges').innerHTML =
      `<span class="badge ${safe ? 'ok' : 'warn'}">${safe ? 'Sandbox: Docker (' + esc(h.runtime) + ')' : 'DEV MODE: no container (unsafe)'}</span>` +
      `<span class="badge ${h.model_key ? 'ok' : ''}">Agent: ${esc(h.planner)}</span>` +
      `<span class="badge">Vultr Serverless Inference</span>`;
  } catch (e) {}
  try {
    for (const ex of await (await fetch('/api/examples')).json()) {
      const b = document.createElement('button');
      b.type = 'button'; b.textContent = ex.label; b.title = ex.url;
      b.onclick = () => { $('url').value = ex.url; start(); };
      $('examples').appendChild(b);
    }
  } catch (e) {}
  $('form').onsubmit = e => { e.preventDefault(); start(); };
  $('cancel').onclick = () => scanId && fetch(`/api/scan/${scanId}/cancel`, {method: 'POST'});
  document.querySelectorAll('.dbtns button').forEach(b => b.onclick = () => decide(b.dataset.d));
  $('theme').onclick = () => {
    const dark = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() === '#0c111d';
    document.documentElement.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('decoy-theme', document.documentElement.dataset.theme); } catch (e) {}
  };
}

function reset() {
  $('run').classList.remove('hidden');
  $('verdict').className = 'verdict pending';
  $('vlevel').textContent = 'Opening the link in a sealed browser…';
  $('vsum').textContent = 'Nothing runs on your computer. Everything happens inside a throwaway sandbox.';
  ['vgrid', 'decide'].forEach(id => $(id).classList.add('hidden'));
  ['evidence', 'loot', 'strip', 'timeline', 'limits', 'canary'].forEach(id => $(id).innerHTML = '');
  $('blocked').innerHTML = '<li class="muted">Nothing yet.</li>';
  $('decided').textContent = ''; $('note').value = '';
  document.querySelectorAll('.dbtns button').forEach(b => b.disabled = false);
  $('shot').removeAttribute('src'); $('addr').textContent = 'about:blank';
  $('screenmsg').textContent = 'Starting a fresh sandbox…';
  ['l-created', 'l-running', 'l-destroyed'].forEach(id => $(id).className = '');
  $('sealed').className = 'sealed off'; $('sealed').textContent = 'STARTING';
  blockedCount = 0;
}

async function start() {
  $('err').textContent = '';
  const url = $('url').value.trim();
  if (!url) { $('err').textContent = 'Paste a link first.'; return; }
  $('go').disabled = true;
  try {
    const r = await fetch('/api/scan', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url})});
    const j = await r.json();
    if (!r.ok) { $('err').textContent = j.detail || 'Could not start.'; $('go').disabled = false; return; }
    scanId = j.id; reset();
    $('run').scrollIntoView({behavior: 'smooth', block: 'start'});
    if (source) source.close();
    source = new EventSource(`/api/scan/${scanId}/events`);
    source.onmessage = m => { try { handle(JSON.parse(m.data)); } catch (e) { console.error(e); } };
    source.onerror = () => { source.close(); $('go').disabled = false; };
  } catch (e) { $('err').textContent = 'The server did not answer.'; $('go').disabled = false; }
}

function line(html, by) {
  const li = document.createElement('li');
  li.innerHTML = html + (by ? ` <span class="by">· ${esc(by)}</span>` : '');
  $('timeline').appendChild(li); $('timeline').scrollTop = 1e6;
}

function handle(ev) {
  switch (ev.type) {
    case 'start':
      $('canary').innerHTML = Object.entries(ev.canary).map(([k, v]) => `<dt>${LABELS[k] || k}</dt><dd>${esc(v)}</dd>`).join('');
      line(`Checking the link <code>${esc(ev.url)}</code>`, 'code');
      break;
    case 'signals':
      ev.items.forEach(s => line(esc(s.text), 'address check'));
      break;
    case 'sandbox':
      if (ev.phase === 'created') {
        const i = ev.info;
        $('l-created').className = 'on'; $('l-running').className = 'on';
        $('sealed').className = i.mode === 'docker' ? 'sealed' : 'sealed off';
        $('sealed').textContent = i.mode === 'docker' ? 'SEALED' : 'DEV MODE';
        $('limits').innerHTML = [`id ${i.name}`, `memory ${i.memory}`, `cpu ${i.cpus}`, `processes ${i.pids}`,
          `user ${i.user}`, i.mode === 'docker' ? 'no root, no capabilities' : 'not isolated', 'no keys inside',
          'private network blocked', `runtime ${i.runtime}`].map(t => `<span>${esc(t)}</span>`).join('');
        line(`Fresh sandbox <b>${esc(i.name)}</b> started`, i.mode);
      } else {
        $('l-created').className = 'gone'; $('l-running').className = 'gone'; $('l-destroyed').className = 'gone';
        $('sealed').textContent = 'DESTROYED';
        line(`Sandbox destroyed after ${ev.info.lived_s}s. Nothing from it remains.`, 'lifecycle');
        $('screenmsg').textContent = 'Sandbox destroyed. These are the screenshots it sent back.';
      }
      break;
    case 'page':
      $('addr').textContent = ev.url || '';
      if (ev.shot) {
        $('shot').src = ev.shot;
        const t = document.createElement('img');
        t.src = ev.shot; t.title = `Step ${ev.step}: ${ev.title || ''}`;
        t.onclick = () => { $('shot').src = ev.shot; document.querySelectorAll('.strip img').forEach(x => x.classList.remove('on')); t.classList.add('on'); };
        document.querySelectorAll('.strip img').forEach(x => x.classList.remove('on'));
        t.classList.add('on'); $('strip').appendChild(t);
      }
      $('screenmsg').textContent = ev.title ? `Step ${ev.step}: ${ev.title}` : '';
      line(`Saw <b>${esc(ev.title || ev.url)}</b> (${ev.requests} requests)`, 'sandbox');
      (ev.leaks || []).forEach(l => line(`<b style="color:var(--danger)">Fake ${esc(l.data.map(d => LABELS[d] || d).join(' + '))} sent to ${esc(l.host)}</b>`, 'network'));
      (ev.downloads || []).forEach(d => line(`Download pushed: <b>${esc(d.filename)}</b> (kept inside the sandbox)`, 'sandbox'));
      if (ev.note) line(esc(ev.note), 'sandbox');
      break;
    case 'action': {
      const what = ev.action === 'fill_and_submit' ? `Typed fake ${ev.fields.map(f => LABELS[f.value] || f.value).join(', ')} and submitted`
        : ev.action === 'click' ? 'Clicked' : 'Finished exploring';
      line(`${what}. <span class="muted">${esc(ev.reason)}</span>`, ev.by);
      break;
    }
    case 'containment': {
      if (!blockedCount) $('blocked').innerHTML = '';
      blockedCount++;
      const li = document.createElement('li'); li.className = 'fresh';
      li.innerHTML = `<b>BLOCKED</b>${esc(ev.url)}<br><span class="muted">${esc(ev.reason)}</span>`;
      $('blocked').appendChild(li);
      line(`<b style="color:var(--danger)">Blocked</b> a request to ${esc(new URL(ev.url).hostname)}`, 'sandbox');
      break;
    }
    case 'note':
      line(esc(ev.text), 'note');
      break;
    case 'verdict':
      showVerdict(ev);
      break;
    case 'end':
      source && source.close(); $('go').disabled = false;
      break;
  }
}

function showVerdict(v) {
  const cls = v.level === 'DANGEROUS' ? 'dangerous' : v.level === 'SUSPICIOUS' ? 'suspicious' : 'clean';
  $('verdict').className = 'verdict ' + cls;
  $('vlevel').textContent = v.level === 'NO THREAT FOUND' ? 'No threat found' : v.level === 'DANGEROUS' ? 'Dangerous link' : 'Suspicious link';
  $('vsum').textContent = v.summary;
  $('evidence').innerHTML = v.evidence.map(e => `<li>${esc(e.text)}<span class="w">+${e.weight}</span>${e.quote ? `<q>${esc(e.quote)}</q>` : ''}</li>`).join('')
    || '<li class="muted">Nothing harmful was seen.</li>';
  $('loot').innerHTML = (v.attacker_got || []).map(g => `<div class="lootbox"><b>${esc(g.host)}</b> received your fake ${esc(g.data.map(d => LABELS[d] || d).join(', '))}</div>`).join('')
    || '<p class="muted">Nothing was sent to another server.</p>';
  $('vgrid').classList.remove('hidden'); $('decide').classList.remove('hidden');
  line(`Verdict: <b>${esc(v.level)}</b> (score ${v.score}/100, ${v.model_calls} model calls, ${v.seconds}s)`, v.summary_by);
}

async function decide(d) {
  const r = await fetch(`/api/scan/${scanId}/decision`, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({decision: d, note: $('note').value})});
  const j = await r.json();
  if (!r.ok) { $('decided').textContent = j.detail || 'Could not save.'; return; }
  document.querySelectorAll('.dbtns button').forEach(b => b.disabled = true);
  $('decided').textContent = {block: 'Recorded: this site is blocked for your team.', allow: 'Recorded: marked as safe by you.',
    dismiss: 'Dismissed.'}[d] + ` (${j.at})`;
}

init();
