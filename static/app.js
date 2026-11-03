// Decoy front end: start a scan, stream the control plane's real events, type the agent's notes live,
// show the verdict and record the human decision. Every event handler is guarded so one bad event cannot stall the page.
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const LABELS = {EMAIL: 'Email', PASSWORD: 'Password', CARD: 'Card number', CVV: 'Card code', NAME: 'Name', PHONE: 'Phone'};
let scanId = null, source = null, mode = 'simple', evCount = 0;
const count = {steps: 0, blocked: 0, leaks: 0};

/* ---------- live trace: lines type out one after another ---------- */
const queue = [];
let typing = false;
function trace(text, who, cls = '') {
  queue.push({text, who, cls});
  if (!typing) nextLine();
}
function nextLine() {
  const item = queue.shift();
  if (!item) { typing = false; return; }
  typing = true;
  const li = document.createElement('li');
  li.className = item.cls + ' typing';
  li.innerHTML = `<span class="who">${esc(item.who)}</span><span class="txt"></span>`;
  $('trace').appendChild(li);
  const txt = li.querySelector('.txt');
  const speed = queue.length > 4 ? 2 : queue.length > 1 ? 7 : 14;  // catch up when events arrive fast
  let i = 0;
  (function tick() {
    i = Math.min(item.text.length, i + (queue.length > 4 ? 6 : 2));
    txt.textContent = item.text.slice(0, i);
    $('trace').scrollTop = 1e6;
    if (i < item.text.length) setTimeout(tick, speed);
    else { li.classList.remove('typing'); setTimeout(nextLine, 60); }
  })();
}

/* ---------- progress UI ---------- */
function stepTo(n) {
  document.querySelectorAll('#steps li').forEach(li => {
    const s = +li.dataset.s;
    li.className = s < n ? 'done' : s === n ? 'on' : '';
  });
  $('stepsFill').style.transform = `scaleX(${Math.min(1, n / 3)})`;
}
function node() {}  // the old small graph is gone: workflow.js draws the panel from the same events
function stat(id, v, hot) { $(id).textContent = v; $(id).parentElement.classList.toggle('hot', !!hot); }


/* ---------- swarm cards, memory banner, ask box, history, QR ---------- */
const LEVEL_TXT = {'DANGEROUS': 'Dangerous', 'SUSPICIOUS': 'Suspicious', 'LOOKS SAFE': 'Looks safe', 'NO THREAT FOUND': 'No threat'};
function levelCls(l) { return l === 'DANGEROUS' ? 'bad' : l === 'SUSPICIOUS' ? 'warn' : 'ok'; }
function buildSwarm(list) {
  $('swarm').innerHTML = ''; $('swarmwarn').classList.add('hidden');
  $('swarmcard').classList.toggle('hidden', !(list && list.length > 1));
  (list || []).forEach(p => {
    const d = document.createElement('div'); d.className = 'sw'; d.id = 'sw-' + p.id;
    d.innerHTML = `<div class="swh"><b>${esc(p.name)}</b><span>${esc(p.device)}</span></div><div class="swimg"><span class="small">waiting…</span></div>
      <div class="swt small">opening the link…</div><div class="swchip"></div>`;
    $('swarm').appendChild(d);
  });
}
function swUpdate(id, o) {
  const d = $('sw-' + id); if (!d) return;
  if (o.shot) d.querySelector('.swimg').innerHTML = `<img src="${o.shot}" alt="">`;
  if (o.title != null) d.querySelector('.swt').textContent = o.title ? `Saw: ${o.title}` : 'Saw a page';
  const bits = [];
  if ((o.asked || []).length) bits.push('asked for ' + o.asked.map(x => (LABELS[x] || x).toLowerCase()).join(' + '));
  if ((o.leaks || []).length) bits.push('fake data sent away');
  const chip = d.querySelector('.swchip');
  chip.innerHTML = (o.level ? `<i class="${levelCls(o.level)}">${LEVEL_TXT[o.level] || o.level}</i>` : '') + bits.map(b => `<i class="bad">${esc(b)}</i>`).join('');
}
function showMemory(m) {
  const box = $('memory'); const parts = [];
  if (m && (m.campaign || []).length) {
    const hosts = [...new Set(m.campaign.map(c => c.shared_server))];
    parts.push(`<b>Linked to a campaign.</b> ${m.campaign.length} earlier scan(s) sent stolen data to the same server (${esc(hosts.join(', '))}): ` +
      esc([...new Set(m.campaign.map(c => c.host))].slice(0, 4).join(', ')) + '.');
  }
  if (m && (m.seen_before || []).length) {
    const l = m.seen_before[0];
    parts.push(`We have scanned this site ${m.seen_before.length} time(s) before. Last result: <b>${esc(LEVEL_TXT[l.level] || l.level)}</b>.`);
  }
  box.innerHTML = parts.map(p => `<p>${p}</p>`).join(''); box.classList.toggle('hidden', !parts.length);
}
const ASK_CHIPS = ['Is it safe to open?', 'What did the attacker get?', 'Why this verdict?', 'Did every visitor see the same page?'];
function initAsk() {
  $('askchips').innerHTML = '';
  ASK_CHIPS.forEach(q => { const b = document.createElement('button'); b.type = 'button'; b.textContent = q; b.onclick = () => ask(q); $('askchips').appendChild(b); });
  $('askform').onsubmit = e => { e.preventDefault(); ask($('askq').value); };
}
async function ask(q) {
  q = (q || '').trim(); if (!q || !scanId) return;
  $('askq').value = q; $('askout').classList.remove('hidden'); $('askout').textContent = 'Thinking…';
  try {
    const r = await fetch(`/api/scan/${scanId}/ask`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({question: q})});
    const j = await r.json();
    if (!r.ok) { $('askout').textContent = j.detail || 'Could not answer.'; return; }
    $('askout').innerHTML = ''; const p = document.createElement('p'); $('askout').appendChild(p); typeInto(p, j.answer);
    $('askout').insertAdjacentHTML('beforeend', `<small class="small">answered from this scan's evidence · ${esc(j.by)}</small>`);
  } catch (e) { $('askout').textContent = 'The server did not answer.'; }
}
function ago(t) { const s = Math.max(1, Date.now() / 1000 - t); return s < 90 ? 'just now' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 129600 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; }
async function refreshHistory() {
  try {
    const rows = await (await fetch('/api/history')).json();
    $('histcard').classList.toggle('hidden', !rows.length);
    $('hist').innerHTML = rows.map(r => {
      const ex = JSON.parse(r.exfil || '[]');
      return `<li data-url="${esc(r.url)}"><i class="${levelCls(r.level)}">${esc(LEVEL_TXT[r.level] || r.level)}</i><span class="hu">${esc(r.host)}</span>` +
        `${r.cloaking ? '<em>cloaked</em>' : ''}${ex.length ? `<em>sent data to ${esc(ex[0])}</em>` : ''}${r.decision ? `<em>you: ${esc(r.decision)}</em>` : ''}<small>${ago(r.at)}</small><button class="rescan" type="button" title="Scan again">↻</button></li>`;
    }).join('');
    document.querySelectorAll('#hist li').forEach(li => li.querySelector('.rescan').onclick = () => { $('url').value = li.dataset.url; start(); });
  } catch (e) {}
}
function renderReport(r) {
  const box = $('report'); box.classList.remove('hidden'); $('invbar').classList.add('hidden');
  const iocRows = r.iocs.map(i => `<tr><td>${esc(i.type)}</td><td><code>${esc(i.value)}</code></td><td>${esc(i.role)}</td></tr>`).join('');
  box.innerHTML = `<div class="rh"><div><span class="lbl">Incident report ${esc(r.id)} · ${esc(r.generated_at)}</span><h4>${esc(r.headline)}</h4></div>`
    + `<div class="rdl"><a class="btn" href="/api/scan/${scanId}/report.md">Download .md</a><a class="btn" href="/api/scan/${scanId}/report.json">Download .json</a></div></div>`
    + `<div class="rcols"><div><h5>How the scam works</h5><ol>${r.how_it_works.map(s => `<li>${esc(s)}</li>`).join('')}</ol>`
    + `<h5>Suggested ATT&amp;CK mapping</h5><ul>${r.techniques.map(t => `<li><b>${esc(t.id || 'no id')}</b> ${esc(t.name)}<br><small class="small">${esc(t.why)}</small></li>`).join('')}</ul></div>`
    + `<div><h5>Recommended actions</h5><ul>${r.actions.map(a => `<li>${esc(a)}</li>`).join('')}</ul></div></div>`
    + `<h5>Indicators of compromise <button class="rescan" id="copyioc" type="button" title="Copy all">⧉</button></h5><div class="tw"><table class="ioc"><thead><tr><th>Type</th><th>Value</th><th>Role</th></tr></thead><tbody>${iocRows}</tbody></table></div>`
    + `<p class="small">${esc(r.note)}</p>`;
  $('copyioc').onclick = () => { try { navigator.clipboard.writeText(r.iocs.map(i => i.value).join('\n')); $('copyioc').textContent = '✓'; } catch (e) {} };
}
async function investigate() {
  if (!scanId) return; $('invbtn').disabled = true;
  try {
    const r = await fetch(`/api/scan/${scanId}/investigate`, {method: 'POST'}); const j = await r.json();
    if (!r.ok) { $('invbar').insertAdjacentHTML('beforeend', `<span class="err">${esc(j.detail || 'Could not start.')}</span>`); $('invbtn').disabled = false; return; }
    if (source) source.close(); source = new EventSource(`/api/scan/${scanId}/events?since=${j.since}`);
    source.onmessage = m => { try { handle(JSON.parse(m.data)); } catch (e) { console.error(e); } };
    source.onerror = () => source.close();
  } catch (e) { $('invbtn').disabled = false; }
}
function initQr() {
  $('qrfile').onchange = async () => {
    const f = $('qrfile').files[0]; if (!f) return; $('qrnote').textContent = 'Reading the QR code…';
    try {
      const r = await fetch('/api/qr', {method: 'POST', headers: {'Content-Type': 'application/octet-stream'}, body: await f.arrayBuffer()});
      const j = await r.json();
      if (!r.ok) { $('qrnote').textContent = j.detail || 'Could not read it.'; $('qrfile').value = ''; return; }
      $('qrnote').textContent = 'The QR code contains: ' + j.url; $('url').value = j.url; start();
    } catch (e) { $('qrnote').textContent = 'The server did not answer.'; }
    $('qrfile').value = '';
  };
}

async function refreshHealth() {
  try {
    const h = await (await fetch('/api/health')).json();
    const sealed = h.sandbox === 'docker';
    $('pSandbox').textContent = sealed ? `Sandbox: Docker (${h.runtime})` : 'Dev mode: not sealed';
    $('pSandbox').className = 'pill ' + (sealed ? 'ok' : 'warn');
    $('pAgent').textContent = 'Agent: ' + h.planner;
    $('pAgent').className = 'pill' + (h.model_key ? ' ok' : '');
    $('pSpend').textContent = `$${(h.today.usd || 0).toFixed(2)} today · cap $${h.caps.usd_per_day}`;
  } catch (e) {}
}

async function init() {
  refreshHealth(); refreshHistory(); initAsk(); initQr();
  try {
    for (const ex of await (await fetch('/api/examples')).json()) {
      const b = document.createElement('button');
      b.type = 'button'; b.textContent = ex.label; b.title = ex.url;
      b.onclick = () => { $('url').value = ex.url; start(); };
      $('examples').appendChild(b);
    }
  } catch (e) {}
  $('form').onsubmit = e => { e.preventDefault(); start(); };
  document.querySelectorAll('#modes button').forEach(b => b.onclick = () => { mode = b.dataset.mode; document.querySelectorAll('#modes button').forEach(x => x.classList.toggle('on', x === b)); });
  $('invbtn').onclick = investigate;
  $('theme').onclick = () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('decoy-theme', next); } catch (e) {}
  };
  $('cancel').onclick = () => scanId && fetch(`/api/scan/${scanId}/cancel`, {method: 'POST'});
  document.querySelectorAll('.decide button').forEach(b => b.onclick = () => decide(b.dataset.d));
}

function reset() {
  $('run').classList.remove('hidden');
  $('intake').classList.add('compact');
  document.body.dataset.risk = 'idle'; $('riskbar').hidden = true;
  $('vlevel').textContent = 'Working…';
  $('vsum').textContent = 'The sealed browser is opening the link. Nothing runs on your device.';
  $('vmeta').innerHTML = ''; $('ringNum').textContent = '–'; $('ringFg').style.strokeDashoffset = 188.5;
  ['vgrid', 'decide'].forEach(id => $(id).classList.add('hidden'));
  ['evidence', 'loot', 'strip', 'trace', 'limits', 'canary'].forEach(id => $(id).innerHTML = '');
  $('blocked').innerHTML = '<li class="small">Nothing yet.</li>';
  $('decided').textContent = ''; $('note').value = '';
  document.querySelectorAll('.decide button').forEach(b => b.disabled = false);
  $('shot').removeAttribute('src'); $('addr').textContent = 'about:blank';
  $('screenmsg').textContent = 'Starting a fresh sandbox…';
  ['l-created', 'l-running', 'l-destroyed'].forEach(id => $(id).className = '');
  $('seal').className = 'seal'; $('seal').textContent = 'STARTING';
  evCount = 0; $('invcard').classList.add('hidden'); $('desks').innerHTML = ''; $('report').classList.add('hidden'); $('invbar').classList.add('hidden');
  WF.reset(); buildSwarm([]); $('memory').classList.add('hidden'); $('askbox').classList.add('hidden'); $('askout').classList.add('hidden'); $('askout').textContent = '';
  Object.keys(count).forEach(k => count[k] = 0);
  stat('sSteps', 0); stat('sBlocked', 0); stat('sLeaks', 0); stat('sCalls', 0);
  queue.length = 0;
  stepTo(1);
}

async function start() {
  $('err').textContent = '';
  const url = $('url').value.trim();
  if (!url) { $('err').textContent = 'Paste a link first.'; return; }
  $('go').disabled = true;
  try {
    const r = await fetch('/api/scan', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url, mode})});
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

function handle(ev) {
  if (ev.type !== 'end') evCount++;
  try { WF.event(ev); } catch (e) { console.error(e); }
  switch (ev.type) {
    case 'investigation':
      $('invcard').classList.remove('hidden'); $('invbar').classList.add('hidden'); $('desks').innerHTML = '';
      ev.analysts.forEach(a => { const d = document.createElement('div'); d.className = 'desk working'; d.id = 'desk-' + a.id;
        d.innerHTML = `<div class="dh"><i>${esc(a.icon)}</i><b>${esc(a.name)}</b><span class="st">working…</span></div><ul class="df"></ul>`; $('desks').appendChild(d); });
      trace('The analyst team is reading the evidence.', 'investigation · control plane', 'ai'); break;
    case 'analyst': {
      const d = $('desk-' + ev.id); if (!d) break;
      d.classList.remove('working'); d.querySelector('.st').textContent = 'done · ' + ev.by;
      ev.findings.forEach(f => { const li = document.createElement('li'); d.querySelector('.df').appendChild(li); typeInto(li, f); });
      trace(`${ev.name}: ${ev.findings[0] || 'no findings'}`, 'analyst · ' + ev.by, 'ai'); break;
    }
    case 'report': renderReport(ev.report); trace('Incident report ready: ' + ev.report.headline, 'lead analyst', 'good'); break;
    case 'queued':
      trace(ev.position > 0 ? `Waiting in the queue, position ${ev.position}.` : 'Starting right away.', 'queue'); break;
    case 'running': break;
    case 'scout':
      swUpdate(ev.id, ev); break;
    case 'cloaking':
      $('swarmwarn').textContent = ev.text; $('swarmwarn').classList.remove('hidden'); trace(ev.text, 'cloaking check · code', 'bad'); break;
    case 'start':
      buildSwarm(ev.swarm); if (ev.swarm && ev.swarm.length > 1) trace(`${ev.swarm.length} visitors will open the link in parallel: ` + ev.swarm.map(s => s.name).join(', ') + '.', 'swarm · control plane');
      $('canary').innerHTML = Object.entries(ev.canary).map(([k, v]) => `<dt>${LABELS[k] || k}</dt><dd>${esc(v)}</dd>`).join('');
      node('check', 'active');
      trace(`Checking the address ${ev.url}`, 'address check · code');
      break;
    case 'signals':
      ev.items.forEach(s => trace(s.text, 'address check · code', s.weight >= 20 ? 'bad' : ''));
      break;
    case 'sandbox':
      if (ev.phase === 'created') {
        const i = ev.info, sealed = i.mode === 'docker';
        node('sandbox', 'active');
        $('l-created').className = 'on'; $('l-running').className = 'on';
        $('seal').className = 'seal ' + (sealed ? 'on' : 'dev'); $('seal').textContent = sealed ? 'SEALED' : 'DEV MODE';
        $('limits').innerHTML = [[`id ${i.name}`], [`memory ${i.memory}`], [`cpu ${i.cpus}`], [`${i.pids} processes max`], [`user ${i.user}`, !sealed],
          [sealed ? 'no root, no capabilities' : 'not isolated', !sealed], ['no keys inside'], ['private network blocked'], [`runtime ${i.runtime}`]]
          .map(([t, w]) => `<span class="${w ? 'warn' : ''}">${esc(t)}</span>`).join('');
        trace(`Fresh sandbox ${i.name} is up: ${i.memory} memory, ${i.cpus} CPU, no keys inside.`, `lifecycle · ${i.mode}`, 'good');
      } else {
        node('destroy', 'active');
        $('l-created').className = 'gone'; $('l-running').className = 'gone'; $('l-destroyed').className = 'gone';
        $('seal').className = 'seal gone'; $('seal').textContent = 'DESTROYED';
        $('screenmsg').textContent = 'Sandbox destroyed. These are the screenshots it sent back.';
        trace(`Sandbox destroyed after ${ev.info.lived_s}s. Nothing from it remains.`, 'lifecycle', 'good');
      }
      break;
    case 'page':
      swUpdate('careless', {shot: ev.shot, title: ev.title, asked: ev.asked, leaks: ev.leaks});
      node('explore', 'active');
      count.steps++; stat('sSteps', count.steps);
      $('addr').textContent = ev.url || '';
      if (ev.shot) {
        $('shot').src = ev.shot;
        const t = document.createElement('img');
        t.src = ev.shot; t.title = `Step ${ev.step}: ${ev.title || ''}`;
        t.onclick = () => { $('shot').src = ev.shot; document.querySelectorAll('.strip img').forEach(x => x.classList.remove('on')); t.classList.add('on'); };
        document.querySelectorAll('.strip img').forEach(x => x.classList.remove('on'));
        t.classList.add('on'); $('strip').appendChild(t);
      }
      $('screenmsg').textContent = ev.title ? `Step ${ev.step + 1} · ${ev.title}` : '';
      (ev.leaks || []).forEach(l => {
        count.leaks++; stat('sLeaks', count.leaks, true);
        trace(`The page sent the fake ${l.data.map(d => (LABELS[d] || d).toLowerCase()).join(' and ')} to ${l.host}.`, 'network · sandbox', 'bad');
      });
      (ev.downloads || []).forEach(d => trace(`The page pushed a download: ${d.filename}. It stays inside the sandbox.`, 'download · sandbox', 'bad'));
      if (ev.note) trace(ev.note, 'sandbox');
      break;
    case 'frame':  // live view of the sandbox browser: cursor moving and text being typed
      $('shot').src = ev.shot;
      break;
    case 'download':
      trace(`The page pushed a download: ${ev.filename}. It stays inside the sandbox.`, 'download · sandbox', 'bad');
      break;
    case 'observe':
      trace(ev.text, 'explorer · sees', 'ai');
      break;
    case 'action': {
      const what = ev.action === 'fill_and_submit' ? `Typing fake ${ev.fields.map(f => (LABELS[f.value] || f.value).toLowerCase()).join(', ')} and submitting.`
        : ev.action === 'click' ? 'Clicking.' : 'Done exploring.';
      trace(`${what} ${ev.reason || ''}`, `explorer · ${ev.by}`, 'ai');
      break;
    }
    case 'containment': {
      
      count.blocked++; stat('sBlocked', count.blocked, true);
      if (count.blocked === 1) $('blocked').innerHTML = '';
      const same = [...$('blocked').children].find(x => x.dataset.url === ev.url);
      if (same) {
        same.dataset.n = +same.dataset.n + 1;
        same.querySelector('.n').textContent = ` ×${same.dataset.n}`;
        same.classList.remove('fresh'); void same.offsetWidth; same.classList.add('fresh');
      } else {
        const li = document.createElement('li'); li.className = 'fresh'; li.dataset.url = ev.url; li.dataset.n = 1;
        li.innerHTML = `<b>BLOCKED</b><span class="n"></span> ${esc(ev.url)}<br><span class="small">${esc(ev.reason)}</span>`;
        $('blocked').appendChild(li);
        trace(`Blocked a request to ${new URL(ev.url).hostname} (${ev.reason}).`, 'containment · sandbox', 'bad');
      }
      break;
    }
    case 'note':
      trace(ev.text, 'note');
      break;
    case 'verdict':
      node('judge', 'active');
      showVerdict(ev);
      break;
    case 'end':
      source && source.close(); $('go').disabled = false;
      node('you', 'active');
      refreshHealth();
      break;
  }
}

function showVerdict(v) {
  const risk = v.level === 'DANGEROUS' ? 'danger' : v.level === 'SUSPICIOUS' ? 'warn' : 'clean';
  document.body.dataset.risk = risk;
  if (risk === 'danger') { $('riskbar').hidden = false; $('riskText').textContent = 'Dangerous link: do not open it on your device.'; }
  $('vlevel').textContent = v.level === 'LOOKS SAFE' ? 'Looks safe' : {danger: 'Dangerous link', warn: 'Suspicious link', clean: 'No threat found'}[risk];
  $('ringNum').textContent = v.score;
  $('ringFg').style.strokeDashoffset = 188.5 * (1 - v.score / 100);
  $('vmeta').innerHTML = `<span>${v.seconds}s · ${v.model_calls} model calls</span><span>summary by ${esc(v.summary_by)}</span><span>score by code</span>`;
  stat('sCalls', v.model_calls);
  $('vsum').textContent = '';
  typeInto($('vsum'), v.summary);
  $('evidence').innerHTML = v.evidence.map(e => `<li>${esc(e.text)}<span class="w">+${e.weight}</span>${e.quote ? `<q>${esc(e.quote)}</q>` : ''}</li>`).join('')
    + (risk === 'clean' ? (v.checks || []).map(c => `<li class="pass">${esc(c)}</li>`).join('') : '');
  $('loot').innerHTML = (v.attacker_got || []).map(g => `<div class="lootbox"><b>${esc(g.host)}</b> received your fake ${esc(g.data.map(d => (LABELS[d] || d).toLowerCase()).join(', '))}</div>`).join('')
    || '<p class="small">Nothing was sent to another server.</p>';
  $('vgrid').classList.remove('hidden'); $('decide').classList.remove('hidden');
  showMemory(v.memory); (v.swarm || []).forEach(s => swUpdate(s.id, {level: s.level, title: s.title, asked: s.asked}));
  $('askbox').classList.remove('hidden'); refreshHistory(); if (mode !== 'investigate') $('invbar').classList.remove('hidden');
  trace(`Verdict ${v.level}, score ${v.score}/100, from ${v.evidence.length} pieces of evidence.`, 'evidence judge · code', risk === 'clean' ? 'good' : 'bad');
  stepTo(3);
}

function typeInto(el, text) {
  let i = 0;
  (function tick() { i = Math.min(text.length, i + 3); el.textContent = text.slice(0, i); if (i < text.length) setTimeout(tick, 12); })();
}

async function decide(d) {
  const r = await fetch(`/api/scan/${scanId}/decision`, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({decision: d, note: $('note').value})});
  const j = await r.json();
  if (!r.ok) { $('decided').textContent = j.detail || 'Could not save.'; return; }
  document.querySelectorAll('.decide button').forEach(b => b.disabled = true);
  $('decided').textContent = {block: 'Recorded: this site is blocked for your team.', allow: 'Recorded: you marked it as safe.',
    dismiss: 'Dismissed.'}[d] + ` (${j.at})`;
  node('you', 'done'); stepTo(4); WF.event({type: 'decision', choice: d});
  trace(`You chose: ${d}.`, 'human decision', 'good');
}

init();
