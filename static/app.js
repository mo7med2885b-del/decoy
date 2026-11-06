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
  if (o.shot) { d.querySelector('.swimg').innerHTML = `<img src="${o.shot}" alt="" title="Click to see the whole page">`; const im = d.querySelector('.swimg img'); im.dataset.full = o.full || o.shot; im.dataset.cap = d.querySelector('.swh b').textContent + ' · ' + d.querySelector('.swh span').textContent; im.onclick = () => openShot(im.dataset.full, im.dataset.cap); }
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
const flag = c => (c && c.length === 2) ? String.fromCodePoint(...[...c.toUpperCase()].map(x => 127397 + x.charCodeAt(0))) : '';
async function refreshThreats() {
  try {
    const rows = await (await fetch('/api/threats?demo=1')).json();
    $('threatcard').classList.toggle('hidden', !rows.length);
    const seenH = new Set(); const uniq = rows.filter(r => !seenH.has(r.host) && seenH.add(r.host));  // one line per site, the latest
    $('thbody').innerHTML = uniq.slice(0, 8).map(r => {
      const geo = r.exfil_geo || [];
      const dest = geo.length ? geo.map(g => `${flag(g.code)} <b>${esc(g.host)}</b><span class="pth">${esc([g.city, g.code].filter(Boolean).join(', '))}${g.simulated ? ' (simulated)' : ''}${g.org ? ' · ' + esc(g.org) : ''}</span>`).join('<br>') : '<span class="small">no data sent away</span>';
      return `<tr><td><b>${esc(r.host)}</b>${r.cloaking ? '<span class="fl bad">cloaked</span>' : ''}</td><td><i class="${levelCls(r.level)} lvl">${esc(LEVEL_TXT[r.level] || r.level)}</i></td><td>${dest}</td><td class="small">${ago(r.at)}</td></tr>`;
    }).join('');
  } catch (e) {}
}
function showProtect(v) {
  const box = $('protect'); const bad = v.level === 'DANGEROUS' || v.level === 'SUSPICIOUS';
  if (!bad) { box.classList.add('hidden'); return; }
  const host = (new URL($('addr').textContent.startsWith('http') ? $('addr').textContent : 'http://' + ($('url').value.replace(/^https?:\/\//, '') || 'x'))).hostname;
  const geo = v.exfil_geo || []; const doms = [...new Set([host, ...geo.map(g => g.host)])];
  box.classList.remove('hidden');
  box.innerHTML = `<h3>Protect your people</h3><p>${geo.length ? `The stolen data goes to <b>${geo.map(g => esc(flag(g.code) + ' ' + g.host + ' (' + [g.city, g.code].filter(Boolean).join(', ') + (g.simulated ? ', simulated' : '') + ')')).join(', ')}</b>.` : 'No data was sent away, but the site is still risky.'} Block these addresses for your team and customers:</p>`
    + `<div class="vchips">${doms.map(d => `<span class="vc alarm">${esc(d)}</span>`).join('')}</div><div class="row" style="margin-top:10px">`
    + `<button class="btn" id="copybl" type="button">Copy block-list</button><a class="btn" href="/api/blocklist.hosts?demo=1" target="_blank" rel="noopener">Hosts file</a>`
    + `<a class="btn" href="/api/scan/${scanId}/abuse.txt">Abuse report draft</a></div><p class="small">Decoy never blocks or reports by itself: you review, then you send.</p>`;
  $('copybl').onclick = () => { try { navigator.clipboard.writeText(doms.join('\n')); $('copybl').textContent = 'Copied ✓'; } catch (e) {} };
}
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
function openShot(src, cap) {
  if (!src) return; $('lbimg').src = src; $('lbopen').href = src; $('lbcap').textContent = cap || ''; $('lightbox').classList.remove('hidden'); $('lightbox').querySelector('.lbscroll').scrollTop = 0;
}
const DT = {net: new Set(), js: new Set(), con: 0, raw: {net: [], con: [], ck: [], js: []}, aiFor: -1};
function devtools(ev) {
  $('devcard').classList.remove('hidden');
  (ev.network || []).forEach(n => {
    const key = n.method + n.url; if (DT.net.has(key)) return; DT.net.add(key);
    DT.raw.net.push({host: n.host, type: n.type, status: n.status, blocked: !!n.blocked, leak: !!n.leak, method: n.method});
    let path = n.url; try { const u = new URL(n.url); path = u.pathname + u.search; } catch (e) {}
    const tr = document.createElement('tr'); tr.className = n.leak ? 'leak' : n.blocked ? 'blk' : '';
    tr.innerHTML = `<td>${esc(n.method)}</td><td><b>${esc(n.host)}</b><span class="pth">${esc(path.slice(0, 80))}</span></td><td>${esc(n.type)}</td><td>${n.blocked ? '—' : esc(n.status ?? '')}</td>`
      + `<td>${n.leak ? '<i class="fl bad">carries fake data</i>' : n.blocked ? '<i class="fl bad">blocked</i>' : ''}</td>`;
    tr.onclick = () => { const p = $('dtpost'); p.classList.remove('hidden'); p.textContent = `${n.method} ${n.url}\n` + (n.post ? `payload (typed values replaced by their names):\n${n.post}` : '(no payload)'); };
    $('dtnet').appendChild(tr);
  });
  $('dn').textContent = DT.net.size;
  (ev.console || []).forEach(c => { DT.raw.con.push({type: c.type, text: String(c.text || '').slice(0, 200)}); DT.con++; const li = document.createElement('li'); li.className = c.type; li.innerHTML = `<i>${esc(c.type)}</i>${esc(c.text)}`; $('dtcon').appendChild(li); });
  $('dc').textContent = DT.con;
  if ((ev.cookies || []).length) { DT.raw.ck = ev.cookies.map(c => ({name: c.name, domain: c.domain, secure: !!c.secure, httpOnly: !!c.httpOnly})); }
  if ((ev.cookies || []).length) { $('dtck').innerHTML = ev.cookies.map(c => `<tr class="${c.secure && c.httpOnly ? '' : 'blk'}"><td><b>${esc(c.name)}</b></td><td>${esc(c.domain)}</td><td>${c.secure ? 'yes' : 'no'}</td><td>${c.httpOnly ? 'yes' : 'no'}</td><td>${esc(c.sameSite || '-')}</td></tr>`).join(''); $('dk').textContent = ev.cookies.length; }
  (ev.scripts || []).forEach(s => { if (DT.js.has(s)) return; DT.js.add(s); DT.raw.js.push(String(s).slice(0, 1500)); const d = document.createElement('div'); d.className = 'js'; d.innerHTML = `<small>inline script</small><pre>${esc(s)}</pre>`; $('dtjs').appendChild(d); });
  (ev.script_srcs || []).forEach(s => { if (DT.js.has(s)) return; DT.js.add(s); const d = document.createElement('div'); d.className = 'js'; d.innerHTML = `<small>external script</small><pre>${esc(s)}</pre>`; $('dtjs').appendChild(d); });
  $('dj').textContent = DT.js.size;
}
const DQ = {t: 0};
function debateMsg(ev) {
  $('debatecard').classList.remove('hidden');
  const add = (cls, who, html, delay) => setTimeout(() => { const d = document.createElement('div'); d.className = 'dmsg ' + cls; d.innerHTML = `<b>${esc(who)}</b><p>${html}</p>`; $('dchat').appendChild(d); }, delay);
  DQ.t = DQ.t + (ev.phase === 'share' ? 0 : 700);
  const d = DQ.t;
  if (ev.phase === 'share') add('sys', 'Evidence board', esc(ev.text), 0);
  else if (ev.phase === 'challenge') add('chal', 'Review lead → ' + ev.name, esc(ev.text), d);
  else if (ev.phase === 'reply') add(ev.stance === 'revise' ? 'rev' : 'keep', ev.name + (ev.stance === 'revise' ? ' revises' : ' keeps its finding'), esc(ev.text) + (ev.revised ? `<br><i>Now: ${esc(ev.revised)}</i>` : '') + `<small>${esc(ev.by)}</small>`, d);
  else if (ev.phase === 'consensus') setTimeout(() => {
    const names = {check: 'Reputation', tls: 'TLS', script: 'Script', endpoints: 'Endpoints', lure: 'Lure', intel: 'Intel', cloak: 'Cloak', geo: 'Location', privacy: 'Privacy'};
    $('dvotes').classList.remove('hidden'); $('dvotes').innerHTML = `<div class="dsum"><b>${esc(ev.text)}</b></div><div class="vchips">` + Object.entries(ev.votes || {}).map(([a, v]) => `<span class="vc ${v}">${esc(names[a] || a)}: ${v}</span>`).join('') + '</div>';
    trace(ev.text, 'swarm debate', ev.dissent && ev.dissent.length ? 'bad' : 'good'); }, d + 600);
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
  refreshHealth(); refreshHistory(); refreshThreats(); initAsk(); initQr();
  try {
    for (const ex of await (await fetch('/api/examples')).json()) {
      const b = document.createElement('button');
      b.type = 'button'; b.textContent = ex.label; b.title = ex.url;
      b.onclick = () => { $('url').value = ex.url; start(); };
      $('examples').appendChild(b);
    }
  } catch (e) {}
  $('form').onsubmit = e => {  // the send button asks how deep to go
    e.preventDefault();
    if (!$('url').value.trim()) { $('err').textContent = 'Paste a link first.'; return; }
    $('err').textContent = ''; $('depth').classList.remove('hidden'); $('depth').scrollIntoView({behavior: 'smooth', block: 'nearest'});
  };
  document.querySelectorAll('#depth .opt').forEach(o => o.onclick = () => {
    mode = o.dataset.mode; document.querySelectorAll('#modes button').forEach(x => x.classList.toggle('on', x.dataset.mode === mode));
    $('depth').classList.add('hidden'); start();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') $('depth').classList.add('hidden'); });
  $('url').addEventListener('input', () => $('depth').classList.add('hidden'));
  document.querySelectorAll('#modes button').forEach(b => b.onclick = () => { mode = b.dataset.mode; document.querySelectorAll('#modes button').forEach(x => x.classList.toggle('on', x === b)); });
  $('invbtn').onclick = investigate;
  $('theme').onclick = () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('decoy-theme', next); } catch (e) {}
  };
  $('cancel').onclick = () => scanId && fetch(`/api/scan/${scanId}/cancel`, {method: 'POST'});
  document.querySelectorAll('.decide button').forEach(b => b.onclick = () => decide(b.dataset.d));
  document.querySelectorAll('#dtabs button').forEach(b => b.onclick = () => { if (b.dataset.t === 'ai') runInspectAI(); document.querySelectorAll('#dtabs button').forEach(x => x.classList.toggle('on', x === b)); document.querySelectorAll('.dpane').forEach(p => p.classList.toggle('hidden', p.id !== 'dp-' + b.dataset.t)); });
  $('shot').onclick = () => $('shot').dataset.full && openShot($('shot').dataset.full, $('shot').dataset.cap);
  $('lbclose').onclick = () => $('lightbox').classList.add('hidden'); $('lightbox').onclick = e => { if (e.target.id === 'lightbox') $('lightbox').classList.add('hidden'); };
  addEventListener('keydown', e => { if (e.key === 'Escape') $('lightbox').classList.add('hidden'); });
}

function reset() {
  $('run').classList.remove('hidden');
  $('intake').classList.add('compact');
  document.body.dataset.risk = 'idle'; $('riskbar').hidden = true; document.body.dataset.stage = 'run';
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
  WF.reset(); try { GLB.reset(); } catch (e) {}
  $('dchat').innerHTML = ''; $('dvotes').classList.add('hidden'); $('debatecard').classList.add('hidden'); DQ.t = 0;
  DT.net.clear(); DT.js.clear(); DT.con = 0; DT.raw = {net: [], con: [], ck: [], js: []}; DT.aiFor = -1; $('dp-ai').innerHTML = '<p class="small">Open this tab after the scan to get a plain-words summary of what the page did in the background.</p>'; ['dtnet', 'dtcon', 'dtck', 'dtjs'].forEach(i => $(i).innerHTML = ''); ['dn', 'dc', 'dk', 'dj'].forEach(i => $(i).textContent = 0); $('devcard').classList.add('hidden'); $('dtpost').classList.add('hidden'); $('lightbox').classList.add('hidden'); buildSwarm([]); $('memory').classList.add('hidden'); $('askbox').classList.add('hidden'); $('askout').classList.add('hidden'); $('askout').textContent = '';
  Object.keys(count).forEach(k => count[k] = 0);
  stat('sSteps', 0); stat('sBlocked', 0); stat('sLeaks', 0); stat('sCalls', 0);
  queue.length = 0;
  stepTo(1);
}

let geoSeen = false;
async function start() {
  $('err').textContent = '';
  const url = $('url').value.trim();
  if (!url) { $('err').textContent = 'Paste a link first.'; return; }
  $('go').disabled = true;
  try {
    fetch('/api/geo?url=' + encodeURIComponent(url)).then(g => g.json()).then(g => {  // the globe does not wait for the queue
      if (g.loc) { geoSeen = true; document.body.dataset.first = 'globe'; try { GLB.event({type: 'start', origin: g.origin}); GLB.event({type: 'geo', role: 'lure', ...g.loc}); } catch (e) {} }
      else { document.body.dataset.first = 'browser'; }
    }).catch(() => {});
    const r = await fetch('/api/scan', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url, mode})});
    const j = await r.json();
    if (!r.ok) { $('err').textContent = j.detail || 'Could not start.'; $('go').disabled = false; return; }
    scanId = j.id; reset(); geoSeen = false;
    document.body.dataset.stage = 'run'; document.body.dataset.first = 'globe'; $('rebarurl').textContent = url.slice(0, 90);  // the world view leads when the link's server can be located
    setTimeout(() => { if (!geoSeen) document.body.dataset.first = 'browser'; }, 2200);  // otherwise the sealed browser leads, as soon as it streams
    ($('globecard') || $('run')).scrollIntoView({behavior: 'smooth', block: 'start'});
    if (source) source.close();
    source = new EventSource(`/api/scan/${scanId}/events`);
    source.onmessage = m => { try { handle(JSON.parse(m.data)); } catch (e) { console.error(e); } };
    source.onerror = () => { source.close(); $('go').disabled = false; };
  } catch (e) { $('err').textContent = 'The server did not answer.'; $('go').disabled = false; }
}

function handle(ev) {
  if (ev.type !== 'end') evCount++;
  if (ev.type === 'geo') { geoSeen = true; if (document.body.dataset.stage === 'run') document.body.dataset.first = 'globe'; }
  try { WF.event(ev); } catch (e) { console.error(e); }
  try { GLB.event(ev); } catch (e) { console.error(e); }
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
      swUpdate('careless', {shot: ev.shot, full: ev.full, title: ev.title, asked: ev.asked, leaks: ev.leaks});
      if (ev.full) { $('shot').dataset.full = ev.full; $('shot').dataset.cap = 'Step ' + (ev.step + 1) + ' · ' + (ev.title || ev.url || ''); }
      node('explore', 'active');
      count.steps++; stat('sSteps', count.steps);
      $('addr').textContent = ev.url || '';
      if (ev.shot) {
        $('shot').src = ev.shot;
        const t = document.createElement('img');
        t.src = ev.shot; t.title = `Step ${ev.step}: ${ev.title || ''}`;
        t.dataset.full = ev.full || ev.shot;
        t.ondblclick = () => openShot(t.dataset.full, 'Step ' + (ev.step + 1) + ' · ' + (ev.title || ''));
        t.onclick = () => { $('shot').src = ev.shot; $('shot').dataset.full = t.dataset.full; $('shot').dataset.cap = 'Step ' + (ev.step + 1) + ' · ' + (ev.title || ''); document.querySelectorAll('.strip img').forEach(x => x.classList.remove('on')); t.classList.add('on'); };
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
    case 'devtools': devtools(ev); break;
    case 'debate': debateMsg(ev); break;
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
    + (risk === 'clean' ? (v.checks || []).map(c => `<li class="pass">${esc(c)}</li>`).join('') : '')
    + (v.limits || []).map(c => `<li class="limit">${esc(c)}</li>`).join('');
  $('loot').innerHTML = (v.attacker_got || []).map(g => `<div class="lootbox"><b>${esc(g.host)}</b> received your fake ${esc(g.data.map(d => (LABELS[d] || d).toLowerCase()).join(', '))}</div>`).join('')
    || '<p class="small">Nothing was sent to another server.</p>';
  $('vgrid').classList.remove('hidden'); $('decide').classList.remove('hidden');
  showProtect(v); showMemory(v.memory); (v.swarm || []).forEach(s => swUpdate(s.id, {level: s.level, title: s.title, asked: s.asked, shot: s.shot, full: s.full}));
  $('askbox').classList.remove('hidden'); refreshHistory(); refreshThreats(); if (mode !== 'investigate') $('invbar').classList.remove('hidden');
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


async function runInspectAI() {  // plain-words AI summary of the captured network, console, cookies and scripts
  const box = $('dp-ai'), size = DT.raw.net.length + DT.raw.con.length + DT.raw.ck.length + DT.raw.js.length;
  if (!size) { box.innerHTML = '<p class="small">Nothing was captured yet. Run a scan first.</p>'; return; }
  if (DT.aiFor === size) return;
  DT.aiFor = size;
  box.innerHTML = '<div class="aisk"><i></i><i></i><i></i></div><p class="small">Reading what the page did in the background…</p>';
  let host = ''; try { host = new URL(($('addr').textContent.startsWith('http') ? $('addr').textContent : 'http://' + $('url').value.replace(/^https?:\/\//, ''))).hostname; } catch (e) {}
  try {
    const r = await fetch('/api/inspect-ai', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({host, ...DT.raw})});
    const j = await r.json(); if (!r.ok) throw new Error(j.detail || 'failed');
    const lvl = {warn: ['warn', 'Could be harmful'], watch: ['watch', 'Keep an eye on it'], info: ['info', 'Good to know']};
    const f = j.facts || {};
    const chips = [['requests', f.requests], ['servers', f.hosts], ['cookies', f.cookies], ['scripts', f.scripts], ['trackers', f.trackers], ['blocked', f.blocked]].map(([k, v]) => `<span class="aichip"><b>${esc(v ?? 0)}</b> ${k}</span>`).join('');
    box.innerHTML = `<div class="aisum"><span class="aibadge">AI summary</span><p>${esc(j.summary)}</p></div>`
      + `<ul class="ainotes">${(j.notes || []).map(n => `<li class="${(lvl[n.level] || lvl.info)[0]}"><i></i><div><b>${(lvl[n.level] || lvl.info)[1]}</b><span>${esc(n.text)}</span></div></li>`).join('')}</ul>`
      + `<div class="aichips">${chips}</div><p class="small">${j.by === 'rules' ? 'Written by rules (no model answered).' : 'Written by ' + esc(j.by) + '.'} Every number is counted by code; a model never changes a warning.</p>`;
  } catch (e) { box.innerHTML = '<p class="small">The summary could not be made right now. The data above is complete.</p>'; DT.aiFor = -1; }
}

document.addEventListener('DOMContentLoaded', () => { const n = document.getElementById('rebarnew'); if (n) n.onclick = () => { document.body.dataset.stage = 'idle'; delete document.body.dataset.first; document.getElementById('url').value = ''; window.scrollTo({top: 0, behavior: 'smooth'}); document.getElementById('url').focus(); }; });

// the browser must not remember what was pasted: a field with a new random name each load has no history to suggest from
document.addEventListener('DOMContentLoaded', () => { const u = document.getElementById('url'); if (u) { u.name = 'u' + Math.random().toString(36).slice(2); u.setAttribute('autocomplete', 'off'); } });
