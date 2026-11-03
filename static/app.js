// Decoy front end: start a scan, stream the control plane's real events, type the agent's notes live,
// show the verdict and record the human decision. Every event handler is guarded so one bad event cannot stall the page.
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const LABELS = {EMAIL: 'Email', PASSWORD: 'Password', CARD: 'Card number', CVV: 'Card code', NAME: 'Name', PHONE: 'Phone'};
let scanId = null, source = null;
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
function node(name, state) {
  const li = document.querySelector(`#chain li[data-n="${name}"]`);
  if (!li) return;
  if (state === 'active') document.querySelectorAll('#chain li.active').forEach(x => { x.classList.remove('active'); x.classList.add('done'); });
  li.classList.remove('active', 'done');
  if (state) li.classList.add(state);
}
function stat(id, v, hot) { $(id).textContent = v; $(id).parentElement.classList.toggle('hot', !!hot); }

async function refreshHealth() {
  try {
    const h = await (await fetch('/api/health')).json();
    const sealed = h.sandbox === 'docker';
    $('pSandbox').textContent = sealed ? `Sandbox: Docker (${h.runtime})` : 'Dev mode: not sealed';
    $('pSandbox').className = 'pill ' + (sealed ? 'ok' : 'warn');
    $('pAgent').textContent = 'Agent: ' + h.planner;
    $('pAgent').className = 'pill' + (h.model_key ? ' ok' : '');
    $('explorerBy').textContent = h.model_key ? h.planner + ' · Vultr' : 'rules (no key yet)';
    $('pSpend').textContent = `$${(h.today.usd || 0).toFixed(2)} today · cap $${h.caps.usd_per_day}`;
  } catch (e) {}
}

async function init() {
  refreshHealth();
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
  document.querySelectorAll('#chain li').forEach(li => li.className = '');
  Object.keys(count).forEach(k => count[k] = 0);
  stat('sSteps', 0); stat('sBlocked', 0); stat('sLeaks', 0); stat('sCalls', 0);
  queue.length = 0;
  $('console').classList.add('live'); $('cstate').textContent = 'Running';
  stepTo(1);
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

function handle(ev) {
  switch (ev.type) {
    case 'start':
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
      $('console').classList.remove('live'); $('cstate').textContent = 'Finished · waiting for your decision';
      node('you', 'active');
      refreshHealth();
      break;
  }
}

function showVerdict(v) {
  const risk = v.level === 'DANGEROUS' ? 'danger' : v.level === 'SUSPICIOUS' ? 'warn' : 'clean';
  document.body.dataset.risk = risk;
  if (risk === 'danger') { $('riskbar').hidden = false; $('riskText').textContent = 'Dangerous link: do not open it on your device.'; }
  $('vlevel').textContent = {danger: 'Dangerous link', warn: 'Suspicious link', clean: 'No threat found'}[risk];
  $('ringNum').textContent = v.score;
  $('ringFg').style.strokeDashoffset = 188.5 * (1 - v.score / 100);
  $('vmeta').innerHTML = `<span>${v.seconds}s · ${v.model_calls} model calls</span><span>summary by ${esc(v.summary_by)}</span><span>score by code</span>`;
  stat('sCalls', v.model_calls);
  $('vsum').textContent = '';
  typeInto($('vsum'), v.summary);
  $('evidence').innerHTML = v.evidence.map(e => `<li>${esc(e.text)}<span class="w">+${e.weight}</span>${e.quote ? `<q>${esc(e.quote)}</q>` : ''}</li>`).join('')
    || '<li class="small">Nothing harmful was seen.</li>';
  $('loot').innerHTML = (v.attacker_got || []).map(g => `<div class="lootbox"><b>${esc(g.host)}</b> received your fake ${esc(g.data.map(d => (LABELS[d] || d).toLowerCase()).join(', '))}</div>`).join('')
    || '<p class="small">Nothing was sent to another server.</p>';
  $('vgrid').classList.remove('hidden'); $('decide').classList.remove('hidden');
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
  node('you', 'done'); stepTo(4);
  trace(`You chose: ${d}.`, 'human decision', 'good');
}

init();
