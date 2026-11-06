// Agent workflow canvas. Every node, line and dot is driven by the real events of a scan (WF.event is called from app.js).
// The swarm: three visitors in their own sandboxes plus nine specialist agents. Nodes APPEAR when their agent starts.
const WF = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  // id: [x%, y px, icon, title, subtitle, kind]
  const NODES = {
    control: [50, 62, '', 'Decoy control plane', 'Vultr VM · plans and verifies', 'core'],
    link: [50, 150, '✉', 'Suspicious link', 'email · WhatsApp · text', 'code'],
    check: [17, 245, '🧠', 'Reputation', 'code · domain age', 'code'],
    geo: [50, 245, '🧠', 'Server location', 'code · IP, city, host', 'code'],
    tls: [83, 245, '🧠', 'TLS certificate', 'code · issuer, age', 'code'],
    sandbox: [50, 345, '▣', 'Sealed browsers', 'Docker + gVisor each', 'code'],
    v_careless: [17, 445, '🧠', 'Careless employee', 'laptop · Vultr AI explorer', 'model'],
    v_phone: [50, 445, '🧠', 'Phone user', 'iPhone · rule-based', 'code'],
    v_bot: [83, 445, '🧠', 'Security bot', 'link scanner · rule-based', 'code'],
    net: [17, 545, '⛨', 'Egress filter', 'blocks private addresses', 'code'],
    destroy: [50, 545, '✕', 'Sandboxes gone', 'nothing remains', 'code'],
    script: [17, 650, '🧠', 'Script analyst', 'DeepSeek · reads the code', 'model'],
    endpoints: [50, 650, '🧠', 'Endpoint hunter', 'Qwen · requests and countries', 'model'],
    privacy: [83, 650, '🧠', 'Privacy', 'MiMo · storage, console', 'model'],
    lure: [17, 750, '🧠', 'Lure analyst', 'MiniMax · manipulation', 'model'],
    intel: [50, 750, '🧠', 'Threat intel', 'memory · campaigns', 'code'],
    cloak: [83, 750, '🧠', 'Cloak detector', 'compares visitors', 'code'],
    orch: [50, 880, '🧠', 'Orchestrator', 'glm-5.3 · the most capable model', 'orch'],
    debate: [50, 1250, '🧠', 'Agent chat room', 'share · challenge · vote', 'chat'],
    judge: [50, 1640, '⚖', 'Evidence judge', 'code · score by rules', 'code'],
    analysts: [17, 1750, '🧠', 'Analyst team', 'Investigate mode', 'model'],
    summary: [50, 1750, '🧠', 'Summary', 'GLM · plain words', 'model'],
    human: [83, 1750, '✓', 'Your decision', 'block · safe · dismiss', 'human'],
  };
  Object.values(NODES).forEach(n => { n[1] = Math.round(n[1] * 1.28); });  // more air between the rows
  const EDGES = [['control', 'link', 'model'], ['link', 'check'], ['link', 'geo'], ['link', 'tls'], ['check', 'sandbox'], ['sandbox', 'v_careless', 'model'], ['sandbox', 'v_phone'], ['sandbox', 'v_bot'],
    ['v_careless', 'net'], ['v_careless', 'destroy'], ['v_phone', 'destroy'], ['v_bot', 'destroy'],
    ['destroy', 'script', 'model'], ['destroy', 'endpoints', 'model'], ['destroy', 'privacy', 'model'], ['script', 'lure', 'model'], ['endpoints', 'intel'], ['privacy', 'cloak'],
    ['orch', 'debate', 'orch'], ['debate', 'judge', 'model'], ['judge', 'analysts', 'model'], ['judge', 'summary', 'model'], ['analysts', 'human', 'model'], ['summary', 'human']];
  EDGES.push(['orch', 'check', 'orch'], ['orch', 'geo', 'orch'], ['orch', 'tls', 'orch'], ['orch', 'script', 'orch'], ['orch', 'endpoints', 'orch'], ['orch', 'privacy', 'orch'], ['orch', 'lure', 'orch'], ['orch', 'intel', 'orch'], ['orch', 'cloak', 'orch']);
  const PARENT = {check: 'link', geo: 'link', tls: 'link', script: 'destroy', endpoints: 'destroy', privacy: 'destroy', lure: 'script', intel: 'endpoints', cloak: 'privacy'};
  const VISITOR = {careless: 'v_careless', phone: 'v_phone', bot: 'v_bot'};
  const INFO = {
    control: 'The control plane runs on a Vultr VM. It plans the scan, starts the sandboxes and the agents, validates every suggestion of the AI in code and enforces the budget caps.',
    link: 'The address you pasted. It is checked in plain code before anything opens: web links only, no private or internal addresses.',
    check: 'Plain code: look-alike brands, link shorteners, free-hosting subdomains, official-site recognition, and the age of the domain from public RDAP data.',
    geo: 'Resolves the host and looks up the server: IP, city, country and hosting company. It never connects to the server itself.',
    tls: 'Reads the HTTPS certificate: does it verify, who issued it, how new it is. A broken or brand-new certificate is a common scam sign.',
    sandbox: 'Every visitor gets its own fresh Docker container, on gVisor: no root, no capabilities, read-only disk, no keys inside, destroyed afterwards.',
    v_careless: 'The laptop visitor. A Vultr AI model sees the page and proposes the next click; code validates it so it can only type fake placeholders and click real elements.',
    v_phone: 'An iPhone visitor with its own browser string, screen and language. Rule-based explorer. Pages that treat phones differently show up here.',
    v_bot: 'A link-scanner visitor. Scam pages often show harmless content to security bots; comparing this visitor with the others is how cloaking is caught.',
    net: 'Every request the page makes is checked. Private, loopback and cloud-metadata addresses are blocked in the browser and again at the server firewall.',
    destroy: 'All sandboxes are deleted after the scan. Nothing from them remains.',
    script: 'Reads the page scripts: what they read, where they send it, redirects, obfuscation. Rule-based static analysis first; DeepSeek (a Vultr-hosted open model) adds a reading.',
    endpoints: 'Lists every background request: which carried the typed fake data, which went to analytics, which to a phishing-kit channel, and in which country they end up. Qwen assists.',
    privacy: 'Cookies and console output: what is stored in the browser, what is weakly protected, any tracking. MiMo assists.',
    lure: 'How the page manipulates the visitor: urgency, fear, brand borrowing, what it asks for. MiniMax assists.',
    intel: 'Threat memory (SQLite): earlier scans of this site and campaigns linked through the same data-collection server.',
    cloak: 'Compares what the laptop, the phone and the security bot were each shown. A login form hidden from the bot is cloaking.',
    orch: 'The orchestrator is the most capable model in the swarm (glm-5.3). Every agent reports to it. It reads all findings, questions agents whose findings clash, calls the vote and starts another round if anyone objects (at most three). The agents themselves run on small flash models. It never changes the score: code owns that.',
    debate: 'The agents post their findings on one board. A review lead (another open model) challenges contradictions and gaps, the challenged agents answer (keep or revise), then every agent votes. Revisions change what an agent says, never the score.',
    judge: 'Plain code scores all the evidence. No model ever sets the verdict.',
    analysts: 'Investigate mode: the specialists above plus the network and infrastructure analysts, and a lead analyst, write the incident report.',
    summary: 'A Vultr AI model writes the plain-words summary. Code rejects it if it contradicts the score.',
    human: 'Decoy never blocks or reports anything by itself. You decide, and it is recorded.',
  };
  const S = d => `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  const ICONS = {  // custom line icons (no emoji): one brain for every agent
    '🧠': S('<path d="M9.5 4a3 3 0 0 0-3 3 3 3 0 0 0-2 2.8 3 3 0 0 0 1 2.2 3 3 0 0 0 1.2 4.3A3 3 0 0 0 9.5 20 2.5 2.5 0 0 0 12 17.5v-12A2.5 2.5 0 0 0 9.5 4z"/><path d="M14.5 4a3 3 0 0 1 3 3 3 3 0 0 1 2 2.8 3 3 0 0 1-1 2.2 3 3 0 0 1-1.2 4.3A3 3 0 0 1 14.5 20a2.5 2.5 0 0 1-2.5-2.5v-12A2.5 2.5 0 0 1 14.5 4z"/><path d="M8.5 9.5h1.5M14 9.5h1.5M8.5 14h1.5M14 14h1.5"/>'),
    '✉': S('<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>'),
    '✎': S('<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>'),
  };
  const iconHtml = ic => ICONS[ic] || ic;
  const START_VISIBLE = ['control', 'link'];
  const hist = {};
  let selected = null, zoom = 1, loop = null, started = false, T0 = performance.now(), destroyed = 0, expected = 1;
  const $ = id => document.getElementById(id);
  const el = {};

  function build() {
    const stage = $('wfStage');
    Object.entries(NODES).forEach(([id, [x, y, ic, t, sub, kind]]) => {
      const d = document.createElement('div');
      d.className = 'wn ' + kind + (START_VISIBLE.includes(id) ? '' : ' ghost'); d.style.left = x + '%'; d.style.top = y + 'px'; d.dataset.id = id;
      if (kind === 'chat') { d.innerHTML = `<div class="cr-head"><span class="cr-ic">${iconHtml('🧠')}</span><b>${t}</b><em class="cr-live">idle</em></div><div class="cr-list" id="crList"><p class="cr-empty">The agents meet here after the visitors leave: they post findings, question each other, answer and vote.</p></div><span class="live"></span>`; d.querySelector('.cr-list').addEventListener('pointerdown', e => e.stopPropagation()); stage.appendChild(d); el[id] = d; hist[id] = []; drag(d, id); return; }
      d.innerHTML = kind === 'core' ? `<div class="ball"></div><b>${t}</b><small>${sub}</small><span class="live"></span>`
        : `<b><i>${iconHtml(ic)}</i>${t}</b><small>${sub}</small><span class="live"></span>`;
      stage.appendChild(d); el[id] = d; hist[id] = []; drag(d, id);
    });
    draw(); addEventListener('resize', draw);
    const z = d => () => { zoom += d; applyZoom(); draw(); };
    $('wzin').onclick = z(0.15); $('wzout').onclick = z(-0.15); $('wzfit').onclick = () => { zoom = 1; applyZoom(); draw(); };
    $('wfView').addEventListener('wheel', e => { if (e.ctrlKey || e.metaKey) { e.preventDefault(); zoom += e.deltaY < 0 ? 0.1 : -0.1; applyZoom(); draw(); } }, {passive: false});
    $('wfReset').onclick = () => { zoom = 1; applyZoom(); Object.entries(NODES).forEach(([id, n]) => { el[id].style.left = n[0] + '%'; el[id].style.top = n[1] + 'px'; }); draw(); };
  }
  function applyZoom() {
    const st = $('wfStage'), view = $('wfView'); zoom = Math.min(1.8, Math.max(0.5, zoom));
    st.style.transformOrigin = '0 0'; st.style.transform = `scale(${zoom})`; st.style.marginLeft = zoom < 1 ? `${(1 - zoom) / 2 * 100}%` : '0';
    view.style.height = Math.max(st.offsetHeight * zoom, 300) + 'px'; view.style.minHeight = '0'; view.style.overflowX = zoom > 1 ? 'auto' : 'hidden'; $('wzfit').textContent = Math.round(zoom * 100) + '%';
  }
  function box(id) {
    const n = el[id];  // layout coordinates inside the stage: unaffected by the canvas zoom and by the active-node scale
    return {x: n.offsetLeft, y: n.offsetTop, w: n.offsetWidth / 2, h: n.offsetHeight / 2};
  }
  function pathD(a, b) {
    const p = box(a), q = box(b), horiz = Math.abs(q.y - p.y) < 20;
    if (horiz) {
      const s = {x: p.x + Math.sign(q.x - p.x) * p.w, y: p.y}, e = {x: q.x - Math.sign(q.x - p.x) * q.w, y: q.y}, m = (s.x + e.x) / 2;
      return `M${s.x},${s.y} C${m},${s.y} ${m},${e.y} ${e.x},${e.y}`;
    }
    const s = {x: p.x, y: p.y + p.h}, e = {x: q.x, y: q.y - q.h}, m = (s.y + e.y) / 2;
    return `M${s.x},${s.y} C${s.x},${m} ${e.x},${m} ${e.x},${e.y}`;
  }
  function drag(d, id) {
    let sx, sy, ox, oy, moved = false;
    d.addEventListener('pointerdown', e => { d.setPointerCapture(e.pointerId); sx = e.clientX; sy = e.clientY; ox = d.offsetLeft; oy = d.offsetTop; moved = false; d.classList.add('dragging'); });
    d.addEventListener('pointermove', e => {
      if (!d.hasPointerCapture(e.pointerId)) return;
      const dx = (e.clientX - sx) / zoom, dy = (e.clientY - sy) / zoom; if (Math.abs(dx) + Math.abs(dy) > 4) moved = true; if (!moved) return;
      const st = $('wfStage'), w = st.clientWidth, h = st.clientHeight;
      const x = Math.min(w - 40, Math.max(40, ox + dx)), y = Math.min(h - 25, Math.max(25, oy + dy));
      d.style.left = (x / w * 100) + '%'; d.style.top = y + 'px'; draw();
    });
    d.addEventListener('pointerup', e => { d.releasePointerCapture(e.pointerId); d.classList.remove('dragging'); if (!moved && e.pointerType === 'touch') detail(id); });  // a mouse opens details through the right-click menu; a finger taps
    d.addEventListener('contextmenu', e => { e.preventDefault(); menu(id, e.clientX, e.clientY); });
  }
  function menu(id, x, y) {  // right-click menu on a node
    document.querySelectorAll('.wf-menu').forEach(m => m.remove());
    const m = document.createElement('div'); m.className = 'wf-menu';
    m.innerHTML = `<div class="mh">${escH(NODES[id][3])}</div><button type="button" data-a="detail">See details</button>${CARDS && CARDS[id] && CARDS[id].model ? '<button type="button" data-a="prompt">Show model and system prompt</button>' : ''}`;
    m.style.left = Math.min(x, innerWidth - 230) + 'px'; m.style.top = Math.min(y, innerHeight - 130) + 'px'; document.body.appendChild(m);
    const close = () => { m.remove(); removeEventListener('pointerdown', away, true); removeEventListener('keydown', esc, true); };
    const away = ev => { if (!m.contains(ev.target)) close(); }, esc = ev => { if (ev.key === 'Escape') close(); };
    setTimeout(() => { addEventListener('pointerdown', away, true); addEventListener('keydown', esc, true); }, 0);
    m.querySelectorAll('button').forEach(b => b.onclick = () => { close(); detail(id); if (b.dataset.a === 'prompt') setTimeout(() => $('wfdetail').querySelector('.sysprompt')?.scrollIntoView({block: 'nearest'}), 50); });
  }
  let CARDS = null;
  fetch('/api/agents').then(r => r.json()).then(c => { CARDS = c; if (selected) detail(selected); }).catch(() => {});
  function detail(id) {
    selected = id; Object.values(el).forEach(n => n.classList.toggle('sel', n.dataset.id === id));
    const n = NODES[id], h = hist[id].slice(-8).reverse(), box = $('wfdetail');
    const kind = {core: 'control plane', code: 'plain code', model: 'Vultr AI model', chat: 'Vultr AI models', orch: 'orchestrator · most capable model', human: 'human'}[n[5]] || n[5];
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    box.innerHTML = `<div class="dhead"><b>${esc(n[3])}</b><span class="dk ${n[5]}">${esc(kind)}</span><button type="button" class="dx" id="wfdx" aria-label="Close">×</button></div>`
      + `<p>${esc(INFO[id] || n[4])}</p>`
      + (CARDS && CARDS[id] ? `<h6>Agent card</h6><p class="small">${esc(CARDS[id].does)}</p>` + (CARDS[id].model ? `<p class="small"><b>Model:</b> ${esc(CARDS[id].model)}</p><h6>System prompt</h6><pre class="sysprompt">${esc(CARDS[id].prompt)}</pre>` : '<p class="small"><b>Plain code:</b> no AI model, so there is no prompt.</p>') : '')
      + (h.length ? `<h6>Latest output</h6><div class="dout">${esc(h[0].text)}</div><h6>History</h6><ul>${h.map(x => `<li><i>${x.at}s</i> ${esc(x.text)}</li>`).join('')}</ul>` : '<p class="small">No activity yet in this scan.</p>');
    box.classList.remove('hidden'); $('wfdx').onclick = () => { box.classList.add('hidden'); selected = null; Object.values(el).forEach(x => x.classList.remove('sel')); };
  }
  function draw() {
    const keep = {}; document.querySelectorAll('#wfSvg .we').forEach(p => keep[p.dataset.e] = p.getAttribute('class'));
    const svg = $('wfSvg'); svg.innerHTML = '';
    EDGES.forEach(([a, b, k]) => {
      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', pathD(a, b)); p.setAttribute('class', keep[a + '>' + b] || ('we ' + (k || ''))); p.dataset.e = a + '>' + b; svg.appendChild(p);
    });
    drawArgues(); syncEdges();
  }
  function syncEdges() {  // a line shows only when both of its nodes have appeared (a class, so no redraw can bring a stray line back)
    const shown = (a, b) => el[a] && el[b] && !el[a].classList.contains('ghost') && !el[b].classList.contains('ghost');
    document.querySelectorAll('#wfSvg .we').forEach(p => {
      const [a, b] = p.dataset.e ? p.dataset.e.split('>') : [p.dataset.a, p.dataset.b];
      p.style.opacity = ''; p.classList.toggle('hid', !shown(a, b));
    });
  }

  const HUES = {script: 262, endpoints: 200, privacy: 160, lure: 24, intel: 330, cloak: 48, check: 210, geo: 180, tls: 120, lead: 285, orch: 42, v_careless: 12, v_phone: 190, v_bot: 90};
  const NAME = {lead: 'Review lead', orch: 'Orchestrator'};
  const escH = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
  function say(who, text, o = {}) {  // one message in the agent chat room
    const list = $('crList'); if (!list) return null; list.querySelector('.cr-empty')?.remove();
    list.querySelectorAll('.cr-typing').forEach(x => x.remove());
    const m = document.createElement('div'); m.className = 'cr-msg ' + (o.cls || '');
    const nm = NAME[who] || (NODES[who] ? NODES[who][3] : who), h = HUES[who] ?? 220;
    m.innerHTML = `<span class="cr-av" style="--h:${h}">${iconHtml('🧠')}</span><div class="cr-body"><div class="cr-name" style="--h:${h}">${escH(nm)}${o.to ? ` <i>to ${escH(NODES[o.to] ? NODES[o.to][3] : o.to)}</i>` : ''}${o.tag ? `<u class="cr-tag ${o.cls || ''}">${escH(o.tag)}</u>` : ''}</div><div class="cr-text">${o.html || escH(text)}</div></div>`;
    list.appendChild(m); list.scrollTop = list.scrollHeight; $('wfStage').querySelector('.cr-live').textContent = o.live || 'live'; return m;
  }
  let CRQ = Promise.resolve();
  const crq = (fn, gap = 700) => { CRQ = CRQ.then(() => new Promise(r => setTimeout(() => { try { fn(); } catch (e) { console.error(e); } r(); }, gap))); };  // messages arrive one by one, like a conversation
  function typing(who) {
    const list = $('crList'); if (!list) return; const m = document.createElement('div'); m.className = 'cr-msg cr-typing';
    m.innerHTML = `<span class="cr-av" style="--h:${HUES[who] ?? 220}">${iconHtml('🧠')}</span><div class="cr-body"><div class="cr-name">${escH(NODES[who] ? NODES[who][3] : who)}</div><div class="cr-text"><b class="dots"><s></s><s></s><s></s></b></div></div>`;
    list.appendChild(m); list.scrollTop = list.scrollHeight;
  }
  let ARGUES = [];
  function drawArgues() {
    ARGUES.forEach(g => { if (!el[g.a] || !el[g.b]) return; const p = document.createElementNS(NS, 'path'); p.setAttribute('d', pathD(g.a, g.b)); p.setAttribute('class', 'we argue ' + g.cls); p.dataset.a = g.a; p.dataset.b = g.b; $('wfSvg').appendChild(p); });
  }
  function bubble(id, text, cls) {  // a speech bubble above an agent while it speaks in the debate
    if (!el[id]) return; const st = $('wfStage'), n = el[id];
    const d = document.createElement('div'); d.className = 'wbub ' + cls; d.textContent = String(text).slice(0, 150);
    d.style.left = n.offsetLeft + 'px'; d.style.top = (n.offsetTop - n.offsetHeight / 2 - 8) + 'px'; st.appendChild(d);
    setTimeout(() => d.classList.add('out'), 9000); setTimeout(() => d.remove(), 9600);
  }
  function argue(a, b, cls, text, speaker) {  // a labelled line between two agents; stays until the scan ends
    if (!el[a] || !el[b]) return; reveal([a, b], 0);
    ARGUES.push({a, b, cls}); if (ARGUES.length > 8) ARGUES.shift(); draw();
    const p = [...document.querySelectorAll('#wfSvg .argue')].pop(); if (!p) return;
    const len = p.getTotalLength(), dot = document.createElementNS(NS, 'circle'); dot.setAttribute('r', 6); dot.setAttribute('class', 'wp' + (cls === 'hot' ? ' bad' : '')); $('wfSvg').appendChild(dot);
    const t0 = performance.now(); (function step(t) { const k = Math.min(1, (t - t0) / 900), pt = p.getPointAtLength(k * len); dot.setAttribute('cx', pt.x); dot.setAttribute('cy', pt.y); if (t - t0 < 900) requestAnimationFrame(step); else dot.remove(); })(t0);
  }
  const edge = (a, b) => document.querySelector(`#wfSvg .we[data-e="${a}>${b}"]`);
  function light(a, b, bad) {
    const e = edge(a, b); if (!e) return;
    e.classList.remove('done'); e.classList.add('on'); e.classList.toggle('bad', !!bad);
    setTimeout(() => { e.classList.remove('on', 'bad'); e.classList.add('done'); }, 1500);
  }
  function packet(a, b, bad, back) {
    const e = edge(a, b); if (!e || e.style.opacity === '0') return;
    const len = e.getTotalLength(), dot = document.createElementNS(NS, 'circle');
    dot.setAttribute('r', 5); dot.setAttribute('class', 'wp' + (bad ? ' bad' : '')); $('wfSvg').appendChild(dot);
    const t0 = performance.now(), dur = 750;
    (function step(t) {
      let k = Math.min(1, (t - t0) / dur); k = k * k * (3 - 2 * k); if (back) k = 1 - k;
      const pt = e.getPointAtLength(k * len); dot.setAttribute('cx', pt.x); dot.setAttribute('cy', pt.y);
      if (t - t0 < dur) requestAnimationFrame(step); else dot.remove();
    })(t0);
  }
  function flow(a, b, bad, back) { light(a, b, bad); packet(a, b, bad, back); }
  function reveal(ids, stagger = 120) {  // nodes pop in one after another
    [].concat(ids).forEach((id, i) => setTimeout(() => { const n = el[id]; if (n && n.classList.contains('ghost')) { n.classList.remove('ghost'); n.classList.add('pop'); setTimeout(() => n.classList.remove('pop'), 700); syncEdges(); } }, i * stagger));
  }
  function state(id, st, text) {
    const n = el[id]; if (!n) return;
    n.classList.remove('ghost'); syncEdges();
    if (st) { n.classList.remove('active', 'done', 'bad'); n.classList.add(st); }
    if (text != null) {
      const t = text.replace(/\s+/g, ' ').slice(0, 64); n.querySelector('.live').textContent = t; n.title = '';
      const last = hist[id][hist[id].length - 1]; if (!last || last.text !== text) hist[id].push({text, at: ((performance.now() - T0) / 1000).toFixed(1)});
      if (selected === id) detail(id);
    }
  }
  function settle(except) { Object.values(el).forEach(n => { if (n.classList.contains('active') && n.dataset.id !== except) { n.classList.remove('active'); n.classList.add('done'); } }); }
  function chatter(on) {  // while the laptop visitor works, observations flow to it and commands flow back
    clearInterval(loop);
    if (on) loop = setInterval(() => { packet('sandbox', 'v_careless'); setTimeout(() => packet('sandbox', 'v_careless', false, true), 400); }, 1600);
  }
  function head(text, run) { $('wfState').textContent = text; $('wf').classList.toggle('run', !!run); }

  function reset() {
    ARGUES = []; document.querySelectorAll('#wfSvg .argue').forEach(x => x.remove()); CRQ = Promise.resolve(); { const l = $('crList'); if (l) l.innerHTML = '<p class="cr-empty">The agents meet here after the visitors leave: they post findings, question each other, answer and vote.</p>'; }
    if (!started) { started = true; build(); }
    T0 = performance.now(); destroyed = 0; expected = 1; Object.keys(hist).forEach(k => hist[k] = []);
    Object.entries(el).forEach(([id, n]) => { n.classList.remove('active', 'done', 'bad', 'pop'); n.classList.toggle('ghost', !START_VISIBLE.includes(id)); n.querySelector('.live').textContent = ''; n.title = ''; });
    document.querySelectorAll('#wfSvg .we').forEach(e => e.classList.remove('on', 'done', 'bad'));
    chatter(false); draw(); head('Starting…', true);
  }

  function event(ev) {
    if (!started) return;
    switch (ev.type) {
      case 'start':
        expected = (ev.swarm || []).length || 1;
        state('control', 'active', `${expected} visitors + ${expected > 1 ? 9 : 4} agents`); state('link', 'active', ev.url); flow('control', 'link'); head('The swarm is starting', true);
        reveal(['check', 'geo', 'tls'], 200); reveal('sandbox'); setTimeout(() => { reveal((ev.swarm || []).map(s => VISITOR[s.id]).filter(Boolean), 250); }, 700); break;
      case 'agent': {
        reveal(ev.id);
        const n = el[ev.id]; if (!n) break;
        setTimeout(() => {
          if (PARENT[ev.id]) flow(PARENT[ev.id], ev.id);
          if (ev.status === 'working') state(ev.id, 'active', 'working…');
          else { state(ev.id, ev.weight >= 15 ? 'bad' : 'done', (ev.findings && ev.findings[0]) || 'done'); (ev.findings || []).slice(1).forEach(f => state(ev.id, null, f)); if (ev.by && ev.by !== 'rules') state(ev.id, null, `${(ev.findings || [])[0] || ''}`); }
        }, 250); break;
      }
      case 'debate': {
        const node = {v_careless: 'v_careless', v_phone: 'v_phone', v_bot: 'v_bot', evidence: 'debate'};
        reveal(['orch', 'debate']);
        const av = (a, cls = '') => `<span class="cr-av ${cls}" style="--h:${HUES[a] ?? 220}">${iconHtml('🧠')}</span>`;
        const nm = a => escH(NAME[a] || (NODES[a] ? NODES[a][3] : a));
        if (ev.phase === 'share') {
          Object.keys(ev.posts || {}).forEach(a => flow(a, 'orch', false, true)); state('orch', 'active', 'reading ' + (ev.agents || []).length + ' findings'); state('debate', 'active', ev.text); head('The agents are debating', true);
          crq(() => say('orch', '', {cls: 'sys', tag: 'orchestrator joins', html: `${escH(ev.text)} The <b>orchestrator</b> (the most capable model) will read everything, question the agents, and call a vote.`}));
          Object.entries(ev.posts || {}).forEach(([a, f]) => crq(() => { flow('orch', a, false, true); say(a, f, {cls: 'post', tag: 'posts finding'}); }, 520));
        } else if (ev.phase === 'orchestrator') {
          crq(() => { state('orch', 'active', 'round ' + ev.round + ': questioning ' + (ev.asks || []).length + ' agent(s)'); state('debate', 'active', 'round ' + ev.round);
            say('orch', '', {cls: 'orch', tag: 'round ' + ev.round + ' · orchestrator', html: `${escH(ev.text)}<div class="cr-model">${escH(ev.model || 'rules')} · asks ${(ev.asks || []).length} agent(s)</div>`}); }, 900);
        } else if (ev.phase === 'challenge') {
          const from = el[ev.with] && ev.with !== 'debate' ? ev.with : 'orch';
          crq(() => { if (from === 'orch') flow('orch', ev.to, true); else argue(from, ev.to, 'hot'); state('debate', 'active', 'question → ' + ev.name);
            say(from, '', {cls: 'ask', tag: 'question', html: `<div class="cr-duel">${av(from, 's')}<span class="cr-arrow hot">asks ➜</span>${av(ev.to, 's')}<b>${nm(ev.to)}</b></div><div class="cr-q">${escH(ev.text)}</div>`}); typing(ev.to); }, 800);
        } else if (ev.phase === 'reply') {
          crq(() => { argue(ev.from, 'debate', ev.stance === 'revise' ? 'revise' : 'keep'); state(ev.from, ev.stance === 'revise' ? 'active' : 'done', (ev.stance === 'revise' ? 'revised: ' : 'kept: ') + (ev.revised || ev.text));
            const diff = ev.revised ? `<div class="cr-diff"><s>${escH(ev.was || '')}</s><span>${escH(ev.revised)}</span></div>` : '<div class="cr-ok">✓ re-checked the evidence, keeps its finding</div>';
            say(ev.from, '', {cls: ev.stance === 'revise' ? 'revise' : 'keep', tag: ev.stance === 'revise' ? 'changes its mind' : 'stands by it', html: `${escH(ev.text)}${diff}`}); }, 800);
        } else if (ev.phase === 'proposal') {
          crq(() => say('orch', '', {cls: 'sys proposal', tag: 'round ' + ev.round + ' · proposal', html: `<b>Vote on this:</b> ${escH(ev.text)}`}), 700);
        } else if (ev.phase === 'vote') {
          crq(() => { const lbl = {agree: 'agrees', neutral: 'nothing in its area', object: 'OBJECTS', abstain: 'abstains'}[ev.vote] || ev.vote;
            const list = $('crList'); if (!list) return; list.querySelector('.cr-empty')?.remove(); list.querySelectorAll('.cr-typing').forEach(x => x.remove());
            const m = document.createElement('div'); m.className = 'cr-ballot ' + ev.vote;
            m.innerHTML = `${av(ev.from, 's')}<b>${nm(ev.from)}</b><span class="cr-pill ${ev.vote}">${lbl}</span><em>${escH(ev.text)}</em>`; list.appendChild(m); list.scrollTop = list.scrollHeight;
            light('orch', ev.from, ev.vote === 'object'); if (ev.vote === 'object' && el[ev.from]) el[ev.from].classList.add('bad'); }, 330);
        } else if (ev.phase === 'consensus') {
          crq(() => {
            const vs = Object.entries(ev.votes || {}).filter(([, v]) => v !== 'abstain');
            const bar = vs.map(([a, v]) => `<i class="${v}" title="${nm(a)}: ${v}"></i>`).join('');
            const dis = ev.dissent && ev.dissent.length;
            state('debate', dis ? 'bad' : 'done', (dis ? 'dissent' : 'agreed') + ' · ' + (ev.rounds || 1) + ' round(s)'); state('orch', dis ? 'bad' : 'done', (dis ? 'dissent recorded' : 'agreement reached') + ' after ' + (ev.rounds || 1) + ' round(s)');
            say('orch', '', {cls: 'sys vote', tag: 'final · ' + (ev.rounds || 1) + ' round(s)', live: dis ? 'dissent' : 'agreed', html: `<div class="cr-meter">${bar}</div><div class="cr-big">${dis ? ev.dissent.length + ' agent(s) object' : 'Agreement reached'} · ${ev.agree} agree, ${(ev.total || 0) - (ev.agree || 0) - (dis ? ev.dissent.length : 0)} neutral</div>${escH(ev.text || '')}`});
          }, 900);
        }
        break;
      }
      case 'signals': break;
      case 'sandbox':
        if (ev.phase === 'created') { flow('check', 'sandbox'); settle('sandbox'); state('sandbox', 'active', `${ev.info.name} · ${ev.info.mode}`); head('Visitors are browsing', true); }
        else {
          destroyed++; reveal('destroy'); setTimeout(() => { state('destroy', destroyed >= expected ? 'done' : 'active', `${destroyed}/${expected} destroyed`); Object.values(VISITOR).forEach(v => flow(v, 'destroy')); }, 200);
          if (destroyed >= expected) { chatter(false); head('Analysts are reading the evidence', true); }
        } break;
      case 'scout': { const v = VISITOR[ev.id]; if (v) { flow('sandbox', v); state(v, ev.asked && ev.asked.length ? 'bad' : 'active', ev.title ? 'saw: ' + ev.title : 'opening…'); } break; }
      case 'page':
        state('v_careless', ev.leaks && ev.leaks.length ? 'bad' : 'active', ev.title ? 'saw: ' + ev.title : 'opening…');
        (ev.leaks || []).forEach(l => { flow('v_careless', 'net', true); state('net', 'bad', `fake ${l.data.join('+').toLowerCase()} → ${l.host}`); }); break;
      case 'observe': flow('sandbox', 'v_careless'); state('v_careless', 'active', ev.text); chatter(true); break;
      case 'action': flow('sandbox', 'v_careless', false, true); state('v_careless', 'active', ev.reason || ev.action); break;
      case 'containment': reveal('net'); flow('v_careless', 'net', true); state('net', 'bad', 'blocked ' + new URL(ev.url).hostname); break;
      case 'download': reveal('net'); flow('v_careless', 'net', true); state('net', 'bad', 'download kept inside: ' + ev.filename); break;
      case 'verdict':
        chatter(false); reveal('judge'); setTimeout(() => {
          flow('debate', 'judge');
          state('judge', ev.level === 'DANGEROUS' ? 'bad' : 'active', `${ev.level.toLowerCase()} · ${ev.score}/100`); reveal('summary');
          setTimeout(() => { flow('judge', 'summary'); settle('summary'); state('summary', 'active', ev.summary); }, 700);
        }, 400); break;
      case 'end': chatter(false); reveal('human'); setTimeout(() => { flow('summary', 'human'); settle('human'); state('human', 'active', 'waiting for you…'); head('Waiting for your decision', false); }, 1300); break;
      case 'investigation': reveal('analysts'); setTimeout(() => { flow('judge', 'analysts'); settle('analysts'); state('analysts', 'active', ev.analysts.map(a => a.name).join(' · ')); head('Analysts investigating', true); }, 300); break;
      case 'analyst': state('analysts', 'active', ev.name + ': ' + (ev.findings[0] || '')); break;
      case 'report': flow('analysts', 'human'); state('analysts', 'done', 'report ready'); head('Report ready', false); break;
      case 'queued': head('Waiting in the queue: #' + ev.position, true); break;
      case 'running': head('Starting…', true); break;
      case 'decision': state('human', 'done', 'you chose: ' + ev.choice); head('Done: you decided', false); break;
    }
  }
  document.addEventListener('DOMContentLoaded', () => { started = true; build(); });
  return {event, reset};
})();
