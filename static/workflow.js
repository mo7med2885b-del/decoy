// Agent workflow canvas. Every node, line and dot is driven by the real events of a scan (WF.event is called from app.js).
// The swarm: three visitors in their own sandboxes plus nine specialist agents. Nodes APPEAR when their agent starts.
const WF = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  // id: [x%, y px, icon, title, subtitle, kind]
  const NODES = {
    control: [50, 62, '', 'Decoy control plane', 'Vultr VM · plans and verifies', 'core'],
    link: [50, 150, '✉', 'Suspicious link', 'email · WhatsApp · text', 'code'],
    check: [17, 245, '⌁', 'Reputation', 'code · domain age', 'code'],
    geo: [50, 245, '◎', 'Server location', 'code · IP, city, host', 'code'],
    tls: [83, 245, '🔒', 'TLS certificate', 'code · issuer, age', 'code'],
    sandbox: [50, 345, '▣', 'Sealed browsers', 'Docker + gVisor each', 'code'],
    v_careless: [17, 445, '◉', 'Careless employee', 'laptop · Vultr AI explorer', 'model'],
    v_phone: [50, 445, '▯', 'Phone user', 'iPhone · rule-based', 'code'],
    v_bot: [83, 445, '⚙', 'Security bot', 'link scanner · rule-based', 'code'],
    net: [17, 545, '⛨', 'Egress filter', 'blocks private addresses', 'code'],
    destroy: [50, 545, '✕', 'Sandboxes gone', 'nothing remains', 'code'],
    script: [17, 650, '‹/›', 'Script analyst', 'DeepSeek · reads the code', 'model'],
    endpoints: [50, 650, '⇄', 'Endpoint hunter', 'Qwen · requests and countries', 'model'],
    privacy: [83, 650, '◔', 'Privacy', 'MiMo · storage, console', 'model'],
    lure: [17, 750, '◎', 'Lure analyst', 'MiniMax · manipulation', 'model'],
    intel: [50, 750, '◈', 'Threat intel', 'memory · campaigns', 'code'],
    cloak: [83, 750, '⚖', 'Cloak detector', 'compares visitors', 'code'],
    debate: [50, 855, '💬', 'Agent debate', 'share · challenge · vote', 'model'],
    judge: [50, 960, '⚖', 'Evidence judge', 'code · score by rules', 'code'],
    analysts: [17, 1065, '🔎', 'Analyst team', 'Investigate mode', 'model'],
    summary: [50, 1065, '✎', 'Summary', 'GLM · plain words', 'model'],
    human: [83, 1065, '✓', 'Your decision', 'block · safe · dismiss', 'human'],
  };
  const EDGES = [['control', 'link', 'model'], ['link', 'check'], ['link', 'geo'], ['link', 'tls'], ['check', 'sandbox'], ['sandbox', 'v_careless', 'model'], ['sandbox', 'v_phone'], ['sandbox', 'v_bot'],
    ['v_careless', 'net'], ['v_careless', 'destroy'], ['v_phone', 'destroy'], ['v_bot', 'destroy'],
    ['destroy', 'script', 'model'], ['destroy', 'endpoints', 'model'], ['destroy', 'privacy', 'model'], ['script', 'lure', 'model'], ['endpoints', 'intel'], ['privacy', 'cloak'],
    ['lure', 'debate'], ['intel', 'debate'], ['cloak', 'debate'], ['debate', 'judge', 'model'], ['judge', 'analysts', 'model'], ['judge', 'summary', 'model'], ['analysts', 'human', 'model'], ['summary', 'human']];
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
    debate: 'The agents post their findings on one board. A review lead (another open model) challenges contradictions and gaps, the challenged agents answer (keep or revise), then every agent votes. Revisions change what an agent says, never the score.',
    judge: 'Plain code scores all the evidence. No model ever sets the verdict.',
    analysts: 'Investigate mode: the specialists above plus the network and infrastructure analysts, and a lead analyst, write the incident report.',
    summary: 'A Vultr AI model writes the plain-words summary. Code rejects it if it contradicts the score.',
    human: 'Decoy never blocks or reports anything by itself. You decide, and it is recorded.',
  };
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
      d.innerHTML = kind === 'core' ? `<div class="ball"></div><b>${t}</b><small>${sub}</small><span class="live"></span>`
        : `<b><i>${ic}</i>${t}</b><small>${sub}</small><span class="live"></span>`;
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
    d.addEventListener('pointerup', e => { d.releasePointerCapture(e.pointerId); d.classList.remove('dragging'); if (!moved) detail(id); });
  }
  function detail(id) {
    selected = id; Object.values(el).forEach(n => n.classList.toggle('sel', n.dataset.id === id));
    const n = NODES[id], h = hist[id].slice(-8).reverse(), box = $('wfdetail');
    const kind = {core: 'control plane', code: 'plain code', model: 'Vultr AI model', human: 'human'}[n[5]] || n[5];
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    box.innerHTML = `<div class="dhead"><b>${esc(n[3])}</b><span class="dk ${n[5]}">${esc(kind)}</span><button type="button" class="dx" id="wfdx" aria-label="Close">×</button></div>`
      + `<p>${esc(INFO[id] || n[4])}</p>`
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
    syncEdges();
  }
  function syncEdges() {  // a line shows only when both of its nodes have appeared
    document.querySelectorAll('#wfSvg .we').forEach(p => { if (!p.dataset.e) return; const [a, b] = p.dataset.e.split('>'); p.style.opacity = (el[a] && el[b] && !el[a].classList.contains('ghost') && !el[b].classList.contains('ghost')) ? '' : '0'; });
  }
  function argue(a, b, hot) {  // a temporary line between two agents while they argue
    if (!el[a] || !el[b]) return; reveal([a, b], 0);
    const p = document.createElementNS(NS, 'path'); p.setAttribute('d', pathD(a, b)); p.setAttribute('class', 'we argue' + (hot ? ' hot' : '')); $('wfSvg').appendChild(p);
    const len = p.getTotalLength(), dot = document.createElementNS(NS, 'circle'); dot.setAttribute('r', 6); dot.setAttribute('class', 'wp' + (hot ? ' bad' : '')); $('wfSvg').appendChild(dot);
    const t0 = performance.now(); (function step(t) { const k = Math.min(1, (t - t0) / 900), pt = p.getPointAtLength(k * len); dot.setAttribute('cx', pt.x); dot.setAttribute('cy', pt.y); if (t - t0 < 900) requestAnimationFrame(step); else dot.remove(); })(t0);
    setTimeout(() => p.remove(), 2600);
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
        reveal('debate');
        if (ev.phase === 'share') { ['lure', 'intel', 'cloak'].forEach(a => flow(a, 'debate')); state('debate', 'active', ev.text); head('The agents are debating', true); }
        else if (ev.phase === 'challenge') { argue(node[ev.with] || ev.with, ev.to, true); state('debate', 'active', 'challenge → ' + ev.name); }
        else if (ev.phase === 'reply') { argue(ev.from, 'debate', false); state(ev.from, ev.stance === 'revise' ? 'active' : 'done', (ev.stance === 'revise' ? 'revised: ' : 'kept: ') + (ev.revised || ev.text)); }
        else if (ev.phase === 'consensus') {
          Object.entries(ev.votes || {}).forEach(([a, vt]) => { if (el[a] && vt === 'alarm') el[a].classList.add('bad'); });
          state('debate', ev.dissent && ev.dissent.length ? 'bad' : 'done', ev.total ? ev.agree + '/' + ev.total + ' agree' : 'no votes');
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
