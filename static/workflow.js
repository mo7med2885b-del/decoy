// Agent workflow panel. Every line and dot is driven by the real events of a scan (WF.event is called from app.js).
const WF = (() => {
  const NS = 'http://www.w3.org/2000/svg';
  // id: [x%, y%, icon, title, subtitle, kind]
  const NODES = {
    control: [50, 62, '', 'Decoy control plane', 'Vultr VM · plans and verifies', 'core'],
    link: [50, 152, '✉', 'Suspicious link', 'email · WhatsApp · text', 'code'],
    check: [50, 230, '⌁', 'Address check', 'code · look-alikes', 'code'],
    sandbox: [50, 308, '▣', 'Sealed browser', 'a fresh Docker box each', 'code'],
    explore: [27, 410, '◉', 'Explorer agent', 'Vultr AI · small model', 'model'],
    net: [73, 410, '⛨', 'Egress filter', 'code · blocks private IPs', 'code'],
    memory: [73, 505, '◈', 'Threat memory', 'SQLite · seen before?', 'code'],
    destroy: [27, 505, '✕', 'Sandbox destroyed', 'lifecycle', 'code'],
    judge: [50, 596, '⚖', 'Evidence judge', 'code · score by rules', 'code'],
    summary: [27, 694, '✎', 'Summary', 'Vultr AI · small model', 'model'],
    human: [73, 694, '✓', 'Your decision', 'block · safe · dismiss', 'human'],
  };
  const EDGES = [['control', 'link', 'model'], ['link', 'check'], ['check', 'sandbox'], ['sandbox', 'explore', 'model'], ['sandbox', 'net'],
    ['explore', 'destroy'], ['destroy', 'judge'], ['net', 'memory'], ['memory', 'judge'], ['judge', 'summary', 'model'], ['summary', 'human']];
  const $ = id => document.getElementById(id);
  const el = {};
  let loop = null, started = false;

  function build() {
    const stage = $('wfStage');
    Object.entries(NODES).forEach(([id, [x, y, ic, t, sub, kind]]) => {
      const d = document.createElement('div');
      d.className = 'wn ' + kind; d.style.left = x + '%'; d.style.top = y + 'px'; d.dataset.id = id;
      d.innerHTML = kind === 'core' ? `<div class="ball"></div><b>${t}</b><small>${sub}</small><span class="live"></span>`
        : `<b><i>${ic}</i>${t}</b><small>${sub}</small><span class="live"></span>`;
      stage.appendChild(d); el[id] = d;
    });
    draw(); addEventListener('resize', draw);
  }
  function box(id) {
    const s = $('wfStage').getBoundingClientRect(), r = el[id].getBoundingClientRect();
    // use the unscaled layout box (active nodes are scaled up a little)
    const w = el[id].offsetWidth, h = el[id].offsetHeight;
    return {x: r.left + r.width / 2 - s.left, y: r.top + r.height / 2 - s.top, w: w / 2, h: h / 2};
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
  function draw() {
    const svg = $('wfSvg'); svg.innerHTML = '';
    EDGES.forEach(([a, b, k]) => {
      const p = document.createElementNS(NS, 'path');
      p.setAttribute('d', pathD(a, b)); p.setAttribute('class', 'we ' + (k || '')); p.dataset.e = a + '>' + b; svg.appendChild(p);
    });
  }
  const edge = (a, b) => document.querySelector(`#wfSvg .we[data-e="${a}>${b}"]`);
  function light(a, b, bad) {
    const e = edge(a, b); if (!e) return;
    e.classList.remove('done'); e.classList.add('on'); e.classList.toggle('bad', !!bad);
    setTimeout(() => { e.classList.remove('on', 'bad'); e.classList.add('done'); }, 1500);
  }
  function packet(a, b, bad, back) {
    const e = edge(a, b); if (!e) return;
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
  function state(id, st, text) {
    const n = el[id]; if (!n) return;
    if (st) { n.classList.remove('active', 'done', 'bad'); n.classList.add(st); }
    if (text != null) { const t = text.replace(/\s+/g, ' ').slice(0, 60); n.querySelector('.live').textContent = t; n.title = text; }
  }
  function settle(except) { Object.values(el).forEach(n => { if (n.classList.contains('active') && n.dataset.id !== except) { n.classList.remove('active'); n.classList.add('done'); } }); }
  function chatter(on) {  // while the explorer works, observations flow to it and commands flow back
    clearInterval(loop);
    if (on) loop = setInterval(() => { packet('sandbox', 'explore'); setTimeout(() => packet('sandbox', 'explore', false, true), 400); }, 1600);
  }
  function head(text, run) { $('wfState').textContent = text; $('wf').classList.toggle('run', !!run); }

  function reset() {
    if (!started) { started = true; build(); }
    Object.values(el).forEach(n => { n.classList.remove('active', 'done', 'bad'); n.querySelector('.live').textContent = ''; n.title = ''; });
    document.querySelectorAll('#wfSvg .we').forEach(e => e.classList.remove('on', 'done', 'bad'));
    chatter(false); draw(); head('Starting…', true);
  }

  function event(ev) {
    if (!started) return;
    switch (ev.type) {
      case 'start':
        state('control', 'active', 'scan started'); state('link', 'active', ev.url); flow('control', 'link'); if (ev.swarm && ev.swarm.length > 1) state('sandbox', null, ev.swarm.length + ' visitors in parallel'); head('Checking the address', true);
        setTimeout(() => { flow('link', 'check'); settle('check'); state('check', 'active', 'checking…'); }, 500); break;
      case 'signals': state('check', 'active', ev.items[0].text); break;
      case 'sandbox':
        if (ev.phase === 'created') {
          flow('check', 'sandbox'); settle('sandbox'); state('sandbox', 'active', `${ev.info.name} · ${ev.info.mode}`); head('Sandbox running', true);
        } else {
          chatter(false); flow('explore', 'destroy'); settle('destroy'); state('destroy', 'active', `destroyed after ${ev.info.lived_s}s`); head('Judging the evidence', true);
        } break;
      case 'page':
        (ev.leaks || []).forEach(l => { flow('sandbox', 'net', true); state('net', 'bad', `fake ${l.data.join('+').toLowerCase()} → ${l.host}`); }); break;
      case 'observe':
        flow('sandbox', 'explore'); settle('explore'); state('explore', 'active', ev.text); chatter(true); head('Explorer agent working', true); break;
      case 'action': flow('sandbox', 'explore', false, true); state('explore', 'active', ev.reason || ev.action); break;
      case 'containment': flow('sandbox', 'net', true); state('net', 'bad', 'blocked ' + new URL(ev.url).hostname); break;
      case 'download': flow('sandbox', 'net', true); state('net', 'bad', 'download kept inside: ' + ev.filename); break;
      case 'verdict':
        chatter(false); flow('net', 'memory'); flow('memory', 'judge'); flow('destroy', 'judge'); settle('memory'); const m = ev.memory || {}; state('memory', (m.campaign || []).length ? 'bad' : 'active', (m.campaign || []).length ? 'campaign: ' + m.campaign.length + ' linked' : (m.seen_before || []).length ? 'seen ' + m.seen_before.length + 'x before' : 'new to us'); settle('judge');
        state('judge', ev.level === 'DANGEROUS' ? 'bad' : 'active', `${ev.level.toLowerCase()} · ${ev.score}/100`);
        setTimeout(() => { flow('judge', 'summary'); settle('summary'); state('summary', 'active', ev.summary); }, 900); break;
      case 'end': chatter(false); flow('summary', 'human'); settle('human'); state('human', 'active', 'waiting for you…'); head('Waiting for your decision', false); break;
      case 'queued': head('Waiting in the queue: #' + ev.position, true); break;
      case 'running': head('Starting…', true); break;
      case 'decision': state('human', 'done', 'you chose: ' + ev.choice); head('Done: you decided', false); break;
    }
  }
  document.addEventListener('DOMContentLoaded', () => { started = true; build(); });
  return {event, reset};
})();
