// Command-center globe. Idle: it rotates. During a scan it flies to where the link's server really is (or a labelled
// simulated place for our fake demo sites), draws the visitors' route from the Vultr server, and orange arcs to wherever
// stolen data goes. Driven only by the scan's real events (GLB.event is called from app.js).
const GLB = (() => {
  const COLORS = {origin: '#4d9bff', lure: '#ff7a1a', redirect: '#ffc48a', contacted: '#8fb0ff', exfil: '#ff4d2e'};
  let g = null, origin = null, lure = null, points = [], arcs = [], rings = [], labels = [], timer = null;
  const $ = id => document.getElementById(id);
  const fmt = (lat, lng) => `${lng >= 0 ? 'E' : 'W'} ${Math.abs(lng).toFixed(2)}  ${lat >= 0 ? 'N' : 'S'} ${Math.abs(lat).toFixed(2)}`;
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

  function init() {
    const el = $('globe');
    if (!el || typeof Globe === 'undefined') { $('globecard') && $('globecard').classList.add('hidden'); return; }
    try {
      g = Globe()(el)
        .globeImageUrl('/static/vendor/earth-blue-marble.jpg').bumpImageUrl('/static/vendor/earth-topology.png').backgroundImageUrl('/static/vendor/night-sky.png')
        .atmosphereColor('#4d8bff').atmosphereAltitude(0.24)
        .pointAltitude(0.015).pointRadius(d => d.role === 'origin' ? 0.5 : 0.6).pointColor(d => d.color)
        .arcColor(d => d.color).arcStroke(0.55).arcDashLength(0.35).arcDashGap(0.18).arcDashAnimateTime(1400).arcAltitudeAutoScale(0.45)
        .ringColor(d => t => hexA(d.color, 1 - t)).ringMaxRadius(d => d.r || 5).ringPropagationSpeed(2.4).ringRepeatPeriod(1100)
        .htmlLat(d => d.lat).htmlLng(d => d.lng).htmlAltitude(0.06).htmlElement(d => label(d));
      try { g.renderer().setPixelRatio(Math.min(devicePixelRatio || 1, 1.25)); } catch (e) {}  // keeps the 3D globe light on laptops
      // the 3D globe only renders while a scan is on screen (and the tab is visible): at the start screen it is paused, so it costs nothing
      const gate = () => { try { (document.body.dataset.stage === 'run' && !document.hidden) ? g.resumeAnimation() : g.pauseAnimation(); } catch (e) {} };
      new MutationObserver(gate).observe(document.body, {attributes: true, attributeFilter: ['data-stage']}); document.addEventListener('visibilitychange', gate); gate();
      g.controls().autoRotate = true; g.controls().autoRotateSpeed = 0.7; g.controls().enableZoom = true; g.controls().minDistance = 125; g.controls().maxDistance = 480; g.controls().zoomSpeed = 0.8;
      g.onPointClick(p => focus(p)).pointRadius(d => d.role === 'origin' ? 0.55 : 0.8);
      const zb = f => () => { const pv = g.pointOfView(); g.controls().autoRotate = false; g.pointOfView({altitude: Math.min(4, Math.max(0.2, pv.altitude * f))}, 450); };
      $('gzin').onclick = zb(0.6); $('gzout').onclick = zb(1.6);
      $('gzreset').onclick = () => { g.controls().autoRotate = !lure; g.pointOfView(lure ? {lat: lure.lat, lng: lure.lng, altitude: 1.6} : {lat: 25, lng: 20, altitude: 2.3}, 900); document.querySelectorAll('.glabel.open').forEach(x => x.classList.remove('open')); };
      const size = () => { const r = el.getBoundingClientRect(); g.width(r.width).height(r.height); };
      size(); new ResizeObserver(size).observe(el);
      g.pointOfView({lat: 25, lng: 20, altitude: 2.3}, 0);
      hud('Paste a link: the visitors set off from our Vultr server', '');
    } catch (e) { console.warn('globe unavailable', e); $('globecard').classList.add('hidden'); g = null; }
  }
  function hexA(hex, a) { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${Math.max(0, a)})`; }
  function label(d) {
    const e = document.createElement('div'); e.className = 'glabel ' + d.role;
    e.innerHTML = `<b>${esc(d.title)}</b><small>${esc(d.sub)}</small>${d.role === 'lure' || d.role === 'exfil' ? `<i>${fmt(d.lat, d.lng)}${d.simulated ? ' · simulated' : ''}</i>` : ''}`
      + `<span class="more">${d.ip && d.ip !== 'simulated' ? 'IP ' + esc(d.ip) + '<br>' : ''}${d.org ? esc(d.org) + '<br>' : ''}${d.simulated ? 'demo location (simulated)' : esc(d.role)}</span>`;
    e.style.pointerEvents = 'auto'; e.style.cursor = 'pointer'; e.onclick = ev => { ev.stopPropagation(); focus(d); };
    return e;
  }
  function focus(d) {
    document.querySelectorAll('.glabel.open').forEach(x => x.classList.remove('open'));
    const el = [...document.querySelectorAll('.glabel')].find(x => x.querySelector('b') && x.querySelector('b').textContent === (d.title || d.host)); if (el) el.classList.add('open');
    fly(d.lat, d.lng, 0.55, 1200);
    hud(`${d.title || d.host}${d.ip && d.ip !== 'simulated' ? ' · ' + d.ip : ''}${d.org ? ' · ' + d.org : ''}`, '');
  }
  function hud(text, state) { if ($('ghud')) { $('ghud').textContent = text; $('gstate').textContent = state; $('gstate').className = 'gstate ' + (state ? state.toLowerCase().replace(/\W+/g, '-') : ''); } }
  function refresh() { if (!g) return; g.pointsData(points).arcsData(arcs).ringsData(rings).htmlElementsData(labels); }
  function fly(lat, lng, alt, ms = 1800) { if (g) { g.controls().autoRotate = false; g.pointOfView({lat, lng, altitude: alt}, ms); } }

  function reset() {
    if (!g) return; clearTimeout(timer);
    origin = lure = null; points = []; arcs = []; rings = []; labels = []; refresh();
    g.controls().autoRotate = true; g.pointOfView({lat: 25, lng: 20, altitude: 2.3}, 1200);
    hud('Sending visitors out…', 'STARTING');
  }

  function event(ev) {
    if (!g) return;
    if (ev.type === 'start' && ev.origin) {
      origin = ev.origin;
      points.push({lat: origin.lat, lng: origin.lng, color: COLORS.origin, role: 'origin'});
      labels.push({lat: origin.lat, lng: origin.lng, role: 'origin', title: origin.label, sub: 'visitors start here', simulated: false});
      rings.push({lat: origin.lat, lng: origin.lng, color: COLORS.origin, r: 4}); refresh();
      fly(origin.lat, origin.lng, 1.9, 1400); hud('Resolving where the link really points…', 'LOCATING');
    } else if (ev.type === 'geo') {
      const where = [ev.city, ev.code].filter(Boolean).join(', ') || ev.country || 'unknown';
      points.push({lat: ev.lat, lng: ev.lng, color: COLORS[ev.role] || COLORS.contacted, role: ev.role, title: ev.host, ip: ev.ip, org: ev.org});
      labels.push({lat: ev.lat, lng: ev.lng, role: ev.role, ip: ev.ip, org: ev.org, title: ev.host, sub: `${ev.role === 'exfil' ? 'stolen data → ' : ''}${where}`, simulated: ev.simulated});
      rings.push({lat: ev.lat, lng: ev.lng, color: COLORS[ev.role] || COLORS.contacted, r: ev.role === 'exfil' ? 8 : 6});
      if (ev.role === 'lure') {
        lure = ev;
        if (origin) arcs.push({startLat: origin.lat, startLng: origin.lng, endLat: ev.lat, endLng: ev.lng, color: COLORS.origin});
        fly(ev.lat, ev.lng, 1.5, 2000); hud(`${ev.host} is hosted in ${where}${ev.org && !ev.simulated ? ' (' + ev.org + ')' : ''}`, 'LOCATED');
      } else if (ev.role === 'exfil') {
        const from = lure || origin;
        if (from) arcs.push({startLat: from.lat, startLng: from.lng, endLat: ev.lat, endLng: ev.lng, color: COLORS.exfil});
        if (from) fly((from.lat + ev.lat) / 2, (from.lng + ev.lng) / 2, 2.0, 1800);
        hud(`Stolen data flows to ${where}`, 'DATA LEAK');
      } else if (lure && ev.role !== 'origin') {
        arcs.push({startLat: lure.lat, startLng: lure.lng, endLat: ev.lat, endLng: ev.lng, color: COLORS[ev.role] || COLORS.contacted});
      }
      refresh();
    } else if (ev.type === 'verdict') {
      const bad = ev.level === 'DANGEROUS' || ev.level === 'SUSPICIOUS';
      hud(bad ? `${ev.level}: ${ev.evidence.length} red flag(s)` : 'No threat found', bad ? ev.level : 'CLEAR');
      timer = setTimeout(() => { if (g) { g.controls().autoRotate = true; g.pointOfView({lat: lure ? lure.lat : 20, lng: lure ? lure.lng : 10, altitude: 2.3}, 2200); } }, 5000);
    }
  }
  document.addEventListener('DOMContentLoaded', init);
  return {event, reset};
})();
