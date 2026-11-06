// Wireframe orb behind the start screen: meridians and parallels, blue on one side and orange on the other, slowly turning. Pure canvas, no library.
(() => {
  const hero = document.getElementById('intake'); if (!hero) return;
  const cv = document.createElement('canvas'); cv.id = 'orb'; hero.prepend(cv); const g = cv.getContext('2d');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches; let rot = 0, W = 0, H = 0, VIS = 0, raf = 0;
  function size() { const r = hero.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 2); W = cv.width = Math.round(r.width * d); H = cv.height = Math.round(r.height * d); cv.style.width = r.width + 'px'; cv.style.height = r.height + 'px'; VIS = Math.min(r.height, Math.max(300, innerHeight - r.top)) * d; }  // the part of the hero that is on screen: the whole globe fits in it
  function draw() {
    if (document.body.dataset.stage === 'run') { raf = requestAnimationFrame(draw); return; }
    g.clearRect(0, 0, W, H);
    const R = Math.min(W * 0.3, VIS * 0.46), cx = W / 2, cy = VIS * 0.5, tilt = -0.35, ct = Math.cos(tilt), st = Math.sin(tilt);
    const P = (lat, lon) => { const x = Math.cos(lat) * Math.sin(lon + rot), y = Math.sin(lat), z = Math.cos(lat) * Math.cos(lon + rot); const y2 = y * ct - z * st, z2 = y * st + z * ct; return [cx + x * R, cy - y2 * R, z2, x]; };
    g.lineWidth = Math.max(1, W / 1400); g.shadowBlur = W / 120;
    const line = (pts) => { for (let i = 1; i < pts.length; i++) { const a = pts[i - 1], b = pts[i]; if (a[2] < -0.02 && b[2] < -0.02) continue; const k = (a[3] + 1) / 2; const front = a[2] > 0 ? 0.75 : 0.22;
      const c = `rgba(${Math.round(45 + 210 * k)},${Math.round(107 + 15 * k)},${Math.round(255 - 229 * k)},${front})`; g.strokeStyle = c; g.shadowColor = c; g.beginPath(); g.moveTo(a[0], a[1]); g.lineTo(b[0], b[1]); g.stroke(); } };
    for (let m = 0; m < 24; m++) { const lon = m / 24 * Math.PI * 2, pts = []; for (let i = 0; i <= 40; i++) pts.push(P(-Math.PI / 2 + i / 40 * Math.PI, lon)); line(pts); }
    for (let p = -3; p <= 3; p++) { const lat = p / 4 * (Math.PI / 2) * 0.96, pts = []; for (let i = 0; i <= 72; i++) pts.push(P(lat, i / 72 * Math.PI * 2)); line(pts); }
    if (!reduce) rot += 0.0035; raf = requestAnimationFrame(draw);
  }
  new ResizeObserver(size).observe(hero); addEventListener('resize', size); size(); draw();
})();
