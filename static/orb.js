// Wireframe orb behind the start screen: meridians and parallels, blue on one side and orange on the other, slowly turning. Pure canvas, no library.
(() => {
  const hero = document.getElementById('intake'); if (!hero) return;
  const cv = document.createElement('canvas'); cv.id = 'orb'; hero.prepend(cv); const g = cv.getContext('2d');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches; let rot = 0, W = 0, H = 0, VIS = 0, raf = 0;
  function size() { const r = hero.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 1.25); W = cv.width = Math.round(r.width * d); H = cv.height = Math.round(r.height * d); cv.style.width = r.width + 'px'; cv.style.height = r.height + 'px'; VIS = Math.min(r.height, Math.max(300, innerHeight - r.top)) * d; }  // the part of the hero that is on screen: the whole globe fits in it
  // Light on the computer: all line segments of one colour are drawn as ONE path (about 20 strokes a frame instead of 1,500), no per-line blur, 30 frames a second, nothing drawn while a scan runs or the tab is hidden.
  let last = 0;
  function draw(now) {
    raf = requestAnimationFrame(draw);
    if (document.body.dataset.stage === 'run' || document.hidden || now - last < 33) return;
    last = now;
    g.clearRect(0, 0, W, H);
    const R = Math.min(W * 0.3, VIS * 0.46), cx = W / 2, cy = VIS * 0.5, tilt = -0.35, ct = Math.cos(tilt), st = Math.sin(tilt);
    const P = (lat, lon) => { const x = Math.cos(lat) * Math.sin(lon + rot), y = Math.sin(lat), z = Math.cos(lat) * Math.cos(lon + rot); const y2 = y * ct - z * st, z2 = y * st + z * ct; return [cx + x * R, cy - y2 * R, z2, x]; };
    g.lineWidth = Math.max(1, W / 1400);
    const B = 8, buckets = Array.from({length: B * 2}, () => []);
    const line = (pts) => { for (let i = 1; i < pts.length; i++) { const a = pts[i - 1], b = pts[i]; if (a[2] < -0.02 && b[2] < -0.02) continue; const k = Math.min(B - 1, Math.floor((a[3] + 1) / 2 * B)); buckets[k * 2 + (a[2] > 0 ? 1 : 0)].push(a[0], a[1], b[0], b[1]); } };
    for (let m = 0; m < 24; m++) { const lon = m / 24 * Math.PI * 2, pts = []; for (let i = 0; i <= 28; i++) pts.push(P(-Math.PI / 2 + i / 28 * Math.PI, lon)); line(pts); }
    for (let p = -3; p <= 3; p++) { const lat = p / 4 * (Math.PI / 2) * 0.96, pts = []; for (let i = 0; i <= 48; i++) pts.push(P(lat, i / 48 * Math.PI * 2)); line(pts); }
    buckets.forEach((s, j) => { if (!s.length) return; const k = (j >> 1) / (B - 1); g.strokeStyle = `rgba(${Math.round(45 + 210 * k)},${Math.round(107 + 15 * k)},${Math.round(255 - 229 * k)},${j & 1 ? 0.75 : 0.22})`;
      g.beginPath(); for (let i = 0; i < s.length; i += 4) { g.moveTo(s[i], s[i + 1]); g.lineTo(s[i + 2], s[i + 3]); } g.stroke(); });
    if (!reduce) rot += 0.0035 * 2;  // two ticks per drawn frame keeps the same turning speed at 30 fps
  }
  new ResizeObserver(size).observe(hero); addEventListener('resize', size); size(); raf = requestAnimationFrame(draw);
})();
