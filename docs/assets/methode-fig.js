/* Figure de la page Méthode / Method : Xi contre eta, référence pure vs mesurée.
   Données réelles : campagne IBM Marrakesh 1. Les couleurs viennent des jetons
   --serie-a / --serie-b de site.css, validés CVD en clair comme en sombre. */
(function () {
  var svg = document.getElementById('fig');
  if (!svg) return;

  var GRID = [], PURE = [], IMP = [];
  for (var k = 0; k <= 44; k++) GRID.push(+(0.46 + k * 0.005).toFixed(3));
  PURE = [0.268548,0.269464,0.270337,0.271166,0.271952,0.272693,0.273391,0.274044,
    0.274653,0.275218,0.275738,0.276213,0.276643,0.277028,0.277368,0.277663,
    0.277912,0.278115,0.278272,0.278382,0.278447,0.278464,0.278435,0.278358,
    0.278234,0.278063,0.277843,0.277575,0.277259,0.276894,0.276479,0.276016,
    0.275502,0.274938,0.274324,0.273659,0.272943,0.272175,0.271355,0.270482,
    0.269557,0.268578,0.267545,0.266458,0.265316];
  IMP = [0.258683,0.259545,0.260365,0.261142,0.261877,0.262569,0.263217,0.263823,
    0.264385,0.264904,0.26538,0.265812,0.266199,0.266543,0.266843,0.267098,
    0.267309,0.267475,0.267596,0.267671,0.267702,0.267686,0.267625,0.267518,
    0.267364,0.267164,0.266917,0.266623,0.266281,0.265891,0.265454,0.264968,
    0.264434,0.26385,0.263217,0.262535,0.261802,0.261019,0.260185,0.2593,
    0.258363,0.257373,0.256332,0.255237,0.254088];
  var PTS = [[0.47099,0.260521,0.001893],[0.49718,0.263932,0.001639],
    [0.49482,0.263785,0.001661],[0.51751,0.26583,0.001514],[0.50685,0.263231,0.001965],
    [0.52622,0.266496,0.001477],[0.54238,0.267181,0.00143],[0.54594,0.267462,0.001381],
    [0.56064,0.266968,0.001639],[0.55994,0.267112,0.001481],[0.5885,0.266464,0.001686],
    [0.59225,0.264736,0.00203],[0.59746,0.265459,0.001827],[0.62084,0.263443,0.002045],
    [0.62147,0.264042,0.001951],[0.63086,0.262991,0.001965],[0.63476,0.262019,0.002152],
    [0.64044,0.26142,0.002063],[0.65909,0.258525,0.002402],[0.67003,0.255791,0.002596]];
  var PEAK_PURE = 0.5643766, VAL_PURE = 0.278465;
  var PEAK_IMP = 0.5608243, VAL_IMP = 0.267702;

  var W = 760, H = 400, M = { t: 30, r: 104, b: 46, l: 60 };
  var x0 = 0.458, x1 = 0.682, y0 = 0.2525, y1 = 0.2800;
  var PW = W - M.l - M.r, PH = H - M.t - M.b;
  var NS = 'http://www.w3.org/2000/svg';
  function X(v) { return M.l + (v - x0) / (x1 - x0) * PW; }
  function Y(v) { return M.t + (y1 - v) / (y1 - y0) * PH; }
  function el(n, a) {
    var e = document.createElementNS(NS, n);
    for (var k in a) e.setAttribute(k, a[k]);
    return e;
  }
  var SEP = svg.getAttribute('data-decimal') || ',';
  function fr(v, n) { return v.toFixed(n).replace('.', SEP); }
  function num(t) { return t.replace('.', SEP).replace(',', SEP); }
  function path(ys) {
    var s = '';
    for (var i = 0; i < GRID.length; i++) {
      s += (i ? 'L' : 'M') + X(GRID[i]).toFixed(2) + ' ' + Y(ys[i]).toFixed(2);
    }
    return s;
  }

  [0.255, 0.260, 0.265, 0.270, 0.275, 0.280].forEach(function (v) {
    svg.appendChild(el('line', { x1: M.l, x2: M.l + PW, y1: Y(v), y2: Y(v),
      stroke: 'var(--line)', 'stroke-width': 1 }));
    var t = el('text', { x: M.l - 9, y: Y(v) + 3.5, class: 'tick', 'text-anchor': 'end' });
    t.textContent = fr(v, 3);
    svg.appendChild(t);
  });
  [0.48, 0.52, 0.56, 0.60, 0.64, 0.68].forEach(function (v) {
    svg.appendChild(el('line', { x1: X(v), x2: X(v), y1: M.t + PH, y2: M.t + PH + 5,
      stroke: 'var(--line)', 'stroke-width': 1 }));
    var t = el('text', { x: X(v), y: M.t + PH + 18, class: 'tick', 'text-anchor': 'middle' });
    t.textContent = fr(v, 2);
    svg.appendChild(t);
  });
  svg.appendChild(el('line', { x1: M.l, x2: M.l + PW, y1: M.t + PH, y2: M.t + PH,
    stroke: 'var(--line)', 'stroke-width': 1 }));

  // Étiquettes d'axe à l'horizontale : pivoté à 90°, le glyphe Ξ devient « ||| ».
  var yl = el('text', { x: M.l - 9, y: M.t - 12, class: 'tick', 'text-anchor': 'end' });
  yl.textContent = svg.getAttribute('data-ylab') || 'Ξ';
  svg.appendChild(yl);
  var xl = el('text', { x: M.l + PW / 2, y: M.t + PH + 36, class: 'tick',
    'text-anchor': 'middle' });
  xl.textContent = svg.getAttribute('data-xlab') || 'η';
  svg.appendChild(xl);

  svg.appendChild(el('path', { d: path(PURE), fill: 'none', stroke: 'var(--serie-a)',
    'stroke-width': 2, 'stroke-linecap': 'round' }));
  svg.appendChild(el('path', { d: path(IMP), fill: 'none', stroke: 'var(--serie-b)',
    'stroke-width': 2, 'stroke-linecap': 'round' }));

  // Étiquettes directes : l'identité des séries ne repose pas sur la couleur seule.
  function dlab(yv, txt, col) {
    var t = el('text', { x: M.l + PW + 10, y: Y(yv) + 3.5, class: 'dlab', fill: col });
    t.textContent = txt;
    svg.appendChild(t);
  }
  dlab(PURE[PURE.length - 1], svg.getAttribute('data-lab-a') || 'pure', 'var(--serie-a)');
  dlab(IMP[IMP.length - 1], svg.getAttribute('data-lab-b') || 'mesurée', 'var(--serie-b)');

  // Points de données : neutres. Ce sont des données, pas un modèle — les
  // colorer comme une série ferait passer un test pour une tautologie.
  PTS.forEach(function (p) {
    svg.appendChild(el('line', { x1: X(p[0]), x2: X(p[0]),
      y1: Y(p[1] - p[2]), y2: Y(p[1] + p[2]),
      stroke: 'var(--line)', 'stroke-width': 1.5, 'stroke-linecap': 'round' }));
    svg.appendChild(el('circle', { cx: X(p[0]), cy: Y(p[1]), r: 3.6,
      fill: 'var(--surface)', stroke: 'var(--muted)', 'stroke-width': 1.5 }));
  });

  // Pics tracés APRÈS les points, sinon les marqueurs disparaissent dessous.
  [[PEAK_IMP, VAL_IMP, 'var(--serie-b)', '0.5608', -1, M.t + PH - 10],
   [PEAK_PURE, VAL_PURE, 'var(--serie-a)', '0.5644', 1, M.t + PH - 26]
  ].forEach(function (p) {
    svg.appendChild(el('line', { x1: X(p[0]), x2: X(p[0]), y1: Y(p[1]), y2: M.t + PH,
      stroke: p[2], 'stroke-width': 1, 'stroke-dasharray': '2 3', opacity: 0.6 }));
    svg.appendChild(el('circle', { cx: X(p[0]), cy: Y(p[1]), r: 5, fill: p[2],
      stroke: 'var(--surface)', 'stroke-width': 2 }));
    var t = el('text', { x: X(p[0]) + p[4] * 7, y: p[5], class: 'dlab', fill: p[2],
      'text-anchor': p[4] < 0 ? 'end' : 'start' });
    t.textContent = num(p[3]);
    svg.appendChild(t);
  });

  // L'écart entre les deux pics : c'est tout le sujet de la page.
  var gy = M.t + PH - 40;
  svg.appendChild(el('line', { x1: X(PEAK_IMP), x2: X(PEAK_PURE), y1: gy, y2: gy,
    stroke: 'var(--muted)', 'stroke-width': 1 }));
  [PEAK_IMP, PEAK_PURE].forEach(function (v) {
    svg.appendChild(el('line', { x1: X(v), x2: X(v), y1: gy - 3, y2: gy + 3,
      stroke: 'var(--muted)', 'stroke-width': 1 }));
  });
  var gl = el('text', { x: (X(PEAK_IMP) + X(PEAK_PURE)) / 2, y: gy - 7, class: 'dlab',
    fill: 'var(--muted)', 'text-anchor': 'middle' });
  gl.textContent = num('0.0036');
  svg.appendChild(gl);
})();
