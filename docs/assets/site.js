/* ============================================================================
   Site vitrine Obscura — comportements.

   Règle : le JS n'ajoute que du CONFORT, jamais du contenu. Le site doit rester
   lisible et navigable sans lui — le lien de langue est un <a href> réel, le
   thème suit prefers-color-scheme par défaut, et les commandes sont
   sélectionnables à la main si le presse-papiers refuse.

   Aucune dépendance, aucun fetch, aucun état persistant hors le thème choisi.
   ========================================================================= */
(function () {
  'use strict';

  /* -------------------------------------------------------------- thème -- */
  // Appliqué le plus tôt possible pour éviter un flash de thème clair. La
  // valeur n'est lue qu'ici ; l'absence de clé = suivre le système.
  var KEY = 'obscura-theme';
  var root = document.documentElement;

  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function remember(v) {
    try { v ? localStorage.setItem(KEY, v) : localStorage.removeItem(KEY); } catch (e) { /* mode privé : on ignore */ }
  }
  function systemDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme:dark)').matches;
  }
  function current() {
    return root.getAttribute('data-theme') || (systemDark() ? 'dark' : 'light');
  }
  function apply(v) {
    if (v) root.setAttribute('data-theme', v);
    else root.removeAttribute('data-theme');
    var btns = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < btns.length; i++) {
      var dark = current() === 'dark';
      btns[i].setAttribute('aria-label', dark ? 'Basculer en thème clair' : 'Basculer en thème sombre');
      btns[i].setAttribute('aria-pressed', dark ? 'true' : 'false');
      var lab = btns[i].querySelector('[data-theme-label]');
      if (lab) lab.textContent = dark ? 'clair' : 'sombre';
    }
  }

  apply(stored());

  document.addEventListener('click', function (ev) {
    var t = ev.target.closest && ev.target.closest('[data-theme-toggle]');
    if (!t) return;
    ev.preventDefault();
    var next = current() === 'dark' ? 'light' : 'dark';
    remember(next);
    apply(next);
  });

  /* ------------------------------------------------------------- copier -- */
  // Le bouton n'existe que si le JS tourne : on l'injecte, plutôt que de le
  // laisser en HTML mort quand le presse-papiers n'est pas disponible.
  var heads = document.querySelectorAll('.cmd-head');
  for (var j = 0; j < heads.length; j++) {
    (function (head) {
      var block = head.parentNode.querySelector('pre');
      if (!block) return;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'copy';
      btn.textContent = 'copier';
      btn.setAttribute('aria-label', 'Copier ces commandes');
      btn.addEventListener('click', function () {
        // On copie le texte brut : les <span> de coloration ne doivent pas
        // se retrouver dans le presse-papiers.
        var txt = block.innerText.replace(/ /g, ' ');
        var done = function () {
          btn.textContent = 'copié';
          btn.setAttribute('data-done', '1');
          setTimeout(function () {
            btn.textContent = 'copier';
            btn.removeAttribute('data-done');
          }, 1600);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(txt).then(done, fallback);
        } else {
          fallback();
        }
        function fallback() {
          // Sélectionne le bloc : l'utilisateur finit au clavier. Échec
          // silencieux — on ne met pas d'erreur pour un confort optionnel.
          try {
            var r = document.createRange();
            r.selectNodeContents(block);
            var s = window.getSelection();
            s.removeAllRanges();
            s.addRange(r);
            if (document.execCommand && document.execCommand('copy')) done();
          } catch (e) { /* rien */ }
        }
      });
      head.appendChild(btn);
    })(heads[j]);
  }

  /* ------------------------------------------------------ année du pied -- */
  var y = document.querySelectorAll('[data-year]');
  for (var k = 0; k < y.length; k++) y[k].textContent = String(new Date().getFullYear());
})();
