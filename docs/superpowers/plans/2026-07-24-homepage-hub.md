# Homepage hub Obscura — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer `docs/index.html`, une page d'accueil / hub statique autonome qui présente Obscura et porte un quickstart testnet local avec des commandes réelles vérifiées.

**Architecture:** Un seul fichier HTML statique, CSS + JS inline, aucune dépendance externe. Réutilise les tokens visuels de `docs/obscura-overview.html` (accent teal, thème clair/sombre). Deux comportements JS : toggle de thème et boutons « copier » sur les blocs de commande.

**Tech Stack:** HTML5, CSS (variables custom, `@media prefers-color-scheme`), JS vanilla (aucune lib). Binaires Rust cibles (lecture seule pour vérifier les commandes) : `obscura-node`, `obscura-wallet`, `obscura-genese`, `obscura-demo` (package cargo `node`).

## Global Constraints

- **Fichier unique** : `docs/index.html`. Aucune modification de code Rust.
- **Autonome** : CSS/JS inline, **aucune** ressource externe (pas de CDN, pas de police web, pas de fetch).
- **Thème** : clair/sombre via `@media (prefers-color-scheme)` + override `:root[data-theme="light"|"dark"]`, toggle persistant.
- **Français**, langue `fr`.
- **Honnêteté (non négociable)** : disclaimer « prototype non audité, sans valeur, remis à zéro » en hero ; **aucun** faucet / explorateur / bouton « rejoindre » ; réseau **sur invitation** ; nœud complet **jamais** en navigateur.
- **Commandes réelles** : toute commande affichée est vérifiée par exécution réelle avant complétude (Task 6). Package cargo = `node`, tout en `--release`.
- **Système visuel réutilisé** : valeurs de tokens reprises de `docs/obscura-overview.html`, pas un nouveau langage visuel.
- **Style d'écriture** : commentaires/textes en français (convention dépôt).

---

## File Structure

- **Create** : `docs/index.html` — la page entière (head + style inline + body + script inline).
- **Read-only (vérification commandes)** : `crates/node/src/bin/obscura-{node,wallet,genese,demo}.rs`, `docs/OPERATEUR.md`, `docs/TESTNET.md`.
- **Scratch (transcript de vérification)** : `C:\Users\W47\AppData\Local\Temp\claude\C--Users-W47-Documents-obscura\c06e8ee4-9f3b-4ece-9f05-e2db76585f8d\scratchpad\verif-commandes.md` — notes de ce qui a réellement tourné (pas commité).

Les tâches éditent toutes le même fichier, séquentiellement. L'exécution inline est donc naturelle ; en subagent, chaque tâche doit relire l'état courant de `docs/index.html`.

---

## Task 1: Vérifier le build et le chemin express (dé-risque tout le reste)

But : confirmer que les binaires se construisent et que `obscura-demo` tourne, AVANT d'écrire la section commandes. Si une commande dévie, on l'apprend ici.

**Files:**
- Scratch: `…/scratchpad/verif-commandes.md` (transcript)

**Interfaces:**
- Produces: la liste des commandes **confirmées** (build + express) que Task 5 affichera verbatim.

- [ ] **Step 1: Construire les binaires**

Run :
```bash
cargo build --release -p node --bins
```
Expected : succès ; binaires présents dans `target/release/` (`obscura-node.exe`, `obscura-wallet.exe`, `obscura-genese.exe`, `obscura-demo.exe`). Noter le temps et tout warning bloquant.

- [ ] **Step 2: Lancer le chemin express**

Run :
```bash
cargo run --release --bin obscura-demo
```
Expected : la démo va au bout (« [5/5] », transaction propagée, pas de panic). Coller la sortie clé dans le transcript.

- [ ] **Step 3: Consigner les écarts éventuels**

Écrire dans `verif-commandes.md` : commandes exactes qui ont marché, chemins réels des binaires, toute divergence vs la spec. Ces valeurs font autorité pour Task 5.

- [ ] **Step 4: (pas de commit — étape de vérification, transcript hors dépôt)**

---

## Task 2: Vérifier le chemin pratique testnet local de bout en bout

But : exécuter réellement wallet → genèse → nœud → synchro → solde → envoi, et capturer les commandes/sorties exactes.

**Files:**
- Scratch: `…/scratchpad/verif-commandes.md` (compléter)

**Interfaces:**
- Consumes: binaires construits (Task 1).
- Produces: les commandes **confirmées** du chemin pratique pour Task 5, avec la forme réelle de l'adresse `obs1…` et le comportement de synchro/solde.

- [ ] **Step 1: Créer un wallet et lire l'adresse**

Run (depuis un répertoire de travail jetable, ex. `./essai-local`) :
```bash
OBSCURA_WALLET_PHRASE=demo ./target/release/obscura-wallet creer   --fichier mon.wallet
OBSCURA_WALLET_PHRASE=demo ./target/release/obscura-wallet adresse --fichier mon.wallet
```
Expected : `creer` refuse d'écraser si le fichier existe ; `adresse` imprime une adresse `obs1…`. Noter l'adresse exacte.

- [ ] **Step 2: Fabriquer une genèse locale ouverte avec allocation**

Run (remplacer `<obs1>` par l'adresse du Step 1) :
```bash
./target/release/obscura-genese --sortie genese.bin --allocation <obs1>:1000000
```
Expected : écrit `genese.bin`, imprime l'identifiant complet (128 hex). Confirmer qu'aucune `--autorite` n'est requise (chaîne ouverte).

- [ ] **Step 3: Démarrer le nœud scelleur + archive (en arrière-plan)**

Run :
```bash
./target/release/obscura-node --ecoute 0.0.0.0:9333 --genese genese.bin \
    --donnees ./donnees --sceller 1000 --archiver
```
Expected : logs de démarrage, identifiant de genèse identique à Step 2, blocs scellés toutes ~1 s. Laisser tourner.

- [ ] **Step 4: Synchroniser et lire le solde**

Run (autre terminal) :
```bash
OBSCURA_WALLET_PHRASE=demo ./target/release/obscura-wallet synchroniser --fichier mon.wallet --noeud 127.0.0.1:9333
OBSCURA_WALLET_PHRASE=demo ./target/release/obscura-wallet solde        --fichier mon.wallet
```
Expected : le solde reflète l'allocation (1000000). Si non, diagnostiquer (l'archive doit être active — elle l'est via `--archiver`).

- [ ] **Step 5: Émettre un envoi**

Run (créer un 2e wallet pour la destination, ou réutiliser une adresse connue) :
```bash
OBSCURA_WALLET_PHRASE=demo ./target/release/obscura-wallet envoyer --fichier mon.wallet \
    --a <obs1_dest> --montant 300 --noeud 127.0.0.1:9333
```
Expected : la transaction est acceptée (preuve générée en `--release`). Noter la sortie.

- [ ] **Step 6: Consigner les commandes confirmées et arrêter le nœud**

Compléter `verif-commandes.md` avec les commandes/sorties réelles. Arrêter le nœud (Ctrl-C). Nettoyer `./essai-local` si souhaité. Ces commandes sont la **source verbatim** de Task 5.

- [ ] **Step 7: (pas de commit)**

---

## Task 3: Scaffold — head, tokens visuels, thème, coquille

But : créer `docs/index.html` qui rend une page vide stylée avec thème clair/sombre fonctionnel.

**Files:**
- Create: `docs/index.html`

**Interfaces:**
- Produces: la structure `<head>` + `<style>` (tokens) + `.shell` + toggle de thème que les tâches 4-7 remplissent.

- [ ] **Step 1: Écrire le squelette + tokens + thème**

Créer `docs/index.html` avec ce contenu initial (valeurs de tokens reprises de `docs/obscura-overview.html:9-49`) :

```html
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Obscura — prototype de monnaie numérique post-quantique conçue pour la confidentialité. Présentation, et comment lancer le testnet local (wallet + nœud).">
<title>Obscura — Monnaie post-quantique conçue pour la confidentialité</title>
<style>
  :root{
    --ink:#14161d; --paper:#f2f3f6; --surface:#ffffff; --surface-2:#e9ebf0;
    --muted:#59616f; --line:#d8dce3; --accent:#0f9a82; --accent-ink:#0b6f5e;
    --accent-soft:#d8f1eb; --secret:#a86f16; --secret-soft:#f4e9d3;
    --danger:#b23b3b; --code-bg:#eef1f5;
    --shadow:0 1px 2px rgba(20,22,29,.06),0 8px 24px rgba(20,22,29,.05);
  }
  @media (prefers-color-scheme:dark){
    :root{
      --ink:#e7eaf1; --paper:#0c0e13; --surface:#14171f; --surface-2:#1b1f2a;
      --muted:#98a2b2; --line:#272c38; --accent:#2fd0b0; --accent-ink:#54e0c4;
      --accent-soft:#123029; --secret:#e2ac52; --secret-soft:#2b2415;
      --danger:#e06b6b; --code-bg:#161a22;
      --shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
    }
  }
  :root[data-theme="light"]{
    --ink:#14161d; --paper:#f2f3f6; --surface:#ffffff; --surface-2:#e9ebf0;
    --muted:#59616f; --line:#d8dce3; --accent:#0f9a82; --accent-ink:#0b6f5e;
    --accent-soft:#d8f1eb; --secret:#a86f16; --secret-soft:#f4e9d3;
    --danger:#b23b3b; --code-bg:#eef1f5;
    --shadow:0 1px 2px rgba(20,22,29,.06),0 8px 24px rgba(20,22,29,.05);
  }
  :root[data-theme="dark"]{
    --ink:#e7eaf1; --paper:#0c0e13; --surface:#14171f; --surface-2:#1b1f2a;
    --muted:#98a2b2; --line:#272c38; --accent:#2fd0b0; --accent-ink:#54e0c4;
    --accent-soft:#123029; --secret:#e2ac52; --secret-soft:#2b2415;
    --danger:#e06b6b; --code-bg:#161a22;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  @media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
  body{
    margin:0; background:var(--paper); color:var(--ink); min-height:100vh;
    font-family:-apple-system,system-ui,"Segoe UI",Roboto,sans-serif;
    font-size:17px; line-height:1.65; -webkit-font-smoothing:antialiased;
  }
  .serif{font-family:Georgia,"Iowan Old Style","Times New Roman",serif}
  .mono{font-family:ui-monospace,"SF Mono","Cascadia Code",Menlo,Consolas,monospace}
  .shell{max-width:1180px; margin:0 auto; padding:0 clamp(18px,4vw,40px)}
  a{color:var(--accent-ink)}
  .theme-toggle{
    position:fixed; top:14px; right:14px; z-index:10; cursor:pointer;
    background:var(--surface); color:var(--ink); border:1px solid var(--line);
    border-radius:9px; padding:7px 11px; font-size:13px; box-shadow:var(--shadow);
  }
</style>
</head>
<body>
<button class="theme-toggle" id="theme-toggle" aria-label="Basculer le thème">◐ thème</button>
<main class="shell">
  <!-- sections ajoutées aux tâches 4-6 -->
  <p style="padding:40px 0">Coquille — remplie aux tâches suivantes.</p>
</main>
<script>
  (function(){
    var root=document.documentElement, KEY="obscura-theme";
    var saved=localStorage.getItem(KEY);
    if(saved){root.setAttribute("data-theme",saved);}
    document.getElementById("theme-toggle").addEventListener("click",function(){
      var cur=root.getAttribute("data-theme");
      if(!cur){ // pas encore forcé : partir de la préférence système
        cur=window.matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light";
      }
      var next=cur==="dark"?"light":"dark";
      root.setAttribute("data-theme",next);
      localStorage.setItem(KEY,next);
    });
  })();
</script>
</body>
</html>
```

- [ ] **Step 2: Ouvrir dans le navigateur et vérifier le thème**

Run : `mcp__Claude_Browser__preview_start` avec `{url:"file:///C:/Users/W47/Documents/obscura/docs/index.html"}`.
Expected : page rendue, bouton « ◐ thème » en haut à droite ; cliquer bascule clair↔sombre ; recharger conserve le choix (localStorage). `read_console_messages` : aucune erreur.

- [ ] **Step 3: Commit**

```bash
git add docs/index.html
git commit -m "feat(web): scaffold docs/index.html — tokens visuels + toggle de thème"
```

---

## Task 4: Hero + disclaimer + section « En bref »

**Files:**
- Modify: `docs/index.html` (remplacer le placeholder dans `<main>`)

**Interfaces:**
- Consumes: `.shell`, `.serif`, tokens (Task 3).
- Produces: ancres `#demarrer` (CTA, cible créée en Task 5) et le style `.card`/`.hero`/`.disclaimer` réutilisés ensuite.

- [ ] **Step 1: Ajouter les styles de composants**

Dans `<style>`, avant `</style>`, ajouter :

```css
  .hero{padding:clamp(46px,9vw,86px) 0 clamp(30px,5vw,46px); border-bottom:1px solid var(--line)}
  .eyebrow{font-family:ui-monospace,Menlo,monospace; font-size:12.5px; letter-spacing:.22em; text-transform:uppercase; color:var(--accent-ink); margin:0 0 18px}
  h1{font-size:clamp(30px,5.5vw,52px); line-height:1.1; margin:0 0 14px; letter-spacing:-.01em}
  .lede{font-size:clamp(18px,2.4vw,22px); color:var(--muted); max-width:60ch; margin:0 0 26px}
  .disclaimer{background:var(--secret-soft); border:1px solid color-mix(in srgb,var(--secret) 40%,transparent); color:var(--secret); border-radius:11px; padding:14px 16px; font-size:14.5px; max-width:70ch; margin:0 0 26px}
  .cta-row{display:flex; flex-wrap:wrap; gap:12px}
  .btn{display:inline-block; text-decoration:none; border-radius:10px; padding:11px 18px; font-size:15px; font-weight:600; border:1px solid var(--line)}
  .btn-primary{background:var(--accent); color:#04211c; border-color:transparent}
  .btn-ghost{background:var(--surface); color:var(--ink)}
  section.band{padding:clamp(34px,6vw,64px) 0; border-bottom:1px solid var(--line)}
  h2{font-size:clamp(23px,3.4vw,32px); margin:0 0 8px; letter-spacing:-.01em}
  .band-lede{color:var(--muted); max-width:64ch; margin:0 0 26px}
  .cards{display:grid; grid-template-columns:1fr; gap:16px}
  @media(min-width:720px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}}
  .card{background:var(--surface); border:1px solid var(--line); border-radius:13px; padding:20px 20px 18px; box-shadow:var(--shadow)}
  .card h3{margin:0 0 7px; font-size:17.5px}
  .card p{margin:0 0 8px; color:var(--muted); font-size:15px}
  .card a{font-size:14px; font-weight:600; text-decoration:none}
```

- [ ] **Step 2: Remplacer le placeholder par le hero + En bref**

Remplacer `<p style="padding:40px 0">Coquille — remplie aux tâches suivantes.</p>` par :

```html
  <header class="hero">
    <p class="eyebrow">Obscura · prototype pédagogique</p>
    <h1 class="serif">Une monnaie post-quantique conçue pour la confidentialité.</h1>
    <p class="lede">Preuve STARK unique par transaction, notes chiffrées, consensus BFT fédéré. Le tout en Rust, ouvert, et lançable sur votre machine.</p>
    <div class="disclaimer"><strong>Prototype non audité, sans valeur.</strong> Les jetons n'ont aucune valeur, n'en auront aucune, et la chaîne sera remise à zéro. Réseau expérimental, sur invitation — ni faucet, ni explorateur.</div>
    <div class="cta-row">
      <a class="btn btn-primary" href="#demarrer">Démarrer</a>
      <a class="btn btn-ghost" href="obscura-overview.html">Comprendre le système</a>
    </div>
  </header>

  <section class="band">
    <h2 class="serif">En bref</h2>
    <p class="band-lede">Quatre partis pris. Le détail technique est dans l'overview.</p>
    <div class="cards">
      <div class="card"><h3>Confidentialité</h3><p>Montants, propriétaire et graphe cachés : une seule preuve STARK établit la validité sans révéler le témoin. Nullifiers contre le double-dépense.</p><a href="obscura-overview.html">Le circuit →</a></div>
      <div class="card"><h3>Post-quantique</h3><p>KEM et signatures hybrides, hash Rescue prouvé côté circuit. Pensé pour survivre à un adversaire quantique.</p><a href="POST_QUANTIQUE.md">Post-quantique →</a></div>
      <div class="card"><h3>Consensus BFT fédéré</h3><p>Quorum <span class="mono">2f+1</span>, finalité, comité d'autorités reconfigurable sur la même chaîne.</p><a href="OPERATEUR.md">Exploitation →</a></div>
      <div class="card"><h3>Prototype balisé</h3><p>Non audité, mais documenté comme un produit : modèle d'adversaire, statement STARK, conformité.</p><a href="THREAT_MODEL.md">Modèle d'adversaire →</a></div>
    </div>
  </section>
```

- [ ] **Step 3: Recharger et vérifier**

Recharger la preview. Expected : hero lisible, disclaimer visible (teinte « secret »), 4 cartes en grille (2 colonnes ≥720px), CTA « Démarrer » pointe vers `#demarrer` (cible en Task 5). Basculer le thème : contrastes corrects. Console propre.

- [ ] **Step 4: Commit**

```bash
git add docs/index.html
git commit -m "feat(web): hero + disclaimer + section En bref"
```

---

## Task 5: Section « Démarrer » (commandes vérifiées) + boutons copier

But : la section cœur. Utilise **verbatim** les commandes confirmées aux tâches 1-2.

**Files:**
- Modify: `docs/index.html`

**Interfaces:**
- Consumes: commandes confirmées (`verif-commandes.md`, Tasks 1-2) ; styles Task 4.
- Produces: la cible `#demarrer` ; le composant `.cmd` + JS de copie.

- [ ] **Step 1: Ajouter les styles des blocs de commande**

Dans `<style>` : 

```css
  .step{margin:0 0 22px}
  .step .k{display:inline-block; min-width:26px; height:26px; line-height:26px; text-align:center; border-radius:7px; background:var(--accent-soft); color:var(--accent-ink); font-weight:700; font-size:13px; margin-right:9px}
  .cmd{position:relative; background:var(--code-bg); border:1px solid var(--line); border-radius:10px; margin:9px 0 0}
  .cmd pre{margin:0; padding:14px 46px 14px 15px; overflow-x:auto; font-family:ui-monospace,"Cascadia Code",Consolas,monospace; font-size:13.5px; line-height:1.55}
  .cmd .copy{position:absolute; top:8px; right:8px; cursor:pointer; border:1px solid var(--line); background:var(--surface); color:var(--muted); border-radius:7px; font-size:12px; padding:4px 8px}
  .cmd .copy.ok{color:var(--accent-ink); border-color:var(--accent)}
  .note{background:var(--surface-2); border-left:3px solid var(--accent); border-radius:0 8px 8px 0; padding:12px 15px; margin:14px 0; font-size:14.5px; color:var(--muted)}
  .subhead{font-size:13px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); margin:30px 0 6px}
```

- [ ] **Step 2: Ajouter la section Démarrer**

Après la section « En bref », insérer (⚠️ **remplacer les commandes par celles confirmées** en Tasks 1-2 si elles diffèrent — ce bloc reflète la spec) :

```html
  <section class="band" id="demarrer">
    <h2 class="serif">Démarrer</h2>
    <p class="band-lede">Un préalable commun, puis deux chemins. Tout se lance en <span class="mono">--release</span> (le circuit est gaté).</p>

    <p class="subhead">Préalable — construire les binaires</p>
    <div class="cmd"><button class="copy">copier</button><pre>cargo build --release -p node --bins</pre></div>
    <p class="note">Produit <span class="mono">obscura-node</span>, <span class="mono">obscura-wallet</span>, <span class="mono">obscura-genese</span> et <span class="mono">obscura-demo</span> dans <span class="mono">target/release/</span>.</p>

    <p class="subhead">Chemin express — « est-ce que ça marche ? » en une commande</p>
    <div class="step"><div class="cmd"><button class="copy">copier</button><pre>cargo run --release --bin obscura-demo</pre></div>
    <p class="note">Monte deux nœuds réels, construit une transaction, l'émet et observe sa propagation. Chaque étape est annoncée.</p></div>

    <p class="subhead">Chemin pratique — un testnet local, à la main</p>

    <div class="step"><span class="k">1</span><strong>Créer un wallet et lire son adresse</strong>
    <div class="cmd"><button class="copy">copier</button><pre>obscura-wallet creer   --fichier mon.wallet
obscura-wallet adresse --fichier mon.wallet   # → obs1…</pre></div>
    <p class="note">La phrase de passe protège le fichier au repos (invite, ou <span class="mono">OBSCURA_WALLET_PHRASE=…</span>).</p></div>

    <div class="step"><span class="k">2</span><strong>Fabriquer une genèse locale (chaîne ouverte) avec une allocation vers ton adresse</strong>
    <div class="cmd"><button class="copy">copier</button><pre>obscura-genese --sortie genese.bin --allocation obs1…:1000000</pre></div>
    <p class="note">Sans <span class="mono">--autorite</span>, la chaîne est <em>ouverte</em> : n'importe quel nœud avec <span class="mono">--sceller</span> produit des blocs. Testnet local uniquement.</p></div>

    <div class="step"><span class="k">3</span><strong>Lancer le nœud (scelleur + archive)</strong>
    <div class="cmd"><button class="copy">copier</button><pre>obscura-node --ecoute 0.0.0.0:9333 --genese genese.bin \
             --donnees ./donnees --sceller 1000 --archiver</pre></div>
    <p class="note"><span class="mono">--archiver</span> est ce qui permet au wallet de se synchroniser. À activer dès l'amorçage.</p></div>

    <div class="step"><span class="k">4</span><strong>Synchroniser puis lire le solde</strong>
    <div class="cmd"><button class="copy">copier</button><pre>obscura-wallet synchroniser --fichier mon.wallet --noeud 127.0.0.1:9333
obscura-wallet solde        --fichier mon.wallet</pre></div></div>

    <div class="step"><span class="k">5</span><strong>Envoyer</strong>
    <div class="cmd"><button class="copy">copier</button><pre>obscura-wallet envoyer --fichier mon.wallet --a obs1…dest --montant 300 \
                       --noeud 127.0.0.1:9333</pre></div></div>

    <p class="subhead">Rejoindre une fédération</p>
    <p class="note">Le réseau est <strong>sur invitation</strong> — pas de bootnode public. Publie ta clé de nœud avec <span class="mono">obscura-node --identite</span>, transmets ton adresse <span class="mono">obs1…</span> et ta clé au fabricant de la genèse, récupère les adresses de pairs <em>hors bande</em>, puis démarre avec <span class="mono">--pair &lt;adresse&gt;</span> sur la même <span class="mono">genese.bin</span>. Détails : <a href="OPERATEUR.md">OPERATEUR.md</a> et <a href="TESTNET.md">TESTNET.md</a>.</p>
  </section>
```

- [ ] **Step 3: Ajouter le JS de copie**

Dans le `<script>`, avant la fermeture `})();`, ajouter :

```js
    document.querySelectorAll(".cmd .copy").forEach(function(b){
      b.addEventListener("click",function(){
        var pre=b.parentElement.querySelector("pre");
        var txt=pre.innerText.replace(/\s+#.*$/gm,"").trim(); // retire les commentaires en fin de ligne
        navigator.clipboard.writeText(txt).then(function(){
          b.textContent="copié ✓"; b.classList.add("ok");
          setTimeout(function(){b.textContent="copier"; b.classList.remove("ok");},1400);
        }).catch(function(){/* pas de presse-papier : no-op */});
      });
    });
```

- [ ] **Step 4: Recharger et vérifier commandes + copie**

Recharger la preview. Expected : ancre `#demarrer` atteinte depuis le CTA « Démarrer » ; blocs de commande lisibles et scrollables ; chaque bouton « copier » copie le texte (tester un clic → « copié ✓ »). Vérifier que **le texte affiché correspond exactement** aux commandes confirmées (Tasks 1-2). Console propre.

- [ ] **Step 5: Commit**

```bash
git add docs/index.html
git commit -m "feat(web): section Démarrer (commandes vérifiées) + boutons copier"
```

---

## Task 6: « Aller plus loin » + pied, puis vérification navigateur finale

**Files:**
- Modify: `docs/index.html`

**Interfaces:**
- Consumes: styles `.cards`/`.card` (Task 4).
- Produces: page complète.

- [ ] **Step 1: Ajouter navigation + pied**

Après la section Démarrer :

```html
  <section class="band">
    <h2 class="serif">Aller plus loin</h2>
    <div class="cards">
      <div class="card"><h3>Overview technique</h3><p>Vulgarisation puis détails : architecture, circuit, ledger, performance, feuille de route.</p><a href="obscura-overview.html">Lire →</a></div>
      <div class="card"><h3>Atelier</h3><p>La procédure pas à pas, côté opérateur.</p><a href="obscura-atelier.html">Ouvrir →</a></div>
      <div class="card"><h3>Atelier pratique</h3><p>Page interactive de la procédure.</p><a href="obscura-atelier-pratique.html">Ouvrir →</a></div>
      <div class="card"><h3>Documents de référence</h3><p>Exploitation, testnet, modèle d'adversaire, statement STARK, protocole.</p><a href="OPERATEUR.md">OPERATEUR</a> · <a href="TESTNET.md">TESTNET</a> · <a href="THREAT_MODEL.md">THREAT_MODEL</a> · <a href="STARK_STATEMENT.md">STARK</a> · <a href="PROTOCOL.md">PROTOCOL</a></div>
    </div>
  </section>

  <footer class="band" style="border-bottom:none">
    <p style="color:var(--muted); font-size:14.5px; max-width:70ch; margin:0">
      <strong>Obscura</strong> — prototype de recherche, non audité, sans valeur.
      Réseau sur invitation : ni faucet, ni explorateur, ni bootnode public.
      La chaîne peut être remise à zéro à tout moment.
    </p>
  </footer>
```

- [ ] **Step 2: Vérifier les liens relatifs**

Vérifier que chaque `href` cible un fichier existant dans `docs/` : `obscura-overview.html`, `obscura-atelier.html`, `obscura-atelier-pratique.html`, `OPERATEUR.md`, `TESTNET.md`, `THREAT_MODEL.md`, `STARK_STATEMENT.md`, `PROTOCOL.md`, `POST_QUANTIQUE.md`.

Run :
```bash
ls docs/obscura-overview.html docs/obscura-atelier.html docs/obscura-atelier-pratique.html docs/OPERATEUR.md docs/TESTNET.md docs/THREAT_MODEL.md docs/STARK_STATEMENT.md docs/PROTOCOL.md docs/POST_QUANTIQUE.md
```
Expected : tous listés. Si un fichier manque (ex. `POST_QUANTIQUE.md`), corriger le lien ou le retirer.

- [ ] **Step 3: Vérification navigateur finale**

- Recharger. `resize_window` desktop puis mobile (375px) : pas de débordement horizontal, cartes en 1 colonne sur mobile.
- Basculer clair/sombre : disclaimer, cartes, blocs de code lisibles dans les deux.
- Cliquer chaque CTA/ancre interne.
- `read_console_messages` : aucune erreur.
- `computer {action:"screenshot"}` en clair et en sombre pour preuve.

- [ ] **Step 4: Commit**

```bash
git add docs/index.html
git commit -m "feat(web): navigation Aller plus loin + pied ; page hub complète"
```

---

## Self-Review (rempli par l'auteur du plan)

**Spec coverage :**
- Hero + disclaimer d'emblée → Task 4. ✓
- En bref (4 cartes) → Task 4. ✓
- Démarrer : express + pratique + rejoindre + copier → Task 5 (commandes vérifiées Tasks 1-2). ✓
- Aller plus loin + pied → Task 6. ✓
- Système visuel réutilisé (tokens overview) → Task 3. ✓
- Thème clair/sombre + toggle → Task 3. ✓
- Autonome, aucune dépendance externe → Task 3 (CSS/JS inline). ✓
- Commandes réelles vérifiées par exécution → Tasks 1-2, revérifié Task 5 Step 4. ✓
- `docs/index.html`, aucun code Rust modifié → File Structure. ✓
- Cadrage honnête (invitation, pas de faucet/explorateur/bouton rejoindre) → Task 4 disclaimer + Task 5 encart fédération + Task 6 pied. ✓

**Placeholder scan :** les `obs1…` sont des gabarits d'adresse volontaires (pas des TODO). Task 5 Step 2 signale explicitement de substituer les commandes confirmées si elles divergent. Aucun « TBD/à compléter ».

**Type consistency :** classes CSS cohérentes entre tâches (`.cmd`, `.copy`, `.card`, `.band`, `.step`, `.note`, `.subhead`) ; le JS de copie (Task 5) cible `.cmd .copy` définis au même endroit ; le toggle (Task 3) et le JS de copie (Task 5) vivent dans le même `<script>`.
