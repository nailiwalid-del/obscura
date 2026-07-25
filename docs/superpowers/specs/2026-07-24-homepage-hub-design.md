# Homepage hub Obscura — design

> Statut : design validé (brainstorming), prêt pour plan d'implémentation
> (`writing-plans`). Livrable : une page statique autonome `docs/index.html`.

## But

Une **page d'accueil / hub** qui présente Obscura et donne un point d'entrée
unique, sans dupliquer les pages existantes. Elle oriente vers l'overview
technique et l'atelier, et porte un **quickstart** que le visiteur peut suivre
seul (testnet local). Public : quelqu'un qui découvre le dépôt et veut soit
comprendre, soit lancer le prototype.

## Cadrage honnête (contraintes non négociables)

Tiré de `docs/TESTNET.md` §0 et `docs/OPERATEUR.md` :

- **Réseau sur invitation.** Aucun bootnode public, aucun faucet, aucun
  explorateur — **par décision**, pas par manque. La page ne promet donc **aucun**
  bouton « rejoindre », faucet, ni explorateur.
- **Sans valeur, non audité, remis à zéro.** Le disclaimer est en **hero**, pas
  en pied de page.
- **Nœud complet en navigateur : non viable** (P2P/CGNAT). La partie « faire son
  nœud » est de l'**onboarding guidé** (commandes), jamais un nœud en page web.
- **Seul parcours suivable en solo = testnet local** (genèse vide / chaîne
  ouverte, une machine). « Rejoindre une fédération » est un chemin **secondaire**,
  honnête sur l'invitation.

## Livrable

Fichier unique **`docs/index.html`** (décision utilisateur), statique, autonome :
CSS + JS **inline**, **aucune** dépendance externe (police système, pas de CDN).

## Système visuel — RÉUTILISÉ, pas réinventé

Reprend les tokens et le langage de `docs/obscura-overview.html` :

- Variables CSS : `--accent` teal, `--paper/--surface/--ink/--muted/--line`,
  `--secret`, `--code-bg`, `--shadow`.
- Thème **clair/sombre** : `@media (prefers-color-scheme)` + override
  `:root[data-theme="light"|"dark"]` (toggle JS inline, comme overview).
- Typo : système sans-serif ; `.serif` (Georgia) pour les titres éditoriaux ;
  `.mono` pour le code. Largeur de lecture `~70ch`, `.shell` max ~1180px.

Cohérence maison : un visiteur qui passe du hub à l'overview ne change pas
d'univers visuel.

## Structure de la page (haut → bas)

1. **Hero** — nom « Obscura », tagline « monnaie post-quantique conçue pour la
   confidentialité », **bandeau disclaimer d'emblée** (prototype non audité, sans
   valeur, remis à zéro). Deux CTA ancrés : « Démarrer » (#demarrer) et
   « Comprendre » (→ overview).
2. **En bref** — 3–4 cartes de valeur, chacune une phrase + lien ancré vers
   l'overview pour le détail :
   - Confidentialité (preuve STARK unique, notes chiffrées, nullifiers).
   - Post-quantique (KEM/signatures hybrides, hash Rescue prouvé).
   - Consensus BFT fédéré (quorum `2f+1`, finalité, comité reconfigurable).
   - Prototype pédagogique (balisé, non audité — lien THREAT_MODEL/CONFORMITE).
3. **Démarrer** (`#demarrer`, cœur de la page) — deux sections **empilées** (pas
   d'onglets : moins de JS, tout visible/imprimable) :
   - **Chemin express (1 commande)** : `cargo run --release --bin obscura-demo`
     → deux nœuds réels, une transaction émise et propagée. « Est-ce que ça
     marche vraiment ? » en une commande.
   - **Chemin pratique (testnet local)** : étapes copiables (voir §Commandes).
   - Encart **« Rejoindre une fédération »** : renvoi honnête (invitation,
     `--identite`, `--autorite-hex`, échange d'adresses hors bande) — pas un
     bouton.
   Chaque bloc de commande a un bouton **« copier »** (JS inline, sans lib).
4. **Aller plus loin** — cartes de navigation :
   - [Overview technique](obscura-overview.html), [Atelier](obscura-atelier.html),
     [Atelier pratique](obscura-atelier-pratique.html).
   - Docs clés : `OPERATEUR.md`, `TESTNET.md`, `THREAT_MODEL.md`,
     `STARK_STATEMENT.md`, `PROTOCOL.md`.
5. **Pied** — rappel statut + « sur invitation, pas de faucet/explorateur » +
   version/date.

## Commandes (source d'autorité : doc-comments des binaires + OPERATEUR.md)

Toutes transcrites depuis les sources ; **vérifiées par exécution réelle** avant
« terminé » (cf. §Barre de vérification). Package cargo : `node`.

**Build (préalable commun) — tout en `--release` (AIR du monolithe gatée) :**

```sh
cargo build --release -p node --bins
# → target/release/{obscura-node, obscura-wallet, obscura-genese, obscura-demo}
```

**Chemin express :**

```sh
cargo run --release --bin obscura-demo
```

**Chemin pratique — testnet local (chaîne ouverte, une machine) :**

```sh
# 1. Wallet + adresse (phrase de passe : invite, ou OBSCURA_WALLET_PHRASE=…)
obscura-wallet creer   --fichier mon.wallet
obscura-wallet adresse --fichier mon.wallet          # → obs1…

# 2. Genèse locale OUVERTE, allocation vers ton adresse (sans --autorite = ouverte)
obscura-genese --sortie genese.bin --allocation obs1…:1000000

# 3. Nœud scelleur + archive (archive = ce qui permet au wallet de synchroniser)
obscura-node --ecoute 0.0.0.0:9333 --genese genese.bin \
             --donnees ./donnees --sceller 1000 --archiver

# 4. Synchroniser puis lire le solde
obscura-wallet synchroniser --fichier mon.wallet --noeud 127.0.0.1:9333
obscura-wallet solde        --fichier mon.wallet

# 5. Envoyer
obscura-wallet envoyer --fichier mon.wallet --a obs1…dest --montant 300 \
                       --noeud 127.0.0.1:9333
```

**Rejoindre une fédération (secondaire, honnête sur l'invitation) :**

```sh
obscura-node --identite --donnees ./donnees          # publie ta clé publique
# → transmettre l'adresse obs1… ET la clé de nœud au fabricant de la genèse ;
#   récupérer les adresses de pairs HORS BANDE, puis :
obscura-node --ecoute 0.0.0.0:9333 --pair <adr_pair> \
             --genese genese.bin --donnees ./donnees
```

Flags nœud confirmés sur `crates/node/src/bin/obscura-node.rs` : `--ecoute`
(obligatoire), `--pair` (répétable), `--donnees`, `--genese`, `--sceller <ms>`
(0 → défaut), `--archiver`, `--identite`. Sous-commandes wallet confirmées sur
l'en-tête de `crates/node/src/bin/obscura-wallet.rs`.

## Interactivité (JS inline minimal)

- **Toggle thème** clair/sombre (pose `data-theme` sur `:root`), même approche
  qu'overview.
- **Boutons « copier »** sur les blocs de commande (`navigator.clipboard`,
  fallback silencieux).
- Rien d'autre : pas de framework, pas de fetch, pas d'état.

## Barre de vérification (la valeur de la page = commandes réelles)

Avant toute affirmation de complétude :

1. `cargo build --release -p node --bins` réussit.
2. **Chemin express** exécuté : `obscura-demo` va au bout (tx propagée).
3. **Chemin pratique** exécuté de bout en bout sur une machine : wallet créé →
   adresse → genèse → nœud scelleur+archive → synchro → solde reflète
   l'allocation → envoi accepté. Toute commande qui diverge de la source est
   corrigée sur la page, pas laissée « probable ».
4. Rendu vérifié dans le navigateur (preview) : thème clair/sombre, copie,
   ancres, responsive ; console sans erreur.

Si une étape du chemin pratique s'avère plus subtile que prévu (ex. format exact
de l'adresse dans `--allocation`, dépendance de synchro), elle est **corrigée ou
documentée sur la page**, jamais masquée.

## Hors périmètre (YAGNI)

Wallet/nœud en navigateur, WASM, faucet, explorateur, bouton « rejoindre »,
i18n/anglais, analytics, back-end. Une seule page, un seul fichier.

## Points de contact

- **Nouveau** : `docs/index.html`.
- **Aucune** modification de code Rust. Lecture seule des binaires pour
  transcrire/vérifier les commandes.
- Liens relatifs vers les `docs/*.html` et `docs/*.md` existants (mêmes chemins
  relatifs, la page vit dans `docs/`).
