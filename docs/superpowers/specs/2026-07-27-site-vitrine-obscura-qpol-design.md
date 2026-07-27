# Site vitrine Obscura + QPoL — design

> Statut : design validé (brainstorming) le 2026-07-27, prêt pour `writing-plans`.
> Livrable : un site statique bilingue servi depuis `docs/`, présentant les **deux**
> projets et portant le parcours « télécharger et faire tourner ».

## But

Un site qui **présente deux projets distincts** et donne un point d'entrée unique :

- **Obscura** — prototype de monnaie post-quantique privée, code public, exécutable.
- **QPoL** — recherche sur une autre ressource rare pour protéger un consensus, **sans code
  publié** et **sans dépôt de brevet à ce jour**.

Il doit servir quatre publics sans page dédiée à chacun, par **mise en couches** :
vulgarisation d'abord, détail technique ensuite, dans le même document.

## Ce que ce design remplace

Il **absorbe et étend** `2026-07-24-homepage-hub-design.md` (design validé, jamais
implémenté : `docs/index.html` n'existe pas). Ce qui change, et pourquoi :

| Point | Design du 2026-07-24 | Ici | Raison |
|---|---|---|---|
| Portée | Obscura seul | Obscura + QPoL | demande utilisateur |
| `index.html` | hub Obscura, section « Démarrer » incluse | hub **deux projets** | il faut un palier au-dessus |
| « Démarrer » | section de `index.html` | page `demarrer.html` | l'index ne peut plus le porter |
| Langue | FR | FR + EN | demande utilisateur |
| CSS/JS | inline par page | `assets/site.css` partagé | 8 pages : l'inline se duplique 8 fois |

**Toutes ses contraintes de cadrage sont conservées telles quelles** (section
suivante). Le fichier du 2026-07-24 reste au dépôt comme trace ; il est marqué
« superseded » par celui-ci.

## Cadrage honnête — contraintes non négociables

Héritées de `docs/TESTNET.md` §0, `docs/OPERATEUR.md` et du design du 2026-07-24.
Ce ne sont pas des manques, ce sont des **décisions** :

- **Réseau sur invitation.** Aucun bootnode public, aucun faucet, aucun explorateur.
  Le site ne porte **aucun** bouton « rejoindre le réseau ».
- **Sans valeur, non audité.** Le disclaimer est en **hero**, pas en pied de page.
- **Nœud complet en navigateur : non viable** (P2P, CGNAT). « Faire son nœud » est
  un onboarding par commandes, jamais un nœud en page web.
- **Seul parcours suivable en solo : le testnet local.** Rejoindre une fédération est
  un chemin secondaire, présenté honnêtement comme soumis à invitation.
- **Aucune release binaire n'existe** (vérifié le 2026-07-27 : `gh release list` est
  vide). Le site ne propose donc **pas** de binaire à télécharger — il propose la
  **source** et le **build**. La procédure minisign (`deploiement/verifier-release.sh`,
  `deploiement/release.pub`) est documentée comme *ce qu'il faudra faire* le jour où
  une release existera, pas comme une étape actuelle.

## Contraintes propres à QPoL

**Aucune demande prioritaire n'est déposée** (état déclaré par l'auteur le
2026-07-27). Or un dossier d'invention rédigé porte déjà des revendications, et
l'analyse de liberté d'exploitation attend la revue du conseil PI. Ces pièces vivent
hors de ce dépôt et n'y sont pas référencées.

Conséquence retenue : **la page QPoL est non habilitante.** Elle énonce le *problème*
et l'*ambition*, jamais le *comment*.

Interdits sur `qpol.html`, formulés **par renvoi** :

- **aucun élément de mécanisme** — rien de ce que décrivent les documents de
  conception et le dossier d'invention du projet de recherche : ni étapes, ni
  ordonnancement, ni composition, ni grandeurs caractéristiques ;
- **aucun paramètre chiffré**, de quelque nature que ce soit ;
- **aucun schéma ni figure** repris des dossiers de recherche ou de brevet ;
- **aucun lien** vers les documents de conception, la note de présentation, le
  simulateur ou le dépôt qui les héberge — **aucun d'eux n'est publié** ;
- **aucune reprise** de la terminologie technique propre au mécanisme.

> ⚠️ **Ce fichier est lui-même publiable.** Il vit sous `docs/`, dans un dépôt
> public. Énumérer *nommément* les termes interdits reviendrait à les divulguer
> dans le document censé les proscrire — c'est pourquoi la liste ci-dessus renvoie
> aux dossiers de recherche au lieu de les citer. La liste nominative reste dans le
> dossier d'invention, hors de ce dépôt. Ne pas « préciser » cette section.

Ce qui est autorisé : le constat public que tout consensus repose sur une ressource
rare et que PoW/PoS centralisent (énergie bon marché, capital) ; l'existence d'un
travail de recherche ; l'état d'avancement en termes non techniques ; un contact.

> **Réserve.** Rédigé sans compétence juridique ; ceci n'est pas un avis juridique.
> Même bornée ainsi, la mise en regard publique du nom du projet et de sa finalité
> annoncée signale déjà la combinaison revendiquée.
> **`qpol.html` ne doit pas être mis en ligne avant relecture par le conseil PI.**
> Porté par la barre de vérification ci-dessous.

## Livrable

Servi par **GitHub Pages depuis le dossier `/docs`** de `nailiwalid-del/obscura`
(dépôt public, vérifié le 2026-07-27). Pages sait servir `/docs` nativement :
**aucun workflow Actions, aucun npm, aucun build.**

```
docs/
  index.html            hub — les deux projets
  obscura.html          présentation Obscura, en couches
  demarrer.html         source, build, testnet local, wallet
  qpol.html             teaser non habilitant  ← relecture conseil PI requise
  en/index.html  en/obscura.html  en/start.html  en/qpol.html
  assets/site.css       design system partagé
  assets/site.js        thème + bascule de langue + boutons « copier »
```

Inchangés : `obscura-overview.html`, `obscura-atelier.html`,
`obscura-atelier-pratique.html`. Le site **y renvoie** au lieu de les réécrire.

Aucune dépendance externe : pas de CDN, pas de police distante, pas de fetch. Les
feuilles partagées sont des chemins **relatifs**, donc le site reste ouvrable en
`file://` comme en `https://`.

## Système visuel — réutilisé, pas réinventé

Repris de `docs/obscura-overview.html` pour qu'un visiteur ne change pas d'univers
en passant du site à l'overview :

- variables CSS `--accent` (teal), `--paper/--surface/--ink/--muted/--line`,
  `--secret`, `--code-bg`, `--shadow` ;
- thème clair/sombre : `@media (prefers-color-scheme)` **plus** override
  `:root[data-theme="light"|"dark"]` piloté par le toggle ;
- typographie système ; `.serif` (Georgia) pour les titres éditoriaux, `.mono` pour
  le code ; largeur de lecture ~70ch, `.shell` max ~1180px.

**Distinction visuelle des deux projets.** Obscura garde le teal existant. QPoL reçoit
une teinte propre (`--accent-qpol`, froide, distincte) pour qu'aucun visiteur ne croie
que QPoL est un module d'Obscura. Ce sont deux projets sans lien de code.

## Contenu par page

### `index.html` — hub

1. **Hero** — l'auteur et la thèse commune : cryptographie post-quantique appliquée,
   menée jusqu'au code exécutable. Disclaimer prototype d'emblée.
2. **Deux cartes**, statut honnête et asymétrique assumée :
   - *Obscura* — prototype complet, testé de bout en bout, code public, exécutable
     aujourd'hui. → `obscura.html`, `demarrer.html`
   - *QPoL* — recherche, pas de code publié, pas de réseau. → `qpol.html`
3. **Ce qui relie les deux** — une thèse courte : les deux interrogent la ressource
   sur laquelle une garantie repose (mathématique post-quantique d'un côté, contrainte physique de l'autre).
4. **Pied** — statut, licence (MIT OR Apache-2.0), bascule de langue.

### `obscura.html` — présentation en couches

1. **Pour tous** — ce que le projet fait, sans jargon : une monnaie où montants,
   expéditeurs et destinataires ne sont jamais publiés.
2. **Le principe** — défense en profondeur : le tableau des quatre fonctions et de
   leurs deux primitives indépendantes (X25519/ML-KEM-768, Ed25519/ML-DSA-65,
   AES-256-GCM/XChaCha20-Poly1305, BLAKE3/SHA3-256), et l'énoncé « la sécurité tient
   si au moins une tient ».
3. **Confidentialité** — modèle à la Zerocash : on-chain, uniquement commitments
   (64 o) et nullifiers (32 o).
4. **Le STARK est le consensus**, pas une option (P1–P7, monolithe m-in/n-out ≤ 4,
   witness-hiding HVZK dans le ROM — avec le caveat honnête-vérifieur).
5. **Consensus BFT** — quorum `2f+1` vérifié **avant** tout STARK, finalité,
   changement de vue, comité reconfigurable à `h+K`.
6. **Les cinq limites connues, affichées et non enterrées** — autorité fédérée ;
   ce que le nœud servant apprend et le témoin (`--temoin`) ; pas de coinbase ;
   soundness 78 bits en régime prouvé ; dette de backend PQ. Plus la conséquence
   structurelle : aucune réorganisation possible.
7. **Aller plus loin** — overview technique, atelier, atelier pratique, et les docs
   d'autorité (`CONFORMITE.md`, `PROTOCOL.md`, `ARCHITECTURE.md`,
   `THREAT_MODEL.md`, `STARK_STATEMENT.md`).

Chaque couche renvoie vers l'overview pour le détail. **Aucun chiffre du dépôt n'est
recopié sans être vérifié à la source** (cf. barre de vérification).

### `demarrer.html` — télécharger et faire tourner

1. **Avertissement en tête** — prototype non audité, sans valeur, ne rien y confier.
2. **Récupérer la source** — `git clone https://github.com/nailiwalid-del/obscura.git`,
   et l'archive `…/archive/refs/heads/master.tar.gz`. Dit explicitement qu'il n'y a
   **pas encore** de binaire publié, et pourquoi (ouvrir une chaîne est un geste
   d'opérateur, `docs/OUVERTURE.md`).
3. **Prérequis et build** — Rust **1.87** minimum (`rust-version` de `Cargo.toml`),
   edition 2021.
   ```sh
   cargo build --release -p node --bins
   # → target/release/{obscura-node, obscura-wallet, obscura-genese, obscura-demo}
   ```
   Rappel : `--release` est requis (l'AIR du monolithe est gatée).
4. **Chemin express — une commande** : `cargo run --release --bin obscura-demo`.
5. **Chemin pratique — testnet local** : wallet → genèse ouverte → nœud scelleur et
   archiviste → synchroniser → solde → envoyer (commandes en §Commandes).
6. **Les deux avertissements d'opérateur**, mis en avant, pas en note :
   - `--sceller` est **off par défaut** — produire des blocs est une décision ;
     et un comité `n ≤ 3` sacrifie la tolérance aux fautes (quorum = `n`).
   - `--noeud-synchro` doit **différer** de `--noeud` — se synchroniser puis payer
     depuis le même nœud relie les deux et désigne l'émetteur.
   - `--archiver` est un rôle d'opérateur, off par défaut : sans archiviste, aucun
     wallet ne peut s'amorcer.
7. **Rejoindre une fédération** — encart honnête : sur invitation, `--identite`,
   `--autorite-hex`, échange d'adresses hors bande, comparaison de l'ancre complète
   (128 hex) entre opérateurs. Pas un bouton.
8. **Vérifier une release** — la procédure minisign, explicitement datée « quand une
   release existera ».
9. **Tests** — `cargo test --release`, et `--all-features` pour les chemins de dev.

Chaque bloc de commande porte un bouton « copier ».

### `qpol.html` — teaser non habilitant

1. **Le problème** — tout consensus décentralisé repose sur une ressource rare non
   falsifiable ; PoW la fait dériver vers l'énergie bon marché, PoS vers le capital.
   Constat public, aucune revendication.
2. **L'ambition** — chercher si une ressource **physique et non clonable** peut tenir
   ce rôle. Rien de plus.
3. **Où en est le travail** — en termes non techniques : design, résultat théorique,
   simulateur, revue d'antériorité, analyse FTO en cours de revue par un conseil.
4. **Ce que ce n'est pas** — pas de réseau, pas de code publié, pas de token, aucune
   date. Symétrique de l'honnêteté affichée pour Obscura.
5. **Contact** — **profil GitHub `nailiwalid-del` uniquement** (décision du
   2026-07-27). Aucune adresse e-mail en clair : elle serait moissonnée, et le lien
   GitHub est de toute façon déjà public via le dépôt `obscura`. Formulé comme une
   prise de contact préalable à toute discussion sous accord de confidentialité.

## Commandes — source d'autorité

Flags **vérifiés dans les sources le 2026-07-27** :

- `obscura-node` : `--ecoute`, `--pair`, `--donnees`, `--genese`, `--sceller`,
  `--archiver`, `--identite`.
- `obscura-genese` : `--sortie`, `--allocation`, `--autorite`, `--autorite-hex`.
- `obscura-wallet` — sous-commandes : `creer`, `adresse`, `synchroniser`, `solde`,
  `envoyer`, `consolider` ; flags : `--fichier`, `--a`, `--montant`, `--frais`,
  `--noeud`, `--noeud-synchro`, `--temoin`.

```sh
# 1. Wallet + adresse (phrase de passe : invite, ou OBSCURA_WALLET_PHRASE=…)
obscura-wallet creer   --fichier mon.wallet
obscura-wallet adresse --fichier mon.wallet          # → obs1…

# 2. Genèse locale OUVERTE (sans --autorite), allocation vers ton adresse
obscura-genese --sortie genese.bin --allocation obs1…:1000000

# 3. Nœud scelleur ET archiviste (l'archive est ce qui permet au wallet de synchroniser)
obscura-node --ecoute 0.0.0.0:9333 --genese genese.bin \
             --donnees ./donnees --sceller 1000 --archiver

# 4. Synchroniser puis lire le solde
obscura-wallet synchroniser --fichier mon.wallet --noeud 127.0.0.1:9333
obscura-wallet solde        --fichier mon.wallet

# 5. Envoyer
obscura-wallet envoyer --fichier mon.wallet --a obs1…dest --montant 300 \
                       --noeud 127.0.0.1:9333
```

## Bilingue

Répertoire `en/`, une URL par langue (meilleur pour l'envoi d'un lien et pour
l'indexation qu'une bascule en JS). Chaque page porte `<link rel="alternate"
hreflang>` vers son équivalent.

Les noms de fichiers diffèrent entre langues ; la bascule s'appuie donc sur une
**table explicite**, pas sur une transformation du chemin :

| FR | EN |
|---|---|
| `index.html` | `en/index.html` |
| `obscura.html` | `en/obscura.html` |
| `demarrer.html` | `en/start.html` |
| `qpol.html` | `en/qpol.html` |

Chaque page déclare sa contrepartie dans un attribut `data-alt` sur `<html>` ; le JS
ne fait que suivre ce lien, et le `<link rel="alternate">` le rend valable sans JS.

**Ordre de rédaction : le français en entier d'abord, l'anglais ensuite.** Mener les
deux de front produirait huit pages à moitié faites. L'anglais est une traduction,
pas une réécriture : toute divergence de fond est un défaut.

## Interactivité — JS minimal

`assets/site.js`, sans framework, sans fetch, sans état persistant autre que le thème :

- toggle thème clair/sombre (pose `data-theme` sur `:root`, mémorisé) ;
- boutons « copier » sur les blocs de commande (`navigator.clipboard`, échec silencieux) ;
- bascule de langue (lien direct, calculé depuis le chemin courant).

Le site doit rester lisible et navigable **sans JavaScript** : le JS n'ajoute que du
confort, jamais du contenu.

## Accessibilité et robustesse

- Contraste AA en clair comme en sombre, y compris sur `--accent-qpol`.
- Navigation clavier complète, focus visible, `prefers-reduced-motion` respecté.
- Responsive à partir de 320 px ; les blocs de code défilent horizontalement dans
  leur propre conteneur, jamais la page.
- Chaque page est imprimable proprement (pas d'onglets masquant du contenu).

## Barre de vérification — « terminé » ne se dit pas sans ça

1. **Toutes les commandes exécutées réellement**, pas relues : build, chemin express,
   testnet local complet jusqu'à `envoyer`.
2. **Chaque chiffre et chaque nom de primitive recoupés** avec `README.md`,
   `Cargo.toml` et `docs/` — le dépôt fait autorité, le site ne l'invente pas.
3. **Aucun lien mort**, interne comme externe, dans les deux langues.
4. **Les deux thèmes et 320 px** vérifiés visuellement.
5. **Parité FR/EN** : même structure de sections, aucun contenu présent d'un seul côté.
6. **`qpol.html` relu contre la liste d'interdits** ci-dessus, ligne à ligne.
7. **`qpol.html` non publié** tant que le conseil PI n'a pas relu.

   ⚠️ **Le verrou est le `git push`, pas le déploiement Pages.** Le dépôt
   `nailiwalid-del/obscura` est **public** : y pousser un commit contenant
   `qpol.html` le rend lisible par tous, que Pages le serve ou non, et qu'une page
   y renvoie ou non. Une page « non liée » sur un dépôt public reste une
   divulgation. Ne pas compter sur l'absence de lien comme protection.

   Conséquence pratique : le travail reste sur la branche locale `site-vitrine`,
   non poussée, jusqu'à la relecture. Deux sorties possibles ensuite :
   - relecture faite → pousser la branche entière ;
   - publier Obscura d'abord → pousser un sous-ensemble **sans** `qpol.html`,
     `en/qpol.html`, ni la carte QPoL du hub.

## Hors périmètre

Cut délibérément, et pourquoi :

- **Cutter une release binaire** — geste d'opérateur, pas une tâche de site
  (`docs/OUVERTURE.md`).
- **Explorateur, faucet, statistiques réseau** — contraires au cadrage « sur
  invitation », et il n'y a pas de chaîne publique.
- **Nœud ou wallet en navigateur** — non viable, et le prototype n'est pas audité.
- **Publier le dépôt qui héberge les travaux de recherche** — décision indépendante,
  bloquée par la PI.
- **Analytics, formulaires, backend** — le site reste statique et sans collecte.
