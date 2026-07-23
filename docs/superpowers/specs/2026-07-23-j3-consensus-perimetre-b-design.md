# J3 — Consensus, périmètre B — conception

**Date :** 2026-07-23
**Objet :** franchir la porte J3 de la carte `2026-07-23-reste-a-faire-vers-B.md`
(cycle 5) — rendre le consensus **défendable en réseau public expérimental** :
survie aux partitions, comportement en minorité, procédure de mise à jour, et
**négociation de version de fil** formalisée.
**Statut :** conception, en attente de revue utilisateur.
**Dépend de :** J1 ✅ (le modèle BFT est tranché et livré). **Gèle :** le format de
fil.
**Spec de référence :** carte `2026-07-22-portes-vers-le-mainnet-design.md`
(fiche J3) et `docs/PROTOCOL.md` (§ protocole applicatif).
**Périmètre B strictement** : admission ouverte, anti-Sybil économique et leur coût
sont **hors périmètre** (porte A).

---

## Contexte vérifié (au 2026-07-23)

Ce que J1 a livré et qui porte J3 :

- **Finalité BFT à quorum** : `appliquer_bloc` exige `⌊2n/3⌋+1` votes ; changement
  de vue (J1-b2) ; append-only, **aucune réorganisation possible par
  construction**. C'est la propriété qui rend la partition *sûre par défaut* (voir
  chantier 1).
- **Tolérance de version réactive** : `crates/node/src/message.rs:128`
  `version_inconnue()` distingue « version future » de « malformation » et **ne
  sanctionne pas** la première — un pair à jour n'est jamais banni par un pair en
  retard. Suffisant pour ne pas partitionner ; **insuffisant comme négociation**.
- **Rattrapage** : `Message::DemandeBloc { hauteur }` + `node::archive` — un nœud
  qui a manqué une hauteur la redemande et rejoint la chaîne par le chemin normal.
  C'est le mécanisme de **rejoin** après partition (chantier 1).
- **Handshake de transport** : `crates/net` — 3 passes hybride, forward secrecy,
  masquage d'identité. C'est là que l'échange de version explicite s'insère
  (chantier 3), **sans primitive nouvelle**.

Restent **trois défauts**.

---

## Chantier 1 — Partition et comportement en minorité

### Le défaut

Le réseau **survit-il à une partition** ? La propriété est probablement déjà vraie
— un côté minoritaire ne peut pas atteindre `2f+1`, donc **ne produit pas**, donc
ne crée pas de chaîne concurrente — mais elle n'est **ni énoncée ni testée**. Une
propriété de sûreté non testée n'est pas une garantie.

### Ce que la spec demande

**Énoncer et prouver par test**, pas ajouter de mécanisme (le BFT fait déjà le
travail) :

1. **Politique de minorité, écrite** : un nœud du côté minoritaire d'une partition
   **s'arrête de produire** (il n'atteint pas le quorum), **continue de servir**
   (lecture, historique, rattrapage), et **ne fork jamais** (append-only). C'est le
   *gel suspensif* déjà décrit pour une autorité absente — la partition en est le
   cas général.
2. **Rejoin propre au retour** : quand la partition guérit, le nœud minoritaire
   **rattrape** par `DemandeBloc` la chaîne majoritaire et converge vers la même
   tête. Aucun état à réconcilier (il n'a rien produit).
3. **Test de chaos partition** (`crates/node/tests/`) : deux groupes de nœuds
   séparés puis reconnectés ; assertions — le groupe majoritaire (≥ quorum)
   continue, le minoritaire s'arrête, et **après guérison les deux ont la même
   tête**, aucun bloc concurrent appliqué. Étend `chaos_producteur.rs` dans
   l'esprit.

⚠️ **Le cas sans majorité.** Si *aucun* côté n'atteint le quorum (partition
équilibrée à `n=4`, 2/2), **personne ne produit** — c'est correct et attendu (la
sûreté prime la liveness), à écrire dans les limites. La chaîne reprend quand la
partition guérit.

### Critère de franchissement

Le test de chaos partition passe : majorité continue, minorité s'arrête sans
forker, convergence vers une tête unique après guérison. La politique de minorité
est écrite dans `docs/PROTOCOL.md` (ou `THREAT_MODEL.md`) et dans les limites de
`docs/TESTNET.md`.

---

## Chantier 2 — Procédure de mise à jour (rolling upgrade)

### Le défaut

Faire évoluer le logiciel d'un réseau vivant **sans forker** n'est pas décrit. La
tolérance de version réactive (`version_inconnue()`) rend l'upgrade *possible* sans
bannissement mutuel, mais aucune **procédure** ne dit à un opérateur comment s'y
prendre — et un upgrade mal ordonné qui change une règle de consensus **est** un
fork.

### Ce que la spec demande

**Une procédure écrite** — dans `docs/OPERATEUR.md` (ou une section du runbook
`docs/OUVERTURE.md` produit par T5) :

1. **Distinguer deux natures de changement** : (a) *compatible fil* (n'affecte pas
   le format de bloc ni les règles de validation — se déploie nœud par nœud, dans
   n'importe quel ordre) ; (b) *rupture de consensus* (change une règle de
   validation ou le format de bloc — **exige une nouvelle chaîne** sur un réseau
   sur invitation, ou un mécanisme d'activation par hauteur, hors périmètre B).
2. **La règle** : sur le testnet fédéré, un changement de rupture **= nouvelle
   chaîne** (cohérent avec « chaîne consommable » de T5). Un changement compatible
   se déploie en rolling, appuyé sur la tolérance de version.
3. **Le lien avec le chantier 3** : la négociation de version explicite donne à un
   opérateur le moyen de *constater* qui parle quelle version avant de déployer.

### Critère de franchissement

`docs/OPERATEUR.md` décrit la procédure de mise à jour, distingue compatible /
rupture, et énonce la règle « rupture = nouvelle chaîne » pour le périmètre B.

---

## Chantier 3 — Négociation de version de fil explicite

### Le défaut

La tolérance actuelle est **réactive** : on ne bannit pas ce qu'on ne comprend pas.
Mais aucun nœud ne **sait** quelle version parle son pair — la version n'est
constatée qu'a posteriori, par l'échec de décodage d'un message. Impossible d'agir
en amont (refuser proprement, ou choisir un comportement compatible).

### Décision (tranchée par l'utilisateur, 2026-07-23) : **échange de version explicite**

Ajouter un **numéro de version de protocole échangé au handshake**, plus une
**règle de compatibilité écrite** (version minimale acceptée). Pas de négociation
de capacités (surdimensionnée pour un réseau sur invitation coordonné hors bande).

### Ce que la spec demande

1. **Un champ de version de protocole** (`VERSION_PROTOCOLE: u16`, distinct de
   `VERSION_BLOC` et des versions de sérialisation) échangé **tôt** dans le
   handshake `crates/net` — dans le premier message applicatif après
   l'établissement du canal chiffré, ou dans le préambule si le format le permet
   **sans casser le masquage d'identité** (à vérifier : la version ne doit pas
   devenir un discriminant qui affaiblit le masquage — recommandation : l'échanger
   *après* le chiffrement établi, jamais en clair sur le fil).
2. **La règle de compatibilité** : chaque nœud publie sa `VERSION_PROTOCOLE` et une
   `VERSION_MIN_ACCEPTEE`. Un pair dont la version est `< VERSION_MIN_ACCEPTEE` est
   **refusé proprement** (déconnexion nommée, **pas de sanction de score** — un pair
   en retard n'est pas hostile, exactement la logique de `version_inconnue()`
   généralisée). Un pair de version *supérieure* connue-compatible est accepté.
3. **La compatibilité descendante préservée** : la tolérance réactive
   (`version_inconnue()`) **reste** — l'échange explicite la *complète*, il ne la
   remplace pas. Un nœud qui ne connaît pas encore l'échange de version (ancien)
   ne doit pas être banni par un nouveau.
4. **Gel de format** : `VERSION_PROTOCOLE` et sa position dans le handshake entrent
   dans le **format de fil** — c'est ce que J3 gèle. Le documenter dans
   `docs/PROTOCOL.md`.

⚠️ **Le piège à ne pas rejouer.** Introduire l'échange de version est
*lui-même* un changement de fil. Il doit être conçu pour qu'un nœud **sans** cet
échange et un nœud **avec** puissent coexister le temps d'un rolling upgrade —
sinon le déploiement de J3 est lui-même un fork. Concrètement : l'absence
d'annonce de version = version de base présumée, jamais un rejet.

### Critère de franchissement

Deux nœuds échangent leur `VERSION_PROTOCOLE` au handshake ; un nœud de version
trop basse est refusé **sans sanction** ; un nœud sans l'échange (ancien) reste
accepté (présumé version de base). Testé sur sockets réelles.

---

## Ce que cette spec ne fait pas

- **Ouverture de l'appartenance et anti-Sybil** : hors périmètre (porte A).
- **Négociation de capacités / feature flags** : écartée (échange de version
  explicite seul).
- **Mécanisme d'activation de règle par hauteur** (hard-fork coordonné) : hors
  périmètre B — sur le testnet, une rupture de consensus = nouvelle chaîne.
- **Ne change pas** le modèle BFT (J1) : J3 le *défend* et le *teste*, il ne le
  redessine pas.

## Découpage suggéré pour le plan

Trois tâches ; la 1 est surtout des tests, la 3 porte le code neuf :

1. **Partition** : test de chaos partition (`crates/node/tests/`), politique de
   minorité écrite (`PROTOCOL.md` + `TESTNET.md`). Peu de code, beaucoup
   d'assertions multi-nœuds.
2. **Mise à jour** : procédure dans `docs/OPERATEUR.md` (compatible vs rupture,
   « rupture = nouvelle chaîne »). Documentation.
3. **Version explicite** : `VERSION_PROTOCOLE`/`VERSION_MIN_ACCEPTEE`, échange au
   handshake `crates/net` **après** le chiffrement établi (préserver le masquage
   d'identité), refus propre sans sanction, coexistence ancien/nouveau, test
   sockets. Code + `PROTOCOL.md`.

⚠️ **Ce que le plan doit vérifier avant d'écrire.** Le point exact du handshake
`crates/net` où insérer l'échange sans affaiblir le masquage d'identité (relire la
machine à états en typestate) ; et que la coexistence ancien/nouveau est bien un
test, pas une supposition. Repartir du working tree.

## Critère de franchissement global

Le réseau **survit à une partition et se met à jour sans fork non intentionnel**
(carte de juillet). Concrètement : le test de chaos partition passe, la procédure
de mise à jour est écrite, et l'échange de version explicite fonctionne sur sockets
avec coexistence ancien/nouveau. À ce point, **l'état B est atteint** — il ne reste
que la décision écrite B → A.
