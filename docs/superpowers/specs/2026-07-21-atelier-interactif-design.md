# Atelier interactif Obscura — design

> Un « petit outil ludique » pour comprendre le fonctionnement d'Obscura :
> `docs/obscura-atelier.html`, page auto-contenue (zéro dépendance, même charte
> visuelle que `obscura-overview.html`) qui fait MANIPULER le cycle de vie d'une
> note au lieu de le lire. Public : non-cryptographe curieux ; le lecteur de
> l'overview qui veut « toucher ».

## 1. Choix d'approche

- **Page HTML interactive** (retenue) plutôt qu'une extension du binaire
  `obscura-demo` (déjà existant, terminal, linéaire) ou qu'une app séparée
  (surdimensionnée). S'ouvre d'un double-clic, fonctionne en `file://`, thème
  clair/sombre hérité de l'overview.
- **Hachage-jouet** (FNV-1a 32 bits itéré, affiché sur 10 hex) — PAS la vraie
  crypto, et c'est affiché en toutes lettres dans la page (« simulation
  pédagogique : les vrais hachages sont Rescue-Prime / BLAKE3‖SHA3 »). La page
  simule les CONCEPTS (commitment, arbre, nullifier, équilibre), pas la sécurité.

## 2. Parcours en 5 étapes (déverrouillage progressif)

1. **Ton identité** — bouton « générer » : `secret` (jamais publié, encadré
   ambre) → `owner = H_owner(secret)` et `nk = H_nk(secret)` (dérivés, publics
   côté wallet). Miroir de P2/P4.
2. **Reçois des notes** — frapper des notes (montants au choix) : chaque note
   `{value, owner, rho, r}` donne `cm = H(note)` inséré comme feuille d'un
   **arbre de Merkle profondeur 3 (8 feuilles) dessiné dans la page**, racine
   recalculée à chaque insertion. Le réseau ne voit QUE `cm`.
3. **Dépense** — choisir une note, un montant vers Bob et des frais ; équation
   d'équilibre en direct (`valeur = vers Bob + frais + monnaie rendue`). Bouton
   « Prouver & envoyer » : **checklist P1–P7 animée** (le chemin de Merkle de la
   feuille dépensée se surligne pendant P1), puis publication : le `nullifier`
   rejoint la liste publique, deux nouveaux commitments (Bob + monnaie rendue
   vers soi-même) entrent dans l'arbre.
4. **Tente la double dépense** — bouton « rejouer la même note » : la
   vérification s'arrête sur « nullifier déjà vu » → REJET animé. Le tampon
   anti-double-dépense devient concret.
5. **L'œil de l'observateur** — deux colonnes : ce que voit LE RÉSEAU (racine,
   nullifiers, commitments, frais — aucun montant, aucune identité) vs ce que
   voit ALICE (ses notes, montants, monnaie rendue). Rappel d'une phrase que la
   couche réseau (Dandelion++, liens chiffrés PQ) protège en plus l'ORIGINE.

Bouton « recommencer » global. Sections suivantes grisées tant que la
précédente n'est pas faite (pédagogie par progression).

## 3. Hors périmètre

- Pas de vraie crypto en JS, pas de STARK simulé au-delà de la checklist.
- Pas de simulation réseau/Dandelion (une phrase de renvoi vers l'overview).
- Arité 1-in/2-out pour rester lisible (le vrai circuit est 2-in/2-out).

## 4. Extension (même jour) — finalité et synchronisation

Le protocole ayant gagné la finalité (blocs scellés) et la synchronisation
wallet ↔ nœud (commit dfa541a), l'atelier passe de 5 à **7 étapes** pour jouer le
MÊME cycle que `crates/node/tests/cycle_wallet.rs` :

1–2. inchangées (identité, réception) ;
3. la dépense prouvée va au **MEMPOOL** — l'arbre ne bouge pas, la note passe
   « en attente de bloc » (l'ancien atelier appliquait instantanément, ce qui
   contredisait désormais le protocole) ;
4. **Sceller un bloc** : tri par digest (deux nœuds honnêtes → même bloc),
   chaînage au parent, application atomique — nullifier publié, sorties
   insérées, chaîne de blocs affichée. Moment pédagogique clé : Alice ne voit
   PAS encore sa monnaie rendue (`connue:false`) ;
5. double dépense (rejet par nullifier, inchangé sur le fond) ;
6. **Synchroniser** : journal animé du rejeu (« position et rien d'autre »,
   racine de fin de bloc vérifiée, un essai de déchiffrement par sortie) —
   Bob découvre sa note, Alice sa monnaie rendue, le cycle est fermé ;
7. observateur (ajout de la hauteur de chaîne).

## 5. Intégration

- Lien croisé : un encart « 🕹️ Envie de manipuler ? » dans la partie I de
  `obscura-overview.html` (après le cycle de vie), pointant vers l'atelier ;
  lien retour vers l'overview dans le pied de page de l'atelier.
- Conventions : français, thème-aware (mêmes variables CSS), aucun réseau,
  aucune dépendance, accessible (boutons réels, aria-labels sur les figures).
