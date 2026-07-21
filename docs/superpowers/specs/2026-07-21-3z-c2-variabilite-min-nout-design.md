# 3z-c2 — variabilité M-in/N-out du monolithe segmenté (conception)

> Statut : conception validée par l'état du dépôt (reconnaissance du 2026-07-21).
> Référence circuit : journal de tête de docs/STARK_STATEMENT.md.
> Prérequis TENUS : 3z-c1 fusionné (le segmenté est le chemin de production),
> protocole complet (payer → sceller → recevoir → redépenser, commit dfa541a).

## Pourquoi maintenant, et pourquoi c'est plus qu'un confort

Le circuit est figé 2-in/2-out. Conséquence CONCRÈTE, visible dans
`crates/wallet/src/lib.rs` : un wallet qui détient UNE note ne peut pas payer
(`PasAssezDeNotes(1)`), et un wallet qui en détient cinq doit les dépenser deux
par deux en cascade. La variabilité M-in/N-out n'est pas une sophistication
gratuite : elle ferme le dernier écart entre « le protocole fonctionne » et
« le protocole est utilisable ».

## La couture existante (3z-c1) — ce sur quoi on construit

- Le schedule est DÉJÀ une liste : `schedule_2in2out() = [Key, In, In, Out, Out]`
  (`seg_layout.rs`). `seg_start(i, depth)` et `used_rows(depth)` sont des sommes
  cumulées sur cette liste — ils généralisent sans refonte.
- L'invariant d'alignement est DÉJÀ gardé pour les schedules variables : toute
  longueur de segment est multiple de `MERKLE_LEVEL_ROWS` (16), donc toute
  frontière l'est, « quel que soit le schedule » (assertion de compilation,
  seg_layout.rs:235-244).
- Ce qui est FIGÉ à 2 : les porteuses partagées (`RHO_C/CM_C/LEAF_C/VIN_C/
  VOUT_C : [usize; 2]`), `MonolithPublicInputs { nullifiers: [_; 2],
  output_commitments: [_; 2] }`, `MonolithWitness { inputs: [_; 2],
  outputs: [_; 2] }`, `ProvedTx` v3 (tableaux fixes, tx_digest v3), et
  `wallet::N_ENTREES = 2`.

## Décisions de conception

### D1 — Bornes : `MAX_IN = 4`, `MAX_OUT = 4`

La soundness de l'équilibre (3b3a/3b3b) exige `Σ par côté < p` : à
`RANGE_BITS = 60`, jusqu'à 8 termes par côté sont sûrs (`8·2^60 = 2^63 < p`),
15 au plus strict. 4 est en dessous de toute limite de soundness, couvre les
usages réels (consolidation de 4 notes, paiement à 3 destinataires + monnaie),
et borne le coût : chaque entrée ajoute 13 colonnes de porteuses
(rho 4 + cm 4 + leaf 4 + vin 1), chaque sortie 1 (vout). Pire cas 4-in/4-out :
92 + 26 + 2 = 120 colonnes (< 255 winterfell), lignes utiles au consensus
16 + 4·512 + 4·64 = 2320 → trace 4096 (×2 du 2/2). Les bornes sont des
constantes consensus : les changer = nouvelle version de format.

Contrainte de plancher : `M ≥ 1` et `N ≥ 1` (une transaction sans entrée
n'a pas d'autorité ; sans sortie, elle n'a pas de destinataire — les frais purs
passent par une sortie de valeur 0 vers soi).

### D2 — Largeur de trace DIMENSIONNÉE À LA FORME, pas à MAX

La largeur winterfell est déjà une donnée runtime, et le côté LIGNES est déjà
runtime (`seg_start(i, depth)`). Le côté COLONNES devient pareil : les offsets
de porteuses deviennent des fonctions de `(m, n)` — `rho_c(i, m)`, `vout_c(j,
m, n)`, `width(m, n)` — au lieu de constantes. Une transaction 1-in/2-out paie
79 colonnes, pas 120.

Rejeté : largeur fixe MAX avec segments de bourrage. Payer 41 colonnes de
porteuses mortes sur chaque petite transaction pour garder des `const` serait
exactement le gaspillage que 3z-c1 a éliminé côté lignes (« une longueur
uniforme calée sur le chemin gaspillait ~480 lignes »).

Garde à porter : les assertions de contiguïté des offsets (tests
`colonnes_partagees_contigues`) deviennent paramétriques sur toutes les formes
`1..=4 × 1..=4`.

### D3 — La FORME est publique, et c'est écrit

`(m, n)` entre dans les publics (implicitement : longueurs de `nullifiers` et
`output_commitments`, comme le statement le prévoit déjà — « nullifiers[] : un
par note dépensée »). Un observateur voit donc la forme de chaque transaction,
et les formes rares partitionnent l'ensemble d'anonymat — le même mécanisme que
l'ancre ou la clé d'intention, en moins grave (4×4 = 16 seaux au plus, contre
un pseudonyme par wallet).

Assumé, PAS corrigé : l'alternative (bourrer toutes les transactions à 4/4)
coûterait ×2 de trace à tout le monde pour uniformiser ce que Zcash Sapling
lui-même expose (le nombre de spends/outputs est public). MAIS le wallet
n'exploite pas la variabilité en silence : `construire` garde la forme 2/2 par
DÉFAUT (le seau le plus peuplé) et n'utilise M>2 ou N≠2 que sur demande
explicite (consolidation, multi-paiement). À écrire dans THREAT_MODEL.

### D4 — `ProvedTx` v4, refusé ≠ réinterprété

Champs variables (`nullifiers: Vec<Digest>` borné `MAX_IN`, `output_commitments`
+ `enc_notes : Vec` bornés `MAX_OUT`), comptes explicites dans l'encodage,
bornes vérifiées AVANT allocation ET dans les constructeurs (règle établie).
`TX_DOMAIN = "obscura/proved-tx/v4"` — les comptes `m`/`n` entrent dans
`tx_digest` (sinon deux découpages différents des mêmes octets pourraient
produire le même digest). Un `ProvedTx` v3 est REFUSÉ par `from_bytes` v4,
jamais réinterprété. Pas de double-pile v3/v4 : le prototype n'a pas de chaîne
publique à migrer, la bascule est franche (comme 0x01→0x02 du bloc).

Cascade mécanique, à porter dans le même mouvement : `ledger::apply_proved_tx`
(itère déjà sur les tableaux — devient itération sur Vec), mempool (2 nf → m),
`node::message`/`synchro` (bornes recalculées : une réponse d'historique reste
bornée par sorties, pas par transactions), `historique` (déjà générique en
sorties par bloc), bloc (taille max de tx change → re-vérifier les assertions
de cadrage), bench et overview.

### D5 — Le wallet choisit la forme, avec un plancher d'ergonomie

`construire(destinataire, montant, frais)` : sélection de notes jusqu'à
couvrir `montant + frais`, bornée à `MAX_IN` (au-delà : erreur nommée «
consolidez d'abord »), monnaie rendue toujours produite (N=2 par défaut).
NOUVEAU : `construire` fonctionne avec UNE note (m=1). `consolider()` :
M notes → 1 note vers soi (le geste que « consolidez d'abord » demande).
`N_ENTREES` disparaît. Forme par défaut 2/2 maintenue quand c'est possible
(cf. D3) : avec 1 seule note on fait 1-in/2-out, avec 3+ notes on prend 2.

### D6 — Suppression du côte-à-côte : APRÈS la parité, pas avant

L'oracle de parité (côte-à-côte vs segmenté, mêmes publics pour le même témoin)
ne couvre QUE la forme 2/2 — c'est sa limite naturelle, il ne sera jamais
généralisé. Ordre imposé : (1) le segmenté devient variable, (2) la parité 2/2
tourne une dernière fois verte, (3) le côte-à-côte est supprimé (~1900 lignes
de air.rs/trace.rs/layout.rs + gadgets morts), (4) les forges du segmenté
deviennent LA seule couverture. Les deux forges non portées (`PaddingMerkle`,
`VaccInitial` forme fine) sont portées AVANT la suppression — sinon leur
couverture disparaît avec l'oracle.

### D7 — L'audit « liaison de racine » par fusion, systématisé

Leçon 3z-c1 (STARK_STATEMENT, « Liaison de racine ») : mutualiser peut
supprimer une garantie que la redondance offrait gratuitement. La variabilité
introduit trois points du même type, chacun exigeant sa forge RED :

1. **Comptage des segments** : l'AIR doit refuser une trace dont le nombre de
   segments IN ne vaut pas `m` (le nombre de nullifiers publics). Sinon un
   prouveur présente m=1 au public mais 2 segments IN dans la trace — une
   dépense non déclarée. L'ancrage : chaque nullifier public est asserté à
   `seg_start(segment IN i) + NF_ANCRE` ; il faut AUSSI que rien d'autre ne
   ressemble à un segment IN — le sélecteur de type est dérivé du schedule,
   lui-même dérivé de (m, n) publics. Forge : trace à m+1 segments IN.
2. **Équilibre à fin variable** : `S == fee` est asserté à la dernière ligne
   UTILE, qui dépend de (m, n). Forge : déplacer la fin (un segment OUT de
   plus, non déclaré) et vérifier que l'assertion ne « glisse » pas.
3. **Publics ↔ segments, ordre par ordre** : `output_commitments[j]` doit être
   lié au j-ième segment OUT (pas à « un » segment OUT). Forge : permutation
   de deux commitments de sortie entre leurs segments.

### D8 — Forges à profondeur consensus (dette 3z-c1)

`build_tree_from_leaves` est câblé profondeur 2 ; cinq forges à reconstruction
d'arbre y restent bloquées. Le généraliser en `build_tree(depth, leaves)` et
faire tourner au moins UNE forge de chaque famille à profondeur 32 (le tableau
de seg_air.rs:1619 documente pourquoi la géométrie 2 ≠ 32 peut masquer un trou).

## Découpage en tâches (TDD, une tâche = une suite verte)

- **C2-T1 — layout paramétré `(m, n)`** : `schedule(m, n) -> Vec<SegKind>`,
  offsets de porteuses en fonctions, `width(m, n)`, `used_rows/trace_len(m, n,
  depth)`, bornes `1..=MAX` dans les constructeurs, gardes compile-time sur les
  MAX + tests paramétriques de contiguïté/alignement sur les 16 formes.
  (2/2 reste un cas particulier strictement identique à l'existant : vérifié
  par égalité des valeurs actuelles.)
- **C2-T2 — trace paramétrée** : `MonolithWitness { inputs: Vec, outputs: Vec }`
  (borné), constructeur de trace itérant le schedule ; sanité hors-prouveur sur
  1/1, 2/2, 4/4, 1/4, 4/1.
- **C2-T3 — AIR paramétrée** : sélecteurs et assertions dérivés de (m, n)
  publics, `MonolithPublicInputs` à Vec bornés, équilibre chaîné à fin
  variable. Preuves 1/1 et 4/4 vertes en dev depth.
- **C2-T4 — soundness variable** : les trois forges de D7 + re-port des forges
  existantes sous formes non-2/2 (chaque forge tourne sur au moins une forme
  ≠ 2/2). RED discipliné partout.
- **C2-T5 — masquage sous formes variables** : test d'inertie du blinding et
  de non-fuite des porteuses sur 1/1 et 4/4 (le nombre de porteuses change, le
  gating global `blind_off` doit couvrir les nouvelles colonnes sans liste
  manuelle à tenir).
- **C2-T6 — ProvedTx v4 + cascade** : wire, tx_digest v4, tx.rs, ledger,
  mempool, node, bornes réseau recalculées, tests hostiles.
- **C2-T7 — wallet** : sélection ≤ MAX_IN, m=1 fonctionne, `consolider()`,
  forme 2/2 par défaut (D3), CLI.
- **C2-T8 — parité finale 2/2 puis SUPPRESSION du côte-à-côte** (D6, ordre
  strict), forges profondeur 32 (D8), re-bench (2/2 ne doit pas régresser ;
  mesurer 1/1, 1/2, 4/4), docs (STARK_STATEMENT en tête, THREAT_MODEL D3,
  CLAUDE.md, overview).

## Limites assumées (à reporter dans THREAT_MODEL avec C2-T8)

- La forme (m, n) est publique — partition d'anonymat en ≤ 16 seaux, atténuée
  par le défaut 2/2 du wallet, jamais éliminée.
- MAX_IN = MAX_OUT = 4 est un choix de coût, pas de soundness (la borne sûre
  est 8) ; l'augmenter plus tard = nouvelle version de format, pas un patch.
- L'oracle de parité meurt avec le côte-à-côte : après C2-T8, la seule
  couverture du circuit est sa propre suite de forges. C'est le prix décidé
  de −1900 lignes ; il oblige à la discipline RED sur chaque forge future.
