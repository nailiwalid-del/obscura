# 3z-b1 — Witness-hiding du monolithe (lignes de blinding)

> Deuxième tranche de la **Phase 3z-b**. Implémente la **Voie A** tranchée par le spike
> 3z-b0 (`2026-07-20-3zb0-spike-rapport.md`) : rendre le monolithe STARK witness-hiding
> par **lignes de blinding au niveau AIR**, sans fork winterfell ni migration. La
> structure du monolithe (201 colonnes, P1–P7, liaisons, padding) reste **inchangée** ;
> on ajoute une région de lignes aléatoires qui masque les ouvertures FRI/OOD.

## 1. Rappel du problème et de la voie retenue

Le monolithe 3z-a est validity-only : les ouvertures de requête (`q=32` positions × toutes
les colonnes) et le frame OOD (`z`, `z·g`, 2 évaluations/colonne — verrouillé par lecture
de `winter-verifier` `composer.rs`) révèlent des combinaisons linéaires des cellules
témoins. Les **colonnes porteuses constantes** fuient même le témoin en clair (polynôme
constant). Winterfell impose `deg(colonne) < n`, donc le blinding polynomial est exclu ;
la voie compatible = **lignes de blinding** : réserver `b ≥ q+2` lignes aléatoires en fin
de trace, gater les contraintes off dessus, garder degré `< n`. Démontré sur code réel
(`crates/zk-spike`, E2).

## 2. Modifications du monolithe

### 2.1 Croissance de la trace
`trace_len(depth) = next_pow2(used(depth) + BLIND_ROWS)` où `used(depth) = max(256,
16·depth)` (l'actuel). Profondeur 32 : `used=512`, `next_pow2(552)=1024`. Profondeur dev
4 : `used=256`, `next_pow2(296)=512`. **Région de blinding** = lignes `[used, trace_len)`
(≥ `BLIND_ROWS` lignes). Toutes les contraintes et assertions utiles vivent dans
`[0, used)` (le chemin de Merkle profondeur 32 occupe exactement `used=512`).

### 2.2 Constante `BLIND_ROWS` (dérivée, pas magique)
`BLIND_ROWS = NUM_QUERIES + NUM_OOD + MARGE = 32 + 2 + 6 = 40`.
- `NUM_QUERIES = 32` : le nombre de requêtes de `proof_options_hi`. Une **assertion de
  construction** vérifie que `BLIND_ROWS ≥ options.num_queries() + 2` (verrouille `b`
  contre un changement futur de `proof_options`).
- `NUM_OOD = 2` : frame OOD (ligne courante + suivante), confirmé dans le vérifieur.
- `MARGE = 6` : marge de sécurité (valeur du spike E2, empiriquement suffisante).

### 2.3 Sélecteur global `blind_off`
Colonne périodique `blind_off` : `1` sur toute transition `r → r+1` avec `r+1 < used`,
`0` dès qu'une transition touche `[used, trace_len)`. **Chaque famille de contraintes de
transition est multipliée par `blind_off`** — rondes clé, éponges (U/O), Merkle (M),
équilibre (bit/S/VACC), **porteuses** (`next−cur=0`), **toutes les liaisons**.
Justification du choix **global** (vs chirurgical) : impossible d'oublier une colonne —
la revue 3z-a a montré le coût des oublis de gating (3 failles de soundness). Les
assertions (`get_assertions`) sont à des lignes fixes `< used` et **ne changent pas**.

**Coût de degré — re-calibration empirique obligatoire.** `blind_off` est un facteur
périodique de longueur `n` → il ajoute une contribution de blowup `+1` à chaque
contrainte (formule winterfell `base·(n−1) + Σ(n/cᵢ)(cᵢ−1)`). Les bornes de degré
actuelles (calibrées près de blowup 16) doivent être **re-mesurées** ; si le blowup doit
monter (16 → 32), on l'accepte et le bench en rend compte. Procédure identique à 3z-a :
itérer en debug pour calibrer, déclarer des bornes supérieures, générer en `--release`.

### 2.4 Remplissage aléatoire des lignes de blinding
`build_monolith_trace` remplit les lignes `[used, trace_len)` de **toutes** les colonnes
témoins d'aléa **frais**. Réserve E2 (capitale) : **aucune** colonne témoin ne doit
rester non blindée — une seule colonne constante non blindée fuirait via son évaluation
OOD `f(z)`. Colonnes concernées : les 36 porteuses, le secret (KEY), toutes les cellules
d'éponge (U/M/O), l'accumulateur `S`, `VACC`, les bits, les frères de chemin. Les
colonnes purement publiques (nullifiers/oc/root — assertées à des lignes `< used`) n'ont
pas besoin d'aléa, mais les remplir d'aléa est inoffensif ; par simplicité on remplit
**toutes** les colonnes d'aléa sur la région de blinding.

Cas particulier des porteuses : leur contrainte `next−cur=0` gardait la constante sur
**toutes** les lignes. Gatée par `blind_off`, la constante ne tient plus que sur
`[0, used)` (là où les porteuses sont produites/consommées) ; la transition `used−1 →
used` n'est plus contrainte → la porteuse saute à l'aléa. Son polynôme n'est donc plus
constant → ouvertures masquées.

## 3. Source d'aléa (décision : OsRng frais + couture de test)
- Production : `rand` (OsRng) ajouté aux dépendances de `circuit`. `prove_tx` tire un aléa
  **système frais par preuve** → vrai witness-hiding (deux preuves du même témoin ont des
  ouvertures disjointes).
- Test : une couture interne (`build_monolith_trace_seeded(w, &mut impl Rng)` ou passage
  d'un `StdRng::seed_from_u64`) permet des traces déterministes pour les tests de
  complétude/sanité ; les tests de **masquage** utilisent au contraire deux aléas frais
  distincts pour vérifier la disjonction.

## 4. API et intégration
- `prove_tx(secret, inputs, outputs, fee, intent)` : **signature inchangée** ; échantillonne
  l'aléa de blinding en interne (OsRng). `ProvedTx` **inchangé**.
- `verify_tx(root, depth, tx)` : **inchangé** — le blinding est transparent au vérifieur
  (les lignes de blinding ne satisfont aucune contrainte, la vérification passe).
- `apply_proved_tx` (ledger) : **inchangé**.

## 5. Argument de zero-knowledge (HVZK en ROM) — à écrire
Rédigé dans le spec ET dans STARK_STATEMENT.md :
- **Cadre** : honnête-vérifieur zero-knowledge, dans le modèle de l'oracle aléatoire
  (Fiat-Shamir : les positions de requête et `z` sont dérivées de la transcription, non
  choisies par un adversaire). PAS de ZK malveillant-vérifieur. Prototype non audité.
- **Comptage** : par colonne, le vérifieur voit `q` ouvertures + 2 évaluations OOD =
  `q+2 = 34` valeurs, toutes combinaisons linéaires des `n` valeurs de la colonne dont les
  `b=40` valeurs aléatoires → système sous-déterminé (`34 < 40`).
- **Simulateur (esquisse)** : à partir des seules entrées publiques, le simulateur
  échantillonne uniformément les `q+2` valeurs révélées par colonne et bâtit une
  transcription cohérente (racines Merkle, frame OOD, ouvertures) de **même distribution**
  qu'une preuve réelle — possible précisément parce que les `b` lignes aléatoires rendent
  les valeurs révélées uniformes et indépendantes du témoin. Donc la preuve ne révèle rien
  de plus que la validité du statement.

## 6. Bascule du langage (gated sur les tests + l'argument)
Une fois les tests de masquage verts et l'argument écrit :
- Retirer l'avertissement « validity-only / ne jamais présenter comme zk » de
  `crates/circuit/src/lib.rs`, `monolith/*`, STARK_STATEMENT.md, CLAUDE.md.
- Le remplacer par : « **witness-hiding (HVZK dans le modèle de l'oracle aléatoire)** »
  avec le caveat précis (honnête-vérifieur, prototype non audité, argument non formalisé
  au niveau publication).
- Ne PAS sur-affirmer : rester « HVZK-ROM », pas « perfect ZK » ni « malicious-verifier ».

## 7. Tests
1. **Complétude** : `prove_tx`/`verify_tx` verts à profondeur dev ET consensus (roundtrip
   `#[ignore]`).
2. **Masquage (propriété zk, testable)** : parser la preuve du monolithe (comme E2), pour
   CHAQUE colonne témoin (au moins les porteuses, le secret, un échantillon d'éponge)
   confirmer qu'aucune ouverture ne vaut le témoin ; deux preuves de la MÊME tx ont des
   ouvertures disjointes. C'est le test de non-régression du witness-hiding.
3. **Soundness préservée** : toute la matrice de sabotage 3z-a + les forges white-box de
   liaison **rejettent toujours** ; test explicite que des lignes de blinding forgées
   (valeurs arbitraires) ne peuvent PAS produire une tx invalide acceptée (aucune
   assertion/contrainte ne lit `≥ used`).
4. **Non-régression e2e ledger** (`apply_proved_tx`).
5. **Re-bench** : profondeur 32, comparer à 634 ms / 1,5 ms / 85,3 Kio ; attendu ~2×
   (trace doublée) + éventuel surcoût si le blowup monte.

## 8. Risques transmis à la revue
- **Re-calibration des degrés + passage éventuel du blowup** (2.3) : le point technique
  le plus délicat ; à valider empiriquement, bornes supérieures conservatrices.
- **Soundness des lignes de blinding** (7.3) : prouver qu'aucune contrainte/assertion ne
  lit la région `[used, trace_len)` → les lignes non contraintes ne peuvent rien forger.
- **Couverture du masquage** : vérifier que TOUTE colonne témoin ouverte est blindée
  (une seule oubliée fuit) — test 7.2 exhaustif sur les colonnes.

## 9. Hors périmètre
- 3z-c (généralisation M-in/N-out) reste séparé.
- Pas de ZK malveillant-vérifieur, pas de preuve formelle niveau publication (HVZK-ROM
  argumenté suffit pour le prototype).
- Suppression de `crates/zk-spike` : NON — conservé comme banc de non-régression du
  masquage, marqué « spike ».
