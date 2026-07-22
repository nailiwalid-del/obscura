# Statement de preuve zk-STARK — v0.2

> **Phase 3 = validity d'abord ; witness-hiding livré en 3z-b1 (monolithe).**
> L'implémentation initiale du circuit prouvait l'INTÉGRITÉ (P1–P7) seulement —
> un STARK n'est pas zero-knowledge par défaut. Depuis **3z-b1**, LA preuve de
> consensus (le monolithe, `prove_tx`/`verify_tx`) est **witness-hiding (HVZK
> dans le modèle de l'oracle aléatoire)** par lignes de blinding — voir l'entrée
> 3z-b1 du journal et la section « Witness-hiding du monolithe — argument HVZK »
> ci-dessous. Caveat : honnête-vérifieur, prototype non audité, argument non
> formalisé au niveau publication. Les gadgets AUTONOMES du crate circuit
> (sponge, balance, spend, … — hors chemin de consensus) restent validity-only.
> Historique de la décision :
> `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md`.
>
> **3a2 (fait) :** premier AIR = la **permutation** Rp64_256 (`crates/circuit`,
> `prove`/`verify`), validée par différentiel contre le vecteur de référence Sage.
> Note : sur Goldilocks (64 bits), l'extension de corps **quadratique** est
> obligatoire — sans elle la sécurité conjecturée plafonne à ~63 bits.
>
> **3a2b (fait) — P2 EST PROUVÉ EN CIRCUIT** : `owner = H_owner(shielded_secret)`
> (`circuit::{prove_owner, verify_owner}`). Le sponge de `hash_elements` n'utilise
> aucun padding (la longueur est injectée dans la capacité) et le préambule 3a0 fait
> exactement un bloc de rate → P2 = **une** permutation. Le `shielded_secret` reste
> témoin : **aucune assertion ne le référence**. Différentiel vert contre
> `proved_hash::rescue::hash` (le hash du ledger).
>
> **3b1 (fait) — sponge MULTI-BLOC généralisé** (`circuit::sponge`) : `prove_sponge`
> prouve `digest = H_domain(payload)` pour un payload arbitraire (cycle 8 = 7 rondes
> + 1 absorption additive, masque `round_flag`). Instances : `prove_nk` (P4, B=1),
> `prove_nullifier` (P3, B=2). Différentiels verts (B=1/2/4). Précondition `B*8`
> puissance de 2 (padding B=3 → 3b4). Positions publiques du payload assertées,
> témoins jamais assertés.
>
> **3b2a (fait) — gadget d'UN niveau de Merkle** (`circuit::merkle_level`) : swap
> conditionnel in-circuit `(gauche, droite) = bit==0 ? (courant, frère) : (frère,
> courant)` + `merge` (sponge B=2). Bit **booléen** contraint ; `courant`/`frère`/`bit`
> en colonnes témoins constantes ; swap réparti ligne 0 / ligne 7 via flags d'init.
> Différentiel vert vs `proved_hash::merkle::node` (les deux bits).
>
> **3b2b intermédiaire (fait) — CHAÎNAGE inter-blocs** (`circuit::merkle_path`) :
> `prove_merkle_path(leaf, path, index)` prouve `root = fold(leaf, path, index)` en
> chaînant D merges (sortie niveau k = `cur` niveau k+1 ; sponge désactivé aux
> frontières par un flag `chain` ; bit variable par niveau). Différentiel vert vs
> `proved_hash::merkle::fold` (D=2, 4 index) + test négatif. **⚠️ preuves à générer
> en `--release`** : le `debug_assert` de degrés de winterfell est input-dépendant
> (colonnes témoins constantes) → on déclare des bornes supérieures (`déclaré ≥
> mesuré`, soundness préservée), l'assert debug étant ignoré en release ; tests
> `#[ignore]` en debug.
>
> **3b2c (fait) — P1 PROUVÉ (par composition), profondeur 32** (`circuit::membership`) :
> `prove_membership(cm, path, index)` compose la preuve du hash de feuille
> (`H_MerkleLeaf(cm)`, sponge B=1) et la preuve de chaînage (`merkle_path`), liées par
> un `leaf_digest` PUBLIC partagé. `verify_membership` vérifie les deux. Différentiel
> vert vs `proved_hash::merkle::root` à profondeur **2 ET 32** (trace chemin = 512),
> + négatif. **P1 (appartenance à l'arbre) est donc prouvable en circuit à la
> profondeur consensus.** Limite assumée : `leaf_digest` public (non privé) — la
> version monolithique privée (leaf_digest témoin, P1 fondu avec P2–P7 et lié à
> tx_digest) est le circuit complet de 3b5.
>
> **3b3a (fait) — range-check** (`circuit::range_check`, P6) : `prove_range(v)` prouve
> `0 ≤ v < 2^RANGE_BITS` par décomposition binaire accumulée (colonne `acc`, colonne
> compteur `idx` pour non-dégénérescence). **`RANGE_BITS = 60`** (raffinement assumé
> du « [0,2^64) » : sur Goldilocks `p≈2^64`, un range 2^64 est vide et l'équilibre en
> corps wrappe ; borner à 2^60 garde chaque côté `< p` — `Σ < 8·2^60 = 2^63 < p` pour
> ≤ 8 termes/côté ; borne stricte ~15/côté, `16·2^60 = 2^64 > p` donc PAS 16). Testé en `--release`
> (positif + hors-range rejeté).
>
> **3b3b (fait) — ÉQUILIBRE P5 PROUVÉ EN CIRCUIT** (`circuit::balance`) :
> `prove_balance(inputs, outputs, fee)` prouve `Σin = Σout + fee` **en addition de
> corps**, sur des montants TÉMOINS. AIR unique : chaque montant occupe un bloc de 64
> lignes de bits ; la colonne périodique `pow` (`2^i`, i<60, puis 0) **remet le poids
> à zéro à chaque bloc**, ce qui borne AUTOMATIQUEMENT chaque montant à `< 2^60`
> (range-check P6 embarqué, gratuit) ; un accumulateur `S` fait la somme SIGNÉE
> (`+1` entrée / `−1` sortie), `S[0]=0`, assertion finale `S = fee`. Signes publics
> assertés par bloc (structure n_in/n_out engagée). Soundness : `≤ 8` entrées ×
> `2^60 < p` → aucun wrap ne masque un déséquilibre. Précondition `n_in+n_out`
> puissance de 2 (padding = sorties de valeur 0). Différentiels verts : équilibres
> honnêtes (avec/sans fee, montants ≈ 2^59) acceptés, déséquilibre et fee falsifié
> rejetés. Montants non révélés ici (témoins), mais preuve non witness-hiding ; la
> liaison bits↔commitments est le monolithe 3b5. À générer en `--release`.
>
> **3b4 (fait) — COMMITMENT DE NOTE P7 PROUVÉ EN CIRCUIT** (`circuit::prove_note_commitment`) :
> `cm = H_NoteCommitment(value ‖ owner ‖ rho ‖ r)` (payload 13 Felts, note
> ENTIÈREMENT témoin, seul `cm` public). **Premier usage du padding PAD_ZERO\*** (le
> B=3 repoussé depuis 3b1) : le préambule logique fait 17 éléments (3 blocs) ; il est
> complété par des zéros jusqu'à un nombre de blocs PUISSANCE DE 2 (4 blocs = 32),
> exigence de la longueur de trace STARK. `absorbed_len` centralise la règle et est
> un NO-OP pour tous les hachages déjà alignés (owner/nk B=1, nullifier/merge B=2) →
> golden vectors 3a1 INCHANGÉS. La capacité du sponge = longueur absorbée (32),
> injective car `LEN=13` figure dans le préambule ; le PAD_ONE reste à sa position
> logique (index 16, découplé de `capacité−1`). Différentiel vert vs
> `proved_hash::note_commitment` (déterministe, hiding via `r`, binding) + cm altéré
> rejeté. Le sponge n'ayant pas de colonne témoin constante, la preuve tourne en
> DEBUG (contrairement aux gadgets gatés). **P7 prouvable en circuit.**
>
> **3b5a (fait) — PREUVE DE CLÉ : P2 ∧ P4 LIÉS PAR UN SECRET PARTAGÉ**
> (`circuit::{prove_key, verify_key}`) : `owner = H_owner(s) ∧ nk = H_nk(s)` pour LE
> MÊME `shielded_secret` s, dans **une seule trace**. Première tranche de l'assemblage
> 3b5 (circuits d'action). **Raison d'être** : la composition de `prove_owner` +
> `prove_nk` séparés ne force PAS `s₁ = s₂` (témoins indépendants) et publier `s` est
> exclu (secret maître) → la liaison « même s » n'est sound que dans une trace
> partagée. Disposition : deux éponges B=1 côte à côte (owner cols `0..12`, nk cols
> `12..24`, longueur 8, mêmes ARK périodiques), tags de domaine distincts. **Contrainte
> de liaison** gatée à la ligne 0 : `owner_state[7+k] − nk_state[19+k] = 0` (k<4) — les
> 4 cellules du secret coïncident ; aucune n'est assertée à une valeur publique
> (`s` reste témoin). Différentiel vert vs `rescue::hash(Owner/Nk, s)`, non-régression
> vs preuves isolées, owner/nk altérés rejetés. **Test de liaison white-box (release)**
> : une trace où owner vient de `s` et nk de `s'≠s` est REJETÉE — la contrainte mord.
> Le sponge évoluant, la preuve tourne en DEBUG. **Prochaines** : 3b5b Spend
> (P1+P3+P6+P7ᵢₙ), 3b5c Output (P6+P7), 3b5d Bundle (câblage public + équilibre +
> `tx_digest`).
>
> **3b5b (fait) — BUNDLE DE DÉPENSE (Spend) PAR COMPOSITION** (`circuit::{prove_spend,
> verify_spend}`) : pour UNE note d'entrée, établit **P7ᵢₙ ∧ P1 ∧ P3 ∧ P6** en
> composant les preuves déjà bâties (commitment, membership, nullifier, range), liées
> par des valeurs PUBLIQUES partagées (`cm_in`, `value`, `rho`, plus `owner`/`nk` du
> statement). **Décision d'archi (AskUserQuestion) : composition liée, PAS de
> mini-monolithe** — un STARK validity-only n'est pas witness-hiding (il fuit ses
> témoins), donc garder `cm_in` hors des entrées publiques ne le cache pas ;
> l'unlinkability + le circuit fusionné rejoignent la Phase 3z. Le seul témoin
> devant rester caché ET partagé (le secret maître) est déjà lié en trace unique par
> 3b5a. Mécanique : chaque sous-preuve EXPOSE ses positions partagées
> (`prove_sponge(..., public_idx)`), `verify_spend` passe la même valeur partout ;
> l'appartenance est liée au `cm_in` public via `leaf == merkle::leaf(cm_in)` recalculé.
> Différentiels verts (cm_in/nf/root vs `proved_hash`), owner/nk/racine erronés et
> `cm_in` falsifié rejetés. **Prochaines** : 3b5c Output, 3b5d Bundle 2-in/2-out +
> équilibre natif + `tx_digest`.
>
> **3b5c (fait) — BUNDLE DE SORTIE (Output)** (`circuit::{prove_output,
> verify_output}`) : simplification stricte de Spend pour une note de SORTIE —
> seulement **P7 ∧ P6** (`oc = H_NoteCommitment(...)`, `value < 2^60`). `oc`/`value`
> publics ; `owner`/`rho`/`r` du destinataire restent témoins (aucun lien externe).
> Commitment exposant `value` (idx 0) + range. Différentiel vert vs `note_commitment`,
> valeur fausse et `oc` falsifié rejetés. **Reste 3b5d** : Bundle 2-in/2-out
> (`prove_key` + 2 Spend + 2 Output + équilibre natif sur montants publics +
> `tx_digest`).
>
> **3b5d (fait) — TRANSACTION PROUVÉE `ProvedTx` : LE VALIDATEUR COMPLET**
> (`circuit::{prove_tx, verify_tx, ProvedTx, ProvedInput}`) : assemble `prove_key`
> (P2∧P4) + 2 `prove_spend` (P1+P3+P6+P7ᵢₙ) + 2 `prove_output` (P7+P6) + **équilibre
> P5 natif** (`Σin = Σout + fee` sur montants publics) + **`tx_digest`** (dual_hash
> BLAKE3‖SHA3 sur l'encodage canonique de toutes les données publiques = non-rejeu).
> `verify_tx(root, depth, tx)` établit ainsi **P1–P7 pour la transaction 2-in/2-out
> entière**, avec `owner`/`nk` de la clé LIÉS à chaque dépense et une racine commune.
> Tests (`--release`, arbre profondeur 2) : tx valide acceptée + matrice de sabotage
> (déséquilibre, nk falsifié, output_commitment falsifié, tx_digest falsifié, racine
> erronée) toute rejetée. **L'ASSEMBLAGE VALIDITY-ONLY DE LA PHASE 3 EST COMPLET.**
>
> **3c (fait) — INTÉGRATION LEDGER : `apply_proved_tx` EST LA RÈGLE DE CONSENSUS**
> (`proved_hash::merkle::ProvedMerkleTree` + `ledger::proved_state::ProvedLedgerState`).
> Arbre de Merkle Rescue INCRÉMENTAL (append/root/path) dont les chemins sont
> compatibles circuit (`merkle::root(cm, tree.path(i), i) == tree.root()`).
> `apply_proved_tx(tx)` : anchor récent → `circuit::verify_tx` (P1–P7 + non-rejeu) →
> nullifiers non dépensés → dépense atomique + insertion des sorties. Tests
> (`--release`) : tx prouvée appliquée (nullifiers dépensés, 2 sorties insérées),
> double-dépense/anchor inconnu/preuve falsifiée rejetés. `ProvedTx` porte désormais
> son `anchor`. **Le mode transparent de dev n'est plus la seule voie : le circuit
> STARK gouverne un vrai état de ledger.** Reste : signature hybride d'intention sur
> `tx_digest` (côté ledger).
>
> **3d (fait) — BENCH d'une `ProvedTx` 2-in/2-out à profondeur 32**
> (`circuit/examples/tx_bench.rs`, `cargo run --release --example tx_bench -p circuit`).
> Mesures indicatives (une machine dev) : **génération ≈ 225 ms**, **vérification ≈
> 2,6 ms**, **taille de preuve ≈ 219 Kio** (15 STARK séparés : 1 clé + 2 dépenses×5 +
> 2 sorties×2). Enseignement pour 3z : la vérification est très rapide et la génération
> raisonnable, mais la TAILLE (~219 Kio) est dominée par la NON-agrégation des 15
> preuves → l'agrégation/récursion ou un monolithe (Phase 3z) est le levier de
> compression, PAS le temps. **Remplacé par 3z-a** : l'assemblage v1 mesuré ici
> (15 preuves séparées) est supprimé ; voir les chiffres du monolithe ci-dessous.
>
> **Signature d'intention (fait) — enveloppe anti-malléabilité** : `ProvedTx` porte
> une clé publique d'intention `signer` (hybride Ed25519+Dilithium3) et une signature
> `intent_sig` sur `tx_digest`. Le `signer` est **lié dans `tx_digest`** → il ne peut
> pas être échangé sans invalider la preuve. `prove_tx` prend un `SigKeypair`
> d'intention et signe ; `apply_proved_tx` vérifie la signature (`InvalidSignature`).
> Ce n'est PAS l'autorité d'ownership (établie par P2) mais une enveloppe d'intention.
> Tests : signature d'une autre clé rejetée, signataire échangé rejeté (via le digest).
>
> **3z-a (fait) — MONOLITHE PRIVÉ : P1–P7 EN UNE SEULE TRACE** (`circuit::monolith`,
> `circuit::tx::{prove_tx, verify_tx}` v2) : remplace l'assemblage v1 (3b5d, 15
> preuves composées) par UNE SEULE preuve STARK. **Le statement lui-même force une
> trace unique** : owner/nk (P2∧P4), les deux dépenses empilées (P7ᵢₙ → feuille →
> nullifier P3, chemin Merkle P1) et les deux sorties (P7) sont liés par **36
> colonnes porteuses constantes** (owner, nk, rho×2, cm×2, leaf×2, vin×2, vout×2)
> avec égalités gatées entre segments, plus l'équilibre P5/P6 natif (3 colonnes,
> accumulateur signé). Layout : **201 colonnes × 512 lignes** (profondeur 32 ; 165
> colonnes de segments + 36 porteuses, sous la limite winterfell). **Publics
> réduits au minimum du statement v2** : `root`, `nullifiers[2]`,
> `output_commitments[2]`, `fee` (+ `depth` technique) — plus aucun `owner`/`nk`
> publiés, plus aucune sous-preuve à assembler séparément ; le témoin (notes,
> chemins de Merkle, `shielded_secret`, `nk`) reste privé. `tx_digest` v2 =
> `dual_hash("obscura/proved-tx/v2", root‖nf₁‖nf₂‖oc₁‖oc₂‖fee‖signer)` ; enveloppe
> d'intention inchangée sur le nouveau domaine `obscura/proved-tx-intent/v2`.
> `ProvedTx` v2 = `{ anchor, proof, nullifiers, output_commitments, fee, signer,
> tx_digest, intent_sig }` — UNE seule `ValidityProof`. **Bench réel (profondeur
> 32, une machine dev)** : génération ≈ **634 ms**, vérification ≈ **1,5 ms**,
> taille de preuve ≈ **85,3 Kio** (vs ≈219 Kio/15 preuves en v1, **−61 %**) —
> remplace les chiffres 3d, désormais caducs (mesure de l'assemblage v1 supprimé).
> Taille dominée par l'ouverture des 201 colonnes de trace aux 32 requêtes FRI
> (structurel pour ce layout) ; leviers de réduction futurs : empilement accru des
> colonnes (3z-c), grinding FRI. Tests : différentiels par famille, matrice de
> sabotage (déséquilibre, nk/owner falsifié, cm@feuille ET cm@47 anti-double-
> dépense, feuille↔chemin, VIN/VOUT isolés), white-box par porteuse, e2e ledger,
> roundtrip consensus `#[ignore]`. **⚠️ Validity-only à ce stade (avertissement
> levé par 3z-b1, voir ci-dessous)** : ce monolithe réduisait drastiquement ce
> qui est PUBLIÉ, mais ne rendait PAS la preuve elle-même witness-hiding
> (winterfell 0.13.1 confirmé sans support zk natif) — les requêtes de trace
> pouvaient encore fuiter des cellules témoins. La voie du witness-hiding a été
> tranchée par le spike 3z-b0 (Voie A, lignes de blinding — ni fork winterfell ni
> migration, `2026-07-20-3zb0-spike-rapport.md`) puis livrée en 3z-b1.
>
> **3z-b1 (fait) — WITNESS-HIDING DU MONOLITHE : LIGNES DE BLINDING AU NIVEAU
> AIR** (`circuit::monolith`, voie du spike 3z-b0) : la preuve monolithique est
> désormais **witness-hiding (HVZK dans le modèle de l'oracle aléatoire)**.
> Mécanique : trace étendue à `next_pow2(used_rows(depth) + BLIND_ROWS)`
> (profondeur 32 : 512 → **1024 lignes**), région de blinding `[used, trace_len)`
> remplie d'aléa système **frais par preuve** (OsRng) dans TOUTES les colonnes
> témoins, et **gating global** : chaque contrainte de transition est multipliée
> par le sélecteur périodique `blind_off` (0 dès qu'une transition touche la
> région de blinding). `BLIND_ROWS = 40 ≥ q(32) + OOD(2) + marge(6)`, verrouillé
> par une assertion de construction contre tout changement de `proof_options`.
> Les porteuses ne sont plus des polynômes constants (elles sautent vers l'aléa
> à la ligne `used`) → leurs ouvertures ne valent plus le témoin en clair. API
> inchangée (`prove_tx`/`verify_tx`/`ProvedTx`, blinding transparent au
> vérifieur). Argument de sécurité : section « Witness-hiding du monolithe —
> argument HVZK » ci-dessous (comptage par colonne de trace `q+2 = 34 < b = 40`
> + argument de taille de la région de blinding pour composition/FRI, esquisse
> de simulateur). Tests : complétude (profondeur 2 et 32), masquage exhaustif par
> colonne témoin + ouvertures DISJOINTES de deux preuves de la même tx,
> soundness préservée (matrice de sabotage 3z-a + inertie des lignes de blinding
> forgées), fraîcheur OsRng. **Bench réel (profondeur 32, une machine dev)** :
> génération ≈ **1477,7 ms** (×2,33), vérification ≈ **3,0 ms** (×1,98), taille
> ≈ **90,5 Kio** (×1,06) vs 3z-a (634 ms / 1,5 ms / 85,3 Kio, caducs) — coût
> dominé par le doublement de trace, taille quasi inchangée. **Caveat** : HVZK
> honnête-vérifieur en ROM, PAS de malicious-verifier ZK ni de « perfect ZK » ;
> prototype non audité, argument non formalisé au niveau publication. Les
> gadgets autonomes (`sponge`, `balance`, `spend`, …) et le banc `crates/zk-spike`
> restent validity-only.
>
> **ProvedTx v3 — enc_notes portés + liés (fait)** : les enveloppes chiffrées
> des sorties voyagent dans `ProvedTx` et sont liées dans `tx_digest` v3
> (anti-substitution passive) ; scan wallet via `ledger::proved_wallet`. Détails,
> portée exacte et limite du relais actif : section « Cohérence commitment ↔
> note chiffrée (P8, différé) » ci-dessous.
>
> **Durcissement pré-testnet #7 — sérialisation canonique de `ProvedTx` (fait)** :
> `ProvedTx::{to_bytes, from_bytes}` (`circuit::tx`), encodage wire **injectif**
> (digests 32 o, `fee` u64 LE, longueurs `u32` LE préfixées pour le variable).
> `from_bytes → Result<_, TxDecodeError>` est LE point d'entrée réseau qui
> VALIDE : curseur borné (aucune panique sur entrée arbitraire), digests
> canoniques, bornes `EncNote` (anti-DoS au parse, avant toute allocation
> coûteuse), rejet des octets résiduels (canonicité : une seule sérialisation
> valide par tx). Pas de `serde` (il ne garantit pas l'injectivité/canonicité).
> Tests : roundtrip réel (`--release`) + matrice de rejet (tronqué, résiduel,
> digest non canonique, enc_note hors bornes, preuve corrompue). Spec :
> `docs/superpowers/specs/2026-07-20-provedtx-serialisation-design.md`.
>
> **Durcissement pré-testnet #7 — zeroize + audit panic + Merkle frontier (faits)** :
> `zeroize` des secrets au drop (`ShieldedSecret` écriture volatile non élidable,
> `WalletKeys`, clés AEAD dérivées ; moitiés dalek OK, trou pqcrypto Kyber/Dilithium
> documenté à fermer en FIPS 0x02). Audit `panic→Result` de la surface réseau :
> `from_bytes`/`verify_tx`/`scan_proved_output`/`apply_proved_tx` sans panique sur
> entrée attaquant. **Merkle frontier** (`proved_hash::MerkleFrontier`) : l'arbre du
> nœud est append-only et ne garde que le bord droit — `append`/`root` en O(depth),
> mémoire bornée, `TreeFull` en `Result` (plus de panique « arbre plein »). Racine
> IDENTIQUE à `ProvedMerkleTree` (test différentiel à chaque étape, depth 16 ET 32)
> → preuves `circuit::membership` inchangées ; les CHEMINS restent produits côté
> wallet (`ProvedMerkleTree`). **Persistance disque** (`ProvedLedgerState::{to_bytes,
> from_bytes, save, load}`) : dump canonique de l'état consensus (frontier ‖
> nullifiers triés ‖ fenêtre de racines FIFO), décodage borné, écriture ATOMIQUE
> (`tmp` + `rename`) → un nœud survit au redémarrage. Specs :
> `2026-07-20-zeroize-secrets-design.md`, `2026-07-20-merkle-frontier-design.md`,
> `2026-07-20-state-persistence-design.md`. #7 bouclé pour la phase 3 ; ne reste que
> le test key-privacy IK-CCA (phase 4).
>
> **3z-c1 — monolithe SEGMENTÉ livré (bascule faite)** : la trace n'est plus un
> côte-à-côte de colonnes parallèles par entrée/sortie, mais une **suite de
> segments séquentiels de lignes** partageant les mêmes colonnes —
> `[KEY][IN0][IN1][OUT0][OUT1]` puis le blinding (`monolith/seg_{layout,trace,
> air}.rs`). Les unités ne sont plus distinguées par la COLONNE mais par le
> SEGMENT : les familles de contraintes fusionnent (éponges 4×12 → 12, chemins
> 2×30 → 30, soit **209 slots au lieu de 263**) et chaque liaison reçoit un
> sélecteur mono-ligne ancré à `seg_start(i) + ancre`.
>
> **Mesure à la profondeur consensus** (même témoin, publics assertés identiques) :
> largeur **92 au lieu de 201**, trace 2048 au lieu de 1024, preuve **67,9 Kio au
> lieu de 89,3 (−24 %)**, génération ×1,41, vérification ×1,46 (4,1 ms). La
> question laissée ouverte par le design — « la largeur ÷2,2 compense-t-elle la
> longueur ×2 ? » — est donc tranchée : **oui**. Le compromis est favorable pour
> une monnaie, la taille étant le coût PERMANENT payé par chaque nœud qui stocke
> et relaie chaque transaction.
>
> **Parité** : `prove_tx`/`verify_tx`/`ProvedTx` v3 et l'API ledger sont
> INCHANGÉS ; tous les tests préexistants passent sans modification. Le monolithe
> côte-à-côte est conservé pour faire tourner l'**oracle de parité** (mêmes
> publics pour le même témoin) — non-régression contre une implémentation
> indépendante — et sera supprimé avec 3z-c2.
>
> **Soundness et masquage re-vérifiés sous segments** : liaisons owner/nk/rho/cm/
> feuille/montants, padding `PAD_ZERO*`, inertie du blinding, et une liaison
> NOUVELLE — voir « Liaison de racine » ci-dessous. Masquage des porteuses re-testé
> (RED vérifié : sans blinding, une ouverture FRI vaut `OWNER_C` en clair).
>
>
> **3z-c2 — VARIABILITÉ M-in/N-out LIVRÉE** : le circuit accepte `1..=MAX_IN`
> entrées et `1..=MAX_OUT` sorties (`MAX = 4`). La forme (m, n) est une `Forme`
> validée, la trace/AIR la dérivent, et le NOMBRE de contraintes varie avec elle
> (prouveur et vérifieur la construisent des MÊMES publics, donc s'accordent). La
> forme est **portée par les longueurs** des publics et **préfixée dans
> Fiat-Shamir** (`to_elements`) : sans ce préfixe, deux découpages des mêmes
> digests donneraient la même graine et une preuve (m=1, n=3) serait rejouable en
> (m=2, n=2). Robustesse : l'AIR dérive sa forme de la LARGEUR de trace commise
> (bijective avec (m, n)), jamais des publics — une forme mentie ne provoque pas
> d'accès hors cadre, elle est rejetée par Fiat-Shamir.
>
> Soundness sous forme variable (C2-T4) — trois garanties que la variabilité aurait
> pu supprimer, chacune avec forge RED : (D7.1) la forme est liée (re-présenter une
> preuve 2/2 en 1/3 est rejeté) ; (D7.2) l'équilibre `S = fee` est scellé à
> `used_rows(m, n)−1`, ligne dépendante de la forme ; (D7.3) chaque public est lié à
> SON segment, position par position. Masquage re-vérifié sur 1/1 et 4/4 (le gating
> `blind_off` couvre toute porteuse nouvelle sans liste manuelle). `ProvedTx` **v4**
> porte des Vec bornés, comptes préfixés au wire ET dans `tx_digest`, bornés avant
> allocation. Le wallet exploite la variabilité : une note UNIQUE paie (1-in/2-out),
> `consolider` regroupe (M-in/1-out), et 2/2 reste le défaut de VIE PRIVÉE (la forme
> est publique — cf. THREAT_MODEL).
>
> **Re-bench profondeur 32** (par forme) : 1/1 → 55,7 Kio / 1,6 ms ; 1/2 → 55,9 Kio ;
> 2/2 → 67,7 Kio / 3,8 ms (inchangé, non-régression) ; 4/4 → 80,3 Kio / 12,6 ms. La
> taille croît doucement avec la forme, la vérification reste sous 13 ms au pire cas.
>
> **C2-T8 — le côte-à-côte est SUPPRIMÉ** : `monolith/{air,layout,trace}.rs`
> (~2 600 lignes) sont effacés. Ce que les deux implémentations PARTAGEAIENT — la
> construction cryptographique : `MonolithPublicInputs` (+ Fiat-Shamir),
> `push_preamble`, `key_rows`/`sponge_rows_for`/`read_digest`, le témoin 2/2 et
> les témoins de test — vit désormais dans `monolith/socle.rs`, module SANS layout
> (pas un offset de colonne). Extraction = pur DÉPLACEMENT : pas un octet de
> comportement ne change (Fiat-Shamir inchangé, suite verte sans modification des
> attentes). L'oracle de parité et le bench segmenté-vs-côte-à-côte partent avec
> lui (leur objet est atteint ; `mesure_formes` reste le bench vivant). Les formes
> libres 2/2 de `seg_layout` (`RHO_C…`, `schedule_2in2out`, `seg_start`,
> `used_rows`, `trace_len`, `N_SEGMENTS`) passent en `#[cfg(test)]` : ce ne sont
> plus des sursis de bascule mais des **épingles de consensus** — la 2/2 est la
> forme par défaut du wallet, des preuves existantes s'y vérifient, et
> `forme_2_2_identique_aux_constantes` interdit à un refactor de `Forme` d'en
> déplacer un offset en silence.
>
> **D8 — forges à reconstruction d'arbre à la profondeur CONSENSUS (soldée)** :
> `build_tree_from_leaves` est généralisé en profondeur (cœur de 4 feuilles aux
> index 0/3, un frère muet par niveau au-dessus — pas besoin de matérialiser
> 2^32 feuilles), et les cinq forges à reconstruction (OwnerConsomme,
> RhoCommitment, CmFeuille, LeafChemin, PaddingCommitment) sont rejouées RED à
> la profondeur 32 (`forges_a_reconstruction_rejetees_a_la_profondeur_consensus`,
> avec contrôle honnête sur le même témoin). C'est à cette profondeur que le
> chemin de Merkle domine la trace (512 lignes par entrée sur 1168) — une liaison
> qui n'aurait mordu qu'aux petites profondeurs était invisible de tous les tests.
> Les forges restent 2/2 en FORME (assertion explicite, pas un silence).

**Ce statement EST la règle de consensus d'une dépense valide.** Tout le reste du
protocole s'organise autour de lui. Le mode transparent actuel (`apply_transparent`)
n'est qu'un échafaudage de développement et ne définit pas la validité.

## Statement

```
Entrées PUBLIQUES :
  root                  racine de l'arbre des commitments (récente)
  nullifiers[]          un par note dépensée
  output_commitments[]  un par note créée
  fee                   frais (u64, en clair ; borné < 2^60, vérifié par verify_tx)
  tx_digest             digest canonique de la transaction (lie preuve ↔ tx)

Témoins PRIVÉS :
  notes d'entrée        (value, owner, rho, r)
  chemins de Merkle     un par note d'entrée
  shielded_secret       secret racine shielded, jamais publié
  nk                    intermédiaire privé contraint par nk = H_nk(shielded_secret)
  notes de sortie       (value, owner, rho, r)

La preuve établit :
  P1. chaque commitment d'entrée appartient à l'arbre de racine `root`
  P2. pour chaque note d'entrée : note.owner = H_owner(shielded_secret)   (autorité de dépense)
  P3. chaque nullifier est correctement dérivé : nf = PRF_nk(rho ‖ commitment)
  P4. nk = H_nk(shielded_secret)   (nk contrainte par le même secret racine)
  P5. Σ valeurs d'entrée = Σ valeurs de sortie + fee
  P6. toutes les valeurs sont range-checkées dans [0, 2^60)   (RANGE_BITS = 60 : sur
      Goldilocks p ≈ 2^64, borner à 2^60 garde chaque côté de l'équilibre < p,
      cf. 3b3a ci-dessus — pas d'overflow/underflow ni de wrap en corps)
  P7. chaque output_commitment est l'engagement correct de sa note de sortie
```

La preuve est vérifiée contre `tx_digest` en entrée publique : elle est liée à CETTE
transaction (non-malléabilité, pas de rejeu de preuve sur une autre tx).

### Liaison de racine — une propriété que la segmentation a rendue NÉCESSAIRE (3z-c1)

Dans le monolithe côte-à-côte, la racine `root` était assertée **publiquement sur
CHAQUE chemin de Merkle** : deux entrées prouvant contre des racines différentes
étaient structurellement impossibles, sans qu'aucune contrainte ait à l'interdire.

La segmentation mutualise les colonnes du chemin entre les entrées, et `root`
devient une **porteuse assertée une seule fois**. Cette économie ouvre un trou : un
prouveur pourrait dépenser une note appartenant à un arbre **et** une note
appartenant à un **autre** arbre dans la même transaction, chaque chemin étant
valide isolément — de l'inflation inter-arbres.

Le statement exige donc explicitement, pour chaque entrée `i` :

> la racine repliée du chemin de `i` **est égale à la porteuse `ROOT_C`**, elle-même
> assertée égale à la racine publique.

C'est la contrepartie obligatoire du gain de slots. Elle est vérifiée par une forge
dédiée dont le caractère RED est établi : liaison neutralisée, une transaction à
deux racines distinctes est **acceptée** ; liaison rétablie, elle est rejetée.

Leçon générale, à garder pour 3z-c2 : **mutualiser des colonnes peut supprimer une
garantie que la redondance offrait gratuitement.** Chaque fusion doit être auditée
sous cet angle, pas seulement pour son gain de taille.

## Ce que le statement supprime par rapport au mode transparent

- `spend_pk` n'est plus publié → les dépenses d'une même clé ne sont plus reliables (point 5 de la revue).
- Le chemin de Merkle n'est plus révélé → on ne sait plus QUEL commitment est dépensé.
- Le consensus vérifie enfin ce qu'il ne pouvait pas vérifier : liaison nullifier↔note
  existante, autorité de dépense, équilibre des montants (point 1 de la revue).

## Witness-hiding du monolithe — argument HVZK (3z-b1)

Depuis 3z-b1, la preuve monolithique (`prove_tx`/`verify_tx`) est revendiquée
**witness-hiding**, au sens précis suivant : **zero-knowledge à vérifieur
honnête (HVZK) dans le modèle de l'oracle aléatoire (ROM)** — et rien de plus.

### Cadre exact de la revendication

- **Non-interactif via Fiat-Shamir** : winterfell dérive tous les défis du
  vérifieur — le point hors-domaine `z` et les positions des `q` requêtes FRI —
  du TRANSCRIPT (hachages des engagements), modélisé comme un oracle aléatoire.
  Les points d'évaluation révélés sont donc distribués uniformément et ne sont
  PAS choisis par un adversaire : c'est exactement le cadre « honnête-vérifieur ».
  Aucune revendication n'est faite contre un vérifieur malveillant qui choisirait
  ses défis (malicious-verifier ZK), et il ne s'agit PAS de « perfect ZK ».
- **Argument, pas preuve formelle** : ce qui suit est un argument en deux
  étages (comptage exact par colonne de trace + heuristique de taille de la
  région de blinding) plus une esquisse de simulateur (style « randomized
  AIR », ethSTARK) — suffisant pour un prototype, non formalisé au niveau
  publication.
- **Prototype non audité**, comme tout Obscura.

### Ce que la preuve révèle (périmètre exact, winter-verifier 0.13.1)

La preuve révèle trois familles de valeurs — TOUTES fonctions déterministes de
la trace COMMITTÉE COMPLÈTE, laquelle inclut la région de blinding :

- **Colonnes de trace** : chaque colonne est un polynôme `f` de degré `< n`
  (`n = trace_len`) interpolant ses `n` cellules sur le domaine de trace `H`.
  Par colonne : `q = 32` **ouvertures de requête** `f(xᵢ)` aux positions
  requêtées du domaine LDE (chaque requête ouvre UNE ligne entière — toutes les
  colonnes) et `2` **évaluations OOD** `f(z)`, `f(z·g)` — soit `q + 2 = 34`
  évaluations, combinaisons linéaires à coefficients PUBLICS (dépendant du seul
  point d'évaluation) des `n` cellules, aux points hors de `H`. Précision
  base-field : `z` vit dans l'extension quadratique, chaque évaluation OOD
  compte donc pour 2 équations sur le corps de base — `32 + 4 = 36` équations
  base-field par colonne.
- **Colonnes de composition/quotient** : le vérifieur LIT dans la preuve les
  ouvertures des colonnes du polynôme de composition aux mêmes positions de
  requête, contre un commitment de contraintes SÉPARÉ
  (`winter-verifier/src/lib.rs`, `read_constraint_evaluations`), plus leur
  frame OOD en `z`. Ce sont des valeurs révélées EN PLUS — fonctions
  déterministes NON LINÉAIRES de la trace complète (via les contraintes), PAS
  recalculables depuis les 34 évaluations de trace (c'est précisément pourquoi
  ce commitment séparé existe).
- **FRI** : chaque couche de repli ouvre des cosets aux positions dérivées, et
  le polynôme de RESTE (degré ≤ 127) est révélé EN ENTIER — autant de valeurs
  dérivées du polynôme DEEP, donc de la trace committée. (C'est la surface qui
  motive le salage de FRI dans ethSTARK ; winterfell ne sale pas FRI.)

### L'argument, en deux étages

**Étage 1 — comptage exact, par colonne de trace.** Chaque colonne témoin porte
`b = BLIND_ROWS = 40` cellules d'aléa uniforme **frais par preuve** (région de
blinding `[used, trace_len)`, OsRng), avec `b = q + 2 + 6 ≥ q + 2` verrouillé
par une assertion de construction contre tout changement de `proof_options`.
Ces cellules sont LIBRES : aucune contrainte de transition ne les lie (gating
global `blind_off`) et aucune assertion ne vise une ligne `≥ used` (inertie
testée white-box).

Les 34 évaluations révélées d'une colonne sont des fonctions AFFINES de ses 40
cellules d'aléa (les cellules utiles — le témoin — fixent le terme constant,
l'aléa fait le reste). Retrouver le témoin exigerait de résoudre 34 équations
(36 sur le corps de base) à 40 inconnues uniformes indépendantes : le système
est **sous-déterminé** (`34 < 40`). Plus précisément, dès que la matrice 34×40
des coefficients (évaluations des polynômes de Lagrange des positions de
blinding aux 34 points révélés) est de rang plein 34, le vecteur des 34
évaluations révélées est **uniforme et indépendant des cellules utiles** — pour
tout témoin, la distribution des valeurs révélées est identique. Les 34 points
étant distincts, hors de `H` et dérivés de l'oracle aléatoire (donc uniformes,
non adverses), un défaut de rang est un événement négligeable : c'est ici que
le modèle ROM intervient. La disjonction observée entre les ouvertures de deux
preuves du même témoin (test de masquage 3z-b1c) est la manifestation empirique
de cette uniformité. Le comptage vaut colonne par colonne ; l'aléa étant tiré
indépendamment par colonne, il s'étend au vecteur joint des ouvertures de
TRACE.

**Étage 2 — taille de la région de blinding (composition + FRI).** Le comptage
ci-dessus ne couvre QUE les évaluations de trace ; les ouvertures de
composition/quotient et les valeurs FRI dépendent elles aussi du témoin. Pour
elles, la garantie repose sur la TAILLE de la région de blinding :
`trace_len − used = next_pow2(used + 40) − used` lignes ENTIÈRES — 512 lignes à
profondeur 32 (1024 − 512), 256 en dev (512 − 256) — sur les 201 colonnes, soit
**≈ 51 000 à 103 000 cellules aléatoires fraîches** injectées dans la trace
committée, contre un total révélé de l'ordre de 10⁴ éléments du corps de base
au plus (ouvertures de trace ≈ 6 400, composition, frames OOD, couches FRI et
reste compris). Toute valeur révélée étant une fonction de cette trace
massivement randomisée, sa distribution JOINTE est — **heuristiquement** —
indépendante du témoin. `34 < 40` reste le comptage exact par colonne de
trace ; il n'est PAS, à lui seul, le périmètre complet de l'argument.

### Esquisse de simulateur

Simulateur `S`, à partir des SEULES entrées publiques (`root`, `nullifiers`,
`output_commitments`, `fee`, `depth`) :

1. pour chaque colonne de trace, échantillonner **uniformément** les `q + 2`
   évaluations « révélées » (au lieu de les calculer depuis un témoin) ;
2. échantillonner de même les ouvertures des colonnes de composition/quotient,
   sous les SEULES cohérences que le vérifieur teste effectivement — l'équation
   OOD (la valeur de composition en `z` doit égaler l'évaluation des
   contraintes sur le frame de trace OOD) et la consistance DEEP/FRI aux
   positions de requête — à la ethSTARK ; le simulateur ne peut PAS « dériver »
   ces ouvertures depuis les évaluations de trace (le vérifieur ne le peut pas
   non plus : c'est la raison d'être du commitment de contraintes séparé) ;
3. bâtir les engagements Merkle et chemins d'authentification autour de ces
   valeurs en **programmant l'oracle aléatoire** pour que les défis (`z`,
   positions de requête) tombent sur les points choisis — latitude standard du
   ROM.

La transcription produite VISE la même distribution qu'une preuve réelle : les
évaluations de trace y sont uniformes (étage 1, exact) ; les valeurs de
composition et FRI y sont cohérentes avec les seuls tests du vérifieur et,
dans une preuve honnête, sont des fonctions d'une trace committée massivement
randomisée (étage 2, heuristique). C'est une esquisse : elle rend plausible
qu'aucun distingueur n'existe, elle ne le démontre pas.

Limites assumées de l'esquisse — surfaces résiduelles NON formellement
traitées par cet argument :

- les **ouvertures de composition/quotient** : leur indépendance du témoin ne
  repose que sur l'heuristique de taille (étage 2), pas sur un comptage exact ;
- le **polynôme de reste FRI** (révélé en entier) et les couches repliées :
  winterfell ne sale PAS FRI (contrairement à ethSTARK) — même statut
  heuristique ;
- la **programmabilité de l'oracle** est utilisée sans être formalisée
  (winterfell enchaîne des engagements réels) ;
- l'argument de **rang plein** (étage 1) est probabiliste (probabilité d'échec
  négligeable, non bornée explicitement).

Un passage au niveau publication exigerait de traiter ces quatre points. Par
ailleurs, les entrées PUBLIQUES restent publiques par définition (root,
nullifiers, output_commitments, fee) : le witness-hiding porte sur le témoin
(notes, montants, `shielded_secret`, `nk`, chemins de Merkle), pas sur le
graphe transactionnel observable au niveau réseau (phase 4).

## Cohérence commitment ↔ note chiffrée (P8, différé)

Prouver en circuit que `enc_note` déchiffre vers la note engagée serait idéal mais
très coûteux. Position v0.2 (identique à Zcash Sapling/Orchard) : non prouvé en
circuit. Un expéditeur malveillant qui chiffre du garbage ne lèse que son destinataire
(fonds inutilisables, pas de création de monnaie) — P5/P7 tiennent indépendamment.
Réévaluer quand le coût des circuits sera mesuré.

**enc_notes portés + liés (fait) :** `ProvedTx` v3 porte les enveloppes chiffrées des
sorties (`enc_notes: [EncNote{kem_ct, enc_note}; 2]`, `circuit::tx`) pour le scan des
destinataires. Elles sont **liées dans `tx_digest` v3** (domaine
`obscura/proved-tx/v3`, longueurs LE préfixées, injectif) → un relais **passif** qui les
substitue casse le digest, donc la signature d'intention (testé
`enc_note_substitue_rejete`). ⚠️ **Portée exacte** : la preuve STARK ne lie PAS
`tx_digest`/`signer` (le digest est calculé après la preuve, il n'est pas un public du
monolithe), donc un relais **actif** peut re-signer un substitut avec sa propre clé —
propriété résiduelle héritée de la v2 (le signataire d'intention n'est pas une autorité
d'ownership). Impact borné : **déni de scan** du destinataire (enc_notes remplacés par
du garbage), PAS de vol ni d'inflation (P5/P7 tiennent). Fermer complètement le trou
exigerait de lier le signataire (ou le digest) dans les publics du monolithe — piste
future. Chiffrement/scan côté wallet (`ledger::proved_wallet`,
réutilise KEM hybride + AEAD, `aad = commitment`). **P8 reste différé** (aucune
contrainte AIR sur enc_notes) ; la **key-privacy IK-CCA** (indistinguabilité du
destinataire) reste un test de phase 4.

## Décision : hash consensus vs hash prouvé (point 3 de la revue)

`dual_hash` (BLAKE3‖SHA3) est excellent hors circuit mais prohibitif en STARK
(les deux sont hostiles à l'arithmétisation).

Décision v0.2 — deux domaines de hachage explicites :

| Domaine | Usage | Hash |
|---|---|---|
| **Hash consensus** | tx_digest, KDF, adresses, transcripts KEM/sig | dual BLAKE3‖SHA3 (inchangé) |
| **Hash prouvé** | commitments de notes, arbre de Merkle, `owner = H(secret)` et `nk = H(secret)`, PRF nullifier | **Rescue-Prime** (circuit-friendly, disponible dans winterfell) |

Conséquence assumée : les objets prouvés perdent la double-primitive et reposent sur
Rescue-Prime seul (fonction éponge algébrique, post-quantique comme tout hash, mais
moins éprouvée que SHA3). Mitigations : paramètres de sécurité conservateurs,
vecteurs de test croisés avec une seconde implémentation, et versioning explicite
(`obscura/…/rescue-prime/v1`) permettant une rotation de fonction si nécessaire.
La migration du code (merkle.rs, note.rs) se fait AVEC le circuit, jamais avant,
pour garantir que l'arbre consensus et l'arbre prouvé sont identiques.

**Padding assertés — préambule canonique pleinement contraint (monolithe).** Les
cellules de padding des éponges du monolithe sont **désormais assertées à zéro**
(`push_preamble`, correction post-revue 3z-a) : toutes les cellules ABSORBÉES
au-delà de la longueur logique `3 + payload_len + 1` jusqu'à la frontière de bloc
`⌈m/8⌉·8` — soit les 15 cellules `PAD_ZERO*` de chaque commitment (préambule
17 → 32, éponges U₀/U₁/O₀/O₁) et les **4 cellules du bloc partiel de chaque merge
de Merkle** (préambule 12, bloc de 16 cellules — zéro-remplissage de trace, même
classe de liberté). Sans ces assertions, le hash prouvé établissait
`H(payload ‖ junk)` au lieu de `H(payload)` : un prouveur pouvait publier un
`cm' = H(note ‖ junk)` internement cohérent mais HORS du schéma canonique (aucune
note ne recalcule ce commitment), ou un nœud de Merkle non canonique — violation
de « hash jamais tronqué ». Forges white-box RED→GREEN
(`padding_non_zero_rejete`, `padding_merge_non_zero_rejete`) : les traces forgées
passaient sans les assertions (cellules réellement libres, confirmé), sont
rejetées avec. Comptage : `num_assertions = 167 + 24·depth` (avant :
`107 + 16·depth`). Les AIR v1 autonomes (`SpongeAir`, `merkle_path`) conservent
l'hypothèse à domaine étendu (sûre sous résistance aux collisions de
Rescue-Prime) — seule la règle de consensus (le monolithe) exigeait le resserrage.

### Précision d'implémentation (v0.2) — où `dual_hash` s'applique réellement

Au sein du domaine « hash consensus », `dual_hash` (BLAKE3‖SHA3, 64 o, jamais tronqué)
est **exigé** là où la résistance aux collisions est *directement* sécuritaire :

- **commitments de notes** (`note.rs`) — binding de la note ;
- **tx_digest** (`tx.rs`) — lie signature et preuve à CETTE transaction ; une
  collision transférerait une signature d'une tx à une autre, et la double
  signature n'y changerait rien (les deux signent le même digest). Implémenté
  en dual depuis la correction d'audit 2026-07.

Les usages en **KDF/PRF** — `derive_key` (sous-clés AEAD), combinaison du secret
KEM — reposent sur **BLAKE3 seul** (keyed / derive-key). Choix
assumé : la défense en profondeur y est portée par les deux primitives KEM/signature
sous-jacentes, pas par le hash ; un hash unique de 256 bits comme PRF/KDF y suffit et
imposer le dual n'apporterait rien. En revanche, le **hash d'identité**
(`owner = H_owner(shielded_secret)`, `keys.rs`) et la **dérivation de `nk`**
(`nk = H_nk(shielded_secret)`) relèvent du **hash prouvé** (Rescue-Prime, migration
avec le circuit), PAS d'un KDF wallet — voir la ligne « hash prouvé » ci-dessus.
BLAKE3 domain-séparé n'y est qu'un échafaudage de dev. « Dual » est donc une *exigence* pour
commitments + tx_digest, non une contrainte uniforme sur tout hachage consensus.

## Candidat d'implémentation

`winterfell` (STARK, Rust) : prouveur/vérifieur génériques, Rescue-Prime fourni,
pas de trusted setup, hash-based (post-quantique). ⚠️ La formule « sécurité 100+ bits
configurables » qui figurait ici était trompeuse : elle vaut pour la sécurité
CONJECTURÉE — voir la section « Soundness » ci-dessous, qui donne les deux chiffres.
Alternative si blocage : `miden-crypto`/RPO. À benchmarker : taille de preuve et temps
de génération pour 2 entrées / 2 sorties, profondeur 32.


## Soundness : conjecturée vs PROUVÉE (mesurée, T3)

Chiffres **annoncés par winterfell** sur une preuve réelle (2/2, profondeur 32),
pas estimés — `cargo test -p circuit --release --lib niveau_de_securite --
--ignored --nocapture` :

```
paramètres : 32 requêtes, blowup 16, grinding 0, extension quadratique
CONJECTURÉE (conjecture 1, eprint 2021/582) : 127 bits
PROUVÉE — décodage par liste :  62 bits | décodage unique : 29 bits
```

La sécurité *conjecturée* suppose vraie une conjecture de la littérature FRI qui
n'est pas démontrée ; la *prouvée* est ce qui tient sans elle. Cette borne est
celle de la SOUNDNESS : la difficulté de forger une preuve invalide — donc, au
pire, de créer de la monnaie.

**62 bits n'est pas un niveau de production pour une monnaie.** Le remède est
paramétrique et connu (la sécurité prouvée demande 2× à 3× plus de requêtes que la
conjecturée à niveau égal) : augmenter `num_queries` — 32 aujourd'hui dans
`proof_options_hi` — au prix direct de la taille de preuve, qui est le coût
permanent payé par chaque nœud. **Arbitrage OUVERT, à trancher avant que la chaîne
ait de la valeur.**

⚠️ Ce chiffre ne dépend pas du quantique : il vaut déjà contre un adversaire
classique. Il est écrit parce qu'annoncer 127 bits sans nommer la conjecture serait
un mensonge par omission. Argument complet : docs/POST_QUANTIQUE.md §5.
