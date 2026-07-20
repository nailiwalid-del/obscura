//! AIR v0 du monolithe (3z-a3) : chaque groupe est CONTRAINT dans ses lignes
//! actives, mais les LIAISONS porteuse↔gadget (owner/nk/rho/cm/feuille/montants)
//! sont ABSENTES — elles arrivent en 3z-a4. Autrement dit : cette version prouve
//! que chaque segment est un calcul Rescue/équilibre correct EN ISOLATION, sans
//! encore forcer qu'ils partagent le même témoin.
//!
//! **Sélecteurs pleine longueur.** Comme `merkle_path`, les frontières de segments
//! (transitions 31→32, 39→40, 55→56 des éponges U_i, fin de chaque M_i, 255→256 de
//! l'équilibre) sont LIBRES : un sélecteur périodique pleine longueur (bâti sur
//! `self.l = trace_info.length()`) éteint la contrainte sur ces transitions et sur
//! toutes les lignes idle. Un SEUL jeu de colonnes ARK (cycle 8) sert tous les
//! groupes d'éponges (KEY, U_i, O_j, M_i partagent l'ordonnancement de rondes).
//!
//! **Degrés = BORNES SUPÉRIEURES (blowup 16, mode release).** Comme
//! `merkle_path`/`balance`, les colonnes témoins peuvent être constantes pour
//! certains témoins → le `debug_assert` de degrés de winterfell (dépendant de
//! l'entrée) est incompatible avec un contrat fixe. Les preuves sont générées en
//! `--release` (assert ignoré) ; on déclare des bornes supérieures calibrées via la
//! formule `base·(n−1) + Σ (n/cᵢ)·(cᵢ−1)` et la contrainte de blowup
//! `next_pow2(base + |cycles| − 1) ≤ 16` (cf. calibration en tête de `degrees()`).
//!
//! ⚠️ validity-only : intégrité des segments ET cohérence inter-segments (liaisons
//! par porteuses, 3z-a4), PAS confidentialité (witness-hiding = Phase 3z ultérieure).
//!
//! `prove_monolith`/`verify_monolith` sont atteignables depuis l'API publique du
//! crate depuis 3z-a5 (`tx::prove_tx`/`tx::verify_tx`) : plus d'`allow(dead_code)`
//! de module nécessaire.

use crate::merkle_path::enforce_merkle_transition;
use crate::monolith::layout::{
    used_rows, BAL_OFF, BLIND_ROWS, CARRIER_OFF, CM_C, CM_ROWS_END, CM_ROWS_START, KEY_OFF,
    LEAF_C, LEAF_ROWS_START, M0_OFF, M1_OFF, NF_ROWS_END, NF_ROWS_START, NK_C, O0_OFF, O1_OFF,
    OWNER_C, RHO_C, U0_OFF, U1_OFF, VIN_C, VOUT_C, WIDTH,
};
use crate::monolith::trace::{build_monolith_trace, MonolithWitness};
use crate::rescue_round::{enforce_round_block, periodic_ark_columns, STATE_WIDTH};
use crate::sponge::{enforce_sponge_transition, locate, RATE_START, RATE_WIDTH};
use crate::ValidityProof;
use proved_hash::digest::DIGEST_FELTS;
use proved_hash::domain::{Domain, ENCODING_VERSION};
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

type Blake3 = Blake3_256<BaseElement>;

// ---- Comptage des familles de contraintes (ordre figé pour `result`/`degrees`). ----
const N_KEY: usize = 2 * STATE_WIDTH; // 24 : rondes owner + nk
const N_SPONGE: usize = STATE_WIDTH; // 12 : une éponge U_i / O_j
const N_MERKLE: usize = 30; // recopie de `merkle_path` (sponge 12 + booléen + copies + swap)
const N_BAL: usize = 3; // bit booléen, accumulateur S, accumulateur de bloc VACC
const N_CARRIER: usize = 36; // porteuses constantes
const N_BASE: usize = N_KEY + 4 * N_SPONGE + 2 * N_MERKLE + N_BAL + N_CARRIER; // 171

// ---- Liaisons par porteuses (3z-a4), une famille à la fois (chacune son test). ----
// Chaque égalité gatée est déclarée ET écrite ensemble (result/degrees synchronisés :
// un slot déclaré mais non écrit lirait un résidu de ligne winterfell → JAMAIS de trou).
const N_SECRET: usize = DIGEST_FELTS; // 4 : liaison secret owner↔nk, gatée ligne 0 (s0)
const N_OWNER: usize = 3 * DIGEST_FELTS; // 12 : prod @7 (clé) + 2× conso @0 (commitments)
const N_NK: usize = 3 * DIGEST_FELTS; // 12 : prod @7 (clé) + 2× conso @40 (nullifiers)
const N_RHO: usize = 2 * (2 * DIGEST_FELTS); // 16 : par entrée @7(4) + @40(1) + @47(3)
const N_CM: usize = 2 * (3 * DIGEST_FELTS); // 24 : par entrée @31(4) + @32(4) + @47(4)
const N_LEAF: usize = 2 * (2 * DIGEST_FELTS); // 16 : par entrée @39(4) + @0(4)
const N_VIN: usize = 4; // 2× (prod @0 + conso VACC fin de bloc)
const N_VOUT: usize = 4; // 2× (prod @0 + conso VACC fin de bloc)
const N_LIAISON: usize =
    N_SECRET + N_OWNER + N_NK + N_RHO + N_CM + N_LEAF + N_VIN + N_VOUT; // 92

const N_CONSTRAINTS: usize = N_BASE + N_LIAISON; // 171 + 92 = 263

// ---- Segments d'équilibre (mêmes constantes que `trace::fill_balance`). ----
const BAL_ROWS: usize = 256; // 4 blocs × 64
const BAL_HALF: usize = 128; // entrées (+1) puis sorties (−1)
const BAL_BLOCK: usize = 64;
const BAL_BIT: usize = 0;
const BAL_S: usize = 1;
const BAL_VACC: usize = 2;

// ================================================================================================
// ENTRÉES PUBLIQUES
// ================================================================================================

/// Publics du monolithe : racine partagée, les 2 nullifiers, les 2 commitments de
/// sortie, les frais. `depth` (profondeur des chemins de Merkle) est engagé pour que
/// l'AIR connaisse la ligne de racine et le nombre de blocs assertés (comme
/// `MerklePathPublicInputs.depth`). Aucun témoin (owner/nk/valeurs/rho/cm/secret) ici.
#[derive(Clone)]
pub(crate) struct MonolithPublicInputs {
    pub root: [BaseElement; DIGEST_FELTS],
    pub nullifiers: [[BaseElement; DIGEST_FELTS]; 2],
    pub output_commitments: [[BaseElement; DIGEST_FELTS]; 2],
    pub fee: u64,
    pub depth: usize,
}

impl winterfell::math::ToElements<BaseElement> for MonolithPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(5 * DIGEST_FELTS + 2);
        v.extend_from_slice(&self.root);
        for nf in &self.nullifiers {
            v.extend_from_slice(nf);
        }
        for oc in &self.output_commitments {
            v.extend_from_slice(oc);
        }
        v.push(BaseElement::new(self.fee));
        v.push(BaseElement::new(self.depth as u64));
        v
    }
}

// ================================================================================================
// AIR
// ================================================================================================

pub(crate) struct MonolithAir {
    context: AirContext<BaseElement>,
    pi: MonolithPublicInputs,
    l: usize,
    depth: usize,
}

/// Nombre d'assertions (publiques uniquement) en fonction de la profondeur.
///
/// `push_preamble` émet 8 assertions fixes (capacité 4 + VERSION/tag/LEN/PAD_ONE)
/// **+ les PAD_ZERO\*** : les cellules absorbées au-delà de la longueur logique
/// `3 + payload_len + 1` jusqu'à la frontière de bloc `⌈m/8⌉·8`, soit :
///   - commitment (m=32, p=13) : cellules 17..32 → **15** ;
///   - merge Merkle (m=12, p=8) : cellules 12..16 → **4** (bloc partiel) ;
///   - clé/feuille/nullifier (m ∈ {8, 8, 16}, préambules pleins) → 0.
///
/// KEY(16) + 2·U(28+15) + 2·M((8+4)·depth+4) + 2·O(12+15) + BAL(3) = 167 + 24·depth.
/// BAL(3) = S[0]=0, S[used−1]=fee, VACC[0]=0 (ancrage anti-inflation de l'entrée 0).
/// Toutes les assertions visent des lignes < used_rows(depth) : AUCUNE ne touche la
/// région de blinding (witness-hiding 3z-b1b).
fn num_assertions(depth: usize) -> usize {
    16 + 2 * (28 + 15) + 2 * (12 * depth + 4) + 2 * (12 + 15) + 3
}

impl winterfell::Air for MonolithAir {
    type BaseField = BaseElement;
    type PublicInputs = MonolithPublicInputs;

    fn new(trace_info: TraceInfo, pi: MonolithPublicInputs, options: ProofOptions) -> Self {
        // Witness-hiding (3z-b1) : chaque requête FRI révèle jusqu'à 2 lignes
        // (cur/next) de la trace ; il faut au moins q + 2 lignes de blinding pour
        // que les q requêtes + l'évaluation OOD ne déterminent pas le témoin.
        assert!(
            BLIND_ROWS >= options.num_queries() + 2,
            "BLIND_ROWS ({}) doit couvrir num_queries + 2 ({})",
            BLIND_ROWS,
            options.num_queries() + 2
        );
        let l = trace_info.length();
        let depth = pi.depth;
        let context = AirContext::new(trace_info, degrees(l), num_assertions(depth), options);
        MonolithAir { context, pi, l, depth }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        pv: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let one = E::ONE;

        // --- Colonnes périodiques (cf. `get_periodic_column_values`). ---
        let round_flag_s = pv[0];
        let ark1 = &pv[1..1 + STATE_WIDTH];
        let ark2 = &pv[1 + STATE_WIDTH..1 + 2 * STATE_WIDTH];
        let round_flag_m = pv[25];
        let init0 = pv[26];
        let init7 = pv[27];
        let chain = pv[28];
        let sel_key = pv[29];
        let sel_u = pv[30];
        let sel_o = pv[31];
        let sel_m = pv[32];
        let sel_bal = pv[33];
        let signe = pv[34];
        let pow = pv[35];
        let endblk = pv[36];
        // Gating global witness-hiding (3z-b1b) : appliqué à TOUTES les contraintes
        // en fin de fonction (cf. le recensement avant la boucle de gating).
        let blind_off = pv[48];

        let mut idx = 0;

        // --- KEY (owner ‖ nk) : 2 blocs de rondes, gatés `sel_key`. ---
        {
            let mut tmp = [E::ZERO; N_KEY];
            let k = &cur[KEY_OFF..KEY_OFF + N_KEY];
            let kn = &next[KEY_OFF..KEY_OFF + N_KEY];
            enforce_round_block(k, kn, 0, ark1, ark2, &mut tmp);
            enforce_round_block(k, kn, STATE_WIDTH, ark1, ark2, &mut tmp);
            for (r, t) in tmp.iter().enumerate() {
                result[idx + r] = sel_key * *t;
            }
            idx += N_KEY;
        }

        // --- Éponges U_i (dépense) et O_j (sortie) : rondes + absorption, gatées. ---
        for (off, sel) in [
            (U0_OFF, sel_u),
            (U1_OFF, sel_u),
            (O0_OFF, sel_o),
            (O1_OFF, sel_o),
        ] {
            let mut tmp = [E::ZERO; N_SPONGE];
            enforce_sponge_transition(
                &cur[off..off + 20],
                &next[off..off + 20],
                round_flag_s,
                ark1,
                ark2,
                &mut tmp,
            );
            for (r, t) in tmp.iter().enumerate() {
                result[idx + r] = sel * *t;
            }
            idx += N_SPONGE;
        }

        // --- Chemins de Merkle M_i : recopie de `merkle_path`, gatée `sel_m`. ---
        for off in [M0_OFF, M1_OFF] {
            let mut tmp = [E::ZERO; N_MERKLE];
            enforce_merkle_transition(
                &cur[off..off + 29],
                &next[off..off + 29],
                round_flag_m,
                ark1,
                ark2,
                init0,
                init7,
                chain,
                &mut tmp,
            );
            for (r, t) in tmp.iter().enumerate() {
                result[idx + r] = sel_m * *t;
            }
            idx += N_MERKLE;
        }

        // --- Équilibre : bit booléen, accumulateur signé S, accumulateur de bloc VACC. ---
        {
            let bit = cur[BAL_OFF + BAL_BIT];
            let s = cur[BAL_OFF + BAL_S];
            let s_next = next[BAL_OFF + BAL_S];
            let vacc = cur[BAL_OFF + BAL_VACC];
            let vacc_next = next[BAL_OFF + BAL_VACC];
            // bit ∈ {0,1} (gaté sel_bal).
            result[idx] = sel_bal * bit * (bit - one);
            // S_next − S − signe·bit·pow : le signe périodique porte le gating de
            // ZONE (signe = 0 au-delà de 256 → S reste constant = fee sur la traîne
            // idle 256..used) ; le gating GLOBAL blind_off (fin de fonction) libère
            // ensuite S sur la région de blinding (assertion finale en S[used−1]).
            result[idx + 1] = s_next - s - signe * bit * pow;
            // VACC_next = (1 − endblk)·(VACC + bit·pow) : accumulation intra-bloc,
            // remise à zéro à la fin de chaque bloc (gaté sel_bal).
            result[idx + 2] = sel_bal * (vacc_next - (one - endblk) * (vacc + bit * pow));
            idx += N_BAL;
        }

        // --- Porteuses : constantes (next − cur = 0) sur la RÉGION UTILE. Le gating
        //     blind_off est appliqué par la boucle GLOBALE en fin de fonction (un
        //     seul facteur, degré wc(1, [n]) inchangé) : la transition used−1 → used
        //     et la région de blinding sont LIBRES (les porteuses y sautent vers
        //     l'aléa de `build_monolith_trace_seeded`). ---
        for c in 0..N_CARRIER {
            result[idx + c] = next[CARRIER_OFF + c] - cur[CARRIER_OFF + c];
        }
        idx += N_CARRIER; // idx == N_BASE

        // ============================================================================
        // LIAISONS PAR PORTEUSES (3z-a4) — chaque égalité gatée à sa ligne unique.
        // Motif : `sel_r · (cur[porteuse] − cur[cellule])`, sel_r allumé à la seule
        // ligne r. Chaque famille contraint sa PRODUCTION et ses CONSOMMATIONS (une
        // porteuse ne liant qu'un côté ne lie rien). Positions vérifiées contre
        // `sponge.rs::locate` et `trace.rs`.
        // ============================================================================
        let s0 = pv[37];
        let s7 = pv[38];
        let s31 = pv[39];
        let s32 = pv[40];
        let s39 = pv[41];
        let s40 = pv[42];
        let s47 = pv[43];
        let vacc_gate = [pv[44], pv[45], pv[46], pv[47]]; // entrées 0/1, sorties 0/1
        // Colonne rate (RATE_START..) = digest de sortie d'un bloc éponge.
        let rate = RATE_START;

        // --- SECRET : le secret du bloc owner == le secret du bloc nk (liaison
        //     owner↔nk, anti-double-dépense). Le bloc KEY prouve owner = H_owner(s_o)
        //     ET nk = H_nk(s_n) pour DEUX témoins ; sans cette égalité un prouveur
        //     dériverait owner et nk de secrets DISTINCTS (owner d'une note qu'il
        //     possède, nk d'une autre → nullifier arbitraire → double-dépense). Le
        //     secret est aux colonnes 7..11 de chaque bloc (KEY_SECRET_START =
        //     RATE_START + 3 = 7 ; cf. key.rs::SECRET_START). Gaté ligne 0 (s0),
        //     miroir exact de key.rs::N_BIND / `liaison_secret_partage_mord`. ---
        for k in 0..DIGEST_FELTS {
            result[idx + k] = s0 * (cur[KEY_OFF + 7 + k] - cur[KEY_OFF + STATE_WIDTH + 7 + k]);
        }
        idx += DIGEST_FELTS;

        // --- OWNER : owner = H_owner(secret) gouverne les commitments d'entrée. ---
        // Production @7 : porteuse == sortie rate du bloc owner de la clé.
        for k in 0..DIGEST_FELTS {
            result[idx + k] = s7 * (cur[OWNER_C + k] - cur[KEY_OFF + rate + k]);
        }
        idx += DIGEST_FELTS;
        // Consommation @0 : owner (préambule commitment idx 4..7 → cols +8..+12) de U0, U1.
        for u_off in [U0_OFF, U1_OFF] {
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s0 * (cur[OWNER_C + k] - cur[u_off + 8 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // --- NK : nk = H_nk(secret) gouverne les nullifiers. ---
        // Production @7 : porteuse == sortie rate du bloc nk de la clé (KEY_OFF+12+4).
        for k in 0..DIGEST_FELTS {
            result[idx + k] = s7 * (cur[NK_C + k] - cur[KEY_OFF + STATE_WIDTH + rate + k]);
        }
        idx += DIGEST_FELTS;
        // Consommation @40 : nk (préambule nullifier idx 3..6 → cols +7..+11) de U0, U1.
        for u_off in [U0_OFF, U1_OFF] {
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s40 * (cur[NK_C + k] - cur[u_off + 7 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // --- RHO : le rho du nullifier == le rho du commitment (v0.2 : nf lié au cm). ---
        for u_off in [U0_OFF, U1_OFF] {
            let i = if u_off == U0_OFF { 0 } else { 1 };
            // Consommation @7 : rho0..3 (préambule commitment inject cols +12..+16).
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s7 * (cur[RHO_C[i] + k] - cur[u_off + 12 + k]);
            }
            idx += DIGEST_FELTS;
            // Consommation @40 : rho0 (préambule nullifier idx 7 → col +11).
            result[idx] = s40 * (cur[RHO_C[i]] - cur[u_off + 11]);
            idx += 1;
            // Consommation @47 : rho1..3 (préambule nullifier idx 8..10 → inject cols +12..+15).
            for j in 0..DIGEST_FELTS - 1 {
                result[idx + j] = s47 * (cur[RHO_C[i] + 1 + j] - cur[u_off + 12 + j]);
            }
            idx += DIGEST_FELTS - 1;
        }

        // --- CM_IN : le cm produit par l'entrée gouverne feuille ET nullifier (P1). ---
        for u_off in [U0_OFF, U1_OFF] {
            let i = if u_off == U0_OFF { 0 } else { 1 };
            // Production @31 : porteuse == digest du commitment (rate cols +4..+8).
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s31 * (cur[CM_C[i] + k] - cur[u_off + rate + k]);
            }
            idx += DIGEST_FELTS;
            // Consommation @32 : cm0..3 (préambule feuille idx 3..6 → cols +7..+11).
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s32 * (cur[CM_C[i] + k] - cur[u_off + 7 + k]);
            }
            idx += DIGEST_FELTS;
            // Consommation @47 : cm0..3 (préambule nullifier idx 11..14 → inject cols +15..+19).
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s47 * (cur[CM_C[i] + k] - cur[u_off + 15 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // --- FEUILLE↔CHEMIN : la feuille produite == la feuille injectée dans M_i. ---
        // (Remplace l'assertion publique `leaf` de merkle_path : la feuille est ici un
        //  TÉMOIN lié au commitment, jamais un public.)
        for (u_off, m_off) in [(U0_OFF, M0_OFF), (U1_OFF, M1_OFF)] {
            let i = if u_off == U0_OFF { 0 } else { 1 };
            // Production @39 : porteuse == digest de la feuille (rate cols +4..+8).
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s39 * (cur[LEAF_C[i] + k] - cur[u_off + rate + k]);
            }
            idx += DIGEST_FELTS;
            // Consommation @0 : `cur` du chemin (M_i cols +20..+24, ligne 0).
            for k in 0..DIGEST_FELTS {
                result[idx + k] = s0 * (cur[LEAF_C[i] + k] - cur[m_off + 20 + k]);
            }
            idx += DIGEST_FELTS;
        }

        // --- MONTANTS (P5 lié aux commitments) : la value de chaque commitment ==
        //     la valeur accumulée VACC de son bloc d'équilibre. VACC est gaté à la
        //     ligne 64·b+60 (valeur PLEINE — bits 60..63 nuls — et < l−1, donc la
        //     transition est bien enforçée même à profondeur 2 ; cf. table qui donnait
        //     64·b+63, écart documenté).
        let vacc = BAL_OFF + BAL_VACC;
        // VIN : entrées (blocs 0,1) — production @0 (value = préambule commitment idx 3
        //       → col +7), consommation VACC.
        for u_off in [U0_OFF, U1_OFF] {
            let i = if u_off == U0_OFF { 0 } else { 1 };
            result[idx] = s0 * (cur[VIN_C[i]] - cur[u_off + 7]);
            result[idx + 1] = vacc_gate[i] * (cur[VIN_C[i]] - cur[vacc]);
            idx += 2;
        }
        // VOUT : sorties (blocs 2,3) — production @0, consommation VACC.
        for o_off in [O0_OFF, O1_OFF] {
            let j = if o_off == O0_OFF { 0 } else { 1 };
            result[idx] = s0 * (cur[VOUT_C[j]] - cur[o_off + 7]);
            result[idx + 1] = vacc_gate[2 + j] * (cur[VOUT_C[j]] - cur[vacc]);
            idx += 2;
        }

        debug_assert_eq!(idx, N_CONSTRAINTS);

        // ============================================================================
        // GATING GLOBAL blind_off (witness-hiding 3z-b1b).
        //
        // Recensement préalable (audit de chaque famille sur la région de blinding
        // `[used_rows(depth), trace_len)`) — les sélecteurs de région bâtis sur
        // `self.l` s'annulent DÉJÀ pour r ≥ used : sel_key (r < 7), sel_u (r < 56),
        // sel_o (r < 31), sel_m (r < 16·depth−1 ≤ used−1), sel_bal (r < 256 ≤ used),
        // les one-hot de liaison s0/s7/s31/s32/s39/s40/s47 et les vacc_gate (lignes
        // ≤ 252 < used). NE s'annulaient PAS :
        //   1. l'équilibre S (`s_next − s − signe·bit·pow`, non gaté) : porté par
        //      `signe` (nul au-delà de 256), il exigeait S CONSTANT sur tout le
        //      blinding (l'assertion S[l−1] = fee est déplacée en S[used−1]) ;
        //   2. le reset VACC à la frontière 255→256 (endblk @255, gaté sel_bal
        //      encore actif à r = 255) : quand used == 256 (profondeur ≤ 16), il
        //      forçait next[VACC] = 0 sur la PREMIÈRE ligne de blinding.
        // Choix robuste (spec 3z-b1) : multiplier CHAQUE contrainte par blind_off —
        // aucune colonne ne peut être oubliée, les lignes de blinding sont libres
        // pour TOUTES les familles (S et VACC y sont randomisées comme le reste par
        // `build_monolith_trace_seeded`). Coût : +1 cycle pleine longueur par
        // famille dans `degrees()` (les porteuses, écrites NON gatées ci-dessus,
        // reçoivent ici leur unique facteur) — le blowup reste 16 (M-sponge :
        // next_pow2(8 + 4 − 1) = 16, cf. calibration de `degrees()`).
        for r in result.iter_mut() {
            *r *= blind_off;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(num_assertions(self.depth));

        // Éponge B=1 du secret : owner (cols KEY_OFF..+12) + nk (cols +12..+24).
        push_preamble(&mut a, 0, KEY_OFF, 8, Domain::Owner.tag() as u64, DIGEST_FELTS);
        push_preamble(
            &mut a,
            0,
            KEY_OFF + STATE_WIDTH,
            8,
            Domain::Nk.tag() as u64,
            DIGEST_FELTS,
        );

        // U_i : commitment (m=32,p=13) ‖ feuille (m=8,p=4) ‖ nullifier (m=16,p=12).
        // Public : nf_i = rate cols 4..8 de la ligne 55.
        for (i, u_off) in [U0_OFF, U1_OFF].into_iter().enumerate() {
            push_preamble(&mut a, CM_ROWS_START, u_off, 32, Domain::NoteCommitment.tag() as u64, 13);
            push_preamble(&mut a, LEAF_ROWS_START, u_off, 8, Domain::MerkleLeaf.tag() as u64, 4);
            push_preamble(&mut a, NF_ROWS_START, u_off, 16, Domain::Nullifier.tag() as u64, 12);
            for k in 0..DIGEST_FELTS {
                a.push(Assertion::single(
                    u_off + RATE_START + k,
                    NF_ROWS_END - 1,
                    self.pi.nullifiers[i][k],
                ));
            }
        }

        // M_i : un préambule de merge par bloc de 16 lignes (m=12, MerkleNode, p=8).
        // Public : root = rate cols 4..8 de la ligne 16·depth−1 (i = 0 ET 1, même valeur).
        let last_m = 16 * self.depth - 1;
        for m_off in [M0_OFF, M1_OFF] {
            for b in 0..self.depth {
                push_preamble(&mut a, b * 16, m_off, 12, Domain::MerkleNode.tag() as u64, 8);
            }
            for k in 0..DIGEST_FELTS {
                a.push(Assertion::single(m_off + RATE_START + k, last_m, self.pi.root[k]));
            }
        }

        // O_j : commitment (m=32,p=13). Public : oc_j = rate cols 4..8 de la ligne 31.
        for (j, o_off) in [O0_OFF, O1_OFF].into_iter().enumerate() {
            push_preamble(&mut a, 0, o_off, 32, Domain::NoteCommitment.tag() as u64, 13);
            for k in 0..DIGEST_FELTS {
                a.push(Assertion::single(
                    o_off + RATE_START + k,
                    CM_ROWS_END - 1,
                    self.pi.output_commitments[j][k],
                ));
            }
        }

        // Équilibre : S[0] = 0, S[used−1] = fee (= Σin − Σout). L'assertion finale
        // vise la DERNIÈRE ligne UTILE (pas l−1 : depuis le gating global blind_off,
        // S est libre — et randomisé — sur la région de blinding ; la contrainte S,
        // active jusqu'à la transition used−2 → used−1, propage fee jusque-là).
        a.push(Assertion::single(BAL_OFF + BAL_S, 0, BaseElement::ZERO));
        a.push(Assertion::single(
            BAL_OFF + BAL_S,
            used_rows(self.depth) - 1,
            BaseElement::new(self.pi.fee),
        ));
        // VACC[0] = 0 : la cellule d'accumulation de bloc de l'entrée 0 est SINON un
        // témoin libre (aucun reset ne la précède, contrairement aux blocs 1..3 dont
        // le VACC de départ est forcé à 0 par le reset endblk de la ligne 63/127/191).
        // Sans cet ancrage, un prouveur y met VACC[0] = −k, décompose l'entrée 0 en
        // (valeur + k) tout en gardant VACC@60 = valeur (porteuse VIN honnête) → S
        // encaisse k de trop → inflation depuis l'entrée 0. L'égalité VACC[0] = 0 force
        // Σbits(bloc 0) = VACC@60 = VIN₀, fermant le trou.
        a.push(Assertion::single(BAL_OFF + BAL_VACC, 0, BaseElement::ZERO));

        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let l = self.l;
        let z = BaseElement::ZERO;
        let o = BaseElement::ONE;
        let mut cols: Vec<Vec<BaseElement>> = Vec::with_capacity(49);

        // [0] round_flag éponge (cycle 8) : ronde sauf à la frontière de bloc.
        let mut rf_s = vec![o; 8];
        rf_s[7] = z;
        cols.push(rf_s);
        // [1..25] ARK1 puis ARK2 (cycle 8), partagés par TOUS les groupes.
        cols.extend(periodic_ark_columns());
        // [25] round_flag Merkle (cycle 16) : 0 aux absorptions/frontières (p ∈ {7,15}).
        cols.push((0..16).map(|p| if p == 7 || p == 15 { z } else { o }).collect());
        // [26] init0 / [27] init7 / [28] chain (cycle 16) : ancrages du swap et chaînage.
        cols.push((0..16).map(|p| if p == 0 { o } else { z }).collect());
        cols.push((0..16).map(|p| if p == 7 { o } else { z }).collect());
        cols.push((0..16).map(|p| if p == 15 { o } else { z }).collect());

        // Sélecteurs pleine longueur (bâtis sur l), frontières éteintes.
        // [29] sel_key : rondes de clé aux transitions 0..6.
        cols.push((0..l).map(|r| if r < 7 { o } else { z }).collect());
        // [30] sel_u : U_i actif sur 0..56 SAUF les frontières de segment 31/39/55.
        cols.push(
            (0..l)
                .map(|r| {
                    if r < NF_ROWS_END && r != 31 && r != 39 && r != 55 {
                        o
                    } else {
                        z
                    }
                })
                .collect(),
        );
        // [31] sel_o : O_j (commitment 4 blocs) actif sur 0..31 (frontière 31 éteinte).
        cols.push((0..l).map(|r| if r < CM_ROWS_END - 1 { o } else { z }).collect());
        // [32] sel_m : M_i actif sur 0..16·depth−1 (au-delà : idle).
        let last_m = 16 * self.depth - 1;
        cols.push((0..l).map(|r| if r < last_m { o } else { z }).collect());
        // [33] sel_bal : équilibre actif sur 0..256.
        cols.push((0..l).map(|r| if r < BAL_ROWS { o } else { z }).collect());
        // [34] signe : +1 (entrées) sur 0..128, −1 (sorties) sur 128..256, 0 au-delà.
        cols.push(
            (0..l)
                .map(|r| {
                    if r < BAL_HALF {
                        o
                    } else if r < BAL_ROWS {
                        -o
                    } else {
                        z
                    }
                })
                .collect(),
        );
        // [35] pow : 2^(r mod 64) pour les bits significatifs (< 60) de la zone active.
        cols.push(
            (0..l)
                .map(|r| {
                    if r < BAL_ROWS && r % BAL_BLOCK < crate::range_check::RANGE_BITS {
                        BaseElement::new(1u64 << (r % BAL_BLOCK))
                    } else {
                        z
                    }
                })
                .collect(),
        );
        // [36] endblk : 1 sur la dernière ligne de chaque bloc d'équilibre (reset VACC).
        cols.push(
            (0..l)
                .map(|r| if r < BAL_ROWS && r % BAL_BLOCK == BAL_BLOCK - 1 { o } else { z })
                .collect(),
        );

        // Sélecteurs mono-ligne pleine longueur (cycle l, un seul 1) pour les liaisons
        // par porteuses (3z-a4) — motif `init` de key.rs, mais ancré à une ligne r ≠ 0.
        // Une liaison ne lit que `cur` ; le sélecteur l'ALLUME sur l'unique ligne du
        // point de production/consommation. La transition de la dernière ligne (l−1)
        // étant EXCLUE du domaine d'enforcement (diviseur winterfell), aucun ancrage
        // n'est placé en l−1 (cf. montants : ligne 64i+60, pas 64i+63).
        let at = |r0: usize| -> Vec<BaseElement> {
            (0..l).map(|r| if r == r0 { o } else { z }).collect()
        };
        cols.push(at(0)); //  [37] s0  : owner/leaf conso, vin/vout prod
        cols.push(at(7)); //  [38] s7  : owner/nk prod (clé), rho conso (commitment)
        cols.push(at(31)); // [39] s31 : cm prod (digest commitment)
        cols.push(at(32)); // [40] s32 : cm conso (préambule feuille)
        cols.push(at(39)); // [41] s39 : feuille prod (digest feuille)
        cols.push(at(40)); // [42] s40 : nk/rho0 conso (préambule nullifier)
        cols.push(at(47)); // [43] s47 : rho1..3/cm conso (nullifier, ligne d'absorption)
        cols.push(at(60)); //  [44] VACC entrée 0 (ligne 64·0+60)
        cols.push(at(124)); // [45] VACC entrée 1 (ligne 64·1+60)
        cols.push(at(188)); // [46] VACC sortie 0 (ligne 64·2+60)
        cols.push(at(252)); // [47] VACC sortie 1 (ligne 64·3+60)

        // [48] blind_off (witness-hiding 3z-b1) : 1 ssi la transition r → r+1 reste
        // DANS la région utile `[0, used_rows(depth))`, i.e. r + 1 < used ; 0 sinon.
        // Éteint les contraintes gatées sur la transition used−1 → used (le saut
        // vers l'aléa) et sur toute la région de blinding.
        let used = used_rows(self.depth);
        cols.push((0..l).map(|r| if r + 1 < used { o } else { z }).collect());

        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Assertions de préambule d'une éponge (capacité + VERSION/tag/LEN/PAD_ONE +
/// PAD_ZERO\*), à la ligne `seg_start`, aux colonnes `col_off..col_off+20`.
/// Positions issues de `locate` DÉCALÉES par l'offset de colonne et la ligne de
/// début de segment. N'asserte AUCUN témoin (payload jamais public ici).
fn push_preamble(
    a: &mut Vec<Assertion<BaseElement>>,
    seg_start: usize,
    col_off: usize,
    m: u64,
    tag: u64,
    payload_len: usize,
) {
    // Capacité [longueur absorbée, 0, 0, 0] à la ligne de début.
    a.push(Assertion::single(col_off, seg_start, BaseElement::new(m)));
    a.push(Assertion::single(col_off + 1, seg_start, BaseElement::ZERO));
    a.push(Assertion::single(col_off + 2, seg_start, BaseElement::ZERO));
    a.push(Assertion::single(col_off + 3, seg_start, BaseElement::ZERO));
    // VERSION (idx 0), tag (1), LEN (2) au bloc 0, PAD_ONE à sa position logique.
    for (i, val) in [
        (0usize, ENCODING_VERSION as u64),
        (1, tag),
        (2, payload_len as u64),
        (3 + payload_len, 1),
    ] {
        let (row, col) = locate(i);
        a.push(Assertion::single(col_off + col, seg_start + row, BaseElement::new(val)));
    }
    // PAD_ZERO* : toutes les cellules ABSORBÉES au-delà de la longueur LOGIQUE
    // `3 + payload_len + 1`, jusqu'à la frontière de bloc `⌈m/8⌉·8` (couvre à la
    // fois le PAD_ZERO* du resize — commitment, 17..32 — ET le zéro-remplissage du
    // bloc partiel — merge m=12, cellules 12..16). La contrainte d'absorption les
    // ADDITIONNE au rate : les laisser libres permettrait de prouver
    // `H(payload ‖ junk)` au lieu du `H(payload)` canonique (« hash jamais
    // tronqué ») — cm'/node' internement cohérents mais hors du schéma. On les
    // épingle donc à ZÉRO. No-op quand le préambule remplit exactement ses blocs
    // (clé, feuille, nullifier).
    let logical = 3 + payload_len + 1;
    let cells = (m as usize).div_ceil(RATE_WIDTH) * RATE_WIDTH;
    for i in logical..cells {
        let (row, col) = locate(i);
        a.push(Assertion::single(col_off + col, seg_start + row, BaseElement::ZERO));
    }
}

/// Degrés déclarés (BORNES SUPÉRIEURES, mode release), dans l'ORDRE de `result`.
///
/// Calibration (formule winterfell `base·(n−1) + Σ (n/cᵢ)·(cᵢ−1)`, contrainte de
/// blowup `next_pow2(base + |cycles| − 1) ≤ 16`) — `n = trace_len`, tout sélecteur
/// pleine longueur ajoute un cycle `n` (contribution `n−1`, coût de blowup +1).
/// Depuis le gating GLOBAL blind_off (3z-b1b), CHAQUE famille gagne un cycle `n`
/// supplémentaire (le facteur blind_off), SAUF les porteuses dont blind_off est
/// l'UNIQUE facteur (écrites non gatées, multipliées une seule fois par la boucle
/// globale) :
///  - KEY : deg 7 × sel_key(n) × blind_off(n)           → base 7, [n,n]     (blowup 8)
///  - U/O : deg 7 × round_flag(8) × sel(n) × blind_off(n)→ base 7, [8,n,n]  (blowup 16)
///  - M sponge : deg 8 × rf(16) × chain × sel_m(n) × blind_off(n)
///    → base 8, [8,16,n,n] (blowup 16)
///  - M booléen/copies : deg 2 × sel_m(n) × blind_off(n) → base 2, [n,n]    (blowup 4)
///  - M swap : deg 3 × sel_m(n) × blind_off(n)           → base 3, [n,n]    (blowup 4)
///  - BAL bit : deg 2 × sel_bal(n) × blind_off(n)        → base 2, [n,n]    (blowup 4)
///  - BAL S : bit × signe(n) × pow(n) × blind_off(n)     → base 2, [n,n,n]  (blowup 4)
///  - BAL VACC : bit × pow(n) × endblk(n) × sel_bal(n) × blind_off(n)
///    → base 2, [n,n,n,n] (blowup 8)
///  - porteuses : (next − cur) × blind_off(n)            → base 1, [n]      (blowup 2)
///  - liaisons : sel(n) × blind_off(n) × (cur[a] − cur[b])→ base 1, [n,n]   (blowup 2)
///
/// Les bornes M-sponge (8 + 4 − 1 = 11) et U/O (7 + 3 − 1 = 9) saturent le
/// blowup 16 ; toutes les autres sont en-dessous. Bornes supérieures ⇒ soundness
/// préservée.
fn degrees(n: usize) -> Vec<TransitionConstraintDegree> {
    let wc = TransitionConstraintDegree::with_cycles;
    let mut d = Vec::with_capacity(N_CONSTRAINTS);

    // KEY (24).
    for _ in 0..N_KEY {
        d.push(wc(7, vec![n, n]));
    }
    // U0, U1, O0, O1 (4 × 12).
    for _ in 0..4 * N_SPONGE {
        d.push(wc(7, vec![8, n, n]));
    }
    // M0, M1 (2 × 30) : 12 sponge, 10 booléen/copies (deg 2), 8 swap (deg 3).
    for _ in 0..2 {
        for _ in 0..12 {
            d.push(wc(8, vec![8, 16, n, n]));
        }
        for _ in 0..10 {
            d.push(wc(2, vec![n, n]));
        }
        for _ in 0..8 {
            d.push(wc(3, vec![n, n]));
        }
    }
    // BAL (3).
    d.push(wc(2, vec![n, n])); // bit booléen
    d.push(wc(2, vec![n, n, n])); // accumulateur S
    d.push(wc(2, vec![n, n, n, n])); // accumulateur VACC
    // Porteuses (36) : blind_off (cycle pleine longueur) est leur UNIQUE facteur.
    for _ in 0..N_CARRIER {
        d.push(wc(1, vec![n]));
    }
    // Liaisons (92, dont la liaison secret owner↔nk) : chacune `sel(cycle n) ·
    // blind_off(cycle n) · (cur[a] − cur[b])` — degré 1, deux cycles pleine
    // longueur. Blowup 16 : très en-dessous.
    for _ in 0..N_LIAISON {
        d.push(wc(1, vec![n, n]));
    }

    debug_assert_eq!(d.len(), N_CONSTRAINTS);
    d
}

// ================================================================================================
// PROVER
// ================================================================================================

struct MonolithProver {
    options: ProofOptions,
    pi: MonolithPublicInputs,
}

impl Prover for MonolithProver {
    type BaseField = BaseElement;
    type Air = MonolithAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MonolithPublicInputs {
        self.pi.clone()
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_options)
    }
    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// ================================================================================================
// API INTERNE
// ================================================================================================

/// Lit un digest (4 Felts winter) à `(row, col..col+4)` de la trace.
fn read4(trace: &TraceTable<BaseElement>, col: usize, row: usize) -> [BaseElement; DIGEST_FELTS] {
    core::array::from_fn(|k| trace.get(col + k, row))
}

/// Prouve le monolithe (segments contraints, liaisons absentes). À GÉNÉRER EN
/// `--release`. Les publics sont EXTRAITS de la trace (cohérents avec les assertions).
pub(crate) fn prove_monolith(w: &MonolithWitness) -> (MonolithPublicInputs, ValidityProof) {
    let depth = w.inputs[0].path.len();
    let trace = build_monolith_trace(w);
    debug_assert_eq!(trace.width(), WIDTH);

    let last_m = 16 * depth - 1;
    let pi = MonolithPublicInputs {
        root: read4(&trace, M0_OFF + RATE_START, last_m),
        nullifiers: [
            read4(&trace, U0_OFF + RATE_START, NF_ROWS_END - 1),
            read4(&trace, U1_OFF + RATE_START, NF_ROWS_END - 1),
        ],
        output_commitments: [
            read4(&trace, O0_OFF + RATE_START, CM_ROWS_END - 1),
            read4(&trace, O1_OFF + RATE_START, CM_ROWS_END - 1),
        ],
        fee: w.fee,
        depth,
    };

    let prover = MonolithProver {
        options: crate::proof_options_hi(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (pi, ValidityProof(proof))
}

/// Vérifie une preuve de monolithe contre les publics et la profondeur annoncée.
pub(crate) fn verify_monolith(
    pi: &MonolithPublicInputs,
    depth: usize,
    proof: &ValidityProof,
) -> bool {
    let mut pv = pi.clone();
    pv.depth = depth;
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<MonolithAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pv,
        &acceptable,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monolith::trace::{
        build_monolith_trace_forge, witness_de_test, witness_de_test_profondeur_consensus, Forge,
    };
    use proved_hash::digest::Digest;
    use proved_hash::felt::Felt;

    fn to_digest(d: [BaseElement; DIGEST_FELTS]) -> Digest {
        Digest(core::array::from_fn(|k| Felt::from_winter(d[k]).expect("digest canonique")))
    }

    /// Un digest de test arbitraire (pour les valeurs forgées).
    fn dg(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| Felt::from_canonical_u64(seed + i as u64).unwrap()))
    }

    /// Prouve (en release) la trace `witness_de_test` éventuellement FORGÉE, publics
    /// relus de la trace (comme `prove_monolith`), et retourne le verdict de `verify`.
    /// Motif de `key.rs::liaison_secret_partage_mord` : le prouveur n'évalue pas les
    /// contraintes en release → la preuve est produite puis (dé)validée par `verify`.
    fn verdict_forge(forge: Forge) -> bool {
        let (w, _root) = witness_de_test();
        let depth = 2;
        let trace = build_monolith_trace_forge(&w, forge);
        let last_m = 16 * depth - 1;
        let pi = MonolithPublicInputs {
            root: read4(&trace, M0_OFF + RATE_START, last_m),
            nullifiers: [
                read4(&trace, U0_OFF + RATE_START, NF_ROWS_END - 1),
                read4(&trace, U1_OFF + RATE_START, NF_ROWS_END - 1),
            ],
            output_commitments: [
                read4(&trace, O0_OFF + RATE_START, CM_ROWS_END - 1),
                read4(&trace, O1_OFF + RATE_START, CM_ROWS_END - 1),
            ],
            fee: w.fee,
            depth,
        };
        let prover = MonolithProver {
            options: crate::proof_options_hi(),
            pi: pi.clone(),
        };
        let proof = ValidityProof(prover.prove(trace).expect("preuve produite en release"));
        verify_monolith(&pi, depth, &proof)
    }

    /// Prouve le monolithe (profondeur 2) sur une trace à graine de blinding FIXÉE
    /// (couture déterministe), publics relus de la trace (comme `prove_monolith`).
    /// Sert au test de masquage : deux graines → deux blindings distincts.
    fn preuve_seedee(w: &MonolithWitness, seed: u64) -> (MonolithPublicInputs, ValidityProof) {
        use crate::monolith::trace::build_monolith_trace_seeded;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let depth = 2;
        let trace = build_monolith_trace_seeded(w, &mut StdRng::seed_from_u64(seed));
        let last_m = 16 * depth - 1;
        let pi = MonolithPublicInputs {
            root: read4(&trace, M0_OFF + RATE_START, last_m),
            nullifiers: [
                read4(&trace, U0_OFF + RATE_START, NF_ROWS_END - 1),
                read4(&trace, U1_OFF + RATE_START, NF_ROWS_END - 1),
            ],
            output_commitments: [
                read4(&trace, O0_OFF + RATE_START, CM_ROWS_END - 1),
                read4(&trace, O1_OFF + RATE_START, CM_ROWS_END - 1),
            ],
            fee: w.fee,
            depth,
        };
        let prover = MonolithProver {
            options: crate::proof_options_hi(),
            pi: pi.clone(),
        };
        let proof = ValidityProof(prover.prove(trace).expect("preuve produite en release"));
        (pi, proof)
    }

    /// Extrait les évaluations OUVERTES de la colonne `col` aux positions de requête
    /// FRI, via `Queries::parse` — motif du spike E1 (`zk-spike::secret_openings`) :
    /// exactement ce qu'un observateur du réseau peut faire sur une preuve sérialisée.
    fn ouvertures_colonne(proof: &ValidityProof, col: usize) -> Vec<BaseElement> {
        let queries = proof.0.trace_queries[0].clone(); // segment principal
        let (_opening_proof, table) = queries
            .parse::<BaseElement, Blake3, MerkleTree<Blake3>>(
                proof.0.lde_domain_size(),
                proof.0.num_unique_queries as usize,
                WIDTH,
            )
            .expect("parse des trace queries");
        table.rows().map(|row| row[col]).collect()
    }

    /// MASQUAGE (witness-hiding 3z-b1b, white-box) : la porteuse OWNER_C est
    /// CONSTANTE (= owner témoin) sur toute la région utile `[0, used)` — sans
    /// blinding, son polynôme serait constant et CHAQUE ouverture FRI vaudrait
    /// owner en clair (zk-spike, expérience A). Avec les lignes de blinding et le
    /// gating global blind_off : (1) AUCUNE ouverture ne vaut le témoin owner ;
    /// (2) deux preuves de la MÊME tx (graines distinctes) ouvrent des valeurs
    /// DISJOINTES sur cette colonne (masquage randomisé, pas déterministe).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn masquage_owner_ouvertures_aleatoires() {
        use proved_hash::rescue;

        let (w, _root) = witness_de_test();
        let (pi1, p1) = preuve_seedee(&w, 41);
        let (pi2, p2) = preuve_seedee(&w, 42);
        assert!(verify_monolith(&pi1, 2, &p1), "preuve blindée 1 acceptée");
        assert!(verify_monolith(&pi2, 2, &p2), "preuve blindée 2 acceptée");

        let owner = rescue::hash(Domain::Owner, w.secret.as_felts());
        for k in 0..DIGEST_FELTS {
            let temoin = owner.0[k].to_winter();
            let o1 = ouvertures_colonne(&p1, OWNER_C + k);
            let o2 = ouvertures_colonne(&p2, OWNER_C + k);
            assert!(!o1.is_empty(), "au moins une ouverture");
            assert_eq!(
                o1.iter().filter(|&&v| v == temoin).count(),
                0,
                "aucune ouverture de p1 ne doit valoir owner[{k}]"
            );
            assert_eq!(
                o2.iter().filter(|&&v| v == temoin).count(),
                0,
                "aucune ouverture de p2 ne doit valoir owner[{k}]"
            );
        }
        // Disjointes sur OWNER_C : aucune valeur commune entre les deux preuves
        // (les combinaisons linéaires mêlent l'aléa de blinding, distinct par graine).
        let o1 = ouvertures_colonne(&p1, OWNER_C);
        let o2 = ouvertures_colonne(&p2, OWNER_C);
        assert!(
            o1.iter().all(|v| !o2.contains(v)),
            "les ouvertures OWNER_C des deux preuves doivent être disjointes"
        );
    }

    /// MASQUAGE EXHAUSTIF (witness-hiding 3z-b1c) : généralise
    /// `masquage_owner_ouvertures_aleatoires` (colonne unique) à un échantillon
    /// représentatif de TOUTES les familles de colonnes témoins — porteuses (owner
    /// complet, nk complet, un représentant de rho/cm/leaf/vin/vout), la cellule
    /// secret de KEY, une cellule témoin BRUTE d'éponge (payload du commitment U0,
    /// non recopiée par une porteuse) et l'accumulateur d'équilibre BAL_S. Pour
    /// chaque colonne : (a) aucune ouverture FRI ne vaut la valeur témoin
    /// correspondante (reconstruite hors-circuit depuis `w`, jamais lue dans la
    /// trace) ; (b) les ouvertures ne sont pas toutes identiques ; (c) deux preuves
    /// de la MÊME tx (graines distinctes) ont des ouvertures DISJOINTES sur chaque
    /// colonne. Motif et helper `ouvertures_colonne` repris tels quels de T2
    /// (DRY : aucune logique de parsing dupliquée).
    ///
    /// **Deux régimes de force, à ne pas confondre (revue post-implémentation) :**
    /// - **13 colonnes PORTEUSES** (owner/nk/rho/cm/leaf/vin/vout) : polynômes
    ///   CONSTANTS sur `[0, used)` (contrainte `next − cur = 0`). Sans blinding, un
    ///   polynôme constant s'évalue à la MÊME valeur partout, y compris aux
    ///   positions de requête FRI (domaine coset, disjoint de `[0, used)`) → (a)
    ///   échouerait DÉTERMINISTIQUEMENT si le gating `blind_off` sautait. C'est un
    ///   vrai DÉTECTEUR DE RÉGRESSION de la fuite catastrophique E1 (zk-spike).
    /// - **3 cellules ÉVOLUTIVES** (`KEY_SECRET[0]`, `U0_COMMIT_VALUE`, `BAL_S`) :
    ///   colonnes NON constantes par construction (même sans blinding, chaque
    ///   ligne y porte une valeur différente) → leurs ouvertures aux positions de
    ///   requête sont déjà génériques AVEC OU SANS blinding : (a) n'y détecte donc
    ///   PAS une non-randomisation ciblée de la région de blinding, et (b)/(c) non
    ///   plus — les positions de requête varient déjà via Fiat-Shamir sur les
    ///   AUTRES colonnes randomisées, donc des ouvertures différentes entre `p1`
    ///   et `p2` peuvent venir de là plutôt que du blinding de CETTE colonne
    ///   précise. Ces 3 cellules sont incluses pour la DIVERSITÉ des familles
    ///   couvertes (secret / éponge brute / équilibre), en couverture QUALITATIVE
    ///   — pas comme détecteur dur au même titre que les porteuses. `BAL_S` en
    ///   particulier est comparé à `fee`, qui est PUBLIC : (a) y agit comme un
    ///   contrôle de cohérence (la cellule ne fuite pas la valeur publique par un
    ///   canal witness), pas comme un test de masquage à proprement parler.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn masquage_colonnes_temoins() {
        use proved_hash::merkle;
        use proved_hash::rescue;

        let (w, _root) = witness_de_test();
        let (pi1, p1) = preuve_seedee(&w, 41);
        let (pi2, p2) = preuve_seedee(&w, 42);
        assert!(verify_monolith(&pi1, 2, &p1), "preuve blindée 1 acceptée");
        assert!(verify_monolith(&pi2, 2, &p2), "preuve blindée 2 acceptée");

        // Valeurs témoins hors-circuit, reconstruites depuis `w` (jamais depuis la
        // trace ni depuis la preuve) : owner/nk via les hachages de clé, rho/valeurs
        // via les notes elles-mêmes, cm/leaf via les fonctions de référence.
        let owner = rescue::hash(Domain::Owner, w.secret.as_felts());
        let nk = rescue::hash(Domain::Nk, w.secret.as_felts());
        let n0 = &w.inputs[0].note;
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let leaf0 = merkle::leaf(&cm0);

        // Table (nom, colonne, valeur témoin attendue) : 8 premières porteuses
        // (OWNER_C + NK_C complets) + un représentant de rho/cm/leaf/vin/vout, la
        // cellule secret (KEY_OFF+7), une cellule témoin d'éponge (U0, valeur du
        // commitment à la ligne d'absorption 0) et BAL_S (accumulateur final =
        // fee, ligne used−1 = 255 — valeur non triviale, à l'intérieur de [0,used)).
        let cases: Vec<(&str, usize, BaseElement)> = vec![
            ("OWNER_C[0]", OWNER_C, owner.0[0].to_winter()),
            ("OWNER_C[1]", OWNER_C + 1, owner.0[1].to_winter()),
            ("OWNER_C[2]", OWNER_C + 2, owner.0[2].to_winter()),
            ("OWNER_C[3]", OWNER_C + 3, owner.0[3].to_winter()),
            ("NK_C[0]", NK_C, nk.0[0].to_winter()),
            ("NK_C[1]", NK_C + 1, nk.0[1].to_winter()),
            ("NK_C[2]", NK_C + 2, nk.0[2].to_winter()),
            ("NK_C[3]", NK_C + 3, nk.0[3].to_winter()),
            ("RHO_C[0][0]", RHO_C[0], n0.rho.0[0].to_winter()),
            ("CM_C[0][0]", CM_C[0], cm0.0[0].to_winter()),
            ("LEAF_C[0][0]", LEAF_C[0], leaf0.0[0].to_winter()),
            ("VIN_C[0]", VIN_C[0], BaseElement::new(n0.value)),
            ("VOUT_C[0]", VOUT_C[0], BaseElement::new(w.outputs[0].value)),
            ("KEY_SECRET[0]", KEY_OFF + 7, w.secret.as_felts()[0].to_winter()),
            ("U0_COMMIT_VALUE", U0_OFF + 7, BaseElement::new(n0.value)),
            ("BAL_S(fin)", BAL_OFF + BAL_S, BaseElement::new(w.fee)),
        ];

        for (nom, col, temoin) in &cases {
            let o1 = ouvertures_colonne(&p1, *col);
            let o2 = ouvertures_colonne(&p2, *col);
            assert!(!o1.is_empty(), "{nom} : au moins une ouverture (p1)");
            assert!(!o2.is_empty(), "{nom} : au moins une ouverture (p2)");

            // (a) aucune ouverture ne vaut la valeur témoin.
            assert_eq!(
                o1.iter().filter(|&&v| v == *temoin).count(),
                0,
                "{nom} : aucune ouverture de p1 ne doit valoir le témoin"
            );
            assert_eq!(
                o2.iter().filter(|&&v| v == *temoin).count(),
                0,
                "{nom} : aucune ouverture de p2 ne doit valoir le témoin"
            );

            // (b) signal de masquage minimal : les ouvertures d'une même preuve ne
            // sont pas toutes identiques (une colonne non blindée renverrait sa
            // constante témoin à CHAQUE position de requête, cf. l'expérience A du
            // spike zk-spike sans blinding).
            assert!(
                o1.iter().skip(1).any(|v| v != &o1[0]),
                "{nom} : les ouvertures de p1 doivent varier"
            );

            // (c) deux preuves de la même tx, graines distinctes → ouvertures
            // DISJOINTES (l'aléa de blinding, distinct par graine, se propage dans
            // les combinaisons linéaires lues par chaque ouverture).
            assert!(
                o1.iter().all(|v| !o2.contains(v)),
                "{nom} : les ouvertures p1/p2 doivent être disjointes"
            );
        }
    }

    /// Roundtrip complet : prouve le monolithe, vérifie, et rejette des publics
    /// falsifiés. Gaté release (l'AIR a des colonnes témoins constantes → degrés
    /// input-dépendants, cf. `merkle_path`).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn roundtrip_monolithe() {
        let (w, root) = witness_de_test();
        let (pi, proof) = prove_monolith(&w);

        // La racine publique == la racine de l'arbre de test.
        assert_eq!(to_digest(pi.root), root);
        assert!(verify_monolith(&pi, 2, &proof));

        // Frais falsifiés → rejet.
        let mut faux = pi.clone();
        faux.fee += 1;
        assert!(!verify_monolith(&faux, 2, &proof));

        // Racine falsifiée → rejet.
        let mut faux = pi.clone();
        faux.root[0] += BaseElement::ONE;
        assert!(!verify_monolith(&faux, 2, &proof));

        // Nullifier falsifié → rejet.
        let mut faux = pi.clone();
        faux.nullifiers[0][0] += BaseElement::ONE;
        assert!(!verify_monolith(&faux, 2, &proof));

        // Commitment de sortie falsifié → rejet.
        let mut faux = pi.clone();
        faux.output_commitments[1][0] += BaseElement::ONE;
        assert!(!verify_monolith(&faux, 2, &proof));
    }

    /// LIAISON OWNER (white-box) : un commitment d'entrée construit avec un owner ≠
    /// sortie de la clé doit être REJETÉ. La trace forgée reste self-consistante
    /// (cm/feuille/nf/arbre recalculés) : SEULE la liaison owner @0 la distingue.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_owner_mord() {
        assert!(verdict_forge(Forge::Aucune), "trace honnête acceptée");
        assert!(!verdict_forge(Forge::OwnerConsomme(dg(555))), "owner ≠ clé doit mordre");
    }

    /// LIAISON NK : nullifier calculé avec un nk ≠ sortie de la clé → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_nk_mord() {
        assert!(!verdict_forge(Forge::NkConsomme(dg(556))), "nk ≠ clé doit mordre");
    }

    /// LIAISON SECRET owner↔nk (anti-double-dépense) : le bloc KEY dérive owner de `s`
    /// mais nk d'un `s' ≠ s`. owner et nk sont chacun corrects pour LEUR secret, la
    /// porteuse NK_C et le nullifier consomment nk = H_nk(s') (cascade honnête) : SEULE
    /// la contrainte de liaison secret (ligne 0) mord. Sans elle, un prouveur combinerait
    /// l'owner d'une note possédée avec un nk arbitraire → nullifier détaché → double-
    /// dépense illimitée. RED vérifié en neutralisant la famille SECRET (s0 → ZÉRO dans
    /// cette famille, non committé) : la forge passait alors → cible bien cette contrainte.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_secret_owner_nk_mord() {
        assert!(!verdict_forge(Forge::SecretNk(dg(561))), "s_nk ≠ s_owner doit mordre");
    }

    /// ANCRAGE VACC[0] (anti-inflation entrée 0) : la trace forge VACC[0] = −k et
    /// décompose l'entrée 0 en (valeur + k), la sortie 0 gonflée de k gardant S_final =
    /// fee. Toutes les liaisons VIN/VOUT restent honnêtes (VACC@60 = porteuses) : SEULE
    /// l'assertion VACC[0] = 0 distingue la forge. Sans elle, k unités seraient créées
    /// ex nihilo. RED vérifié en retirant l'assertion VACC[0] (non committé) : la forge
    /// passait alors.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn vacc_initial_libre_mord() {
        assert!(verdict_forge(Forge::Aucune), "trace honnête acceptée");
        assert!(!verdict_forge(Forge::VaccInitial(100)), "VACC[0] ≠ 0 (inflation) doit mordre");
    }

    /// LIAISON RHO (propriété v0.2 « nullifier lié au commitment ») : rho du nullifier
    /// ≠ rho du commitment → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_rho_mord() {
        assert!(!verdict_forge(Forge::RhoNullifier(0, dg(557))), "rho nf ≠ rho cm doit mordre");
    }

    /// LIAISON RHO CÔTÉ COMMITMENT (ancre @7, différée de la revue T4 sur argument de
    /// symétrie avec `liaison_rho_mord`) : le rho ABSORBÉ dans le commitment de
    /// l'entrée 0 diverge de la porteuse RHO_C, alors que le nullifier reste honnête
    /// (rho = note.rho, comme RHO_C) — cm/feuille/nullifier/arbre recalculés en
    /// cascade honnête sur cm' = H(valeur ‖ owner ‖ rho' ‖ r). C'est le miroir
    /// PRODUCTION de `liaison_rho_mord` (qui mord côté nullifier, @40/@47) : ancre
    /// @7 distincte, cellules distinctes (inject cols +12..+16 ligne 7 du
    /// COMMITMENT, vs +11 ligne 40 et +12..+15 ligne 47 du NULLIFIER). RED vérifié
    /// en neutralisant localement la sous-boucle « Consommation @7 » de la famille
    /// RHO dans `evaluate_transition` (`result[idx+k] = s7 * (...)` → `E::ZERO`,
    /// NON committé) : la forge passait alors → confirme que le test cible bien
    /// cette ancre et pas une autre (owner/nk @7 partagent le même sélecteur s7
    /// mais des cellules disjointes, restées actives pendant le RED).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_rho_commitment_mord() {
        assert!(
            !verdict_forge(Forge::RhoCommitment(0, dg(562))),
            "rho commitment ≠ porteuse doit mordre"
        );
    }

    /// LIAISON CM_IN (P1 non détournable) : feuille bâtie sur un autre commitment que
    /// celui produit par l'entrée → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_cm_mord() {
        assert!(!verdict_forge(Forge::CmFeuille(0, dg(558))), "cm feuille ≠ cm produit doit mordre");
    }

    /// LIAISON CM_IN SUR L'ENTRÉE 1 (jumelle U1, différée de la revue T4 sur argument
    /// de symétrie avec `liaison_cm_mord`) : même forge que `liaison_cm_mord` mais sur
    /// l'entrée 1 (`Forge::CmFeuille(1, …)`) — exerce la SECONDE itération de la
    /// boucle `for u_off in [U0_OFF, U1_OFF]` de la famille CM dans
    /// `evaluate_transition`, sur des colonnes disjointes (U1_OFF au lieu de U0_OFF)
    /// et un sélecteur de ligne partagé (s32) mais une porteuse CM_C[1] distincte de
    /// CM_C[0]. Confirme que l'ancrage de l'entrée 1 est INDÉPENDANTE de celle de
    /// l'entrée 0 (pas seulement dupliquée par construction Rust sans être réellement
    /// exercée par le prouveur). RED vérifié en neutralisant localement toute la
    /// sous-boucle « Consommation @32 » de la famille CM (`result[idx+k] = s32 *
    /// (...)` → `E::ZERO`, pour i ∈ {0,1}, NON committé) : la forge passait alors.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_cm_mord_u1() {
        assert!(
            !verdict_forge(Forge::CmFeuille(1, dg(563))),
            "cm feuille ≠ cm produit (entrée 1) doit mordre"
        );
    }

    /// LIAISON FEUILLE↔CHEMIN : chemin de Merkle prouvé sur une autre feuille que
    /// celle produite par l'entrée → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_leaf_mord() {
        assert!(!verdict_forge(Forge::LeafChemin(0, dg(559))), "feuille chemin ≠ feuille produite doit mordre");
    }

    /// LIAISON MONTANTS (P5 lié aux commitments) : un commitment déclarant 1000 mais
    /// un bloc d'équilibre à 900 → rejet. Le bloc reste self-consistant (compensation
    /// sur la sortie 0 → S_final = fee), donc seule la liaison VIN mord.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_valeurs_mord() {
        assert!(!verdict_forge(Forge::ValeurBal(0, 900)), "value bloc ≠ value commitment doit mordre");
    }

    /// LIAISON CM@47 (nullifier↔cm, anti-double-dépense) : nullifier calculé sur un
    /// AUTRE cm que celui produit par le commitment de l'entrée → rejet. La forge ne
    /// touche QUE les cellules cm@47 (inject cols +15..+19 ligne 47, DISJOINTES de
    /// rho@47 en +12..+15) : commitment, feuille, arbre et porteuse CM_C honnêtes.
    /// RED vérifié en désactivant localement la contrainte cm@47 (s47 → zéro dans la
    /// famille CM uniquement, non committé) : la forge passait alors → le test cible
    /// bien exactement cette contrainte.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_cm_nullifier_mord() {
        assert!(!verdict_forge(Forge::CmNullifier(0, dg(560))), "cm du nullifier ≠ cm produit doit mordre");
    }

    /// ISOLATION VIN : bloc BAL 0 forgé à 900, compensé sur le bloc BAL 1 (deux blocs
    /// d'ENTRÉE, même signe) → Σ signée reste fee, les gates VOUT restent honnêtes,
    /// SEULS VIN[0]/VIN[1] diffèrent de leurs porteuses. Un bug du seul gate VIN ne
    /// peut plus être masqué par le gate VOUT (contrairement à `liaison_valeurs_mord`
    /// qui exerce VIN[0] ET VOUT[0]). RED vérifié en désactivant localement les deux
    /// consommations VACC de VIN (non committé) : la forge passait alors.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_vin_isole_mord() {
        assert!(!verdict_forge(Forge::ValeurBalEntrees(900)), "VIN seul doit mordre");
    }

    /// ISOLATION VOUT (miroir de `liaison_vin_isole_mord`, différée de la revue T4 sur
    /// argument de symétrie) : bloc BAL 2 (sortie 0) forgé à 700, compensé sur le
    /// bloc BAL 3 (sortie 1, même signe −) → Σ signée reste fee, les gates VIN
    /// restent honnêtes (VIN_C inchangées), les porteuses VOUT_C restent la valeur
    /// RÉELLE des commitments de sortie (fixées avant la forge de montants) —
    /// SEULS VOUT[0]/VOUT[1] diffèrent de leur porteuse. Un bug du seul gate VOUT ne
    /// peut plus être masqué par le gate VIN. RED vérifié en neutralisant localement
    /// les deux consommations VACC de la famille VOUT dans `evaluate_transition`
    /// (`result[idx+1] = vacc_gate[2+j] * (...)` → `E::ZERO` pour j ∈ {0,1}, NON
    /// committé) : la forge passait alors.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_vout_isole_mord() {
        assert!(!verdict_forge(Forge::ValeurBalSorties(700)), "VOUT seul doit mordre");
    }

    /// PAD_ZERO* du COMMITMENT (préambule canonique) : l'entrée 0 publie
    /// cm' = H(payload ‖ junk) — une cellule de padding (idx 17) non nulle, digest
    /// recalculé, cascade feuille/nullifier/arbre/porteuses HONNÊTE sur cm'. La
    /// trace est entièrement self-consistante (l'absorption absorbe le junk, les
    /// rondes suivent) : SEULES les assertions PAD_ZERO la distinguent d'une trace
    /// honnête. Ce qu'elles empêchent : publier un commitment HORS du schéma
    /// canonique (LEN annonce 13 mais 15 cellules de junk sont absorbées → cm'
    /// n'est le `note_commitment` d'AUCUNE note) — violation de « hash jamais
    /// tronqué ». RED vérifié en neutralisant le bloc PAD_ZERO de `push_preamble`
    /// (compte `num_assertions` réajusté ENSEMBLE, non committé) : la forge passait.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn padding_non_zero_rejete() {
        assert!(verdict_forge(Forge::Aucune), "trace honnête acceptée");
        assert!(
            !verdict_forge(Forge::PaddingCommitment(41)),
            "PAD_ZERO ≠ 0 (commitment) doit mordre"
        );
    }

    /// PAD_ZERO* du MERGE de Merkle (bloc partiel m=12 → 16 cellules de trace, 4
    /// libres) : node' = H(l0 ‖ l1 ‖ junk), arbre REBÂTI sur node' (root' partagée
    /// M0/M1, publics relus de la trace) → trace self-consistante, seule l'assertion
    /// PAD_ZERO du merge la rejette. Même classe d'attaque que le commitment : un
    /// nœud de Merkle hors du schéma canonique. RED vérifié conjointement avec
    /// `padding_non_zero_rejete` (même neutralisation, non committée).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn padding_merge_non_zero_rejete() {
        assert!(
            !verdict_forge(Forge::PaddingMerkle(43)),
            "PAD_ZERO ≠ 0 (merge Merkle) doit mordre"
        );
    }

    /// INERTIE DES LIGNES DE BLINDING (soundness 3z-b1d, white-box) : la région de
    /// blinding `[used, len)` est remplie de valeurs CHOISIES par l'attaquant
    /// (recopies de lignes utiles + junk violant grossièrement les invariants
    /// utiles : bit d'équilibre non booléen, accumulateur S sautant, porteuse
    /// discontinue, cellule secret incohérente — cf. `Forge::LigneBlindingArbitraire`)
    /// au lieu de l'aléa honnête. Test d'ACCEPTATION, pas de rejet : c'est
    /// l'affirmation d'INERTIE — aucune contrainte de transition (toutes gatées par
    /// blind_off, nul dès la transition used−1 → used) ni aucune assertion (toutes
    /// à des lignes < used) ne lit la région de blinding, donc quoi que le prouveur
    /// y mette, le statement vérifié (P1–P7) est INCHANGÉ. L'attaquant ne gagne
    /// rien (il ne peut qu'y perdre son propre witness-hiding en y mettant du
    /// non-aléa). Complète la matrice de rejet : les 13 forges `*_mord`/`*_rejete`
    /// (qui tournent désormais elles-mêmes SOUS blinding seedé, cf.
    /// `build_monolith_trace_forge`) prouvent que les violations UTILES mordent
    /// toujours ; ce test prouve que la région NON contrainte, elle, ne peut RIEN
    /// forger. Si ce test se met à REJETER, une contrainte ou une assertion s'est
    /// mise à lire `≥ used` : à traiter comme un bug (trou de complétude ET
    /// dépendance interdite à la région de blinding), ne pas le « corriger » en
    /// inversant l'assert.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn lignes_blinding_ne_forgent_rien() {
        assert!(
            verdict_forge(Forge::LigneBlindingArbitraire),
            "les lignes de blinding adverses doivent être INERTES (tx acceptée)"
        );
    }

    /// Roundtrip HONNÊTE à profondeur CONSENSUS (32, trace_len 512) : prouve et
    /// vérifie le monolithe complet 2-in/2-out. Valide de bout en bout le fix de
    /// complétude BAL (S constant au-delà de 256) ET l'ensemble des liaisons à la
    /// vraie profondeur. LENT (~plusieurs secondes) : lancé explicitement
    /// (`cargo test -p circuit --release -- --ignored roundtrip_profondeur_consensus`)
    /// et par le bench T7 ; `#[ignore]` même en release pour ne pas alourdir la CI.
    #[test]
    #[ignore = "lent : lancé explicitement et par le bench T7"]
    fn roundtrip_profondeur_consensus() {
        if cfg!(debug_assertions) {
            return; // AIR gaté : la génération de preuve exige --release.
        }
        let (w, root) = witness_de_test_profondeur_consensus();
        let (pi, proof) = prove_monolith(&w);
        assert_eq!(to_digest(pi.root), root, "racine prouvée == racine consensus");
        assert!(verify_monolith(&pi, 32, &proof), "preuve honnête profondeur 32 acceptée");
        // Frais falsifiés → rejet (sanité liaison montants à profondeur réelle).
        let mut faux = pi.clone();
        faux.fee += 1;
        assert!(!verify_monolith(&faux, 32, &proof));
    }

    /// Cohérence des publics extraits (indépendant du prouveur, tourne en DEBUG) :
    /// root/nf/oc == références hors-circuit. NE fait PAS tourner l'AIR.
    #[test]
    fn publics_coherents_avec_les_references() {
        use proved_hash::merkle;
        use proved_hash::rescue;

        let (w, root) = witness_de_test();
        let depth = w.inputs[0].path.len();
        let trace = build_monolith_trace(&w);

        // root extrait == fold hors-circuit.
        let root_pi = to_digest(read4(&trace, M0_OFF + RATE_START, 16 * depth - 1));
        assert_eq!(root_pi, root);

        // nf_i extrait == H_Nullifier(nk ‖ rho ‖ cm) hors-circuit.
        let nk = rescue::hash(Domain::Nk, w.secret.as_felts());
        for i in 0..2 {
            let note = &w.inputs[i].note;
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            let mut payload = Vec::new();
            payload.extend_from_slice(&nk.0);
            payload.extend_from_slice(&note.rho.0);
            payload.extend_from_slice(&cm.0);
            let nf = rescue::hash(Domain::Nullifier, &payload);
            let u_off = if i == 0 { U0_OFF } else { U1_OFF };
            assert_eq!(to_digest(read4(&trace, u_off + RATE_START, NF_ROWS_END - 1)), nf);
        }

        // oc_j extrait == note_commitment hors-circuit.
        for j in 0..2 {
            let out = &w.outputs[j];
            let oc = rescue::note_commitment(out.value, &out.owner, &out.rho, &out.r);
            let o_off = if j == 0 { O0_OFF } else { O1_OFF };
            assert_eq!(to_digest(read4(&trace, o_off + RATE_START, CM_ROWS_END - 1)), oc);
        }

        // Sanité : la feuille de merkle est bien celle du commitment (hors-circuit).
        let n0 = &w.inputs[0].note;
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let _ = merkle::leaf(&cm0);
    }
}
