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
//! ⚠️ validity-only : intégrité des segments, PAS confidentialité, PAS encore la
//! cohérence inter-segments (3z-a4).
//!
//! `#![allow(dead_code)]` de module : `prove_monolith`/`verify_monolith` n'ont pour
//! l'instant qu'un appelant, les tests (`#[cfg(test)]`). En build normal, aucun point
//! d'entrée public n'atteint encore ce module (`prove_monolith_tx` de 3z-a5 le fera) ;
//! l'allow tombera à ce moment-là (comme `layout.rs`/`trace.rs`).
#![allow(dead_code)]

use crate::merkle_path::enforce_merkle_transition;
use crate::monolith::layout::{
    BAL_OFF, CARRIER_OFF, CM_C, CM_ROWS_END, CM_ROWS_START, KEY_OFF, LEAF_C, LEAF_ROWS_START,
    M0_OFF, M1_OFF, NF_ROWS_END, NF_ROWS_START, NK_C, O0_OFF, O1_OFF, OWNER_C, RHO_C, U0_OFF,
    U1_OFF, VIN_C, VOUT_C, WIDTH,
};
use crate::monolith::trace::{build_monolith_trace, MonolithWitness};
use crate::rescue_round::{enforce_round_block, periodic_ark_columns, STATE_WIDTH};
use crate::sponge::{enforce_sponge_transition, locate, RATE_START};
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
const N_OWNER: usize = 3 * DIGEST_FELTS; // 12 : prod @7 (clé) + 2× conso @0 (commitments)
const N_NK: usize = 3 * DIGEST_FELTS; // 12 : prod @7 (clé) + 2× conso @40 (nullifiers)
const N_RHO: usize = 2 * (2 * DIGEST_FELTS); // 16 : par entrée @7(4) + @40(1) + @47(3)
const N_CM: usize = 2 * (3 * DIGEST_FELTS); // 24 : par entrée @31(4) + @32(4) + @47(4)
const N_LEAF: usize = 2 * (2 * DIGEST_FELTS); // 16 : par entrée @39(4) + @0(4)
const N_VIN: usize = 4; // 2× (prod @0 + conso VACC fin de bloc)
const N_VOUT: usize = 4; // 2× (prod @0 + conso VACC fin de bloc)
const N_LIAISON: usize = N_OWNER + N_NK + N_RHO + N_CM + N_LEAF + N_VIN + N_VOUT; // 88

const N_CONSTRAINTS: usize = N_BASE + N_LIAISON; // 171 + 88 = 259

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
/// KEY(16) + 2·U(28) + 2·M(8·depth+4) + 2·O(12) + BAL(2) = 106 + 16·depth.
fn num_assertions(depth: usize) -> usize {
    16 + 2 * 28 + 2 * (8 * depth + 4) + 2 * 12 + 2
}

impl winterfell::Air for MonolithAir {
    type BaseField = BaseElement;
    type PublicInputs = MonolithPublicInputs;

    fn new(trace_info: TraceInfo, pi: MonolithPublicInputs, options: ProofOptions) -> Self {
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
            // S_next − S − signe·bit·pow : le signe périodique PORTE le gating
            // (signe = 0 au-delà de la zone d'équilibre → S reste constant = fee).
            result[idx + 1] = s_next - s - signe * bit * pow;
            // VACC_next = (1 − endblk)·(VACC + bit·pow) : accumulation intra-bloc,
            // remise à zéro à la fin de chaque bloc (gaté sel_bal).
            result[idx + 2] = sel_bal * (vacc_next - (one - endblk) * (vacc + bit * pow));
            idx += N_BAL;
        }

        // --- Porteuses : constantes (next − cur = 0), NON gatées. ---
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

        // Équilibre : S[0] = 0, S[dernière ligne] = fee (= Σin − Σout).
        a.push(Assertion::single(BAL_OFF + BAL_S, 0, BaseElement::ZERO));
        a.push(Assertion::single(BAL_OFF + BAL_S, self.l - 1, BaseElement::new(self.pi.fee)));

        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let l = self.l;
        let z = BaseElement::ZERO;
        let o = BaseElement::ONE;
        let mut cols: Vec<Vec<BaseElement>> = Vec::with_capacity(37);

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

        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Assertions de préambule d'une éponge (capacité + VERSION/tag/LEN/PAD_ONE), à la
/// ligne `seg_start`, aux colonnes `col_off..col_off+20`. Positions issues de
/// `locate` DÉCALÉES par l'offset de colonne et la ligne de début de segment.
/// N'asserte AUCUN témoin (payload jamais public ici).
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
}

/// Degrés déclarés (BORNES SUPÉRIEURES, mode release), dans l'ORDRE de `result`.
///
/// Calibration (formule winterfell `base·(n−1) + Σ (n/cᵢ)·(cᵢ−1)`, contrainte de
/// blowup `next_pow2(base + |cycles| − 1) ≤ 16`) — `n = trace_len`, tout sélecteur
/// pleine longueur ajoute un cycle `n` (contribution `n−1`, coût de blowup +1) :
///  - KEY : ronde deg 7 × sel_key(n)               → base 7, cycles [n]      (blowup 8)
///  - U/O : ronde deg 7 × round_flag(8) × sel(n)    → base 7, cycles [8,n]    (blowup 8)
///  - M sponge : deg 8 × round_flag(16) × chain × sel_m(n) → base 8, [8,16,n] (blowup 16)
///  - M booléen/copies : deg 2 × sel_m(n)           → base 2, cycles [n]      (blowup 4)
///  - M swap : deg 3 × sel_m(n)                      → base 3, cycles [n]      (blowup 4)
///  - BAL bit : deg 2 × sel_bal(n)                   → base 2, cycles [n]      (blowup 4)
///  - BAL S : bit × signe(n) × pow(n)                → base 2, cycles [n,n]    (blowup 4)
///  - BAL VACC : bit × pow(n) × endblk(n) × sel_bal(n)→ base 2, cycles [n,n,n] (blowup 8)
///  - porteuses : next − cur                         → base 1                  (blowup 2)
///
/// La borne M-sponge (base 8, 3 cycles) sature EXACTEMENT le blowup 16 ; toutes les
/// autres sont en-dessous. Bornes supérieures ⇒ soundness préservée.
fn degrees(n: usize) -> Vec<TransitionConstraintDegree> {
    let wc = TransitionConstraintDegree::with_cycles;
    let mut d = Vec::with_capacity(N_CONSTRAINTS);

    // KEY (24).
    for _ in 0..N_KEY {
        d.push(wc(7, vec![n]));
    }
    // U0, U1, O0, O1 (4 × 12).
    for _ in 0..4 * N_SPONGE {
        d.push(wc(7, vec![8, n]));
    }
    // M0, M1 (2 × 30) : 12 sponge, 10 booléen/copies (deg 2), 8 swap (deg 3).
    for _ in 0..2 {
        for _ in 0..12 {
            d.push(wc(8, vec![8, 16, n]));
        }
        for _ in 0..10 {
            d.push(wc(2, vec![n]));
        }
        for _ in 0..8 {
            d.push(wc(3, vec![n]));
        }
    }
    // BAL (3).
    d.push(wc(2, vec![n])); // bit booléen
    d.push(wc(2, vec![n, n])); // accumulateur S
    d.push(wc(2, vec![n, n, n])); // accumulateur VACC
    // Porteuses (36).
    for _ in 0..N_CARRIER {
        d.push(TransitionConstraintDegree::new(1));
    }
    // Liaisons (88) : chacune `sel(cycle n) · (cur[a] − cur[b])` — degré 1, un cycle
    // pleine longueur (motif `wc(1, vec![n])` de key.rs). Blowup 16 : très en-dessous.
    for _ in 0..N_LIAISON {
        d.push(wc(1, vec![n]));
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

    /// LIAISON RHO (propriété v0.2 « nullifier lié au commitment ») : rho du nullifier
    /// ≠ rho du commitment → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_rho_mord() {
        assert!(!verdict_forge(Forge::RhoNullifier(0, dg(557))), "rho nf ≠ rho cm doit mordre");
    }

    /// LIAISON CM_IN (P1 non détournable) : feuille bâtie sur un autre commitment que
    /// celui produit par l'entrée → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace forgée : générer en --release")]
    fn liaison_cm_mord() {
        assert!(!verdict_forge(Forge::CmFeuille(0, dg(558))), "cm feuille ≠ cm produit doit mordre");
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
