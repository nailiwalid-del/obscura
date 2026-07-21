//! Chaînage de D merges de Merkle (3b2b, version intermédiaire).
//!
//! Prouve `root = fold(leaf, path, index)` : partant d'une feuille DÉJÀ hachée
//! (entrée publique), on remonte D niveaux, chaque niveau étant un
//! `merge(MerkleNode, swap(cur, sib_k, bit_k))` (bloc B=2, 16 lignes), la sortie du
//! niveau k devenant le `cur` du niveau k+1 (**chaînage inter-blocs**).
//!
//! ⚠️ **Ces preuves doivent être générées en mode RELEASE.** Le `debug_assert` de
//! degrés de winterfell est dépendant de l'entrée (colonnes témoins `bit`/`cur`
//! constantes pour certains index → degré mesuré 0), incompatible avec un contrat
//! de degrés fixe. En release, l'assert est ignoré ; on déclare des BORNES
//! SUPÉRIEURES (`déclaré ≥ mesuré`, calibrées sur le pire cas L=32/index varié), ce
//! qui préserve la soundness. Les tests de ce module sont `#[ignore]` en debug.
//!
//! Périmètre : D puissance de 2 (trace = 16·D). Feuille en circuit + profondeur 32
//! = 3b2b complet. validity-only.

// CONSENSUS : le monolithe réutilise `enforce_merkle_transition` et `path_rows`
// (+ les constantes de layout). L'AIR/prouveur standalone
// (`prove_merkle_path`/`verify_merkle_path`) est gaté `dev-circuits`.
#[cfg(feature = "dev-circuits")]
use crate::sponge::locate;
use crate::sponge::{
    enforce_sponge_transition, sponge_rows, INJECT_START, RATE_START, TRACE_WIDTH,
};
#[cfg(feature = "dev-circuits")]
use crate::ValidityProof;
use proved_hash::digest::{Digest, DIGEST_FELTS};
#[cfg(feature = "dev-circuits")]
use proved_hash::domain::ENCODING_VERSION;
use proved_hash::domain::{sponge_preamble, Domain};
use proved_hash::felt::Felt;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
#[cfg(feature = "dev-circuits")]
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
#[cfg(feature = "dev-circuits")]
use winterfell::matrix::ColMatrix;
#[cfg(feature = "dev-circuits")]
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain, Trace,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

#[cfg(feature = "dev-circuits")]
type Blake3 = Blake3_256<BaseElement>;

const BLOCK: usize = 16;
const WIDTH: usize = TRACE_WIDTH + 2 * DIGEST_FELTS + 1; // 29
const CUR_START: usize = TRACE_WIDTH; // 20
const SIB_START: usize = CUR_START + DIGEST_FELTS; // 24
const BIT_COL: usize = SIB_START + DIGEST_FELTS; // 28
#[cfg(feature = "dev-circuits")]
const MERGE_M: usize = 12;
#[cfg(feature = "dev-circuits")]
const MERGE_LEN: u64 = (2 * DIGEST_FELTS) as u64;

/// Contraintes de transition d'un merge de Merkle (sponge B=2 gaté `chain` + booléen
/// de bit + copies/chaînage des témoins + swap d'initialisation), écrites dans
/// `result[0..30]`. Lit un bloc de 29 colonnes (`cur`/`next` déjà tranchés au bon
/// offset). Extrait pour être RÉUTILISÉ tel quel par le monolithe (segment `M_i`,
/// re-gaté par un sélecteur d'activité) sans dupliquer la sémantique.
#[allow(clippy::too_many_arguments)] // scalaires périodiques explicites : plus clair que packer
pub(crate) fn enforce_merkle_transition<E: FieldElement + From<BaseElement>>(
    cur: &[E],
    next: &[E],
    round_flag: E,
    ark1: &[E],
    ark2: &[E],
    init0: E,
    init7: E,
    chain: E,
    result: &mut [E],
) {
    let one = E::ONE;

    enforce_sponge_transition(cur, next, round_flag, ark1, ark2, &mut result[..12]);
    for r in result.iter_mut().take(12) {
        *r *= one - chain;
    }

    let bit = cur[BIT_COL];
    let cur_d: [E; 4] = core::array::from_fn(|i| cur[CUR_START + i]);
    let sib_d: [E; 4] = core::array::from_fn(|i| cur[SIB_START + i]);
    let left = |i: usize| cur_d[i] + bit * (sib_d[i] - cur_d[i]);
    let right = |i: usize| sib_d[i] + bit * (cur_d[i] - sib_d[i]);

    result[12] = bit * (bit - one);

    for i in 0..4 {
        let copy = next[CUR_START + i] - cur[CUR_START + i];
        let chained = next[CUR_START + i] - cur[RATE_START + i];
        result[13 + i] = (one - chain) * copy + chain * chained;
    }
    for i in 0..4 {
        result[17 + i] = (one - chain) * (next[SIB_START + i] - cur[SIB_START + i]);
    }
    result[21] = (one - chain) * (next[BIT_COL] - cur[BIT_COL]);

    for i in 0..4 {
        result[22 + i] = init0 * (cur[RATE_START + 3 + i] - left(i));
    }
    result[26] = init0 * (cur[RATE_START + 7] - right(0));
    for j in 0..3 {
        result[27 + j] = init7 * (cur[INJECT_START + j] - right(1 + j));
    }
}

/// Lignes de la trace de chaînage (état sponge + témoins `cur`/`sib`/`bit`), sans
/// passer par une `TraceTable` — réutilisé tel quel par le monolithe (3z-a2) pour
/// recopier un segment `M_i` aux colonnes du layout global.
pub(crate) fn path_rows(leaf: &Digest, path: &[Digest], index: u64) -> Vec<[BaseElement; WIDTH]> {
    let l = path.len() * BLOCK;
    assert!(
        l.is_power_of_two(),
        "3b2b intermédiaire : 16·D doit être une puissance de 2"
    );

    let mut rows = vec![[BaseElement::ZERO; WIDTH]; l];
    let mut cur = *leaf;

    for (b, sib) in path.iter().enumerate() {
        let bit = (index >> b) & 1 == 1;
        let (left, right) = if bit { (sib, &cur) } else { (&cur, sib) };
        let mut payload = Vec::with_capacity(2 * DIGEST_FELTS);
        payload.extend_from_slice(&left.0);
        payload.extend_from_slice(&right.0);
        let preamble: Vec<BaseElement> = sponge_preamble(Domain::MerkleNode, &payload)
            .iter()
            .map(|f| f.to_winter())
            .collect();
        let sp_rows = sponge_rows(&preamble);

        let cur_be: [BaseElement; 4] = core::array::from_fn(|i| cur.0[i].to_winter());
        let sib_be: [BaseElement; 4] = core::array::from_fn(|i| sib.0[i].to_winter());
        let bit_be = if bit {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        };

        for (r, sr) in sp_rows.iter().enumerate() {
            let row = &mut rows[b * BLOCK + r];
            row[..TRACE_WIDTH].copy_from_slice(sr);
            row[CUR_START..CUR_START + 4].copy_from_slice(&cur_be);
            row[SIB_START..SIB_START + 4].copy_from_slice(&sib_be);
            row[BIT_COL] = bit_be;
        }

        let last = b * BLOCK + BLOCK - 1;
        cur = Digest(core::array::from_fn(|i| {
            Felt::from_winter(rows[last][RATE_START + i]).expect("digest canonique")
        }));
    }

    rows
}

#[cfg(feature = "dev-circuits")]
fn build_path_trace(leaf: &Digest, path: &[Digest], index: u64) -> TraceTable<BaseElement> {
    let rows = path_rows(leaf, path, index);
    let mut trace = TraceTable::new(WIDTH, rows.len());
    for (i, row) in rows.iter().enumerate() {
        trace.update_row(i, row);
    }
    trace
}

#[cfg(feature = "dev-circuits")]
#[derive(Clone)]
pub struct MerklePathPublicInputs {
    pub leaf: [BaseElement; DIGEST_FELTS],
    pub root: [BaseElement; DIGEST_FELTS],
    pub depth: usize,
}

#[cfg(feature = "dev-circuits")]
impl winterfell::math::ToElements<BaseElement> for MerklePathPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(1 + 2 * DIGEST_FELTS);
        v.push(BaseElement::new(self.depth as u64));
        v.extend_from_slice(&self.leaf);
        v.extend_from_slice(&self.root);
        v
    }
}

#[cfg(feature = "dev-circuits")]
pub struct MerklePathAir {
    context: AirContext<BaseElement>,
    pi: MerklePathPublicInputs,
    l: usize,
}

#[cfg(feature = "dev-circuits")]
impl winterfell::Air for MerklePathAir {
    type BaseField = BaseElement;
    type PublicInputs = MerklePathPublicInputs;

    fn new(trace_info: TraceInfo, pi: MerklePathPublicInputs, options: ProofOptions) -> Self {
        // BORNES SUPÉRIEURES (mode release) — calibrées sur le pire cas mesuré :
        // sponge ≤ 245, booléen/copies ≤ 31, swap ≤ 61 à L=32.
        let mut degrees = Vec::with_capacity(30);
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(8, vec![8, BLOCK]));
            // → 275 ≥ 245
        }
        degrees.push(TransitionConstraintDegree::new(2)); // booléen → 31 ≥ 31
        for _ in 0..9 {
            degrees.push(TransitionConstraintDegree::new(2)); // copies → 31
        }
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(3)); // swap → 62 ≥ 61
        }
        let l = trace_info.length();
        let num_assertions = 8 * pi.depth + 2 * DIGEST_FELTS;
        MerklePathAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pi,
            l,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let round_flag = periodic_values[0];
        let ark1 = &periodic_values[1..13];
        let ark2 = &periodic_values[13..25];
        let init0 = periodic_values[25];
        let init7 = periodic_values[26];
        let chain = periodic_values[27];
        enforce_merkle_transition(
            frame.current(),
            frame.next(),
            round_flag,
            ark1,
            ark2,
            init0,
            init7,
            chain,
            result,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(self.context.num_assertions());
        let put =
            |a: &mut Vec<Assertion<BaseElement>>, row: usize, col: usize, val: BaseElement| {
                a.push(Assertion::single(col, row, val));
            };
        for b in 0..self.pi.depth {
            let base = b * BLOCK;
            put(&mut a, base, 0, BaseElement::new(MERGE_M as u64));
            put(&mut a, base, 1, BaseElement::ZERO);
            put(&mut a, base, 2, BaseElement::ZERO);
            put(&mut a, base, 3, BaseElement::ZERO);
            for (idx, val) in [
                (0usize, ENCODING_VERSION as u64),
                (1, Domain::MerkleNode.tag() as u64),
                (2, MERGE_LEN),
                (MERGE_M - 1, 1),
            ] {
                let (row, col) = locate(idx);
                put(&mut a, base + row, col, BaseElement::new(val));
            }
        }
        for i in 0..DIGEST_FELTS {
            put(&mut a, 0, CUR_START + i, self.pi.leaf[i]);
            put(&mut a, self.l - 1, RATE_START + i, self.pi.root[i]);
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let l = self.l;
        let z = BaseElement::ZERO;
        let o = BaseElement::ONE;
        let round_flag: Vec<BaseElement> = (0..l)
            .map(|r| {
                let p = r % BLOCK;
                if p == 7 || p == 15 {
                    z
                } else {
                    o
                }
            })
            .collect();
        let mut cols = Vec::with_capacity(30);
        cols.push(round_flag);
        cols.extend(crate::rescue_round::periodic_ark_columns());
        let init0: Vec<BaseElement> = (0..l).map(|r| if r % BLOCK == 0 { o } else { z }).collect();
        let init7: Vec<BaseElement> = (0..l).map(|r| if r % BLOCK == 7 { o } else { z }).collect();
        let chain: Vec<BaseElement> = (0..l)
            .map(|r| {
                if r % BLOCK == BLOCK - 1 && r + 1 < l {
                    o
                } else {
                    z
                }
            })
            .collect();
        cols.push(init0);
        cols.push(init7);
        cols.push(chain);
        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

#[cfg(feature = "dev-circuits")]
struct MerklePathProver {
    options: ProofOptions,
    pi: MerklePathPublicInputs,
}

#[cfg(feature = "dev-circuits")]
impl Prover for MerklePathProver {
    type BaseField = BaseElement;
    type Air = MerklePathAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MerklePathPublicInputs {
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

/// Prouve `root = fold(leaf, path, index)`. À GÉNÉRER EN MODE RELEASE (voir en-tête).
#[cfg(feature = "dev-circuits")]
pub fn prove_merkle_path(leaf: &Digest, path: &[Digest], index: u64) -> (Digest, ValidityProof) {
    let trace = build_path_trace(leaf, path, index);
    let last = trace.length() - 1;
    let root = Digest(core::array::from_fn(|i| {
        Felt::from_winter(trace.get(RATE_START + i, last)).expect("digest canonique")
    }));
    let pi = MerklePathPublicInputs {
        leaf: core::array::from_fn(|i| leaf.0[i].to_winter()),
        root: core::array::from_fn(|i| root.0[i].to_winter()),
        depth: path.len(),
    };
    let prover = MerklePathProver {
        options: crate::proof_options_hi(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (root, ValidityProof(proof))
}

/// Vérifie une preuve de chaînage contre `leaf`/`root` publics.
#[cfg(feature = "dev-circuits")]
pub fn verify_merkle_path(
    leaf: &Digest,
    root: &Digest,
    depth: usize,
    proof: &ValidityProof,
) -> bool {
    let pi = MerklePathPublicInputs {
        leaf: core::array::from_fn(|i| leaf.0[i].to_winter()),
        root: core::array::from_fn(|i| root.0[i].to_winter()),
        depth,
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<MerklePathAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pi,
        &acceptable,
    )
    .is_ok()
}

// Tests gatés en bloc : les différentiels appellent `prove_merkle_path`, et la
// sanité de trace passe par `build_path_trace` (apparatus standalone).
#[cfg(all(test, feature = "dev-circuits"))]
mod tests {
    use super::*;
    use proved_hash::merkle;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// D=2 : chaînage inter-blocs + bits distincts. `--release` requis (voir en-tête).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn chaine_d2_differentiel() {
        let leaf = digest(7);
        let path = [digest(100), digest(200)];
        for index in [0b00u64, 0b01, 0b10, 0b11] {
            let (root, proof) = prove_merkle_path(&leaf, &path, index);
            assert_eq!(root, merkle::fold(&leaf, &path, index), "index={index:#b}");
            assert!(verify_merkle_path(&leaf, &root, path.len(), &proof));
        }
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn racine_alteree_rejetee() {
        let leaf = digest(3);
        let path = [digest(30), digest(40)];
        let (root, proof) = prove_merkle_path(&leaf, &path, 0b10);
        assert!(verify_merkle_path(&leaf, &root, path.len(), &proof));
        let mut faux = root;
        faux.0[0] = Felt::from_canonical_u64(faux.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_merkle_path(&leaf, &faux, path.len(), &proof));
    }

    /// Sanité (debug OK) : la TRACE calcule la bonne racine (chaînage correct),
    /// indépendamment du prouveur.
    #[test]
    fn trace_calcule_bonne_racine() {
        let leaf = digest(7);
        let path = [digest(100), digest(200)];
        for index in [0b00u64, 0b01, 0b10, 0b11] {
            let trace = build_path_trace(&leaf, &path, index);
            let last = trace.length() - 1;
            let root = Digest(core::array::from_fn(|i| {
                Felt::from_winter(trace.get(RATE_START + i, last)).unwrap()
            }));
            assert_eq!(root, merkle::fold(&leaf, &path, index), "index={index:#b}");
        }
    }
}
