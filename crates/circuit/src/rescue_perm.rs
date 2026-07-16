//! AIR de la permutation Rescue-Prime Rp64_256 (validity skeleton, 3a2).
//!
//! Statement : « je connais un état d'entrée S tel que apply_permutation(S) = P »,
//! avec P public et S témoin. S n'apparaît PAS dans les assertions publiques.
//!
//! Contrainte de ronde (meet-in-the-middle, cf. exemple `rescue` de winterfell) :
//! une ronde Rescue-XLIX est `sbox -> MDS -> +ARK1` puis `inv_sbox -> MDS -> +ARK2`.
//! L'inverse S-box est de degré prohibitif, donc on ne l'évalue jamais : on va en
//! AVANT depuis l'état courant et en ARRIÈRE depuis l'état suivant, et on impose
//! l'égalité au point milieu :
//!   forward  : step1 = MDS·sbox(current) + ARK1
//!   backward : step2 = sbox( INV_MDS·(next − ARK2) )
//!   contrainte : step1 == step2      (degré ALPHA = 7)
//!
//! Les constantes (MDS, INV_MDS, ARK1, ARK2, ALPHA) sont celles, publiques, de
//! `winter_crypto::hashers::Rp64_256` → aucune divergence possible avec le hash
//! hors-circuit de 3a1. Le garde-fou est le différentiel contre le vecteur Sage.

use proved_hash::felt::Felt;
use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    Trace, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

/// Largeur d'état de Rp64_256.
pub const STATE_WIDTH: usize = 12;
/// Nombre de rondes de Rp64_256.
pub const NUM_ROUNDS: usize = 7;
/// Longueur de trace : un état par ronde + l'état initial, arrondi à une puissance de 2.
pub const TRACE_LEN: usize = 8;
/// Exposant de la S-box.
const ALPHA: u32 = 7;

type Blake3 = Blake3_256<BaseElement>;

// ================================================================================================
// HELPERS DE CONTRAINTE (génériques sur le corps d'évaluation)
// ================================================================================================

fn apply_sbox<E: FieldElement>(state: &mut [E; STATE_WIDTH]) {
    for s in state.iter_mut() {
        *s = s.exp(ALPHA.into());
    }
}

fn apply_matrix<E: FieldElement + From<BaseElement>>(
    state: &mut [E; STATE_WIDTH],
    m: &[[BaseElement; STATE_WIDTH]; STATE_WIDTH],
) {
    let mut out = [E::ZERO; STATE_WIDTH];
    for (i, out_i) in out.iter_mut().enumerate() {
        let mut acc = E::ZERO;
        for (j, s_j) in state.iter().enumerate() {
            acc += E::from(m[i][j]) * *s_j;
        }
        *out_i = acc;
    }
    *state = out;
}

// ================================================================================================
// TRACE
// ================================================================================================

/// Construit la trace : ligne 0 = entrée, ligne i+1 = état après la ronde i.
pub fn build_trace(input: [BaseElement; STATE_WIDTH]) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(STATE_WIDTH, TRACE_LEN);
    trace.fill(
        |state| {
            state.copy_from_slice(&input);
        },
        |step, state| {
            // `fill` appelle cette closure pour step = 0..TRACE_LEN-2, soit les 7 rondes.
            if step < NUM_ROUNDS {
                let mut s: [BaseElement; STATE_WIDTH] =
                    state.try_into().expect("largeur d'état");
                Rp64_256::apply_round(&mut s, step);
                state.copy_from_slice(&s);
            }
        },
    );
    trace
}

// ================================================================================================
// AIR
// ================================================================================================

#[derive(Clone)]
pub struct PublicInputs {
    pub output: [BaseElement; STATE_WIDTH],
}

impl winterfell::math::ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.output.to_vec()
    }
}

pub struct RescuePermAir {
    context: AirContext<BaseElement>,
    output: [BaseElement; STATE_WIDTH],
}

impl winterfell::Air for RescuePermAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // Une contrainte par élément d'état, de degré ALPHA.
        //
        // Pas de `with_cycles` ici : les ARK n'introduisent pas de facteur périodique
        // MULTIPLICATIF (contrairement au `flag` de l'exemple `rescue`). Elles sont
        // additionnées à l'intérieur de la S-box — `(next − ARK2)` reste de degré 1 en
        // trace/périodique, et c'est l'élévation `^ALPHA` qui fixe le degré total.
        let degrees = vec![TransitionConstraintDegree::new(ALPHA as usize); STATE_WIDTH];
        RescuePermAir {
            context: AirContext::new(trace_info, degrees, STATE_WIDTH, options),
            output: pub_inputs.output,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let ark1 = &periodic_values[..STATE_WIDTH];
        let ark2 = &periodic_values[STATE_WIDTH..];

        // forward : step1 = MDS·sbox(current) + ARK1
        let mut step1 = [E::ZERO; STATE_WIDTH];
        step1.copy_from_slice(current);
        apply_sbox(&mut step1);
        apply_matrix(&mut step1, &Rp64_256::MDS);
        for i in 0..STATE_WIDTH {
            step1[i] += ark1[i];
        }

        // backward : step2 = sbox(INV_MDS·(next − ARK2))
        let mut step2 = [E::ZERO; STATE_WIDTH];
        step2.copy_from_slice(next);
        for i in 0..STATE_WIDTH {
            step2[i] -= ark2[i];
        }
        apply_matrix(&mut step2, &Rp64_256::INV_MDS);
        apply_sbox(&mut step2);

        for i in 0..STATE_WIDTH {
            result[i] = step2[i] - step1[i];
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // SEULE la sortie (dernière ligne) est publique. La ligne 0 (le témoin)
        // n'est PAS assertée : le secret ne doit jamais entrer dans les entrées publiques.
        let last = self.trace_length() - 1;
        (0..STATE_WIDTH)
            .map(|i| Assertion::single(i, last, self.output[i]))
            .collect()
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // 24 colonnes : ARK1[0..12] puis ARK2[0..12]. Cycle de TRACE_LEN ; les rondes
        // 0..6 portent les constantes, la dernière entrée n'est jamais utilisée
        // (pas de transition depuis la dernière ligne).
        let mut cols = Vec::with_capacity(2 * STATE_WIDTH);
        for i in 0..STATE_WIDTH {
            let mut c = vec![BaseElement::ZERO; TRACE_LEN];
            for (r, c_r) in c.iter_mut().enumerate().take(NUM_ROUNDS) {
                *c_r = Rp64_256::ARK1[r][i];
            }
            cols.push(c);
        }
        for i in 0..STATE_WIDTH {
            let mut c = vec![BaseElement::ZERO; TRACE_LEN];
            for (r, c_r) in c.iter_mut().enumerate().take(NUM_ROUNDS) {
                *c_r = Rp64_256::ARK2[r][i];
            }
            cols.push(c);
        }
        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ================================================================================================
// PROVER
// ================================================================================================

struct RescuePermProver {
    options: ProofOptions,
}

impl Prover for RescuePermProver {
    type BaseField = BaseElement;
    type Air = RescuePermAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last = trace.length() - 1;
        let mut output = [BaseElement::ZERO; STATE_WIDTH];
        for (i, o) in output.iter_mut().enumerate() {
            *o = trace.get(i, last);
        }
        PublicInputs { output }
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
// API PUBLIQUE
// ================================================================================================

/// Preuve de VALIDITÉ (intégrité). **Pas** witness-hiding — voir l'avertissement du crate.
pub struct ValidityProof(pub Proof);

fn proof_options() -> ProofOptions {
    // Paramètres de prototype visant >= 95 bits de sécurité conjecturée.
    //
    // IMPORTANT : Goldilocks est un corps de 64 bits — SANS extension, la sécurité
    // plafonne à ~63 bits (winterfell rejette alors la preuve). L'extension
    // quadratique (~128 bits) est donc obligatoire ici, pas une optimisation.
    ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::Quadratic,
        8,
        127,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

/// Prouve la connaissance d'un état d'entrée dont la permutation vaut la sortie retournée.
pub fn prove_permutation(input: [Felt; STATE_WIDTH]) -> ([Felt; STATE_WIDTH], ValidityProof) {
    let input_be: [BaseElement; STATE_WIDTH] = core::array::from_fn(|i| input[i].to_winter());
    let trace = build_trace(input_be);

    let last = trace.length() - 1;
    let output: [Felt; STATE_WIDTH] =
        core::array::from_fn(|i| Felt::from_winter(trace.get(i, last)).expect("sortie canonique"));

    let prover = RescuePermProver { options: proof_options() };
    let proof = prover.prove(trace).expect("génération de preuve");
    (output, ValidityProof(proof))
}

/// Vérifie une preuve contre la sortie publique.
pub fn verify_permutation(output: [Felt; STATE_WIDTH], proof: &ValidityProof) -> bool {
    let pub_inputs = PublicInputs {
        output: core::array::from_fn(|i| output[i].to_winter()),
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<RescuePermAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pub_inputs,
        &acceptable,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteur de l'implémentation de référence Sage (via les tests winter-crypto) :
    /// apply_permutation([0..11]). C'est LE garde-fou du différentiel natif ⟷ circuit.
    const SAGE: [u64; STATE_WIDTH] = [
        11084501481526603421,
        6291559951628160880,
        13626645864671311919,
        18397438323058963117,
        7443014167353970324,
        17930833023906771425,
        4275355080008025761,
        7676681476902901785,
        3460534574143792217,
        11912731278641497187,
        8104899243369883110,
        674509706691634438,
    ];

    fn felts(f: impl Fn(usize) -> u64) -> [Felt; STATE_WIDTH] {
        core::array::from_fn(|i| Felt::from_canonical_u64(f(i)).unwrap())
    }

    #[test]
    fn differentiel_sage() {
        let input = felts(|i| i as u64);
        let (output, proof) = prove_permutation(input);
        for i in 0..STATE_WIDTH {
            assert_eq!(output[i].as_u64(), SAGE[i], "divergence à l'indice {i}");
        }
        assert!(verify_permutation(output, &proof));
    }

    #[test]
    fn output_altere_rejete() {
        let input = felts(|i| i as u64 + 1);
        let (mut output, proof) = prove_permutation(input);
        output[0] = Felt::from_canonical_u64(output[0].as_u64() ^ 1).unwrap();
        assert!(!verify_permutation(output, &proof));
    }

    #[test]
    fn coherence_avec_winter() {
        for seed in [1u64, 42, 1000] {
            let input = felts(|i| seed + i as u64);
            let (output, _) = prove_permutation(input);
            let mut st: [BaseElement; STATE_WIDTH] =
                core::array::from_fn(|i| BaseElement::new(seed + i as u64));
            Rp64_256::apply_permutation(&mut st);
            for i in 0..STATE_WIDTH {
                assert_eq!(output[i], Felt::from_winter(st[i]).unwrap());
            }
        }
    }
}
