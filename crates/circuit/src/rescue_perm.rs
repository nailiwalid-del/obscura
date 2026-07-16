//! AIR de la permutation Rescue-Prime Rp64_256 (validity skeleton, 3a2).
//!
//! Statement : « je connais un état d'entrée S tel que apply_permutation(S) = P »,
//! avec P public et S témoin. S n'apparaît PAS dans les assertions publiques.
//!
//! Note : une permutation étant bijective, ce statement est trivial — c'est assumé.
//! Son rôle est de valider la chaîne AIR/prouveur/vérifieur et la contrainte de
//! ronde contre le vecteur de référence Sage. Le vrai P2 (non inversible) est dans
//! `owner_hash` (3a2b).
//!
//! La contrainte de ronde elle-même vit dans [`crate::rescue_round`].

use crate::rescue_round::{
    build_perm_trace, enforce_round, periodic_ark_columns, transition_degrees, STATE_WIDTH,
};
use crate::ValidityProof;
use proved_hash::felt::Felt;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain, Trace,
    TraceInfo, TracePolyTable, TraceTable,
};

type Blake3 = Blake3_256<BaseElement>;

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
        RescuePermAir {
            context: AirContext::new(trace_info, transition_degrees(), STATE_WIDTH, options),
            output: pub_inputs.output,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        enforce_round(frame, periodic_values, result);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // SEULE la sortie (dernière ligne) est publique. La ligne 0 (le témoin)
        // n'est PAS assertée.
        let last = self.trace_length() - 1;
        (0..STATE_WIDTH)
            .map(|i| Assertion::single(i, last, self.output[i]))
            .collect()
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        periodic_ark_columns()
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

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

/// Prouve la connaissance d'un état d'entrée dont la permutation vaut la sortie retournée.
pub fn prove_permutation(input: [Felt; STATE_WIDTH]) -> ([Felt; STATE_WIDTH], ValidityProof) {
    let input_be: [BaseElement; STATE_WIDTH] = core::array::from_fn(|i| input[i].to_winter());
    let trace = build_perm_trace(input_be);

    let last = trace.length() - 1;
    let output: [Felt; STATE_WIDTH] =
        core::array::from_fn(|i| Felt::from_winter(trace.get(i, last)).expect("sortie canonique"));

    let prover = RescuePermProver {
        options: crate::proof_options(),
    };
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
    use winter_crypto::hashers::Rp64_256;

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
        assert!(verify_permutation(output, &proof), "roundtrip doit être vert");
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
