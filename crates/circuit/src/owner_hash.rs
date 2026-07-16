//! P2 en circuit : `owner = H_owner(shielded_secret)` (3a2b).
//!
//! Réplique le sponge de `Rp64_256::hash_elements` : la longueur absorbée est
//! injectée dans la CAPACITÉ (winter n'utilise aucun padding), puis le bloc de rate
//! est absorbé et une permutation est appliquée.
//!
//! Le préambule 3a0 `sponge_preamble(Owner, secret)` fait exactement 8 éléments
//! (= 1 bloc de rate, `RATE = 4..12`), donc P2 se réduit à **UNE** permutation, et
//! `owner = état[4..8]` (`DIGEST = 4..8`) après les 7 rondes.
//!
//! ⚠️ validity-only : la preuve établit l'intégrité, PAS la confidentialité.

use crate::rescue_round::{
    build_perm_trace, enforce_round, periodic_ark_columns, transition_degrees, STATE_WIDTH,
};
use crate::ValidityProof;
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_FELTS};
use proved_hash::domain::{Domain, ENCODING_VERSION};
use proved_hash::felt::Felt;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain, Trace,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

type Blake3 = Blake3_256<BaseElement>;

/// Nombre d'éléments absorbés = taille du préambule `[VERSION, tag, LEN, s0..s3, PAD_ONE]`.
const ABSORBED_LEN: u64 = 8;
/// Nombre de Felts du payload (le secret).
const PAYLOAD_LEN: u64 = DIGEST_FELTS as u64;
/// Début de la portion rate de l'état (winter : `RATE_RANGE = 4..12`).
const RATE_START: usize = 4;
/// Indice du premier Felt du secret dans l'état initial.
const SECRET_START: usize = RATE_START + 3; // après VERSION, tag, LEN
/// Indice de PAD_ONE (dernier élément du bloc de rate).
const PAD_ONE_IDX: usize = 11;

/// État initial du sponge pour `H_owner(secret)`.
///
/// Capacité : `[ABSORBED_LEN, 0, 0, 0]` — winter injecte la longueur ici AU LIEU
/// d'un padding. Rate : le préambule 3a0.
fn initial_state(secret: &[Felt; DIGEST_FELTS]) -> [BaseElement; STATE_WIDTH] {
    let mut st = [BaseElement::ZERO; STATE_WIDTH];
    st[0] = BaseElement::new(ABSORBED_LEN);
    st[RATE_START] = BaseElement::new(ENCODING_VERSION as u64);
    st[RATE_START + 1] = BaseElement::new(Domain::Owner.tag() as u64);
    st[RATE_START + 2] = BaseElement::new(PAYLOAD_LEN);
    for (i, s) in secret.iter().enumerate() {
        st[SECRET_START + i] = s.to_winter();
    }
    st[PAD_ONE_IDX] = BaseElement::new(1); // PAD_ONE
    st
}

// ================================================================================================
// AIR
// ================================================================================================

#[derive(Clone)]
pub struct OwnerPublicInputs {
    pub owner: [BaseElement; DIGEST_FELTS],
}

impl winterfell::math::ToElements<BaseElement> for OwnerPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.owner.to_vec()
    }
}

pub struct OwnerAir {
    context: AirContext<BaseElement>,
    owner: [BaseElement; DIGEST_FELTS],
}

impl winterfell::Air for OwnerAir {
    type BaseField = BaseElement;
    type PublicInputs = OwnerPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: OwnerPublicInputs, options: ProofOptions) -> Self {
        let degrees: Vec<TransitionConstraintDegree> = transition_degrees();
        // 8 assertions sur l'état initial (constantes publiques) + 4 sur le digest.
        let num_assertions = 8 + DIGEST_FELTS;
        OwnerAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            owner: pub_inputs.owner,
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
        let last = self.trace_length() - 1;
        let mut a = Vec::with_capacity(8 + DIGEST_FELTS);

        // --- Ligne 0 : UNIQUEMENT des constantes PUBLIQUES ---
        // Capacité : longueur absorbée puis zéros.
        a.push(Assertion::single(0, 0, BaseElement::new(ABSORBED_LEN)));
        for i in 1..RATE_START {
            a.push(Assertion::single(i, 0, BaseElement::ZERO));
        }
        // Préambule de domaine.
        a.push(Assertion::single(
            RATE_START,
            0,
            BaseElement::new(ENCODING_VERSION as u64),
        ));
        a.push(Assertion::single(
            RATE_START + 1,
            0,
            BaseElement::new(Domain::Owner.tag() as u64),
        ));
        a.push(Assertion::single(
            RATE_START + 2,
            0,
            BaseElement::new(PAYLOAD_LEN),
        ));
        a.push(Assertion::single(PAD_ONE_IDX, 0, BaseElement::new(1)));
        // NOTE : les indices SECRET_START..SECRET_START+4 (le shielded_secret) ne sont
        // VOLONTAIREMENT pas assertés — le témoin ne doit jamais devenir public.

        // --- Ligne finale : le digest public ---
        for (i, o) in self.owner.iter().enumerate() {
            a.push(Assertion::single(RATE_START + i, last, *o));
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        periodic_ark_columns()
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ================================================================================================
// PROVER
// ================================================================================================

struct OwnerProver {
    options: ProofOptions,
}

impl Prover for OwnerProver {
    type BaseField = BaseElement;
    type Air = OwnerAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> OwnerPublicInputs {
        let last = trace.length() - 1;
        let mut owner = [BaseElement::ZERO; DIGEST_FELTS];
        for (i, o) in owner.iter_mut().enumerate() {
            *o = trace.get(RATE_START + i, last);
        }
        OwnerPublicInputs { owner }
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

/// Prouve **P2** : connaissance d'un `shielded_secret` dont l'identité est `owner`.
///
/// Le secret reste dans la trace témoin ; il n'apparaît dans aucune entrée publique.
pub fn prove_owner(secret: &ShieldedSecret) -> (Digest, ValidityProof) {
    let trace = build_perm_trace(initial_state(secret.as_felts()));

    let last = trace.length() - 1;
    let owner_felts: [Felt; DIGEST_FELTS] = core::array::from_fn(|i| {
        Felt::from_winter(trace.get(RATE_START + i, last)).expect("digest canonique")
    });

    let prover = OwnerProver {
        options: crate::proof_options(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (Digest(owner_felts), ValidityProof(proof))
}

/// Vérifie une preuve P2 contre l'identité publique `owner`.
pub fn verify_owner(owner: &Digest, proof: &ValidityProof) -> bool {
    let pub_inputs = OwnerPublicInputs {
        owner: core::array::from_fn(|i| owner.0[i].to_winter()),
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<OwnerAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pub_inputs,
        &acceptable,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::rescue;

    fn secret(seed: u64) -> ShieldedSecret {
        ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// LE différentiel natif ⟷ circuit sur le vrai P2 : le circuit doit calculer
    /// exactement le même owner que le hash hors-circuit de 3a1.
    #[test]
    fn differentiel_owner_vs_rescue_hash() {
        let s = secret(1000);
        let (owner, proof) = prove_owner(&s);
        let attendu = rescue::hash(Domain::Owner, s.as_felts());
        assert_eq!(owner, attendu, "le circuit diverge du hash hors-circuit");
        // roundtrip : écarte le faux positif du test négatif ci-dessous.
        assert!(verify_owner(&owner, &proof));
    }

    #[test]
    fn owner_altere_rejete() {
        let s = secret(7);
        let (owner, proof) = prove_owner(&s);
        assert!(verify_owner(&owner, &proof), "roundtrip doit être vert");
        let mut altere = owner;
        altere.0[0] = Felt::from_canonical_u64(altere.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_owner(&altere, &proof));
    }

    #[test]
    fn secrets_distincts_donnent_owners_distincts() {
        let (a, _) = prove_owner(&secret(1));
        let (b, _) = prove_owner(&secret(2));
        assert_ne!(a, b);
    }
}
