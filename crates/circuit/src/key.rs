//! 3b5a — Preuve de clé : `owner = H_owner(s)` ET `nk = H_nk(s)` pour LE MÊME
//! `shielded_secret` s, prouvés dans UNE trace (P2 ∧ P4 liés).
//!
//! **Pourquoi une seule trace.** La composition de `prove_owner` et `prove_nk`
//! séparés ne force PAS le même secret (deux témoins indépendants `s₁`, `s₂`), et
//! rendre `s` public est exclu (secret maître). La liaison « même s » n'est donc
//! sound que si les deux dérivations partagent les cellules du secret dans une trace
//! commune. C'est le premier circuit d'action de l'assemblage 3b5 (cf.
//! `docs/superpowers/specs/2026-07-19-3b5a-key-proof-design.md`).
//!
//! **Disposition.** Deux éponges B=1 côte à côte : bloc owner (colonnes `0..12`),
//! bloc nk (colonnes `12..24`), longueur 8 (une permutation, comme 3a2b). Même
//! ordonnancement de rondes (ARK périodiques partagés) ; seuls les tags de domaine
//! diffèrent. Une contrainte de transition **gatée à la ligne 0** impose l'égalité
//! des 4 cellules du secret entre les deux blocs — c'est la liaison.
//!
//! ⚠️ validity-only : `owner`/`nk` sont publics, seul `s` est témoin (jamais asserté).

use crate::rescue_round::{
    apply_matrix, apply_sbox, periodic_ark_columns, NUM_ROUNDS, STATE_WIDTH, TRACE_LEN,
};
use crate::ValidityProof;
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_FELTS};
use proved_hash::domain::{Domain, ENCODING_VERSION};
use proved_hash::felt::Felt;
use winter_crypto::hashers::Rp64_256;
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

const ABSORBED_LEN: u64 = 8; // préambule [V, tag, LEN, s0..s3, PAD_ONE] = 1 bloc
const PAYLOAD_LEN: u64 = DIGEST_FELTS as u64;
const RATE_START: usize = 4;
const SECRET_START: usize = RATE_START + 3; // s0..s3 aux colonnes 7,8,9,10
const PAD_ONE_IDX: usize = 11;
const NK_OFF: usize = STATE_WIDTH; // décalage du bloc nk (colonnes 12..24)
const WIDTH: usize = 2 * STATE_WIDTH; // 24
const N_BIND: usize = DIGEST_FELTS; // 4 contraintes de liaison

/// État initial d'un bloc pour `H_domain(secret)` (capacité + préambule 3a0).
fn initial_state(domain: Domain, secret: &[Felt; DIGEST_FELTS]) -> [BaseElement; STATE_WIDTH] {
    let mut st = [BaseElement::ZERO; STATE_WIDTH];
    st[0] = BaseElement::new(ABSORBED_LEN);
    st[RATE_START] = BaseElement::new(ENCODING_VERSION as u64);
    st[RATE_START + 1] = BaseElement::new(domain.tag() as u64);
    st[RATE_START + 2] = BaseElement::new(PAYLOAD_LEN);
    for (i, s) in secret.iter().enumerate() {
        st[SECRET_START + i] = s.to_winter();
    }
    st[PAD_ONE_IDX] = BaseElement::new(1);
    st
}

/// Construit la trace largeur 24 : bloc owner (`s_owner`) + bloc nk (`s_nk`) côte à
/// côte. Pour une preuve VALIDE, `s_owner == s_nk` (la liaison l'exige) ; le
/// paramètre séparé sert uniquement au test négatif de liaison.
fn build_key_trace(
    s_owner: &[Felt; DIGEST_FELTS],
    s_nk: &[Felt; DIGEST_FELTS],
) -> TraceTable<BaseElement> {
    let mut o = initial_state(Domain::Owner, s_owner);
    let mut n = initial_state(Domain::Nk, s_nk);
    let mut trace = TraceTable::new(WIDTH, TRACE_LEN);
    for step in 0..TRACE_LEN {
        let mut row = [BaseElement::ZERO; WIDTH];
        row[..STATE_WIDTH].copy_from_slice(&o);
        row[NK_OFF..].copy_from_slice(&n);
        trace.update_row(step, &row);
        if step < NUM_ROUNDS {
            Rp64_256::apply_round(&mut o, step);
            Rp64_256::apply_round(&mut n, step);
        }
    }
    trace
}

/// Impose une ronde Rescue sur le bloc d'état à l'offset `off` (meet-in-the-middle,
/// cf. `rescue_round`), écrivant dans `result[off..off+12]`.
fn enforce_round_block<E: FieldElement + From<BaseElement>>(
    cur: &[E],
    next: &[E],
    off: usize,
    ark1: &[E],
    ark2: &[E],
    result: &mut [E],
) {
    let mut step1: [E; STATE_WIDTH] = core::array::from_fn(|i| cur[off + i]);
    apply_sbox(&mut step1);
    apply_matrix(&mut step1, &Rp64_256::MDS);
    for i in 0..STATE_WIDTH {
        step1[i] += ark1[i];
    }
    let mut step2: [E; STATE_WIDTH] = core::array::from_fn(|i| next[off + i] - ark2[i]);
    apply_matrix(&mut step2, &Rp64_256::INV_MDS);
    apply_sbox(&mut step2);
    for i in 0..STATE_WIDTH {
        result[off + i] = step2[i] - step1[i];
    }
}

// ================================================================================================
// AIR
// ================================================================================================

#[derive(Clone)]
pub struct KeyPublicInputs {
    pub owner: [BaseElement; DIGEST_FELTS],
    pub nk: [BaseElement; DIGEST_FELTS],
}

impl winterfell::math::ToElements<BaseElement> for KeyPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(2 * DIGEST_FELTS);
        v.extend_from_slice(&self.owner);
        v.extend_from_slice(&self.nk);
        v
    }
}

pub struct KeyAir {
    context: AirContext<BaseElement>,
    owner: [BaseElement; DIGEST_FELTS],
    nk: [BaseElement; DIGEST_FELTS],
}

impl winterfell::Air for KeyAir {
    type BaseField = BaseElement;
    type PublicInputs = KeyPublicInputs;

    fn new(trace_info: TraceInfo, pi: KeyPublicInputs, options: ProofOptions) -> Self {
        // 12 rondes owner + 12 rondes nk (degré ALPHA, ARK additionnées → new(7)),
        // puis 4 contraintes de liaison (degré 1 × flag d'init périodique cycle 8).
        let mut degrees = vec![TransitionConstraintDegree::new(7); WIDTH];
        for _ in 0..N_BIND {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]));
        }
        // 8 constantes ligne 0 (owner) + 8 (nk) + 4 digest owner + 4 digest nk.
        let num_assertions = 8 + 8 + DIGEST_FELTS + DIGEST_FELTS;
        KeyAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            owner: pi.owner,
            nk: pi.nk,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();
        let ark1 = &periodic_values[..STATE_WIDTH];
        let ark2 = &periodic_values[STATE_WIDTH..2 * STATE_WIDTH];
        let init = periodic_values[2 * STATE_WIDTH];
        // Rondes des deux blocs (mêmes ARK).
        enforce_round_block(cur, next, 0, ark1, ark2, result);
        enforce_round_block(cur, next, NK_OFF, ark1, ark2, result);
        // Liaison : à la ligne 0, le secret des deux blocs coïncide.
        for k in 0..N_BIND {
            result[WIDTH + k] = init * (cur[SECRET_START + k] - cur[NK_OFF + SECRET_START + k]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = TRACE_LEN - 1;
        let mut a = Vec::with_capacity(16 + 2 * DIGEST_FELTS);

        // Constantes publiques ligne 0 d'un bloc à l'offset `off` (secret NON asserté).
        let preamble = |a: &mut Vec<Assertion<BaseElement>>, off: usize, tag: u64| {
            a.push(Assertion::single(off, 0, BaseElement::new(ABSORBED_LEN)));
            for i in 1..RATE_START {
                a.push(Assertion::single(off + i, 0, BaseElement::ZERO));
            }
            a.push(Assertion::single(
                off + RATE_START,
                0,
                BaseElement::new(ENCODING_VERSION as u64),
            ));
            a.push(Assertion::single(off + RATE_START + 1, 0, BaseElement::new(tag)));
            a.push(Assertion::single(
                off + RATE_START + 2,
                0,
                BaseElement::new(PAYLOAD_LEN),
            ));
            a.push(Assertion::single(off + PAD_ONE_IDX, 0, BaseElement::new(1)));
        };
        preamble(&mut a, 0, Domain::Owner.tag() as u64);
        preamble(&mut a, NK_OFF, Domain::Nk.tag() as u64);

        // Digests publics ligne finale.
        for (i, o) in self.owner.iter().enumerate() {
            a.push(Assertion::single(RATE_START + i, last, *o));
        }
        for (i, n) in self.nk.iter().enumerate() {
            a.push(Assertion::single(NK_OFF + RATE_START + i, last, *n));
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut cols = periodic_ark_columns(); // ARK1(12) + ARK2(12)
        // init_flag : 1 à la ligne 0, 0 ailleurs (cycle TRACE_LEN).
        let mut init = vec![BaseElement::ZERO; TRACE_LEN];
        init[0] = BaseElement::ONE;
        cols.push(init);
        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ================================================================================================
// PROVER
// ================================================================================================

struct KeyProver {
    options: ProofOptions,
}

impl Prover for KeyProver {
    type BaseField = BaseElement;
    type Air = KeyAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> KeyPublicInputs {
        let last = trace.length() - 1;
        KeyPublicInputs {
            owner: core::array::from_fn(|i| trace.get(RATE_START + i, last)),
            nk: core::array::from_fn(|i| trace.get(NK_OFF + RATE_START + i, last)),
        }
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

/// Prouve `owner = H_owner(s) ∧ nk = H_nk(s)` pour le même `shielded_secret` s.
pub fn prove_key(secret: &ShieldedSecret) -> (Digest, Digest, ValidityProof) {
    let s = secret.as_felts();
    let trace = build_key_trace(s, s);
    let last = trace.length() - 1;
    let owner = Digest(core::array::from_fn(|i| {
        Felt::from_winter(trace.get(RATE_START + i, last)).expect("digest canonique")
    }));
    let nk = Digest(core::array::from_fn(|i| {
        Felt::from_winter(trace.get(NK_OFF + RATE_START + i, last)).expect("digest canonique")
    }));
    let prover = KeyProver {
        options: crate::proof_options(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (owner, nk, ValidityProof(proof))
}

/// Vérifie que `owner` et `nk` dérivent d'un même secret (P2 ∧ P4 liés).
pub fn verify_key(owner: &Digest, nk: &Digest, proof: &ValidityProof) -> bool {
    let pi = KeyPublicInputs {
        owner: core::array::from_fn(|i| owner.0[i].to_winter()),
        nk: core::array::from_fn(|i| nk.0[i].to_winter()),
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<KeyAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pi,
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

    /// Différentiel : owner et nk prouvés == hachages hors-circuit du MÊME secret.
    #[test]
    fn differentiel_owner_et_nk() {
        for seed in [1u64, 42, 1000] {
            let s = secret(seed);
            let (owner, nk, proof) = prove_key(&s);
            assert_eq!(owner, rescue::hash(Domain::Owner, s.as_felts()));
            assert_eq!(nk, rescue::hash(Domain::Nk, s.as_felts()));
            assert!(verify_key(&owner, &nk, &proof));
        }
    }

    /// Non-régression : identiques aux preuves isolées `prove_owner`/`prove_nk`.
    #[test]
    fn coherence_avec_preuves_isolees() {
        let s = secret(5);
        let (owner, nk, _) = prove_key(&s);
        let (owner_iso, _) = crate::prove_owner(&s);
        let (nk_iso, _) = crate::prove_nk(&s);
        assert_eq!(owner, owner_iso);
        assert_eq!(nk, nk_iso);
    }

    #[test]
    fn owner_ou_nk_altere_rejete() {
        let s = secret(3);
        let (owner, nk, proof) = prove_key(&s);
        assert!(verify_key(&owner, &nk, &proof));
        let mut faux_owner = owner;
        faux_owner.0[0] = Felt::from_canonical_u64(faux_owner.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_key(&faux_owner, &nk, &proof));
        let mut faux_nk = nk;
        faux_nk.0[0] = Felt::from_canonical_u64(faux_nk.0[0].as_u64() ^ 1).unwrap();
        assert!(!verify_key(&owner, &faux_nk, &proof));
    }

    /// LIAISON (white-box) : une trace où owner vient de `s` et nk de `s'≠s` doit
    /// être REJETÉE — la contrainte de liaison mord. Trace invalide → `--release`
    /// (le prouveur n'évalue pas les contraintes en release, la preuve est produite
    /// puis rejetée par `verify`).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "trace invalide : générer en --release")]
    fn liaison_secret_partage_mord() {
        let s = secret(1);
        let s2 = secret(99);
        let trace = build_key_trace(s.as_felts(), s2.as_felts());
        let last = trace.length() - 1;
        let owner = Digest(core::array::from_fn(|i| {
            Felt::from_winter(trace.get(RATE_START + i, last)).unwrap()
        }));
        let nk = Digest(core::array::from_fn(|i| {
            Felt::from_winter(trace.get(NK_OFF + RATE_START + i, last)).unwrap()
        }));
        // owner/nk sont individuellement corrects pour leur propre secret...
        assert_eq!(owner, rescue::hash(Domain::Owner, s.as_felts()));
        assert_eq!(nk, rescue::hash(Domain::Nk, s2.as_felts()));
        // ...mais la liaison « même secret » est violée → preuve rejetée.
        let prover = KeyProver {
            options: crate::proof_options(),
        };
        let proof = ValidityProof(prover.prove(trace).expect("preuve produite en release"));
        assert!(!verify_key(&owner, &nk, &proof), "la liaison doit rejeter s != s'");
    }
}
