//! AIR sponge Rescue-Prime multi-bloc (3b1) — généralisation de 3a2b.
//!
//! Prouve `digest = H_domain(payload)` pour un payload de longueur arbitraire, en
//! répliquant le sponge de `Rp64_256::hash_elements` (voir 3a2b) : la longueur est
//! injectée dans la capacité (pas de padding), absorption ADDITIVE bloc par bloc,
//! une permutation par bloc.
//!
//! Périmètre 3b1 : `B*8` doit être une puissance de 2 (couvre B ∈ {1,2,4}). Le
//! padding par blocs-copie (B=3, commitment) est repoussé à 3b4. Précondition
//! assertie dans `build_sponge_trace`.
//!
//! Piège de degré (inverse de 3a2/3a2b) : ici le masque `round_flag` MULTIPLIE la
//! contrainte de ronde → `with_cycles` est CORRECT.
//!
//! ⚠️ validity-only : intégrité, PAS confidentialité.

use crate::rescue_round::{
    apply_matrix, apply_sbox, periodic_ark_columns, NUM_ROUNDS, STATE_WIDTH, TRACE_LEN,
};
use crate::ValidityProof;
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::{sponge_preamble, Domain, ENCODING_VERSION};
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

const RATE_START: usize = 4;
const RATE_WIDTH: usize = 8;
const TRACE_WIDTH: usize = STATE_WIDTH + RATE_WIDTH; // 12 état + 8 inject = 20
const INJECT_START: usize = STATE_WIDTH;

// ================================================================================================
// TRACE
// ================================================================================================

/// Localise l'élément `idx` du préambule dans la trace : `(ligne, colonne)`.
/// Bloc 0 → colonnes d'état (rate) de la ligne 0 ; bloc b>0 → colonnes d'inject de
/// la ligne d'absorption `(b-1)*8 + 7`.
fn locate(idx: usize) -> (usize, usize) {
    let block = idx / RATE_WIDTH;
    let pos = idx % RATE_WIDTH;
    if block == 0 {
        (0, RATE_START + pos)
    } else {
        ((block - 1) * TRACE_LEN + (TRACE_LEN - 1), INJECT_START + pos)
    }
}

/// Construit la trace du sponge à partir des éléments du préambule.
fn build_sponge_trace(preamble: &[BaseElement]) -> TraceTable<BaseElement> {
    let m = preamble.len();
    let b = m.div_ceil(RATE_WIDTH);
    let l = b * TRACE_LEN;
    assert!(
        l.is_power_of_two(),
        "3b1 : B*8 doit être une puissance de 2 (padding B=3 repoussé à 3b4)"
    );

    // blocs de rate (dernier bloc complété par des zéros).
    let block = |k: usize| -> [BaseElement; RATE_WIDTH] {
        core::array::from_fn(|j| preamble.get(k * RATE_WIDTH + j).copied().unwrap_or(BaseElement::ZERO))
    };

    let mut trace = TraceTable::new(TRACE_WIDTH, l);

    // état initial : capacité = longueur absorbée, rate = bloc 0.
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[0] = BaseElement::new(m as u64);
    let b0 = block(0);
    for j in 0..RATE_WIDTH {
        state[RATE_START + j] += b0[j];
    }

    for k in 0..b {
        let base = k * TRACE_LEN;
        let mut s = state;
        for r in 0..NUM_ROUNDS {
            let mut row = [BaseElement::ZERO; TRACE_WIDTH];
            row[..STATE_WIDTH].copy_from_slice(&s);
            trace.update_row(base + r, &row);
            Rp64_256::apply_round(&mut s, r);
        }
        // ligne base+7 : état pleinement permuté ; inject = bloc suivant s'il existe.
        let mut row = [BaseElement::ZERO; TRACE_WIDTH];
        row[..STATE_WIDTH].copy_from_slice(&s);
        if k + 1 < b {
            let nb = block(k + 1);
            row[INJECT_START..].copy_from_slice(&nb);
            let mut ns = s;
            for j in 0..RATE_WIDTH {
                ns[RATE_START + j] += nb[j];
            }
            state = ns;
        }
        trace.update_row(base + TRACE_LEN - 1, &row);
    }

    trace
}

// ================================================================================================
// AIR
// ================================================================================================

#[derive(Clone)]
pub struct SpongePublicInputs {
    pub tag: u64,
    pub payload_len: u64,
    pub digest: [BaseElement; DIGEST_FELTS],
    /// Positions (dans le payload) et valeurs des éléments PUBLICS. Vide pour un
    /// payload entièrement témoin (owner, nk, nullifier).
    pub public_payload: Vec<(usize, BaseElement)>,
}

impl winterfell::math::ToElements<BaseElement> for SpongePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(2 + DIGEST_FELTS + 2 * self.public_payload.len());
        v.push(BaseElement::new(self.tag));
        v.push(BaseElement::new(self.payload_len));
        v.extend_from_slice(&self.digest);
        for (i, val) in &self.public_payload {
            v.push(BaseElement::new(*i as u64));
            v.push(*val);
        }
        v
    }
}

pub struct SpongeAir {
    context: AirContext<BaseElement>,
    pi: SpongePublicInputs,
    m: usize,
    l: usize,
}

impl winterfell::Air for SpongeAir {
    type BaseField = BaseElement;
    type PublicInputs = SpongePublicInputs;

    fn new(trace_info: TraceInfo, pi: SpongePublicInputs, options: ProofOptions) -> Self {
        // 12 contraintes de degré ALPHA, chacune multipliée par le masque round_flag
        // (cycle TRACE_LEN) → `with_cycles` (correct ici : le masque MULTIPLIE).
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(
                crate::rescue_round::ALPHA as usize,
                vec![TRACE_LEN],
            );
            STATE_WIDTH
        ];
        let m = 3 + pi.payload_len as usize + 1;
        let l = trace_info.length();
        // assertions : capacité (4) + VERSION/tag/LEN (3) + PAD_ONE (1) + digest (4)
        // + payload public.
        let num_assertions = 4 + 3 + 1 + DIGEST_FELTS + pi.public_payload.len();
        SpongeAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pi,
            m,
            l,
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
        let round_flag = periodic_values[0];
        let ark1 = &periodic_values[1..1 + STATE_WIDTH];
        let ark2 = &periodic_values[1 + STATE_WIDTH..1 + 2 * STATE_WIDTH];

        let cur_state: [E; STATE_WIDTH] = core::array::from_fn(|i| cur[i]);
        let next_state: [E; STATE_WIDTH] = core::array::from_fn(|i| next[i]);
        let inject: [E; RATE_WIDTH] = core::array::from_fn(|j| cur[INJECT_START + j]);

        // Contrainte de ronde (meet-in-the-middle).
        let mut step1 = cur_state;
        apply_sbox(&mut step1);
        apply_matrix(&mut step1, &Rp64_256::MDS);
        for i in 0..STATE_WIDTH {
            step1[i] += ark1[i];
        }
        let mut step2 = next_state;
        for i in 0..STATE_WIDTH {
            step2[i] -= ark2[i];
        }
        apply_matrix(&mut step2, &Rp64_256::INV_MDS);
        apply_sbox(&mut step2);

        // Contrainte d'absorption : next[cap] = cur[cap] ; next[rate+j] = cur[rate+j] + inject[j].
        let one = E::ONE;
        for i in 0..STATE_WIDTH {
            let round_c = step2[i] - step1[i];
            let absorbed = if i >= RATE_START {
                inject[i - RATE_START]
            } else {
                E::ZERO
            };
            let absorb_c = next_state[i] - cur_state[i] - absorbed;
            result[i] = round_flag * round_c + (one - round_flag) * absorb_c;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a =
            Vec::with_capacity(4 + 3 + 1 + DIGEST_FELTS + self.pi.public_payload.len());

        // Ligne 0 — capacité : [longueur absorbée, 0, 0, 0] (PUBLIC).
        a.push(Assertion::single(0, 0, BaseElement::new(self.m as u64)));
        a.push(Assertion::single(1, 0, BaseElement::ZERO));
        a.push(Assertion::single(2, 0, BaseElement::ZERO));
        a.push(Assertion::single(3, 0, BaseElement::ZERO));

        // Préambule public : VERSION (idx 0), tag (idx 1), LEN (idx 2).
        let put = |a: &mut Vec<Assertion<BaseElement>>, idx: usize, val: BaseElement| {
            let (row, col) = locate(idx);
            a.push(Assertion::single(col, row, val));
        };
        put(&mut a, 0, BaseElement::new(ENCODING_VERSION as u64));
        put(&mut a, 1, BaseElement::new(self.pi.tag));
        put(&mut a, 2, BaseElement::new(self.pi.payload_len));
        // PAD_ONE (dernier élément du préambule).
        put(&mut a, self.m - 1, BaseElement::new(1));
        // Payload public (positions relatives au payload → +3 dans le préambule).
        for (pi, val) in &self.pi.public_payload {
            put(&mut a, 3 + *pi, *val);
        }

        // NOTE : les positions témoins (shielded_secret, nk, valeurs de note) ne sont
        // JAMAIS assertées — seules les constantes publiques et le payload public le sont.

        // Digest : dernière ligne, colonnes du rate DIGEST (4..8).
        let last = self.l - 1;
        for (i, d) in self.pi.digest.iter().enumerate() {
            a.push(Assertion::single(RATE_START + i, last, *d));
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // round_flag = [1;7, 0] (cycle TRACE_LEN), puis ARK1(12), ARK2(12).
        let mut round_flag = vec![BaseElement::ONE; TRACE_LEN];
        round_flag[TRACE_LEN - 1] = BaseElement::ZERO;
        let mut cols = Vec::with_capacity(1 + 2 * STATE_WIDTH);
        cols.push(round_flag);
        cols.extend(periodic_ark_columns());
        cols
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ================================================================================================
// PROVER
// ================================================================================================

struct SpongeProver {
    options: ProofOptions,
    pi: SpongePublicInputs,
}

impl Prover for SpongeProver {
    type BaseField = BaseElement;
    type Air = SpongeAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SpongePublicInputs {
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
// API PUBLIQUE
// ================================================================================================

/// Prouve `digest = H_domain(payload)`. `public_idx` = positions du payload rendues
/// publiques (assertées) ; les autres restent témoin.
pub fn prove_sponge(
    domain: Domain,
    payload: &[Felt],
    public_idx: &[usize],
) -> (Digest, ValidityProof) {
    let preamble: Vec<BaseElement> = sponge_preamble(domain, payload)
        .iter()
        .map(|f| f.to_winter())
        .collect();
    let trace = build_sponge_trace(&preamble);

    let last = trace.length() - 1;
    let digest_felts: [Felt; DIGEST_FELTS] = core::array::from_fn(|i| {
        Felt::from_winter(trace.get(RATE_START + i, last)).expect("digest canonique")
    });
    let digest = Digest(digest_felts);

    let public_payload: Vec<(usize, BaseElement)> = public_idx
        .iter()
        .map(|&i| (i, payload[i].to_winter()))
        .collect();
    let pi = SpongePublicInputs {
        tag: domain.tag() as u64,
        payload_len: payload.len() as u64,
        digest: core::array::from_fn(|i| digest.0[i].to_winter()),
        public_payload,
    };

    let prover = SpongeProver {
        options: crate::proof_options(),
        pi: pi.clone(),
    };
    let proof = prover.prove(trace).expect("génération de preuve");
    (digest, ValidityProof(proof))
}

/// Vérifie une preuve sponge. `public_payload` = les positions/valeurs publiques
/// (doivent correspondre à celles fournies à `prove_sponge`).
pub fn verify_sponge(
    domain: Domain,
    payload_len: usize,
    digest: &Digest,
    public_payload: &[(usize, Felt)],
    proof: &ValidityProof,
) -> bool {
    let pi = SpongePublicInputs {
        tag: domain.tag() as u64,
        payload_len: payload_len as u64,
        digest: core::array::from_fn(|i| digest.0[i].to_winter()),
        public_payload: public_payload
            .iter()
            .map(|(i, f)| (*i, f.to_winter()))
            .collect(),
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<SpongeAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pi,
        &acceptable,
    )
    .is_ok()
}

// --- Instances (sucre) ---

use proved_hash::digest::ShieldedSecret;

/// P4 en circuit : `nk = H_nk(shielded_secret)` (B=1, payload entièrement témoin).
pub fn prove_nk(secret: &ShieldedSecret) -> (Digest, ValidityProof) {
    prove_sponge(Domain::Nk, secret.as_felts(), &[])
}

/// Nullifier prouvé : `nf = H_nullifier(nk ‖ rho ‖ cm)` (B=2, payload témoin).
pub fn prove_nullifier(
    nk: &[Felt; DIGEST_FELTS],
    rho: &[Felt; DIGEST_FELTS],
    cm: &[Felt; DIGEST_FELTS],
) -> (Digest, ValidityProof) {
    let mut payload = Vec::with_capacity(3 * DIGEST_FELTS);
    payload.extend_from_slice(nk);
    payload.extend_from_slice(rho);
    payload.extend_from_slice(cm);
    prove_sponge(Domain::Nullifier, &payload, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::rescue;

    fn felt(x: u64) -> Felt {
        Felt::from_canonical_u64(x).unwrap()
    }

    /// B=1 : nk == hash hors-circuit (différentiel), + roundtrip.
    #[test]
    fn nk_differentiel_b1() {
        let s = ShieldedSecret::from_felts(core::array::from_fn(|i| felt(100 + i as u64)));
        let (nk, proof) = prove_nk(&s);
        assert_eq!(nk, rescue::hash(Domain::Nk, s.as_felts()));
        assert!(verify_sponge(Domain::Nk, DIGEST_FELTS, &nk, &[], &proof));
    }

    /// B=2 : nullifier == hash hors-circuit (différentiel multi-bloc), + roundtrip.
    #[test]
    fn nullifier_differentiel_b2() {
        let nk: [Felt; 4] = core::array::from_fn(|i| felt(1 + i as u64));
        let rho: [Felt; 4] = core::array::from_fn(|i| felt(10 + i as u64));
        let cm: [Felt; 4] = core::array::from_fn(|i| felt(20 + i as u64));
        let (nf, proof) = prove_nullifier(&nk, &rho, &cm);

        let mut payload = Vec::new();
        payload.extend_from_slice(&nk);
        payload.extend_from_slice(&rho);
        payload.extend_from_slice(&cm);
        assert_eq!(nf, rescue::hash(Domain::Nullifier, &payload));
        assert!(verify_sponge(Domain::Nullifier, 12, &nf, &[], &proof));
    }

    /// B=4 : payload de 28 Felts (préambule 32) — exerce le chaînage sans padding.
    #[test]
    fn sponge_b4_differentiel() {
        let payload: Vec<Felt> = (0..28).map(|i| felt(i as u64 + 3)).collect();
        let (d, proof) = prove_sponge(Domain::NoteCommitment, &payload, &[]);
        assert_eq!(d, rescue::hash(Domain::NoteCommitment, &payload));
        assert!(verify_sponge(Domain::NoteCommitment, payload.len(), &d, &[], &proof));
    }

    #[test]
    fn digest_altere_rejete() {
        let s = ShieldedSecret::from_felts(core::array::from_fn(|i| felt(7 + i as u64)));
        let (nk, proof) = prove_nk(&s);
        assert!(verify_sponge(Domain::Nk, DIGEST_FELTS, &nk, &[], &proof));
        let mut faux = nk;
        faux.0[0] = felt(faux.0[0].as_u64() ^ 1);
        assert!(!verify_sponge(Domain::Nk, DIGEST_FELTS, &faux, &[], &proof));
    }

    /// Non-régression : le sponge (B=1, tag Owner) reproduit bien owner de 3a2b.
    #[test]
    fn owner_non_regression() {
        let s = ShieldedSecret::from_felts(core::array::from_fn(|i| felt(1000 + i as u64)));
        let (owner_sponge, _) = prove_sponge(Domain::Owner, s.as_felts(), &[]);
        assert_eq!(owner_sponge, rescue::hash(Domain::Owner, s.as_felts()));
    }
}
