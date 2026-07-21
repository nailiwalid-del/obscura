//! Range-check d'un montant (3b3, P6) : prouve `0 <= v < 2^RANGE_BITS`.
//!
//! **Choix de conception (Goldilocks)** : la spec disait `[0, 2^64)`, mais sur le
//! corps de Goldilocks (`p ≈ 2^64`) un tel range est VIDE (tout élément canonique
//! est déjà `< p < 2^64`) et, surtout, l'équilibre `Σin = Σout + fee` par addition
//! de corps devient NON-SOUND dès que les sommes approchent 2^64 (elles wrappent
//! `p` → création de monnaie invisible). On borne donc les montants à
//! **`< 2^RANGE_BITS`** avec `RANGE_BITS = 60`. Condition de soundness : chaque
//! somme d'un côté doit rester `< p` (l'égalité en corps `Σin ≡ Σout+fee` n'implique
//! l'égalité entière que si les deux côtés sont `< p`). Avec des montants `< 2^60`,
//! `Σ < (nb de termes) · 2^60` ; pour ≤ 8 termes par côté c'est `< 2^63 < p` (large
//! marge). Borne stricte : ~15 termes/côté (`16 · 2^60 = 2^64 > p` — d'où PAS 16) ;
//! `RANGE_BITS = 59` la porterait à 16. L'équilibre en corps (3b3b) est ainsi sound.
//!
//! Preuve = décomposition binaire par ACCUMULATION : une colonne `acc` accumule
//! `Σ b_i · 2^i` (bit à bit), `acc[0] = 0`, `acc[RANGE_BITS] = v`. Une colonne
//! compteur `idx` (0,1,2,…) garantit une trace non-dégénérée (winterfell rejette
//! une trace constante). `2^i` est fourni en colonne périodique.
//!
//! ⚠️ À générer en `--release` (colonnes témoins potentiellement constantes → degrés
//! input-dépendants ; cf. merkle_path).

// CONSENSUS : seule `RANGE_BITS` est réutilisée par le monolithe/tx. Tout le
// sous-circuit standalone (AIR, prouveur, `prove_range`/`verify_range`) est gaté
// derrière `dev-circuits`.
#[cfg(feature = "dev-circuits")]
use crate::ValidityProof;
#[cfg(feature = "dev-circuits")]
use winter_math::fields::f64::BaseElement;
#[cfg(feature = "dev-circuits")]
use winter_math::FieldElement;
#[cfg(feature = "dev-circuits")]
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
#[cfg(feature = "dev-circuits")]
use winterfell::matrix::ColMatrix;
#[cfg(feature = "dev-circuits")]
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

#[cfg(feature = "dev-circuits")]
type Blake3 = Blake3_256<BaseElement>;

/// Bits d'un montant valide (borne de soundness de l'équilibre, cf. en-tête).
pub const RANGE_BITS: usize = 60;
#[cfg(feature = "dev-circuits")]
const TRACE_LEN: usize = 64; // puissance de 2 ≥ RANGE_BITS + 1
#[cfg(feature = "dev-circuits")]
const ACC: usize = 0;
#[cfg(feature = "dev-circuits")]
const BIT: usize = 1;
#[cfg(feature = "dev-circuits")]
const IDX: usize = 2;
#[cfg(feature = "dev-circuits")]
const WIDTH: usize = 3;

#[cfg(feature = "dev-circuits")]
fn build_trace(v: u64) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(WIDTH, TRACE_LEN);
    let mut acc = 0u128;
    for step in 0..TRACE_LEN {
        let bit = if step < RANGE_BITS {
            (v >> step) & 1
        } else {
            0
        };
        let mut row = [BaseElement::ZERO; WIDTH];
        row[ACC] = BaseElement::new(acc as u64);
        row[BIT] = BaseElement::new(bit);
        row[IDX] = BaseElement::new(step as u64);
        trace.update_row(step, &row);
        if step < RANGE_BITS {
            acc += (bit as u128) << step;
        }
    }
    trace
}

#[cfg(feature = "dev-circuits")]
#[derive(Clone)]
pub struct RangePublicInputs {
    pub value: BaseElement,
}

#[cfg(feature = "dev-circuits")]
impl winterfell::math::ToElements<BaseElement> for RangePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.value]
    }
}

#[cfg(feature = "dev-circuits")]
pub struct RangeAir {
    context: AirContext<BaseElement>,
    value: BaseElement,
}

#[cfg(feature = "dev-circuits")]
impl winterfell::Air for RangeAir {
    type BaseField = BaseElement;
    type PublicInputs = RangePublicInputs;

    fn new(trace_info: TraceInfo, pi: RangePublicInputs, options: ProofOptions) -> Self {
        // acc (degré 1 × pow2 périodique), bit booléen (degré 2), idx (degré 1).
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(1),
        ];
        // acc[0]=0, idx[0]=0, acc[RANGE_BITS]=v.
        RangeAir {
            context: AirContext::new(trace_info, degrees, 3, options),
            value: pi.value,
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
        let one = E::ONE;
        let pow2 = periodic_values[0];
        // acc_next = acc_cur + bit_cur · 2^i.
        result[0] = next[ACC] - cur[ACC] - cur[BIT] * pow2;
        // bit booléen.
        result[1] = cur[BIT] * (cur[BIT] - one);
        // idx_next = idx_cur + 1 (trace non-dégénérée).
        result[2] = next[IDX] - cur[IDX] - one;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(ACC, 0, BaseElement::ZERO),
            Assertion::single(IDX, 0, BaseElement::ZERO),
            // valeur = accumulateur après les RANGE_BITS bits (publique).
            Assertion::single(ACC, RANGE_BITS, self.value),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // 2^i pour i < RANGE_BITS, 0 au-delà (les bits de padding sont nuls).
        let pow2: Vec<BaseElement> = (0..TRACE_LEN)
            .map(|i| {
                if i < RANGE_BITS {
                    BaseElement::new(1u64 << i)
                } else {
                    BaseElement::ZERO
                }
            })
            .collect();
        vec![pow2]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

#[cfg(feature = "dev-circuits")]
struct RangeProver {
    options: ProofOptions,
}

#[cfg(feature = "dev-circuits")]
impl Prover for RangeProver {
    type BaseField = BaseElement;
    type Air = RangeAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> RangePublicInputs {
        // La valeur prouvée = accumulateur après RANGE_BITS bits.
        RangePublicInputs {
            value: trace.get(ACC, RANGE_BITS),
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

/// Prouve `0 <= value < 2^RANGE_BITS`. À GÉNÉRER EN `--release`.
#[cfg(feature = "dev-circuits")]
pub fn prove_range(value: u64) -> ValidityProof {
    let trace = build_trace(value);
    let prover = RangeProver {
        options: crate::proof_options(),
    };
    ValidityProof(prover.prove(trace).expect("génération de preuve"))
}

/// Vérifie une preuve de range contre la `value` publique.
#[cfg(feature = "dev-circuits")]
pub fn verify_range(value: u64, proof: &ValidityProof) -> bool {
    let pi = RangePublicInputs {
        value: BaseElement::new(value),
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<RangeAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pi,
        &acceptable,
    )
    .is_ok()
}

#[cfg(all(test, feature = "dev-circuits"))]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn valeurs_dans_le_range() {
        for v in [0u64, 1, 42, (1u64 << 32) + 7, (1u64 << RANGE_BITS) - 1] {
            let proof = prove_range(v);
            assert!(verify_range(v, &proof), "v={v}");
        }
    }

    /// Une valeur ≥ 2^RANGE_BITS : la preuve porte sur `v mod 2^RANGE_BITS`
    /// (l'accumulateur tronqué), donc `verify_range(v)` (valeur pleine) rejette.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn valeur_hors_range_rejetee() {
        let v = 1u64 << RANGE_BITS; // 2^60
        let proof = prove_range(v);
        assert!(!verify_range(v, &proof));
    }
}
