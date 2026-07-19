//! Équilibre (3b3b, P5) : prouve `Σ entrées = Σ sorties + fee` — **en addition de
//! corps**, sur des montants témoins bornés à `< 2^RANGE_BITS`.
//!
//! **Conception (AIR unique, range-check embarqué).** Chaque montant occupe un bloc
//! de `BLOCK = 64` lignes de bits témoins. La colonne périodique `pow` vaut
//! `2^i` pour `i < RANGE_BITS` puis `0` : elle **remet le poids à zéro à chaque
//! bloc**, ce qui borne AUTOMATIQUEMENT chaque montant à `< 2^RANGE_BITS` (le
//! range-check P6 est gratuit, aucun overflow possible). Un accumulateur global `S`
//! fait la somme SIGNÉE en corps, bit à bit :
//!   `S_next = S + signe · bit · 2^i`,   `S[0] = 0`,   `S[dernier] = fee`.
//! Les entrées ont le signe `+1`, les sorties `-1`, donc `S = Σin − Σout` et
//! l'assertion finale `S = fee` EST `Σin = Σout + fee`.
//!
//! **Soundness (Goldilocks).** `RANGE_BITS = 60` : chaque montant `< 2^60`.
//! L'égalité en corps `Σin ≡ Σout+fee (mod p)` n'implique l'égalité entière que si
//! CHAQUE côté est `< p`. Avec ≤ 8 termes par côté : `Σin < 8·2^60 = 2^63 < p` et
//! `Σout+fee < 9·2^60 < p` → aucune réduction modulaire ne masque un déséquilibre.
//! (Borne stricte ~15/côté : `16·2^60 = 2^64 > p`, donc PAS 16.) C'est le range-check
//! qui rend l'addition de corps SOUND (cf. `range_check`).
//!
//! **Portée.** Le nombre total de blocs `k = n_in + n_out` doit être une puissance
//! de 2 (2-in/2-out → 4, natif) ; sinon le portefeuille bourre avec des sorties de
//! valeur 0 (notes muettes, comme Zcash). Les signes publics sont assertés au début
//! de chaque bloc → la structure (n_in, n_out) est engagée dans la preuve.
//!
//! ⚠️ **validity-only + non privé** : les montants restent témoins (jamais assertés,
//! donc non révélés ici), mais la preuve n'est pas witness-hiding. La liaison des
//! bits de montant aux commitments/nullifiers est le circuit monolithique de 3b5.
//! À GÉNÉRER EN `--release` (cf. `merkle_path`).

use crate::range_check::RANGE_BITS;
use crate::ValidityProof;
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

const BLOCK: usize = 64; // lignes par montant (>= RANGE_BITS, puissance de 2)
const BIT: usize = 0; // bit témoin du montant
const SIGN: usize = 1; // +1 (entrée) / -1 (sortie), constant par bloc
const S: usize = 2; // accumulateur global signé
const IDX: usize = 3; // compteur (non-dégénérescence)
const WIDTH: usize = 4;

/// Construit la trace : entrées (signe +1) puis sorties (signe −1), un bloc chacune.
fn build_trace(inputs: &[u64], outputs: &[u64], _fee: u64) -> TraceTable<BaseElement> {
    let k = inputs.len() + outputs.len();
    assert!(k.is_power_of_two(), "k = n_in + n_out doit être une puissance de 2");
    let trace_len = BLOCK * k;
    let mut trace = TraceTable::new(WIDTH, trace_len);

    let amounts = inputs
        .iter()
        .map(|&a| (a, BaseElement::ONE))
        .chain(outputs.iter().map(|&a| (a, -BaseElement::ONE)));

    let mut s = BaseElement::ZERO;
    let mut global = 0usize;
    for (amount, sign) in amounts {
        for r in 0..BLOCK {
            let bit = if r < RANGE_BITS { (amount >> r) & 1 } else { 0 };
            let mut row = [BaseElement::ZERO; WIDTH];
            row[BIT] = BaseElement::new(bit);
            row[SIGN] = sign;
            row[S] = s; // valeur AVANT la contribution de cette ligne (S[0] = 0)
            row[IDX] = BaseElement::new(global as u64);
            trace.update_row(global, &row);
            // S_next = S + signe · bit · 2^i (pow = 0 pour les lignes de padding r >= RANGE_BITS)
            if r < RANGE_BITS {
                s += sign * BaseElement::new(bit) * BaseElement::new(1u64 << r);
            }
            global += 1;
        }
    }
    trace
}

#[derive(Clone)]
pub struct BalancePublicInputs {
    pub fee: BaseElement,
    pub n_in: usize,
    pub n_out: usize,
}

impl winterfell::math::ToElements<BaseElement> for BalancePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.fee,
            BaseElement::new(self.n_in as u64),
            BaseElement::new(self.n_out as u64),
        ]
    }
}

pub struct BalanceAir {
    context: AirContext<BaseElement>,
    fee: BaseElement,
    n_in: usize,
    k: usize,
}

impl winterfell::Air for BalanceAir {
    type BaseField = BaseElement;
    type PublicInputs = BalancePublicInputs;

    fn new(trace_info: TraceInfo, pi: BalancePublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            // S_next − S − SIGN·BIT·pow : base degré 2 (SIGN·BIT) × pow périodique.
            TransitionConstraintDegree::with_cycles(2, vec![BLOCK]),
            // BIT booléen.
            TransitionConstraintDegree::new(2),
            // SIGN ∈ {+1, −1} : SIGN² − 1.
            TransitionConstraintDegree::new(2),
            // SIGN constant dans le bloc : (1 − end)·(SIGN_next − SIGN).
            TransitionConstraintDegree::with_cycles(1, vec![BLOCK]),
            // IDX compteur.
            TransitionConstraintDegree::new(1),
        ];
        let k = trace_info.length() / BLOCK;
        // S[0]=0, IDX[0]=0, S[dernier]=fee, + un signe asserté par bloc.
        let num_assertions = 3 + k;
        BalanceAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            fee: pi.fee,
            n_in: pi.n_in,
            k,
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
        let pow = periodic_values[0];
        let end = periodic_values[1];
        // Somme signée en corps, bit à bit.
        result[0] = next[S] - cur[S] - cur[SIGN] * cur[BIT] * pow;
        // Bit booléen.
        result[1] = cur[BIT] * (cur[BIT] - one);
        // Signe ∈ {+1, −1}.
        result[2] = (cur[SIGN] - one) * (cur[SIGN] + one);
        // Signe constant à l'intérieur d'un bloc (libre au passage de bloc).
        result[3] = (one - end) * (next[SIGN] - cur[SIGN]);
        // Compteur (trace non-dégénérée).
        result[4] = next[IDX] - cur[IDX] - one;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let trace_len = self.context.trace_len();
        let mut a = vec![
            Assertion::single(S, 0, BaseElement::ZERO),
            Assertion::single(IDX, 0, BaseElement::ZERO),
            // Σin − Σout = fee (public).
            Assertion::single(S, trace_len - 1, self.fee),
        ];
        // Signe public au début de chaque bloc : +1 pour les entrées, −1 pour les sorties.
        for j in 0..self.k {
            let sign = if j < self.n_in {
                BaseElement::ONE
            } else {
                -BaseElement::ONE
            };
            a.push(Assertion::single(SIGN, j * BLOCK, sign));
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // pow : 2^i pour i < RANGE_BITS, 0 ensuite (borne chaque montant à 2^RANGE_BITS).
        let pow: Vec<BaseElement> = (0..BLOCK)
            .map(|i| {
                if i < RANGE_BITS {
                    BaseElement::new(1u64 << i)
                } else {
                    BaseElement::ZERO
                }
            })
            .collect();
        // end : 1 sur la dernière ligne d'un bloc (autorise le changement de signe).
        let end: Vec<BaseElement> = (0..BLOCK)
            .map(|i| {
                if i == BLOCK - 1 {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                }
            })
            .collect();
        vec![pow, end]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct BalanceProver {
    options: ProofOptions,
    fee: u64,
    n_in: usize,
    n_out: usize,
}

impl Prover for BalanceProver {
    type BaseField = BaseElement;
    type Air = BalanceAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BalancePublicInputs {
        BalancePublicInputs {
            fee: BaseElement::new(self.fee),
            n_in: self.n_in,
            n_out: self.n_out,
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

/// Prouve `Σ inputs = Σ outputs + fee`. Précondition : `n_in + n_out` puissance de 2,
/// montants `< 2^RANGE_BITS`. À GÉNÉRER EN `--release`.
pub fn prove_balance(inputs: &[u64], outputs: &[u64], fee: u64) -> ValidityProof {
    let trace = build_trace(inputs, outputs, fee);
    let prover = BalanceProver {
        options: crate::proof_options(),
        fee,
        n_in: inputs.len(),
        n_out: outputs.len(),
    };
    ValidityProof(prover.prove(trace).expect("génération de preuve"))
}

/// Vérifie l'équilibre contre la structure publique (`n_in`, `n_out`, `fee`).
pub fn verify_balance(n_in: usize, n_out: usize, fee: u64, proof: &ValidityProof) -> bool {
    let pi = BalancePublicInputs {
        fee: BaseElement::new(fee),
        n_in,
        n_out,
    };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<BalanceAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.0.clone(),
        pi,
        &acceptable,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Différentiel : équilibre honnête (2-in/2-out, avec et sans fee) → accepté.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn equilibre_accepte() {
        // 100 + 50 = 80 + 70 + 0
        let p = prove_balance(&[100, 50], &[80, 70], 0);
        assert!(verify_balance(2, 2, 0, &p));
        // 100 + 50 = 90 + 40 + 20  (fee = 20)
        let p = prove_balance(&[100, 50], &[90, 40], 20);
        assert!(verify_balance(2, 2, 20, &p));
    }

    /// 1-in/1-out avec fee (k = 2).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn equilibre_1_1_avec_fee() {
        let p = prove_balance(&[1_000], &[990], 10);
        assert!(verify_balance(1, 1, 10, &p));
    }

    /// Grands montants proches de la borne (2^59), somme < p → toujours sound.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn equilibre_grands_montants() {
        let big = (1u64 << 59) - 1;
        let p = prove_balance(&[big, big], &[big, big], 0);
        assert!(verify_balance(2, 2, 0, &p));
    }

    /// Déséquilibre : Σin − Σout ≠ fee annoncé → rejeté.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn desequilibre_rejete() {
        // Vraie somme : 100 − 80 = 20, mais on annonce fee = 10.
        let p = prove_balance(&[100], &[80], 10);
        assert!(!verify_balance(1, 1, 10, &p));
    }

    /// Un fee falsifié à la vérification (preuve honnête fee=20) → rejeté.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn fee_falsifie_rejete() {
        let p = prove_balance(&[100, 50], &[90, 40], 20);
        assert!(verify_balance(2, 2, 20, &p));
        assert!(!verify_balance(2, 2, 19, &p)); // mauvais fee public
    }
}
