//! Spike E2 (phase 3z-b) — « lignes de blindage » sur un AIR-jouet winterfell 0.13.1.
//!
//! Question : winterfell exige deg(colonne) < n (pas de blinding polynomial
//! `f + Z_H·r`) ; la seule voie compatible est de réserver `b` lignes ALÉATOIRES
//! en fin de trace, de désactiver toutes les contraintes sur ces lignes (sélecteur
//! périodique) et de laisser la LDE mélanger l'aléa dans chaque ouverture.
//!
//! Deux expériences :
//! - **A (baseline)** : colonne SECRET constante = s sur toute la trace →
//!   le polynôme interpolant est la constante s, donc CHAQUE ouverture FRI
//!   vaut s en clair. C'est la fuite du monolithe (colonnes porteuses).
//! - **B (blindée)** : trace de 128 lignes = 88 lignes porteuses (SECRET = s)
//!   plus 40 lignes d'aléa frais ; contraintes gatées OFF sur la zone d'aléa.
//!   Le polynôme est alors générique (degré 127) : chaque ouverture est une
//!   combinaison linéaire des 88 s ET des 40 aléas, donc masquée.
//!
//! ⚠️ Preuves à générer en `--release` (cf. range_check du crate circuit).

use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree};
use winterfell::matrix::ColMatrix;
use winterfell::{
    AirContext, Assertion, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, EvaluationFrame, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

type Blake3 = Blake3_256<BaseElement>;

/// Colonne témoin : la valeur secrète s (JAMAIS assertée).
const SECRET: usize = 0;
/// Colonne compteur : trace non-dégénérée + assertions publiques.
const IDX: usize = 1;
const WIDTH: usize = 2;

/// Mêmes paramètres que `circuit::proof_options()` : 32 requêtes, blowup 8,
/// extension quadratique.
fn proof_options() -> ProofOptions {
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

/// Entrées publiques : uniquement la borne du compteur (rien sur s).
#[derive(Clone)]
pub struct PublicInputs {
    pub last_idx: BaseElement,
}

impl winterfell::math::ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.last_idx]
    }
}

/// Extrait les évaluations ouvertes de la colonne SECRET aux positions de
/// requête FRI, via `Queries::parse` (exactement ce qu'un observateur du
/// réseau peut faire sur une preuve sérialisée).
pub fn secret_openings(proof: &Proof) -> Vec<BaseElement> {
    let queries = proof.trace_queries[0].clone(); // segment principal
    let (_opening_proof, table) = queries
        .parse::<BaseElement, Blake3, MerkleTree<Blake3>>(
            proof.lde_domain_size(),
            proof.num_unique_queries as usize,
            WIDTH,
        )
        .expect("parse des trace queries");
    table.rows().map(|row| row[SECRET]).collect()
}

// ================================================================================================
// EXPÉRIENCE A — BASELINE (colonne porteuse constante, sans blindage)
// ================================================================================================
pub mod baseline {
    use super::*;

    const TRACE_LEN: usize = 64;

    fn build_trace(s: BaseElement) -> TraceTable<BaseElement> {
        let mut trace = TraceTable::new(WIDTH, TRACE_LEN);
        for step in 0..TRACE_LEN {
            trace.update_row(step, &[s, BaseElement::new(step as u64)]);
        }
        trace
    }

    pub struct BaselineAir {
        context: AirContext<BaseElement>,
        last_idx: BaseElement,
    }

    impl winterfell::Air for BaselineAir {
        type BaseField = BaseElement;
        type PublicInputs = PublicInputs;

        fn new(trace_info: TraceInfo, pi: PublicInputs, options: ProofOptions) -> Self {
            // SECRET constant (degré 1), IDX incrément (degré 1).
            let degrees = vec![
                TransitionConstraintDegree::new(1),
                TransitionConstraintDegree::new(1),
            ];
            BaselineAir {
                context: AirContext::new(trace_info, degrees, 2, options),
                last_idx: pi.last_idx,
            }
        }

        fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
            &self,
            frame: &EvaluationFrame<E>,
            _periodic_values: &[E],
            result: &mut [E],
        ) {
            let cur = frame.current();
            let next = frame.next();
            // La colonne SECRET est constante — miroir des porteuses du monolithe.
            result[0] = next[SECRET] - cur[SECRET];
            // idx_next = idx_cur + 1.
            result[1] = next[IDX] - cur[IDX] - E::ONE;
        }

        fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
            // Publiques et SANS rapport avec s : s reste un pur témoin.
            vec![
                Assertion::single(IDX, 0, BaseElement::ZERO),
                Assertion::single(IDX, TRACE_LEN - 1, self.last_idx),
            ]
        }

        fn context(&self) -> &AirContext<Self::BaseField> {
            &self.context
        }
    }

    pub struct BaselineProver {
        options: ProofOptions,
    }

    impl Prover for BaselineProver {
        type BaseField = BaseElement;
        type Air = BaselineAir;
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
            PublicInputs {
                last_idx: trace.get(IDX, TRACE_LEN - 1),
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

    pub fn prove(s: BaseElement) -> Proof {
        let prover = BaselineProver {
            options: proof_options(),
        };
        prover.prove(build_trace(s)).expect("génération baseline")
    }

    pub fn verify(proof: Proof) -> bool {
        let pi = PublicInputs {
            last_idx: BaseElement::new((TRACE_LEN - 1) as u64),
        };
        let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
        winterfell::verify::<BaselineAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
            proof, pi, &acceptable,
        )
        .is_ok()
    }
}

// ================================================================================================
// EXPÉRIENCE B — BLINDÉE (b lignes d'aléa en fin de trace, contraintes gatées)
// ================================================================================================
pub mod blinded {
    use super::*;
    use rand::Rng;

    /// Longueur totale (puissance de 2).
    const TRACE_LEN: usize = 128;
    /// Lignes de blindage : b = 40 ≥ q + 2 + marge = 32 + 2 + 6.
    pub const B_BLINDING: usize = 40;
    /// Zone porteuse : lignes 0..MEANINGFUL.
    const MEANINGFUL: usize = TRACE_LEN - B_BLINDING; // 88

    /// Trace : SECRET = s et IDX = compteur sur la zone porteuse ; les B_BLINDING
    /// dernières lignes sont remplies d'aléa frais (les DEUX colonnes).
    fn build_trace(s: BaseElement) -> TraceTable<BaseElement> {
        let mut rng = rand::thread_rng();
        let mut trace = TraceTable::new(WIDTH, TRACE_LEN);
        for step in 0..TRACE_LEN {
            let row = if step < MEANINGFUL {
                [s, BaseElement::new(step as u64)]
            } else {
                // BaseElement::new réduit mod p — biais négligeable pour le spike.
                [
                    BaseElement::new(rng.gen::<u64>()),
                    BaseElement::new(rng.gen::<u64>()),
                ]
            };
            trace.update_row(step, &row);
        }
        trace
    }

    pub struct BlindedAir {
        context: AirContext<BaseElement>,
        last_idx: BaseElement,
    }

    impl winterfell::Air for BlindedAir {
        type BaseField = BaseElement;
        type PublicInputs = PublicInputs;

        fn new(trace_info: TraceInfo, pi: PublicInputs, options: ProofOptions) -> Self {
            // Contraintes de degré 1 × sélecteur périodique (cycle = trace entière),
            // même motif que range_check (`with_cycles(1, vec![TRACE_LEN])`).
            let degrees = vec![
                TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]),
                TransitionConstraintDegree::with_cycles(1, vec![TRACE_LEN]),
            ];
            BlindedAir {
                context: AirContext::new(trace_info, degrees, 2, options),
                last_idx: pi.last_idx,
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
            // Sélecteur : 1 sur les transitions de la zone porteuse, 0 sur celles
            // qui touchent la zone d'aléa → les contraintes y sont ÉTEINTES.
            let sel = periodic_values[0];
            result[0] = sel * (next[SECRET] - cur[SECRET]);
            result[1] = sel * (next[IDX] - cur[IDX] - E::ONE);
        }

        fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
            // Uniquement dans la zone porteuse — JAMAIS sur les lignes d'aléa.
            vec![
                Assertion::single(IDX, 0, BaseElement::ZERO),
                Assertion::single(IDX, MEANINGFUL - 1, self.last_idx),
            ]
        }

        fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
            // sel[i] = 1 ssi la transition i→i+1 reste dans la zone porteuse,
            // c.-à-d. i ≤ MEANINGFUL−2 ; 0 dès que la ligne i+1 est aléatoire.
            let sel: Vec<BaseElement> = (0..TRACE_LEN)
                .map(|i| {
                    if i < MEANINGFUL - 1 {
                        BaseElement::ONE
                    } else {
                        BaseElement::ZERO
                    }
                })
                .collect();
            vec![sel]
        }

        fn context(&self) -> &AirContext<Self::BaseField> {
            &self.context
        }
    }

    pub struct BlindedProver {
        options: ProofOptions,
    }

    impl Prover for BlindedProver {
        type BaseField = BaseElement;
        type Air = BlindedAir;
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
            PublicInputs {
                last_idx: trace.get(IDX, MEANINGFUL - 1),
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

    /// Preuve blindée : chaque appel tire un aléa de blindage FRAIS.
    pub fn prove(s: BaseElement) -> Proof {
        let prover = BlindedProver {
            options: proof_options(),
        };
        prover.prove(build_trace(s)).expect("génération blindée")
    }

    pub fn verify(proof: Proof) -> bool {
        let pi = PublicInputs {
            last_idx: BaseElement::new((MEANINGFUL - 1) as u64),
        };
        let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
        winterfell::verify::<BlindedAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
            proof, pi, &acceptable,
        )
        .is_ok()
    }
}

// ================================================================================================
// EXPÉRIENCES (tests --release, sortie avec --nocapture)
// ================================================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Le secret jouet : une valeur de champ arbitraire.
    fn secret() -> BaseElement {
        BaseElement::new(0xdead_beef_cafe_f00d)
    }

    /// EXPÉRIENCE A : la colonne constante fuit s EN CLAIR dans chaque ouverture.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn experience_a_baseline_fuite() {
        let s = secret();
        let t0 = Instant::now();
        let proof = baseline::prove(s);
        let dt = t0.elapsed();
        let size = proof.to_bytes().len();
        assert!(baseline::verify(proof.clone()), "baseline doit vérifier");

        let openings = secret_openings(&proof);
        assert!(!openings.is_empty());
        let leaked = openings.iter().filter(|&&v| v == s).count();
        println!(
            "[A] preuve {} o, {:?} ; {} ouvertures SECRET, {} == s",
            size,
            dt,
            openings.len(),
            leaked
        );
        println!("[A] premières ouvertures : {:?}", &openings[..4.min(openings.len())]);
        // Fuite totale : le polynôme constant s'évalue à s PARTOUT.
        assert_eq!(
            leaked,
            openings.len(),
            "attendu : toutes les ouvertures == s (fuite en clair)"
        );
    }

    /// EXPÉRIENCE B : avec b = 40 lignes d'aléa et contraintes gatées,
    /// la preuve vérifie ENCORE et les ouvertures ne valent plus s.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "AIR gaté : générer en --release")]
    fn experience_b_blindee_masquage() {
        let s = secret();

        let t0 = Instant::now();
        let proof1 = blinded::prove(s);
        let dt1 = t0.elapsed();
        let proof2 = blinded::prove(s); // même s, aléa de blindage frais
        let size = proof1.to_bytes().len();

        // 1) Complétude : les preuves blindées vérifient toujours.
        assert!(blinded::verify(proof1.clone()), "preuve blindée 1 doit vérifier");
        assert!(blinded::verify(proof2.clone()), "preuve blindée 2 doit vérifier");

        // 2) Masquage : plus aucune ouverture ne vaut s.
        let o1 = secret_openings(&proof1);
        let o2 = secret_openings(&proof2);
        let leaked1 = o1.iter().filter(|&&v| v == s).count();
        let leaked2 = o2.iter().filter(|&&v| v == s).count();
        println!(
            "[B] preuve {} o, {:?} ; {} ouvertures, fuites p1={} p2={}",
            size,
            dt1,
            o1.len(),
            leaked1,
            leaked2
        );
        println!("[B] premières ouvertures p1 : {:?}", &o1[..4.min(o1.len())]);
        println!("[B] premières ouvertures p2 : {:?}", &o2[..4.min(o2.len())]);
        assert_eq!(leaked1, 0, "aucune ouverture de p1 ne doit valoir s");
        assert_eq!(leaked2, 0, "aucune ouverture de p2 ne doit valoir s");

        // 3) Randomisation : deux preuves du MÊME s ouvrent des valeurs différentes.
        assert_ne!(o1, o2, "le masquage doit être randomisé, pas déterministe");
    }
}
