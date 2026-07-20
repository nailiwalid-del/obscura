//! Ronde Rescue-XLIX (Rp64_256) partagée par tous les AIR d'Obscura.
//!
//! Contrainte **meet-in-the-middle** (patron : exemple `rescue` de winterfell).
//! Une ronde est `sbox -> MDS -> +ARK1` puis `inv_sbox -> MDS -> +ARK2`. L'inverse
//! S-box est de degré prohibitif : on ne l'évalue jamais. On va en AVANT depuis
//! l'état courant, en ARRIÈRE depuis le suivant, et on impose l'égalité au milieu :
//!
//! ```text
//! forward  : step1 = MDS·sbox(current) + ARK1
//! backward : step2 = sbox( INV_MDS·(next − ARK2) )
//! contrainte : step1 == step2                        (degré ALPHA = 7)
//! ```
//!
//! Toutes les constantes viennent des `pub const` de `Rp64_256` → aucune divergence
//! possible avec le hash hors-circuit (`proved-hash`).

use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
// EvaluationFrame/TraceTable/TransitionConstraintDegree ne servent qu'aux helpers
// des AIR standalone (`rescue_perm`, `owner_hash`) — gatés `dev-circuits`.
#[cfg(feature = "dev-circuits")]
use winterfell::{EvaluationFrame, TraceTable, TransitionConstraintDegree};

/// Largeur d'état de Rp64_256.
pub const STATE_WIDTH: usize = 12;
/// Nombre de rondes.
pub const NUM_ROUNDS: usize = 7;
/// Longueur de trace : état initial + une ligne par ronde (puissance de 2).
pub const TRACE_LEN: usize = 8;
/// Exposant de la S-box.
pub const ALPHA: u32 = 7;

pub(crate) fn apply_sbox<E: FieldElement>(state: &mut [E; STATE_WIDTH]) {
    for s in state.iter_mut() {
        *s = s.exp(ALPHA.into());
    }
}

pub(crate) fn apply_matrix<E: FieldElement + From<BaseElement>>(
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

/// Degrés des contraintes : une par élément d'état, de degré ALPHA.
///
/// Pas de `with_cycles` : les ARK n'introduisent pas de facteur périodique
/// MULTIPLICATIF (contrairement au `flag` de l'exemple `rescue`). Elles sont
/// additionnées à l'intérieur de la S-box — c'est l'élévation `^ALPHA` qui fixe
/// le degré. Déclarer un cycle ici provoque « transition constraint degrees
/// didn't match ».
#[cfg(feature = "dev-circuits")]
pub(crate) fn transition_degrees() -> Vec<TransitionConstraintDegree> {
    vec![TransitionConstraintDegree::new(ALPHA as usize); STATE_WIDTH]
}

/// Colonnes périodiques : ARK1[0..12] puis ARK2[0..12], cycle de `TRACE_LEN`.
/// Les rondes 0..6 portent les constantes ; la dernière entrée n'est jamais
/// utilisée (pas de transition depuis la dernière ligne).
pub(crate) fn periodic_ark_columns() -> Vec<Vec<BaseElement>> {
    let mut cols = Vec::with_capacity(2 * STATE_WIDTH);
    for ark in [&Rp64_256::ARK1, &Rp64_256::ARK2] {
        // Transposition ARK[ronde][état] → colonnes[état][ronde] : `i` indexe la
        // colonne (état) au sein de CHAQUE ligne `ark[r]` (une par ronde), pas un
        // conteneur unique — le for-range est donc volontaire, pas un
        // `needless_range_loop` classique (`ark.iter()` itérerait sur les 7 rondes,
        // pas les 12 colonnes). Reformulé en `.map` pour rester silencieux côté
        // clippy sans changer l'ordre ni les valeurs produites.
        let cs = (0..STATE_WIDTH).map(|i| {
            let mut c = vec![BaseElement::ZERO; TRACE_LEN];
            for (r, c_r) in c.iter_mut().enumerate().take(NUM_ROUNDS) {
                *c_r = ark[r][i];
            }
            c
        });
        cols.extend(cs);
    }
    cols
}

/// Impose une ronde Rescue sur le bloc d'état à l'offset `off` (meet-in-the-middle),
/// écrivant dans `result[off..off+STATE_WIDTH]`. Lit l'état dans `cur[off..]` /
/// `next[off..]`. Partagé par `key.rs` (2 blocs côte à côte) et le monolithe (bloc
/// clé aux colonnes du layout global).
pub(crate) fn enforce_round_block<E: FieldElement + From<BaseElement>>(
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

/// Impose une ronde Rescue entre l'état courant et le suivant.
#[cfg(feature = "dev-circuits")]
pub(crate) fn enforce_round<E: FieldElement + From<BaseElement>>(
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

/// Construit la trace de la permutation : ligne 0 = état initial, ligne i+1 = ronde i.
#[cfg(feature = "dev-circuits")]
pub(crate) fn build_perm_trace(initial: [BaseElement; STATE_WIDTH]) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(STATE_WIDTH, TRACE_LEN);
    trace.fill(
        |state| {
            state.copy_from_slice(&initial);
        },
        |step, state| {
            // `fill` appelle cette closure pour step = 0..TRACE_LEN-2, soit les 7 rondes.
            if step < NUM_ROUNDS {
                let mut s: [BaseElement; STATE_WIDTH] = state.try_into().expect("largeur d'état");
                Rp64_256::apply_round(&mut s, step);
                state.copy_from_slice(&s);
            }
        },
    );
    trace
}
