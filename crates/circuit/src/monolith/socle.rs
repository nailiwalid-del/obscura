//! Socle PARTAGÉ du monolithe : la construction cryptographique commune.
//!
//! Extrait du côte-à-côte au moment de sa suppression (C2-T8). Le côte-à-côte
//! (3z-b1) et le segmenté (3z-c1/c2) n'ont jamais différé que par la DISPOSITION
//! des colonnes : la construction elle-même — lignes d'éponge, bloc de clé
//! owner ∧ nk, lecture de digest, publics et assertions de préambule — était
//! identique, et vivait dans les modules du côte-à-côte. Sa suppression a donc
//! consisté à extraire ce socle, puis à effacer la disposition morte.
//!
//! Rien ici ne connaît un LAYOUT : pas un offset de colonne de trace. Ce qui
//! dépend de la disposition vit dans `seg_layout`/`seg_trace`/`seg_air`.

use crate::rescue_round::{NUM_ROUNDS, STATE_WIDTH, TRACE_LEN as ROUND_LEN};
use crate::spend::SpendNote;
use crate::sponge::{locate, sponge_rows, RATE_START, RATE_WIDTH, TRACE_WIDTH};
use crate::tx::ProvedInput;
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_FELTS};
use proved_hash::domain::{sponge_preamble, Domain, ENCODING_VERSION};
use proved_hash::felt::Felt;
use proved_hash::rescue::absorbed_len;
use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::Assertion;

/// Témoin complet du monolithe 2-in/2-out : le secret racine, les deux entrées
/// prouvées (note + chemin + position) et les deux sorties, plus les frais
/// publics. C'est la forme HISTORIQUE ; la forme variable passe par
/// `seg_trace::SegWitness` (qui sait se construire `depuis_2in2out`).
pub(crate) struct MonolithWitness {
    pub secret: ShieldedSecret,
    pub inputs: [ProvedInput; 2],
    pub outputs: [SpendNote; 2],
    pub fee: u64,
}

/// Lit un digest (4 Felts) dans un tampon de lignes largeur `N`, à `(row, col)`.
pub(crate) fn read_digest<const N: usize>(
    rows: &[[BaseElement; N]],
    row: usize,
    col: usize,
) -> Digest {
    Digest(core::array::from_fn(|k| {
        Felt::from_winter(rows[row][col + k]).expect("digest canonique")
    }))
}

/// Lignes d'une éponge `H_domain(payload)`, alignées PAD_ZERO* (motif de
/// `sponge::prove_sponge`, sans le prouveur).
pub(crate) fn sponge_rows_for(domain: Domain, payload: &[Felt]) -> Vec<[BaseElement; TRACE_WIDTH]> {
    let mut preamble: Vec<BaseElement> = sponge_preamble(domain, payload)
        .iter()
        .map(|f| f.to_winter())
        .collect();
    preamble.resize(absorbed_len(preamble.len()), BaseElement::ZERO);
    sponge_rows(&preamble)
}

// ================================================================================================
// CLÉ (recopie locale de `key::build_key_trace`, cf. brief T2 — 2 blocs B=1, 8 lignes)
// ================================================================================================

pub(crate) const KEY_WIDTH: usize = 2 * STATE_WIDTH; // 24
const KEY_SECRET_START: usize = RATE_START + 3; // 7
const KEY_PAD_ONE_IDX: usize = 11;
pub(crate) const KEY_NK_LOCAL_OFF: usize = STATE_WIDTH; // 12 : bloc nk dans les 24 colonnes locales
const KEY_ABSORBED_LEN: u64 = 8; // préambule [V, tag, LEN, s0..s3, PAD_ONE] = 1 bloc
const KEY_PAYLOAD_LEN: u64 = DIGEST_FELTS as u64;

/// État initial d'un bloc `H_domain(secret)` (capacité + préambule), identique à
/// `key::initial_state`.
fn key_initial_state(domain: Domain, secret: &[Felt; DIGEST_FELTS]) -> [BaseElement; STATE_WIDTH] {
    let mut st = [BaseElement::ZERO; STATE_WIDTH];
    st[0] = BaseElement::new(KEY_ABSORBED_LEN);
    st[RATE_START] = BaseElement::new(ENCODING_VERSION as u64);
    st[RATE_START + 1] = BaseElement::new(domain.tag() as u64);
    st[RATE_START + 2] = BaseElement::new(KEY_PAYLOAD_LEN);
    for (i, s) in secret.iter().enumerate() {
        st[KEY_SECRET_START + i] = s.to_winter();
    }
    st[KEY_PAD_ONE_IDX] = BaseElement::new(1);
    st
}

/// Lignes de la trace de clé : bloc owner (colonnes locales `0..12`) + bloc nk
/// (`12..24`) côte à côte, pour LE MÊME secret — recopie de `key::build_key_trace`
/// (sans dépendre de sa visibilité privée).
pub(crate) fn key_rows(secret: &[Felt; DIGEST_FELTS]) -> Vec<[BaseElement; KEY_WIDTH]> {
    key_rows_split(secret, secret)
}

/// Comme `key_rows` mais avec un secret DISTINCT par bloc (`s_owner` pour owner,
/// `s_nk` pour nk). Pour un témoin honnête `s_owner == s_nk` (la liaison secret
/// owner↔nk l'exige) ; le paramètre séparé sert uniquement à la forge
/// `SegForge::SecretNk` (miroir de `key::build_key_trace` à deux secrets).
pub(crate) fn key_rows_split(
    s_owner: &[Felt; DIGEST_FELTS],
    s_nk: &[Felt; DIGEST_FELTS],
) -> Vec<[BaseElement; KEY_WIDTH]> {
    let mut o = key_initial_state(Domain::Owner, s_owner);
    let mut n = key_initial_state(Domain::Nk, s_nk);
    let mut rows = Vec::with_capacity(ROUND_LEN);
    for step in 0..ROUND_LEN {
        let mut row = [BaseElement::ZERO; KEY_WIDTH];
        row[..STATE_WIDTH].copy_from_slice(&o);
        row[KEY_NK_LOCAL_OFF..].copy_from_slice(&n);
        rows.push(row);
        if step < NUM_ROUNDS {
            Rp64_256::apply_round(&mut o, step);
            Rp64_256::apply_round(&mut n, step);
        }
    }
    rows
}

/// Un élément de corps uniformément aléatoire (réduit mod p par winterfell).
pub(crate) fn felt_alea(rng: &mut impl rand::Rng) -> BaseElement {
    BaseElement::new(rng.next_u64())
}

// ================================================================================================
// ENTRÉES PUBLIQUES
// ================================================================================================

/// Publics du monolithe : racine partagée, un nullifier PAR ENTRÉE, un commitment
/// PAR SORTIE, les frais. `depth` (profondeur des chemins de Merkle) est engagé pour
/// que l'AIR connaisse la ligne de racine et le nombre de blocs assertés. Aucun
/// témoin (owner/nk/valeurs/rho/cm/secret) ici.
///
/// # La FORME (m, n) est portée par les LONGUEURS (3z-c2)
///
/// `nullifiers.len()` = m, `output_commitments.len()` = n : c'est ce que le
/// statement prévoyait (« nullifiers[] : un par note dépensée »), et c'est CE QUI
/// EST HACHÉ par Fiat-Shamir — `to_elements` préfixe les deux comptes, sinon deux
/// découpages différents des mêmes digests produiraient la même graine de
/// challenge, et une preuve pour (m=1, n=3) pourrait se rejouer comme (m=2, n=2).
/// L'AIR segmentée dérive son schedule de ces longueurs (C2-T3).
#[derive(Clone)]
pub(crate) struct MonolithPublicInputs {
    pub root: [BaseElement; DIGEST_FELTS],
    pub nullifiers: Vec<[BaseElement; DIGEST_FELTS]>,
    pub output_commitments: Vec<[BaseElement; DIGEST_FELTS]>,
    pub fee: u64,
    pub depth: usize,
}

impl MonolithPublicInputs {
    /// Nombre d'entrées de la forme déclarée.
    pub(crate) fn m(&self) -> usize {
        self.nullifiers.len()
    }

    /// Nombre de sorties de la forme déclarée.
    pub(crate) fn n(&self) -> usize {
        self.output_commitments.len()
    }
}

impl winterfell::math::ToElements<BaseElement> for MonolithPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity((1 + self.m() + self.n()) * DIGEST_FELTS + 4);
        // Les COMPTES d'abord : la forme fait partie de ce que la preuve engage.
        v.push(BaseElement::new(self.m() as u64));
        v.push(BaseElement::new(self.n() as u64));
        v.extend_from_slice(&self.root);
        for nf in &self.nullifiers {
            v.extend_from_slice(nf);
        }
        for oc in &self.output_commitments {
            v.extend_from_slice(oc);
        }
        v.push(BaseElement::new(self.fee));
        v.push(BaseElement::new(self.depth as u64));
        v
    }
}

// ================================================================================================
// ASSERTIONS DE PRÉAMBULE
// ================================================================================================

/// Assertions de préambule d'une éponge (capacité + VERSION/tag/LEN/PAD_ONE +
/// PAD_ZERO\*), à la ligne `seg_start`, aux colonnes `col_off..col_off+20`.
/// Positions issues de `locate` DÉCALÉES par l'offset de colonne et la ligne de
/// début de segment. N'asserte AUCUN témoin (payload jamais public ici).
pub(crate) fn push_preamble(
    a: &mut Vec<Assertion<BaseElement>>,
    seg_start: usize,
    col_off: usize,
    m: u64,
    tag: u64,
    payload_len: usize,
) {
    // Capacité [longueur absorbée, 0, 0, 0] à la ligne de début.
    a.push(Assertion::single(col_off, seg_start, BaseElement::new(m)));
    a.push(Assertion::single(col_off + 1, seg_start, BaseElement::ZERO));
    a.push(Assertion::single(col_off + 2, seg_start, BaseElement::ZERO));
    a.push(Assertion::single(col_off + 3, seg_start, BaseElement::ZERO));
    // VERSION (idx 0), tag (1), LEN (2) au bloc 0, PAD_ONE à sa position logique.
    for (i, val) in [
        (0usize, ENCODING_VERSION as u64),
        (1, tag),
        (2, payload_len as u64),
        (3 + payload_len, 1),
    ] {
        let (row, col) = locate(i);
        a.push(Assertion::single(
            col_off + col,
            seg_start + row,
            BaseElement::new(val),
        ));
    }
    // PAD_ZERO* : toutes les cellules ABSORBÉES au-delà de la longueur LOGIQUE
    // `3 + payload_len + 1`, jusqu'à la frontière de bloc `⌈m/8⌉·8` (couvre à la
    // fois le PAD_ZERO* du resize — commitment, 17..32 — ET le zéro-remplissage du
    // bloc partiel — merge m=12, cellules 12..16). La contrainte d'absorption les
    // ADDITIONNE au rate : les laisser libres permettrait de prouver
    // `H(payload ‖ junk)` au lieu du `H(payload)` canonique (« hash jamais
    // tronqué ») — cm'/node' internement cohérents mais hors du schéma. On les
    // épingle donc à ZÉRO. No-op quand le préambule remplit exactement ses blocs
    // (clé, feuille, nullifier).
    let logical = 3 + payload_len + 1;
    let cells = (m as usize).div_ceil(RATE_WIDTH) * RATE_WIDTH;
    for i in logical..cells {
        let (row, col) = locate(i);
        a.push(Assertion::single(
            col_off + col,
            seg_start + row,
            BaseElement::ZERO,
        ));
    }
}

// ================================================================================================
// TÉMOINS DE TEST (partagés par les tests de seg_trace/seg_air et de tx)
// ================================================================================================

#[cfg(test)]
fn digest(seed: u64) -> Digest {
    Digest(core::array::from_fn(|i| {
        Felt::from_canonical_u64(seed + i as u64).unwrap()
    }))
}

/// Prolonge un cœur d'arbre de profondeur 2 jusqu'à `depth` : les deux entrées
/// vivent aux index 0 et 3, donc dans le sous-arbre le plus à GAUCHE de chaque
/// niveau supérieur — le nœud courant est enfant gauche partout, et chaque niveau
/// ajoute UN frère muet (le même pour les deux chemins). C'est ce qui permet aux
/// forges à reconstruction de tourner à la profondeur CONSENSUS (dette D8) sans
/// matérialiser 2^32 feuilles.
#[cfg(test)]
fn prolonger(
    mut root: Digest,
    mut path0: Vec<Digest>,
    mut path1: Vec<Digest>,
    depth: usize,
) -> (Digest, Vec<Digest>, Vec<Digest>) {
    use proved_hash::merkle;
    assert!(depth >= 2, "l'arbre synthétique commence à la profondeur 2");
    for niveau in 2..depth {
        let frere = merkle::leaf(&digest(9100 + niveau as u64));
        path0.push(frere);
        path1.push(frere);
        root = merkle::node(&root, &frere);
    }
    (root, path0, path1)
}

/// Arbre synthétique de profondeur `depth` (≥ 2) : `cm0` en index 0, `cm1` en
/// index 3, deux feuilles muettes au bas, un frère muet par niveau au-dessus.
/// Recopie généralisée de `tx.rs::tests::build_tree` (profondeur 2 historique).
#[cfg(test)]
fn build_tree(cm0: &Digest, cm1: &Digest, depth: usize) -> (Digest, Vec<Digest>, Vec<Digest>) {
    use proved_hash::merkle;
    let l0 = merkle::leaf(cm0);
    let l1 = merkle::leaf(&digest(9001));
    let l2 = merkle::leaf(&digest(9002));
    let l3 = merkle::leaf(cm1);
    let n_left = merkle::node(&l0, &l1);
    let n_right = merkle::node(&l2, &l3);
    let root = merkle::node(&n_left, &n_right);
    let path0 = vec![l1, n_right];
    let path1 = vec![l2, n_left];
    prolonger(root, path0, path1, depth)
}

/// Arbre de profondeur `depth` à partir des FEUILLES injectées directement (idx 0
/// et 3, feuilles muettes ailleurs), miroir de `build_tree` mais sans re-hacher
/// les cm — utilisé par la forge pour reconstruire un arbre cohérent après
/// réécriture d'une feuille.
#[cfg(test)]
pub(crate) fn build_tree_from_leaves(
    leaf0: &Digest,
    leaf1: &Digest,
    depth: usize,
) -> (Digest, Vec<Digest>, Vec<Digest>) {
    use proved_hash::merkle;
    let l0 = *leaf0;
    let l1 = merkle::leaf(&digest(9001));
    let l2 = merkle::leaf(&digest(9002));
    let l3 = *leaf1;
    let n_left = merkle::node(&l0, &l1);
    let n_right = merkle::node(&l2, &l3);
    let root = merkle::node(&n_left, &n_right);
    prolonger(root, vec![l1, n_right], vec![l2, n_left], depth)
}

/// Témoin de test : deux entrées (1000/500, même `owner`) équilibrées avec deux
/// sorties (900/580) + fee 20, arbre de profondeur 2.
#[cfg(test)]
pub(crate) fn witness_de_test() -> (MonolithWitness, Digest) {
    witness_de_test_profondeur(2)
}

/// Le même témoin, sur un arbre SYNTHÉTIQUE de profondeur `depth` (index 0 et 3,
/// frères muets au-dessus). C'est ce qui permet de rejouer les forges à
/// reconstruction d'arbre à la profondeur CONSENSUS (dette D8) — contrairement à
/// `witness_de_test_profondeur_consensus`, dont l'arbre `ProvedMerkleTree` réel
/// place ses feuilles aux index 0 et 1 (la reconstruction, elle, suppose 0 et 3).
#[cfg(test)]
pub(crate) fn witness_de_test_profondeur(depth: usize) -> (MonolithWitness, Digest) {
    use proved_hash::rescue;

    let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(700 + i as u64).unwrap()
    }));
    let owner = rescue::hash(Domain::Owner, secret.as_felts());

    let n0 = SpendNote {
        value: 1_000,
        owner,
        rho: digest(20),
        r: digest(30),
    };
    let n1 = SpendNote {
        value: 500,
        owner,
        rho: digest(40),
        r: digest(50),
    };
    let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
    let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
    let (root, path0, path1) = build_tree(&cm0, &cm1, depth);

    // Sorties : 900 + 580 + fee 20 = 1500 = 1000 + 500.
    let o0 = SpendNote {
        value: 900,
        owner: digest(60),
        rho: digest(61),
        r: digest(62),
    };
    let o1 = SpendNote {
        value: 580,
        owner: digest(70),
        rho: digest(71),
        r: digest(72),
    };

    let inputs = [
        ProvedInput {
            note: n0,
            path: path0,
            index: 0,
        },
        ProvedInput {
            note: n1,
            path: path1,
            index: 3,
        },
    ];

    let w = MonolithWitness {
        secret,
        inputs,
        outputs: [o0, o1],
        fee: 20,
    };
    (w, root)
}

/// Témoin de test à profondeur CONSENSUS (32) : mêmes notes que `witness_de_test`,
/// mais insérées dans un vrai arbre `ProvedMerkleTree::consensus()` → chemins de
/// longueur 32. Sert aux roundtrips lents à la profondeur réelle.
#[cfg(test)]
pub(crate) fn witness_de_test_profondeur_consensus() -> (MonolithWitness, Digest) {
    use proved_hash::merkle::ProvedMerkleTree;
    use proved_hash::rescue;

    let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(700 + i as u64).unwrap()
    }));
    let owner = rescue::hash(Domain::Owner, secret.as_felts());

    let n0 = SpendNote {
        value: 1_000,
        owner,
        rho: digest(20),
        r: digest(30),
    };
    let n1 = SpendNote {
        value: 500,
        owner,
        rho: digest(40),
        r: digest(50),
    };
    let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
    let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

    let mut tree = ProvedMerkleTree::consensus();
    let i0 = tree.append(&cm0);
    let i1 = tree.append(&cm1);
    let root = tree.root();
    let path0 = tree.path(i0).unwrap();
    let path1 = tree.path(i1).unwrap();

    let o0 = SpendNote {
        value: 900,
        owner: digest(60),
        rho: digest(61),
        r: digest(62),
    };
    let o1 = SpendNote {
        value: 580,
        owner: digest(70),
        rho: digest(71),
        r: digest(72),
    };
    let inputs = [
        ProvedInput {
            note: n0,
            path: path0,
            index: i0,
        },
        ProvedInput {
            note: n1,
            path: path1,
            index: i1,
        },
    ];
    let w = MonolithWitness {
        secret,
        inputs,
        outputs: [o0, o1],
        fee: 20,
    };
    (w, root)
}
