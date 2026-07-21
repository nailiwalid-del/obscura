//! Constructeur de trace du monolithe SEGMENTÉ (3z-c1, tâche T2).
//!
//! Contrairement au monolithe côte-à-côte historique (3z-b1, supprimé en C2-T8),
//! qui rangeait chaque entrée/sortie dans SES PROPRES colonnes sur les mêmes
//! lignes, celui-ci empile les unités en **segments séquentiels de lignes**
//! partageant les MÊMES colonnes : `[KEY][IN×m][OUT×n]` puis les lignes de
//! blinding. C'est ce qui permet (3z-c2) de faire varier le NOMBRE
//! d'entrées/sorties sans exploser la largeur — le côte-à-côte plafonnait à
//! ~255 colonnes.
//!
//! Ce module ne fait tourner AUCUN prouveur : il est la RÉFÉRENCE DIFFÉRENTIELLE
//! de la disposition segmentée (les cellules produites doivent coïncider avec
//! `rescue::note_commitment`, `merkle::leaf`, `merkle::fold`). L'AIR segmentée
//! vit dans `seg_air`.
//!
//! Les gadgets de lignes (`key_rows`, `sponge_rows_for`, `merkle_path::path_rows`)
//! viennent du socle partagé (`super::socle`) — la même construction
//! cryptographique que le côte-à-côte utilisait, seule la DISPOSITION diffère.
//! C'est ce qui rendait l'oracle de parité crédible tant qu'il a existé.
//!
//! Witness-hiding (3z-b1) : la région `[used_rows, trace_len)` est remplie d'aléa
//! frais sur toutes les colonnes.

use super::seg_layout::*;
use super::socle::{
    felt_alea, key_rows, key_rows_split, read_digest, sponge_rows_for, MonolithWitness,
    KEY_NK_LOCAL_OFF,
};
use crate::sponge::RATE_START;
use proved_hash::digest::{Digest, DIGEST_FELTS};
use proved_hash::domain::Domain;
use proved_hash::rescue::note_commit_payload;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;
use winterfell::TraceTable;

/// Témoin du monolithe segmenté à FORME VARIABLE (3z-c2) : m entrées, n sorties.
///
/// Construit VALIDÉ : la forme sort du constructeur ou pas du tout — les bornes
/// `1..=MAX` vivent dans `Forme::new`, et les profondeurs des chemins doivent
/// concorder (deux entrées prouvant à des profondeurs différentes ne décrivent pas
/// le même arbre ; un témoin pareil est un bug de l'appelant, pas une entrée
/// hostile — le prouveur est notre propre wallet — d'où l'`assert`).
pub(crate) struct SegWitness {
    pub secret: proved_hash::digest::ShieldedSecret,
    pub inputs: Vec<crate::ProvedInput>,
    pub outputs: Vec<crate::SpendNote>,
    /// Consommé à partir de C2-T3 (les publics à forme variable sortent du témoin).
    #[allow(dead_code)]
    pub fee: u64,
    forme: Forme,
}

impl SegWitness {
    pub(crate) fn new(
        secret: proved_hash::digest::ShieldedSecret,
        inputs: Vec<crate::ProvedInput>,
        outputs: Vec<crate::SpendNote>,
        fee: u64,
    ) -> Result<Self, FormeInvalide> {
        let forme = Forme::new(inputs.len(), outputs.len())?;
        let depth = inputs[0].path.len();
        assert!(
            inputs.iter().all(|i| i.path.len() == depth),
            "tous les chemins d'un témoin doivent avoir la même profondeur"
        );
        Ok(SegWitness {
            secret,
            inputs,
            outputs,
            fee,
            forme,
        })
    }

    pub(crate) fn forme(&self) -> Forme {
        self.forme
    }

    /// Conversion depuis le témoin 2/2 historique : `prove_seg_monolith` prend un
    /// `MonolithWitness`, et toute la suite 2/2 tourne sur le chemin GÉNÉRALISÉ
    /// via cette conversion.
    pub(crate) fn depuis_2in2out(w: &MonolithWitness) -> SegWitness {
        SegWitness::new(
            w.secret.clone(),
            w.inputs.to_vec(),
            w.outputs.to_vec(),
            w.fee,
        )
        .expect("2/2 est une forme valide")
    }
}

/// Recopie `rows` (segment de lignes × colonnes) dans le tampon segmenté à
/// `(row_off, col_off)`, à la largeur du TAMPON (`WIDTH_MAX`).
fn seg_copy<const N: usize>(
    dst: &mut [[BaseElement; WIDTH_MAX]],
    rows: &[[BaseElement; N]],
    row_off: usize,
    col_off: usize,
) {
    for (i, row) in rows.iter().enumerate() {
        dst[row_off + i][col_off..col_off + N].copy_from_slice(row);
    }
}

/// Écrit un digest sur TOUTES les lignes d'une colonne porteuse (valeur constante,
/// lisible depuis n'importe quel segment — c'est le mécanisme de chaînage
/// inter-segments, inchangé par rapport au côte-à-côte).
fn set_carrier_digest(rows: &mut [[BaseElement; WIDTH_MAX]], col: usize, d: &Digest) {
    let be: [BaseElement; DIGEST_FELTS] = core::array::from_fn(|k| d.0[k].to_winter());
    for row in rows.iter_mut() {
        row[col..col + DIGEST_FELTS].copy_from_slice(&be);
    }
}

/// Idem pour une porteuse scalaire (montants).
fn set_carrier_scalar(rows: &mut [[BaseElement; WIDTH_MAX]], col: usize, v: u64) {
    let be = BaseElement::new(v);
    for row in rows.iter_mut() {
        row[col] = be;
    }
}

/// Point de forge : réécrit UN côté d'une liaison porteuse↔gadget en gardant le
/// PRODUCTEUR (la porteuse) honnête, pour qu'une trace forgée ne diffère d'une
/// trace honnête QUE par l'égalité de liaison ciblée.
///
/// Contrairement au côte-à-côte — qui a DEUX constructeurs quasi identiques
/// (`build_monolith_trace_seeded` et `build_monolith_trace_forge`), un piège de
/// maintenance : une correction sur l'un peut manquer l'autre — la forge est ici
/// un PARAMÈTRE du constructeur unique.
///
/// Ne figurent ici que les forges SANS reconstruction d'arbre : celles qui
/// altèrent le commitment ou la feuille changent la racine, ce qui ferait mordre
/// la liaison `root_in` au lieu de la liaison visée — il faut alors rebâtir
/// l'arbre pour que les deux entrées restent sur la MÊME racine. Reste à porter.
// Machinerie de forge : utilisée UNIQUEMENT par les tests de soundness, mais le
// type doit exister hors tests car il paramètre `build_seg_trace_interne` (chemin
// de code UNIQUE pour l'honnête et le forgé — cf. doc ci-dessus).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) enum SegForge {
    /// Trace honnête.
    #[default]
    Aucune,
    /// Le bloc nk dérive d'un secret `s' ≠ s` (le bloc owner garde `s`). owner et
    /// nk restent INDIVIDUELLEMENT corrects pour leur propre secret et toute la
    /// cascade est honnête : SEULE la liaison secret owner↔nk peut mordre. Sans
    /// elle, un prouveur dérive owner d'une note qu'il possède et nk d'une AUTRE
    /// → nullifier arbitraire → double-dépense.
    SecretNk(Digest),
    /// `nk` CONSOMMÉ dans le nullifier de l'entrée `i` ≠ nk produit par la clé
    /// (porteuse `NK_C` honnête). Aval : le nullifier change, rien d'autre.
    NkConsomme(usize, Digest),
    /// `rho` CONSOMMÉ dans le NULLIFIER de l'entrée `i` ≠ rho de la porteuse
    /// (côté commitment intact). Aval : le nullifier change.
    RhoNullifier(usize, Digest),
    /// `cm` CONSOMMÉ dans le NULLIFIER de l'entrée `i` ≠ cm produit par le
    /// commitment. C'est LA liaison anti-double-dépense : sans elle un nullifier
    /// peut être calculé sur un autre commitment que celui réellement dépensé.
    CmNullifier(usize, Digest),

    // --- Forges qui altèrent le COMMITMENT ou la FEUILLE : elles changent la
    //     racine, donc l'arbre est REBÂTI (cf. `rebatit_arbre`) pour que les deux
    //     entrées restent sur la MÊME racine — sans quoi `root_in` mordrait à la
    //     place de la liaison visée et le test ne prouverait rien. ---
    /// `owner` CONSOMMÉ dans le commitment de l'entrée `i` ≠ owner produit par la
    /// clé (porteuse `OWNER_C` honnête). Sans cette liaison, un prouveur dépense
    /// une note dont il n'est PAS le propriétaire.
    OwnerConsomme(usize, Digest),
    /// `rho` CONSOMMÉ dans le COMMITMENT de l'entrée `i` (cellules @7, DISJOINTES
    /// du côté nullifier ciblé par `RhoNullifier`) ≠ rho de la porteuse.
    RhoCommitment(usize, Digest),
    /// `cm` CONSOMMÉ dans la FEUILLE de l'entrée `i` ≠ cm produit par le commitment.
    CmFeuille(usize, Digest),
    /// Feuille INJECTÉE dans le chemin de l'entrée `i` ≠ feuille produite par
    /// l'éponge (porteuse `LEAF_C` honnête).
    LeafChemin(usize, Digest),

    /// Les bits du segment d'ENTRÉE 0 décomposent `valeur₀ + k`, ceux de l'entrée 1
    /// `valeur₁ − k`. Deux segments de MÊME signe (+) : la somme signée `S` est
    /// inchangée, donc `S_final = fee` tient et l'assertion d'équilibre ne masque
    /// PAS la forge. Les porteuses `VIN_C` restent honnêtes → seules les liaisons
    /// VIN↔VACC diffèrent. Isole la famille VIN de la famille VOUT.
    ValeurEntrees(u64),
    /// Miroir sur les deux segments de SORTIE (signe −) : isole VOUT de VIN.
    ValeurSorties(u64),
    /// Région de blinding remplie de valeurs ADVERSES au lieu d'aléa frais (copies
    /// de lignes utiles, bits non booléens, `S` sautant, porteuses discontinues).
    ///
    /// ⚠️ Test d'INERTIE, à l'inverse de toutes les autres : la transaction doit
    /// rester **ACCEPTÉE**. Aucune contrainte (toutes gatées `blind_off`) ni
    /// assertion (toutes `< used`) ne lit cette région — l'attaquant n'y gagne rien.
    BlindingAdversarial,

    /// `PAD_ZERO*` NON CANONIQUE dans le commitment de l'entrée 0 : la première
    /// cellule de padding (idx 17) vaut `v ≠ 0`.
    ///
    /// L'absorption ADDITIONNE cette cellule au rate, donc le digest devient
    /// `cm' = H(payload ‖ v ‖ 0…)` — INTERNEMENT cohérent (rondes et absorptions
    /// valides), et tout l'aval cascade honnêtement sur `cm'`. SEULE l'assertion
    /// `PAD_ZERO` distingue la forge : sans elle, un prouveur publie un commitment
    /// HORS du schéma canonique (LEN annonce 13 mais 15 cellules de junk sont
    /// absorbées) — violation de « hash jamais tronqué ».
    PaddingCommitment(u64),

    /// INFLATION par `VACC` initial libre — forge FINE (à ne pas confondre avec un
    /// écrasement brutal de la cellule).
    ///
    /// Le segment KEY ne produit pas d'`endblk`, donc le `VACC` de la première ligne
    /// du premier segment d'ENTRÉE n'est remis à zéro par aucune transition : c'est
    /// un témoin LIBRE. Le prouveur y met `−k` et décompose `valeur₀ + k` en bits.
    /// À la ligne d'ancrage, `VACC = −k + (valeur₀ + k) = valeur₀` — la liaison
    /// VIN↔VACC reste donc HONNÊTE — mais `S` a encaissé `valeur₀ + k`.
    ///
    /// La sortie 0 est gonflée de `k` (commitment, porteuse VOUT et bits tous
    /// cohérents à la nouvelle valeur) pour que `S_final = fee` tienne et que
    /// l'assertion d'équilibre ne rejette pas AVANT l'ancrage.
    ///
    /// Résultat : TOUTE la trace est cohérente sauf `VACC[première ligne] ≠ 0`.
    /// Seul l'ancrage `VACC = 0` ferme le trou — sans lui, `k` unités sont créées
    /// ex nihilo.
    VaccInitial(u64),
}

#[cfg_attr(not(test), allow(dead_code))]
impl SegForge {
    /// `true` si la forge change une feuille injectée dans l'arbre : il faut alors
    /// rebâtir l'arbre pour que les deux entrées gardent la MÊME racine.
    fn rebatit_arbre(self) -> bool {
        matches!(
            self,
            SegForge::OwnerConsomme(..)
                | SegForge::RhoCommitment(..)
                | SegForge::CmFeuille(..)
                | SegForge::LeafChemin(..)
                | SegForge::PaddingCommitment(..)
        )
    }

    /// Owner à CONSOMMER dans le commitment de l'entrée `i` (honnête par défaut).
    fn owner_commit(self, i: usize, honnete: Digest) -> Digest {
        match self {
            SegForge::OwnerConsomme(fi, a) if fi == i => a,
            _ => honnete,
        }
    }

    /// Rho à CONSOMMER dans le commitment de l'entrée `i`.
    fn rho_commit(self, i: usize, honnete: Digest) -> Digest {
        match self {
            SegForge::RhoCommitment(fi, a) if fi == i => a,
            _ => honnete,
        }
    }

    /// Cm à CONSOMMER dans la feuille de l'entrée `i`.
    fn cm_feuille(self, i: usize, honnete: Digest) -> Digest {
        match self {
            SegForge::CmFeuille(fi, a) if fi == i => a,
            _ => honnete,
        }
    }

    /// Feuille à INJECTER dans le chemin de l'entrée `i`.
    fn leaf_chemin(self, i: usize, honnete: Digest) -> Digest {
        match self {
            SegForge::LeafChemin(fi, a) if fi == i => a,
            _ => honnete,
        }
    }

    /// Valeur réellement DÉCOMPOSÉE en bits dans le segment (la porteuse, elle,
    /// garde la valeur honnête). `+k` sur l'unité 0, `−k` sur l'unité 1 : de même
    /// signe, donc `S` est inchangé et l'assertion d'équilibre ne masque pas la
    /// forge.
    fn valeur_bits(self, est_entree: bool, n: usize, honnete: u64) -> u64 {
        // VaccInitial : l'entrée 0 décompose `valeur₀ + k` (compensée par le VACC
        // initial à −k, donc la liaison VIN reste honnête) et la sortie 0 est
        // gonflée de `k` pour que `S_final = fee` tienne.
        // ⚠️ Uniquement l'ENTRÉE 0. Le gonflement de la sortie 0 est déjà appliqué en
        // amont par `valeur_sortie` (qui fixe commitment ET porteuse VOUT) et
        // `honnete` le porte donc déjà : ré-ajouter `k` ici ferait décomposer
        // `out₀ + 2k` face à une porteuse à `out₀ + k` — la liaison VOUT mordrait et
        // masquerait l'ancrage VACC qu'on veut tester.
        if let SegForge::VaccInitial(k) = self {
            return if est_entree && n == 0 { honnete + k } else { honnete };
        }
        let k = match (self, est_entree) {
            (SegForge::ValeurEntrees(k), true) => k,
            (SegForge::ValeurSorties(k), false) => k,
            _ => return honnete,
        };
        match n {
            0 => honnete + k,
            _ => honnete - k,
        }
    }

    /// `VACC` de DÉPART du segment (0 pour une trace honnête). Non nul uniquement
    /// pour `VaccInitial`, et seulement sur le premier segment d'entrée.
    fn vacc_initial(self, est_entree: bool, n: usize) -> BaseElement {
        match self {
            SegForge::VaccInitial(k) if est_entree && n == 0 => -BaseElement::new(k),
            _ => BaseElement::ZERO,
        }
    }

    /// Valeur réelle de la sortie `n` (commitment, porteuse VOUT et bits cohérents).
    /// `VaccInitial` gonfle la sortie 0 de `k` pour compenser l'entrée.
    fn valeur_sortie(self, n: usize, honnete: u64) -> u64 {
        match self {
            SegForge::VaccInitial(k) if n == 0 => honnete + k,
            _ => honnete,
        }
    }
}

/// Lignes d'éponge du commitment de l'entrée `i`, forge de padding comprise.
///
/// Avec `PaddingCommitment`, on rebâtit le préambule, on écrase la première cellule
/// `PAD_ZERO` puis on REJOUE l'éponge : la trace reste internement cohérente
/// (rondes et absorptions valides) et produit un digest `cm'` hors schéma canonique.
fn lignes_commitment(
    payload: &[proved_hash::felt::Felt],
    i: usize,
    forge: SegForge,
) -> Vec<[BaseElement; crate::sponge::TRACE_WIDTH]> {
    match forge {
        SegForge::PaddingCommitment(v) if i == 0 => {
            use proved_hash::domain::sponge_preamble;
            use proved_hash::rescue::absorbed_len;
            let mut preamble: Vec<BaseElement> =
                sponge_preamble(Domain::NoteCommitment, payload)
                    .iter()
                    .map(|f| f.to_winter())
                    .collect();
            preamble.resize(absorbed_len(preamble.len()), BaseElement::ZERO);
            preamble[17] = BaseElement::new(v); // première cellule PAD_ZERO
            crate::sponge::sponge_rows(&preamble)
        }
        _ => sponge_rows_for(Domain::NoteCommitment, payload),
    }
}

/// Commitment tel qu'il apparaîtra RÉELLEMENT dans la trace pour l'entrée `i`
/// (forges comprises) — y compris la forge de padding, dont le digest ne peut pas
/// se recalculer via `rescue::note_commitment`.
#[cfg_attr(not(test), allow(dead_code))]
fn commitment_injecte(w: &SegWitness, i: usize, forge: SegForge) -> Digest {
    let note = &w.inputs[i].note;
    let owner = forge.owner_commit(i, note.owner);
    let rho = forge.rho_commit(i, note.rho);
    let payload = note_commit_payload(note.value, &owner, &rho, &note.r);
    let rows = lignes_commitment(&payload, i, forge);
    read_digest(&rows, rows.len() - 1, RATE_START)
}

/// Feuille qui sera réellement injectée dans l'arbre pour l'entrée `i`, forges
/// comprises. Utilisé par la pré-passe de reconstruction d'arbre.
#[cfg_attr(not(test), allow(dead_code))]
fn feuille_injectee(w: &SegWitness, i: usize, forge: SegForge) -> Digest {
    let cm = commitment_injecte(w, i, forge);
    let cm_leaf = forge.cm_feuille(i, cm);
    let leaf = proved_hash::merkle::leaf(&cm_leaf);
    forge.leaf_chemin(i, leaf)
}

/// Construit la trace segmentée avec un aléa de blinding tiré d'`OsRng`
/// (production). Voir `build_seg_trace_seeded` pour la couture de test.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_seg_trace(w: &MonolithWitness) -> TraceTable<BaseElement> {
    build_seg_trace_seeded(w, &mut rand::rngs::OsRng)
}

/// Point d'entrée à FORME VARIABLE (3z-c2). Les fonctions `MonolithWitness`
/// ci-dessous convertissent vers celui-ci : UN seul chemin de construction.
pub(crate) fn build_seg_trace_forme_seeded(
    w: &SegWitness,
    rng: &mut impl rand::Rng,
) -> TraceTable<BaseElement> {
    build_seg_trace_interne(w, rng, SegForge::Aucune)
}

/// Trace FORGÉE à forme variable (soundness C2-T4). Aléa de production, une liaison
/// sabotée. ⚠️ Les forges à RECONSTRUCTION d'arbre restent 2/2 (assertion interne) :
/// seules les forges SANS reconstruction s'appliquent à une forme quelconque.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_seg_trace_forme_forge(
    w: &SegWitness,
    forge: SegForge,
) -> TraceTable<BaseElement> {
    build_seg_trace_interne(w, &mut rand::rngs::OsRng, forge)
}

/// Trace segmentée FORGÉE (tests de soundness) : aléa de production, mais une
/// liaison sabotée.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_seg_trace_forge(
    w: &MonolithWitness,
    forge: SegForge,
) -> TraceTable<BaseElement> {
    build_seg_trace_interne(&SegWitness::depuis_2in2out(w), &mut rand::rngs::OsRng, forge)
}

/// Construit la trace segmentée du monolithe 2-in/2-out à partir du témoin `w`.
///
/// Parcourt le SCHEDULE (`schedule_2in2out`) et remplit chaque segment à sa ligne
/// de début (`seg_start`), selon son `SegKind` :
/// - `Key` : les deux blocs d'éponge owner/nk du MÊME secret (côte à côte en
///   colonnes dans le segment — 24 colonnes) ;
/// - `Input` : pile d'éponge `commitment → feuille → nullifier` (lignes locales
///   0..56) ET chemin de Merkle (lignes locales 0..16·depth) EN PARALLÈLE sur des
///   groupes de colonnes disjoints, plus les bits du montant ;
/// - `Output` : éponge de commitment (lignes locales 0..32) plus les bits du montant.
///
/// L'accumulateur d'équilibre `S` est CHAÎNÉ à travers tous les segments (colonne
/// partagée `S_COL`) : il vaut 0 à la première ligne, encaisse `+value` sur chaque
/// segment IN et `−value` sur chaque segment OUT, et vaut `fee` à la dernière ligne
/// utile. C'est le remplacement de la région d'équilibre dédiée du côte-à-côte.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_seg_trace_seeded(
    w: &MonolithWitness,
    rng: &mut impl rand::Rng,
) -> TraceTable<BaseElement> {
    build_seg_trace_forme_seeded(&SegWitness::depuis_2in2out(w), rng)
}

/// Cœur du constructeur, paramétré par le point de forge (`SegForge::Aucune` pour
/// une trace honnête). UN seul chemin de code pour l'honnête et le forgé.
fn build_seg_trace_interne(
    w: &SegWitness,
    rng: &mut impl rand::Rng,
    forge: SegForge,
) -> TraceTable<BaseElement> {
    let f = w.forme();
    let depth = w.inputs[0].path.len();
    let len = f.trace_len(depth);
    // Tampon à largeur MAX (transient) ; la trace ÉMISE garde `f.width()` colonnes
    // — spec D2 : une 1-in/2-out ne paie pas les colonnes d'une 4-in/4-out.
    let mut rows = vec![[BaseElement::ZERO; WIDTH_MAX]; len];

    // Pré-passe de RECONSTRUCTION D'ARBRE. Une forge qui altère le commitment ou la
    // feuille change la racine repliée : si on gardait les chemins du témoin, les
    // deux entrées se replieraient vers des racines DIFFÉRENTES et c'est `root_in`
    // qui mordrait — masquant la liaison qu'on veut tester. On rebâtit donc l'arbre
    // sur les feuilles réellement injectées, pour que la trace reste
    // self-consistante et que SEULE la liaison visée diffère.
    // (La reconstruction est gatée `cfg(test)` : hors tests, `forge` vaut toujours
    // `Aucune` et les chemins sont ceux du témoin.)
    let chemins_temoin = || -> Vec<Vec<Digest>> {
        w.inputs.iter().map(|i| i.path.clone()).collect()
    };
    #[cfg(test)]
    let chemins: Vec<Vec<Digest>> = if forge.rebatit_arbre() {
        // Les forges à reconstruction restent 2/2 jusqu'à C2-T4 (le helper
        // `build_tree_from_leaves` est câblé sur deux feuilles) : asserté, pas
        // silencieusement faux sur une autre forme.
        assert_eq!(f, Forme::F22, "forge à reconstruction d'arbre : 2/2 seulement (C2-T4)");
        let f0 = feuille_injectee(w, 0, forge);
        let f1 = feuille_injectee(w, 1, forge);
        let (_root, p0, p1) = super::socle::build_tree_from_leaves(&f0, &f1);
        vec![p0, p1]
    } else {
        chemins_temoin()
    };
    #[cfg(not(test))]
    let chemins: Vec<Vec<Digest>> = chemins_temoin();

    // --- Segment KEY : owner ∧ nk du MÊME secret. ---
    let key_i = 0;
    debug_assert_eq!(f.seg_kind(key_i), SegKind::Key);
    // Forge SecretNk : le bloc nk part d'un secret DIFFÉRENT. La porteuse NK_C et
    // le nullifier consomment ensuite ce nk = H_nk(s') en cascade HONNÊTE — seule
    // la liaison secret owner↔nk peut donc mordre.
    let kr = match forge {
        SegForge::SecretNk(s_nk) => key_rows_split(w.secret.as_felts(), &s_nk.0),
        _ => key_rows(w.secret.as_felts()),
    };
    // Le calcul de clé occupe `KEY_USED_ROWS` (8) des `KEY_LEN` (16) lignes du
    // segment ; le reste est inactif (voir seg_layout : alignement sur le cycle 16).
    debug_assert_eq!(kr.len(), KEY_USED_ROWS);
    // (`KEY_USED_ROWS <= KEY_LEN` est garanti par une garde compile-time de seg_layout.)
    seg_copy(&mut rows, &kr, f.seg_start(key_i, depth), SEG_KEY_OFF);
    let owner = read_digest(&kr, kr.len() - 1, RATE_START);
    let nk = read_digest(&kr, kr.len() - 1, KEY_NK_LOCAL_OFF + RATE_START);
    set_carrier_digest(&mut rows, OWNER_C, &owner);
    set_carrier_digest(&mut rows, NK_C, &nk);

    // --- Segments d'ENTRÉE et de SORTIE, dans l'ordre du schedule. ---
    // `s` = accumulateur d'équilibre chaîné (valeur AVANT la contribution de la
    // ligne courante), `root_vu` = racine repliée (identique pour les deux entrées).
    let mut s = BaseElement::ZERO;
    let mut root_vu: Option<Digest> = None;
    let (mut n_in, mut n_out) = (0usize, 0usize);

    for i in 0..f.n_segments() {
        let kind = f.seg_kind(i);
        let start = f.seg_start(i, depth);
        let seg_rows = seg_len(kind, depth);
        match kind {
            SegKind::Key => {
                // Aucune contribution à l'équilibre : `S` reste constant, bits à 0.
                // (Colonne S de LA FORME — pas la constante 2/2 : sur une autre
                // forme, S_COL pointerait dans les porteuses.)
                for r in 0..seg_rows {
                    rows[start + r][f.s_col()] = s;
                }
            }
            SegKind::Input => {
                let input = &w.inputs[n_in];
                let note = &input.note;

                // cm = H_NoteCommitment(value ‖ owner ‖ rho ‖ r) — lignes 0..32.
                // Forges OwnerConsomme / RhoCommitment : on réécrit l'opérande
                // CONSOMMÉ ici, les porteuses OWNER_C/RHO_C restant honnêtes.
                let owner_commit = forge.owner_commit(n_in, note.owner);
                let rho_commit = forge.rho_commit(n_in, note.rho);
                let cm_payload =
                    note_commit_payload(note.value, &owner_commit, &rho_commit, &note.r);
                // Forge PaddingCommitment : préambule au PAD_ZERO non canonique.
                let cm_rows = lignes_commitment(&cm_payload, n_in, forge);
                debug_assert_eq!(cm_rows.len(), CM_ROWS_END - CM_ROWS_START);
                seg_copy(&mut rows, &cm_rows, start + CM_ROWS_START, SEG_SPONGE_OFF);
                let cm = read_digest(&cm_rows, cm_rows.len() - 1, RATE_START);

                // feuille = H_MerkleLeaf(cm) — lignes 32..40.
                // Forge CmFeuille : cm consommé ici ≠ cm produit (porteuse honnête).
                let cm_leaf = forge.cm_feuille(n_in, cm);
                let leaf_rows = sponge_rows_for(Domain::MerkleLeaf, &cm_leaf.0);
                debug_assert_eq!(leaf_rows.len(), LEAF_ROWS_END - LEAF_ROWS_START);
                seg_copy(&mut rows, &leaf_rows, start + LEAF_ROWS_START, SEG_SPONGE_OFF);
                let leaf_d = read_digest(&leaf_rows, leaf_rows.len() - 1, RATE_START);

                // nullifier = H_Nullifier(nk ‖ rho ‖ cm) — lignes 40..56.
                // Points de forge : chacun réécrit UN opérande consommé ici, en
                // laissant la porteuse correspondante (NK_C / RHO_C / CM_C) honnête.
                let nk_nf = match forge {
                    SegForge::NkConsomme(fi, a) if fi == n_in => a,
                    _ => nk,
                };
                let rho_nf = match forge {
                    SegForge::RhoNullifier(fi, a) if fi == n_in => a,
                    _ => note.rho,
                };
                let cm_nf = match forge {
                    SegForge::CmNullifier(fi, a) if fi == n_in => a,
                    _ => cm,
                };
                let mut nf_payload = Vec::with_capacity(3 * DIGEST_FELTS);
                nf_payload.extend_from_slice(&nk_nf.0);
                nf_payload.extend_from_slice(&rho_nf.0);
                nf_payload.extend_from_slice(&cm_nf.0);
                let nf_rows = sponge_rows_for(Domain::Nullifier, &nf_payload);
                debug_assert_eq!(nf_rows.len(), NF_ROWS_END - NF_ROWS_START);
                seg_copy(&mut rows, &nf_rows, start + NF_ROWS_START, SEG_SPONGE_OFF);

                // Chemin de Merkle, EN PARALLÈLE de la pile d'éponge (colonnes
                // disjointes) : lignes locales 0..16·depth.
                // Forge LeafChemin : feuille injectée ≠ feuille produite. Les chemins
                // viennent de la pré-passe (rebâtis si la forge change une feuille).
                let leaf_injectee = forge.leaf_chemin(n_in, leaf_d);
                let m_rows =
                    crate::merkle_path::path_rows(&leaf_injectee, &chemins[n_in], input.index);
                debug_assert_eq!(m_rows.len(), MERKLE_LEVEL_ROWS * depth);
                debug_assert!(m_rows.len() <= seg_rows, "le chemin tient dans le segment");
                seg_copy(&mut rows, &m_rows, start, SEG_MERKLE_OFF);

                // Racine repliée = sortie d'éponge du DERNIER merge du chemin
                // (lue dans la trace, pas recopiée d'une référence : c'est ce que
                // l'AIR contraindra, et ce que le test différentiel compare à
                // `merkle::fold`).
                let root_i = read_digest(&m_rows, m_rows.len() - 1, RATE_START);
                match &root_vu {
                    None => root_vu = Some(root_i),
                    Some(r0) => debug_assert_eq!(
                        *r0, root_i,
                        "TOUTES les entrées doivent prouver contre la MÊME racine"
                    ),
                }

                // Porteuses de l'entrée + bits/équilibre du montant.
                set_carrier_digest(&mut rows, f.rho_c(n_in), &note.rho);
                set_carrier_digest(&mut rows, f.cm_c(n_in), &cm);
                set_carrier_digest(&mut rows, f.leaf_c(n_in), &leaf_d);
                set_carrier_scalar(&mut rows, f.vin_c(n_in), note.value);
                s = fill_segment_balance(
                    &mut rows,
                    start,
                    seg_rows,
                    forge.valeur_bits(true, n_in, note.value),
                    true,
                    s,
                    forge.vacc_initial(true, n_in),
                    f.s_col(),
                );

                n_in += 1;
            }
            SegKind::Output => {
                let out = &w.outputs[n_out];
                // `VaccInitial` gonfle la sortie 0 : commitment, porteuse VOUT et
                // bits sont TOUS cohérents à la nouvelle valeur (aucune liaison de
                // sortie ne doit mordre — seul l'ancrage VACC doit le faire).
                let valeur_out = forge.valeur_sortie(n_out, out.value);
                let cm_payload = note_commit_payload(valeur_out, &out.owner, &out.rho, &out.r);
                let out_rows = sponge_rows_for(Domain::NoteCommitment, &cm_payload);
                debug_assert_eq!(out_rows.len(), CM_ROWS_END - CM_ROWS_START);
                seg_copy(&mut rows, &out_rows, start + CM_ROWS_START, SEG_SPONGE_OFF);

                set_carrier_scalar(&mut rows, f.vout_c(n_out), valeur_out);
                s = fill_segment_balance(
                    &mut rows,
                    start,
                    seg_rows,
                    forge.valeur_bits(false, n_out, valeur_out),
                    false,
                    s,
                    forge.vacc_initial(false, n_out),
                    f.s_col(),
                );

                n_out += 1;
            }
        }
    }
    debug_assert_eq!((n_in, n_out), (f.m(), f.n()));

    // Porteuse de racine : partagée, assertée publique une seule fois par l'AIR.
    if let Some(root) = root_vu {
        set_carrier_digest(&mut rows, ROOT_C, &root);
    }

    // --- Blinding (witness-hiding 3z-b1) : aléa frais sur TOUTES les colonnes de
    //     la région [used, len), S_COL comprise (l'AIR y est gatée par blind_off). ---
    let used = f.used_rows(depth);
    debug_assert_eq!(
        used,
        f.seg_start(f.n_segments() - 1, depth)
            + seg_len(f.seg_kind(f.n_segments() - 1), depth)
    );
    for row in rows.iter_mut().skip(used) {
        for cell in row.iter_mut() {
            *cell = felt_alea(rng);
        }
    }

    // Forge d'INERTIE : au lieu d'aléa, un attaquant choisit les valeurs de la
    // région de blinding. Il tente (a) de recopier des lignes utiles pour
    // « nourrir » une liaison, et (b) d'y écrire du junk qui VIOLERAIT chaque
    // famille de contraintes s'il était lu. Comme rien n'y est lu, la transaction
    // doit rester ACCEPTÉE — c'est ce que le test vérifie.
    if forge == SegForge::BlindingAdversarial {
        for r in used..len {
            if r % 2 == 0 {
                // (a) recopie d'une ligne utile.
                rows[r] = rows[r % used];
            } else {
                // (b) junk violant chaque famille si elle était active.
                for cell in rows[r].iter_mut() {
                    *cell = BaseElement::new(0xDEAD_BEEF);
                }
                rows[r][SEG_BALBIT_OFF + SEG_BAL_BIT] = BaseElement::new(5); // non booléen
                rows[r][f.s_col()] = BaseElement::new(999_999); // S qui saute
                rows[r][OWNER_C] = BaseElement::new(1); // porteuse discontinue
            }
        }
    }

    // Émission à la LARGEUR DE LA FORME : les colonnes du tampon au-delà de
    // `f.width()` (réservées aux formes plus larges) ne sortent jamais d'ici.
    let mut trace = TraceTable::new(f.width(), len);
    for (i, row) in rows.iter().enumerate() {
        trace.update_row(i, &row[..f.width()]);
    }
    trace
}

/// Remplit les colonnes d'équilibre LOCALES d'un segment (bit du montant, `VACC`
/// partiel) et la colonne PARTAGÉE `S_COL`, et retourne la valeur de `S` après le
/// segment.
///
/// Sémantique reprise telle quelle du `fill_balance` du côte-à-côte historique,
/// mais par segment : `S` porté par la ligne est la somme signée AVANT la
/// contribution de cette ligne ; `VACC` est la valeur partielle reconstruite depuis
/// les bits, remise à 0 au début du segment. Les lignes au-delà de `RANGE_BITS`
/// portent un bit nul (elles ne contribuent pas) — c'est ce qui borne le montant à
/// `< 2^RANGE_BITS`.
#[allow(clippy::too_many_arguments)]
fn fill_segment_balance(
    rows: &mut [[BaseElement; WIDTH_MAX]],
    start: usize,
    seg_rows: usize,
    value: u64,
    est_entree: bool,
    s_initial: BaseElement,
    vacc_initial: BaseElement,
    s_col: usize,
) -> BaseElement {
    let sign = if est_entree {
        BaseElement::ONE
    } else {
        -BaseElement::ONE
    };
    let mut s = s_initial;
    // `vacc_initial` est nul pour une trace honnête ; il n'est non nul que pour la
    // forge `VaccInitial`, qui exploite le fait que cette cellule n'est remise à
    // zéro par AUCUNE transition (le segment KEY ne produit pas d'`endblk`).
    let mut vacc = vacc_initial;
    for r in 0..seg_rows {
        let row = &mut rows[start + r];
        let bit = if r < crate::range_check::RANGE_BITS {
            (value >> r) & 1
        } else {
            0
        };
        let bit_be = BaseElement::new(bit);
        row[SEG_BALBIT_OFF + SEG_BAL_BIT] = bit_be;
        row[SEG_BALBIT_OFF + SEG_BAL_VACC] = vacc;
        row[s_col] = s;
        if r < crate::range_check::RANGE_BITS {
            let pow = BaseElement::new(1u64 << r);
            s += sign * bit_be * pow;
            vacc += bit_be * pow;
        }
    }
    s
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::spend::SpendNote;
    use crate::tx::ProvedInput;
    use proved_hash::digest::ShieldedSecret;
    use proved_hash::felt::Felt;
    use proved_hash::{merkle, rescue};
    use winterfell::Trace;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Arbre de profondeur 2 : `cm0` en index 0, `cm1` en index 3.
    fn build_tree(cm0: &Digest, cm1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
        let l0 = merkle::leaf(cm0);
        let l1 = merkle::leaf(&digest(9001));
        let l2 = merkle::leaf(&digest(9002));
        let l3 = merkle::leaf(cm1);
        let n_left = merkle::node(&l0, &l1);
        let n_right = merkle::node(&l2, &l3);
        (merkle::node(&n_left, &n_right), vec![l1, n_right], vec![l2, n_left])
    }

    /// Témoin 2-in/2-out équilibré (1000 + 500 = 900 + 580 + fee 20), profondeur 2.
    fn witness_de_test() -> MonolithWitness {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(proved_hash::domain::Domain::Owner, secret.as_felts());
        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
        let (_root, path0, path1) = build_tree(&cm0, &cm1);
        MonolithWitness {
            secret,
            inputs: [
                ProvedInput { note: n0, path: path0, index: 0 },
                ProvedInput { note: n1, path: path1, index: 3 },
            ],
            outputs: [
                SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) },
                SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) },
            ],
            fee: 20,
        }
    }

    /// Lit la cellule `(row, col)` d'une `TraceTable` (l'API winterfell est
    /// `get(col, row)` — on garde l'ordre `(row, col)` ici, plus lisible).
    /// Témoin à forme (m, n) sur un VRAI arbre partagé (profondeur 2, jusqu'à
    /// 4 feuilles) : toutes les entrées prouvent contre la même racine, comme
    /// l'exige le constructeur.
    pub(crate) fn witness_forme(m: usize, n: usize) -> SegWitness {
        witness_forme_profondeur(m, n, 2)
    }

    /// Témoin (m, n) à une PROFONDEUR d'arbre donnée — le re-bench 3z-c2 en a besoin
    /// à la profondeur consensus (32).
    pub(crate) fn witness_forme_profondeur(m: usize, n: usize, profondeur: usize) -> SegWitness {
        use proved_hash::merkle::ProvedMerkleTree;
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(4_000 + i as u64).unwrap()
        }));
        let owner = proved_hash::rescue::hash(Domain::Owner, secret.as_felts());
        let d = |seed: u64| {
            Digest(core::array::from_fn(|i| {
                Felt::from_canonical_u64(seed + i as u64).unwrap()
            }))
        };

        let notes: Vec<crate::SpendNote> = (0..m)
            .map(|i| crate::SpendNote {
                value: 1_000 * (i as u64 + 1),
                owner,
                rho: d(100 + 10 * i as u64),
                r: d(200 + 10 * i as u64),
            })
            .collect();
        let mut arbre = ProvedMerkleTree::new(profondeur);
        let index: Vec<u64> = notes
            .iter()
            .map(|note| {
                let cm = proved_hash::rescue::note_commitment(
                    note.value, &note.owner, &note.rho, &note.r,
                );
                arbre.append(&cm)
            })
            .collect();
        let inputs: Vec<crate::ProvedInput> = notes
            .into_iter()
            .zip(index)
            .map(|(note, i)| crate::ProvedInput {
                note,
                path: arbre.path(i).unwrap(),
                index: i,
            })
            .collect();

        let total: u64 = inputs.iter().map(|i| i.note.value).sum();
        let fee = 7u64;
        // Sorties : répartition quelconque qui équilibre (dernière = reste).
        let part = (total - fee) / n as u64;
        let outputs: Vec<crate::SpendNote> = (0..n)
            .map(|j| crate::SpendNote {
                value: if j == n - 1 {
                    total - fee - part * (n as u64 - 1)
                } else {
                    part
                },
                owner: d(500 + 10 * j as u64),
                rho: d(600 + 10 * j as u64),
                r: d(700 + 10 * j as u64),
            })
            .collect();

        SegWitness::new(secret, inputs, outputs, fee).expect("forme valide")
    }

    /// SANITÉ PARAMÉTRIQUE sur 5 formes : la trace émise a la largeur de SA forme,
    /// chaque porteuse est à SA colonne, et l'accumulateur d'équilibre traverse le
    /// schedule variable de 0 à `Σin − Σout = fee`.
    ///
    /// C'est le test qui donnera son sens à l'AIR paramétrée (C2-T3) : si le
    /// constructeur plaçait une porteuse une colonne trop loin sur la forme 4/1,
    /// aucune suite à forme fixe ne le verrait — et l'AIR contraindrait alors des
    /// cellules vides, preuve valide sur un statement vide.
    #[test]
    fn trace_parametrique_5_formes() {
        use winter_math::StarkField;
        for (m, n) in [(1, 1), (2, 2), (4, 4), (1, 4), (4, 1)] {
            let w = witness_forme(m, n);
            let f = w.forme();
            let t = build_seg_trace_forme_seeded(&w, &mut rand::rngs::OsRng);
            let etiquette = format!("forme {m}/{n}");
            let depth = 2;

            // La trace émise a la LARGEUR DE LA FORME (spec D2), pas celle du tampon.
            assert_eq!(t.width(), f.width(), "{etiquette}");
            assert_eq!(t.length(), f.trace_len(depth), "{etiquette}");

            // Porteuses : chaque entrée et chaque sortie à SA colonne.
            for (i, input) in w.inputs.iter().enumerate() {
                assert_eq!(
                    cell_digest(&t, 0, f.rho_c(i)),
                    input.note.rho,
                    "{etiquette} rho[{i}]"
                );
                assert_eq!(
                    cell(&t, 0, f.vin_c(i)),
                    BaseElement::new(input.note.value),
                    "{etiquette} vin[{i}]"
                );
            }
            for (j, out) in w.outputs.iter().enumerate() {
                assert_eq!(
                    cell(&t, 0, f.vout_c(j)),
                    BaseElement::new(out.value),
                    "{etiquette} vout[{j}]"
                );
            }

            // L'accumulateur S traverse le schedule : 0 au départ, cumul signé à
            // chaque frontière de segment, fee à l'entame du dernier segment + sa
            // contribution — soit, à la dernière ligne utile, S = fee une fois la
            // dernière sortie retranchée. On vérifie les frontières, qui suffisent :
            // l'intérieur des segments est couvert par `equilibre_chaine_de_zero_a_fee`.
            let mut attendu = 0i128;
            for i in 0..f.n_segments() {
                let s_frontiere = cell(&t, f.seg_start(i, depth), f.s_col());
                let attendu_be = if attendu >= 0 {
                    BaseElement::new(attendu as u64)
                } else {
                    -BaseElement::new((-attendu) as u64)
                };
                assert_eq!(s_frontiere, attendu_be, "{etiquette} S au segment {i}");
                match f.seg_kind(i) {
                    SegKind::Key => {}
                    SegKind::Input => attendu += w.inputs[i - 1].note.value as i128,
                    SegKind::Output => {
                        attendu -= w.outputs[i - 1 - f.m()].value as i128;
                    }
                }
            }
            assert_eq!(
                attendu, w.fee as i128,
                "{etiquette} : Σin − Σout = fee (témoin équilibré)"
            );

            // Racine : la porteuse ROOT_C vaut la racine de l'arbre partagé —
            // TOUTES les entrées ont replié vers elle (le debug_assert du
            // constructeur l'exige déjà ; ici on le voit depuis la trace émise).
            let _ = BaseElement::MODULUS; // (use) — garde l'import justifié
            assert_eq!(
                cell_digest(&t, 0, ROOT_C),
                {
                    use proved_hash::merkle::ProvedMerkleTree;
                    let mut a = ProvedMerkleTree::new(2);
                    for input in &w.inputs {
                        let note = &input.note;
                        let cm = proved_hash::rescue::note_commitment(
                            note.value, &note.owner, &note.rho, &note.r,
                        );
                        a.append(&cm);
                    }
                    a.root()
                },
                "{etiquette} : ROOT_C = racine de l'arbre partagé"
            );
        }
    }

    /// Les BORNES du témoin vivent dans son constructeur : 0 entrée ou 5 sorties
    /// sont refusées AVANT toute construction de trace.
    #[test]
    fn witness_hors_bornes_refuse() {
        let bon = witness_forme(1, 1);
        // 0 entrée : le constructeur de Forme refuse (aucune autorité de dépense).
        assert!(
            SegWitness::new(bon.secret.clone(), Vec::new(), bon.outputs.clone(), 0).is_err()
        );
        // 5 sorties : au-delà de MAX_OUT.
        let trop: Vec<crate::SpendNote> = (0..MAX_OUT + 1)
            .map(|_| bon.outputs[0].clone())
            .collect();
        assert!(SegWitness::new(bon.secret.clone(), bon.inputs.clone(), trop, 0).is_err());
    }

    fn cell(t: &TraceTable<BaseElement>, row: usize, col: usize) -> BaseElement {
        t.get(col, row)
    }

    fn cell_digest(t: &TraceTable<BaseElement>, row: usize, col: usize) -> Digest {
        Digest(core::array::from_fn(|k| {
            Felt::from_winter(cell(t, row, col + k)).expect("canonique")
        }))
    }

    /// Sanité DIFFÉRENTIELLE de la trace segmentée : chaque valeur produite dans les
    /// segments doit coïncider avec la référence HORS-CIRCUIT (`rescue::*`,
    /// `merkle::*`) — pas avec la construction elle-même.
    #[test]
    fn trace_segmentee_coincide_avec_les_references() {
        let w = witness_de_test();
        let depth = 2;
        let t = build_seg_trace(&w);
        assert_eq!(t.width(), WIDTH);
        assert_eq!(t.length(), trace_len(depth));

        // Porteuses owner/nk : dérivées du secret (P2/P4).
        let owner_attendu = rescue::hash(Domain::Owner, w.secret.as_felts());
        let nk_attendu = rescue::hash(Domain::Nk, w.secret.as_felts());
        assert_eq!(cell_digest(&t, 0, OWNER_C), owner_attendu);
        assert_eq!(cell_digest(&t, 0, NK_C), nk_attendu);

        // Segments d'entrée : cm, feuille, nullifier aux lignes du segment.
        let schedule = schedule_2in2out();
        let mut n_in = 0;
        for (i, kind) in schedule.iter().enumerate() {
            if *kind != SegKind::Input {
                continue;
            }
            let start = seg_start(i, depth);
            let note = &w.inputs[n_in].note;
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            let leaf = merkle::leaf(&cm);

            // Dernière ligne de chaque sous-pile d'éponge = le digest produit.
            assert_eq!(
                cell_digest(&t, start + CM_ROWS_END - 1, SEG_SPONGE_OFF + RATE_START),
                cm,
                "commitment de l'entrée {n_in}"
            );
            assert_eq!(
                cell_digest(&t, start + LEAF_ROWS_END - 1, SEG_SPONGE_OFF + RATE_START),
                leaf,
                "feuille de l'entrée {n_in}"
            );
            // Porteuses de l'entrée.
            assert_eq!(cell_digest(&t, 0, CM_C[n_in]), cm);
            assert_eq!(cell_digest(&t, 0, LEAF_C[n_in]), leaf);
            assert_eq!(cell_digest(&t, 0, RHO_C[n_in]), note.rho);
            assert_eq!(cell(&t, 0, VIN_C[n_in]), BaseElement::new(note.value));
            n_in += 1;
        }
        assert_eq!(n_in, 2);

        // Segments de sortie : commitment de sortie.
        let mut n_out = 0;
        for (i, kind) in schedule.iter().enumerate() {
            if *kind != SegKind::Output {
                continue;
            }
            let start = seg_start(i, depth);
            let out = &w.outputs[n_out];
            let oc = rescue::note_commitment(out.value, &out.owner, &out.rho, &out.r);
            assert_eq!(
                cell_digest(&t, start + CM_ROWS_END - 1, SEG_SPONGE_OFF + RATE_START),
                oc,
                "commitment de la sortie {n_out}"
            );
            assert_eq!(cell(&t, 0, VOUT_C[n_out]), BaseElement::new(out.value));
            n_out += 1;
        }
        assert_eq!(n_out, 2);

        // Porteuse de racine == racine hors-circuit de l'arbre.
        let cm0 = rescue::note_commitment(
            w.inputs[0].note.value,
            &w.inputs[0].note.owner,
            &w.inputs[0].note.rho,
            &w.inputs[0].note.r,
        );
        let cm1 = rescue::note_commitment(
            w.inputs[1].note.value,
            &w.inputs[1].note.owner,
            &w.inputs[1].note.rho,
            &w.inputs[1].note.r,
        );
        let (root_attendu, _, _) = build_tree(&cm0, &cm1);
        assert_eq!(cell_digest(&t, 0, ROOT_C), root_attendu);
    }

    /// Équilibre CHAÎNÉ : `S` vaut 0 à la première ligne et `fee` à la dernière
    /// ligne utile — c'est la propriété que l'AIR (T3) assertera.
    #[test]
    fn equilibre_chaine_de_zero_a_fee() {
        let w = witness_de_test();
        let depth = 2;
        let t = build_seg_trace(&w);

        assert_eq!(cell(&t, 0, S_COL), BaseElement::ZERO, "S démarre à 0");
        let used = used_rows(depth);
        assert_eq!(
            cell(&t, used - 1, S_COL),
            BaseElement::new(w.fee),
            "S vaut fee à la dernière ligne utile"
        );
    }

    /// La région de blinding `[used, len)` diffère d'un tirage à l'autre (aléa frais)
    /// alors que la région utile est identique — witness-hiding préservé.
    #[test]
    fn region_de_blinding_aleatoire_region_utile_deterministe() {
        let w = witness_de_test();
        let depth = 2;
        let t1 = build_seg_trace(&w);
        let t2 = build_seg_trace(&w);
        let used = used_rows(depth);

        // Région utile : identique (déterministe).
        for col in [OWNER_C, NK_C, S_COL, ROOT_C] {
            for row in [0, used - 1] {
                assert_eq!(cell(&t1, row, col), cell(&t2, row, col));
            }
        }
        // Région de blinding : au moins une cellule diffère (proba d'égalité ≈ 2^-64).
        let differe = (used..t1.length())
            .any(|row| (0..WIDTH).any(|col| cell(&t1, row, col) != cell(&t2, row, col)));
        assert!(differe, "la région de blinding doit être ré-aléatoirisée");
    }
}
