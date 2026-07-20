//! 3z-a5 — `ProvedTx` v2 : la transaction prouvée par LE monolithe.
//!
//! Remplace l'assemblage v1 (3b5, composition de 15 sous-preuves : `prove_key` +
//! 2×`prove_spend` + 2×`prove_output` + équilibre natif) par UNE SEULE preuve
//! STARK — celle du monolithe (`monolith::air::prove_monolith`), qui établit
//! **P1–P7 pour la transaction entière** (clé, deux dépenses, deux sorties,
//! équilibre, TOUTES les liaisons inter-segments) dans une trace unique.
//!
//! Publics MINIMAUX : racine, les deux nullifiers, les deux commitments de sortie,
//! les frais. Plus aucun `owner`/`nk` publiés en clair, plus aucune sous-preuve —
//! le prouveur (`prove_monolith`) extrait ces publics directement des cellules de
//! trace ; le vérificateur les fournit lui-même (root passée en argument, reste lu
//! sur `tx`) et ne fait tourner qu'UN SEUL `winterfell::verify`.
//!
//! `tx_digest` (v2, domaine `obscura/proved-tx/v2`) lie `root ‖ nf ‖ oc ‖ fee ‖
//! signer` — non-rejeu et anti-échange du signataire d'intention, comme en v1.
//! La signature hybride d'intention reste une enveloppe anti-malléabilité, PAS une
//! autorisation d'ownership : l'autorité vient de la liaison `owner = H_owner(secret)`
//! DANS le monolithe (contrainte AIR, cf. `monolith::air` « liaisons par porteuses »).
//!
//! ⚠️ **À générer en `--release`** (AIR du monolithe gatée, cf. `monolith::air`).

use crate::monolith::air::{prove_monolith, verify_monolith, MonolithPublicInputs};
use crate::monolith::trace::MonolithWitness;
use crate::range_check::RANGE_BITS;
use crate::spend::SpendNote;
use crate::ValidityProof;
use crypto::hash::dual_hash;
use crypto::sig::{HybridSignature, SigKeypair, SigPublicKey};
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_FELTS};
use proved_hash::felt::Felt;
use winter_math::fields::f64::BaseElement;

/// Domaine de la signature d'intention (anti-malléabilité), signée sur `tx_digest`.
pub const INTENT_DOMAIN: &str = "obscura/proved-tx-intent/v2";

/// Une entrée à dépenser : la note, son chemin de Merkle et sa position.
pub struct ProvedInput {
    pub note: SpendNote,
    pub path: Vec<Digest>,
    pub index: u64,
}

/// Transaction prouvée 2-in/2-out. `proof` est LA preuve monolithique unique ; les
/// autres champs sont ses publics (racine, nullifiers, commitments de sortie, fee)
/// plus l'enveloppe d'intention (signataire, digest, signature hybride).
pub struct ProvedTx {
    /// Racine (anchor) contre laquelle les entrées prouvent leur appartenance.
    pub anchor: Digest,
    /// LA preuve monolithique : établit P1–P7 pour toute la transaction.
    pub proof: ValidityProof,
    pub nullifiers: [Digest; 2],
    pub output_commitments: [Digest; 2],
    pub fee: u64,
    /// Clé publique d'intention (liée dans `tx_digest` → non échangeable).
    pub signer: SigPublicKey,
    pub tx_digest: [u8; 64],
    /// Signature hybride d'intention sur `tx_digest` (enveloppe anti-malléabilité,
    /// PAS autorité d'ownership — celle-ci est établie par la liaison `owner` du
    /// monolithe).
    pub intent_sig: HybridSignature,
}

const TX_DOMAIN: &str = "obscura/proved-tx/v2";

/// Encodage canonique injectif (tailles fixes) des publics : `root ‖ nf₁ ‖ nf₂ ‖
/// oc₁ ‖ oc₂ ‖ fee LE ‖ signer`.
fn tx_digest_bytes(
    root: &Digest,
    nullifiers: &[Digest; 2],
    output_commitments: &[Digest; 2],
    fee: u64,
    signer: &SigPublicKey,
) -> [u8; 64] {
    let mut b = Vec::new();
    b.extend_from_slice(&root.to_bytes());
    for nf in nullifiers {
        b.extend_from_slice(&nf.to_bytes());
    }
    for oc in output_commitments {
        b.extend_from_slice(&oc.to_bytes());
    }
    b.extend_from_slice(&fee.to_le_bytes());
    // Le signataire d'intention est LIÉ dans le digest → il ne peut pas être échangé
    // sans invalider la preuve (qui lie tx_digest).
    b.extend_from_slice(&signer.to_bytes());
    dual_hash(TX_DOMAIN, &b)
}

/// `Digest` → tableau de `BaseElement` winterfell (publics du monolithe).
fn digest_to_felts(d: &Digest) -> [BaseElement; DIGEST_FELTS] {
    core::array::from_fn(|k| d.0[k].to_winter())
}

/// Tableau de `BaseElement` winterfell → `Digest`. Toujours canonique : ces valeurs
/// sont extraites de cellules de trace Goldilocks, déjà réduites mod p.
fn felts_to_digest(f: &[BaseElement; DIGEST_FELTS]) -> Digest {
    Digest(core::array::from_fn(|k| {
        Felt::from_winter(f[k]).expect("digest canonique issu du circuit")
    }))
}

/// Construit la transaction prouvée. Le témoin (secret + entrées + sorties + fee)
/// alimente LE monolithe (`prove_monolith`) : une seule trace établit P1–P7 pour la
/// tx entière. Les publics (racine, nullifiers, commitments de sortie) sont extraits
/// de la preuve pour former `tx_digest`, signé par la clé d'intention. Retourne la
/// racine prouvée et la `ProvedTx`.
///
/// Précondition : notes d'entrée possédées par `secret` (owner = H_owner(secret)),
/// chemins de même profondeur cohérents avec un même arbre, équilibre respecté,
/// montants `< 2^60`. Une entrée qui ne respecte pas ces préconditions ne fait PAS
/// paniquer la construction : elle produit une preuve que `verify_tx` rejette (la
/// liaison correspondante mord dans l'AIR du monolithe, cf. `monolith::air`).
pub fn prove_tx(
    secret: &ShieldedSecret,
    inputs: [ProvedInput; 2],
    outputs: [SpendNote; 2],
    fee: u64,
    intent: &SigKeypair,
) -> (Digest, ProvedTx) {
    let witness = MonolithWitness {
        secret: secret.clone(),
        inputs,
        outputs,
        fee,
    };
    let (pi, proof) = prove_monolith(&witness);

    let root = felts_to_digest(&pi.root);
    let nullifiers = [
        felts_to_digest(&pi.nullifiers[0]),
        felts_to_digest(&pi.nullifiers[1]),
    ];
    let output_commitments = [
        felts_to_digest(&pi.output_commitments[0]),
        felts_to_digest(&pi.output_commitments[1]),
    ];
    let signer = intent.public.clone();
    let tx_digest = tx_digest_bytes(&root, &nullifiers, &output_commitments, fee, &signer);
    // Enveloppe d'intention : le porteur de la clé signe CETTE transaction.
    let intent_sig = intent.sign(INTENT_DOMAIN, &tx_digest);

    (
        root,
        ProvedTx {
            anchor: root,
            proof,
            nullifiers,
            output_commitments,
            fee,
            signer,
            tx_digest,
            intent_sig,
        },
    )
}

/// Vérifie la transaction contre l'arbre public `root` (profondeur `depth`).
/// Reconstruit les publics du monolithe depuis `root` (argument, PAS `tx.anchor` —
/// c'est la racine consensus qui fait foi) et les champs publics de `tx`, établit
/// P1–P7 pour toute la tx via `verify_monolith`, puis recompare `tx_digest`
/// (non-rejeu, signataire lié). NB : la signature elle-même est vérifiée côté ledger
/// (`apply_proved_tx`) — `verify_tx` n'établit que la preuve STARK + la cohérence du
/// digest.
pub fn verify_tx(root: &Digest, depth: usize, tx: &ProvedTx) -> bool {
    // Borne native du fee (miroir de `balance.rs`) : l'équilibre n'est prouvé que
    // MODULO p (`S ≡ fee (mod p)`, `fee: u64` réduit dans le corps). Sans cette borne,
    // `fee = p − k` (valide en u64) fait passer des sorties dépassant les entrées de k :
    // `S_final = Σin − Σout = −k ≡ p − k` satisfait l'égalité en corps, mais crée k
    // unités (wrap mod p). Avec `fee < 2^RANGE_BITS` ET chaque montant `< 2^RANGE_BITS`
    // (contrainte de range du circuit), on a `|Σin − Σout| < 4·2^60 + 2^60 < 2^63 ≪ p` :
    // l'égalité en corps implique alors l'égalité ENTIÈRE (aucun wrap). Le vérificateur
    // ne fait pas confiance au prouveur → cette borne EST la garantie de consensus.
    if tx.fee >= (1u64 << RANGE_BITS) {
        return false;
    }
    let pi = MonolithPublicInputs {
        root: digest_to_felts(root),
        nullifiers: [
            digest_to_felts(&tx.nullifiers[0]),
            digest_to_felts(&tx.nullifiers[1]),
        ],
        output_commitments: [
            digest_to_felts(&tx.output_commitments[0]),
            digest_to_felts(&tx.output_commitments[1]),
        ],
        fee: tx.fee,
        depth,
    };
    if !verify_monolith(&pi, depth, &tx.proof) {
        return false;
    }
    let expected = tx_digest_bytes(root, &tx.nullifiers, &tx.output_commitments, tx.fee, &tx.signer);
    expected == tx.tx_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::domain::Domain;
    use proved_hash::merkle;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    const DEPTH: usize = 2;

    /// Arbre de profondeur 2 (4 feuilles) : `cm0` en index 0, `cm1` en index 3,
    /// deux feuilles muettes. Retourne (root, path0, path1) selon la convention `fold`.
    fn build_tree(cm0: &Digest, cm1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
        let l0 = merkle::leaf(cm0);
        let l1 = merkle::leaf(&digest(9001)); // muette
        let l2 = merkle::leaf(&digest(9002)); // muette
        let l3 = merkle::leaf(cm1);
        let n_left = merkle::node(&l0, &l1);
        let n_right = merkle::node(&l2, &l3);
        let root = merkle::node(&n_left, &n_right);
        // index 0 (00) : sib niveau0 = l1, niveau1 = n_right.
        let path0 = vec![l1, n_right];
        // index 3 (11) : sib niveau0 = l2, niveau1 = n_left.
        let path1 = vec![l2, n_left];
        (root, path0, path1)
    }

    /// Construit le témoin d'une transaction 2-in/2-out équilibrée (1000/500 →
    /// 900/580 + fee 20, arbre de profondeur DEPTH). `owner0_faux`, si fourni,
    /// remplace l'owner de l'entrée 0 (test de liaison owner ≠ clé) — le reste de la
    /// construction (commitment, arbre) suit fidèlement cet owner, SANS aucun assert
    /// de cohérence : c'est la contrainte AIR de liaison qui doit mordre, pas un
    /// panic hors-circuit.
    fn setup(owner0_faux: Option<Digest>) -> (ShieldedSecret, Digest, [ProvedInput; 2], [SpendNote; 2]) {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let owner0 = owner0_faux.unwrap_or(owner);

        let n0 = SpendNote { value: 1_000, owner: owner0, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
        let (root, path0, path1) = build_tree(&cm0, &cm1);

        // Sorties (destinataires) : 900 + 580 + fee 20 = 1500 = 1000 + 500.
        let o0 = SpendNote { value: 900, owner: digest(60), rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 580, owner: digest(70), rho: digest(71), r: digest(72) };

        let inputs = [
            ProvedInput { note: n0, path: path0, index: 0 },
            ProvedInput { note: n1, path: path1, index: 3 },
        ];
        (secret, root, inputs, [o0, o1])
    }

    /// Transaction valide de référence (owner honnête, fee correct).
    fn valid_tx() -> (ShieldedSecret, Digest, ProvedTx) {
        let (secret, root, inputs, outputs) = setup(None);
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, outputs, 20, &intent);
        assert_eq!(proved_root, root);
        (secret, root, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn transaction_valide() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
    }

    /// Déséquilibre : `fee` passé à `prove_tx` (999) NE correspond PAS à Σentrées −
    /// Σsorties (réellement 20, cf. `setup`). `fill_balance` (monolith/trace.rs)
    /// accumule `S` = Σ entrées − Σ sorties INDÉPENDAMMENT du `fee` fourni — c'est
    /// l'ASSERTION publique `S[dernière ligne] == pi.fee` (monolith/air.rs) qui lie
    /// les deux, et `pi.fee` est extrait tel quel du témoin (`w.fee`). Comme le
    /// prouveur ET le vérificateur utilisent donc le MÊME `fee` faux (999) alors que
    /// la trace réelle atteint `S = 20`, l'assertion est fausse relativement à la
    /// trace commise : aucun panic (aucune vérification hors-circuit de l'équilibre
    /// dans `build_monolith_trace`/`prove_monolith`), mais la preuve — bien générée —
    /// ne peut pas satisfaire une assertion fausse et `verify_monolith` (donc
    /// `verify_tx`) rejette. Même mécanisme que la falsification de `fee` dans
    /// `monolith::air::tests::roundtrip_monolithe`, ici appliqué AVANT la preuve
    /// plutôt qu'après.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn desequilibre_rejete() {
        let (secret, root, inputs, outputs) = setup(None);
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, outputs, 999, &intent);
        assert_eq!(proved_root, root);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn nullifier_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.nullifiers[0] = digest(123);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn output_commitment_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.output_commitments[0] = digest(321);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn tx_digest_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.tx_digest[0] ^= 1;
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn racine_erronee_rejetee() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
        assert!(!verify_tx(&digest(1), DEPTH, &tx));
    }

    /// INFLATION par wrap mod p via l'API publique (sans force brute white-box) : les
    /// sorties dépassent les entrées de `k`, avec `fee = p − k`. L'équilibre du circuit
    /// n'établit que `S ≡ fee (mod p)` : `S_final = Σin − Σout = −k ≡ p − k = fee` — la
    /// preuve STARK est donc VALIDE (on le vérifie explicitement via `verify_monolith`).
    /// Seule la borne native `fee < 2^RANGE_BITS` de `verify_tx` ferme le trou : `p − k`
    /// dépasse 2^60 → rejet. RED vérifié en retirant la borne (non committé) :
    /// `verify_tx` renvoyait alors `true` malgré k unités créées.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn fee_wrappe_rejete() {
        // Modulus Goldilocks p = 2^64 − 2^32 + 1.
        const P: u64 = 0xFFFF_FFFF_0000_0001;
        let k = 1_000u64;

        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let n0 = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let n1 = SpendNote { value: 500, owner, rho: digest(40), r: digest(50) };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);
        let (root, path0, path1) = build_tree(&cm0, &cm1);

        // Σsorties = 1500 + k > Σentrées = 1500 : k unités créées ; fee = p − k ≡ −k.
        let o0 = SpendNote { value: 1_000, owner: digest(60), rho: digest(61), r: digest(62) };
        let o1 = SpendNote { value: 500 + k, owner: digest(70), rho: digest(71), r: digest(72) };
        let inputs = [
            ProvedInput { note: n0, path: path0, index: 0 },
            ProvedInput { note: n1, path: path1, index: 3 },
        ];
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, [o0, o1], P - k, &intent);
        assert_eq!(proved_root, root);

        // La preuve STARK est valide (S ≡ fee mod p) : le trou est bien réel...
        let pi = MonolithPublicInputs {
            root: digest_to_felts(&root),
            nullifiers: [digest_to_felts(&tx.nullifiers[0]), digest_to_felts(&tx.nullifiers[1])],
            output_commitments: [
                digest_to_felts(&tx.output_commitments[0]),
                digest_to_felts(&tx.output_commitments[1]),
            ],
            fee: tx.fee,
            depth: DEPTH,
        };
        assert!(verify_monolith(&pi, DEPTH, &tx.proof), "preuve STARK valide (wrap mod p)");
        // ...mais la borne native `fee < 2^60` de verify_tx le ferme.
        assert!(!verify_tx(&root, DEPTH, &tx), "fee = p − k ≥ 2^60 doit être rejeté");
    }

    /// Entrée d'un AUTRE owner : la note 0 porte `owner = digest(9999)` ≠
    /// `H_owner(secret)`. `build_monolith_trace` ne fait AUCUN assert d'égalité — le
    /// commitment est construit avec l'owner mensonger tel quel (comme le ferait un
    /// prouveur malhonnête), et l'arbre/le chemin restent self-consistants avec ce
    /// commitment (`proved_root == root` tient). SEULE la contrainte AIR de liaison
    /// owner (« Consommation @0 » de `monolith::air::evaluate_transition`, qui force
    /// l'owner consommé par le commitment de l'entrée == l'owner produit par la clé
    /// dérivée du secret) mord — exactement le mécanisme de
    /// `monolith::air::tests::liaison_owner_mord`, ici exercé via l'API publique
    /// `prove_tx`/`verify_tx` plutôt que par forge white-box directe de la trace.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn entree_d_un_autre_owner_rejetee() {
        let (secret, root, inputs, outputs) = setup(Some(digest(9999)));
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, outputs, 20, &intent);
        assert_eq!(proved_root, root);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    /// 3z-b1e — fraîcheur de l'aléa de blinding en PRODUCTION : `prove_tx` (donc
    /// `prove_monolith` → `build_monolith_trace`, le wrapper `OsRng` — pas la
    /// couture seedée `build_monolith_trace_seeded`, réservée aux tests) tiré DEUX
    /// fois sur la MÊME entrée (même secret/entrées/sorties/fee/intent) doit
    /// produire deux preuves STARK dont les OCTETS diffèrent : sans aléa frais, un
    /// observateur verrait deux preuves identiques et pourrait détecter la
    /// réémission d'une même dépense (fuite d'équivalence). `tx_digest`/`intent_sig`
    /// /`signer` sont, eux, IDENTIQUEMENT reconstruits (fonction déterministe des
    /// publics extraits de la trace) — on n'affirme PAS leur égalité/inégalité ici,
    /// seule `tx.proof` (bytes) est comparée. Les deux preuves doivent rester
    /// valides.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn deux_preuves_meme_tx_disjointes() {
        let (secret, root, inputs, outputs) = setup(None);
        let intent = SigKeypair::generate();

        // Même témoin dupliqué (les ProvedInput/SpendNote ne sont pas Copy) : la
        // fonction `setup` reconstruit une entrée strictement équivalente (mêmes
        // valeurs, owner, rho, r, arbre) — le seul aléa en jeu est celui de
        // `prove_tx`.
        let (_secret2, _root2, inputs2, outputs2) = setup(None);

        let (root1, tx1) = prove_tx(&secret, inputs, outputs, 20, &intent);
        let (root2, tx2) = prove_tx(&secret, inputs2, outputs2, 20, &intent);
        assert_eq!(root1, root);
        assert_eq!(root2, root);

        let bytes1 = tx1.proof.0.to_bytes();
        let bytes2 = tx2.proof.0.to_bytes();
        assert_ne!(
            bytes1, bytes2,
            "deux preuves de la même tx doivent être DISJOINTES (aléa frais par appel)"
        );

        assert!(verify_tx(&root, DEPTH, &tx1));
        assert!(verify_tx(&root, DEPTH, &tx2));
    }
}
