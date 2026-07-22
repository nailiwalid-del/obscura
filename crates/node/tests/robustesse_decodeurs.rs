//! ROBUSTESSE DES NEUF DÉCODEURS — mini-fuzz déterministe, en stable.
//!
//! Le vrai fuzzing (libFuzzer, guidé par la couverture) tourne la nuit et exige
//! nightly : `.github/workflows/lourd.yml`. Ce test-ci ne le remplace pas — il
//! occupe le créneau que le nocturne laisse ouvert. Une régression introduite à
//! 10 h serait sinon découverte à 2 h du matin, sur une branche déjà mergée.
//!
//! Ce qu'il vérifie, pour chaque décodeur : **aucune panique**, quelles que soient
//! les entrées. Pas de `Result` attendu — un refus est le résultat NORMAL. Une
//! panique, elle, est un déni de service : sur les décodeurs de l'anneau 1, elle
//! s'atteint depuis le réseau par un inconnu.
//!
//! Le générateur est un xorshift à graine FIXE : mêmes octets à chaque exécution,
//! donc un échec est reproductible et ne dépend pas du jour de la semaine.

/// Xorshift64* — générateur déterministe, sans dépendance.
struct Alea(u64);

impl Alea {
    fn suivant(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn octet(&mut self) -> u8 {
        (self.suivant() >> 24) as u8
    }

    /// Vecteur d'octets de longueur bornée — la borne évite de mesurer la vitesse
    /// d'allocation plutôt que la robustesse.
    fn octets(&mut self, max: usize) -> Vec<u8> {
        let n = (self.suivant() as usize) % max;
        (0..n).map(|_| self.octet()).collect()
    }
}

/// Les entrées qui cassent un décodeur ne sont presque jamais aléatoires : ce sont
/// des entrées PRESQUE valides. On produit donc trois familles.
fn corpus(graine: u64, n: usize) -> Vec<Vec<u8>> {
    let mut a = Alea(graine);
    let mut v = Vec::with_capacity(n * 3);

    for _ in 0..n {
        // 1. Bruit pur — attrape les décodeurs qui lisent avant de vérifier.
        v.push(a.octets(512));

        // 2. Préfixe de version plausible + bruit : franchit le premier contrôle
        //    et fait travailler les longueurs, là où vivent les débordements.
        let mut b = vec![(a.suivant() % 5) as u8];
        b.extend(a.octets(256));
        v.push(b);

        // 3. Longueurs ÉNORMES annoncées : c'est le cas anti-DoS par excellence —
        //    un décodeur qui alloue avant de borner meurt ici, pas ailleurs.
        let mut b = vec![(a.suivant() % 5) as u8];
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        b.extend(a.octets(64));
        v.push(b);
    }
    v
}

/// ANNEAU 1 — les décodeurs atteignables par un INCONNU sur le réseau.
///
/// C'est la surface la plus exposée du projet : ces quatre fonctions décodent des
/// octets qu'un adversaire choisit entièrement.
#[test]
fn anneau_1_reseau_ne_panique_jamais() {
    for entree in corpus(0x0B5C_1A11, 700) {
        let _ = node::message::Message::from_bytes(&entree);
        let _ = circuit::ProvedTx::from_bytes(&entree);
        let _ = ledger::bloc::Bloc::from_bytes(&entree);
        let _ = node::synchro::ReponseHistorique::from_bytes(&entree);
    }
}

/// ANNEAU 2 — les décodeurs de DISQUE.
///
/// L'entrée ne vient pas d'un adversaire mais d'un fichier abîmé (coupure de
/// courant, disque défaillant). L'exigence reste la même : REFUSER, jamais
/// paniquer. Un nœud qui panique au démarrage sur un état corrompu est un nœud
/// perdu, et `Wallet::from_bytes_secret` porte l'autorité de dépense.
#[test]
fn anneau_2_disque_ne_panique_jamais() {
    for entree in corpus(0x0B5C_2A22, 700) {
        let _ = ledger::proved_state::ProvedLedgerState::from_bytes(&entree);
        let _ = ledger::historique::HistoriqueSorties::from_bytes(&entree);
        let _ = wallet::Wallet::from_bytes_secret(&entree);
        let _ = proved_hash::merkle::ProvedMerkleTree::from_bytes(&entree);
        let _ = proved_hash::merkle::MerkleFrontier::from_bytes(&entree);
    }
}

/// LA TRONCATURE : chaque préfixe d'un encodage VALIDE doit être refusé proprement.
///
/// C'est le cas qu'un générateur aléatoire n'atteint quasiment jamais, et c'est
/// pourtant le plus réaliste des deux : une écriture interrompue produit
/// exactement ça — un préfixe valide, puis plus rien.
#[test]
fn tout_prefixe_dun_encodage_valide_est_refuse_sans_panique() {
    let bloc = ledger::bloc::Bloc::genese().to_bytes();
    for i in 0..bloc.len() {
        let _ = ledger::bloc::Bloc::from_bytes(&bloc[..i]);
    }

    let etat = ledger::proved_state::ProvedLedgerState::with_depth(4).to_bytes();
    for i in 0..etat.len() {
        let _ = ledger::proved_state::ProvedLedgerState::from_bytes(&etat[..i]);
    }
    // Et l'encodage COMPLET, lui, se relit — sinon le test ci-dessus serait
    // satisfait par un décodeur qui refuse tout.
    assert!(ledger::proved_state::ProvedLedgerState::from_bytes(&etat).is_ok());

    let arbre = proved_hash::merkle::ProvedMerkleTree::new(4).to_bytes();
    for i in 0..arbre.len() {
        let _ = proved_hash::merkle::ProvedMerkleTree::from_bytes(&arbre[..i]);
    }
    assert!(proved_hash::merkle::ProvedMerkleTree::from_bytes(&arbre).is_ok());
}

/// L'OCTET RETOURNÉ : une corruption d'UN SEUL bit ne doit jamais paniquer.
///
/// C'est le mode de défaillance réel d'un disque, et il est bien plus vicieux que
/// la troncature : la longueur reste plausible, seuls les octets mentent. Un
/// compteur d'éléments retourné devient un ordre d'allocation gigantesque, et
/// `with_capacity` panique AVANT que la moindre borne ne soit consultée.
///
/// **Ce test a trouvé un défaut réel** (« Hash table capacity overflow » dans
/// `ProvedLedgerState::from_bytes`) : un fichier d'état abîmé faisait paniquer le
/// nœud au démarrage. D'où l'application à TOUS les décodeurs qui portent un
/// compteur — un défaut de cette classe ne vient jamais seul.
#[test]
fn un_octet_corrompu_ne_panique_jamais() {
    /// Retourne un bit au hasard dans `origine`, `essais` fois, et passe chaque
    /// version abîmée au décodeur. On ne vérifie RIEN du résultat : accepter ou
    /// refuser sont deux issues correctes — paniquer ne l'est pas.
    fn marteler(nom: &str, origine: &[u8], graine: u64, decodeur: impl Fn(&[u8])) {
        assert!(!origine.is_empty(), "{nom} : encodage de référence vide");
        let mut a = Alea(graine);
        for _ in 0..2_000 {
            let mut abime = origine.to_vec();
            let i = (a.suivant() as usize) % abime.len();
            abime[i] ^= 1 << (a.suivant() % 8);
            decodeur(&abime);
        }
    }

    marteler(
        "état",
        &ledger::proved_state::ProvedLedgerState::with_depth(4).to_bytes(),
        0x0B5C_3A33,
        |b| {
            let _ = ledger::proved_state::ProvedLedgerState::from_bytes(b);
        },
    );

    marteler(
        "bloc",
        &ledger::bloc::Bloc::genese().to_bytes(),
        0x0B5C_3A34,
        |b| {
            let _ = ledger::bloc::Bloc::from_bytes(b);
        },
    );

    marteler(
        "arbre",
        &proved_hash::merkle::ProvedMerkleTree::new(4).to_bytes(),
        0x0B5C_3A35,
        |b| {
            let _ = proved_hash::merkle::ProvedMerkleTree::from_bytes(b);
        },
    );

    marteler(
        "frontier",
        &proved_hash::merkle::MerkleFrontier::new(4).to_bytes(),
        0x0B5C_3A36,
        |b| {
            let _ = proved_hash::merkle::MerkleFrontier::from_bytes(b);
        },
    );

    // (`HistoriqueSorties::nouveau` est `pub(crate)` — l'archive ne se crée que par
    // `depuis_genese_archivant`, une seule porte. Le décodeur est couvert par le
    // corpus de l'anneau 2 et par le fuzzing nocturne.)

    // Message applicatif : anneau 1, donc atteignable par un inconnu. Une annonce
    // porte un compteur de digests — la même classe de défaut, côté réseau.
    marteler(
        "message",
        &node::message::Message::Annonce(vec![[7u8; 64], [9u8; 64]]).to_bytes(),
        0x0B5C_3A38,
        |b| {
            let _ = node::message::Message::from_bytes(b);
        },
    );
}
