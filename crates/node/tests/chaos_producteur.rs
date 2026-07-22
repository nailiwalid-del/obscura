//! CHAOS — le producteur s'arrête, puis revient. La chaîne reprend-elle ?
//!
//! Défaut n°1 de la porte D (cf. `docs/superpowers/specs/2026-07-22-portes-vers-le-mainnet-design.md`).
//! Sur une chaîne à autorités, `producteur_attendu(h, vue) = autorites[(h−1+vue) mod n]` est
//! une fonction PURE de la hauteur : si l'autorité du tour est absente, **personne**
//! ne peut produire `h`. Le gel est donc **SUSPENSIF**, pas définitif — l'autorité
//! qui revient produit `h` et la chaîne repart.
//!
//! Cette propriété était documentée et **jamais testée**. Or elle repose entièrement
//! sur la persistance : une autorité qui redémarre avec une identité NEUVE ne serait
//! plus jamais reconnue comme productrice légitime, et la chaîne resterait figée pour
//! toujours — panne silencieuse et irrécupérable, puisque l'état est append-only.
//!
//! # Ce que ce test exige
//!
//! Pas « le nœud redémarre ». Il exige que **l'identité, la hauteur, la tête et la
//! racine traversent l'arrêt à l'identique**, que le bloc suivant s'enchaîne sur le
//! précédent, et qu'un observateur INDÉPENDANT — parti de la seule genèse — retrouve
//! exactement la même tête. C'est cette dernière égalité qui distingue « le nœud a
//! redémarré » de « la chaîne a repris ».
//!
//! # Ce qu'il ne couvre PAS, et c'est documenté
//!
//! Le mempool n'est pas persisté (limite connue : les pairs réannoncent). Le test
//! l'ASSERTE plutôt que de le passer sous silence, pour qu'un changement de ce
//! comportement soit remarqué.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::persistance::Donnees;
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::merkle::CONSENSUS_DEPTH;
use proved_hash::rescue;
use wallet::Wallet;

fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

/// Un pair de test : identité et adresse.
fn pair_de_test() -> (net::pairs::PeerId, std::net::SocketAddr) {
    let id = net::pairs::PeerId::depuis_identite(&SigKeypair::generate().public);
    (
        id,
        std::net::SocketAddr::from((std::net::Ipv4Addr::new(203, 0, 113, 1), 8333)),
    )
}

/// Répertoire de données jetable, propre à ce test et à ce processus.
fn repertoire(nom: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("obscura_chaos_{}_{}", nom, std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Genèse à UNE autorité, une note émise vers CHAQUE wallet de `vers`.
///
/// Une seule autorité, délibérément : son absence fige alors la chaîne ENTIÈREMENT,
/// ce qui rend le gel et la reprise observables sans ambiguïté.
///
/// Un wallet par transaction, délibérément aussi : `construire` ne retire pas la note
/// dépensée (c'est `oublier_depensees` qui le fait, après diffusion). Deux transactions
/// tirées du même wallet risqueraient donc de rejouer la MÊME note, et la seconde
/// serait refusée en double-dépense — un échec qui n'aurait rien appris sur le chaos.
///
/// ⚠️ Chaque wallet tire une paire KEM NEUVE : seul le `owner` dérive du secret
/// shielded. Un « wallet miroir » du même secret ne déchiffrerait donc AUCUNE
/// enveloppe. Les notes doivent être émises vers les instances qui les dépenseront.
fn genese_pour(vers: &[&Wallet], autorite: &SigKeypair) -> Bloc {
    let emissions = vers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let valeur = 1_000u64 + i as u64 * 100;
            let note = circuit::SpendNote {
                value: valeur,
                owner: w.owner(),
                rho: rescue::hash(
                    proved_hash::domain::Domain::Owner,
                    &[Felt::from_canonical_u64(valeur).unwrap(); 4],
                ),
                r: rescue::hash(
                    proved_hash::domain::Domain::Nk,
                    &[Felt::from_canonical_u64(valeur).unwrap(); 4],
                ),
            };
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note).unwrap()
        })
        .collect();
    Bloc::genese_avec_autorites(emissions, vec![autorite.public.clone()]).expect("genèse bornée")
}

/// Rejoue la genèse dans le wallet : sans index, aucune preuve d'appartenance.
fn rejouer_genese(w: &mut Wallet, genese: &Bloc, etat: &ProvedLedgerState) {
    let lot = wallet::synchro::MorceauHistorique::bloc_entier(
        0,
        0,
        etat.tree.root(),
        genese
            .emissions
            .iter()
            .map(ledger::historique::Sortie::from)
            .collect(),
    );
    w.synchroniser(std::slice::from_ref(&lot)).expect("rejeu");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn arret_et_reprise_du_producteur() {
    let racine = repertoire("producteur");
    let beneficiaire = Wallet::depuis_secret(secret(900), CONSENSUS_DEPTH);

    // Un wallet par transaction — voir `genese_pour`.
    let mut avant = Wallet::depuis_secret(secret(700), CONSENSUS_DEPTH);
    let mut etranger = Wallet::depuis_secret(secret(750), CONSENSUS_DEPTH);
    let mut apres = Wallet::depuis_secret(secret(800), CONSENSUS_DEPTH);

    // ---------- PREMIER DÉMARRAGE ----------
    let donnees = Donnees::ouvrir(&racine).expect("ouverture du dépôt");
    let (identite, creee) = donnees.charger_ou_creer_identite().expect("identité");
    assert!(creee, "premier démarrage : l'identité vient d'être créée");
    let empreinte_identite = identite.public.to_bytes();

    let genese = genese_pour(&[&avant, &etranger, &apres], &identite);
    let etat = donnees
        .charger_ou_amorcer_etat(&genese)
        .expect("amorçage sur la genèse");
    for w in [&mut avant, &mut etranger, &mut apres] {
        rejouer_genese(w, &genese, &etat);
        assert_eq!(
            w.notes().len(),
            1,
            "chaque wallet ne voit QUE sa propre note"
        );
    }

    let tx1 = avant
        .construire(&beneficiaire.adresse(), 300, 0)
        .expect("transaction 1");

    let mut noeud = Noeud::new(identite, etat, [7u8; 32]);
    noeud
        .mempool
        .admettre(&noeud.etat, tx1)
        .expect("admission 1");
    let (bloc1, _) = noeud.sceller().expect("notre tour : un bloc");
    assert_eq!(noeud.etat.hauteur(), 1, "le bloc 1 est appliqué chez nous");

    // L'état est persisté — c'est ce que fait le runtime après chaque bloc.
    donnees
        .enregistrer_etat(&noeud.etat)
        .expect("persistance de l'état");

    let hauteur_avant = noeud.etat.hauteur();
    let tete_avant = noeud.etat.tete();
    let racine_avant = noeud.etat.tree.root();

    // ---------- ARRÊT ----------
    // Le processus disparaît. Rien d'autre ne peut produire : l'autorité est unique.
    drop(noeud);

    // LE GEL, vérifié plutôt qu'affirmé : un nœud qui n'est PAS l'autorité, parti du
    // même état et avec une transaction en attente, ne scelle rien.
    {
        let tiers = SigKeypair::generate();
        let tx = etranger
            .construire(&beneficiaire.adresse(), 100, 0)
            .expect("transaction d'un tiers");
        let etat_tiers = ProvedLedgerState::depuis_genese(&genese).expect("amorçage tiers");
        let mut n = Noeud::new(tiers, etat_tiers, [9u8; 32]);
        n.mempool.admettre(&n.etat, tx).expect("admission");
        assert!(
            n.sceller().is_none(),
            "GEL : hors autorité, aucun bloc — la chaîne est bien arrêtée"
        );
        assert_eq!(n.mempool.len(), 1, "et la transaction reste candidate");
    }

    // ---------- REDÉMARRAGE ----------
    let donnees = Donnees::ouvrir(&racine).expect("réouverture du dépôt");
    let (identite2, creee2) = donnees.charger_ou_creer_identite().expect("identité relue");
    assert!(!creee2, "l'identité ne doit PAS être régénérée");
    assert_eq!(
        identite2.public.to_bytes(),
        empreinte_identite,
        "L'IDENTITÉ DOIT SURVIVRE : une autorité re-clefée n'est plus jamais          reconnue comme productrice, et la chaîne resterait figée pour toujours"
    );

    let etat2 = donnees
        .charger_ou_amorcer_etat(&genese)
        .expect("état relu depuis le disque");
    assert_eq!(etat2.hauteur(), hauteur_avant, "la hauteur a survécu");
    assert_eq!(etat2.tete(), tete_avant, "la tête a survécu");
    assert_eq!(etat2.tree.root(), racine_avant, "la racine a survécu");

    let mut noeud = Noeud::new(identite2, etat2, [7u8; 32]);
    assert_eq!(
        noeud.mempool.len(),
        0,
        "LIMITE CONNUE : le mempool n'est pas persisté (les pairs réannoncent).          Assertée ici pour qu'un changement de ce comportement soit remarqué."
    );

    // ---------- LA CHAÎNE REPREND ----------
    let tx2 = apres
        .construire(&beneficiaire.adresse(), 200, 0)
        .expect("transaction 2");
    noeud
        .mempool
        .admettre(&noeud.etat, tx2)
        .expect("admission 2");
    let (bloc2, _) = noeud
        .sceller()
        .expect("après reprise : notre tour à nouveau");

    assert_eq!(
        bloc2.hauteur, 2,
        "la hauteur reprend EXACTEMENT où elle s'était arrêtée"
    );
    assert_eq!(
        bloc2.parent,
        bloc1.id(),
        "le bloc 2 s'enchaîne sur le bloc 1, pas sur la genèse"
    );
    assert_eq!(
        bloc2.vue, 0,
        "aucun changement de vue dans ce scénario : la reprise se fait au même tour"
    );
    assert!(
        bloc2.verifier_scellement(&genese.autorites[0]),
        "scellé par l'autorité gravée en genèse, la même qu'avant l'arrêt"
    );

    // ---------- L'OBSERVATEUR INDÉPENDANT ----------
    // Un tiers parti de la SEULE genèse, qui applique les deux blocs dans l'ordre,
    // doit retrouver la tête et la racine du nœud redémarré. C'est ce qui distingue
    // « le nœud a redémarré » de « la chaîne a repris ».
    let mut temoin = ProvedLedgerState::depuis_genese(&genese).expect("amorçage témoin");
    temoin.appliquer_bloc(&bloc1).expect("témoin : bloc 1");
    temoin.appliquer_bloc(&bloc2).expect("témoin : bloc 2");
    assert_eq!(
        temoin.tete(),
        noeud.etat.tete(),
        "un observateur indépendant retrouve la MÊME tête"
    );
    assert_eq!(
        temoin.tree.root(),
        noeud.etat.tree.root(),
        "et la MÊME racine — la chaîne a bien repris, pas seulement le processus"
    );

    let _ = std::fs::remove_dir_all(&racine);
}

/// SÛRETÉ APRÈS REDÉMARRAGE : un nœud qui a voté, puis redémarre, ne vote pas pour
/// un AUTRE bloc à la même `(hauteur, vue)`.
///
/// # Pourquoi ce test est le plus important du fichier
///
/// Sans registre persisté, il échoue — et l'échec réel ne serait pas un test rouge
/// mais une **chaîne divergente**, définitive sur un ledger append-only. Deux blocs
/// différents réuniraient `2f+1` à la même hauteur, deux nœuds honnêtes
/// appliqueraient des blocs différents, et rien ne pourrait les réconcilier.
///
/// # Comment on obtient deux blocs distincts à la même position
///
/// Par leur CONTENU. Deux blocs VIDES à la même `(hauteur, vue)` ont le même
/// identifiant — c'est la canonicité, et elle est voulue. Le second bloc porte donc
/// une transaction.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn le_redemarrage_ne_fait_pas_revoter() {
    let racine = repertoire("revote");
    let beneficiaire = Wallet::depuis_secret(secret(900), CONSENSUS_DEPTH);
    let mut payeur = Wallet::depuis_secret(secret(700), CONSENSUS_DEPTH);

    let donnees = Donnees::ouvrir(&racine).expect("ouverture");
    let (identite, _) = donnees.charger_ou_creer_identite().expect("identité");
    let genese = genese_pour(&[&payeur], &identite);
    let etat = donnees.charger_ou_amorcer_etat(&genese).expect("amorçage");
    rejouer_genese(&mut payeur, &genese, &etat);
    let tx = payeur
        .construire(&beneficiaire.adresse(), 300, 0)
        .expect("transaction");

    // Deux propositions DISTINCTES à la hauteur 1, vue 0 : l'une vide, l'autre
    // portant la transaction. Contenus différents donc identifiants différents.
    let mut bloc_a = Bloc::sceller(&genese.id(), 1, Vec::new()).expect("bloc A");
    bloc_a.signer_scellement(&identite);
    let mut bloc_b = Bloc::sceller(&genese.id(), 1, vec![tx]).expect("bloc B");
    bloc_b.signer_scellement(&identite);
    assert_ne!(
        bloc_a.id(),
        bloc_b.id(),
        "deux contenus distincts, deux identifiants"
    );

    // ---------- LE NŒUD VOTE POUR A ----------
    let mut noeud = Noeud::new(identite, etat, [7u8; 32]);
    noeud.adopter_votes(donnees.charger_ou_creer_votes().expect("registre"));
    let (p, adr) = pair_de_test();
    noeud.pairs.ajouter(p, adr);

    let copie_a = Bloc::from_bytes(&bloc_a.to_bytes()).expect("copie A");
    let actions = noeud.traiter(p, Message::Proposition(Box::new(copie_a)), 0);
    // Le registre est persisté par l'ACTION, dans l'ordre — ici on l'exécute nous-mêmes.
    let mut vote_emis = false;
    for a in &actions {
        match a {
            Action::PersisterVotes(r) => donnees.enregistrer_votes(r).expect("écriture"),
            Action::Envoyer(_, Message::Vote(_)) => vote_emis = true,
            _ => {}
        }
    }
    assert!(vote_emis, "le nœud doit voter pour A");

    // ---------- REDÉMARRAGE ----------
    drop(noeud);
    let donnees = Donnees::ouvrir(&racine).expect("réouverture");
    let (identite2, creee) = donnees.charger_ou_creer_identite().expect("identité relue");
    assert!(!creee, "l'identité survit");
    let etat2 = donnees.charger_ou_amorcer_etat(&genese).expect("état relu");
    let mut noeud = Noeud::new(identite2, etat2, [7u8; 32]);
    noeud.adopter_votes(donnees.charger_ou_creer_votes().expect("registre relu"));
    noeud.pairs.ajouter(p, adr);

    // ---------- B NE DOIT PAS ÊTRE VOTÉ ----------
    let copie_b = Bloc::from_bytes(&bloc_b.to_bytes()).expect("copie B");
    assert!(
        noeud
            .traiter(p, Message::Proposition(Box::new(copie_b)), 0)
            .is_empty(),
        "ÉQUIVOCATION : après redémarrage, voter pour un AUTRE bloc à la même \
         position produirait une divergence DÉFINITIVE"
    );

    // ---------- A RESTE VOTABLE ----------
    let copie_a = Bloc::from_bytes(&bloc_a.to_bytes()).expect("copie A bis");
    assert!(
        !noeud
            .traiter(p, Message::Proposition(Box::new(copie_a)), 0)
            .is_empty(),
        "re-voter pour le MÊME bloc reste permis : idempotent, et nécessaire \
         puisqu'un vote peut se perdre"
    );

    let _ = std::fs::remove_dir_all(&racine);
}
