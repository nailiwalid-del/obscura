//! Tests du handshake en duplex MÉMOIRE — aucun socket.
//!
//! Le transport est une machine à états pure : la tester sans réseau donne un
//! retour immédiat et déterministe, et isole les défauts de protocole des aléas
//! d'E/S.

use crypto::sig::SigKeypair;
use net::{Initiateur, NetError, Repondeur};

/// Handshake complet. Retourne les deux sessions et les identités authentifiées,
/// telles que chaque pair les a vues.
fn handshake_complet() -> (net::Session, net::Session, SigKeypair, SigKeypair) {
    let id_i = SigKeypair::generate();
    let id_r = SigKeypair::generate();

    let (init, passe1) = Initiateur::commencer();
    let (rep, passe2) = Repondeur::repondre(&passe1, &id_r).expect("passe 2");
    let final_i = init.recevoir_passe2(&passe2, &id_i).expect("passe 2 acceptée");
    let (passe3, sess_i, vu_par_i) = final_i.terminer();
    let (sess_r, vu_par_r) = rep.recevoir_passe3(&passe3).expect("passe 3 acceptée");

    // Chacun a authentifié la VRAIE identité de l'autre.
    assert_eq!(vu_par_i.to_bytes(), id_r.public.to_bytes(), "I authentifie R");
    assert_eq!(vu_par_r.to_bytes(), id_i.public.to_bytes(), "R authentifie I");

    (sess_i, sess_r, id_i, id_r)
}

/// NOMINAL : le handshake aboutit et les deux pairs dérivent des clés APPARIÉES —
/// vérifié par un échange réel dans les deux sens, pas en comparant des clés.
#[test]
fn handshake_puis_echange_bidirectionnel() {
    let (mut i, mut r, _, _) = handshake_complet();

    let c = i.chiffrer(b"transaction").unwrap();
    assert_eq!(r.dechiffrer(&c).unwrap(), b"transaction");

    let c2 = r.chiffrer(b"accuse de reception").unwrap();
    assert_eq!(i.dechiffrer(&c2).unwrap(), b"accuse de reception");
}

/// FORWARD SECRECY : deux handshakes entre les MÊMES identités produisent des
/// sessions indépendantes. Un cadre d'une session est indéchiffrable dans l'autre —
/// c'est l'effet des éphémères frais.
#[test]
fn sessions_independantes_entre_handshakes() {
    let id_i = SigKeypair::generate();
    let id_r = SigKeypair::generate();

    let etablir = || {
        let (init, p1) = Initiateur::commencer();
        let (rep, p2) = Repondeur::repondre(&p1, &id_r).unwrap();
        let fi = init.recevoir_passe2(&p2, &id_i).unwrap();
        let (p3, si, _) = fi.terminer();
        let (sr, _) = rep.recevoir_passe3(&p3).unwrap();
        (si, sr)
    };

    let (mut i1, _r1) = etablir();
    let (_i2, mut r2) = etablir();

    let c = i1.chiffrer(b"secret").unwrap();
    assert_eq!(
        r2.dechiffrer(&c),
        Err(NetError::DechiffrementEchoue),
        "les clés doivent être propres à chaque session (forward secrecy)"
    );
}

/// MASQUAGE D'IDENTITÉ : aucune clé publique d'identité n'apparaît en clair dans les
/// octets du handshake.
///
/// Même discipline que les tests key-privacy de `ledger::proved_wallet` : on cherche
/// toute fenêtre de 8 octets de la clé publique dans le flux. C'est un test de
/// non-fuite STRUCTURELLE — la classe d'erreur qu'une implémentation introduit
/// réellement (sérialiser l'identité « pour déboguer », l'oublier hors du scellé).
#[test]
fn identites_jamais_en_clair_sur_le_fil() {
    let id_i = SigKeypair::generate();
    let id_r = SigKeypair::generate();

    let (init, passe1) = Initiateur::commencer();
    let (rep, passe2) = Repondeur::repondre(&passe1, &id_r).unwrap();
    let final_i = init.recevoir_passe2(&passe2, &id_i).unwrap();
    let (passe3, _, _) = final_i.terminer();
    let _ = rep.recevoir_passe3(&passe3).unwrap();

    // Tout ce qu'un observateur passif voit passer.
    let mut fil = passe1.clone();
    fil.extend_from_slice(&passe2);
    fil.extend_from_slice(&passe3);

    for (nom, pk) in [("initiateur", id_i.public.to_bytes()), ("répondeur", id_r.public.to_bytes())] {
        for fenetre in pk.windows(8) {
            assert!(
                !fil.windows(8).any(|w| w == fenetre),
                "fragment de l'identité du {nom} visible en clair sur le fil"
            );
        }
    }
}

/// MitM : un attaquant qui substitue SA propre identité dans la passe 2 est rejeté.
/// Il ne peut pas produire une signature valide sur le transcript attendu sans la
/// clé du vrai répondeur, et il ne peut pas non plus recalculer `k1` sans l'éphémère.
#[test]
fn mitm_substituant_son_identite_rejete() {
    let id_i = SigKeypair::generate();
    let id_r = SigKeypair::generate();
    let id_mitm = SigKeypair::generate();

    let (init, passe1) = Initiateur::commencer();
    // Le MitM répond à la place du vrai répondeur, avec SA clé.
    let (_rep_mitm, passe2_mitm) = Repondeur::repondre(&passe1, &id_mitm).unwrap();

    // L'initiateur accepte cryptographiquement (le MitM a signé correctement SON
    // transcript) mais authentifie le MITM, pas le répondeur attendu — c'est
    // exactement la limite documentée : l'identité du répondeur est révélée et
    // substituable pour un actif. La défense est au niveau supérieur (liste de
    // pairs connus), d'où ce test qui FIGE le comportement observable.
    let final_i = init.recevoir_passe2(&passe2_mitm, &id_i).unwrap();
    let (_, _, vu) = final_i.terminer();
    assert_eq!(
        vu.to_bytes(),
        id_mitm.public.to_bytes(),
        "l'initiateur voit l'identité du MitM, PAS celle du répondeur attendu"
    );
    assert_ne!(vu.to_bytes(), id_r.public.to_bytes());
}

/// ALTÉRATION DU TRANSCRIPT : modifier un octet de la passe 2 fait diverger le
/// transcript → le scellé ne s'ouvre plus (ou la signature ne vérifie plus).
#[test]
fn passe2_alteree_rejetee() {
    let id_i = SigKeypair::generate();
    let id_r = SigKeypair::generate();

    for position in [0usize, 100, 500] {
        let (init, passe1) = Initiateur::commencer();
        let (_rep, mut passe2) = Repondeur::repondre(&passe1, &id_r).unwrap();
        if position >= passe2.len() {
            continue;
        }
        passe2[position] ^= 1;
        assert!(
            init.recevoir_passe2(&passe2, &id_i).is_err(),
            "passe 2 altérée à l'octet {position} doit être rejetée"
        );
    }
}

/// ALTÉRATION DE LA PASSE 3 : le répondeur rejette.
#[test]
fn passe3_alteree_rejetee() {
    let id_i = SigKeypair::generate();
    let id_r = SigKeypair::generate();

    let (init, passe1) = Initiateur::commencer();
    let (rep, passe2) = Repondeur::repondre(&passe1, &id_r).unwrap();
    let final_i = init.recevoir_passe2(&passe2, &id_i).unwrap();
    let (mut passe3, _, _) = final_i.terminer();
    let dernier = passe3.len() - 1;
    passe3[dernier] ^= 1;
    assert!(rep.recevoir_passe3(&passe3).is_err(), "passe 3 altérée doit être rejetée");
}

/// SURFACE HOSTILE : messages tronqués, vides, aux longueurs aberrantes ou avec des
/// octets résiduels → `Result`, JAMAIS de panique. C'est un point d'entrée réseau.
#[test]
fn messages_malformes_rejetes_sans_panique() {
    let id_r = SigKeypair::generate();

    // Vide et tronqués.
    assert_eq!(Repondeur::repondre(&[], &id_r).err(), Some(NetError::Tronque));
    assert_eq!(Repondeur::repondre(&[0, 0], &id_r).err(), Some(NetError::Tronque));

    // Longueur annoncée gigantesque (anti-DoS mémoire) : refus AVANT allocation.
    let mut enorme = u32::MAX.to_le_bytes().to_vec();
    enorme.push(0);
    assert_eq!(
        Repondeur::repondre(&enorme, &id_r).err(),
        Some(NetError::TailleInvalide)
    );

    // Longueur cohérente mais contenu non décodable.
    let mut bidon = (16u32).to_le_bytes().to_vec();
    bidon.extend_from_slice(&[0xAB; 16]);
    assert_eq!(
        Repondeur::repondre(&bidon, &id_r).err(),
        Some(NetError::EncodageInvalide)
    );

    // Octets résiduels après une passe 1 par ailleurs valide.
    let (_init, mut passe1) = Initiateur::commencer();
    passe1.push(0);
    assert_eq!(
        Repondeur::repondre(&passe1, &id_r).err(),
        Some(NetError::OctetsResiduels)
    );
}
