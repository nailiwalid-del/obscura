//! `obscura-demo` — démonstration de bout en bout, en local.
//!
//! Monte deux nœuds réels sur de vraies sockets, construit une transaction avec un
//! wallet, l'émet, et observe sa propagation. Chaque étape est annoncée : c'est
//! l'artefact qui répond à « est-ce que ça marche vraiment ? » autrement que par
//! une suite de tests verte.
//!
//! ```text
//! cargo run --release --bin obscura-demo
//! ```
//!
//! ⚠️ À lancer en `--release` : l'AIR du monolithe est gatée, et une preuve prend
//! plusieurs centaines de millisecondes.

use crypto::sig::SigKeypair;
use ledger::proved_state::ProvedLedgerState;
use node::message::Message;
use node::orchestration::{Action, Noeud};
use node::runtime::Runtime;
use proved_hash::digest::ShieldedSecret;
use proved_hash::felt::Felt;
use proved_hash::rescue;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 4;

fn secret(graine: u64) -> ShieldedSecret {
    ShieldedSecret::from_felts(core::array::from_fn(|i| {
        Felt::from_canonical_u64(graine + i as u64).unwrap()
    }))
}

fn attendre<F: FnMut() -> bool>(mut c: F, delai: Duration) -> bool {
    let t = Instant::now();
    while t.elapsed() < delai {
        if c() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    c()
}

fn main() {
    println!("=== Obscura — démonstration locale ===\n");
    println!("⚠️  Prototype non audité : à ne pas utiliser pour détenir de la valeur.\n");

    // ---- 1. Deux wallets et un état initial partagé ----
    println!("[1/5] Création des wallets et de l'état initial");
    let mut alice = wallet::Wallet::depuis_secret(secret(700), PROFONDEUR);
    let bob = wallet::Wallet::depuis_secret(secret(900), PROFONDEUR);

    // Émission (faucet du prototype) : deux notes vers Alice.
    let mut etat = ProvedLedgerState::with_depth(PROFONDEUR);
    for valeur in [1_000u64, 500u64] {
        let note = circuit::SpendNote {
            value: valeur,
            owner: alice.owner(),
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
        etat.mint(&cm).expect("émission");
        alice.crediter_pour_demo(note, &cm);
    }
    println!("      solde d'Alice : {} unités", alice.solde());
    println!(
        "      racines nœud/wallet concordantes : {}",
        etat.tree.root() == alice.racine()
    );

    // ---- 2. Construction de la transaction (preuve STARK) ----
    println!("\n[2/5] Alice construit une transaction de 300 vers Bob (frais 20)");
    let debut = Instant::now();
    let tx = alice
        .construire(&bob.adresse(), 300, 20)
        .expect("transaction constructible");
    let duree = debut.elapsed();
    let taille = tx.to_bytes().len();
    println!("      preuve générée en {:.1} ms", duree.as_secs_f64() * 1e3);
    println!("      taille de la transaction : {:.1} Kio", taille as f64 / 1024.0);
    println!("      monnaie rendue à Alice : {} unités", 1_500 - 300 - 20);

    // ---- 3. Deux nœuds réels ----
    println!("\n[3/5] Démarrage de deux nœuds sur de vraies sockets");
    let digest = tx.tx_digest;
    let id_a = SigKeypair::generate();
    let id_b = SigKeypair::generate();
    let ecoute = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let adresse = ecoute.local_addr().unwrap();
    println!("      nœud B écoute sur {adresse}");

    let b = std::thread::spawn(move || {
        let mut rt = Runtime::new(Noeud::new(
            SigKeypair::generate(),
            {
                // B reconstruit le MÊME état initial (sinon : « ancre inconnue »).
                let mut e = ProvedLedgerState::with_depth(PROFONDEUR);
                let w = wallet::Wallet::depuis_secret(secret(700), PROFONDEUR);
                for valeur in [1_000u64, 500u64] {
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
                    let cm =
                        rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
                    e.mint(&cm).unwrap();
                }
                e
            },
            [2u8; 32],
        ));
        let (flux, _) = ecoute.accept().unwrap();
        rt.accepter(flux, &id_b).expect("handshake");
        let recu = attendre(
            || {
                rt.pomper(0);
                rt.noeud().mempool.contient(&digest)
            },
            Duration::from_secs(30),
        );
        recu
    });

    // ---- 4. Handshake post-quantique et soumission ----
    println!("\n[4/5] Handshake post-quantique (X25519+Kyber768 / Ed25519+Dilithium3)");
    let mut a = Runtime::new(Noeud::new(SigKeypair::generate(), etat, [1u8; 32]));
    let debut_hs = Instant::now();
    let pair_b = a.connecter(adresse, &id_a).expect("handshake");
    println!(
        "      canal chiffré établi en {:.1} ms (PFS + identités masquées)",
        debut_hs.elapsed().as_secs_f64() * 1e3
    );

    println!("\n[5/5] Alice soumet sa transaction et l'annonce");
    a.noeud_mut().soumettre(tx, 0).expect("admission locale");
    a.executer(vec![Action::Envoyer(pair_b, Message::Annonce(vec![digest]))]);
    attendre(|| a.pomper(0) > 0, Duration::from_secs(30));

    let recu = b.join().expect("nœud B");
    println!();
    if recu {
        println!("✅ La transaction a été vérifiée (STARK) et acceptée par le nœud B.");
        println!("   Chemin : wallet → preuve → cadrage → chiffrement PQ → socket");
        println!("            → décodage → admission → mempool");
    } else {
        println!("❌ La transaction n'est pas parvenue au nœud B.");
        std::process::exit(1);
    }
}
