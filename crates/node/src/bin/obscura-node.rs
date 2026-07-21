//! `obscura-node` — nœud Obscura autonome.
//!
//! ```text
//! obscura-node --ecoute 127.0.0.1:9333 [--pair 127.0.0.1:9334]...
//! ```
//!
//! ⚠️ **Prototype non audité.** Ce binaire fait tourner la pile réelle (transport
//! post-quantique, mempool, Dandelion++) mais NE PERSISTE RIEN entre deux
//! lancements : identité, état et mempool sont neufs à chaque démarrage. Il sert à
//! observer le protocole, pas à détenir de la valeur.

use crypto::sig::SigKeypair;
use ledger::proved_state::ProvedLedgerState;
use node::orchestration::Noeud;
use node::runtime::Runtime;
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

/// Période de rotation d'époque Dandelion++ (ms). Un successeur trop stable finit
/// par être identifié ; trop volatil, il laisse apprendre la topologie.
const EPOQUE_MS: u64 = 600_000; // 10 min

fn usage() -> ! {
    eprintln!("usage : obscura-node --ecoute <adresse> [--pair <adresse>]...");
    eprintln!();
    eprintln!("  --ecoute <adresse>   adresse d'écoute (ex. 127.0.0.1:9333)");
    eprintln!("  --pair   <adresse>   pair à contacter (répétable)");
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut ecoute: Option<SocketAddr> = None;
    let mut pairs: Vec<SocketAddr> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ecoute" | "--pair" => {
                let Some(valeur) = args.get(i + 1) else { usage() };
                let Ok(adresse) = valeur.parse::<SocketAddr>() else {
                    eprintln!("adresse invalide : {valeur}");
                    std::process::exit(2);
                };
                if args[i] == "--ecoute" {
                    ecoute = Some(adresse);
                } else {
                    pairs.push(adresse);
                }
                i += 2;
            }
            _ => usage(),
        }
    }
    let Some(adresse_ecoute) = ecoute else { usage() };

    let identite = SigKeypair::generate();
    let mut secret_dandelion = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret_dandelion);

    let mut rt = Runtime::new(Noeud::new(
        SigKeypair::generate(),
        ProvedLedgerState::new(),
        secret_dandelion,
    ));

    let listener = match TcpListener::bind(adresse_ecoute) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("écoute impossible sur {adresse_ecoute} : {e}");
            std::process::exit(1);
        }
    };
    // Non bloquant : la boucle doit pouvoir traiter les messages même sans nouvelle
    // connexion entrante — sinon le nœud se fige en attendant un visiteur.
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("mode non bloquant indisponible : {e}");
        std::process::exit(1);
    }
    println!("écoute sur {adresse_ecoute}");

    for p in &pairs {
        match rt.connecter(*p, &identite) {
            Ok(_) => println!("connecté à {p}"),
            Err(e) => eprintln!("échec de connexion à {p} : {e}"),
        }
    }

    let depart = Instant::now();
    let mut derniere_epoque = u64::MAX;
    loop {
        let maintenant = depart.elapsed().as_millis() as u64;

        // Rotation d'époque Dandelion++ : re-choisit le successeur de tige.
        let epoque = maintenant / EPOQUE_MS;
        if epoque != derniere_epoque {
            derniere_epoque = epoque;
            let table = std::mem::take(&mut rt.noeud_mut().pairs);
            rt.noeud_mut().dandelion.nouvelle_epoque(epoque, &table);
            rt.noeud_mut().pairs = table;
        }

        // Connexions entrantes (non bloquant).
        match listener.accept() {
            Ok((flux, distant)) => match rt.accepter(flux, &identite) {
                Ok(_) => println!("connexion entrante de {distant}"),
                Err(e) => eprintln!("handshake échoué avec {distant} : {e}"),
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("accept : {e}"),
        }

        rt.pomper(maintenant);
        rt.tick(maintenant);

        // Le protocole est piloté par les événements ; sans cette pause la boucle
        // consommerait un cœur entier à ne rien faire.
        std::thread::sleep(Duration::from_millis(10));
    }
}
