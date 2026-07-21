//! Persistance d'un nœud entre deux lancements.
//!
//! Un nœud qui repart de zéro à chaque démarrage n'en est pas un : il perd son
//! ÉTAT (donc doit tout resynchroniser) et son IDENTITÉ (donc ses pairs ne le
//! reconnaissent pas, et la réputation accumulée est effacée). C'est aussi une
//! aubaine pour un nœud malveillant, qui se blanchirait en redémarrant.
//!
//! Trois fichiers dans un répertoire de données :
//!
//! | fichier | contenu | sensibilité |
//! |---|---|---|
//! | `identite.cle` | paire de signature hybride | **SECRET** |
//! | `etat.bin` | frontier + nullifiers + racines récentes | public |
//! | `historique.bin` | sorties ordonnées — **archiviste seulement** | public |
//!
//! # Pourquoi l'historique est un fichier SÉPARÉ
//!
//! L'archivage est un rôle d'opérateur, pas une obligation de consensus : un nœud qui
//! n'archive pas est valide (cf. `ledger::historique`). L'embarquer dans `etat.bin`
//! aurait imposé plusieurs Gio à tous les nœuds et changé `VERSION_ETAT`.
//!
//! Deux fichiers = deux écritures, donc un crash peut les laisser désaccordés.
//! [`Donnees::enregistrer_etat`] écrit **l'historique D'ABORD, l'état ensuite**, et ce
//! n'est pas indifférent : si le crash tombe entre les deux, l'archive est en AVANCE
//! d'un bloc — un écart nommé, dont le contenu excédentaire existe encore. L'ordre
//! inverse aurait laissé l'état en avance, c'est-à-dire une archive à qui il manque des
//! sorties que PLUS AUCUN état ne peut reproduire (la frontier ne garde que le bord
//! droit).
//!
//! Dans les deux cas, aucune réparation muette : le désaccord remonte en erreur
//! (`HistoriqueDesaccorde`), l'appelant le journalise et tourne en mode DÉGRADÉ, sans
//! archive. Le fichier n'est ni tronqué ni effacé — le bloc en trop a peut-être été
//! relayé à tout le réseau.
//!
//! # Le fichier d'identité est du matériel de clé
//!
//! Il contient les clés secrètes EN CLAIR. Quiconque le lit peut se faire passer
//! pour ce nœud. Les permissions sont donc restreintes au propriétaire dès la
//! création (`0600` sur Unix), et l'écriture est atomique — un fichier de clé
//! à moitié écrit rendrait l'identité irrécupérable.
//!
//! ⚠️ Limite assumée : le fichier n'est PAS chiffré au repos. Le protéger par une
//! phrase de passe supposerait une saisie interactive, hors périmètre d'un
//! prototype ; c'est écrit ici plutôt que laissé à supposer.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::historique::{HistoriqueSorties, Reprise};
use ledger::proved_state::ProvedLedgerState;
use std::fs;
use std::path::{Path, PathBuf};

const FICHIER_IDENTITE: &str = "identite.cle";
const FICHIER_ETAT: &str = "etat.bin";
const FICHIER_HISTORIQUE: &str = "historique.bin";

#[derive(Debug, thiserror::Error)]
pub enum PersistanceError {
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("fichier d'identité illisible ou corrompu")]
    IdentiteInvalide,
    #[error("fichier d'état illisible ou corrompu : {0}")]
    EtatInvalide(String),
    #[error("fichier de genèse illisible ou corrompu : {0}")]
    GeneseInvalide(String),
    #[error("genèse inapplicable : {0}")]
    GeneseRefusee(String),
    #[error("fichier d'historique illisible ou corrompu : {0}")]
    HistoriqueInvalide(String),
    /// L'archive et l'état ne racontent pas la même chaîne.
    ///
    /// Erreur DISTINCTE d'une corruption : les deux fichiers sont individuellement bien
    /// formés, c'est leur accord qui manque. La distinction compte pour l'opérateur —
    /// « corrompu » invite à effacer, « désaccordé » invite à comprendre lequel des deux
    /// est en avance avant de décider.
    #[error("archive désaccordée avec l'état : {0} — mode DÉGRADÉ (sans archive), rien n'est réparé")]
    HistoriqueDesaccorde(String),
    /// Le nœud doit archiver mais l'état est déjà à une hauteur non nulle sans archive.
    #[error("archivage demandé sur un état déjà à la hauteur {hauteur} sans fichier d'historique : le préfixe est irrécupérable")]
    HistoriqueAbsent { hauteur: u64 },
    /// L'état sur disque descend d'une AUTRE genèse que celle demandée.
    ///
    /// Sans ce refus, l'erreur d'opérateur la plus banale — pointer `--donnees` vers
    /// un répertoire peuplé par une autre chaîne — donnait un nœud d'apparence saine
    /// qui refusait tous les blocs, indiscernable d'un nœud au repos. Les identifiants
    /// sont montrés (8 premiers octets) pour que la correction soit évidente : soit la
    /// bonne genèse, soit le bon répertoire.
    #[error(
        "l'état de ce répertoire descend de la genèse {trouvee}, pas de {demandee} : \
         mauvais --genese ou mauvais --donnees — rien n'est écrasé"
    )]
    GeneseDifferente { demandee: String, trouvee: String },
}

/// Charge un bloc de GENÈSE depuis un fichier (octets de `Bloc::to_bytes`).
///
/// Passe par `Bloc::from_bytes`, c'est-à-dire le décodeur BORNÉ du réseau : un fichier
/// de genèse vient d'un tiers (l'opérateur de la chaîne qu'on rejoint) et n'est pas
/// plus digne de confiance qu'un octet arrivé par socket.
///
/// ⚠️ Aucune variante « charger ou créer » : une genèse absente doit faire ÉCHOUER le
/// démarrage. Se rabattre en silence sur la genèse vide donnerait un nœud d'apparence
/// saine, à la hauteur 0, refusant tous les blocs — indiscernable d'un nœud neuf.
pub fn charger_genese(chemin: impl AsRef<Path>) -> Result<Bloc, PersistanceError> {
    let octets = fs::read(chemin.as_ref())?;
    Bloc::from_bytes(&octets).map_err(|e| PersistanceError::GeneseInvalide(e.to_string()))
}

/// Répertoire de données d'un nœud.
pub struct Donnees {
    racine: PathBuf,
    /// Tranches d'historique déjà PERSISTÉES dans le journal.
    ///
    /// C'est la comptabilité qui rend l'ajout possible : `enregistrer_etat` n'écrit
    /// que les tranches au-delà de ce compte. `Cell` et non un champ nu : les
    /// signatures de chargement/sauvegarde prennent `&self` partout et la persistance
    /// est mono-thread — un verrou serait du théâtre.
    tranches_persistees: std::cell::Cell<usize>,
}

impl Donnees {
    /// Ouvre (et crée au besoin) le répertoire de données.
    pub fn ouvrir(racine: impl AsRef<Path>) -> Result<Self, PersistanceError> {
        let racine = racine.as_ref().to_path_buf();
        fs::create_dir_all(&racine)?;
        Ok(Donnees {
            racine,
            tranches_persistees: std::cell::Cell::new(0),
        })
    }

    fn chemin(&self, nom: &str) -> PathBuf {
        self.racine.join(nom)
    }

    /// Charge l'identité, ou en crée une NEUVE si le fichier n'existe pas.
    ///
    /// Retourne aussi `true` si l'identité vient d'être créée — l'appelant peut
    /// ainsi signaler qu'il s'agit d'un premier démarrage, information utile pour
    /// ne pas croire à tort qu'on a perdu son identité.
    pub fn charger_ou_creer_identite(&self) -> Result<(SigKeypair, bool), PersistanceError> {
        let chemin = self.chemin(FICHIER_IDENTITE);
        if chemin.exists() {
            let octets = fs::read(&chemin)?;
            let kp = SigKeypair::from_bytes_secret(&octets)
                .map_err(|_| PersistanceError::IdentiteInvalide)?;
            return Ok((kp, false));
        }
        let kp = SigKeypair::generate();
        self.ecrire_secret(&chemin, &kp.to_bytes_secret())?;
        Ok((kp, true))
    }

    /// Charge l'état, ou l'AMORCE sur `genese` s'il n'existe pas encore.
    ///
    /// La genèse est un paramètre EXPLICITE : c'est elle qui fixe la monnaie initiale
    /// et la tête de départ. Un nœud ne peut pas la deviner, et en inventer une
    /// reviendrait à démarrer une chaîne à soi tout en croyant rejoindre celle des
    /// autres.
    ///
    /// L'identifiant de genèse est GRAVÉ dans le dump (VERSION_ETAT 0x03) et vérifié
    /// ici : un état qui descend d'une autre genèse que celle demandée est REFUSÉ,
    /// avec les deux identifiants dans le message. C'était la dernière divergence
    /// silencieuse connue du démarrage — un répertoire peuplé par une autre chaîne
    /// donnait un nœud d'apparence saine qui refusait tout.
    pub fn charger_ou_amorcer_etat(
        &self,
        genese: &Bloc,
    ) -> Result<ProvedLedgerState, PersistanceError> {
        let chemin = self.chemin(FICHIER_ETAT);
        if !chemin.exists() {
            return ProvedLedgerState::depuis_genese(genese)
                .map_err(|e| PersistanceError::GeneseRefusee(e.to_string()));
        }
        let etat = ProvedLedgerState::load(&chemin)
            .map_err(|e| PersistanceError::EtatInvalide(e.to_string()))?;
        Self::verifier_genese(&etat, genese)?;
        Ok(etat)
    }

    /// Refuse un état qui ne descend pas de `genese`. AVANT toute autre confrontation
    /// (historique compris) : comparer une archive à un état de la mauvaise chaîne
    /// produirait un « désaccord » trompeur là où la cause est le répertoire.
    fn verifier_genese(
        etat: &ProvedLedgerState,
        genese: &Bloc,
    ) -> Result<(), PersistanceError> {
        let demandee = genese.id();
        let trouvee = etat.genese_id();
        if trouvee != demandee {
            return Err(PersistanceError::GeneseDifferente {
                demandee: hex::encode(&demandee[..8]),
                trouvee: hex::encode(&trouvee[..8]),
            });
        }
        Ok(())
    }

    /// Charge l'état en ARCHIVANT l'historique des sorties, ou l'amorce sur `genese`.
    ///
    /// Trois cas, et aucun n'est silencieux :
    ///
    /// - **répertoire neuf** : l'état est amorcé archivant, la genèse devient la
    ///   première tranche de l'historique ;
    /// - **répertoire peuplé, archive présente et concordante** : elle est adoptée ;
    /// - **archive absente ou désaccordée** : erreur. L'appelant journalise et tourne
    ///   en mode DÉGRADÉ (sans archive). On ne fabrique JAMAIS une archive partielle à
    ///   partir de l'état : elle démarrerait à la hauteur courante, servirait des index
    ///   décalés de tout le préfixe manquant, et rien ne le dirait à un wallet.
    ///
    /// Un état à la hauteur 0 sans fichier d'historique est le seul cas rattrapable :
    /// l'historique de la genèse se reconstruit depuis la genèse elle-même.
    pub fn charger_ou_amorcer_archive(
        &self,
        genese: &Bloc,
    ) -> Result<ProvedLedgerState, PersistanceError> {
        let chemin_etat = self.chemin(FICHIER_ETAT);
        if !chemin_etat.exists() {
            return ProvedLedgerState::depuis_genese_archivant(genese)
                .map_err(|e| PersistanceError::GeneseRefusee(e.to_string()));
        }
        let mut etat = ProvedLedgerState::load(&chemin_etat)
            .map_err(|e| PersistanceError::EtatInvalide(e.to_string()))?;
        Self::verifier_genese(&etat, genese)?;

        let chemin_hist = self.chemin(FICHIER_HISTORIQUE);
        if !chemin_hist.exists() {
            if etat.hauteur() == 0 {
                // Rien n'a encore été scellé : l'historique de la genèse se
                // reconstruit exactement, sans rien inventer.
                let neuf = ProvedLedgerState::depuis_genese_archivant(genese)
                    .map_err(|e| PersistanceError::GeneseRefusee(e.to_string()))?;
                let hist = neuf
                    .historique()
                    .expect("amorçage archivant")
                    .to_bytes();
                let hist = HistoriqueSorties::from_bytes(&hist)
                    .map_err(|e| PersistanceError::HistoriqueInvalide(e.to_string()))?;
                etat.adopter_historique(hist)
                    .map_err(|e| PersistanceError::HistoriqueDesaccorde(e.to_string()))?;
                return Ok(etat);
            }
            return Err(PersistanceError::HistoriqueAbsent {
                hauteur: etat.hauteur(),
            });
        }

        let (hist, reprise) = HistoriqueSorties::load_fichier(&chemin_hist)
            .map_err(|e| PersistanceError::HistoriqueInvalide(e.to_string()))?;

        match reprise {
            // Dump intégral hérité : réécrit UNE FOIS au format journal (atomique,
            // tmp + rename — le contenu est identique, seul le format change ; rien
            // n'est perdu, et les sauvegardes suivantes deviennent des ajouts).
            Reprise::AncienFormat => {
                self.tranches_persistees
                    .set(hist.save_journal(&chemin_hist, 0)?);
            }
            Reprise::Journal {
                octets_valides,
                queue_partielle,
            } => {
                if queue_partielle {
                    // Un crash a interrompu un ajout : le fichier se termine par des
                    // octets qui n'ont JAMAIS formé un enregistrement. L'ordre
                    // historique-avant-état garantit qu'aucun état persisté ne les
                    // couvre — les retirer n'ampute donc aucun bloc que quiconque
                    // possédait. Ce n'est PAS la troncature « réparatrice » que le
                    // dépôt interdit : celle-là retire des enregistrements COMPLETS.
                    // Tronquer est même OBLIGATOIRE : ajouter après des octets morts
                    // rendrait tout le fichier illisible au chargement suivant.
                    let f = fs::OpenOptions::new().write(true).open(&chemin_hist)?;
                    f.set_len(octets_valides)?;
                    f.sync_all()?;
                }
                self.tranches_persistees.set(hist.nombre_de_tranches());
            }
        }

        etat.adopter_historique(hist)
            .map_err(|e| PersistanceError::HistoriqueDesaccorde(e.to_string()))?;
        Ok(etat)
    }

    /// Enregistre l'état (écriture atomique, cf. `ProvedLedgerState::save`), et
    /// l'historique AVANT lui si ce nœud archive.
    ///
    /// L'ordre est délibéré — voir la tête de module : un crash entre les deux doit
    /// laisser l'archive EN AVANCE (récupérable) plutôt qu'en retard (irrécupérable).
    pub fn enregistrer_etat(&self, etat: &ProvedLedgerState) -> Result<(), PersistanceError> {
        if let Some(h) = etat.historique() {
            // JOURNAL : seules les tranches nouvelles depuis la dernière sauvegarde
            // sont écrites. Le dump intégral réécrivait tout — des Gio par jour sous
            // charge, toutes les 30 s.
            let persistees = self
                .tranches_persistees
                .replace(h.save_journal(&self.chemin(FICHIER_HISTORIQUE), self.tranches_persistees.get())?);
            let _ = persistees;
        }
        etat.save(&self.chemin(FICHIER_ETAT))?;
        Ok(())
    }

    /// Écrit un fichier SECRET : permissions restreintes au propriétaire, écriture
    /// atomique (`.tmp` puis `rename`).
    ///
    /// Les permissions sont posées AVANT d'écrire le contenu — sinon la clé
    /// existerait brièvement en lecture pour tous, fenêtre suffisante pour un
    /// processus local qui l'attend.
    fn ecrire_secret(&self, chemin: &Path, octets: &[u8]) -> Result<(), PersistanceError> {
        let tmp = chemin.with_extension("tmp");

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // rw pour le propriétaire seulement, dès la création
                .open(&tmp)?;
            f.write_all(octets)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            // Sur les plateformes sans permissions POSIX, on écrit sans restriction
            // d'accès : le répertoire de données doit alors être protégé par
            // l'utilisateur. Documenté plutôt que silencieux.
            fs::write(&tmp, octets)?;
        }

        fs::rename(&tmp, chemin)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repertoire_temporaire(nom: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("obscura_test_{}_{}", nom, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    /// PREMIER DÉMARRAGE puis REDÉMARRAGE : l'identité doit être la MÊME.
    ///
    /// C'est toute la raison d'être de ce module — sans cela, les pairs ne
    /// reconnaissent pas le nœud d'un lancement à l'autre.
    #[test]
    fn identite_survit_au_redemarrage() {
        let dir = repertoire_temporaire("identite");
        let d = Donnees::ouvrir(&dir).unwrap();

        let (premiere, creee) = d.charger_ou_creer_identite().unwrap();
        assert!(creee, "premier démarrage : identité créée");

        let (rechargee, creee2) = d.charger_ou_creer_identite().unwrap();
        assert!(!creee2, "redémarrage : identité RECHARGÉE, pas recréée");
        assert_eq!(
            rechargee.public.to_bytes(),
            premiere.public.to_bytes(),
            "le nœud doit rester LE MÊME pair"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    fn digest(seed: u64) -> proved_hash::digest::Digest {
        proved_hash::digest::Digest(core::array::from_fn(|i| {
            proved_hash::felt::Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// L'état survit lui aussi : la monnaie de la genèse et les racines connues
    /// restent en place, sinon un redémarrage rouvrirait la porte aux double-dépenses
    /// déjà rejetées.
    #[test]
    fn etat_survit_au_redemarrage() {
        let dir = repertoire_temporaire("etat");
        let d = Donnees::ouvrir(&dir).unwrap();

        let genese =
            Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(&digest(1))]).unwrap();
        let etat = d.charger_ou_amorcer_etat(&genese).unwrap();
        let racine = etat.tree.root();
        let taille = etat.tree.len();
        assert_eq!(taille, 1, "la genèse a bien émis sa note");
        d.enregistrer_etat(&etat).unwrap();

        // Au redémarrage la genèse est passée à nouveau — mais c'est le FICHIER qui
        // fait foi : ré-amorcer effacerait la chaîne accumulée depuis.
        let recharge = d.charger_ou_amorcer_etat(&genese).unwrap();
        assert_eq!(recharge.tree.root(), racine, "même racine après redémarrage");
        assert_eq!(recharge.tree.len(), taille);
        assert_eq!(recharge.tete(), etat.tete(), "même tête de chaîne");
        assert!(
            recharge.anchor_connu(&racine),
            "la fenêtre de racines doit survivre : sinon les tx en vol seraient rejetées"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// DEUX GENÈSES DIFFÉRENTES ⇒ DEUX TÊTES DIFFÉRENTES, à hauteur égale.
    ///
    /// C'est ce qui rend une erreur d'amorçage détectable au lieu de silencieuse : un
    /// nœud parti de la mauvaise genèse refuse tout, et sa tête le dit. Deux
    /// opérateurs comparent une ligne (l'identifiant imprimé au démarrage) plutôt que
    /// de chercher pourquoi « rien ne se passe ».
    #[test]
    fn deux_geneses_deux_tetes() {
        let dir_a = repertoire_temporaire("genese_a");
        let dir_b = repertoire_temporaire("genese_b");
        let (a, b) = (
            Donnees::ouvrir(&dir_a).unwrap(),
            Donnees::ouvrir(&dir_b).unwrap(),
        );

        let g1 =
            Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(&digest(1))]).unwrap();
        let g2 =
            Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(&digest(2))]).unwrap();

        let ea = a.charger_ou_amorcer_etat(&g1).unwrap();
        let eb = b.charger_ou_amorcer_etat(&g2).unwrap();
        assert_eq!(ea.hauteur(), eb.hauteur(), "tous deux à la hauteur 0");
        assert_ne!(
            ea.tete(),
            eb.tete(),
            "des genèses différentes doivent produire des têtes différentes"
        );

        // Même genèse des deux côtés : accord parfait.
        let dir_c = repertoire_temporaire("genese_c");
        let ec = Donnees::ouvrir(&dir_c)
            .unwrap()
            .charger_ou_amorcer_etat(&g1)
            .unwrap();
        assert_eq!(ec.tete(), ea.tete());
        assert_eq!(ec.tree.root(), ea.tree.root());

        for d in [&dir_a, &dir_b, &dir_c] {
            let _ = fs::remove_dir_all(d);
        }
    }

    /// Un fichier de genèse ABSENT ou CORROMPU est signalé, jamais remplacé par la
    /// genèse vide : un repli silencieux donnerait un nœud d'apparence saine sur une
    /// chaîne qui n'est pas celle qu'on croyait rejoindre.
    #[test]
    fn genese_absente_ou_corrompue_signalee() {
        let dir = repertoire_temporaire("genese_fichier");
        fs::create_dir_all(&dir).unwrap();

        let absent = dir.join("introuvable.genese");
        assert!(matches!(
            charger_genese(&absent),
            Err(PersistanceError::Io(_))
        ));

        let corrompu = dir.join("corrompu.genese");
        fs::write(&corrompu, b"pas un bloc").unwrap();
        assert!(matches!(
            charger_genese(&corrompu),
            Err(PersistanceError::GeneseInvalide(_))
        ));

        // Aller-retour d'une vraie genèse par fichier : c'est l'artefact que deux
        // opérateurs s'échangent.
        let g =
            Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(&digest(9))]).unwrap();
        let chemin = dir.join("bonne.genese");
        fs::write(&chemin, g.to_bytes()).unwrap();
        let relue = charger_genese(&chemin).expect("genèse relue");
        assert_eq!(relue.id(), g.id(), "le fichier doit désigner LA MÊME chaîne");

        let _ = fs::remove_dir_all(&dir);
    }

    /// L'ARCHIVE SURVIT AU REDÉMARRAGE, dans son propre fichier.
    ///
    /// Sans cela, un nœud archiviste redémarré repartirait avec une archive vide (ou
    /// pire, une archive commençant à la hauteur courante) : il servirait des index
    /// décalés de tout le préfixe manquant, et un wallet obtiendrait des chemins de
    /// Merkle faux sans qu'aucune erreur ne le dise.
    #[test]
    fn archive_survit_au_redemarrage() {
        let dir = repertoire_temporaire("archive");
        let d = Donnees::ouvrir(&dir).unwrap();

        let genese = Bloc::genese_avec(vec![
            ledger::proved_wallet::emission_factice(&digest(1)),
            ledger::proved_wallet::emission_factice(&digest(2)),
        ])
        .unwrap();
        let mut etat = d.charger_ou_amorcer_archive(&genese).unwrap();
        assert_eq!(etat.historique().unwrap().len(), 2);
        let bloc = Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        etat.appliquer_bloc(&bloc).unwrap();
        d.enregistrer_etat(&etat).unwrap();

        let recharge = d.charger_ou_amorcer_archive(&genese).unwrap();
        let h = recharge.historique().expect("archive rechargée");
        assert_eq!(h.hauteur_max(), Some(1), "la hauteur servie survit");
        assert_eq!(h.len(), 2);
        assert_eq!(
            h.sorties_du_bloc(0).unwrap()[0].commitment.to_bytes(),
            digest(1).to_bytes(),
            "et l'ORDRE des feuilles avec elle"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// UN DÉSACCORD ARCHIVE/ÉTAT EST SIGNALÉ, ET RIEN N'EST RÉPARÉ.
    ///
    /// Le cas simulé est celui d'un crash entre les deux écritures : l'archive reste à
    /// la hauteur 0 alors que l'état est passé à 1. Tronquer ou compléter en silence
    /// serait le pire choix — les sorties d'un bloc ne se reconstruisent depuis aucun
    /// état (la frontier ne garde que le bord droit), et le bloc en trop a peut-être
    /// été relayé à tout le réseau. Le fichier doit donc être INTACT après l'échec.
    #[test]
    fn archive_desaccordee_est_signalee_et_le_fichier_reste_intact() {
        let dir = repertoire_temporaire("archive_desaccord");
        let d = Donnees::ouvrir(&dir).unwrap();

        let genese =
            Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(&digest(1))]).unwrap();
        let mut etat = d.charger_ou_amorcer_archive(&genese).unwrap();
        d.enregistrer_etat(&etat).unwrap();
        let archive_avant = fs::read(dir.join(FICHIER_HISTORIQUE)).unwrap();

        // L'état avance d'un bloc et est sauvegardé SEUL — exactement ce qu'un crash
        // entre les deux écritures produirait dans le mauvais sens.
        let bloc = Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        etat.appliquer_bloc(&bloc).unwrap();
        etat.save(&dir.join(FICHIER_ETAT)).unwrap();

        // `ProvedLedgerState` n'est pas `Debug` : on filtre le résultat sans `unwrap_err`.
        let rendu = d.charger_ou_amorcer_archive(&genese);
        assert!(
            matches!(rendu, Err(PersistanceError::HistoriqueDesaccorde(_))),
            "un écart doit être NOMMÉ, pas rattrapé"
        );
        assert_eq!(
            fs::read(dir.join(FICHIER_HISTORIQUE)).unwrap(),
            archive_avant,
            "l'échec ne doit ni tronquer ni réécrire l'archive"
        );

        // Et le nœud reste utilisable SANS archive : le rôle est optionnel.
        let sobre = d.charger_ou_amorcer_etat(&genese).unwrap();
        assert_eq!(sobre.hauteur(), 1);
        assert!(sobre.historique().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    /// Demander l'archivage sur un état DÉJÀ AVANCÉ et sans fichier d'historique
    /// échoue, au lieu de fabriquer une archive qui commencerait au milieu.
    ///
    /// Une archive partielle est le pire des deux mondes : elle a l'air de fonctionner,
    /// et tous les index qu'elle sert sont décalés du préfixe manquant.
    #[test]
    fn archivage_active_trop_tard_est_refuse() {
        let dir = repertoire_temporaire("archive_tardive");
        let d = Donnees::ouvrir(&dir).unwrap();

        let genese =
            Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(&digest(1))]).unwrap();
        let mut etat = d.charger_ou_amorcer_etat(&genese).unwrap(); // SANS archive
        let bloc = Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        etat.appliquer_bloc(&bloc).unwrap();
        d.enregistrer_etat(&etat).unwrap();
        assert!(
            !dir.join(FICHIER_HISTORIQUE).exists(),
            "un nœud sobre n'écrit pas d'archive"
        );

        assert!(matches!(
            d.charger_ou_amorcer_archive(&genese),
            Err(PersistanceError::HistoriqueAbsent { hauteur: 1 })
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    /// UN RÉPERTOIRE D'UNE AUTRE CHAÎNE EST REFUSÉ, avec les deux identifiants.
    ///
    /// C'était la dernière divergence silencieuse du démarrage : pointer `--donnees`
    /// vers un répertoire peuplé par une autre genèse donnait un nœud d'apparence
    /// saine qui refusait tous les blocs — indiscernable d'un nœud au repos.
    #[test]
    fn demarrer_sur_une_autre_genese_est_refuse() {
        let dir = repertoire_temporaire("genese_croisee");
        let d = Donnees::ouvrir(&dir).unwrap();

        let genese_a = Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(
            &digest(1),
        )])
        .unwrap();
        let genese_b = Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(
            &digest(2),
        )])
        .unwrap();
        assert_ne!(genese_a.id(), genese_b.id());

        // Amorçage et persistance sur la genèse A.
        let etat = d.charger_ou_amorcer_etat(&genese_a).unwrap();
        d.enregistrer_etat(&etat).unwrap();

        // Rechargement sur A : accepté. Sur B : REFUSÉ, et l'erreur nomme les deux.
        assert!(d.charger_ou_amorcer_etat(&genese_a).is_ok());
        match d.charger_ou_amorcer_etat(&genese_b) {
            Err(PersistanceError::GeneseDifferente { demandee, trouvee }) => {
                assert_eq!(demandee, hex::encode(&genese_b.id()[..8]));
                assert_eq!(trouvee, hex::encode(&genese_a.id()[..8]));
            }
            _ => panic!("une genèse étrangère doit être refusée nommément"),
        }
        // Même refus sur le chemin archivant.
        assert!(matches!(
            d.charger_ou_amorcer_archive(&genese_b),
            Err(PersistanceError::GeneseDifferente { .. })
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    /// L'archive persiste en JOURNAL : plusieurs cycles sauvegarde/rechargement
    /// n'écrivent que la queue et rechargent l'identique — y compris après migration
    /// depuis un dump intégral hérité.
    #[test]
    fn archive_persistee_en_journal_et_migre_lancien_format() {
        let dir = repertoire_temporaire("journal");
        let d = Donnees::ouvrir(&dir).unwrap();
        let genese = Bloc::genese_avec(vec![ledger::proved_wallet::emission_factice(
            &digest(7),
        )])
        .unwrap();

        // Amorçage archivant + première persistance (journal complet).
        let etat = d.charger_ou_amorcer_archive(&genese).unwrap();
        d.enregistrer_etat(&etat).unwrap();
        let chemin_hist = dir.join("historique.bin");
        let taille_1 = fs::metadata(&chemin_hist).unwrap().len();

        // Rechargement (fixe la comptabilité), re-sauvegarde SANS rien de neuf :
        // le fichier ne bouge pas d'un octet.
        let d2 = Donnees::ouvrir(&dir).unwrap();
        let etat = d2.charger_ou_amorcer_archive(&genese).unwrap();
        d2.enregistrer_etat(&etat).unwrap();
        assert_eq!(
            fs::metadata(&chemin_hist).unwrap().len(),
            taille_1,
            "sans tranche nouvelle, une sauvegarde n'écrit RIEN"
        );

        // Migration : réécrit le fichier au FORMAT HÉRITÉ (dump 0x01), puis
        // recharge — le contenu doit être adopté à l'identique et re-persisté en
        // journal, sans erreur.
        etat.historique().unwrap().save(&chemin_hist).unwrap();
        let d3 = Donnees::ouvrir(&dir).unwrap();
        let etat3 = d3.charger_ou_amorcer_archive(&genese).unwrap();
        assert_eq!(
            etat3.historique().unwrap().to_bytes(),
            etat.historique().unwrap().to_bytes(),
            "la migration ne change pas un octet du CONTENU"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Un fichier d'identité corrompu est signalé, PAS silencieusement remplacé :
    /// régénérer une identité en douce ferait perdre le nœud à ses pairs sans
    /// que l'opérateur comprenne pourquoi.
    #[test]
    fn identite_corrompue_signalee_pas_ecrasee() {
        let dir = repertoire_temporaire("corrompue");
        let d = Donnees::ouvrir(&dir).unwrap();
        d.charger_ou_creer_identite().unwrap();

        fs::write(dir.join(FICHIER_IDENTITE), b"pas une cle").unwrap();
        assert!(
            matches!(
                d.charger_ou_creer_identite(),
                Err(PersistanceError::IdentiteInvalide)
            ),
            "une identité corrompue doit être signalée, pas remplacée en silence"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Sur Unix, le fichier d'identité n'est lisible que par son propriétaire.
    #[cfg(unix)]
    #[test]
    fn fichier_identite_permissions_restreintes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = repertoire_temporaire("perms");
        let d = Donnees::ouvrir(&dir).unwrap();
        d.charger_ou_creer_identite().unwrap();

        let meta = fs::metadata(dir.join(FICHIER_IDENTITE)).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "le matériel de clé ne doit être lisible que par son propriétaire");

        let _ = fs::remove_dir_all(&dir);
    }
}
