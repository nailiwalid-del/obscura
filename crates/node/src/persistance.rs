//! Persistance d'un nœud entre deux lancements.
//!
//! Un nœud qui repart de zéro à chaque démarrage n'en est pas un : il perd son
//! ÉTAT (donc doit tout resynchroniser) et son IDENTITÉ (donc ses pairs ne le
//! reconnaissent pas, et la réputation accumulée est effacée). C'est aussi une
//! aubaine pour un nœud malveillant, qui se blanchirait en redémarrant.
//!
//! Deux fichiers dans un répertoire de données :
//!
//! | fichier | contenu | sensibilité |
//! |---|---|---|
//! | `identite.cle` | paire de signature hybride | **SECRET** |
//! | `etat.bin` | frontier + nullifiers + racines récentes | public |
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
use ledger::proved_state::ProvedLedgerState;
use std::fs;
use std::path::{Path, PathBuf};

const FICHIER_IDENTITE: &str = "identite.cle";
const FICHIER_ETAT: &str = "etat.bin";

#[derive(Debug, thiserror::Error)]
pub enum PersistanceError {
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("fichier d'identité illisible ou corrompu")]
    IdentiteInvalide,
    #[error("fichier d'état illisible ou corrompu : {0}")]
    EtatInvalide(String),
}

/// Répertoire de données d'un nœud.
pub struct Donnees {
    racine: PathBuf,
}

impl Donnees {
    /// Ouvre (et crée au besoin) le répertoire de données.
    pub fn ouvrir(racine: impl AsRef<Path>) -> Result<Self, PersistanceError> {
        let racine = racine.as_ref().to_path_buf();
        fs::create_dir_all(&racine)?;
        Ok(Donnees { racine })
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

    /// Charge l'état, ou en crée un neuf (profondeur consensus) s'il n'existe pas.
    pub fn charger_ou_creer_etat(&self) -> Result<ProvedLedgerState, PersistanceError> {
        let chemin = self.chemin(FICHIER_ETAT);
        if !chemin.exists() {
            return Ok(ProvedLedgerState::new());
        }
        ProvedLedgerState::load(&chemin).map_err(|e| PersistanceError::EtatInvalide(e.to_string()))
    }

    /// Enregistre l'état (écriture atomique, cf. `ProvedLedgerState::save`).
    pub fn enregistrer_etat(&self, etat: &ProvedLedgerState) -> Result<(), PersistanceError> {
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

    /// L'état survit lui aussi : les nullifiers déjà dépensés restent connus, sinon
    /// un redémarrage rouvrirait la porte aux double-dépenses déjà rejetées.
    #[test]
    fn etat_survit_au_redemarrage() {
        use proved_hash::digest::Digest;
        use proved_hash::felt::Felt;

        let dir = repertoire_temporaire("etat");
        let d = Donnees::ouvrir(&dir).unwrap();

        let cm = Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(1 + i as u64).unwrap()
        }));
        let mut etat = d.charger_ou_creer_etat().unwrap();
        etat.mint(&cm).unwrap();
        let racine = etat.tree.root();
        let taille = etat.tree.len();
        d.enregistrer_etat(&etat).unwrap();

        let recharge = d.charger_ou_creer_etat().unwrap();
        assert_eq!(recharge.tree.root(), racine, "même racine après redémarrage");
        assert_eq!(recharge.tree.len(), taille);
        assert!(
            recharge.anchor_connu(&racine),
            "la fenêtre de racines doit survivre : sinon les tx en vol seraient rejetées"
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
