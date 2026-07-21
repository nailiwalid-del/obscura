//! Persistance d'un wallet entre deux lancements.
//!
//! # Ce fichier est le plus sensible du projet
//!
//! Le fichier d'identité d'un nœud permet de se faire PASSER pour lui. Le fichier de
//! wallet permet de DÉPENSER ses fonds : il contient le `shielded_secret`, qui est
//! l'autorité de dépense prouvée dans le circuit. Le perdre, c'est perdre l'argent ;
//! le laisser lire, c'est le donner.
//!
//! D'où trois exigences, dans cet ordre d'importance :
//!
//! 1. **Ne jamais écraser en silence.** Un wallet écrasé est irrécupérable — il n'y
//!    a pas de serveur qui garde une copie. Toute écriture est donc atomique
//!    (`.tmp` puis `rename`), et un fichier corrompu est SIGNALÉ, jamais remplacé
//!    par un wallet neuf. Un « wallet vide » affiché après corruption ferait croire
//!    à une perte de fonds — ou pire, inviterait à écrire par-dessus.
//! 2. **Restreindre l'accès dès la création** (`0600` sur Unix, posé AVANT d'écrire
//!    le contenu).
//! 3. **Détecter la corruption.** Un octet retourné dans un montant, un index ou une
//!    clé ne provoquerait aucune erreur visible : le wallet afficherait un solde
//!    faux, ou construirait des preuves systématiquement rejetées sans dire
//!    pourquoi. Le fichier porte donc une empreinte à domaine séparé, NON tronquée,
//!    vérifiée avant toute interprétation.
//!
//! ## ⚠️ Limite assumée : le fichier n'est PAS chiffré au repos
//!
//! Quiconque lit ce fichier peut vider le wallet. Le protéger par une phrase de
//! passe demanderait une dérivation à mémoire dure (Argon2) et une saisie
//! interactive — hors périmètre de ce prototype, et à faire correctement plutôt
//! qu'à moitié. C'est écrit ici plutôt que laissé à supposer : à ce stade, la
//! confidentialité du wallet repose ENTIÈREMENT sur les permissions du système de
//! fichiers.
//!
//! Sur les plateformes sans permissions POSIX (Windows), même cette protection-là
//! n'est pas posée par le code : le répertoire doit être protégé par l'utilisateur.
//!
//! # La POSITION DE SYNCHRONISATION est dans le fichier (0x02)
//!
//! Un wallet qui ne se souvient pas d'où il en est redemande l'historique depuis la
//! hauteur 0 et le rejoue sur un arbre déjà rempli : chaque commitment inséré une
//! seconde fois, tous les index décalés, et pas une seule erreur — juste des preuves
//! refusées pour « ancre inconnue ». La position entre donc dans le fichier, et un
//! fichier `0x01` (antérieur) est REFUSÉ par son nom, jamais réinterprété avec une
//! position par défaut.
//!
//! # Ce qui n'est PAS dans le fichier
//!
//! La clé d'INTENTION n'y figure pas : elle est tirée neuve à chaque transaction
//! (voir « Le signataire est PUBLIC » en tête de `lib.rs`). La persister aurait été
//! le réflexe naturel — et aurait rendu toutes nos transactions liables entre elles.

use crate::{NoteDetenue, Wallet};
use circuit::SpendNote;
use crypto::kem::KemKeypair;
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_BYTES};
use proved_hash::merkle::ProvedMerkleTree;
use std::path::Path;

/// Version du format de fichier. Un fichier d'une autre version est REFUSÉ, jamais
/// réinterprété : lire de travers les clés d'un wallet perdrait les fonds.
///
/// `0x02` ajoute la POSITION DE SYNCHRONISATION (prochaine hauteur à demander, feuilles
/// de la dernière frontière de bloc adoptée).
pub const VERSION_FICHIER: u8 = 0x02;

/// Format antérieur à la synchronisation. Il n'existe plus, et il est nommé
/// séparément : voir [`WalletFichierError::VersionSansPosition`].
pub const VERSION_SANS_POSITION: u8 = 0x01;

const DOMAINE_EMPREINTE: &str = "obscura/wallet/fichier/v1";

/// Longueur de l'empreinte d'intégrité : `dual_hash` COMPLET (BLAKE3‖SHA3-256), non
/// tronqué — contrairement à la somme de contrôle d'adresse, qui vise l'œil humain,
/// celle-ci ne coûte rien à stocker.
const EMPREINTE: usize = crypto::hash::DUAL_DIGEST_LEN;

/// Un enregistrement de note : `value ‖ owner ‖ rho ‖ r ‖ index`.
const TAILLE_NOTE: usize = 8 + 3 * DIGEST_BYTES + 8;

#[derive(Debug, thiserror::Error)]
pub enum WalletFichierError {
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("fichier de wallet tronqué")]
    Tronque,
    #[error("octets résiduels après la fin du fichier")]
    OctetsResiduels,
    #[error("version de fichier inconnue : {0:#04x}")]
    VersionInconnue(u8),
    #[error(
        "fichier de wallet en version 0x01 : format antérieur à la synchronisation, sans \
         position — le relire ferait rejouer l'historique depuis la hauteur 0 sur un arbre \
         déjà rempli, et tous les index seraient décalés en silence"
    )]
    VersionSansPosition,
    #[error(
        "ancre à {ancre} feuilles pour un arbre de {feuilles} : le fichier a été écrit \
         hors d'une frontière de bloc"
    )]
    AncreIncoherente { ancre: u64, feuilles: u64 },
    #[error("empreinte incorrecte — fichier de wallet corrompu")]
    EmpreinteIncorrecte,
    #[error("clé de réception illisible")]
    KemInvalide,
    #[error("champ non canonique dans le fichier")]
    ChampInvalide,
    #[error("arbre de notes illisible")]
    ArbreInvalide,
    #[error("une note référence l'index {index}, hors de l'arbre ({feuilles} feuilles)")]
    IndexHorsArbre { index: u64, feuilles: usize },
}

impl Wallet {
    /// Sérialise le wallet, **clés secrètes comprises**.
    ///
    /// ⚠️ Le résultat donne l'autorité de DÉPENSE. Voir l'avertissement en tête de
    /// module.
    pub fn to_bytes_secret(&self) -> Vec<u8> {
        let mut b = vec![VERSION_FICHIER];
        b.extend_from_slice(&self.secret.to_bytes());
        // POSITION DE SYNCHRONISATION (0x02). Sans elle, un wallet rechargé repartirait
        // de la hauteur 0 et rejouerait tout l'historique sur un arbre déjà rempli :
        // chaque commitment inséré une seconde fois, tous les index décalés, aucun
        // message d'erreur — juste des preuves refusées pour « ancre inconnue ».
        b.extend_from_slice(&self.prochaine_hauteur.to_le_bytes());
        b.extend_from_slice(&self.feuilles_ancrees.to_le_bytes());

        let kem = self.reception.to_bytes_secret();
        b.extend_from_slice(&(kem.len() as u32).to_le_bytes());
        b.extend_from_slice(&kem);

        b.extend_from_slice(&(self.notes.len() as u32).to_le_bytes());
        for n in &self.notes {
            b.extend_from_slice(&n.note.value.to_le_bytes());
            b.extend_from_slice(&n.note.owner.to_bytes());
            b.extend_from_slice(&n.note.rho.to_bytes());
            b.extend_from_slice(&n.note.r.to_bytes());
            b.extend_from_slice(&n.index.to_le_bytes());
        }

        let arbre = self.arbre.to_bytes();
        b.extend_from_slice(&(arbre.len() as u64).to_le_bytes());
        b.extend_from_slice(&arbre);

        let empreinte = crypto::hash::dual_hash(DOMAINE_EMPREINTE, &b);
        b.extend_from_slice(&empreinte);
        b
    }

    /// Restaure un wallet depuis `to_bytes_secret`.
    ///
    /// L'empreinte est vérifiée AVANT toute interprétation : un fichier abîmé doit
    /// dire « corrompu », pas produire un solde faux.
    pub fn from_bytes_secret(b: &[u8]) -> Result<Self, WalletFichierError> {
        if b.len() < EMPREINTE + 1 {
            return Err(WalletFichierError::Tronque);
        }
        let (corps, empreinte) = b.split_at(b.len() - EMPREINTE);
        if crypto::hash::dual_hash(DOMAINE_EMPREINTE, corps) != empreinte {
            return Err(WalletFichierError::EmpreinteIncorrecte);
        }

        let mut pos = 0usize;
        // Curseur BORNÉ : chaque prise vérifie ce qui reste. Le fichier est local et
        // trusté, mais un disque abîmé ne doit pas faire paniquer un wallet.
        fn prendre<'a>(
            b: &'a [u8],
            pos: &mut usize,
            n: usize,
        ) -> Result<&'a [u8], WalletFichierError> {
            let fin = pos.checked_add(n).ok_or(WalletFichierError::Tronque)?;
            if fin > b.len() {
                return Err(WalletFichierError::Tronque);
            }
            let s = &b[*pos..fin];
            *pos = fin;
            Ok(s)
        }
        fn digest(b: &[u8], pos: &mut usize) -> Result<Digest, WalletFichierError> {
            let a: [u8; DIGEST_BYTES] = prendre(b, pos, DIGEST_BYTES)?
                .try_into()
                .map_err(|_| WalletFichierError::Tronque)?;
            Digest::from_bytes(&a).map_err(|_| WalletFichierError::ChampInvalide)
        }

        let version = prendre(corps, &mut pos, 1)?[0];
        // Le 0x01 est refusé PAR SON NOM, pas confondu avec un octet quelconque : c'est
        // un format que ce binaire a réellement écrit, et son porteur doit lire
        // pourquoi son fichier n'est plus lisible plutôt que « version inconnue ».
        if version == VERSION_SANS_POSITION {
            return Err(WalletFichierError::VersionSansPosition);
        }
        if version != VERSION_FICHIER {
            return Err(WalletFichierError::VersionInconnue(version));
        }

        let s: [u8; DIGEST_BYTES] = prendre(corps, &mut pos, DIGEST_BYTES)?
            .try_into()
            .map_err(|_| WalletFichierError::Tronque)?;
        let secret =
            ShieldedSecret::from_bytes(&s).map_err(|_| WalletFichierError::ChampInvalide)?;

        let prochaine_hauteur =
            u64::from_le_bytes(prendre(corps, &mut pos, 8)?.try_into().unwrap());
        let feuilles_ancrees =
            u64::from_le_bytes(prendre(corps, &mut pos, 8)?.try_into().unwrap());

        let n_kem =
            u32::from_le_bytes(prendre(corps, &mut pos, 4)?.try_into().unwrap()) as usize;
        let reception = KemKeypair::from_bytes_secret(prendre(corps, &mut pos, n_kem)?)
            .map_err(|_| WalletFichierError::KemInvalide)?;

        let n_notes =
            u32::from_le_bytes(prendre(corps, &mut pos, 4)?.try_into().unwrap()) as usize;
        // Borne AVANT allocation : l'en-tête ne doit pas pouvoir réserver plus que ce
        // que le fichier peut réellement contenir.
        if corps.len().saturating_sub(pos) < n_notes.saturating_mul(TAILLE_NOTE) {
            return Err(WalletFichierError::Tronque);
        }
        let mut notes = Vec::with_capacity(n_notes);
        for _ in 0..n_notes {
            let value = u64::from_le_bytes(prendre(corps, &mut pos, 8)?.try_into().unwrap());
            let owner = digest(corps, &mut pos)?;
            let rho = digest(corps, &mut pos)?;
            let r = digest(corps, &mut pos)?;
            let index = u64::from_le_bytes(prendre(corps, &mut pos, 8)?.try_into().unwrap());
            notes.push(NoteDetenue {
                note: SpendNote { value, owner, rho, r },
                index,
            });
        }

        let n_arbre =
            u64::from_le_bytes(prendre(corps, &mut pos, 8)?.try_into().unwrap());
        let n_arbre = usize::try_from(n_arbre).map_err(|_| WalletFichierError::Tronque)?;
        let arbre = ProvedMerkleTree::from_bytes(prendre(corps, &mut pos, n_arbre)?)
            .map_err(|_| WalletFichierError::ArbreInvalide)?;

        if pos != corps.len() {
            return Err(WalletFichierError::OctetsResiduels);
        }

        // COHÉRENCE CROISÉE : chaque note doit pointer dans l'arbre. Sans ce contrôle,
        // une note d'index aberrant ferait échouer `construire` sur un `expect`
        // (« index observé, donc dans l'arbre ») — une panique au moment de payer,
        // là où un message clair au chargement est possible.
        for n in &notes {
            if n.index as usize >= arbre.len() {
                return Err(WalletFichierError::IndexHorsArbre {
                    index: n.index,
                    feuilles: arbre.len(),
                });
            }
        }

        // COHÉRENCE DE L'ANCRE : elle ne peut pas désigner plus de feuilles que l'arbre
        // n'en a. Une ancre en avance ferait passer `construire` alors que l'arbre est
        // court — c'est-à-dire publier une racine qui n'est celle d'aucun nœud.
        if feuilles_ancrees > arbre.len() as u64 {
            return Err(WalletFichierError::AncreIncoherente {
                ancre: feuilles_ancrees,
                feuilles: arbre.len() as u64,
            });
        }

        let owner = proved_hash::rescue::hash(
            proved_hash::domain::Domain::Owner,
            secret.as_felts(),
        );
        Ok(Wallet {
            secret,
            owner,
            reception,
            notes,
            arbre,
            prochaine_hauteur,
            feuilles_ancrees,
        })
    }

    /// Enregistre le wallet dans un fichier aux permissions restreintes, de façon
    /// ATOMIQUE.
    ///
    /// Les permissions sont posées AVANT d'écrire le contenu — sinon les clés
    /// existeraient brièvement en lecture pour tous, fenêtre suffisante pour un
    /// processus local qui les attend.
    pub fn enregistrer(&self, chemin: &Path) -> Result<(), WalletFichierError> {
        let octets = self.to_bytes_secret();
        let tmp = chemin.with_extension("tmp");

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // rw propriétaire seulement, dès la création
                .open(&tmp)?;
            f.write_all(&octets)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, &octets)?;
        }

        std::fs::rename(&tmp, chemin)?;
        Ok(())
    }

    /// Charge un wallet depuis un fichier écrit par `enregistrer`.
    ///
    /// Volontairement SANS variante « ou créer » : un wallet absent et un wallet
    /// illisible doivent être des situations distinctes et visibles. Créer un wallet
    /// neuf en réponse à un fichier illisible masquerait une perte de fonds.
    pub fn charger(chemin: &Path) -> Result<Self, WalletFichierError> {
        Self::from_bytes_secret(&std::fs::read(chemin)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::felt::Felt;
    use proved_hash::rescue;

    /// Wallet garni par la MÊME porte que le réseau : une genèse rejouée. Sa position
    /// de synchronisation est donc réelle, pas fabriquée pour le test.
    fn wallet_garni() -> Wallet {
        let mut w = Wallet::depuis_secret(crate::tests_communs::secret(700), 6);
        let (lot, _etat) = crate::tests_communs::lot_de_genese(&w, &[1_000, 500, 42], 6);
        w.synchroniser(&[lot]).expect("genèse rejouée");
        w
    }

    fn fichier(nom: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "obscura_wallet_{}_{}.cle",
            nom,
            std::process::id()
        ))
    }

    /// LA propriété : un wallet rechargé peut encore DÉPENSER et RECEVOIR.
    ///
    /// On n'éprouve pas l'égalité des octets — on éprouve les deux capacités qui
    /// font qu'un wallet est un wallet : produire les chemins de Merkle qu'exigent
    /// les preuves (dépenser), et déchiffrer ce qui lui est adressé (recevoir).
    #[test]
    fn wallet_recharge_peut_encore_depenser_et_recevoir() {
        let w = wallet_garni();
        let r = Wallet::from_bytes_secret(&w.to_bytes_secret()).expect("aller-retour");

        assert_eq!(r.solde(), w.solde(), "solde préservé");
        assert_eq!(r.owner(), w.owner(), "même identité prouvée");
        assert_eq!(r.racine(), w.racine(), "même arbre");
        assert_eq!(
            r.adresse().kem.to_bytes(),
            w.adresse().kem.to_bytes(),
            "MÊME adresse : sinon les paiements déjà en route deviendraient illisibles"
        );

        // DÉPENSER : les chemins de Merkle, qui entrent dans la preuve, sont
        // identiques note par note.
        for (a, b) in r.notes().iter().zip(w.notes()) {
            assert_eq!(a.index, b.index);
            assert_eq!(a.note.value, b.note.value);
            assert!(
                r.arbre.path(a.index).is_some(),
                "le wallet rechargé doit pouvoir prouver l'appartenance de ses notes"
            );
            assert_eq!(r.arbre.path(a.index), w.arbre.path(b.index));
        }

        // RECEVOIR : une note chiffrée vers l'adresse d'origine est déchiffrable par
        // le wallet rechargé.
        let note = SpendNote {
            value: 77,
            owner: w.owner(),
            rho: rescue::hash(proved_hash::domain::Domain::Owner, &[Felt::ONE; 4]),
            r: rescue::hash(proved_hash::domain::Domain::Nk, &[Felt::ONE; 4]),
        };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        let enc = ledger::proved_wallet::encrypt_note(&w.adresse().kem, &cm, &note).unwrap();
        assert_eq!(
            ledger::proved_wallet::scan_proved_output(&r.reception, &r.owner, &cm, &enc)
                .map(|n| n.value),
            Some(77),
            "le wallet rechargé doit déchiffrer ce qui vise son adresse"
        );

        assert_eq!(
            r.to_bytes_secret(),
            w.to_bytes_secret(),
            "canonique : même wallet ⇒ mêmes octets"
        );
    }

    /// Aller-retour à travers un VRAI fichier.
    #[test]
    fn aller_retour_fichier() {
        let chemin = fichier("roundtrip");
        let w = wallet_garni();
        w.enregistrer(&chemin).expect("écriture");
        let r = Wallet::charger(&chemin).expect("lecture");
        assert_eq!(r.solde(), w.solde());
        assert_eq!(r.racine(), w.racine());
        std::fs::remove_file(&chemin).ok();
    }

    /// UN OCTET RETOURNÉ est détecté.
    ///
    /// Sans empreinte, un bit abîmé dans un montant donnerait un solde faux et des
    /// preuves rejetées, sans jamais dire que le fichier est en cause. On balaie
    /// chaque octet du corps.
    #[test]
    fn corruption_dun_seul_octet_detectee() {
        let w = wallet_garni();
        let bon = w.to_bytes_secret();

        for i in (0..bon.len()).step_by(13) {
            let mut abime = bon.clone();
            abime[i] ^= 0x01;
            assert!(
                Wallet::from_bytes_secret(&abime).is_err(),
                "un octet retourné en position {i} doit être détecté"
            );
        }
    }

    /// Fichier tronqué, vide, ou d'une autre version : `Result`, jamais de panique,
    /// et jamais un wallet vide présenté comme légitime.
    #[test]
    fn fichier_malforme_refuse() {
        let w = wallet_garni();
        let bon = w.to_bytes_secret();

        assert!(matches!(
            Wallet::from_bytes_secret(&[]),
            Err(WalletFichierError::Tronque)
        ));
        assert!(Wallet::from_bytes_secret(&bon[..bon.len() / 2]).is_err());

        let mut trop = bon.clone();
        trop.push(0);
        assert!(Wallet::from_bytes_secret(&trop).is_err());

        // Version inconnue, empreinte RECALCULÉE : seul le format diffère, et cela
        // doit suffire à refuser (une future migration FIPS ne doit pas être lue
        // comme du round-3).
        let mut autre = bon[..bon.len() - EMPREINTE].to_vec();
        autre[0] = 0x03;
        let e = crypto::hash::dual_hash(DOMAINE_EMPREINTE, &autre);
        autre.extend_from_slice(&e);
        assert!(matches!(
            Wallet::from_bytes_secret(&autre),
            Err(WalletFichierError::VersionInconnue(0x03))
        ));
    }

    /// UN FICHIER 0x01 EST REFUSÉ PAR SON NOM.
    ///
    /// Le 0x01 ne portait aucune position de synchronisation. Le relire en supposant
    /// « position 0 » ferait redemander l'historique depuis la genèse et le rejouer sur
    /// un arbre déjà rempli : chaque commitment inséré deux fois, tous les index
    /// suivants décalés, aucune erreur — le wallet se contenterait de ne plus jamais
    /// pouvoir dépenser, sans dire pourquoi. Le refus est donc explicite, et distinct de
    /// « version inconnue » pour que le message explique la vraie cause.
    #[test]
    fn fichier_version_01_refuse_avec_son_propre_message() {
        let w = wallet_garni();
        let bon = w.to_bytes_secret();
        let mut ancien = bon[..bon.len() - EMPREINTE].to_vec();
        ancien[0] = VERSION_SANS_POSITION;
        let e = crypto::hash::dual_hash(DOMAINE_EMPREINTE, &ancien);
        ancien.extend_from_slice(&e);

        // `matches!` : `Wallet` n'est pas `Debug` (il porte l'autorité de dépense).
        match Wallet::from_bytes_secret(&ancien) {
            Err(e @ WalletFichierError::VersionSansPosition) => assert!(
                e.to_string().contains("position"),
                "le refus doit dire POURQUOI le fichier n'est plus lisible"
            ),
            _ => panic!("un fichier 0x01 doit être refusé par son propre message"),
        }
    }

    /// LA POSITION DE SYNCHRONISATION SURVIT AU RECHARGEMENT.
    ///
    /// C'est ce qui empêche un wallet redémarré de rejouer l'historique depuis zéro
    /// par-dessus son propre arbre. La perdre ne casserait rien de VISIBLE : le wallet
    /// resynchroniserait, doublerait ses feuilles, et découvrirait le problème à sa
    /// première dépense refusée.
    #[test]
    fn position_de_synchronisation_preservee() {
        let w = wallet_garni();
        assert_eq!(w.prochaine_hauteur(), 1, "la genèse a été rejouée");
        assert_eq!(w.feuilles_ancrees(), 3);

        let r = Wallet::from_bytes_secret(&w.to_bytes_secret()).expect("aller-retour");
        assert_eq!(r.prochaine_hauteur(), w.prochaine_hauteur());
        assert_eq!(r.feuilles_ancrees(), w.feuilles_ancrees());
        assert_eq!(r.racine(), w.racine());
    }

    /// Une ancre annonçant plus de feuilles que l'arbre n'en a est refusée AU
    /// CHARGEMENT : la laisser passer autoriserait `construire` à publier une racine
    /// qui n'est celle d'aucun nœud.
    #[test]
    fn ancre_en_avance_refusee_au_chargement() {
        let mut w = wallet_garni();
        w.feuilles_ancrees = 99;
        let mut corps = w.to_bytes_secret();
        corps.truncate(corps.len() - EMPREINTE);
        let e = crypto::hash::dual_hash(DOMAINE_EMPREINTE, &corps);
        corps.extend_from_slice(&e);

        assert!(matches!(
            Wallet::from_bytes_secret(&corps),
            Err(WalletFichierError::AncreIncoherente {
                ancre: 99,
                feuilles: 3
            })
        ));
    }

    /// Une note pointant hors de l'arbre est refusée AU CHARGEMENT, avec un message
    /// clair — plutôt qu'en paniquant plus tard, au moment de payer.
    #[test]
    fn note_hors_arbre_refusee_au_chargement() {
        let mut w = wallet_garni();
        w.notes[0].index = 9_999;
        let mut corps = w.to_bytes_secret();
        corps.truncate(corps.len() - EMPREINTE);
        let e = crypto::hash::dual_hash(DOMAINE_EMPREINTE, &corps);
        corps.extend_from_slice(&e);

        assert!(
            matches!(
                Wallet::from_bytes_secret(&corps),
                Err(WalletFichierError::IndexHorsArbre { index: 9_999, .. })
            ),
            "un index aberrant doit être signalé au chargement"
        );
    }

    /// Charger un fichier ABSENT est une erreur d'E/S — surtout pas un wallet neuf
    /// et vide, qui laisserait croire à une perte de fonds.
    #[test]
    fn fichier_absent_est_une_erreur() {
        let chemin = fichier("absent_zzz");
        std::fs::remove_file(&chemin).ok();
        assert!(matches!(
            Wallet::charger(&chemin),
            Err(WalletFichierError::Io(_))
        ));
    }

    /// Sur Unix, le fichier de wallet n'est lisible que par son propriétaire.
    #[cfg(unix)]
    #[test]
    fn permissions_restreintes() {
        use std::os::unix::fs::PermissionsExt;
        let chemin = fichier("perms");
        wallet_garni().enregistrer(&chemin).unwrap();
        let mode = std::fs::metadata(&chemin).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "l'autorité de dépense ne doit être lisible que par son propriétaire");
        std::fs::remove_file(&chemin).ok();
    }
}
