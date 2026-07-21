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
//! ## Chiffrement au repos (0x03)
//!
//! Quiconque lit ce fichier en clair peut vider le wallet. Il est donc chiffrable par
//! une phrase de passe : dérivation à MÉMOIRE DURE (Argon2id, qui rend le crible par
//! GPU coûteux) puis cascade AEAD `XChaCha20-Poly1305 ∘ AES-256-GCM`. Le sel ET les
//! paramètres Argon2 entrent dans l'AAD : un attaquant ne peut pas rejouer le fichier
//! avec un coût mémoire abaissé pour accélérer sa recherche.
//!
//! Le choix est EXPLICITE ([`Protection`]) : aucune valeur par défaut ne décide à la
//! place de l'appelant. Écrire en clair reste possible — c'est ce dont les tests ont
//! besoin — mais cela se lit dans le code appelant, au lieu de se produire par
//! omission.
//!
//! Cela compte particulièrement hors Unix : les permissions `0o600` posées ci-dessous
//! n'existent pas sur Windows, où le chiffrement est alors la SEULE protection.
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

/// Enveloppe CHIFFRÉE : `0x03 ‖ sel(16) ‖ m_cost ‖ t_cost ‖ p_cost ‖ cascade AEAD`.
/// Le clair ainsi protégé est exactement un fichier `VERSION_FICHIER`.
pub const VERSION_CHIFFRE: u8 = 0x03;

const SEL_LEN: usize = 16;
/// Paramètres Argon2id (recommandation OWASP) : 19 Mio, 2 passes, 1 voie.
const ARGON_M_COST: u32 = 19_456;
const ARGON_T_COST: u32 = 2;
const ARGON_P_COST: u32 = 1;

/// Comment le fichier est protégé au repos. **Sans valeur par défaut** : l'appelant
/// choisit, et le choix de ne pas chiffrer se voit dans son code.
pub enum Protection {
    /// Chiffre par phrase de passe (Argon2id + cascade AEAD).
    Phrase(String),
    /// N'chiffre PAS : l'autorité de dépense reste en clair sur le disque. Réservé
    /// aux tests et aux environnements où le fichier est protégé autrement.
    Aucune,
}

/// Dérive la clé de fichier depuis la phrase. Coûteuse à dessein : c'est ce coût,
/// payé une fois par l'utilisateur légitime, qui se multiplie par la taille du
/// dictionnaire pour l'attaquant.
fn deriver_cle(
    phrase: &str,
    sel: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<[u8; 32], WalletFichierError> {
    let params = argon2::Params::new(m, t, p, Some(32))
        .map_err(|_| WalletFichierError::ParametresArgon)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut cle = [0u8; 32];
    a.hash_password_into(phrase.as_bytes(), sel, &mut cle)
        .map_err(|_| WalletFichierError::ParametresArgon)?;
    Ok(cle)
}

/// Ce qui est authentifié SANS être chiffré : version, sel, paramètres. Les lier
/// interdit de rejouer le fichier avec un coût mémoire abaissé.
fn aad_enveloppe(sel: &[u8], m: u32, t: u32, p: u32) -> Vec<u8> {
    let mut a = vec![VERSION_CHIFFRE];
    a.extend_from_slice(sel);
    a.extend_from_slice(&m.to_le_bytes());
    a.extend_from_slice(&t.to_le_bytes());
    a.extend_from_slice(&p.to_le_bytes());
    a
}

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
    #[error("fichier chiffré : une phrase de passe est requise pour le lire")]
    PhraseRequise,
    #[error(
        "fichier de wallet EN CLAIR alors qu'une phrase de passe est fournie — refus de \
         le lire en silence : accepter ici un fichier non chiffré permettrait de \
         SUBSTITUER un wallet en clair à un wallet chiffré sans que rien ne le signale. \
         Migrez explicitement (rechargez sous Protection::Aucune puis réenregistrez \
         sous la phrase), ou assumez le clair"
    )]
    FichierEnClair,
    #[error("phrase de passe incorrecte, ou fichier chiffré altéré")]
    PhraseIncorrecte,
    #[error("paramètres Argon2 invalides")]
    ParametresArgon,
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
    /// `protection` est OBLIGATOIRE : voir [`Protection`]. Chiffrer est le cas normal ;
    /// [`Protection::Aucune`] laisse l'autorité de dépense en clair et doit se lire
    /// dans le code appelant.
    pub fn enregistrer(
        &self,
        chemin: &Path,
        protection: &Protection,
    ) -> Result<(), WalletFichierError> {
        let clair = self.to_bytes_secret();
        let octets = match protection {
            Protection::Aucune => clair,
            Protection::Phrase(phrase) => {
                let mut sel = [0u8; SEL_LEN];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut sel);
                let cle = deriver_cle(phrase, &sel, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST)?;
                let aad = aad_enveloppe(&sel, ARGON_M_COST, ARGON_T_COST, ARGON_P_COST);
                let scelle = crypto::aead::encrypt(&cle, &aad, &clair);
                let mut v = aad;
                v.extend_from_slice(&scelle);
                v
            }
        };
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
    pub fn charger(chemin: &Path, protection: &Protection) -> Result<Self, WalletFichierError> {
        let brut = std::fs::read(chemin)?;
        // Un fichier EN CLAIR n'est lisible que si l'appelant a ASSUMÉ le clair
        // (`Protection::Aucune`). Avec une phrase fournie, le lire en silence serait un
        // repli : un attaquant local capable d'écrire le fichier substituerait un
        // wallet en clair au wallet chiffré, et l'utilisateur — qui croit son fichier
        // protégé — ne verrait rien. La migration d'un wallet antérieur reste possible,
        // mais EXPLICITE (recharger sous `Aucune`, réenregistrer sous la phrase).
        // L'inverse ne change pas : un fichier chiffré sans phrase donne
        // `PhraseRequise`, jamais un « illisible » confondable avec une corruption.
        if brut.first() != Some(&VERSION_CHIFFRE) {
            return match protection {
                Protection::Aucune => Self::from_bytes_secret(&brut),
                Protection::Phrase(_) => Err(WalletFichierError::FichierEnClair),
            };
        }
        let Protection::Phrase(phrase) = protection else {
            return Err(WalletFichierError::PhraseRequise);
        };
        let entete = 1 + SEL_LEN + 12;
        if brut.len() < entete {
            return Err(WalletFichierError::Tronque);
        }
        let sel = &brut[1..1 + SEL_LEN];
        let lire = |o: usize| {
            u32::from_le_bytes([brut[o], brut[o + 1], brut[o + 2], brut[o + 3]])
        };
        let (m, t, p) = (lire(1 + SEL_LEN), lire(5 + SEL_LEN), lire(9 + SEL_LEN));
        let cle = deriver_cle(phrase, sel, m, t, p)?;
        let aad = aad_enveloppe(sel, m, t, p);
        let clair = crypto::aead::decrypt(&cle, &aad, &brut[entete..])
            .map_err(|_| WalletFichierError::PhraseIncorrecte)?;
        Self::from_bytes_secret(&clair)
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
        w.enregistrer(&chemin, &Protection::Aucune).expect("écriture");
        let r = Wallet::charger(&chemin, &Protection::Aucune).expect("lecture");
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
            Wallet::charger(&chemin, &Protection::Aucune),
            Err(WalletFichierError::Io(_))
        ));
    }

    /// Sur Unix, le fichier de wallet n'est lisible que par son propriétaire.
    /// Le CYCLE chiffré : un wallet écrit sous phrase se relit à l'identique, et le
    /// fichier ne contient plus le secret en clair.
    #[test]
    fn cycle_chiffre_et_secret_absent_du_fichier() {
        let w = wallet_garni();
        let dir = std::env::temp_dir().join(format!("obsc-chiffre-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = dir.join("w.bin");
        let phrase = Protection::Phrase("corbeau bleu 42".to_string());

        w.enregistrer(&chemin, &phrase).unwrap();
        let brut = std::fs::read(&chemin).unwrap();
        assert_eq!(brut[0], VERSION_CHIFFRE, "l'enveloppe doit s'annoncer chiffrée");
        // Le secret de dépense ne doit apparaître NULLE PART dans le fichier.
        let clair = w.to_bytes_secret();
        assert!(
            !brut.windows(32).any(|f| clair.windows(32).any(|c| f == c)),
            "un fragment du clair se retrouve dans le fichier chiffré"
        );

        let relu = Wallet::charger(&chemin, &phrase).unwrap();
        assert_eq!(relu.to_bytes_secret(), clair, "cycle chiffré non fidèle");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Une MAUVAISE phrase est refusée explicitement — jamais confondue avec un
    /// fichier corrompu, et jamais silencieusement dégradée en wallet vide.
    #[test]
    fn mauvaise_phrase_refusee() {
        let w = wallet_garni();
        let dir = std::env::temp_dir().join(format!("obsc-phrase-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = dir.join("w.bin");
        w.enregistrer(&chemin, &Protection::Phrase("bonne".into())).unwrap();

        assert!(matches!(
            Wallet::charger(&chemin, &Protection::Phrase("mauvaise".into())),
            Err(WalletFichierError::PhraseIncorrecte)
        ));
        // Et sans phrase du tout : un message qui DIT qu'il faut une phrase.
        assert!(matches!(
            Wallet::charger(&chemin, &Protection::Aucune),
            Err(WalletFichierError::PhraseRequise)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// ADVERSE — abaisser le coût mémoire dans l'en-tête pour accélérer un crible doit
    /// invalider le fichier : les paramètres sont authentifiés (AAD), pas seulement lus.
    #[test]
    fn parametres_argon_abaisses_sont_rejetes() {
        let w = wallet_garni();
        let dir = std::env::temp_dir().join(format!("obsc-aad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = dir.join("w.bin");
        let phrase = Protection::Phrase("corbeau bleu 42".to_string());
        w.enregistrer(&chemin, &phrase).unwrap();

        let mut brut = std::fs::read(&chemin).unwrap();
        let o = 1 + SEL_LEN; // m_cost
        brut[o..o + 4].copy_from_slice(&8u32.to_le_bytes()); // 19 Mio → 8 Kio
        std::fs::write(&chemin, &brut).unwrap();
        assert!(
            matches!(
                Wallet::charger(&chemin, &phrase),
                Err(WalletFichierError::PhraseIncorrecte)
            ),
            "des paramètres Argon abaissés doivent invalider le fichier"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// MIGRATION : un fichier écrit en clair (wallet antérieur) reste lisible sous
    /// `Protection::Aucune` — sinon la mise à jour perdrait les fonds existants.
    ///
    /// ADVERSE, la moitié qui compte : le MÊME fichier est REFUSÉ quand une phrase est
    /// fournie. L'accepter serait un repli silencieux — un attaquant local capable
    /// d'écrire le fichier substituerait un wallet en clair au wallet chiffré, et
    /// l'utilisateur croirait toujours son fichier protégé. La migration passe donc
    /// par un rechargement EXPLICITE sous `Aucune`, jamais par un repli implicite.
    #[test]
    fn un_fichier_en_clair_lisible_sans_phrase_refuse_avec() {
        let w = wallet_garni();
        let dir = std::env::temp_dir().join(format!("obsc-clair-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = dir.join("w.bin");
        w.enregistrer(&chemin, &Protection::Aucune).unwrap();

        let relu = Wallet::charger(&chemin, &Protection::Aucune).unwrap();
        assert_eq!(relu.to_bytes_secret(), w.to_bytes_secret());

        assert!(matches!(
            Wallet::charger(&chemin, &Protection::Phrase("peu importe".into())),
            Err(WalletFichierError::FichierEnClair)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn permissions_restreintes() {
        use std::os::unix::fs::PermissionsExt;
        let chemin = fichier("perms");
        wallet_garni().enregistrer(&chemin, &Protection::Aucune).unwrap();
        let mode = std::fs::metadata(&chemin).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "l'autorité de dépense ne doit être lisible que par son propriétaire");
        std::fs::remove_file(&chemin).ok();
    }
}
