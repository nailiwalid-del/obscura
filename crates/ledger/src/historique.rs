//! Historique des SORTIES : de quoi permettre à un wallet de rejouer l'arbre.
//!
//! # Le manque que ce module comble
//!
//! Un wallet ne peut pas RECEVOIR tant qu'il ne connaît pas l'INDEX de ses notes dans
//! l'arbre : sans index, pas de chemin de Merkle, donc pas de preuve d'appartenance,
//! donc aucune dépense possible. Or l'état de consensus du nœud est une
//! [`MerkleFrontier`](proved_hash::merkle::MerkleFrontier) : elle ne conserve que le
//! bord droit de l'arbre. Une fois un bloc appliqué, **plus rien dans l'état ne dit
//! quelles feuilles ont été insérées**. Le nœud n'avait donc rien à servir.
//!
//! Ce module conserve, dans l'ORDRE D'INSERTION, chaque sortie insérée dans l'arbre :
//! son commitment et son enveloppe chiffrée. Un wallet qui les rejoue dans cet ordre
//! reconstruit exactement l'arbre du nœud, donc ses index, donc ses chemins.
//!
//! # Une entrée porte TOUJOURS les deux champs
//!
//! [`Sortie`] est `(commitment, enc_note)` — jamais un `Option<EncNote>`, jamais un
//! drapeau de type. La raison est la même que pour [`crate::bloc::Emission`] : un
//! drapeau de présence partitionnerait PUBLIQUEMENT les feuilles de l'arbre (« émise
//! sans bénéficiaire » vs « transférée »), et cette partition suffirait à vider le
//! witness-hiding du circuit. Une émission de genèse et une sortie de transaction
//! entrent donc ici sous la MÊME forme et avec la MÊME longueur — c'est ce que vérifie
//! `emission_et_sortie_ont_la_meme_forme`.
//!
//! # L'unité de synchronisation est le BLOC
//!
//! L'historique n'est pas une simple liste : il est découpé en [`TrancheBloc`], une par
//! hauteur, portant la PLAGE de feuilles insérées par ce bloc **et la racine de fin de
//! bloc**. Sans la racine de fin de bloc, un wallet ne pourrait s'ancrer qu'au milieu
//! d'un bloc, et son `ProvedTx::anchor` — qui est PUBLIC — vaudrait sa position exacte
//! de synchronisation : un pseudonyme quasi unique, exactement le défaut corrigé pour
//! la clé d'intention. Sur une frontière de bloc, tous les wallets à jour partagent la
//! même ancre.
//!
//! # ⚠️ Décision tranchée : `racine_apres` et `fin` n'entrent PAS dans `Bloc::to_bytes`
//!
//! La question posée était : faut-il ajouter ces deux champs au bloc, donc à
//! `Bloc::id()`, pour qu'un wallet puisse vérifier autre chose que la parole du nœud
//! qui le sert ?
//!
//! **Non — parce que le bloc les engage DÉJÀ.** `Bloc::id()` est le `dual_hash` de
//! l'encodage canonique du bloc, lequel contient ses transactions entières (et, pour la
//! genèse, ses émissions). Or les sorties d'une hauteur ne sont rien d'autre que les
//! `output_commitments` et `enc_notes` de ces transactions, dans l'ordre. La liste des
//! sorties d'un bloc est donc déjà liée à son identifiant, exactement et intégralement
//! (`historique_est_exactement_ce_que_le_bloc_engage` le vérifie mécaniquement).
//! `fin` et `racine_apres` sont des valeurs DÉRIVÉES de (état avant ‖ contenu du bloc) :
//! les inscrire dans le bloc changerait le format de consensus (`VERSION_BLOC` 0x03),
//! obligerait le scelleur à appliquer son bloc spéculativement avant de le sceller, et
//! n'ajouterait **pas un bit** d'authentification.
//!
//! ⚠️ **Ce que cela laisse ouvert, écrit franchement.** Un wallet qui prend l'historique
//! ET les identifiants de blocs auprès du MÊME nœud n'a rien vérifié : ce nœud peut
//! servir une chaîne cohérente et fausse. La vérification ne devient réelle que si les
//! identifiants de blocs viennent d'ailleurs (plusieurs nœuds, un point de contrôle hors
//! bande). C'est le même trou que « personne n'a autorité pour sceller »
//! (docs/THREAT_MODEL.md), pas un trou de format — et le corriger relève de l'élection
//! de producteur, hors périmètre du prototype.
//!
//! # ⚠️ Un nœud qui n'archive pas reste VALIDE
//!
//! Le rôle d'archiviste est SÉPARÉ et OPTIONNEL. L'état de consensus reste borné (la
//! frontier, O(profondeur)) ; l'historique vit à côté, dans un `Option`, et n'entre dans
//! AUCUNE règle de validation. Un nœud qui ne l'active pas valide et propage exactement
//! comme les autres — il ne peut simplement pas amorcer de wallet. Faire dépendre
//! l'admission d'une transaction du fait de servir l'historique ferait de la
//! confidentialité un privilège d'opérateur.
//!
//! # Le COÛT, chiffré
//!
//! Une entrée pèse au plus [`TAILLE_SORTIE_MAX`] = 32 (commitment) + 4 + 1121 (`kem_ct`
//! hybride X25519+Kyber768) + 4 + 256 (`enc_note`) ≈ **1,4 Kio**, dominée par le
//! ciphertext KEM post-quantique. Un bloc plein (512 transactions × 2 sorties = 1024
//! entrées) pèse donc ≈ **1,4 Mio**, et une chaîne scellant un bloc plein toutes les
//! 10 s produirait ≈ **12 Gio par jour**. Ce n'est pas une structure en mémoire vive
//! pour un nœud public chargé : c'est un rôle d'opérateur, assumé, et c'est pourquoi il
//! est optionnel.
//!
//! ⚠️ Limite écrite plutôt que supposée : [`HistoriqueSorties::save`] réécrit le dump
//! ENTIER à chaque sauvegarde. À l'échelle du prototype (testnet, quelques milliers
//! d'entrées) c'est sans conséquence ; à l'échelle ci-dessus c'est inutilisable, et il
//! faudra un journal en ajout plutôt qu'un dump.
//!
//! # Élagage : prévu dans le FORMAT, pas encore dans la valeur
//!
//! [`HistoriqueSorties::debut`] est la première hauteur servie. Elle vaut toujours 0
//! aujourd'hui, et le champ existe quand même : le jour où un archiviste élaguera son
//! préfixe, ce sera un changement de VALEUR, pas de FORMAT. L'adoption d'un historique
//! élagué est en revanche REFUSÉE tant que rien ne sait reconstruire le préfixe
//! manquant (cf. [`HistoriqueDesaccord::DebutNonNul`]) — sans quoi un wallet recevrait
//! un historique tronqué sans qu'aucune erreur ne le dise.

use crate::bloc::Emission;
use circuit::tx::{KEM_CT_LEN, MAX_ENC_NOTE_LEN};
use circuit::EncNote;
use proved_hash::digest::{Digest, DIGEST_BYTES};

/// Version du format de dump de l'historique.
pub const VERSION_HISTORIQUE: u8 = 0x01;

/// Taille sérialisée MAXIMALE d'une entrée : commitment + les deux champs de
/// l'`EncNote`, chacun préfixé de sa longueur. ≈ 1,4 Kio (cf. tête de module).
pub const TAILLE_SORTIE_MAX: usize = DIGEST_BYTES + 4 + KEM_CT_LEN + 4 + MAX_ENC_NOTE_LEN;

/// Taille sérialisée MINIMALE d'une entrée (`enc_note` vide). Sert de borne AVANT
/// allocation au décodage : un compteur annonçant N entrées exige au moins
/// `N × TAILLE_SORTIE_MIN` octets présents.
const TAILLE_SORTIE_MIN: usize = DIGEST_BYTES + 4 + KEM_CT_LEN + 4;

/// Taille sérialisée d'une tranche (hauteur ‖ début ‖ fin ‖ racine).
const TAILLE_TRANCHE: usize = 8 + 8 + 8 + DIGEST_BYTES;

/// CONSIGNÉ À LA COMPILATION : le chiffrage de la tête de module (≈1,4 Kio par entrée)
/// devient faux si les bornes d'`EncNote` changent. Casser la compilation vaut mieux
/// qu'un commentaire qui ment sur le coût d'un rôle d'opérateur.
const _: () = assert!(TAILLE_SORTIE_MAX > 1300 && TAILLE_SORTIE_MAX < 1500);

/// Une sortie insérée dans l'arbre : le commitment (la feuille) et son enveloppe
/// chiffrée (ce qui permet au destinataire de la reconnaître).
///
/// **Jamais d'`Option` sur `enc_note`** — cf. tête de module.
#[derive(Clone)]
pub struct Sortie {
    pub commitment: Digest,
    pub enc_note: EncNote,
}

impl From<&Emission> for Sortie {
    /// Une émission de genèse entre dans l'historique sous la MÊME forme qu'une sortie
    /// de transaction. C'est délibéré : si les deux se distinguaient ici, l'historique
    /// lui-même partitionnerait publiquement les feuilles — ce que le refus d'un
    /// `Option<EncNote>` dans le bloc existe précisément pour empêcher.
    fn from(e: &Emission) -> Self {
        Sortie {
            commitment: e.commitment,
            enc_note: e.enc_note.clone(),
        }
    }
}

/// Ce qu'un bloc a inséré dans l'arbre : la PLAGE de feuilles et la racine de fin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrancheBloc {
    /// Hauteur du bloc (la genèse est à la hauteur 0).
    pub hauteur: u64,
    /// Index ABSOLU de la première feuille insérée par ce bloc (inclus).
    pub debut: u64,
    /// Index ABSOLU de fin (exclu). `fin == debut` pour un bloc sans sortie.
    pub fin: u64,
    /// Racine de l'arbre APRÈS application complète du bloc.
    ///
    /// C'est l'ancre qu'un wallet à jour doit publier. La conserver par bloc — et non
    /// par feuille — est ce qui empêche l'ancre de devenir un pseudonyme.
    pub racine_apres: Digest,
}

/// Erreur de décodage d'un dump d'historique.
///
/// Le fichier est local, mais il est traité comme des octets hostiles : il peut être
/// corrompu par un crash, et sa forme sera celle servie sur le fil à l'étape suivante.
/// Aucune variante ne peut naître d'une panique.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HistoriqueDecodeError {
    #[error("historique tronqué")]
    Tronque,
    #[error("octets résiduels après la fin de l'historique")]
    OctetsResiduels,
    #[error("version d'historique inconnue : {0:#04x}")]
    VersionInconnue(u8),
    #[error("tranche {0} incohérente (hauteur non contiguë ou plage inversée)")]
    TrancheIncoherente(u64),
    #[error("sortie {0} indécodable ou hors bornes")]
    SortieInvalide(u64),
    #[error("les tranches couvrent {couvert} feuilles pour {presentes} sorties présentes")]
    CouvertureIncoherente { couvert: u64, presentes: u64 },
}

/// Erreur de chargement depuis un fichier.
#[derive(Debug, thiserror::Error)]
pub enum HistoriqueLoadError {
    #[error("E/S : {0}")]
    Io(std::io::Error),
    #[error("décodage d'historique : {0}")]
    Decode(HistoriqueDecodeError),
}

/// Désaccord entre un historique rechargé et l'état de consensus.
///
/// # Pourquoi aucune variante ne « répare »
///
/// Un écart signifie qu'un crash est survenu entre deux écritures. Tronquer
/// l'historique pour le faire coller à l'état serait une réparation MUETTE d'une
/// divergence réelle : le bloc en trop a peut-être déjà été relayé à tout le réseau, et
/// les sorties qu'il contient ne sont reconstructibles depuis AUCUN état (la frontier
/// ne garde que le bord droit). L'adoption échoue donc, l'écart est nommé, et
/// l'appelant décide — en le journalisant — de tourner en mode DÉGRADÉ (sans archive)
/// plutôt que de servir un historique faux.
#[derive(Debug, thiserror::Error)]
pub enum HistoriqueDesaccord {
    #[error("historique vide : aucune hauteur servie")]
    Vide,
    #[error("historique arrêté à la hauteur {historique}, état à la hauteur {etat}")]
    Hauteur { etat: u64, historique: u64 },
    #[error("historique de {historique} feuilles, arbre de {etat} feuilles")]
    Longueur { etat: u64, historique: u64 },
    #[error("racine de fin de bloc différente à la hauteur {hauteur}")]
    Racine { hauteur: u64 },
    #[error("historique élagué (débute à la hauteur {debut}) : rien ne sait encore reconstruire le préfixe")]
    DebutNonNul { debut: u64 },
}

/// Les sorties de la chaîne, dans l'ordre d'insertion, découpées par bloc.
pub struct HistoriqueSorties {
    debut: u64,
    tranches: Vec<TrancheBloc>,
    sorties: Vec<Sortie>,
}

impl HistoriqueSorties {
    /// Historique NEUF, servant depuis la hauteur 0.
    ///
    /// `pub(crate)` : le seul créateur légitime est `ProvedLedgerState`, qui garantit
    /// que l'historique et l'arbre grandissent ensemble. Un historique construit
    /// ailleurs pourrait présenter un ordre que l'arbre n'a jamais eu.
    pub(crate) fn nouveau() -> Self {
        HistoriqueSorties {
            debut: 0,
            tranches: Vec::new(),
            sorties: Vec::new(),
        }
    }

    /// Enregistre ce qu'un bloc a inséré. **Appelée UNIQUEMENT après une application
    /// réussie** — c'est ce qui rend l'atomicité structurelle : rien n'est à défaire,
    /// puisque rien n'est écrit avant le succès.
    ///
    /// Les bornes que `from_bytes` vérifie sont garanties EN AMONT sur les deux seuls
    /// chemins d'appel, comme l'exige la règle « une borne du décodage doit exister
    /// aussi dans le constructeur » : les enveloppes d'une transaction sont bornées par
    /// `verify_tx` (`EncNote::within_bounds`, contrôle de consensus), celles d'une
    /// genèse par `ProvedLedgerState::amorcer`. Contiguïté des hauteurs et cohérence
    /// des plages sont ici garanties par construction.
    pub(crate) fn ajouter_bloc(&mut self, hauteur: u64, sorties: Vec<Sortie>, racine_apres: Digest) {
        let debut = self.tranches.last().map(|t| t.fin).unwrap_or(0);
        debug_assert_eq!(
            hauteur,
            self.debut + self.tranches.len() as u64,
            "les hauteurs de l'historique doivent être contiguës"
        );
        let fin = debut.saturating_add(sorties.len() as u64);
        self.sorties.extend(sorties);
        self.tranches.push(TrancheBloc {
            hauteur,
            debut,
            fin,
            racine_apres,
        });
    }

    /// Première hauteur servie. Vaut 0 tant qu'aucun élagage n'existe (cf. tête de
    /// module) — le champ est là pour que l'élagage soit un changement de VALEUR.
    pub fn debut(&self) -> u64 {
        self.debut
    }

    /// Dernière hauteur servie.
    pub fn hauteur_max(&self) -> Option<u64> {
        self.tranches.last().map(|t| t.hauteur)
    }

    /// Dernière tranche — celle que l'état de consensus doit corroborer.
    pub fn derniere_tranche(&self) -> Option<&TrancheBloc> {
        self.tranches.last()
    }

    /// Nombre de sorties CONSERVÉES (pas le nombre de feuilles de l'arbre, qui peut
    /// être plus grand si l'historique est élagué).
    pub fn len(&self) -> usize {
        self.sorties.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sorties.is_empty()
    }

    /// Toutes les sorties conservées, dans l'ordre d'insertion.
    pub fn sorties(&self) -> &[Sortie] {
        &self.sorties
    }

    /// Nombre de hauteurs servies.
    pub fn nombre_de_tranches(&self) -> usize {
        self.tranches.len()
    }

    /// Tranche d'une hauteur donnée.
    ///
    /// `hauteur` viendra du RÉSEAU : elle n'est jamais utilisée comme indice brut.
    /// `checked_sub` + `usize::try_from` + `get` — et la hauteur trouvée est
    /// RECOMPARÉE, pour qu'aucun décalage ne puisse faire désigner une autre hauteur.
    pub fn tranche(&self, hauteur: u64) -> Option<&TrancheBloc> {
        let rang = usize::try_from(hauteur.checked_sub(self.debut)?).ok()?;
        let t = self.tranches.get(rang)?;
        if t.hauteur != hauteur {
            return None;
        }
        Some(t)
    }

    /// Sorties insérées par le bloc de cette hauteur, dans l'ordre.
    ///
    /// Aucune indexation directe : la plage est ramenée dans le repère local par
    /// `checked_sub` puis lue avec `get(..)`.
    pub fn sorties_du_bloc(&self, hauteur: u64) -> Option<&[Sortie]> {
        let t = self.tranche(hauteur)?;
        let base = self.tranches.first()?.debut;
        let a = usize::try_from(t.debut.checked_sub(base)?).ok()?;
        let b = usize::try_from(t.fin.checked_sub(base)?).ok()?;
        self.sorties.get(a..b)
    }

    /// Empreinte sérialisée, en octets — calculée sans allouer, pour qu'un opérateur
    /// puisse voir grossir son archive avant qu'elle ne le surprenne.
    pub fn octets(&self) -> usize {
        let entete: usize = 1 + 8 + 8 + 8;
        let tranches = self.tranches.len().saturating_mul(TAILLE_TRANCHE);
        let sorties: usize = self
            .sorties
            .iter()
            .map(|s| DIGEST_BYTES + 4 + s.enc_note.kem_ct.len() + 4 + s.enc_note.enc_note.len())
            .sum();
        entete
            .saturating_add(tranches)
            .saturating_add(sorties)
    }

    /// Encodage canonique : `version ‖ debut LE ‖ T LE ‖ [hauteur ‖ debut ‖ fin ‖
    /// racine]ᵀ ‖ S LE ‖ [cm ‖ len(kem_ct) ‖ kem_ct ‖ len(enc_note) ‖ enc_note]ˢ`.
    ///
    /// Aucun drapeau ne distingue une émission d'une sortie de transaction : leurs
    /// octets ont la même forme et la même longueur (cf. tête de module).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.octets());
        b.push(VERSION_HISTORIQUE);
        b.extend_from_slice(&self.debut.to_le_bytes());
        b.extend_from_slice(&(self.tranches.len() as u64).to_le_bytes());
        for t in &self.tranches {
            b.extend_from_slice(&t.hauteur.to_le_bytes());
            b.extend_from_slice(&t.debut.to_le_bytes());
            b.extend_from_slice(&t.fin.to_le_bytes());
            b.extend_from_slice(&t.racine_apres.to_bytes());
        }
        b.extend_from_slice(&(self.sorties.len() as u64).to_le_bytes());
        for s in &self.sorties {
            b.extend_from_slice(&s.commitment.to_bytes());
            b.extend_from_slice(&(s.enc_note.kem_ct.len() as u32).to_le_bytes());
            b.extend_from_slice(&s.enc_note.kem_ct);
            b.extend_from_slice(&(s.enc_note.enc_note.len() as u32).to_le_bytes());
            b.extend_from_slice(&s.enc_note.enc_note);
        }
        b
    }

    /// Décode un historique. Curseur BORNÉ, jamais de panique.
    ///
    /// # Pourquoi il n'y a pas de constante de borne ici
    ///
    /// Un historique croît avec la chaîne : aucun plafond constant ne pourrait être
    /// juste. On ne pré-alloue donc JAMAIS d'après le compteur annoncé sans l'avoir
    /// confronté aux octets réellement présents — `N × TAILLE_MIN > restant` est refusé
    /// avant toute réservation. Un en-tête annonçant 10⁹ entrées ne coûte donc rien.
    pub fn from_bytes(b: &[u8]) -> Result<Self, HistoriqueDecodeError> {
        let mut pos = 0usize;
        fn prendre<'a>(
            b: &'a [u8],
            pos: &mut usize,
            n: usize,
        ) -> Result<&'a [u8], HistoriqueDecodeError> {
            let fin = pos.checked_add(n).ok_or(HistoriqueDecodeError::Tronque)?;
            if fin > b.len() {
                return Err(HistoriqueDecodeError::Tronque);
            }
            let s = &b[*pos..fin];
            *pos = fin;
            Ok(s)
        }

        let version = prendre(b, &mut pos, 1)?[0];
        if version != VERSION_HISTORIQUE {
            return Err(HistoriqueDecodeError::VersionInconnue(version));
        }
        let debut = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());

        let t = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());
        let t = usize::try_from(t).map_err(|_| HistoriqueDecodeError::Tronque)?;
        // BORNE AVANT ALLOCATION : le compteur est confronté aux octets présents.
        if t.saturating_mul(TAILLE_TRANCHE) > b.len().saturating_sub(pos) {
            return Err(HistoriqueDecodeError::Tronque);
        }
        let mut tranches: Vec<TrancheBloc> = Vec::with_capacity(t);
        for i in 0..t {
            let hauteur = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());
            let d = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());
            let f = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());
            let r: [u8; DIGEST_BYTES] = prendre(b, &mut pos, DIGEST_BYTES)?
                .try_into()
                .map_err(|_| HistoriqueDecodeError::Tronque)?;
            // Racine CANONIQUE : des felts hors du corps seraient acceptés puis
            // compareraient faux contre l'arbre sans qu'on sache pourquoi.
            let racine_apres = Digest::from_bytes(&r)
                .map_err(|_| HistoriqueDecodeError::TrancheIncoherente(i as u64))?;
            // Hauteurs CONTIGUËS et plages CHAÎNÉES : c'est ce qui autorise
            // `tranche()` à indexer par soustraction plutôt que par recherche, et ce
            // qui empêche un trou de passer pour une continuité.
            let attendue = debut.checked_add(i as u64);
            let debut_attendu = tranches.last().map(|p: &TrancheBloc| p.fin).unwrap_or(d);
            if attendue != Some(hauteur) || d != debut_attendu || f < d {
                return Err(HistoriqueDecodeError::TrancheIncoherente(i as u64));
            }
            tranches.push(TrancheBloc {
                hauteur,
                debut: d,
                fin: f,
                racine_apres,
            });
        }

        let s = u64::from_le_bytes(prendre(b, &mut pos, 8)?.try_into().unwrap());
        let s = usize::try_from(s).map_err(|_| HistoriqueDecodeError::Tronque)?;
        if s.saturating_mul(TAILLE_SORTIE_MIN) > b.len().saturating_sub(pos) {
            return Err(HistoriqueDecodeError::Tronque);
        }
        let mut sorties: Vec<Sortie> = Vec::with_capacity(s);
        for j in 0..s {
            let cm: [u8; DIGEST_BYTES] = prendre(b, &mut pos, DIGEST_BYTES)?
                .try_into()
                .map_err(|_| HistoriqueDecodeError::Tronque)?;
            let commitment = Digest::from_bytes(&cm)
                .map_err(|_| HistoriqueDecodeError::SortieInvalide(j as u64))?;

            let lk = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            if lk != KEM_CT_LEN {
                return Err(HistoriqueDecodeError::SortieInvalide(j as u64));
            }
            let kem_ct = prendre(b, &mut pos, lk)?.to_vec();

            let le = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            if le > MAX_ENC_NOTE_LEN {
                return Err(HistoriqueDecodeError::SortieInvalide(j as u64));
            }
            let enc_note = prendre(b, &mut pos, le)?.to_vec();

            sorties.push(Sortie {
                commitment,
                enc_note: EncNote { kem_ct, enc_note },
            });
        }

        if pos != b.len() {
            return Err(HistoriqueDecodeError::OctetsResiduels);
        }

        // Les tranches doivent couvrir EXACTEMENT les sorties présentes. Un historique
        // dont les plages annoncent plus (ou moins) que ce qu'il porte servirait des
        // index faux — et un index faux produit un chemin de Merkle faux, qu'aucune
        // erreur ne signale : la transaction du wallet est simplement refusée.
        // (Le cas « aucune tranche mais des sorties présentes » tombe ici aussi :
        // couverture 0 contre N présentes.)
        let couvert = match (tranches.first(), tranches.last()) {
            (Some(p), Some(d)) => d.fin.saturating_sub(p.debut),
            _ => 0,
        };
        if couvert != sorties.len() as u64 {
            return Err(HistoriqueDecodeError::CouvertureIncoherente {
                couvert,
                presentes: sorties.len() as u64,
            });
        }

        Ok(HistoriqueSorties {
            debut,
            tranches,
            sorties,
        })
    }

    /// Sauvegarde ATOMIQUE (`<path>.tmp` puis `rename`).
    ///
    /// ⚠️ Réécrit le dump ENTIER (cf. tête de module) : acceptable au prototype,
    /// inutilisable à l'échelle d'une chaîne chargée.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes())?;
        std::fs::rename(&tmp, path)
    }

    /// Recharge un historique écrit par `save`.
    pub fn load(path: &std::path::Path) -> Result<Self, HistoriqueLoadError> {
        let octets = std::fs::read(path).map_err(HistoriqueLoadError::Io)?;
        Self::from_bytes(&octets).map_err(HistoriqueLoadError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proved_wallet::emission_factice;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            proved_hash::felt::Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    fn historique_de(blocs: &[usize]) -> HistoriqueSorties {
        let mut h = HistoriqueSorties::nouveau();
        let mut graine = 0u64;
        for (hauteur, n) in blocs.iter().enumerate() {
            let sorties: Vec<Sortie> = (0..*n)
                .map(|_| {
                    graine += 1;
                    Sortie::from(&emission_factice(&digest(graine * 100)))
                })
                .collect();
            h.ajouter_bloc(hauteur as u64, sorties, digest(9_000 + hauteur as u64));
        }
        h
    }

    /// UNE ÉMISSION DE GENÈSE ET UNE SORTIE DE TRANSACTION ONT LA MÊME FORME.
    ///
    /// Si l'historique distinguait les deux — un drapeau, une longueur qui varie — il
    /// partitionnerait publiquement les feuilles de l'arbre en « émises » et
    /// « transférées ». C'est exactement la fuite que le refus d'un `Option<EncNote>`
    /// dans `Bloc` existe pour empêcher ; elle serait rouverte ici sans que rien ne
    /// casse par ailleurs.
    #[test]
    fn emission_et_sortie_ont_la_meme_forme() {
        let emise = Sortie::from(&emission_factice(&digest(1)));
        // Une « sortie de transaction » : même structure, enveloppe fabriquée de la
        // même façon (le consensus ne regarde pas le clair).
        let transferee = Sortie::from(&emission_factice(&digest(2)));

        let taille = |s: &Sortie| {
            let mut h = HistoriqueSorties::nouveau();
            h.ajouter_bloc(0, vec![s.clone()], digest(7));
            h.to_bytes().len()
        };
        assert_eq!(
            taille(&emise),
            taille(&transferee),
            "une longueur qui varierait trahirait le type de feuille"
        );
    }

    /// Aller-retour canonique, y compris le champ `debut` prévu pour l'élagage.
    #[test]
    fn aller_retour_canonique() {
        let h = historique_de(&[2, 0, 3]);
        let octets = h.to_bytes();
        let relu = HistoriqueSorties::from_bytes(&octets).expect("aller-retour");
        assert_eq!(relu.to_bytes(), octets, "canonique");
        assert_eq!(relu.debut(), 0);
        assert_eq!(relu.len(), 5);
        assert_eq!(relu.hauteur_max(), Some(2));
        assert_eq!(h.octets(), octets.len(), "le compteur d'octets ne dérive pas");

        // Les plages sont bien celles de l'insertion.
        assert_eq!(relu.tranche(0).map(|t| (t.debut, t.fin)), Some((0, 2)));
        assert_eq!(relu.tranche(1).map(|t| (t.debut, t.fin)), Some((2, 2)));
        assert_eq!(relu.tranche(2).map(|t| (t.debut, t.fin)), Some((2, 5)));
        assert_eq!(relu.sorties_du_bloc(1).map(|s| s.len()), Some(0));
        assert_eq!(relu.sorties_du_bloc(2).map(|s| s.len()), Some(3));
    }

    /// UNE HAUTEUR VENUE DU RÉSEAU NE DOIT NI PANIQUER NI DÉSIGNER UNE VOISINE.
    ///
    /// `tranche` et `sorties_du_bloc` reçoivent un `u64` arbitraire. Un `u64::MAX`, un
    /// zéro sur un historique élagué, une hauteur au-delà de la tête : `None` à chaque
    /// fois. Une indexation directe donnerait ici une panique — ou pire, la tranche
    /// d'une AUTRE hauteur, donc des index faux servis en silence.
    #[test]
    fn hauteur_hors_domaine_rend_none_sans_paniquer() {
        let h = historique_de(&[1, 1]);
        for hauteur in [2u64, 3, 1_000_000, u64::MAX] {
            assert!(h.tranche(hauteur).is_none(), "hauteur {hauteur}");
            assert!(h.sorties_du_bloc(hauteur).is_none(), "hauteur {hauteur}");
        }
        assert!(h.tranche(0).is_some());
    }

    /// Matrice de rejet : version, troncature, octets résiduels, compteur menteur,
    /// tranche incohérente, couverture fausse. Jamais de panique.
    #[test]
    fn historiques_malformes_rejetes_sans_panique() {
        assert!(matches!(
            HistoriqueSorties::from_bytes(&[]),
            Err(HistoriqueDecodeError::Tronque)
        ));
        assert!(matches!(
            HistoriqueSorties::from_bytes(&[0x02]),
            Err(HistoriqueDecodeError::VersionInconnue(0x02))
        ));

        let bon = historique_de(&[2]).to_bytes();
        assert!(matches!(
            HistoriqueSorties::from_bytes(&bon[..bon.len() - 1]),
            Err(HistoriqueDecodeError::Tronque)
        ));
        let mut trop = bon.clone();
        trop.push(0);
        assert!(matches!(
            HistoriqueSorties::from_bytes(&trop),
            Err(HistoriqueDecodeError::OctetsResiduels)
        ));

        // ANTI-DoS : un en-tête annonçant 10⁹ tranches, puis plus rien. Sans la
        // confrontation du compteur aux octets présents, ce sont ≈56 Gio réservés pour
        // des octets jamais reçus.
        let mut menteur = vec![VERSION_HISTORIQUE];
        menteur.extend_from_slice(&0u64.to_le_bytes());
        menteur.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        assert!(matches!(
            HistoriqueSorties::from_bytes(&menteur),
            Err(HistoriqueDecodeError::Tronque)
        ));

        // Idem pour le compteur de sorties (≈1,4 Tio réservés).
        let mut menteur = vec![VERSION_HISTORIQUE];
        menteur.extend_from_slice(&0u64.to_le_bytes());
        menteur.extend_from_slice(&0u64.to_le_bytes());
        menteur.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        assert!(matches!(
            HistoriqueSorties::from_bytes(&menteur),
            Err(HistoriqueDecodeError::Tronque)
        ));

        // Une tranche à la hauteur NON contiguë : refusée. Un trou ferait dériver tous
        // les index calculés par soustraction.
        let mut trouee = historique_de(&[1, 1]);
        trouee.tranches[1].hauteur = 5;
        assert!(matches!(
            HistoriqueSorties::from_bytes(&trouee.to_bytes()),
            Err(HistoriqueDecodeError::TrancheIncoherente(1))
        ));

        // Des plages qui annoncent plus de feuilles que l'historique n'en porte.
        let mut mentie = historique_de(&[2]);
        mentie.tranches[0].fin = 9;
        assert!(matches!(
            HistoriqueSorties::from_bytes(&mentie.to_bytes()),
            Err(HistoriqueDecodeError::CouvertureIncoherente {
                couvert: 9,
                presentes: 2
            })
        ));
    }
}
