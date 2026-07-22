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
//! hybride X25519+ML-KEM-768) + 4 + 256 (`enc_note`) ≈ **1,4 Kio**, dominée par le
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
        Self::nouveau_depuis(0)
    }

    /// Historique neuf servant depuis `debut` — utilise par le decodage du journal
    /// (le champ existe pour que l'elagage soit un changement de VALEUR, pas de
    /// format ; il vaut 0 partout aujourd'hui).
    fn nouveau_depuis(debut: u64) -> Self {
        HistoriqueSorties {
            debut,
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
    pub(crate) fn ajouter_bloc(
        &mut self,
        hauteur: u64,
        sorties: Vec<Sortie>,
        racine_apres: Digest,
    ) {
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
        entete.saturating_add(tranches).saturating_add(sorties)
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
    /// ⚠️ Réécrit le dump ENTIER : conservé pour les tests et la migration, mais le
    /// chemin de production est [`Self::save_journal`] — une chaîne chargée produit
    /// ≈1,4 Mio de sorties par bloc plein, et réécrire des Gio toutes les 30 s n'est
    /// pas une politique de sauvegarde, c'est une usure de disque.
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

    // ------------------------------------------------------------------ journal

    /// Enregistrement d'une tranche dans le JOURNAL : en-tête de tranche suivi de SES
    /// sorties — c'est ce regroupement qui rend l'ajout possible, là où le dump
    /// intégral sépare toutes les tranches de toutes les sorties.
    fn encoder_enregistrement(&self, t: &TrancheBloc, b: &mut Vec<u8>) {
        b.extend_from_slice(&t.hauteur.to_le_bytes());
        b.extend_from_slice(&t.debut.to_le_bytes());
        b.extend_from_slice(&t.fin.to_le_bytes());
        b.extend_from_slice(&t.racine_apres.to_bytes());
        let base = self.premiere_sortie();
        let (d, f) = ((t.debut - base) as usize, (t.fin - base) as usize);
        for sortie in &self.sorties[d..f] {
            b.extend_from_slice(&sortie.commitment.to_bytes());
            b.extend_from_slice(&(sortie.enc_note.kem_ct.len() as u32).to_le_bytes());
            b.extend_from_slice(&sortie.enc_note.kem_ct);
            b.extend_from_slice(&(sortie.enc_note.enc_note.len() as u32).to_le_bytes());
            b.extend_from_slice(&sortie.enc_note.enc_note);
        }
    }

    /// Index absolu de la première sortie détenue (les tranches indexent en absolu).
    fn premiere_sortie(&self) -> u64 {
        self.tranches.first().map(|t| t.debut).unwrap_or(0)
    }

    /// Sauvegarde en JOURNAL : n'écrit que les tranches d'index `>= persistees`.
    ///
    /// # Pourquoi un journal, et pas le dump atomique
    ///
    /// Le dump intégral réécrit TOUT à chaque sauvegarde — des Gio sur une chaîne
    /// chargée, toutes les 30 s. Le journal n'écrit que la QUEUE nouvelle, puis
    /// `sync_all`. Le prix : l'ajout n'est pas atomique. Un crash en plein ajout
    /// laisse un enregistrement PARTIEL en fin de fichier — cas traité par
    /// [`Self::load_fichier`], et INOFFENSIF par construction : l'ordre d'écriture du
    /// nœud est « historique d'abord, état ensuite », donc un enregistrement partiel
    /// correspond toujours à des blocs que l'état PERSISTÉ ne couvre pas encore.
    /// L'écarter ne fait perdre aucune donnée que quiconque possédait.
    ///
    /// Si le fichier n'existe pas (ou `persistees == 0`), le journal COMPLET est
    /// écrit atomiquement (tmp + rename) — c'est l'amorçage, et la migration depuis
    /// l'ancien format passe aussi par là.
    ///
    /// Retourne le nouveau compte de tranches persistées.
    pub fn save_journal(
        &self,
        path: &std::path::Path,
        persistees: usize,
    ) -> std::io::Result<usize> {
        use std::io::Write;

        if persistees > self.tranches.len() {
            // Un compteur en avance sur les données signalerait une corruption de la
            // comptabilité de l'appelant : refuser bruyamment plutôt qu'écrire un
            // journal à trous.
            return Err(std::io::Error::other(
                "compteur de tranches persistées en avance sur l'historique",
            ));
        }

        if persistees == 0 || !path.exists() {
            let mut b = vec![VERSION_JOURNAL];
            b.extend_from_slice(&self.debut.to_le_bytes());
            for t in &self.tranches {
                self.encoder_enregistrement(t, &mut b);
            }
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, &b)?;
            std::fs::rename(&tmp, path)?;
            return Ok(self.tranches.len());
        }

        if persistees == self.tranches.len() {
            return Ok(persistees); // rien de neuf : aucune écriture
        }

        let mut b = Vec::new();
        for t in &self.tranches[persistees..] {
            self.encoder_enregistrement(t, &mut b);
        }
        let mut f = std::fs::OpenOptions::new().append(true).open(path)?;
        f.write_all(&b)?;
        // `sync_all` : sans lui, « écrit » voudrait dire « remis au cache du
        // système », et l'ordre historique-avant-état — dont dépend tout le
        // raisonnement de reprise — ne serait garanti qu'en mémoire.
        f.sync_all()?;
        Ok(self.tranches.len())
    }

    /// Charge `historique.bin` quel que soit son format, discriminé par l'octet de
    /// version : `0x01` = dump intégral hérité, `0x02` = journal.
    ///
    /// Retourne l'historique et la [`Reprise`] qui dit à l'appelant ce qu'il doit
    /// faire du fichier (migrer, tronquer une queue partielle, ou rien).
    pub fn load_fichier(path: &std::path::Path) -> Result<(Self, Reprise), HistoriqueLoadError> {
        let octets = std::fs::read(path).map_err(HistoriqueLoadError::Io)?;
        match octets.first() {
            Some(&VERSION_HISTORIQUE) => {
                let h = Self::from_bytes(&octets).map_err(HistoriqueLoadError::Decode)?;
                Ok((h, Reprise::AncienFormat))
            }
            Some(&VERSION_JOURNAL) => Self::decoder_journal(&octets),
            Some(&v) => Err(HistoriqueLoadError::Decode(
                HistoriqueDecodeError::VersionInconnue(v),
            )),
            None => Err(HistoriqueLoadError::Decode(HistoriqueDecodeError::Tronque)),
        }
    }

    /// Décode un journal. Séquentiel, borné, jamais de panique.
    ///
    /// # Queue partielle ≠ corruption — et la distinction est TOUTE la reprise
    ///
    /// Un crash en plein ajout laisse un dernier enregistrement incomplet : des
    /// octets qui MANQUENT, exactement en fin de fichier. C'est un artefact attendu,
    /// écarté et signalé — pas une « réparation » : ces octets n'ont jamais formé un
    /// enregistrement, et l'ordre historique-avant-état garantit qu'aucun état
    /// persisté ne les couvre.
    ///
    /// Tout AUTRE défaut — hauteur non contiguë, plage non chaînée, digest non
    /// canonique, longueur d'enveloppe hors bornes — est une CORRUPTION : le fichier
    /// a été altéré, pas interrompu, et on refuse. Tronquer là reviendrait à amputer
    /// des blocs peut-être relayés à tout le réseau, la faute exacte que la
    /// discipline du dépôt interdit.
    fn decoder_journal(b: &[u8]) -> Result<(Self, Reprise), HistoriqueLoadError> {
        use HistoriqueDecodeError as E;
        let corrompu = |e: E| HistoriqueLoadError::Decode(e);

        let mut pos = 1usize; // version déjà lue
        let prendre = |b: &[u8], pos: &mut usize, n: usize| -> Option<usize> {
            let fin = pos.checked_add(n)?;
            if fin > b.len() {
                return None;
            }
            let d = *pos;
            *pos = fin;
            Some(d)
        };

        let Some(d) = prendre(b, &mut pos, 8) else {
            return Err(corrompu(E::Tronque)); // en-tête absent : rien d'exploitable
        };
        let debut = u64::from_le_bytes(b[d..d + 8].try_into().unwrap());

        let mut h = HistoriqueSorties::nouveau_depuis(debut);
        let mut octets_valides = pos as u64;
        let mut queue_partielle = false;
        let mut index_tranche = 0u64;

        'enregistrements: while pos < b.len() {
            // En-tête de tranche. Des octets manquants ICI = queue partielle.
            let Some(o) = prendre(b, &mut pos, 8 + 8 + 8 + DIGEST_BYTES) else {
                queue_partielle = true;
                break;
            };
            let hauteur = u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
            let t_debut = u64::from_le_bytes(b[o + 8..o + 16].try_into().unwrap());
            let t_fin = u64::from_le_bytes(b[o + 16..o + 24].try_into().unwrap());
            let r: [u8; DIGEST_BYTES] = b[o + 24..o + 24 + DIGEST_BYTES].try_into().unwrap();
            // Un digest non canonique n'est PAS une interruption d'écriture : refus.
            let racine = Digest::from_bytes(&r)
                .map_err(|_| corrompu(E::TrancheIncoherente(index_tranche)))?;

            // Cohérence de chaînage — même règle que le dump : hauteurs contiguës,
            // plages chaînées. Une violation est une corruption, pas une queue.
            let attendue = debut.checked_add(index_tranche);
            // Sans élagage, la première tranche commence toujours à la sortie 0 —
            // c'est aussi ce que `ajouter_bloc` reconstruira : accepter autre chose
            // ici stockerait des index décalés en silence.
            let debut_attendu = h.derniere_tranche().map(|t| t.fin).unwrap_or(0);
            if attendue != Some(hauteur) || t_debut != debut_attendu || t_fin < t_debut {
                return Err(corrompu(E::TrancheIncoherente(index_tranche)));
            }
            let n = t_fin - t_debut;
            // BORNE AVANT ALLOCATION : le compte annoncé est confronté aux octets
            // réellement présents avant toute réservation. Un manque d'octets est
            // indistinguable d'une écriture interrompue : queue partielle.
            if n.saturating_mul(TAILLE_SORTIE_MIN as u64) > b.len().saturating_sub(pos) as u64 {
                queue_partielle = true;
                break;
            }
            let mut sorties = Vec::with_capacity(n as usize);
            for j in 0..n {
                let Some(o) = prendre(b, &mut pos, DIGEST_BYTES) else {
                    queue_partielle = true;
                    break 'enregistrements;
                };
                let cm: [u8; DIGEST_BYTES] = b[o..o + DIGEST_BYTES].try_into().unwrap();
                let commitment =
                    Digest::from_bytes(&cm).map_err(|_| corrompu(E::SortieInvalide(j)))?;
                let Some(o) = prendre(b, &mut pos, 4) else {
                    queue_partielle = true;
                    break 'enregistrements;
                };
                let lk = u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
                if lk != KEM_CT_LEN {
                    return Err(corrompu(E::SortieInvalide(j)));
                }
                let Some(o) = prendre(b, &mut pos, lk) else {
                    queue_partielle = true;
                    break 'enregistrements;
                };
                let kem_ct = b[o..o + lk].to_vec();
                let Some(o) = prendre(b, &mut pos, 4) else {
                    queue_partielle = true;
                    break 'enregistrements;
                };
                let le = u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
                if le > MAX_ENC_NOTE_LEN {
                    return Err(corrompu(E::SortieInvalide(j)));
                }
                let Some(o) = prendre(b, &mut pos, le) else {
                    queue_partielle = true;
                    break 'enregistrements;
                };
                sorties.push(Sortie {
                    commitment,
                    enc_note: EncNote {
                        kem_ct,
                        enc_note: b[o..o + le].to_vec(),
                    },
                });
            }
            h.ajouter_bloc(hauteur, sorties, racine);
            octets_valides = pos as u64;
            index_tranche += 1;
        }

        Ok((
            h,
            Reprise::Journal {
                octets_valides,
                queue_partielle,
            },
        ))
    }
}

/// Version du format JOURNAL de `historique.bin` (en ajout, par enregistrements de
/// bloc). Cohabite avec [`VERSION_HISTORIQUE`] (dump intégral) sur le même nom de
/// fichier : l'octet de version discrimine, et un dump hérité est migré une fois.
pub const VERSION_JOURNAL: u8 = 0x02;

/// Ce que [`HistoriqueSorties::load_fichier`] a trouvé, et ce que l'appelant en fait.
#[derive(Debug, PartialEq, Eq)]
pub enum Reprise {
    /// Fichier au format journal.
    Journal {
        /// Longueur du préfixe VALIDE. Si `queue_partielle`, l'appelant doit tronquer
        /// le fichier à cette longueur avant tout nouvel ajout — sinon les prochains
        /// enregistrements s'écriraient APRÈS des octets morts, et le fichier entier
        /// deviendrait illisible au chargement suivant.
        octets_valides: u64,
        /// Un enregistrement incomplet terminait le fichier (crash en plein ajout).
        queue_partielle: bool,
    },
    /// Dump intégral hérité (`0x01`) : à réécrire en journal (migration unique).
    AncienFormat,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proved_wallet::emission_factice;

    fn chemin_temp(nom: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "obscura_journal_{}_{}.bin",
            nom,
            std::process::id()
        ))
    }

    /// LE JOURNAL EST ÉQUIVALENT AU DUMP — écrit par ajouts successifs, il recharge
    /// exactement le même historique.
    ///
    /// C'est la propriété qui autorise à remplacer la réécriture intégrale : si un
    /// seul octet divergeait entre les deux chemins, un nœud redémarré servirait des
    /// index différents de ceux qu'il servait avant l'arrêt — et chaque wallet
    /// synchronisé chez lui construirait des chemins de Merkle faux, sans erreur.
    #[test]
    fn journal_par_ajouts_recharge_identique_au_dump() {
        let chemin = chemin_temp("ajouts");
        std::fs::remove_file(&chemin).ok();

        let mut h = historique_de(&[2]);
        // Amorçage : écriture complète (1 tranche).
        let mut persistees = h.save_journal(&chemin, 0).unwrap();
        assert_eq!(persistees, 1);

        // Deux blocs de plus, persistés par AJOUT — en deux sauvegardes distinctes,
        // comme le ferait la boucle du nœud.
        h.ajouter_bloc(1, vec![sortie(50), sortie(51), sortie(52)], digest(500));
        persistees = h.save_journal(&chemin, persistees).unwrap();
        assert_eq!(persistees, 2);
        h.ajouter_bloc(2, vec![sortie(60)], digest(600));
        persistees = h.save_journal(&chemin, persistees).unwrap();
        assert_eq!(persistees, 3);

        let (relu, reprise) = HistoriqueSorties::load_fichier(&chemin).unwrap();
        assert!(matches!(
            reprise,
            Reprise::Journal {
                queue_partielle: false,
                ..
            }
        ));
        assert_eq!(
            relu.to_bytes(),
            h.to_bytes(),
            "le journal par ajouts doit recharger EXACTEMENT le dump en mémoire"
        );

        // Sauvegarder sans rien de neuf n'écrit RIEN (taille de fichier inchangée).
        let avant = std::fs::metadata(&chemin).unwrap().len();
        let apres_compte = h.save_journal(&chemin, persistees).unwrap();
        assert_eq!(apres_compte, persistees);
        assert_eq!(std::fs::metadata(&chemin).unwrap().len(), avant);

        std::fs::remove_file(&chemin).ok();
    }

    /// L'AJOUT n'écrit que la QUEUE : le chemin d'ajout ne repasse JAMAIS par la
    /// réécriture intégrale (`.tmp` + rename).
    ///
    /// # Pourquoi un canari, et pas une mesure de taille
    ///
    /// Le premier jet de ce test comparait les tailles de fichier avant/après —
    /// tautologique : une réécriture intégrale produit exactement le même delta
    /// qu'un ajout, puisque le contenu final est identique. L'observable qui
    /// distingue réellement les deux chemins est le fichier `.tmp` : la réécriture
    /// intégrale passe par lui, l'ajout jamais. Un `.tmp` préexistant EN LECTURE
    /// SEULE fait donc échouer toute régression vers la réécriture — c'est-à-dire
    /// vers des Gio par jour d'usure disque sans information nouvelle.
    #[test]
    fn ajout_ne_repasse_jamais_par_la_reecriture() {
        let chemin = chemin_temp("cout");
        let tmp = chemin.with_extension("tmp");
        std::fs::remove_file(&chemin).ok();
        if tmp.exists() {
            let mut p = std::fs::metadata(&tmp).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            std::fs::set_permissions(&tmp, p).ok();
            std::fs::remove_file(&tmp).ok();
        }

        let mut h = historique_de(&[2, 3]);
        let persistees = h.save_journal(&chemin, 0).unwrap();

        // CANARI : un `.tmp` verrouillé. Toute tentative de réécriture intégrale
        // échouera dessus ; l'ajout ne le regarde même pas.
        std::fs::write(&tmp, b"canari").unwrap();
        let mut p = std::fs::metadata(&tmp).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&tmp, p).unwrap();

        h.ajouter_bloc(2, vec![sortie(90), sortie(91)], digest(900));
        h.save_journal(&chemin, persistees)
            .expect("l'ajout ne doit pas repasser par le fichier temporaire");

        let (relu, _) = HistoriqueSorties::load_fichier(&chemin).unwrap();
        assert_eq!(relu.to_bytes(), h.to_bytes(), "et le contenu reste exact");

        let mut p = std::fs::metadata(&tmp).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        std::fs::set_permissions(&tmp, p).ok();
        std::fs::remove_file(&tmp).ok();
        std::fs::remove_file(&chemin).ok();
    }

    /// QUEUE PARTIELLE (crash en plein ajout) : le préfixe valide est rechargé, la
    /// queue est signalée, et après troncature l'ajout REPREND proprement.
    ///
    /// Sans le signalement, le prochain ajout s'écrirait après des octets morts et le
    /// fichier entier deviendrait illisible — la panne se déclarerait au redémarrage
    /// SUIVANT, loin de sa cause.
    #[test]
    fn queue_partielle_signalee_puis_reprise() {
        let chemin = chemin_temp("queue");
        std::fs::remove_file(&chemin).ok();

        let h = historique_de(&[2]);
        h.save_journal(&chemin, 0).unwrap();
        let taille_valide = std::fs::metadata(&chemin).unwrap().len();

        // Simule un crash : un enregistrement COMMENCÉ, jamais fini.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&chemin)
                .unwrap();
            f.write_all(&1u64.to_le_bytes()).unwrap(); // hauteur seule, puis plus rien
        }

        let (relu, reprise) = HistoriqueSorties::load_fichier(&chemin).unwrap();
        let Reprise::Journal {
            octets_valides,
            queue_partielle,
        } = reprise
        else {
            panic!("format journal attendu");
        };
        assert!(queue_partielle, "la queue interrompue doit être SIGNALÉE");
        assert_eq!(
            octets_valides, taille_valide,
            "le préfixe valide est intact"
        );
        assert_eq!(relu.nombre_de_tranches(), 1, "le préfixe est rechargé");

        // Troncature (le geste de l'appelant), puis l'ajout reprend.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&chemin)
            .unwrap();
        f.set_len(octets_valides).unwrap();
        drop(f);
        let mut h2 = relu;
        h2.ajouter_bloc(1, vec![sortie(70)], digest(700));
        h2.save_journal(&chemin, 1).unwrap();
        let (fin, reprise) = HistoriqueSorties::load_fichier(&chemin).unwrap();
        assert!(matches!(
            reprise,
            Reprise::Journal {
                queue_partielle: false,
                ..
            }
        ));
        assert_eq!(fin.nombre_de_tranches(), 2, "la reprise est complète");

        std::fs::remove_file(&chemin).ok();
    }

    /// CORRUPTION AU MILIEU ≠ queue partielle : refus, jamais de « réparation ».
    ///
    /// Tronquer sur une corruption amputerait des enregistrements COMPLETS — des
    /// blocs peut-être relayés à tout le réseau. La distinction porte toute la
    /// politique de reprise.
    #[test]
    fn corruption_au_milieu_refusee_pas_reparee() {
        let chemin = chemin_temp("corruption");
        std::fs::remove_file(&chemin).ok();

        let mut h = historique_de(&[2]);
        h.ajouter_bloc(1, vec![sortie(80)], digest(800));
        h.save_journal(&chemin, 0).unwrap();

        // Corrompt la HAUTEUR du second enregistrement : contiguïté violée — un
        // fichier ALTÉRÉ, pas interrompu.
        let mut octets = std::fs::read(&chemin).unwrap();
        let mut premier = Vec::new();
        h.encoder_enregistrement(h.tranche(0).unwrap(), &mut premier);
        let pos_hauteur_2e = 1 + 8 + premier.len();
        octets[pos_hauteur_2e] ^= 0xFF;
        std::fs::write(&chemin, &octets).unwrap();

        assert!(
            HistoriqueSorties::load_fichier(&chemin).is_err(),
            "une corruption interne doit être un REFUS, pas une troncature"
        );

        std::fs::remove_file(&chemin).ok();
    }

    /// MIGRATION : un dump intégral hérité (0x01) est reconnu, rechargé à
    /// l'identique, et signalé pour réécriture.
    #[test]
    fn ancien_format_reconnu_et_identique() {
        let chemin = chemin_temp("migration");
        std::fs::remove_file(&chemin).ok();

        let h = historique_de(&[2, 1]);
        h.save(&chemin).unwrap(); // ancien chemin : dump intégral 0x01

        let (relu, reprise) = HistoriqueSorties::load_fichier(&chemin).unwrap();
        assert_eq!(reprise, Reprise::AncienFormat);
        assert_eq!(
            relu.to_bytes(),
            h.to_bytes(),
            "contenu strictement identique"
        );

        // La réécriture en journal (le geste de migration) reste équivalente.
        relu.save_journal(&chemin, 0).unwrap();
        let (rejournal, reprise) = HistoriqueSorties::load_fichier(&chemin).unwrap();
        assert!(matches!(reprise, Reprise::Journal { .. }));
        assert_eq!(rejournal.to_bytes(), h.to_bytes());

        std::fs::remove_file(&chemin).ok();
    }

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            proved_hash::felt::Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Une sortie de test déterministe par graine (enveloppe factice réelle).
    fn sortie(graine: u64) -> Sortie {
        Sortie::from(&emission_factice(&digest(graine)))
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
        assert_eq!(
            h.octets(),
            octets.len(),
            "le compteur d'octets ne dérive pas"
        );

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
