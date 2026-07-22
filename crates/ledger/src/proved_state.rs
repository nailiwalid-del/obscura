//! État du ledger PROUVÉ (3c) : arbre Rescue + nullifiers, piloté par la preuve STARK.
//!
//! Contrairement à `state::apply_transparent` (mode de dev non-sound), `apply_proved_tx`
//! applique la RÈGLE DE CONSENSUS CIBLE : il vérifie la preuve `ProvedTx`
//! (`circuit::verify_tx`, qui établit P1–P7 + non-rejeu) contre une racine récente,
//! puis dépense les nullifiers et insère les commitments de sortie dans l'arbre Rescue.
//!
//! L'arbre du nœud est une `proved_hash::merkle::MerkleFrontier` (durcissement #7) :
//! append-only, ne conserve que le bord droit (O(depth), mémoire bornée), et rend
//! `TreeFull` plutôt que paniquer sur un arbre plein. Il produit les MÊMES racines
//! que la `ProvedMerkleTree` de référence (test différentiel), donc les preuves
//! d'appartenance `circuit::membership` restent valides. Le nœud n'a pas besoin des
//! CHEMINS (produits côté wallet par `ProvedMerkleTree`) : il n'appelle qu'`append` +
//! `root`.
//!
//! Depuis 3z-a6, `ProvedTx` est monolithique (v3 depuis enc-notes) : `proof` est LA
//! preuve unique (P1–P7 pour toute la tx, une seule trace) et les nullifiers/commitments
//! de sortie sont des champs publics top-level (`tx.nullifiers`, plus de
//! `tx.spends[i].nullifier`) — la provenance change, la logique de consensus
//! ci-dessous (anchor → preuve → signature d'intention → nullifiers → application
//! atomique) est inchangée.
//!
//! Depuis 3z-b1, la preuve monolithique vérifiée ici est witness-hiding (HVZK en
//! ROM — voir docs/STARK_STATEMENT.md, « Argument HVZK ») ; rien ne change côté
//! ledger (blinding transparent au vérifieur).
//!
//! Persistance (#7) : `save`/`load` sérialisent l'état complet (frontier +
//! nullifiers + fenêtre de racines) en octets canoniques et écrivent de façon
//! ATOMIQUE (`<path>.tmp` puis `rename`) — un nœud survit au redémarrage. Le dump
//! est bon marché côté arbre grâce à la frontier (O(depth)) ; seul l'ensemble des
//! nullifiers est volumineux (inhérent).
//!
//! Historique des sorties (synchronisation wallet) : l'état peut, EN OPTION, conserver
//! à côté de la frontier la liste ordonnée des sorties insérées
//! (`crate::historique::HistoriqueSorties`). C'est ce qui permet à un wallet de rejouer
//! l'arbre et d'en connaître les index. Le rôle est SÉPARÉ et OPTIONNEL : un nœud qui
//! ne l'active pas reste parfaitement valide, et l'état de consensus reste borné.
//! **Une seule porte d'insertion** : `mint` (genèse) et `apply_proved_tx` sont privées,
//! et l'historique n'est écrit que par `amorcer` et `appliquer_bloc` — les deux seuls
//! endroits qui font grandir l'arbre.
//!
//! Hors périmètre (→ ledger/Phase 3z-c) : généralisation M-in/N-out.

use crate::bloc::{Bloc, MAX_EMISSIONS_PAR_BLOC, PAS_DE_PARENT, TAILLE_ID};
use crate::historique::{HistoriqueDesaccord, HistoriqueSorties, Sortie};
use crate::LedgerError;
use circuit::{verify_tx, ProvedTx, INTENT_DOMAIN};
use crypto::sig;
use proved_hash::digest::Digest;
use proved_hash::merkle::{FrontierDecodeError, MerkleFrontier};
use std::collections::{HashSet, VecDeque};

/// Erreur de désérialisation de l'état (`ProvedLedgerState::from_bytes`). Le
/// fichier d'état est local et trusté : la validation détecte la corruption sans
/// jamais paniquer.
#[derive(Debug, PartialEq, Eq)]
pub enum StateDecodeError {
    /// Champ tronqué (moins d'octets que nécessaire).
    TooShort,
    /// Octets résiduels après la fin — encodage non canonique.
    TrailingBytes,
    /// La `MerkleFrontier` embarquée est corrompue.
    BadFrontier(FrontierDecodeError),
    /// Version de format inconnue — refusée, jamais réinterprétée.
    BadVersion(u8),
    /// Autorité de scellement indécodable ou hors bornes.
    BadAutorite,
}

/// Erreur de chargement d'un état depuis un fichier (`load`).
#[derive(Debug)]
pub enum StateLoadError {
    Io(std::io::Error),
    Decode(StateDecodeError),
}

impl std::fmt::Display for StateLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateLoadError::Io(e) => write!(f, "E/S : {e}"),
            StateLoadError::Decode(e) => write!(f, "décodage d'état : {e:?}"),
        }
    }
}
impl std::error::Error for StateLoadError {}

/// Fenêtre glissante de racines récentes acceptées.
///
/// # Pourquoi elle doit dépasser un bloc PLEIN
///
/// `remember_root` est appelé à CHAQUE insertion — donc une à deux fois par
/// transaction. Une fenêtre de 100 racines était donc entièrement purgée par
/// l'application d'un seul bloc de plus de 100 transactions.
///
/// La conséquence n'était pas théorique : un wallet s'ancre sur la racine courante,
/// puis passe ≈1,8 s à générer sa preuve. Si un bloc chargé est appliqué pendant ce
/// temps, son ancre a disparu de la fenêtre et sa transaction est refusée pour
/// « ancre inconnue » — un message qui désigne l'ancre, jamais la vraie cause. Pire,
/// n'importe qui pouvant sceller (aucune élection de producteur), un adversaire
/// purgeait la fenêtre à volonté à partir du mempool HONNÊTE, sans fabriquer une
/// seule preuve : une censure de paiements à coût de calcul nul.
///
/// Quatre blocs pleins de marge, soit ≈64 Kio de racines mémorisées.
pub const RECENT_ROOTS_WINDOW: usize = 4 * crate::bloc::MAX_TX_PAR_BLOC;

/// Une ancre doit survivre à l'application d'un bloc PLEIN, sinon les transactions en
/// vol sont refusées dès que le réseau est chargé. Consigné à la compilation : tout
/// ajustement de l'une des deux constantes qui romprait la marge casse le build.
const _: () = assert!(RECENT_ROOTS_WINDOW > crate::bloc::MAX_TX_PAR_BLOC);

/// Version du format de dump de l'état (`to_bytes`).
///
/// `0x01` : ajout du chaînage (tête + hauteur). `0x02` : l'arrivée des émissions
/// change l'encodage du bloc, donc `Bloc::id`, donc l'identifiant de la genèse VIDE
/// elle-même. La disposition des octets de l'état n'a pas bougé, mais la SIGNIFICATION
/// du champ `tete` a changé : un dump `0x01` rechargé tel quel porterait une tête que
/// plus aucun bloc ne prolonge, et le nœud refuserait tout en silence. On le refuse
/// donc explicitement plutôt que de le lire de travers.
/// `0x03` : l'identifiant de GENÈSE est gravé dans le dump — sans lui, redémarrer
/// avec une autre genèse sur un répertoire déjà peuplé passait inaperçu jusqu'au
/// premier bloc refusé, un nœud sur la mauvaise chaîne étant indiscernable d'un nœud
/// au repos.
/// `0x04` : les AUTORITÉS de scellement entrent dans le dump (élection de
/// producteur) — et `VERSION_BLOC` passant à 0x03, tous les identifiants de bloc
/// changent : un dump antérieur porte une tête périmée, refusé plutôt que relu.
pub const VERSION_ETAT: u8 = 0x04;

pub struct ProvedLedgerState {
    pub tree: MerkleFrontier,
    nullifiers: HashSet<[u8; 32]>,
    recent_roots: HashSet<[u8; 32]>,
    roots_order: VecDeque<[u8; 32]>,
    /// Identifiant du dernier bloc appliqué — la TÊTE de chaîne.
    tete: [u8; TAILLE_ID],
    /// Hauteur de cette tête (genèse = 0).
    hauteur: u64,
    /// Identifiant du bloc de GENÈSE dont cet état descend.
    ///
    /// `tete` le vaut à la hauteur 0, puis avance et l'information serait perdue.
    /// Gravé séparément parce que c'est LA question qu'un redémarrage doit pouvoir
    /// poser : « cet état appartient-il à la chaîne qu'on me demande de suivre ? »
    /// Sans ce champ, la réponse n'arrivait qu'au premier bloc refusé — en silence.
    genese: [u8; TAILLE_ID],
    /// AUTORITÉS de scellement de la chaîne, copiées de la GENÈSE à l'amorçage.
    ///
    /// Liste VIDE = chaîne OUVERTE (tout nœud peut sceller — mode testnet local) ;
    /// non vide = tour de rôle par hauteur, scellement exigé et vérifié par
    /// `appliquer_bloc`. Sérialisée dans le dump d'état : un nœud rechargé doit
    /// appliquer la même règle sans relire la genèse.
    autorites: Vec<crypto::sig::SigPublicKey>,
    /// Historique des sorties — `None` par DÉFAUT.
    ///
    /// Un `Option` et pas un champ toujours présent : l'archivage est un rôle
    /// d'opérateur, pas une obligation de consensus (cf. `crate::historique`). Le champ
    /// est privé et n'est écrit que par `amorcer` et `appliquer_bloc`, exactement là où
    /// l'arbre grandit — c'est ce qui garantit que les deux ne peuvent pas diverger.
    historique: Option<HistoriqueSorties>,
}

/// Refus d'un bloc. Distinct de `LedgerError` : un bloc peut être parfaitement formé
/// et n'être simplement pas le suivant de NOTRE chaîne.
#[derive(Debug, thiserror::Error)]
pub enum BlocRefus {
    #[error("bloc chaîné à un autre parent (notre tête n'est pas celle attendue)")]
    ParentInattendu,
    #[error("hauteur {recue} inattendue (attendue : {attendue})")]
    HauteurInattendue { attendue: u64, recue: u64 },
    #[error("bloc de {recues} transactions (borne : {borne})")]
    TropDeTransactions { borne: usize, recues: usize },
    /// Émission hors genèse : **tentative d'inflation**, à la différence des refus de
    /// chaînage qui sont le cas normal d'un nœud en retard.
    #[error("{recues} émissions à la hauteur {hauteur} : seule la genèse peut émettre")]
    EmissionHorsGenese { hauteur: u64, recues: usize },
    /// Autorités hors genèse : même nature que l'émission — aucun bloc valide n'en
    /// porte à hauteur non nulle, sur aucune chaîne.
    #[error("{recues} autorités à la hauteur {hauteur} : seule la genèse en déclare")]
    AutoritesHorsGenese { hauteur: u64, recues: usize },
    /// Chaîne à autorités, bloc NON signé : personne n'a le droit de sceller sans
    /// prouver qu'il est le producteur du tour.
    #[error("bloc de hauteur {hauteur} sans scellement : cette chaîne a des autorités")]
    ScellementManquant { hauteur: u64 },
    /// Signature absente de la BONNE clé : soit un producteur hors de son tour, soit
    /// un tiers, soit une signature altérée. Faute non équivoque dans tous les cas.
    #[error("scellement invalide à la hauteur {hauteur} (producteur attendu : n° {attendu})")]
    ScellementInvalide { hauteur: u64, attendu: usize },
    /// Chaîne OUVERTE, bloc signé : le scellement n'y a aucun sens, et l'accepter
    /// rendrait deux encodages valides pour le même bloc (canonicité).
    #[error("scellement présent sur une chaîne sans autorités")]
    ScellementInattendu,
    #[error("transaction {index} refusée : {source}")]
    Transaction {
        index: usize,
        #[source]
        source: LedgerError,
    },
}

/// Refus d'un bloc de GENÈSE (`ProvedLedgerState::depuis_genese`).
///
/// Enum distinct de `BlocRefus` à dessein : aucune de ces variantes ne peut naître
/// d'un bloc reçu du réseau, et les confondre obligerait `node::orchestration` à
/// traiter — ou pire, à oublier — des cas inatteignables.
#[derive(Debug, thiserror::Error)]
pub enum GeneseRefus {
    #[error("bloc de genèse chaîné à un parent : une genèse n'en a pas")]
    ParentPresent,
    #[error("hauteur {recue} : une genèse est à la hauteur 0")]
    HauteurNonNulle { recue: u64 },
    /// Une transaction dans la genèse ne pourrait de toute façon pas s'appliquer
    /// (aucune ancre n'existe encore). La refuser explicitement évite qu'une genèse
    /// en contienne en donnant l'illusion qu'elle sera exécutée.
    #[error("{recues} transactions dans la genèse : aucune ancre n'existe encore")]
    TransactionsPresentes { recues: usize },
    #[error("{recues} émissions dans la genèse (borne : {borne})")]
    TropDEmissions { borne: usize, recues: usize },
    #[error("{recues} autorités dans la genèse (borne : {borne})")]
    TropDAutorites { borne: usize, recues: usize },
    #[error("émission {index} refusée : {source}")]
    Emission {
        index: usize,
        #[source]
        source: LedgerError,
    },
}

impl ProvedLedgerState {
    /// État aux paramètres consensus (profondeur 32), amorcé sur la genèse VIDE.
    ///
    /// Raccourci de `depuis_genese(&Bloc::genese())` : une chaîne sans aucune monnaie
    /// préexistante. Une chaîne réelle s'amorce sur une genèse paramétrée.
    pub fn new() -> Self {
        Self::with_tree(MerkleFrontier::consensus())
    }

    /// État en profondeur `depth` sur la genèse VIDE — tests/dev uniquement.
    pub fn with_depth(depth: usize) -> Self {
        Self::with_tree(MerkleFrontier::new(depth))
    }

    /// **Amorce** l'état sur un bloc de genèse (profondeur consensus).
    ///
    /// # La genèse ne s'APPLIQUE pas, elle AMORCE
    ///
    /// Il n'y a rien à défaire ici : l'état est neuf. C'est pourquoi l'amorçage est un
    /// constructeur et non un cas particulier d'`appliquer_bloc` — l'atomicité
    /// durement acquise de cette dernière (instantané de la frontier, défaisage des
    /// nullifiers) n'a pas à être compliquée pour un cas où l'échec se traduit
    /// simplement par « pas d'état ».
    ///
    /// La tête devient l'identifiant de CETTE genèse. Deux nœuds amorcés sur des
    /// genèses différentes sont donc à la même hauteur (0) mais avec des têtes
    /// DIFFÉRENTES : leurs blocs ne s'enchaînent pas et le désaccord est visible
    /// immédiatement, au lieu d'apparaître bien plus tard sous forme d'« ancre
    /// inconnue ».
    ///
    /// Les commitments d'émission sont insérés DANS L'ORDRE du bloc : l'émission
    /// d'indice `i` occupe la feuille `i`. Un wallet qui rejoue la genèse dans cet
    /// ordre obtient les mêmes index — et sans cela, ses chemins de Merkle seraient
    /// faux sans qu'aucune erreur ne le dise.
    pub fn depuis_genese(genese: &Bloc) -> Result<Self, GeneseRefus> {
        Self::amorcer(MerkleFrontier::consensus(), genese, false)
    }

    /// Amorçage en profondeur `depth` — tests/dev uniquement.
    pub fn depuis_genese_depth(genese: &Bloc, depth: usize) -> Result<Self, GeneseRefus> {
        Self::amorcer(MerkleFrontier::new(depth), genese, false)
    }

    /// Amorce l'état en ARCHIVANT l'historique des sorties (rôle d'archiviste).
    ///
    /// L'archivage se décide à l'amorçage et nulle part ailleurs : l'activer plus tard
    /// donnerait un historique amputé de son préfixe, que rien ne pourrait reconstruire
    /// depuis la frontier — et ce trou serait invisible, puisque tous les index servis
    /// seraient simplement décalés. Voir `crate::historique` pour le coût.
    pub fn depuis_genese_archivant(genese: &Bloc) -> Result<Self, GeneseRefus> {
        Self::amorcer(MerkleFrontier::consensus(), genese, true)
    }

    /// Amorçage archivant en profondeur `depth` — tests/dev uniquement.
    pub fn depuis_genese_depth_archivant(genese: &Bloc, depth: usize) -> Result<Self, GeneseRefus> {
        Self::amorcer(MerkleFrontier::new(depth), genese, true)
    }

    fn amorcer(tree: MerkleFrontier, genese: &Bloc, archiver: bool) -> Result<Self, GeneseRefus> {
        if genese.parent != PAS_DE_PARENT {
            return Err(GeneseRefus::ParentPresent);
        }
        if genese.hauteur != 0 {
            return Err(GeneseRefus::HauteurNonNulle {
                recue: genese.hauteur,
            });
        }
        if !genese.transactions.is_empty() {
            return Err(GeneseRefus::TransactionsPresentes {
                recues: genese.transactions.len(),
            });
        }
        // Borne re-vérifiée ici : `genese_avec` la garantit pour un bloc construit
        // localement, `from_bytes` pour un bloc décodé — mais `Bloc` a des champs
        // publics, et l'amorçage est le dernier endroit où l'on peut refuser.
        if genese.emissions.len() > MAX_EMISSIONS_PAR_BLOC {
            return Err(GeneseRefus::TropDEmissions {
                borne: MAX_EMISSIONS_PAR_BLOC,
                recues: genese.emissions.len(),
            });
        }

        let mut etat = Self::with_tree(tree);
        for (index, emission) in genese.emissions.iter().enumerate() {
            // BORNES DES ENVELOPPES, re-vérifiées ici pour la même raison que le
            // compteur ci-dessus : `Bloc` a des champs publics, donc `genese_avec` et
            // `from_bytes` ne couvrent pas tous les chemins. Ce n'est pas de la
            // paranoïa décorative — une émission hors bornes archivée produirait un
            // `historique.bin` que `HistoriqueSorties::from_bytes` REFUSERAIT au
            // rechargement : un dump illisible par son propre auteur, découvert au
            // redémarrage suivant et pas avant.
            if !emission.enc_note.within_bounds() {
                return Err(GeneseRefus::Emission {
                    index,
                    source: LedgerError::Encoding,
                });
            }
            etat.mint(&emission.commitment)
                .map_err(|source| GeneseRefus::Emission { index, source })?;
        }
        // Borne re-vérifiée pour la même raison que les émissions : champs publics.
        if genese.autorites.len() > crate::bloc::MAX_AUTORITES {
            return Err(GeneseRefus::TropDAutorites {
                borne: crate::bloc::MAX_AUTORITES,
                recues: genese.autorites.len(),
            });
        }
        etat.autorites = genese.autorites.clone();
        etat.tete = genese.id();
        etat.genese = genese.id();
        etat.hauteur = 0;
        // L'historique n'est écrit qu'une fois l'amorçage RÉUSSI — un amorçage refusé
        // ne laisse pas d'état du tout, donc rien à défaire. La genèse est la première
        // tranche : ses émissions sont les feuilles 0..m, dans l'ordre du bloc.
        if archiver {
            let mut h = HistoriqueSorties::nouveau();
            let sorties: Vec<Sortie> = genese.emissions.iter().map(Sortie::from).collect();
            h.ajouter_bloc(0, sorties, etat.tree.root());
            etat.historique = Some(h);
        }
        Ok(etat)
    }

    fn with_tree(tree: MerkleFrontier) -> Self {
        let mut s = ProvedLedgerState {
            tree,
            nullifiers: HashSet::new(),
            recent_roots: HashSet::new(),
            roots_order: VecDeque::new(),
            tete: Bloc::genese().id(),
            hauteur: 0,
            genese: Bloc::genese().id(),
            autorites: Vec::new(),
            historique: None,
        };
        let root = s.tree.root();
        s.remember_root(root);
        s
    }

    fn remember_root(&mut self, root: Digest) {
        let key = root.to_bytes();
        if self.recent_roots.insert(key) {
            self.roots_order.push_back(key);
            if self.roots_order.len() > RECENT_ROOTS_WINDOW {
                if let Some(old) = self.roots_order.pop_front() {
                    self.recent_roots.remove(&old);
                }
            }
        }
    }

    /// Insère un commitment ÉMIS et retourne son index. `TreeFull` si l'arbre est
    /// saturé (2^profondeur feuilles).
    ///
    /// ⚠️ **PRIVÉE, et ce n'est pas négociable.** Son unique appelant légitime est
    /// `amorcer`, c'est-à-dire la genèse. Publique, elle était une porte de création de
    /// monnaie hors de tout bloc : la seule chose qui empêchait l'inflation était que
    /// le fraudeur divergeait (racine que personne d'autre n'a, monnaie inutilisable
    /// parce qu'invisible). C'est un accident heureux, pas une règle — et un futur
    /// appel depuis un chemin de consensus l'aurait transformé en inflation
    /// DIFFUSÉE et ACCEPTÉE par tous, sans qu'aucune erreur ne soit levée.
    fn mint(&mut self, cm: &Digest) -> Result<u64, LedgerError> {
        let idx = self.tree.append(cm).map_err(|_| LedgerError::TreeFull)?;
        let root = self.tree.root();
        self.remember_root(root);
        Ok(idx)
    }

    /// L'ancre est-elle une racine RÉCENTE acceptable ? Contrôle O(1), destiné aux
    /// filtres bon marché (mempool) qui doivent écarter une transaction AVANT la
    /// vérification STARK, bien plus coûteuse.
    pub fn anchor_connu(&self, racine: &Digest) -> bool {
        self.recent_roots.contains(&racine.to_bytes())
    }

    pub fn is_spent(&self, nullifier: &Digest) -> bool {
        self.nullifiers.contains(&nullifier.to_bytes())
    }

    /// Valide et applique une transaction PROUVÉE (règle de consensus cible).
    ///
    /// Étapes : (1) l'anchor est une racine récente ; (2) la preuve établit P1–P7 +
    /// non-rejeu (`verify_tx`) ; (3) aucun nullifier déjà dépensé, ni doublon interne ;
    /// puis application atomique (dépense des nullifiers, insertion des sorties).
    /// Retourne les index d'insertion des commitments de sortie.
    ///
    /// ⚠️ `pub(crate)` DÉLIBÉRÉMENT : son seul appelant légitime est `appliquer_bloc`.
    /// Exposée, elle serait une SECONDE porte d'insertion dans l'arbre, hors de tout
    /// bloc — un futur appel direct ferait diverger l'état de la chaîne sans qu'aucune
    /// erreur ne soit levée, et le premier symptôme serait un « ancre inconnue »
    /// inexplicable bien plus tard.
    pub(crate) fn apply_proved_tx(&mut self, tx: &ProvedTx) -> Result<Vec<u64>, LedgerError> {
        // 1. Anchor connu et récent.
        if !self.recent_roots.contains(&tx.anchor.to_bytes()) {
            return Err(LedgerError::UnknownRoot);
        }
        // 2. La preuve établit P1–P7 + liaison tx_digest contre CET anchor.
        if !verify_tx(&tx.anchor, self.tree.depth(), tx) {
            return Err(LedgerError::InvalidProof);
        }
        // 2 bis. Enveloppe d'intention : signature hybride valide sur tx_digest
        // (anti-malléabilité ; le signataire est lié dans tx_digest).
        if !sig::verify(&tx.signer, INTENT_DOMAIN, &tx.tx_digest, &tx.intent_sig) {
            return Err(LedgerError::InvalidSignature);
        }
        // 3. Nullifiers non dépensés + pas de doublon dans la tx.
        let mut seen = HashSet::new();
        for nf in &tx.nullifiers {
            let nf = nf.to_bytes();
            if self.nullifiers.contains(&nf) || !seen.insert(nf) {
                return Err(LedgerError::DoubleSpend);
            }
        }
        // 3 bis. Capacité : refuser AVANT toute mutation si les sorties ne tiennent
        // pas dans l'arbre (atomicité — les nullifiers ne sont pas encore dépensés
        // ici). À 2^32 feuilles c'est hors de portée pratique, mais on garantit qu'un
        // arbre saturé rejette proprement (`TreeFull`) au lieu de paniquer.
        let n_out = tx.output_commitments.len() as u128;
        if (self.tree.len() as u128) + n_out > (1u128 << self.tree.depth()) {
            return Err(LedgerError::TreeFull);
        }
        // Application atomique.
        for nf in &tx.nullifiers {
            self.nullifiers.insert(nf.to_bytes());
        }
        let mut indices = Vec::with_capacity(tx.output_commitments.len());
        for oc in &tx.output_commitments {
            indices.push(self.tree.append(oc).map_err(|_| LedgerError::TreeFull)?);
        }
        let root = self.tree.root();
        self.remember_root(root);
        Ok(indices)
    }

    /// Identifiant du dernier bloc appliqué (tête de chaîne).
    pub fn tete(&self) -> [u8; TAILLE_ID] {
        self.tete
    }

    /// Hauteur de la tête de chaîne (genèse = 0).
    pub fn hauteur(&self) -> u64 {
        self.hauteur
    }

    /// Identifiant du bloc de genèse dont cet état descend.
    pub fn genese_id(&self) -> [u8; TAILLE_ID] {
        self.genese
    }

    /// Autorités de scellement de la chaîne (vide = chaîne OUVERTE).
    pub fn autorites(&self) -> &[crypto::sig::SigPublicKey] {
        &self.autorites
    }

    /// Producteur LÉGITIME de la hauteur `hauteur` : tour de rôle
    /// `autorites[(hauteur − 1) mod n]`. `None` sur une chaîne ouverte, ou pour la
    /// hauteur 0 (la genèse n'a pas de producteur, elle amorce).
    pub fn producteur_attendu(&self, hauteur: u64) -> Option<&crypto::sig::SigPublicKey> {
        if self.autorites.is_empty() || hauteur == 0 {
            return None;
        }
        let i = ((hauteur - 1) % self.autorites.len() as u64) as usize;
        Some(&self.autorites[i])
    }

    /// Historique des sorties, si ce nœud tient le rôle d'archiviste.
    ///
    /// `None` est le cas NORMAL : l'archivage est optionnel, et un nœud qui rend `None`
    /// ici est parfaitement valide — il ne peut simplement pas amorcer de wallet.
    /// Aucune référence MUTABLE n'est exposée : l'historique ne doit grandir que par
    /// `appliquer_bloc`, sans quoi il pourrait présenter un ordre que l'arbre n'a
    /// jamais eu.
    pub fn historique(&self) -> Option<&HistoriqueSorties> {
        self.historique.as_ref()
    }

    /// Adopte un historique RECHARGÉ depuis le disque, après l'avoir confronté à l'état.
    ///
    /// # Ce que ce contrôle attrape
    ///
    /// L'état et l'historique sont deux fichiers, donc deux écritures : un crash entre
    /// les deux les laisse désaccordés. Un historique plus court que l'arbre servirait
    /// des index incomplets ; un historique plus LONG que l'arbre est une divergence
    /// franche (il porte des feuilles que notre chaîne n'a pas). Dans les deux cas le
    /// symptôme, sans ce contrôle, serait muet : le wallet obtiendrait des chemins de
    /// Merkle faux et ses transactions seraient refusées pour « ancre inconnue », sans
    /// que rien ne désigne l'archive.
    ///
    /// Les trois contrôles sont ceux que l'état PEUT faire : la dernière hauteur, le
    /// nombre de feuilles, et la racine de fin de bloc. Le troisième est le seul qui
    /// lie le CONTENU : deux historiques de même longueur mais d'ordre différent ont
    /// des racines différentes.
    ///
    /// ⚠️ **Aucune réparation.** L'échec ne tronque rien et n'efface rien : le bloc en
    /// trop a peut-être été relayé à tout le réseau, et les sorties d'un bloc ne se
    /// reconstruisent depuis aucun état. L'appelant journalise et tourne en mode
    /// dégradé (sans archive).
    pub fn adopter_historique(
        &mut self,
        historique: HistoriqueSorties,
    ) -> Result<(), HistoriqueDesaccord> {
        if historique.debut() != 0 {
            return Err(HistoriqueDesaccord::DebutNonNul {
                debut: historique.debut(),
            });
        }
        let derniere = historique
            .derniere_tranche()
            .ok_or(HistoriqueDesaccord::Vide)?;
        if derniere.hauteur != self.hauteur {
            return Err(HistoriqueDesaccord::Hauteur {
                etat: self.hauteur,
                historique: derniere.hauteur,
            });
        }
        if derniere.fin != self.tree.len() {
            return Err(HistoriqueDesaccord::Longueur {
                etat: self.tree.len(),
                historique: derniere.fin,
            });
        }
        if derniere.racine_apres != self.tree.root() {
            return Err(HistoriqueDesaccord::Racine {
                hauteur: derniere.hauteur,
            });
        }
        self.historique = Some(historique);
        Ok(())
    }

    /// Applique un bloc — **atomiquement** : tout ou rien.
    ///
    /// # L'atomicité n'est pas un raffinement
    ///
    /// Un bloc à moitié appliqué est pire qu'un bloc refusé : le nœud se retrouve
    /// dans un état qu'AUCUN autre nœud n'a, sans le savoir. Il refuserait alors
    /// toutes les transactions suivantes pour « ancre inconnue », et rien dans les
    /// messages d'erreur ne pointerait vers le bloc fautif.
    ///
    /// La restauration est bon marché parce que l'arbre est une frontier : la copier
    /// coûte O(profondeur), pas O(nombre de feuilles). La fenêtre de racines est
    /// bornée à `RECENT_ROOTS_WINDOW`. Seuls les nullifiers insérés sont suivis un à
    /// un — et il y en a au plus deux par transaction.
    ///
    /// # Les transactions sont appliquées DANS L'ORDRE, et l'ordre compte
    ///
    /// Une transaction peut dépenser une sortie d'une transaction plus tôt dans le
    /// même bloc : elle s'ancre alors sur une racine née à l'intérieur du bloc. Les
    /// valider toutes d'abord, puis les appliquer, rejetterait ce cas légitime.
    ///
    /// # L'ÉMISSION est refusée en premier, et c'est délibéré
    ///
    /// `hauteur > 0 ⇒ emissions.is_empty()`. Ce contrôle O(1) précède TOUT : le
    /// chaînage, l'instantané, la boucle de vérification. Placé après, un bloc de 512
    /// transactions parfaitement valides accompagnées d'une émission illégitime nous
    /// coûterait ≈2 s de vérification STARK avant le refus — un déni de service à prix
    /// d'un octet.
    ///
    /// Il précède aussi le contrôle de chaînage parce que ces deux refus ne sont pas
    /// de même nature : « ce bloc ne prolonge pas MA chaîne » est relatif à nous et
    /// n'accuse personne, tandis qu'« il crée de la monnaie hors genèse » est invalide
    /// pour TOUT LE MONDE. Répondre le second quand les deux sont vrais permet à
    /// `node::orchestration` de sanctionner l'un sans sanctionner l'autre.
    pub fn appliquer_bloc(&mut self, bloc: &Bloc) -> Result<Vec<u64>, BlocRefus> {
        if bloc.hauteur > 0 && !bloc.emissions.is_empty() {
            return Err(BlocRefus::EmissionHorsGenese {
                hauteur: bloc.hauteur,
                recues: bloc.emissions.len(),
            });
        }
        // Même nature que l'émission : des autorités hors genèse sont invalides pour
        // tout le monde, à toute hauteur, sur toute chaîne — refus AVANT le chaînage.
        if bloc.hauteur > 0 && !bloc.autorites.is_empty() {
            return Err(BlocRefus::AutoritesHorsGenese {
                hauteur: bloc.hauteur,
                recues: bloc.autorites.len(),
            });
        }
        if bloc.parent != self.tete {
            return Err(BlocRefus::ParentInattendu);
        }
        if bloc.hauteur != self.hauteur + 1 {
            return Err(BlocRefus::HauteurInattendue {
                attendue: self.hauteur + 1,
                recue: bloc.hauteur,
            });
        }
        // FRONTIÈRE DU COÛT, comme au mempool : ce contrôle O(1) sur un champ déjà
        // décodé précède l'instantané ET la boucle de vérification. Placé après, un
        // bloc de 512 transactions valides suivies d'une 513ᵉ nous coûterait ~2 s de
        // vérification STARK avant d'être refusé — un déni de service par bloc.
        if bloc.transactions.len() > crate::bloc::MAX_TX_PAR_BLOC {
            return Err(BlocRefus::TropDeTransactions {
                borne: crate::bloc::MAX_TX_PAR_BLOC,
                recues: bloc.transactions.len(),
            });
        }

        // ÉLECTION DE PRODUCTEUR — après le chaînage (un bloc d'une autre chaîne
        // tombe en `ParentInattendu`, sans accusation), avant tout coût STARK (une
        // vérification de signature contre ~4 ms × n transactions). Chaîne OUVERTE :
        // un scellement n'y a aucun sens et l'accepter donnerait deux encodages
        // valides du même bloc. Chaîne À AUTORITÉS : signature du producteur du TOUR
        // exigée — c'est ce qui fait de « qui scelle » une règle et non une course.
        match self.producteur_attendu(bloc.hauteur) {
            None => {
                if bloc.scellement.is_some() {
                    return Err(BlocRefus::ScellementInattendu);
                }
            }
            Some(attendu) => {
                if bloc.scellement.is_none() {
                    return Err(BlocRefus::ScellementManquant {
                        hauteur: bloc.hauteur,
                    });
                }
                if !bloc.verifier_scellement(attendu) {
                    let attendu = ((bloc.hauteur - 1) % self.autorites.len() as u64) as usize;
                    return Err(BlocRefus::ScellementInvalide {
                        hauteur: bloc.hauteur,
                        attendu,
                    });
                }
            }
        }

        // Instantané de ce qui n'est pas restaurable autrement (la frontier est
        // append-only : elle ne sait pas revenir en arrière).
        let arbre_avant = self.tree.clone();
        let recent_avant = self.recent_roots.clone();
        let ordre_avant = self.roots_order.clone();
        let mut nullifiers_ajoutes: Vec<[u8; 32]> = Vec::new();

        // Les sorties du bloc sont accumulées LOCALEMENT et ne rejoignent l'historique
        // qu'à la toute fin. L'atomicité de l'historique est donc STRUCTURELLE : il n'y
        // a rien à défaire, parce que rien n'est écrit avant le succès. Un historique
        // plus long que l'arbre serait une divergence silencieuse — le wallet servirait
        // des index décalés et ses chemins de Merkle seraient faux sans qu'aucune
        // erreur ne le dise.
        let mut sorties_du_bloc: Vec<Sortie> = Vec::new();

        let mut indices = Vec::new();
        for (index, tx) in bloc.transactions.iter().enumerate() {
            let avant = self.nullifiers.len();
            match self.apply_proved_tx(tx) {
                Ok(mut i) => {
                    debug_assert_eq!(self.nullifiers.len(), avant + tx.nullifiers.len());
                    nullifiers_ajoutes.extend(tx.nullifiers.iter().map(|n| n.to_bytes()));
                    if self.historique.is_some() {
                        // MÊME ORDRE que les insertions d'`apply_proved_tx`
                        // (`output_commitments` dans l'ordre) et même appariement que
                        // `tx_digest` v3 (`enc_notes[j]` ↔ `output_commitments[j]`).
                        for (oc, enc) in tx.output_commitments.iter().zip(tx.enc_notes.iter()) {
                            sorties_du_bloc.push(Sortie {
                                commitment: *oc,
                                enc_note: enc.clone(),
                            });
                        }
                    }
                    indices.append(&mut i);
                }
                Err(source) => {
                    // DÉFAISAGE : on remet exactement l'état d'avant le bloc.
                    self.tree = arbre_avant;
                    self.recent_roots = recent_avant;
                    self.roots_order = ordre_avant;
                    for nf in &nullifiers_ajoutes {
                        self.nullifiers.remove(nf);
                    }
                    return Err(BlocRefus::Transaction { index, source });
                }
            }
        }

        self.tete = bloc.id();
        self.hauteur = bloc.hauteur;
        // Seul endroit, avec `amorcer`, où l'historique est écrit — et il l'est APRÈS
        // que l'arbre a fini de bouger, donc `racine_apres` est bien la racine de fin
        // de bloc sur laquelle un wallet à jour doit s'ancrer.
        if let Some(h) = self.historique.as_mut() {
            h.ajouter_bloc(bloc.hauteur, sorties_du_bloc, self.tree.root());
        }
        Ok(indices)
    }

    /// Encodage canonique de l'état consensus (durcissement #7) : `len(tree) u32 LE
    /// ‖ tree ‖ N u64 LE ‖ nullifiers TRIÉS (32 o) ‖ M u64 LE ‖ roots_order FIFO
    /// (32 o)`. Les nullifiers sont triés (le `HashSet` n'a pas d'ordre stable) →
    /// même état ⇒ mêmes octets. `roots_order` garde son ordre FIFO (la fenêtre
    /// glissante en dépend) ; `recent_roots` est reconstruit au chargement.
    ///
    /// ⚠️ L'historique des sorties n'est **pas** ici : il a son propre dump
    /// (`HistoriqueSorties::save`) et se rattache par `adopter_historique`. Deux
    /// fichiers, donc deux écritures, donc un désaccord possible après un crash — c'est
    /// exactement ce que `adopter_historique` refuse de réparer en silence.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![VERSION_ETAT];
        // Position dans la chaîne : sans elle, un nœud redémarré aurait l'état d'une
        // chaîne mais ne saurait plus quel bloc attendre — il refuserait le suivant
        // et resterait bloqué en silence.
        b.extend_from_slice(&self.hauteur.to_le_bytes());
        b.extend_from_slice(&self.tete);
        b.extend_from_slice(&self.genese);
        let tree = self.tree.to_bytes();
        b.extend_from_slice(&(tree.len() as u32).to_le_bytes());
        b.extend_from_slice(&tree);

        let mut nfs: Vec<[u8; 32]> = self.nullifiers.iter().copied().collect();
        nfs.sort_unstable();
        b.extend_from_slice(&(nfs.len() as u64).to_le_bytes());
        for nf in &nfs {
            b.extend_from_slice(nf);
        }

        b.extend_from_slice(&(self.roots_order.len() as u64).to_le_bytes());
        for r in &self.roots_order {
            b.extend_from_slice(r);
        }

        // Autorités de scellement (0x04) : un nœud rechargé doit appliquer la même
        // règle d'élection sans relire la genèse.
        b.extend_from_slice(&(self.autorites.len() as u32).to_le_bytes());
        for pk in &self.autorites {
            let o = pk.to_bytes();
            b.extend_from_slice(&(o.len() as u32).to_le_bytes());
            b.extend_from_slice(&o);
        }
        b
    }

    /// Décode l'état depuis `to_bytes`. Curseur BORNÉ (chaque prise vérifie les
    /// octets restants) et validant — aucune panique sur fichier corrompu.
    pub fn from_bytes(b: &[u8]) -> Result<Self, StateDecodeError> {
        let mut pos = 0usize;
        fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], StateDecodeError> {
            let end = pos.checked_add(n).ok_or(StateDecodeError::TooShort)?;
            if end > b.len() {
                return Err(StateDecodeError::TooShort);
            }
            let s = &b[*pos..end];
            *pos = end;
            Ok(s)
        }

        let version = take(b, &mut pos, 1)?[0];
        if version != VERSION_ETAT {
            return Err(StateDecodeError::BadVersion(version));
        }
        let hauteur = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        let tete: [u8; TAILLE_ID] = take(b, &mut pos, TAILLE_ID)?
            .try_into()
            .map_err(|_| StateDecodeError::TooShort)?;
        let genese: [u8; TAILLE_ID] = take(b, &mut pos, TAILLE_ID)?
            .try_into()
            .map_err(|_| StateDecodeError::TooShort)?;

        let tree_len = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let tree_bytes = take(b, &mut pos, tree_len)?;
        let tree = MerkleFrontier::from_bytes(tree_bytes).map_err(StateDecodeError::BadFrontier)?;

        // BORNE AVANT ALLOCATION. `usize::try_from` ne protège de rien sur une
        // machine 64 bits : un compteur corrompu à 2^60 passe la conversion puis
        // fait PANIQUER `with_capacity` (« Hash table capacity overflow »), et le
        // nœud meurt au démarrage sur un fichier abîmé — exactement ce que la
        // discipline « borne avant allocation » du dépôt existe pour empêcher.
        //
        // La borne est NATURELLE et sans constante arbitraire : chaque entrée pèse
        // 32 octets, donc un compteur supérieur à ce que le fichier peut encore
        // contenir est faux, quelle qu'en soit la cause.
        let reste = |pos: usize| b.len().saturating_sub(pos) / 32;

        let n = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        let n = usize::try_from(n).map_err(|_| StateDecodeError::TooShort)?;
        if n > reste(pos) {
            return Err(StateDecodeError::TooShort);
        }
        let mut nullifiers = HashSet::with_capacity(n);
        for _ in 0..n {
            let d: [u8; 32] = take(b, &mut pos, 32)?.try_into().unwrap();
            nullifiers.insert(d);
        }

        let m = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
        let m = usize::try_from(m).map_err(|_| StateDecodeError::TooShort)?;
        if m > reste(pos) {
            return Err(StateDecodeError::TooShort);
        }
        let mut roots_order = VecDeque::with_capacity(m);
        let mut recent_roots = HashSet::with_capacity(m);
        for _ in 0..m {
            let d: [u8; 32] = take(b, &mut pos, 32)?.try_into().unwrap();
            roots_order.push_back(d);
            recent_roots.insert(d);
        }

        let a = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        if a > crate::bloc::MAX_AUTORITES {
            return Err(StateDecodeError::BadAutorite);
        }
        let mut autorites = Vec::with_capacity(a);
        for _ in 0..a {
            let lp = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
            if lp > crate::bloc::TAILLE_AUTORITE_MAX {
                return Err(StateDecodeError::BadAutorite);
            }
            let pk = crypto::sig::SigPublicKey::from_bytes(take(b, &mut pos, lp)?)
                .map_err(|_| StateDecodeError::BadAutorite)?;
            autorites.push(pk);
        }

        if pos != b.len() {
            return Err(StateDecodeError::TrailingBytes);
        }
        Ok(ProvedLedgerState {
            tree,
            nullifiers,
            recent_roots,
            roots_order,
            tete,
            hauteur,
            genese,
            autorites,
            // L'historique vit dans un fichier SÉPARÉ et se rattache par
            // `adopter_historique`, qui le confronte à cet état. L'embarquer ici
            // aurait forcé TOUS les nœuds à porter un dump de plusieurs Gio pour un
            // rôle qui est optionnel, et aurait changé `VERSION_ETAT`.
            historique: None,
        })
    }

    /// Sauvegarde ATOMIQUE : écrit dans `<path>.tmp` puis `rename` (aucun état à
    /// moitié écrit après un crash — `rename` est atomique sur un même système de
    /// fichiers).
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_bytes())?;
        std::fs::rename(&tmp, path)
    }

    /// Recharge un état depuis un fichier écrit par `save`.
    pub fn load(path: &std::path::Path) -> Result<Self, StateLoadError> {
        let bytes = std::fs::read(path).map_err(StateLoadError::Io)?;
        Self::from_bytes(&bytes).map_err(StateLoadError::Decode)
    }
}

impl Default for ProvedLedgerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::{prove_tx, ProvedInput, SpendNote};
    use proved_hash::domain::Domain;
    use proved_hash::felt::Felt;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    const DEPTH: usize = 4; // petit pour la vitesse (membership@32 validé ailleurs)

    /// État amorcé sur une genèse portant `cms` en émissions FACTICES (personne ne
    /// peut les déchiffrer — voir `proved_wallet::emission_factice`).
    ///
    /// Les tests qui ont besoin de notes DÉPENSABLES fournissent des commitments
    /// dont ils connaissent le témoin par ailleurs : le chiffré de l'émission ne sert
    /// alors qu'à occuper la place, ce que le consensus ne regarde pas.
    fn genese_de(cms: &[Digest], depth: usize) -> ProvedLedgerState {
        genese_de_archivant(cms, depth, false)
    }

    fn genese_de_archivant(cms: &[Digest], depth: usize, archiver: bool) -> ProvedLedgerState {
        let emissions = cms
            .iter()
            .map(crate::proved_wallet::emission_factice)
            .collect();
        let genese = crate::bloc::Bloc::genese_avec(emissions).expect("genèse bornée");
        if archiver {
            ProvedLedgerState::depuis_genese_depth_archivant(&genese, depth).expect("amorçage")
        } else {
            ProvedLedgerState::depuis_genese_depth(&genese, depth).expect("amorçage")
        }
    }

    /// Chaîne à DEUX autorités (a, b) : état amorcé sur leur genèse, profondeur 4.
    fn chaine_a_deux_autorites() -> (
        crypto::sig::SigKeypair,
        crypto::sig::SigKeypair,
        ProvedLedgerState,
    ) {
        let a = crypto::sig::SigKeypair::generate();
        let b = crypto::sig::SigKeypair::generate();
        let genese = crate::bloc::Bloc::genese_avec_autorites(
            Vec::new(),
            vec![a.public.clone(), b.public.clone()],
        )
        .expect("genèse bornée");
        let etat = ProvedLedgerState::depuis_genese_depth(&genese, DEPTH).expect("amorçage");
        (a, b, etat)
    }

    /// Chaîne À AUTORITÉS : un bloc non signé, signé hors tour ou signé par un tiers
    /// est REFUSÉ ; le bon producteur passe, et le tour TOURNE (a, b, a, …).
    #[test]
    fn scellement_exige_et_rotation_du_producteur() {
        let (a, b, mut etat) = chaine_a_deux_autorites();

        // Non signé : refusé, et l'état n'a pas bougé.
        let nu = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        assert!(matches!(
            etat.appliquer_bloc(&nu),
            Err(BlocRefus::ScellementManquant { hauteur: 1 })
        ));
        assert_eq!(etat.hauteur(), 0);

        // Signé par la MAUVAISE autorité (b, alors que la hauteur 1 revient à a).
        let mut hors_tour = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        hors_tour.signer_scellement(&b);
        assert!(matches!(
            etat.appliquer_bloc(&hors_tour),
            Err(BlocRefus::ScellementInvalide {
                hauteur: 1,
                attendu: 0
            })
        ));

        // Signé par un TIERS hors liste.
        let mut tiers = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        tiers.signer_scellement(&crypto::sig::SigKeypair::generate());
        assert!(matches!(
            etat.appliquer_bloc(&tiers),
            Err(BlocRefus::ScellementInvalide { .. })
        ));

        // Le BON producteur, trois hauteurs de suite : a (h=1), b (h=2), a (h=3).
        for (h, producteur) in [(1u64, &a), (2, &b), (3, &a)] {
            let mut bloc = crate::bloc::Bloc::sceller(&etat.tete(), h, Vec::new()).unwrap();
            bloc.signer_scellement(producteur);
            etat.appliquer_bloc(&bloc)
                .unwrap_or_else(|e| panic!("hauteur {h} par le bon producteur : {e}"));
            assert_eq!(etat.hauteur(), h);
        }
    }

    /// Chaîne OUVERTE (aucune autorité) : un bloc signé est REFUSÉ — accepter deux
    /// encodages (signé/non signé) pour le même bloc casserait la canonicité — et le
    /// comportement historique (bloc nu accepté) est inchangé.
    #[test]
    fn chaine_ouverte_refuse_un_scellement() {
        let mut etat = ProvedLedgerState::with_depth(DEPTH);
        let mut signe = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        signe.signer_scellement(&crypto::sig::SigKeypair::generate());
        assert!(matches!(
            etat.appliquer_bloc(&signe),
            Err(BlocRefus::ScellementInattendu)
        ));

        let nu = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        etat.appliquer_bloc(&nu)
            .expect("chaîne ouverte : bloc nu accepté");
    }

    /// Des AUTORITÉS hors genèse sont refusées comme une émission hors genèse :
    /// aucun bloc valide n'en porte à hauteur non nulle, sur aucune chaîne.
    #[test]
    fn autorites_hors_genese_refusees() {
        let (_a, _b, mut etat) = chaine_a_deux_autorites();
        let hostile = crate::bloc::Bloc {
            vue: 0,
            parent: etat.tete(),
            hauteur: 1,
            transactions: Vec::new(),
            emissions: Vec::new(),
            autorites: vec![crypto::sig::SigKeypair::generate().public],
            extension: Vec::new(),
            scellement: None,
        };
        assert!(matches!(
            etat.appliquer_bloc(&hostile),
            Err(BlocRefus::AutoritesHorsGenese {
                hauteur: 1,
                recues: 1
            })
        ));
    }

    /// L'état SÉRIALISÉ porte ses autorités : un nœud rechargé applique la même
    /// règle sans relire la genèse.
    #[test]
    fn letat_recharge_garde_ses_autorites() {
        let (a, _b, etat) = chaine_a_deux_autorites();
        let mut relu = ProvedLedgerState::from_bytes(&etat.to_bytes()).expect("état relisible");
        assert_eq!(
            relu.autorites().len(),
            2,
            "les autorités doivent survivre au dump"
        );

        let nu = crate::bloc::Bloc::sceller(&relu.tete(), 1, Vec::new()).unwrap();
        assert!(
            matches!(
                relu.appliquer_bloc(&nu),
                Err(BlocRefus::ScellementManquant { .. })
            ),
            "l'état rechargé doit encore exiger le scellement"
        );
        let mut bon = crate::bloc::Bloc::sceller(&relu.tete(), 1, Vec::new()).unwrap();
        bon.signer_scellement(&a);
        relu.appliquer_bloc(&bon)
            .expect("bon producteur accepté après rechargement");
    }

    /// La borne d'autorités est re-vérifiée à l'AMORÇAGE (champs publics).
    #[test]
    fn amorcage_borne_les_autorites() {
        let pk = crypto::sig::SigKeypair::generate().public;
        let hostile = crate::bloc::Bloc {
            vue: 0,
            parent: crate::bloc::PAS_DE_PARENT,
            hauteur: 0,
            transactions: Vec::new(),
            emissions: Vec::new(),
            autorites: (0..crate::bloc::MAX_AUTORITES + 1)
                .map(|_| pk.clone())
                .collect(),
            extension: Vec::new(),
            scellement: None,
        };
        assert!(matches!(
            ProvedLedgerState::depuis_genese_depth(&hostile, DEPTH),
            Err(GeneseRefus::TropDAutorites { .. })
        ));
    }

    /// Prépare un état avec 2 notes d'entrée émises et construit une tx équilibrée.
    /// Retourne (état, tx, indices d'entrée).
    fn setup() -> (ProvedLedgerState, circuit::ProvedTx) {
        setup_avec(false)
    }

    /// Idem, en choisissant si l'état tient le rôle d'archiviste.
    fn setup_avec(archiver: bool) -> (ProvedLedgerState, circuit::ProvedTx) {
        let secret = proved_hash::digest::ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());

        let n0 = SpendNote {
            value: 1_000,
            owner,
            rho: digest(20),
            r: digest(30),
        };
        let n1 = SpendNote {
            value: 500,
            owner,
            rho: digest(40),
            r: digest(50),
        };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        // La monnaie n'existe QUE par la genèse : deux émissions, insérées dans
        // l'ordre du bloc (donc index 0 et 1).
        let state = genese_de_archivant(&[cm0, cm1], DEPTH, archiver);
        // Arbre wallet parallèle : produit les chemins (le nœud n'a que la frontier,
        // qui n'expose pas `path`). Mêmes commitments, même ordre → même racine
        // (garanti par `merkle::frontier_differentiel_full_tree`), donc témoin valide.
        let mut wallet_tree = proved_hash::merkle::ProvedMerkleTree::new(DEPTH);
        wallet_tree.append(&cm0);
        wallet_tree.append(&cm1);
        debug_assert_eq!(state.tree.root(), wallet_tree.root());
        let (i0, i1) = (0u64, 1u64);
        let path0 = wallet_tree.path(i0).unwrap();
        let path1 = wallet_tree.path(i1).unwrap();

        let o0 = SpendNote {
            value: 900,
            owner: digest(60),
            rho: digest(61),
            r: digest(62),
        };
        let o1 = SpendNote {
            value: 580,
            owner: digest(70),
            rho: digest(71),
            r: digest(72),
        };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);

        let inputs = [
            ProvedInput {
                note: n0,
                path: path0,
                index: i0,
            },
            ProvedInput {
                note: n1,
                path: path1,
                index: i1,
            },
        ];
        let intent = crypto::sig::SigKeypair::generate();
        // enc_notes RÉELS chiffrés vers deux destinataires (keypairs éphémères ici — le
        // scan de bout en bout est testé par `applique_puis_scanne`). Leur binding dans
        // tx_digest v3 est ainsi exercé sur de vrais ciphertexts.
        let (r0, r1) = (
            crypto::kem::KemKeypair::generate(),
            crypto::kem::KemKeypair::generate(),
        );
        let enc_notes = [
            crate::proved_wallet::encrypt_note(&r0.public, &oc0, &o0).unwrap(),
            crate::proved_wallet::encrypt_note(&r1.public, &oc1, &o1).unwrap(),
        ];
        let (_root, tx) = prove_tx(&secret, inputs, [o0, o1], 20, &intent, enc_notes);
        (state, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn applique_une_tx_prouvee() {
        let (mut state, tx) = setup();
        // Les nullifiers ne sont pas encore dépensés.
        assert!(!state.is_spent(&tx.nullifiers[0]));
        let indices = state.apply_proved_tx(&tx).expect("tx valide");
        assert_eq!(indices.len(), 2); // 2 sorties insérées
                                      // Nullifiers désormais dépensés.
        assert!(state.is_spent(&tx.nullifiers[0]));
        assert!(state.is_spent(&tx.nullifiers[1]));
    }

    /// e2e chemin prouvé : construire → appliquer → SCANNER. Les deux destinataires
    /// retrouvent LEUR note de sortie via `scan_proved_output` sur
    /// `(output_commitments[j], enc_notes[j])` ; un non-destinataire échoue.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn applique_puis_scanne() {
        let secret = proved_hash::digest::ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let n0 = SpendNote {
            value: 1_000,
            owner,
            rho: digest(20),
            r: digest(30),
        };
        let n1 = SpendNote {
            value: 500,
            owner,
            rho: digest(40),
            r: digest(50),
        };
        let cm0 = rescue::note_commitment(n0.value, &n0.owner, &n0.rho, &n0.r);
        let cm1 = rescue::note_commitment(n1.value, &n1.owner, &n1.rho, &n1.r);

        let mut state = genese_de(&[cm0, cm1], DEPTH);
        // Arbre wallet parallèle pour les chemins (cf. `setup`).
        let mut wallet_tree = proved_hash::merkle::ProvedMerkleTree::new(DEPTH);
        wallet_tree.append(&cm0);
        wallet_tree.append(&cm1);
        let (i0, i1) = (0u64, 1u64);
        let (path0, path1) = (wallet_tree.path(i0).unwrap(), wallet_tree.path(i1).unwrap());

        // Deux destinataires avec leurs clés KEM et owners prouvés.
        let alice = crypto::kem::KemKeypair::generate();
        let bob = crypto::kem::KemKeypair::generate();
        let (owner_a, owner_b) = (digest(60), digest(70));
        let o0 = SpendNote {
            value: 900,
            owner: owner_a,
            rho: digest(61),
            r: digest(62),
        };
        let o1 = SpendNote {
            value: 580,
            owner: owner_b,
            rho: digest(71),
            r: digest(72),
        };
        let oc0 = rescue::note_commitment(o0.value, &o0.owner, &o0.rho, &o0.r);
        let oc1 = rescue::note_commitment(o1.value, &o1.owner, &o1.rho, &o1.r);

        let inputs = [
            ProvedInput {
                note: n0,
                path: path0,
                index: i0,
            },
            ProvedInput {
                note: n1,
                path: path1,
                index: i1,
            },
        ];
        let enc_notes = [
            crate::proved_wallet::encrypt_note(&alice.public, &oc0, &o0).unwrap(),
            crate::proved_wallet::encrypt_note(&bob.public, &oc1, &o1).unwrap(),
        ];
        let intent = crypto::sig::SigKeypair::generate();
        let (_root, tx) = prove_tx(
            &secret,
            inputs,
            [o0.clone(), o1.clone()],
            20,
            &intent,
            enc_notes,
        );

        state.apply_proved_tx(&tx).expect("tx valide");

        // Alice retrouve o0, Bob retrouve o1 — sur les PUBLICS de la tx (oc + enc_note).
        assert_eq!(
            crate::proved_wallet::scan_proved_output(
                &alice,
                &owner_a,
                &tx.output_commitments[0],
                &tx.enc_notes[0]
            ),
            Some(o0)
        );
        assert_eq!(
            crate::proved_wallet::scan_proved_output(
                &bob,
                &owner_b,
                &tx.output_commitments[1],
                &tx.enc_notes[1]
            ),
            Some(o1)
        );
        // Alice n'est pas destinataire de la sortie 1.
        assert_eq!(
            crate::proved_wallet::scan_proved_output(
                &alice,
                &owner_a,
                &tx.output_commitments[1],
                &tx.enc_notes[1]
            ),
            None
        );
    }

    /// Anti-substitution au NIVEAU LEDGER (relais passif) : substituer un enc_note sans
    /// re-signer casse le digest → `verify_tx` échoue → `apply_proved_tx` rejette
    /// (`InvalidProof`, avant même la vérification de signature). NB : un relais ACTIF
    /// qui re-signe avec sa propre clé produirait un substitut accepté (déni de scan) —
    /// limitation documentée (le signataire d'intention n'est pas lié au secret).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn enc_note_substitue_rejete_au_ledger() {
        let (mut state, mut tx) = setup();
        tx.enc_notes[0].enc_note = vec![0xBA, 0xD0];
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn double_depense_rejetee() {
        let (mut state, tx) = setup();
        assert!(state.apply_proved_tx(&tx).is_ok());
        // Rejouer la même tx : nullifiers déjà dépensés.
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::DoubleSpend)
        ));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn anchor_inconnu_rejete() {
        let (mut state, mut tx) = setup();
        tx.anchor = digest(123456); // racine jamais vue
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::UnknownRoot)
        ));
    }

    // En v2, les montants ne sont plus des champs publics visibles (`tx.outputs` a
    // disparu) : on ne peut plus saboter l'équilibre en mutant une valeur en clair
    // après-coup. On falsifie donc un autre public — le commitment de sortie. Cela
    // casserait AUSSI `tx_digest`, mais `verify_tx` court-circuite sur `verify_monolith`
    // AVANT la comparaison du digest : c'est donc l'assertion du monolithe (cellule
    // liée) qui rejette ici — la défense `tx_digest` n'est pas exercée par ce test.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn preuve_falsifiee_rejetee() {
        let (mut state, mut tx) = setup();
        // Sabotage d'un public de la preuve : anchor reste récent mais verify_tx échoue.
        tx.output_commitments[0] = digest(321);
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }

    /// Un nullifier ne peut pas être substitué après coup : il est asserté DANS la
    /// preuve du monolithe (cellule liée au commitment consommé) ET lié dans
    /// `tx_digest`. Le remplacer par un digest arbitraire violerait les deux, mais
    /// `verify_tx` court-circuite sur `verify_monolith` AVANT de comparer `tx_digest` :
    /// c'est donc l'assertion du monolithe qui rejette (`InvalidProof`), la défense
    /// `tx_digest` restant non exercée. Distinct de `preuve_falsifiee_rejetee` qui
    /// falsifie le commitment de sortie plutôt que le nullifier.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn nullifier_ne_peut_etre_substitue() {
        let (mut state, mut tx) = setup();
        tx.nullifiers[0] = digest(999_999);
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }

    /// Signature d'intention falsifiée (signée par une autre clé) → rejet.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn signature_intention_falsifiee_rejetee() {
        let (mut state, mut tx) = setup();
        // Signature valide MAIS d'une autre clé que `tx.signer` → verify échoue.
        let autre = crypto::sig::SigKeypair::generate();
        tx.intent_sig = autre.sign(INTENT_DOMAIN, &tx.tx_digest);
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidSignature)
        ));
    }

    /// Saturation à l'AMORÇAGE : une genèse qui émet plus de feuilles que l'arbre n'en
    /// contient est refusée par un `Result` (`TreeFull`) qui DÉSIGNE l'émission
    /// fautive, jamais par une panique. Le décodage borne le NOMBRE d'émissions, pas
    /// leur compatibilité avec la profondeur : c'est ici que ça se joue. Aucune preuve
    /// STARK ⇒ tourne en build nu (pas de `--release`).
    #[test]
    fn genese_trop_grande_pour_larbre_rend_treefull() {
        let genese = crate::bloc::Bloc::genese_avec(
            [1u64, 2, 3]
                .iter()
                .map(|s| crate::proved_wallet::emission_factice(&digest(*s)))
                .collect(),
        )
        .expect("genèse bornée");
        // 2^1 = 2 feuilles pour 3 émissions.
        assert!(matches!(
            ProvedLedgerState::depuis_genese_depth(&genese, 1),
            Err(GeneseRefus::Emission {
                index: 2,
                source: LedgerError::TreeFull
            })
        ));
    }

    /// UNE ÉMISSION HORS GENÈSE EST REFUSÉE, ET LE REFUS TOMBE AVANT LES PREUVES.
    ///
    /// C'est LA règle qui remplace la protection accidentelle d'avant : jusqu'ici rien
    /// n'interdisait de créer de la monnaie, c'est la DIVERGENCE qui punissait (racine
    /// que personne n'a). Un champ `emissions` applicable à toute hauteur aurait rendu
    /// l'inflation diffusée et ACCEPTÉE — la règle doit donc exister vraiment.
    ///
    /// Le bloc contient ici une transaction SABOTÉE en plus de l'émission : si le
    /// contrôle était placé après la boucle de vérification, on obtiendrait
    /// `Transaction { .. }` après ≈4 ms de STARK brûlées par transaction. À 512
    /// transactions valides suivies d'une émission, c'est ≈2 s offertes à l'attaquant
    /// pour un octet — le test échoue sur l'autre variante et le dit.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn emission_hors_genese_refusee_avant_toute_verification() {
        let (mut etat, mut sabotee) = setup();
        sabotee.output_commitments[0] = digest(1_234_567); // preuve invalidée
        let avant_racine = etat.tree.root();

        let mut bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, vec![sabotee]).unwrap();
        // Champs publics : on force l'émission comme le ferait un pair hostile.
        bloc.emissions = vec![crate::proved_wallet::emission_factice(&digest(5_000))];

        assert!(
            matches!(
                etat.appliquer_bloc(&bloc),
                Err(BlocRefus::EmissionHorsGenese {
                    hauteur: 1,
                    recues: 1
                })
            ),
            "le refus doit désigner l'ÉMISSION, pas la transaction : sinon le contrôle \
             O(1) est placé après la vérification STARK"
        );
        assert_eq!(etat.tree.root(), avant_racine, "aucune feuille créée");
        assert_eq!(etat.hauteur(), 0);
    }

    /// Même bloc, mais chaîné AILLEURS : le refus reste `EmissionHorsGenese`.
    ///
    /// Les deux refus ne sont pas de même nature — « ne prolonge pas ma chaîne » est
    /// relatif à nous et n'accuse personne (deux scellements simultanés), « crée de la
    /// monnaie » est invalide pour tout le monde. C'est cette priorité qui permet à
    /// `node::orchestration` de sanctionner l'un sans sanctionner l'autre ; l'inverser
    /// laisserait un émetteur frauduleux impuni en chaînant mal exprès.
    #[test]
    fn emission_prime_sur_le_refus_de_chainage() {
        let mut etat = ProvedLedgerState::with_depth(6);
        let mut bloc = crate::bloc::Bloc::sceller(&[9u8; TAILLE_ID], 1, Vec::new()).unwrap();
        bloc.emissions = vec![crate::proved_wallet::emission_factice(&digest(1))];
        assert!(matches!(
            etat.appliquer_bloc(&bloc),
            Err(BlocRefus::EmissionHorsGenese { .. })
        ));
    }

    /// DEUX NŒUDS, MÊME GENÈSE : même racine ET même tête. Genèses différentes : même
    /// hauteur (0) mais têtes DIFFÉRENTES.
    ///
    /// C'est ce qui rend l'erreur d'amorçage DÉTECTABLE. Sans la tête liée à la
    /// genèse, deux opérateurs partis de paramètres différents auraient deux nœuds
    /// « à la hauteur 0 » d'apparence saine, qui se refuseraient tous les blocs sans
    /// que rien ne désigne la cause.
    #[test]
    fn genese_identique_meme_tete_genese_differente_tetes_distinctes() {
        let cm = digest(1);
        let g1 = crate::bloc::Bloc::genese_avec(vec![crate::proved_wallet::emission_factice(&cm)])
            .unwrap();
        let a = ProvedLedgerState::depuis_genese_depth(&g1, 6).unwrap();
        let b = ProvedLedgerState::depuis_genese_depth(&g1, 6).unwrap();
        assert_eq!(a.tree.root(), b.tree.root(), "même genèse ⇒ même racine");
        assert_eq!(a.tete(), b.tete(), "même genèse ⇒ même tête");

        // Une AUTRE genèse : même commitment, mais une enveloppe factice fraîche.
        let g2 = crate::bloc::Bloc::genese_avec(vec![crate::proved_wallet::emission_factice(&cm)])
            .unwrap();
        let c = ProvedLedgerState::depuis_genese_depth(&g2, 6).unwrap();
        assert_eq!(c.hauteur(), a.hauteur(), "les deux sont à la hauteur 0");
        assert_ne!(
            c.tete(),
            a.tete(),
            "des genèses différentes doivent donner des TÊTES différentes : c'est le \
             seul signal qui distingue un nœud mal amorcé d'un nœud neuf en bonne santé"
        );
    }

    /// Une genèse à hauteur non nulle, chaînée, ou porteuse de transactions est
    /// refusée. Un bloc ordinaire passé pour une genèse amorcerait sinon un état
    /// silencieusement faux.
    #[test]
    fn genese_malformee_refusee() {
        let ordinaire = crate::bloc::Bloc::sceller(&[7u8; TAILLE_ID], 3, Vec::new()).unwrap();
        assert!(matches!(
            ProvedLedgerState::depuis_genese_depth(&ordinaire, 6),
            Err(GeneseRefus::ParentPresent)
        ));

        let mut haute = crate::bloc::Bloc::genese();
        haute.hauteur = 3;
        assert!(matches!(
            ProvedLedgerState::depuis_genese_depth(&haute, 6),
            Err(GeneseRefus::HauteurNonNulle { recue: 3 })
        ));
    }

    /// `new`/`with_depth` sont bien le raccourci de la genèse VIDE, pas un troisième
    /// point de départ. S'ils divergeaient, un nœud lancé sans `--genese` ne pourrait
    /// pas échanger de blocs avec un nœud amorcé sur `Bloc::genese()`.
    #[test]
    fn etat_neuf_egale_genese_vide() {
        let neuf = ProvedLedgerState::with_depth(6);
        let amorce =
            ProvedLedgerState::depuis_genese_depth(&crate::bloc::Bloc::genese(), 6).unwrap();
        assert_eq!(neuf.tete(), amorce.tete());
        assert_eq!(neuf.tree.root(), amorce.tree.root());
        assert_eq!(neuf.to_bytes(), amorce.to_bytes());
    }

    /// LA PROPRIÉTÉ QUI JUSTIFIE LE BLOC : deux nœuds qui appliquent la MÊME chaîne
    /// obtiennent le MÊME arbre — et deux nœuds qui appliquent les mêmes
    /// transactions dans un ORDRE différent divergent.
    ///
    /// C'est exactement pourquoi `apply_proved_tx` ne pouvait pas être appelée à la
    /// réception : le mempool est un ensemble, il n'a pas d'ordre. La seconde moitié
    /// du test montre le désastre évité — même contenu, ordre inverse, racines
    /// différentes, donc rejets mutuels pour « ancre inconnue ».
    #[test]
    fn meme_chaine_meme_arbre_ordre_different_divergence() {
        let cms: Vec<Digest> = (1..=4).map(|i| digest(i * 100)).collect();

        let mut a = ProvedLedgerState::with_depth(6);
        let mut b = ProvedLedgerState::with_depth(6);
        for cm in &cms {
            a.mint(cm).unwrap();
        }
        for cm in &cms {
            b.mint(cm).unwrap();
        }
        assert_eq!(a.tree.root(), b.tree.root(), "même ordre ⇒ même racine");

        let mut c = ProvedLedgerState::with_depth(6);
        for cm in cms.iter().rev() {
            c.mint(cm).unwrap();
        }
        assert_ne!(
            c.tree.root(),
            a.tree.root(),
            "ordre inverse ⇒ racine DIFFÉRENTE : c'est la divergence que le bloc \
             existe pour empêcher"
        );
    }

    /// Le chaînage est vérifié : un bloc dont le parent n'est pas notre tête, ou dont
    /// la hauteur saute, est refusé. Sans cela un nœud en retard accepterait un bloc
    /// du futur et perdrait définitivement les blocs intermédiaires (l'état est
    /// append-only : rien ne se rattrape).
    #[test]
    fn chainage_verifie() {
        let mut etat = ProvedLedgerState::with_depth(6);
        let genese = crate::bloc::Bloc::genese();
        assert_eq!(etat.tete(), genese.id(), "on démarre à la genèse");
        assert_eq!(etat.hauteur(), 0);

        // Bloc chaîné ailleurs.
        let orphelin = crate::bloc::Bloc::sceller(&[9u8; TAILLE_ID], 1, Vec::new()).unwrap();
        assert!(matches!(
            etat.appliquer_bloc(&orphelin),
            Err(BlocRefus::ParentInattendu)
        ));

        // Bon parent, mauvaise hauteur.
        let saute = crate::bloc::Bloc::sceller(&etat.tete(), 5, Vec::new()).unwrap();
        assert!(matches!(
            etat.appliquer_bloc(&saute),
            Err(BlocRefus::HauteurInattendue {
                attendue: 1,
                recue: 5
            })
        ));

        // Le bloc suivant, lui, passe — et la tête avance.
        let suivant = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        let id = suivant.id();
        assert!(etat.appliquer_bloc(&suivant).is_ok());
        assert_eq!(etat.tete(), id);
        assert_eq!(etat.hauteur(), 1);

        // Rejouer le même bloc est refusé : sa hauteur n'est plus la suivante.
        assert!(matches!(
            etat.appliquer_bloc(&suivant),
            Err(BlocRefus::ParentInattendu)
        ));
    }

    /// ATOMICITÉ : un bloc dont une transaction est refusée ne laisse AUCUNE trace.
    ///
    /// Un bloc à moitié appliqué placerait le nœud dans un état qu'aucun autre n'a,
    /// sans qu'il le sache : il refuserait ensuite toutes les transactions pour
    /// « ancre inconnue », sans que rien ne désigne le bloc fautif.
    ///
    /// Le bloc contient ici une transaction VALIDE suivie d'une transaction sabotée.
    /// Après le refus, l'arbre, la tête, la hauteur et les nullifiers doivent être
    /// exactement ceux d'avant.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn bloc_partiellement_invalide_ne_laisse_aucune_trace() {
        let (mut etat, tx) = setup();
        let (_autre_etat, mut sabotee) = setup();
        sabotee.output_commitments[0] = digest(1_234_567); // preuve invalidée

        let avant_racine = etat.tree.root();
        let avant_feuilles = etat.tree.len();
        let avant_tete = etat.tete();
        let avant_hauteur = etat.hauteur();
        let nf0 = tx.nullifiers[0];

        let bloc = crate::bloc::Bloc::sceller(&avant_tete, 1, vec![tx, sabotee]).unwrap();
        assert!(
            matches!(
                etat.appliquer_bloc(&bloc),
                Err(BlocRefus::Transaction { index: 1, .. })
            ),
            "le refus doit DÉSIGNER la transaction fautive"
        );

        assert_eq!(etat.tree.root(), avant_racine, "arbre restauré");
        assert_eq!(etat.tree.len(), avant_feuilles);
        assert_eq!(etat.tete(), avant_tete, "la tête n'a pas bougé");
        assert_eq!(etat.hauteur(), avant_hauteur);
        assert!(
            !etat.is_spent(&nf0),
            "le nullifier de la PREMIÈRE transaction doit être rendu : sinon ses \
             fonds seraient détruits par l'échec d'une transaction voisine"
        );
        assert!(
            !etat.anchor_connu(&digest(1_234_567)),
            "aucune racine intermédiaire ne doit subsister"
        );
    }

    /// Un bloc VALIDE applique bien ses transactions et fait avancer la tête.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn bloc_valide_applique_et_avance_la_tete() {
        let (mut etat, tx) = setup();
        let nf = tx.nullifiers[0];
        let bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, vec![tx]).unwrap();
        let id = bloc.id();

        let indices = etat.appliquer_bloc(&bloc).expect("bloc valide");
        assert_eq!(indices.len(), 2, "les 2 sorties sont insérées");
        assert!(etat.is_spent(&nf));
        assert_eq!(etat.tete(), id);
        assert_eq!(etat.hauteur(), 1);
    }

    /// Une ANCRE doit survivre à l'application d'un bloc PLEIN.
    ///
    /// `remember_root` étant appelé à chaque insertion, une fenêtre plus courte qu'un
    /// bloc était intégralement purgée par un seul bloc chargé — et la transaction
    /// qu'un wallet mettait ≈1,8 s à prouver arrivait sur une ancre morte, refusée
    /// avec un message qui désigne l'ancre et jamais la cause.
    #[test]
    fn une_ancre_survit_a_un_bloc_plein() {
        let mut etat = ProvedLedgerState::with_depth(20);
        let ancre = etat.tree.root();
        assert!(etat.anchor_connu(&ancre));

        // Autant d'insertions qu'un bloc plein en produit au maximum (2 sorties par
        // transaction), plus une marge.
        for i in 0..(crate::bloc::MAX_TX_PAR_BLOC as u64) {
            etat.mint(&digest(i * 7 + 1)).unwrap();
        }
        assert!(
            etat.anchor_connu(&ancre),
            "l'ancre d'une transaction en vol doit survivre à un bloc plein"
        );
    }

    /// Un bloc au-delà de la borne est refusé AVANT toute vérification coûteuse.
    ///
    /// Le contrôle est O(1) sur un champ déjà décodé. Placé après la boucle, un bloc
    /// de 512 transactions valides suivies d'une 513ᵉ nous aurait coûté ~2 s de
    /// vérification STARK avant le refus — un déni de service par bloc.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn bloc_hors_borne_refuse_avant_verification() {
        let (mut etat, tx) = setup();
        // Une SEULE preuve, recopiée : le refus doit tomber avant qu'on en regarde
        // une seule. Si le contrôle était mal placé, ce test échouerait sur une autre
        // variante (Transaction { .. }) plutôt que sur celle-ci — c'est ce qui le
        // rend probant.
        let octets = tx.to_bytes();
        let trop: Vec<circuit::ProvedTx> = (0..crate::bloc::MAX_TX_PAR_BLOC + 1)
            .map(|_| circuit::ProvedTx::from_bytes(&octets).unwrap())
            .collect();
        // Construction par LITTÉRAL, à dessein : `Bloc::sceller` refuserait désormais
        // ce bloc (borne dans le constructeur). Or ce test simule un bloc venu d'un
        // pair HOSTILE, qui n'emprunte évidemment pas notre constructeur — c'est le
        // chemin d'APPLICATION qu'on veut éprouver ici.
        let bloc = crate::bloc::Bloc {
            vue: 0,
            parent: etat.tete(),
            hauteur: 1,
            transactions: trop,
            emissions: Vec::new(),
            autorites: Vec::new(),
            extension: Vec::new(),
            scellement: None,
        };
        assert!(matches!(
            etat.appliquer_bloc(&bloc),
            Err(BlocRefus::TropDeTransactions { .. })
        ));
        assert_eq!(etat.hauteur(), 0, "aucune trace du bloc refusé");
    }

    /// Le PLAFOND D'OCTETS mord bien AVANT la borne de nombre : 20 transactions, soit
    /// vingt-cinq fois moins que `MAX_TX_PAR_BLOC`, suffisent déjà à dépasser le cadre
    /// réseau. C'est tout l'objet de la borne — sceller un tel bloc produirait un
    /// artefact que personne ne pourrait recevoir.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn sceller_refuse_un_bloc_trop_lourd_bien_avant_la_borne_de_nombre() {
        let (etat, tx) = setup();
        let octets = tx.to_bytes();
        let vingt: Vec<circuit::ProvedTx> = (0..20)
            .map(|_| circuit::ProvedTx::from_bytes(&octets).unwrap())
            .collect();
        assert!(
            vingt.len() < crate::bloc::MAX_TX_PAR_BLOC,
            "sous la borne de NOMBRE"
        );
        assert!(matches!(
            crate::bloc::Bloc::sceller(&etat.tete(), 1, vingt),
            Err(crate::bloc::BlocConstructionError::TropDOctets { .. })
        ));
    }

    /// La position dans la chaîne SURVIT au redémarrage. Sans elle, un nœud rechargé
    /// aurait l'état d'une chaîne sans savoir quel bloc attendre : il refuserait le
    /// suivant et resterait bloqué sans rien dire.
    #[test]
    fn position_dans_la_chaine_survit_au_dump() {
        let mut etat = ProvedLedgerState::with_depth(6);
        etat.mint(&digest(1)).unwrap();
        let bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        etat.appliquer_bloc(&bloc).unwrap();

        let recharge = ProvedLedgerState::from_bytes(&etat.to_bytes()).expect("aller-retour");
        assert_eq!(recharge.tete(), etat.tete());
        assert_eq!(recharge.hauteur(), 1);

        // Et il accepte bien la SUITE de la chaîne, pas autre chose.
        let mut recharge = recharge;
        let suivant = crate::bloc::Bloc::sceller(&recharge.tete(), 2, Vec::new()).unwrap();
        assert!(recharge.appliquer_bloc(&suivant).is_ok());
    }

    /// Un dump d'une AUTRE version est refusé, pas réinterprété. Les dumps antérieurs
    /// au chaînage n'ont pas d'octet de version : leur premier octet est lu comme tel
    /// et ne vaut pas `VERSION_ETAT`, donc ils échouent ici plutôt que d'être décalés
    /// silencieusement.
    #[test]
    fn dump_dautre_version_refuse() {
        let etat = ProvedLedgerState::with_depth(4);
        let mut octets = etat.to_bytes();
        octets[0] = 0x05; // version FUTURE
        assert!(matches!(
            ProvedLedgerState::from_bytes(&octets),
            Err(StateDecodeError::BadVersion(0x05))
        ));
        // Versions PRÉCÉDENTES : refusées aussi — le 0x02 n'a pas de genèse gravée,
        // le 0x03 pas d'autorités ; les relire décalerait les champs suivants.
        octets[0] = 0x02;
        assert!(matches!(
            ProvedLedgerState::from_bytes(&octets),
            Err(StateDecodeError::BadVersion(0x02))
        ));
        octets[0] = 0x03;
        assert!(matches!(
            ProvedLedgerState::from_bytes(&octets),
            Err(StateDecodeError::BadVersion(0x03))
        ));
        // Et un dump de la version PRÉCÉDENTE (0x01) : refusé aussi. Son champ `tete`
        // porte l'identifiant d'une genèse calculée sur l'ancien encodage de bloc ;
        // relu tel quel, le nœud attendrait un bloc que personne ne produira jamais et
        // se figerait sans rien dire.
        octets[0] = 0x01;
        assert!(matches!(
            ProvedLedgerState::from_bytes(&octets),
            Err(StateDecodeError::BadVersion(0x01))
        ));
    }

    /// Persistance (#7) : `from_bytes(to_bytes)` restaure un état au COMPORTEMENT
    /// fidèle — nullifiers dépensés, fenêtre de racines, arbre. Aucune preuve STARK
    /// ⇒ build nu.
    #[test]
    fn etat_serialisation_roundtrip_comportement() {
        let mut state = ProvedLedgerState::with_depth(8);
        state.mint(&digest(1)).unwrap();
        state.mint(&digest(2)).unwrap();
        // Simuler une dépense : marquer un nullifier (champ privé, accès module).
        state.nullifiers.insert(digest(4242).to_bytes());
        let root_courant = state.tree.root();

        let bytes = state.to_bytes();
        let reloaded = ProvedLedgerState::from_bytes(&bytes).expect("roundtrip");

        assert_eq!(reloaded.to_bytes(), bytes, "canonique (même octets)");
        assert_eq!(reloaded.tree.root(), root_courant);
        assert_eq!(reloaded.tree.len(), state.tree.len());
        assert!(reloaded.is_spent(&digest(4242)));
        // La racine courante reste dans la fenêtre (anchor accepté après rechargement).
        assert!(reloaded.recent_roots.contains(&root_courant.to_bytes()));
    }

    /// Matrice de rejet de `from_bytes` — jamais de panique.
    #[test]
    fn etat_serialisation_rejette_les_malformes() {
        let state = ProvedLedgerState::with_depth(4);
        let bytes = state.to_bytes();
        assert!(matches!(
            ProvedLedgerState::from_bytes(&bytes[..bytes.len() - 1]),
            Err(StateDecodeError::TooShort)
        ));
        let mut trailing = bytes.clone();
        trailing.push(7);
        assert!(matches!(
            ProvedLedgerState::from_bytes(&trailing),
            Err(StateDecodeError::TrailingBytes)
        ));
        assert!(matches!(
            ProvedLedgerState::from_bytes(&[]),
            Err(StateDecodeError::TooShort)
        ));
    }

    /// `save`/`load` à travers un vrai fichier temporaire : l'état rechargé égale
    /// l'original (mêmes octets). Écriture atomique (tmp + rename).
    #[test]
    fn save_load_fichier_roundtrip() {
        let mut state = ProvedLedgerState::with_depth(6);
        state.mint(&digest(11)).unwrap();
        state.mint(&digest(22)).unwrap();
        state.nullifiers.insert(digest(7).to_bytes());

        let path =
            std::env::temp_dir().join(format!("obscura_state_test_{}.bin", std::process::id()));
        state.save(&path).expect("save");
        let reloaded = ProvedLedgerState::load(&path).expect("load");
        assert_eq!(reloaded.to_bytes(), state.to_bytes());
        assert!(reloaded.is_spent(&digest(7)));
        std::fs::remove_file(&path).ok();
    }

    /// Charger un fichier absent = erreur d'E/S (pas de panique).
    #[test]
    fn load_fichier_absent_est_erreur_io() {
        let path = std::env::temp_dir().join("obscura_absent_zzz_introuvable.bin");
        std::fs::remove_file(&path).ok();
        assert!(matches!(
            ProvedLedgerState::load(&path),
            Err(StateLoadError::Io(_))
        ));
    }

    // ================================================================================
    // HISTORIQUE DES SORTIES (synchronisation wallet)
    // ================================================================================

    /// L'ORDRE DE L'HISTORIQUE EST EXACTEMENT CELUI DE L'ARBRE.
    ///
    /// C'est la seule garantie réellement vérifiable, et elle est vérifiable parce que
    /// la racine de Merkle dépend de l'ORDRE : rejouer les sorties servies dans l'ordre
    /// servi doit reproduire, tranche par tranche, les racines que le nœud a réellement
    /// eues. Deux sorties interverties dans l'historique — la faute la plus facile à
    /// commettre en refactorant `appliquer_bloc` — donneraient une racine différente
    /// dès la tranche fautive.
    ///
    /// Sans cette propriété, un wallet obtiendrait des index décalés, donc des chemins
    /// de Merkle faux, donc des transactions refusées pour « ancre inconnue » sans que
    /// rien ne désigne l'archive comme coupable.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn historique_rejoue_reproduit_larbre_et_ses_racines() {
        let (mut etat, tx) = setup_avec(true);
        let bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, vec![tx]).unwrap();
        etat.appliquer_bloc(&bloc).expect("bloc valide");

        let h = etat.historique().expect("état archiviste");
        // Un wallet part d'un arbre VIDE et n'insère que ce qu'on lui sert.
        let mut rejeu = proved_hash::merkle::ProvedMerkleTree::new(DEPTH);
        let mut vues = 0u64;
        for hauteur in 0..=etat.hauteur() {
            let tranche = h.tranche(hauteur).expect("tranche présente");
            for sortie in h.sorties_du_bloc(hauteur).expect("sorties présentes") {
                rejeu.append(&sortie.commitment);
                vues += 1;
            }
            assert_eq!(
                rejeu.root(),
                tranche.racine_apres,
                "la racine de fin de bloc {hauteur} doit être celle que le nœud a eue : \
                 c'est l'ancre que tous les wallets à jour publieront"
            );
            assert_eq!(
                vues, tranche.fin,
                "la plage annoncée doit être la plage servie"
            );
        }
        assert_eq!(
            rejeu.root(),
            etat.tree.root(),
            "arbre rejoué ≠ arbre du nœud : l'historique n'est pas dans l'ordre de l'arbre"
        );
        assert_eq!(
            h.len() as u64,
            etat.tree.len(),
            "autant d'entrées que de feuilles"
        );
    }

    /// L'HISTORIQUE D'UNE HAUTEUR EST EXACTEMENT CE QUE LE BLOC ENGAGE DÉJÀ.
    ///
    /// C'est l'argument, rendu mécanique, de la décision consignée dans
    /// `crate::historique` : `racine_apres` et `fin` n'ont pas à entrer dans
    /// `Bloc::to_bytes` (donc dans `Bloc::id`), parce que l'encodage du bloc contient
    /// déjà ses transactions entières — donc leurs `output_commitments` et `enc_notes`,
    /// dans l'ordre. Ce test compare les deux entrée par entrée : si un jour l'historique
    /// servait autre chose que ce que le bloc engage, la décision deviendrait fausse et
    /// ce test tomberait.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn historique_est_exactement_ce_que_le_bloc_engage() {
        let (mut etat, tx) = setup_avec(true);
        let bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, vec![tx]).unwrap();
        etat.appliquer_bloc(&bloc).expect("bloc valide");

        let servies = etat
            .historique()
            .expect("archiviste")
            .sorties_du_bloc(1)
            .expect("hauteur servie");
        let engagees: Vec<_> = bloc
            .transactions
            .iter()
            .flat_map(|t| t.output_commitments.iter().zip(t.enc_notes.iter()))
            .collect();

        assert_eq!(servies.len(), engagees.len());
        for (servie, (oc, enc)) in servies.iter().zip(engagees) {
            assert_eq!(servie.commitment.to_bytes(), oc.to_bytes());
            assert_eq!(servie.enc_note.kem_ct, enc.kem_ct);
            assert_eq!(servie.enc_note.enc_note, enc.enc_note);
        }
    }

    /// Même propriété pour la GENÈSE : ses émissions sont la première tranche, dans
    /// l'ordre du bloc. Sans preuve STARK, donc en build nu.
    #[test]
    fn historique_de_genese_est_exactement_les_emissions() {
        let genese = crate::bloc::Bloc::genese_avec(
            (1..=3)
                .map(|i| crate::proved_wallet::emission_factice(&digest(i * 10)))
                .collect(),
        )
        .unwrap();
        let etat = ProvedLedgerState::depuis_genese_depth_archivant(&genese, 6).unwrap();
        let servies = etat
            .historique()
            .expect("archiviste")
            .sorties_du_bloc(0)
            .expect("la genèse est la hauteur 0");
        assert_eq!(servies.len(), 3);
        for (servie, emise) in servies.iter().zip(genese.emissions.iter()) {
            assert_eq!(servie.commitment.to_bytes(), emise.commitment.to_bytes());
            assert_eq!(servie.enc_note.kem_ct, emise.enc_note.kem_ct);
            assert_eq!(servie.enc_note.enc_note, emise.enc_note.enc_note);
        }
    }

    /// ATOMICITÉ DE L'HISTORIQUE : un bloc refusé n'y laisse rien.
    ///
    /// Un historique plus long que l'arbre est une divergence SILENCIEUSE : toutes les
    /// feuilles suivantes seraient décalées d'un cran, le wallet produirait des chemins
    /// faux, et le seul symptôme serait un « ancre inconnue » inexplicable. Le bloc
    /// contient ici une transaction valide suivie d'une transaction sabotée — le cas
    /// où un défaisage partiel serait possible.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn bloc_refuse_ne_laisse_rien_dans_lhistorique() {
        let (mut etat, tx) = setup_avec(true);
        let (_autre, mut sabotee) = setup_avec(false);
        sabotee.output_commitments[0] = digest(1_234_567);

        let avant_entrees = etat.historique().unwrap().len();
        let avant_tranches = etat.historique().unwrap().nombre_de_tranches();

        let bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, vec![tx, sabotee]).unwrap();
        assert!(matches!(
            etat.appliquer_bloc(&bloc),
            Err(BlocRefus::Transaction { index: 1, .. })
        ));

        let h = etat.historique().unwrap();
        assert_eq!(h.len(), avant_entrees, "aucune sortie ne doit rester");
        assert_eq!(
            h.nombre_de_tranches(),
            avant_tranches,
            "aucune tranche en trop"
        );
        assert_eq!(
            h.derniere_tranche().unwrap().fin,
            etat.tree.len(),
            "historique et arbre doivent porter le MÊME nombre de feuilles"
        );
    }

    /// L'ARCHIVAGE NE CHANGE AUCUN OCTET DE L'ÉTAT DE CONSENSUS.
    ///
    /// C'est la contrainte de `docs/THREAT_MODEL.md` : le rôle d'archiviste est séparé
    /// et optionnel, et un nœud qui n'archive pas est VALIDE. S'il en allait autrement,
    /// deux nœuds appliquant la même chaîne divergeraient selon un choix d'opérateur —
    /// et la confidentialité deviendrait un privilège de celui qui archive.
    #[test]
    fn un_noeud_qui_narchive_pas_reste_valide_et_identique() {
        let genese = crate::bloc::Bloc::genese_avec(vec![
            crate::proved_wallet::emission_factice(&digest(1)),
            crate::proved_wallet::emission_factice(&digest(2)),
        ])
        .unwrap();

        let mut sobre = ProvedLedgerState::depuis_genese_depth(&genese, 6).unwrap();
        let mut archiviste = ProvedLedgerState::depuis_genese_depth_archivant(&genese, 6).unwrap();
        assert!(
            sobre.historique().is_none(),
            "l'archivage est OFF par défaut"
        );
        assert!(archiviste.historique().is_some());

        for hauteur in 1..=3u64 {
            let b = crate::bloc::Bloc::sceller(&sobre.tete(), hauteur, Vec::new()).unwrap();
            sobre.appliquer_bloc(&b).unwrap();
            let b = crate::bloc::Bloc::sceller(&archiviste.tete(), hauteur, Vec::new()).unwrap();
            archiviste.appliquer_bloc(&b).unwrap();
        }
        assert_eq!(
            sobre.to_bytes(),
            archiviste.to_bytes(),
            "l'archivage doit être invisible au consensus, octet pour octet"
        );
        assert!(
            sobre.historique().is_none(),
            "et il ne s'active pas tout seul"
        );
        assert_eq!(archiviste.historique().unwrap().hauteur_max(), Some(3));
    }

    /// L'HISTORIQUE SURVIT AU REDÉMARRAGE, dans son PROPRE fichier.
    ///
    /// Le dump d'état ne le porte pas : l'embarquer aurait imposé plusieurs Gio à tous
    /// les nœuds pour un rôle optionnel. Il se rattache par `adopter_historique`, qui
    /// le confronte à l'état — c'est ce raccord qui est testé ici.
    #[test]
    fn historique_survit_au_redemarrage() {
        let genese = crate::bloc::Bloc::genese_avec(vec![
            crate::proved_wallet::emission_factice(&digest(1)),
            crate::proved_wallet::emission_factice(&digest(2)),
        ])
        .unwrap();
        let mut etat = ProvedLedgerState::depuis_genese_depth_archivant(&genese, 6).unwrap();
        let bloc = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        etat.appliquer_bloc(&bloc).unwrap();

        let octets_etat = etat.to_bytes();
        let octets_hist = etat.historique().unwrap().to_bytes();

        let mut recharge = ProvedLedgerState::from_bytes(&octets_etat).expect("état relu");
        assert!(
            recharge.historique().is_none(),
            "le dump d'état ne doit PAS porter l'historique"
        );
        let hist = HistoriqueSorties::from_bytes(&octets_hist).expect("historique relu");
        recharge
            .adopter_historique(hist)
            .expect("historique concordant avec l'état");

        let h = recharge.historique().unwrap();
        assert_eq!(h.hauteur_max(), Some(1));
        assert_eq!(h.len(), 2, "les deux émissions de genèse sont là");
        assert_eq!(
            h.sorties_du_bloc(0).unwrap()[0].commitment.to_bytes(),
            digest(1).to_bytes(),
            "et dans l'ORDRE de la genèse"
        );
        assert_eq!(h.sorties_du_bloc(1).unwrap().len(), 0, "bloc 1 sans sortie");
    }

    /// UN DÉSACCORD ÉTAT/HISTORIQUE EST NOMMÉ, JAMAIS RÉPARÉ EN SILENCE.
    ///
    /// Deux fichiers, donc deux écritures : un crash entre les deux les laisse
    /// désaccordés. Tronquer pour « réparer » serait le pire choix — le bloc en trop a
    /// peut-être été relayé à tout le réseau, et les sorties d'un bloc ne se
    /// reconstruisent depuis aucun état (la frontier ne garde que le bord droit).
    ///
    /// Les trois écarts que l'état peut voir sont couverts : la HAUTEUR, le NOMBRE de
    /// feuilles, et le CONTENU (via la racine — deux historiques de même longueur mais
    /// d'ordre différent ont des racines différentes).
    #[test]
    fn historique_desaccorde_est_nomme_pas_repare() {
        let genese = crate::bloc::Bloc::genese_avec(vec![
            crate::proved_wallet::emission_factice(&digest(1)),
            crate::proved_wallet::emission_factice(&digest(2)),
        ])
        .unwrap();

        // Écart de HAUTEUR : l'historique a été écrit avant le dernier bloc.
        let vieux = ProvedLedgerState::depuis_genese_depth_archivant(&genese, 6)
            .unwrap()
            .historique()
            .unwrap()
            .to_bytes();
        let mut avance = ProvedLedgerState::depuis_genese_depth_archivant(&genese, 6).unwrap();
        let b = crate::bloc::Bloc::sceller(&avance.tete(), 1, Vec::new()).unwrap();
        avance.appliquer_bloc(&b).unwrap();
        assert!(matches!(
            avance.adopter_historique(HistoriqueSorties::from_bytes(&vieux).unwrap()),
            Err(HistoriqueDesaccord::Hauteur {
                etat: 1,
                historique: 0
            })
        ));
        assert!(
            avance.historique().is_some(),
            "l'échec d'adoption ne doit pas non plus détruire l'archive déjà en place"
        );

        // Écart de CONTENU : même hauteur, même nombre de feuilles, autres commitments.
        let autre_genese = crate::bloc::Bloc::genese_avec(vec![
            crate::proved_wallet::emission_factice(&digest(300)),
            crate::proved_wallet::emission_factice(&digest(400)),
        ])
        .unwrap();
        let etranger = ProvedLedgerState::depuis_genese_depth_archivant(&autre_genese, 6)
            .unwrap()
            .historique()
            .unwrap()
            .to_bytes();
        let mut chez_nous = ProvedLedgerState::depuis_genese_depth_archivant(&genese, 6).unwrap();
        assert!(matches!(
            chez_nous.adopter_historique(HistoriqueSorties::from_bytes(&etranger).unwrap()),
            Err(HistoriqueDesaccord::Racine { hauteur: 0 })
        ));

        // Écart de LONGUEUR : une émission de plus, à la même hauteur.
        let plus_longue = crate::bloc::Bloc::genese_avec(vec![
            crate::proved_wallet::emission_factice(&digest(1)),
            crate::proved_wallet::emission_factice(&digest(2)),
            crate::proved_wallet::emission_factice(&digest(3)),
        ])
        .unwrap();
        let trop = ProvedLedgerState::depuis_genese_depth_archivant(&plus_longue, 6)
            .unwrap()
            .historique()
            .unwrap()
            .to_bytes();
        assert!(matches!(
            chez_nous.adopter_historique(HistoriqueSorties::from_bytes(&trop).unwrap()),
            Err(HistoriqueDesaccord::Longueur {
                etat: 2,
                historique: 3
            })
        ));
    }

    /// UNE BORNE DU DÉCODAGE DOIT EXISTER AUSSI À L'AMORÇAGE.
    ///
    /// `Bloc` a des champs publics : une genèse peut être fabriquée en contournant
    /// `genese_avec` et `from_bytes`, les deux endroits qui bornaient jusqu'ici les
    /// enveloppes. Sans ce contrôle, un nœud archiviste amorcé sur une telle genèse
    /// écrirait un `historique.bin` que `HistoriqueSorties::from_bytes` refuserait —
    /// un dump illisible par son propre auteur, découvert au redémarrage suivant.
    #[test]
    fn emission_hors_bornes_refusee_a_lamorcage() {
        let mut genese = crate::bloc::Bloc::genese();
        let mut gonflee = crate::proved_wallet::emission_factice(&digest(1));
        gonflee.enc_note.enc_note = vec![0u8; circuit::tx::MAX_ENC_NOTE_LEN + 1];
        genese.emissions = vec![gonflee];

        assert!(matches!(
            ProvedLedgerState::depuis_genese_depth(&genese, 6),
            Err(GeneseRefus::Emission {
                index: 0,
                source: LedgerError::Encoding
            })
        ));
    }

    /// UN HISTORIQUE ÉLAGUÉ EST REFUSÉ TANT QUE RIEN NE SAIT RECONSTRUIRE SON PRÉFIXE.
    ///
    /// Le champ `debut` existe dès maintenant pour que l'élagage soit un changement de
    /// VALEUR et non de FORMAT. Mais l'accepter aujourd'hui donnerait à un wallet un
    /// historique amputé de son début : ses index seraient tous décalés et rien ne le
    /// lui dirait. On refuse donc explicitement, plutôt que de servir un décalage.
    #[test]
    fn historique_elague_refuse_faute_de_prefixe() {
        // Historique fabriqué à la main : `debut = 5`, une tranche vide à la hauteur 5.
        let mut b = vec![crate::historique::VERSION_HISTORIQUE];
        b.extend_from_slice(&5u64.to_le_bytes()); // debut
        b.extend_from_slice(&1u64.to_le_bytes()); // une tranche
        b.extend_from_slice(&5u64.to_le_bytes()); // hauteur
        b.extend_from_slice(&0u64.to_le_bytes()); // debut de plage
        b.extend_from_slice(&0u64.to_le_bytes()); // fin de plage
        b.extend_from_slice(&digest(1).to_bytes()); // racine
        b.extend_from_slice(&0u64.to_le_bytes()); // aucune sortie

        let elague = HistoriqueSorties::from_bytes(&b).expect("format valide");
        assert_eq!(elague.debut(), 5, "le FORMAT accepte déjà l'élagage");

        let mut etat = ProvedLedgerState::with_depth(6);
        assert!(matches!(
            etat.adopter_historique(elague),
            Err(HistoriqueDesaccord::DebutNonNul { debut: 5 })
        ));
    }

    /// Échanger le signataire casse `tx_digest` (il y est lié) → la preuve est rejetée
    /// AVANT même la signature — le signataire n'est pas échangeable.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "sous-preuves gatées : --release")]
    fn signataire_non_echangeable() {
        let (mut state, mut tx) = setup();
        tx.signer = crypto::sig::SigKeypair::generate().public;
        assert!(matches!(
            state.apply_proved_tx(&tx),
            Err(LedgerError::InvalidProof)
        ));
    }
}
