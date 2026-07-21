//! Wallet Obscura : détention de notes, scan, construction de transactions.
//!
//! # Pourquoi le wallet tient son PROPRE arbre
//!
//! Le nœud ne conserve que le bord droit de l'arbre (`MerkleFrontier`, durcissement
//! #7) : il sait calculer la racine, mais **pas produire de chemin d'appartenance**.
//! Or prouver une dépense EXIGE ce chemin. C'est donc au wallet de maintenir un
//! `ProvedMerkleTree` complet, alimenté par les commitments qu'il observe.
//!
//! Cette répartition n'est pas un contournement : c'est le partage de rôles décidé
//! en brique frontier — le nœud tient un état borné, le wallet tient SES données.
//!
//! # Le piège de la monnaie rendue — et sa vraie forme
//!
//! Le circuit impose `Σ entrées = Σ sorties + frais` en égalité STRICTE. Un wallet
//! qui paie 300 depuis 1 500 avec 20 de frais doit produire une sortie de 1 180
//! vers lui-même.
//!
//! **Oublier cette sortie ne brûle PAS les fonds** : l'équilibre n'étant plus
//! satisfait, la transaction est INVALIDE et sera rejetée. (Vérifié : neutraliser
//! la monnaie fait échouer `verify_proved_tx_full`.) Le circuit protège donc
//! contre l'étourderie la plus grossière.
//!
//! Le vrai risque est ailleurs, et il est SILENCIEUX : verser l'excédent dans les
//! **frais** produit une transaction parfaitement VALIDE qui donne 1 180 au mineur.
//! Aucune vérification ne peut l'attraper — c'est un choix légitime du point de vue
//! du protocole. La protection ne peut donc être qu'ici, dans le wallet : `frais`
//! est un paramètre EXPLICITE, jamais un résidu calculé.
//!
//! `construire` calcule toujours la monnaie et la chiffre vers le wallet lui-même —
//! la produire sans pouvoir la déchiffrer équivaudrait à l'oublier.
//!
//! # Le signataire est PUBLIC : une clé d'intention par transaction
//!
//! `ProvedTx::signer` est un champ public, sérialisé sur le fil et lisible par tout
//! le réseau. Une clé d'intention STABLE serait donc un identifiant permanent
//! attaché à chacune de nos transactions : un observateur les relierait toutes entre
//! elles d'un simple regroupement par `signer`, sans casser la moindre primitive.
//!
//! Cela réduirait à néant, pour ce wallet, ce que le reste du protocole construit —
//! montants engagés, destinataires chiffrés, preuve witness-hiding, Dandelion++ à
//! l'émission. La chaîne de confidentialité vaut son maillon le plus faible, et un
//! pseudonyme public en clair est un maillon très faible.
//!
//! `construire` tire donc une clé d'intention NEUVE à chaque appel. C'est licite
//! parce que la signature d'intention est une **enveloppe d'anti-malléabilité**, pas
//! une autorisation de propriété : l'autorité de dépense vient du `shielded_secret`
//! prouvé dans le circuit, jamais du signataire. Rien n'a donc besoin de reconnaître
//! une clé d'intention d'une transaction à l'autre — et c'est précisément ce qui
//! permet de ne jamais la réutiliser.
//!
//! # L'ancre publiée est celle d'une FRONTIÈRE DE BLOC
//!
//! `ProvedTx::anchor` est public et vaut la racine de l'arbre du wallet, c'est-à-dire
//! sa position de synchronisation EXACTE. Un wallet arrêté au milieu d'un bloc
//! publierait donc une ancre quasi unique — le même défaut que la clé d'intention
//! stable, sous une autre forme. Le wallet mémorise le nombre de feuilles de la
//! dernière frontière de bloc adoptée (`feuilles_ancrees`) et `construire` REFUSE de
//! prouver contre un arbre qui a débordé de cette frontière. Voir [`synchro`].
//!
//! ⚠️ Portée EXACTE de la garantie : « même ancre » ne vaut qu'entre wallets
//! synchronisés à la MÊME hauteur. Un wallet EN RETARD — arrêté à un bloc ancien
//! encore dans la fenêtre d'ancres — publie la racine de fin de CE bloc-là :
//! acceptée par le consensus, mais partagée seulement par les wallets arrêtés au
//! même bloc. L'ancre partitionne donc l'ensemble d'anonymat par hauteur de
//! dernière synchronisation, en autant de seaux que la fenêtre contient de blocs.
//! Fuite ACCEPTÉE faute de mieux (bornée par la taille de la fenêtre) — la parade
//! pratique est de se resynchroniser juste avant d'émettre. Cf. THREAT_MODEL.

pub mod adresse;
pub mod persistance;
pub mod synchro;

use circuit::{prove_tx, EncNote, ProvedInput, ProvedTx, SpendNote};
use crypto::kem::{KemKeypair, KemPublicKey};
use crypto::sig::SigKeypair;
use ledger::proved_wallet::{encrypt_note, scan_proved_output};
use proved_hash::digest::{Digest, ShieldedSecret};
use proved_hash::domain::Domain;
use proved_hash::felt::Felt;
use proved_hash::merkle::ProvedMerkleTree;
use proved_hash::rescue;
use rand_core::{OsRng, RngCore};

/// Le circuit actuel est figé en 2 entrées / 2 sorties (généralisation = 3z-c2).
pub const N_ENTREES: usize = 2;

/// Borne des montants imposée par le circuit (`RANGE_BITS` = 60).
pub const MONTANT_MAX: u64 = 1 << 60;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WalletError {
    #[error("il faut exactement {N_ENTREES} notes dépensables (disponibles : {0})")]
    PasAssezDeNotes(usize),
    #[error("solde insuffisant : {disponible} disponible, {requis} requis")]
    SoldeInsuffisant { disponible: u64, requis: u64 },
    #[error("montant hors bornes du circuit (< 2^60)")]
    MontantHorsBornes,
    #[error(
        "arbre hors frontière de bloc : {feuilles} feuilles pour une ancre à {ancre} — \
         prouver ici publierait une ancre quasi unique"
    )]
    ArbreHorsFrontiereDeBloc { feuilles: u64, ancre: u64 },
}

/// Une note possédée, avec sa position dans l'arbre (indispensable au chemin).
#[derive(Clone, Debug)]
pub struct NoteDetenue {
    pub note: SpendNote,
    pub index: u64,
}

/// Adresse publique d'un destinataire : identité prouvée + clé de réception.
#[derive(Clone)]
pub struct Adresse {
    pub owner: Digest,
    pub kem: KemPublicKey,
}

pub struct Wallet {
    secret: ShieldedSecret,
    owner: Digest,
    reception: KemKeypair,
    notes: Vec<NoteDetenue>,
    /// Arbre COMPLET : le nœud n'en a qu'une frontier, incapable de produire les
    /// chemins dont les preuves ont besoin.
    arbre: ProvedMerkleTree,
    /// Prochaine hauteur de bloc à demander — LA position de synchronisation.
    ///
    /// Elle n'avance que sur une tranche COMPLÈTE de la hauteur demandée, jamais sur
    /// une `hauteur_tete` annoncée par un nœud (cf. [`synchro`]).
    prochaine_hauteur: u64,
    /// Nombre de feuilles à la dernière frontière de bloc adoptée.
    ///
    /// Séparé de `arbre.len()` À DESSEIN : la divergence des deux est exactement le cas
    /// « arbre à moitié rempli », que [`Wallet::construire`] doit refuser plutôt que
    /// d'en publier la racine comme ancre.
    feuilles_ancrees: u64,
}

impl Wallet {
    /// Nouveau wallet, secret racine tiré d'`OsRng`.
    pub fn nouveau(profondeur: usize) -> Self {
        let mut brut = [0u8; 32];
        OsRng.fill_bytes(&mut brut);
        // Réduction canonique dans le corps (chaque Felt < p).
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            let mut o = [0u8; 8];
            o.copy_from_slice(&brut[i * 8..(i + 1) * 8]);
            Felt::from_canonical_u64(u64::from_le_bytes(o) >> 4).expect("réduit")
        }));
        Self::depuis_secret(secret, profondeur)
    }

    /// Wallet déterministe à partir d'un secret donné (tests, restauration).
    pub fn depuis_secret(secret: ShieldedSecret, profondeur: usize) -> Self {
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        Wallet {
            secret,
            owner,
            reception: KemKeypair::generate(),
            notes: Vec::new(),
            arbre: ProvedMerkleTree::new(profondeur),
            prochaine_hauteur: 0,
            feuilles_ancrees: 0,
        }
    }

    /// Adresse à communiquer hors-chaîne au payeur.
    pub fn adresse(&self) -> Adresse {
        Adresse {
            owner: self.owner,
            kem: self.reception.public.clone(),
        }
    }

    pub fn owner(&self) -> Digest {
        self.owner
    }

    pub fn solde(&self) -> u64 {
        self.notes.iter().map(|n| n.note.value).sum()
    }

    pub fn notes(&self) -> &[NoteDetenue] {
        &self.notes
    }

    /// Observe un commitment inséré dans l'arbre du consensus. **Primitive de bas
    /// niveau** : le chemin normal est [`Wallet::synchroniser`].
    ///
    /// ⚠️ Doit être appelé pour CHAQUE commitment, dans le MÊME ordre que le nœud —
    /// sinon les index divergent et les chemins produits sont invalides. C'est le
    /// prix du partage de rôles : le wallet rejoue l'arbre que le nœud ne garde pas.
    ///
    /// ⚠️ **N'avance PAS l'ancre.** Rien ici ne dit qu'on se trouve sur une frontière
    /// de bloc, et c'est justement ce qu'`observer` ne peut pas savoir. Un wallet
    /// alimenté par cette porte seule verra `construire` refuser de prouver
    /// (`ArbreHorsFrontiereDeBloc`) plutôt que publier une ancre à mi-bloc.
    pub fn observer(&mut self, commitment: &Digest) -> u64 {
        self.arbre.append(commitment)
    }

    /// Racine courante de l'arbre du wallet — doit coïncider avec celle du nœud.
    pub fn racine(&self) -> Digest {
        self.arbre.root()
    }

    /// Tente de reconnaître une sortie comme nous étant destinée, et la retient.
    /// Retourne `true` si la note nous appartient.
    pub fn scanner(&mut self, commitment: &Digest, enc: &EncNote, index: u64) -> bool {
        match scan_proved_output(&self.reception, &self.owner, commitment, enc) {
            Some(note) => {
                self.notes.push(NoteDetenue { note, index });
                true
            }
            None => false,
        }
    }

    /// Construit et PROUVE une transaction payant `montant` à `destinataire`.
    ///
    /// Produit toujours DEUX sorties : le paiement, et la **monnaie rendue** vers
    /// nous-mêmes. Oublier la seconde brûlerait la différence — le circuit exige
    /// `Σ entrées = Σ sorties + frais` en égalité stricte, et n'a aucun moyen de
    /// signaler qu'on s'est spolié soi-même.
    ///
    /// ⚠️ À exécuter en `--release` (AIR du monolithe gatée).
    pub fn construire(
        &self,
        destinataire: &Adresse,
        montant: u64,
        frais: u64,
    ) -> Result<ProvedTx, WalletError> {
        if montant >= MONTANT_MAX || frais >= MONTANT_MAX {
            return Err(WalletError::MontantHorsBornes);
        }
        // L'ANCRE AVANT TOUT : `tx.anchor` est public et vaut la racine de cet arbre.
        // S'il a débordé de la dernière frontière de bloc, cette racine n'est celle
        // d'aucun autre wallet — elle nous désignerait aussi sûrement qu'un nom.
        // Refuser ici est la seule protection possible : rien, plus loin dans la
        // chaîne, ne peut distinguer une ancre à mi-bloc d'une ancre légitime.
        let feuilles = self.arbre.len() as u64;
        if feuilles != self.feuilles_ancrees {
            return Err(WalletError::ArbreHorsFrontiereDeBloc {
                feuilles,
                ancre: self.feuilles_ancrees,
            });
        }
        if self.notes.len() < N_ENTREES {
            return Err(WalletError::PasAssezDeNotes(self.notes.len()));
        }
        // Sélection : les `N_ENTREES` premières notes (une stratégie plus fine —
        // minimiser la monnaie, éviter de lier des notes — relève d'une politique
        // de confidentialité, pas de la mécanique).
        let choisies: Vec<&NoteDetenue> = self.notes.iter().take(N_ENTREES).collect();
        let disponible: u64 = choisies.iter().map(|n| n.note.value).sum();
        let requis = montant.checked_add(frais).ok_or(WalletError::MontantHorsBornes)?;
        if disponible < requis {
            return Err(WalletError::SoldeInsuffisant { disponible, requis });
        }

        // LA monnaie rendue. Son omission rendrait la transaction INVALIDE (équilibre
        // strict), pas silencieusement spoliatrice — c'est en revanche le versement
        // de l'excédent dans les FRAIS qui serait valide et coûteux, d'où `frais`
        // en paramètre explicite plutôt qu'en résidu.
        let monnaie = disponible - requis;

        let sortie_paiement = SpendNote {
            value: montant,
            owner: destinataire.owner,
            rho: self.alea(),
            r: self.alea(),
        };
        let sortie_monnaie = SpendNote {
            value: monnaie,
            owner: self.owner, // vers NOUS
            rho: self.alea(),
            r: self.alea(),
        };

        let cm_paiement = rescue::note_commitment(
            sortie_paiement.value,
            &sortie_paiement.owner,
            &sortie_paiement.rho,
            &sortie_paiement.r,
        );
        let cm_monnaie = rescue::note_commitment(
            sortie_monnaie.value,
            &sortie_monnaie.owner,
            &sortie_monnaie.rho,
            &sortie_monnaie.r,
        );

        // Chaque sortie est chiffrée vers SON destinataire — la monnaie vers notre
        // propre clé de réception, sinon nous ne pourrions pas la retrouver au scan.
        let enc = [
            encrypt_note(&destinataire.kem, &cm_paiement, &sortie_paiement),
            encrypt_note(&self.reception.public, &cm_monnaie, &sortie_monnaie),
        ];

        let entrees: [ProvedInput; N_ENTREES] = core::array::from_fn(|i| ProvedInput {
            note: choisies[i].note.clone(),
            path: self
                .arbre
                .path(choisies[i].index)
                .expect("index observé, donc dans l'arbre"),
            index: choisies[i].index,
        });

        // Clé d'intention FRAÎCHE à chaque transaction — voir « Le signataire est
        // public » en tête de module. La réutiliser lierait publiquement toutes nos
        // transactions entre elles.
        let intent = SigKeypair::generate();

        let (_racine, tx) = prove_tx(
            &self.secret,
            entrees,
            [sortie_paiement, sortie_monnaie],
            frais,
            &intent,
            enc,
        );
        Ok(tx)
    }

    /// Nullifier d'une note détenue — exactement ce que le circuit publiera si nous
    /// la dépensons : `H(nk ‖ rho ‖ cm)`, domaine `Nullifier`.
    fn nullifier(&self, note: &SpendNote) -> Digest {
        let nk = rescue::hash(Domain::Nk, self.secret.as_felts());
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        let mut payload = Vec::with_capacity(12);
        payload.extend_from_slice(&nk.0);
        payload.extend_from_slice(&note.rho.0);
        payload.extend_from_slice(&cm.0);
        rescue::hash(Domain::Nullifier, &payload)
    }

    /// Retire de notre réserve les notes que `tx` dépense. Retourne combien.
    ///
    /// La reconnaissance se fait en RECALCULANT le nullifier de chacune de nos notes
    /// et en le comparant à ceux publiés par la transaction. C'est la seule méthode
    /// correcte : les nullifiers sont opaques, et rien dans la transaction ne dit
    /// « ces entrées venaient de vous ». Elle a l'avantage de fonctionner sur
    /// N'IMPORTE quelle transaction observée, pas seulement les nôtres — donc aussi
    /// pour un wallet restauré depuis sa graine, ou dépensé depuis un autre appareil.
    ///
    /// ⚠️ Ne fait PAS rentrer la monnaie rendue. Le wallet connaît sa note de
    /// monnaie, mais pas son INDEX dans l'arbre — celui-ci n'existe qu'une fois la
    /// transaction appliquée par le consensus. La monnaie sort donc de la vue du
    /// wallet au moment de la dépense, et y revient à la SYNCHRONISATION
    /// ([`Wallet::synchroniser`]) : elle est chiffrée vers notre propre clé de
    /// réception, donc `scan_proved_output` la reconnaît comme n'importe quel
    /// paiement reçu. C'est ce qui ferme le cycle payer → recevoir, et c'est pourquoi
    /// il ne faut SURTOUT pas la recréditer ici avec un index deviné.
    pub fn oublier_depensees(&mut self, tx: &ProvedTx) -> usize {
        let publies: Vec<[u8; 32]> = tx.nullifiers.iter().map(|n| n.to_bytes()).collect();
        // Les nôtres sont calculés AVANT le `retain` : la fermeture ne peut pas
        // emprunter `self` alors qu'elle mute `self.notes`.
        let miens: Vec<bool> = self
            .notes
            .iter()
            .map(|d| publies.contains(&self.nullifier(&d.note).to_bytes()))
            .collect();
        let avant = self.notes.len();
        let mut i = 0;
        self.notes.retain(|_| {
            let garder = !miens[i];
            i += 1;
            garder
        });
        avant - self.notes.len()
    }

    fn alea(&self) -> Digest {
        Digest(core::array::from_fn(|_| {
            Felt::from_canonical_u64(OsRng.next_u64() >> 4).expect("réduit")
        }))
    }
}

/// Fabriques partagées par les tests des trois modules du crate.
#[cfg(test)]
pub(crate) mod tests_communs {
    use super::*;
    use crate::synchro::MorceauHistorique;
    use ledger::bloc::Bloc;
    use ledger::historique::Sortie;
    use ledger::proved_state::ProvedLedgerState;

    pub fn secret(graine: u64) -> ShieldedSecret {
        ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(graine + i as u64).unwrap()
        }))
    }

    /// Une GENÈSE dont les émissions vont à `w`, l'état amorcé dessus, et le lot
    /// d'historique que servirait un nœud archiviste pour cette hauteur.
    ///
    /// La monnaie n'existe plus que par la genèse : le wallet la découvre par SCAN,
    /// exactement comme un paiement reçu — c'est le même chemin, exercé au même
    /// endroit, plutôt qu'un crédit hors bande qui ne prouverait rien.
    pub fn lot_de_genese(
        w: &Wallet,
        valeurs: &[u64],
        profondeur: usize,
    ) -> (MorceauHistorique, ProvedLedgerState) {
        let emissions = valeurs
            .iter()
            .map(|valeur| {
                let note = SpendNote {
                    value: *valeur,
                    owner: w.owner(),
                    rho: w.alea(),
                    r: w.alea(),
                };
                let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
                ledger::proved_wallet::emission_vers(&w.adresse().kem, &cm, &note)
            })
            .collect();
        let genese = Bloc::genese_avec(emissions).expect("genèse bornée");
        // ARCHIVANT : c'est l'historique qui alimente le rejeu, et l'activer ne change
        // aucun octet de l'état de consensus (vérifié côté ledger).
        let etat = ProvedLedgerState::depuis_genese_depth_archivant(&genese, profondeur)
            .expect("amorçage");
        let sorties: Vec<Sortie> = genese.emissions.iter().map(Sortie::from).collect();
        (
            MorceauHistorique::bloc_entier(0, 0, etat.tree.root(), sorties),
            etat,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synchro::{MorceauHistorique, Statut};
    use crate::tests_communs::{lot_de_genese, secret};

    const PROFONDEUR: usize = 4;

    // `matches!` plutôt que `assert_eq!` : `ProvedTx` n'est ni `Debug` ni
    // `PartialEq` (preuve STARK, signature hybride).

    /// Crédite `w` par une genèse rejouée : même porte que le réseau.
    fn crediter(w: &mut Wallet, a: u64, b: u64) -> ledger::proved_state::ProvedLedgerState {
        let (lot, etat) = lot_de_genese(w, &[a, b], PROFONDEUR);
        let p = w.synchroniser(&[lot]).expect("rejeu de la genèse");
        assert_eq!(p.notes_recues, 2, "le bénéficiaire retrouve ses émissions");
        etat
    }

    /// LE BÉNÉFICIAIRE D'UNE ÉMISSION LA RETROUVE, UN TIERS NON.
    ///
    /// Une émission de genèse doit passer par le MÊME chemin de scan qu'un paiement :
    /// s'il fallait créditer le wallet hors bande, la monnaie initiale ne serait
    /// distribuable qu'à ceux qui hébergent le nœud.
    #[test]
    fn emission_de_genese_scannee_par_son_beneficiaire() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let etat = crediter(&mut w, 1_000, 500);
        assert_eq!(w.solde(), 1_500, "les deux émissions ont été reconnues");
        assert_eq!(w.racine(), etat.tree.root());

        // Un tiers rejoue la MÊME genèse : il reconstruit le même arbre (il en a
        // besoin pour ses propres chemins) mais n'y reconnaît aucune note.
        let mut autre = Wallet::depuis_secret(secret(901), PROFONDEUR);
        let (lot, etat_tiers) = lot_de_genese(&w, &[10, 20], PROFONDEUR);
        let p = autre.synchroniser(&[lot]).expect("rejeu");
        assert_eq!(
            p.notes_recues, 0,
            "une émission destinée à autrui ne doit pas créditer ce wallet"
        );
        assert_eq!(autre.solde(), 0);
        assert_eq!(
            autre.racine(),
            etat_tiers.tree.root(),
            "l'arbre est rejoué même quand rien ne nous revient"
        );
    }

    #[test]
    fn solde_et_adresse() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        assert_eq!(w.solde(), 0);
        let _ = crediter(&mut w, 1_000, 500);
        assert_eq!(w.solde(), 1_500);
        assert_eq!(w.adresse().owner, w.owner());
    }

    /// L'arbre du wallet doit produire la MÊME racine que celui du nœud — sinon les
    /// chemins seraient invalides et les preuves rejetées pour « ancre inconnue ».
    #[test]
    fn arbre_du_wallet_en_phase_avec_le_noeud() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let etat = crediter(&mut w, 1_000, 500);
        assert_eq!(
            w.racine(),
            etat.tree.root(),
            "wallet et nœud doivent voir la MÊME racine"
        );
    }

    #[test]
    fn refuse_sans_assez_de_notes() {
        let w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let dest = Wallet::depuis_secret(secret(900), PROFONDEUR).adresse();
        assert!(matches!(w.construire(&dest, 100, 10), Err(WalletError::PasAssezDeNotes(0))));
    }

    #[test]
    fn refuse_solde_insuffisant() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let _ = crediter(&mut w, 100, 50);
        let dest = Wallet::depuis_secret(secret(900), PROFONDEUR).adresse();
        assert!(matches!(w.construire(&dest, 1_000, 10), Err(WalletError::SoldeInsuffisant { disponible: 150, requis: 1_010 })));
    }

    #[test]
    fn refuse_montant_hors_bornes() {
        let w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let dest = Wallet::depuis_secret(secret(900), PROFONDEUR).adresse();
        assert!(matches!(w.construire(&dest, MONTANT_MAX, 0), Err(WalletError::MontantHorsBornes)));
    }

    /// LE PIÈGE : la monnaie rendue.
    ///
    /// On paie 300 depuis 1 500 avec 20 de frais → monnaie de 1 180 vers nous.
    ///
    /// RED vérifié en neutralisant la monnaie : la transaction devient INVALIDE
    /// (`verify_proved_tx_full` échoue), car l'équilibre strict du circuit n'est plus
    /// satisfait. L'oubli est donc rattrapé par le consensus — ce test garde surtout
    /// la seconde moitié de la propriété : la monnaie doit nous être DÉCHIFFRABLE.
    ///
    /// La produire sans pouvoir la déchiffrer nous ferait perdre les fonds tout
    /// aussi sûrement, et CELA ne serait rattrapé par aucune vérification.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn monnaie_rendue_produite_et_retrouvable() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let etat = crediter(&mut w, 1_000, 500);
        let destinataire = Wallet::depuis_secret(secret(900), PROFONDEUR);

        let tx = w
            .construire(&destinataire.adresse(), 300, 20)
            .expect("transaction constructible");

        // La transaction est valide contre l'état du nœud.
        assert!(
            circuit::verify_proved_tx_full(&etat.tree.root(), PROFONDEUR, &tx),
            "la transaction doit être valide"
        );

        // La sortie 1 est la monnaie : 1500 − 300 − 20 = 1180, et NOUS pouvons la lire.
        let retrouvee = scan_proved_output(
            &w.reception,
            &w.owner,
            &tx.output_commitments[1],
            &tx.enc_notes[1],
        );
        let note = retrouvee.expect("la monnaie doit nous être déchiffrable");
        assert_eq!(note.value, 1_180, "monnaie = disponible − montant − frais");
        assert_eq!(note.owner, w.owner(), "la monnaie revient à NOUS");
    }

    /// LIABILITÉ : deux transactions du MÊME wallet ne doivent pas partager de
    /// signataire.
    ///
    /// `tx.signer` circule en clair. S'il était stable, un observateur relierait
    /// toutes nos transactions par simple regroupement — sans casser aucune
    /// primitive, et en rendant vaines la preuve witness-hiding comme Dandelion++.
    ///
    /// RED vérifié en réutilisant une clé d'intention de wallet : les deux
    /// signataires deviennent identiques et le test échoue.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn deux_transactions_ne_partagent_pas_de_signataire() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let _ = crediter(&mut w, 1_000, 500);
        let dest = Wallet::depuis_secret(secret(900), PROFONDEUR).adresse();

        let tx1 = w.construire(&dest, 100, 10).unwrap();
        let tx2 = w.construire(&dest, 200, 10).unwrap();

        assert_ne!(
            tx1.signer.to_bytes(),
            tx2.signer.to_bytes(),
            "un signataire stable rendrait nos transactions liables entre elles"
        );
    }

    /// Après une dépense, les notes consommées quittent la réserve — reconnues par
    /// RECALCUL de leur nullifier, jamais par mémorisation de ce qu'on vient
    /// d'envoyer.
    ///
    /// Sans cela, un second paiement resélectionnerait les mêmes notes et produirait
    /// une double-dépense que le réseau rejetterait, en faisant brûler 4 ms de CPU à
    /// chaque pair au passage.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn les_notes_depensees_quittent_la_reserve() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let _ = crediter(&mut w, 1_000, 500);
        let dest = Wallet::depuis_secret(secret(900), PROFONDEUR).adresse();
        assert_eq!(w.solde(), 1_500);

        let tx = w.construire(&dest, 300, 20).unwrap();
        assert_eq!(w.oublier_depensees(&tx), 2, "les 2 entrées sont consommées");
        assert_eq!(w.solde(), 0, "la monnaie rendue n'est PAS re-créditée (index inconnu)");

        // Idempotent : rejouer la même transaction ne retire rien de plus.
        assert_eq!(w.oublier_depensees(&tx), 0);
    }

    /// Une transaction d'un AUTRE wallet ne doit rien retirer de notre réserve —
    /// sinon observer le réseau nous ferait perdre nos propres notes.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn transaction_dautrui_ne_touche_pas_notre_reserve() {
        let mut etranger = Wallet::depuis_secret(secret(900), PROFONDEUR);
        let _ = crediter(&mut etranger, 300, 200);
        let tx = etranger
            .construire(&Wallet::depuis_secret(secret(1_100), PROFONDEUR).adresse(), 50, 5)
            .unwrap();

        let mut nous = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let _ = crediter(&mut nous, 1_000, 500);
        assert_eq!(nous.oublier_depensees(&tx), 0);
        assert_eq!(nous.solde(), 1_500);
    }

    /// LE CYCLE PAYER → RECEVOIR EST FERMÉ : LA MONNAIE RENDUE REVIENT.
    ///
    /// `oublier_depensees` retire les notes consommées sans recréditer la monnaie —
    /// son index n'existe qu'une fois la transaction dans un bloc. Le wallet est donc
    /// momentanément à zéro : c'est correct, et c'était jusqu'ici DÉFINITIF. La
    /// synchronisation est ce qui la ramène, par le chemin ordinaire du scan (elle est
    /// chiffrée vers notre propre clé de réception).
    ///
    /// Sans ce test, le protocole pourrait « fonctionner » de bout en bout tout en
    /// faisant disparaître les fonds à chaque paiement — la panne la plus coûteuse
    /// imaginable, et parfaitement silencieuse.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn la_monnaie_rendue_revient_par_la_synchronisation() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot0, mut etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);
        w.synchroniser(&[lot0]).expect("genèse rejouée");
        assert_eq!(w.solde(), 1_500);

        let destinataire = Wallet::depuis_secret(secret(900), PROFONDEUR);
        let tx = w
            .construire(&destinataire.adresse(), 300, 20)
            .expect("transaction constructible");
        assert_eq!(w.oublier_depensees(&tx), 2);
        assert_eq!(w.solde(), 0, "la monnaie est hors de vue tant que le bloc n'est pas là");

        // Le nœud scelle et applique le bloc 1, ce qui inscrit les DEUX sorties dans
        // l'arbre (le paiement du destinataire et notre monnaie).
        let bloc = ledger::bloc::Bloc::sceller(&etat.tete(), 1, vec![tx]);
        etat.appliquer_bloc(&bloc).expect("bloc valide");
        let historique = etat.historique().expect("état archivant");
        let tranche = historique.tranche(1).expect("tranche du bloc 1").clone();
        let sorties = historique.sorties_du_bloc(1).expect("sorties").to_vec();
        assert_eq!(sorties.len(), 2);

        let lot1 = MorceauHistorique::bloc_entier(1, tranche.debut, tranche.racine_apres, sorties);
        let p = w.synchroniser(std::slice::from_ref(&lot1)).expect("rejeu du bloc 1");
        assert_eq!(p.notes_recues, 1, "exactement UNE note nous revient : la monnaie");
        assert_eq!(p.solde, 1_180, "1500 − 300 − 20");
        assert_eq!(w.solde(), 1_180);
        assert_eq!(w.racine(), etat.tree.root(), "ancre alignée sur le nœud");

        // L'index de la monnaie est celui du NŒUD : c'est ce qui rendra son chemin de
        // Merkle valide. Il vaut 3 (2 émissions de genèse, puis paiement, puis monnaie).
        assert_eq!(w.notes()[0].index, 3);

        // Et surtout : elle n'est pas comptée DEUX fois si le bloc revient.
        let p2 = w.synchroniser(&[lot1]).expect("livraison en double");
        assert_eq!(p2.statut, Statut::DejaApplique);
        assert_eq!(w.solde(), 1_180);
        assert_eq!(w.notes().len(), 1);
    }

    /// L'ANCRE N'EST PAS UN PSEUDONYME : deux wallets à jour en publient la MÊME.
    ///
    /// `ProvedTx::anchor` circule en clair. Si chaque wallet s'ancrait où bon lui
    /// semble — à une feuille, au milieu d'un bloc — son ancre serait quasi unique et
    /// relierait publiquement toutes ses transactions, exactement comme le ferait une
    /// clé d'intention stable. C'est la propriété qui justifie que l'unité de
    /// synchronisation soit le BLOC et non la plage de feuilles.
    ///
    /// Le test le montre là où cela compte : sur deux transactions RÉELLEMENT prouvées,
    /// par deux wallets aux notes différentes, qui ont rejoué le même historique.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn deux_wallets_a_jour_publient_la_meme_ancre() {
        let alice = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let bob = Wallet::depuis_secret(secret(900), PROFONDEUR);

        // UNE genèse, quatre émissions : deux pour chacun, entrelacées.
        let mut emissions = Vec::new();
        for (w, valeur) in [(&alice, 1_000u64), (&bob, 700), (&alice, 500), (&bob, 300)] {
            let note = SpendNote {
                value: valeur,
                owner: w.owner(),
                rho: w.alea(),
                r: w.alea(),
            };
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            emissions.push(ledger::proved_wallet::emission_vers(
                &w.adresse().kem,
                &cm,
                &note,
            ));
        }
        let genese = ledger::bloc::Bloc::genese_avec(emissions).expect("genèse bornée");
        let etat = ledger::proved_state::ProvedLedgerState::depuis_genese_depth_archivant(
            &genese, PROFONDEUR,
        )
        .expect("amorçage");
        let sorties: Vec<ledger::historique::Sortie> =
            genese.emissions.iter().map(Into::into).collect();

        let mut alice = alice;
        let mut bob = bob;
        for w in [&mut alice, &mut bob] {
            let lot = MorceauHistorique::bloc_entier(0, 0, etat.tree.root(), sorties.clone());
            w.synchroniser(&[lot]).expect("rejeu");
        }
        assert_eq!(alice.solde(), 1_500);
        assert_eq!(bob.solde(), 1_000);

        let tx_alice = alice.construire(&bob.adresse(), 100, 5).expect("tx alice");
        let tx_bob = bob.construire(&alice.adresse(), 50, 5).expect("tx bob");

        assert_eq!(
            tx_alice.anchor.to_bytes(),
            tx_bob.anchor.to_bytes(),
            "deux wallets à jour doivent être INDISCERNABLES par leur ancre"
        );
        assert_eq!(
            tx_alice.anchor.to_bytes(),
            etat.tree.root().to_bytes(),
            "et cette ancre est bien la racine de fin de bloc du nœud"
        );
    }

    /// PROUVER CONTRE UN ARBRE À MOITIÉ REMPLI EST REFUSÉ.
    ///
    /// C'est le pendant structurel du test précédent : dès qu'une feuille entre hors
    /// d'une frontière de bloc, la racine de l'arbre n'est plus celle d'aucun autre
    /// wallet. Rien en aval ne pourrait distinguer cette ancre d'une ancre légitime —
    /// la transaction serait acceptée et le pseudonyme publié pour de bon.
    #[test]
    fn construire_refuse_un_arbre_hors_frontiere_de_bloc() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let _ = crediter(&mut w, 1_000, 500);
        // Une sortie observée « en avance », avant que son bloc ne soit complet.
        w.observer(&rescue::note_commitment(1, &w.owner(), &w.owner(), &w.owner()));

        let dest = Wallet::depuis_secret(secret(900), PROFONDEUR).adresse();
        assert!(matches!(
            w.construire(&dest, 100, 10),
            Err(WalletError::ArbreHorsFrontiereDeBloc {
                feuilles: 3,
                ancre: 2
            })
        ));
    }

    /// Le destinataire retrouve SON paiement, et pas la monnaie.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuve gatée : --release")]
    fn destinataire_retrouve_son_paiement_seulement() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let _ = crediter(&mut w, 1_000, 500);
        let destinataire = Wallet::depuis_secret(secret(900), PROFONDEUR);
        let tx = w.construire(&destinataire.adresse(), 300, 20).unwrap();

        let paiement = scan_proved_output(
            &destinataire.reception,
            &destinataire.owner,
            &tx.output_commitments[0],
            &tx.enc_notes[0],
        );
        assert_eq!(paiement.map(|n| n.value), Some(300));

        // La monnaie ne lui est PAS déchiffrable (elle est chiffrée vers nous).
        assert!(
            scan_proved_output(
                &destinataire.reception,
                &destinataire.owner,
                &tx.output_commitments[1],
                &tx.enc_notes[1],
            )
            .is_none(),
            "le destinataire ne doit pas pouvoir lire notre monnaie"
        );
    }
}
