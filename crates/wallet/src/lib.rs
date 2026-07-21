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
    intent: SigKeypair,
    notes: Vec<NoteDetenue>,
    /// Arbre COMPLET : le nœud n'en a qu'une frontier, incapable de produire les
    /// chemins dont les preuves ont besoin.
    arbre: ProvedMerkleTree,
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
            intent: SigKeypair::generate(),
            notes: Vec::new(),
            arbre: ProvedMerkleTree::new(profondeur),
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

    /// Observe un commitment inséré dans l'arbre du consensus.
    ///
    /// ⚠️ Doit être appelé pour CHAQUE commitment, dans le MÊME ordre que le nœud —
    /// sinon les index divergent et les chemins produits sont invalides. C'est le
    /// prix du partage de rôles : le wallet rejoue l'arbre que le nœud ne garde pas.
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

        let (_racine, tx) = prove_tx(
            &self.secret,
            entrees,
            [sortie_paiement, sortie_monnaie],
            frais,
            &self.intent,
            enc,
        );
        Ok(tx)
    }

    fn alea(&self) -> Digest {
        Digest(core::array::from_fn(|_| {
            Felt::from_canonical_u64(OsRng.next_u64() >> 4).expect("réduit")
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFONDEUR: usize = 4;

    // `matches!` plutôt que `assert_eq!` : `ProvedTx` n'est ni `Debug` ni
    // `PartialEq` (preuve STARK, signature hybride).

    fn secret(graine: u64) -> ShieldedSecret {
        ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(graine + i as u64).unwrap()
        }))
    }

    /// Crédite `w` de deux notes, en observant les commitments comme le ferait un
    /// nœud, et retourne l'état ledger correspondant.
    fn crediter(w: &mut Wallet, a: u64, b: u64) -> ledger::proved_state::ProvedLedgerState {
        let mut etat = ledger::proved_state::ProvedLedgerState::with_depth(PROFONDEUR);
        for valeur in [a, b] {
            let note = SpendNote {
                value: valeur,
                owner: w.owner(),
                rho: w.alea(),
                r: w.alea(),
            };
            let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
            etat.mint(&cm).unwrap();
            let index = w.observer(&cm);
            w.notes.push(NoteDetenue { note, index });
        }
        etat
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
