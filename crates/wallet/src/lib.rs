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

pub mod adresse;
pub mod persistance;

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

    /// Crédite directement une note possédée (émission/faucet du prototype).
    ///
    /// Réservé aux démonstrations et à l'amorçage : en fonctionnement normal, les
    /// notes arrivent par `scanner`, qui vérifie qu'elles nous sont bien destinées.
    pub fn crediter_pour_demo(&mut self, note: SpendNote, commitment: &Digest) -> u64 {
        let index = self.observer(commitment);
        self.notes.push(NoteDetenue { note, index });
        index
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
    /// transaction appliquée par le consensus, et rien ne le lui rapporte
    /// aujourd'hui. Tant que la synchronisation wallet ↔ nœud n'existe pas, dépenser
    /// fait donc DISPARAÎTRE la monnaie de la vue du wallet. C'est une limite du
    /// protocole, pas de cette fonction, et l'appelant doit le dire à l'utilisateur.
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
