//! REJEU de l'historique des sorties : ce qui permet enfin au wallet de RECEVOIR.
//!
//! Le nœud conserve (`ledger::historique`) et sert (`node::synchro`) les sorties
//! insérées dans l'arbre, dans l'ordre, découpées par BLOC. Ce module est l'autre
//! moitié : le wallet les rejoue, retrouve les INDEX de ses notes — sans lesquels
//! aucun chemin de Merkle, donc aucune dépense — et adopte l'ancre du bloc.
//!
//! # L'invariant d'ordre est STRUCTUREL, pas documenté
//!
//! Rejouer les sorties dans un ordre différent de celui du nœud ne produit aucune
//! erreur : cela produit d'AUTRES INDEX, donc d'autres chemins, donc des preuves que
//! le réseau refuse pour « ancre inconnue » sans jamais dire pourquoi. C'est la panne
//! silencieuse la plus coûteuse de tout le protocole.
//!
//! Le wallet mémorise donc sa position ([`Wallet::prochaine_hauteur`]) et REFUSE tout
//! lot qui ne commence pas exactement là où il s'est arrêté — dans les DEUX dimensions,
//! la hauteur et la feuille. Un trou de bloc et un décalage de feuilles sont deux
//! erreurs distinctes et nommées, jamais un silence.
//!
//! # L'unité appliquée est le BLOC ENTIER, jamais un morceau
//!
//! [`Wallet::synchroniser`] reçoit TOUS les morceaux d'une hauteur d'un coup. Il n'y a
//! aucun tampon de morceaux partiels dans le wallet, et c'est délibéré : un tampon
//! serait un état à moitié appliqué qu'il faudrait persister, et un wallet rechargé au
//! milieu d'un bloc s'ancrerait au milieu d'un bloc. Une synchronisation interrompue
//! (morceaux manquants) est donc simplement un lot INCOMPLET : refusé, rien n'est
//! appliqué, le wallet reste exactement où il était.
//!
//! Les morceaux sont RANGÉS par leur index, jamais concaténés dans l'ordre d'arrivée :
//! ils arrivent dans l'ordre sur une session TCP donnée, mais rien dans le format ne
//! l'impose, et un simple `extend` ferait dépendre l'index de nos notes de l'ordre
//! d'arrivée des paquets.
//!
//! # `hauteur_tete` est ABSENTE de ce module
//!
//! La réponse du nœud porte sa hauteur de tête ; le type rejoué ici ne la porte pas.
//! C'est la forme la plus forte de l'invariant « `hauteur_tete` ne pilote rien » : elle
//! n'est pas *ignorée* par la logique de rejeu, elle lui est structurellement
//! inaccessible. La position n'avance que sur la tranche DEMANDÉE, et un nœud qui
//! annonce une tête gonflée ne peut au pire que provoquer une requête sans réponse.
//!
//! # ⚠️ Ce que le rejeu ne vérifie PAS
//!
//! La racine reconstruite est confrontée à celle que le nœud ANNONCE (`racine_apres`).
//! Cela attrape un historique incohérent avec lui-même, pas un nœud qui ment de façon
//! cohérente : taire une sortie donne une chaîne parfaitement close dont la racine est
//! celle qu'il annonce, et le paiement omis reste invisible. Fermer ce trou exige des
//! identifiants de blocs venus d'AILLEURS (plusieurs nœuds, point de contrôle hors
//! bande) — cf. docs/THREAT_MODEL.md, « mentir par omission ».

use crate::Wallet;
use ledger::historique::Sortie;
use proved_hash::digest::Digest;

/// UN morceau de la tranche d'un bloc, tel que le wallet le rejoue.
///
/// Miroir de `node::synchro::ReponseHistorique` **moins `hauteur_tete`** (cf. tête de
/// module) : le crate `wallet` ne peut pas dépendre de `node`, qui dépend de lui, et
/// cette séparation a l'avantage de rendre le rejeu testable sans réseau.
///
/// Ni `Debug` ni `PartialEq` : il porte des `EncNote`.
#[derive(Clone)]
pub struct MorceauHistorique {
    /// Hauteur du bloc servi.
    pub hauteur: u64,
    /// Index absolu de la première feuille DU BLOC (inclus).
    pub debut: u64,
    /// Index absolu de fin DU BLOC (exclu).
    pub fin: u64,
    /// Racine de l'arbre après application complète du bloc — l'ancre à adopter.
    pub racine_apres: Digest,
    /// Index de ce morceau (0-based).
    pub morceau: u32,
    /// Nombre total de morceaux du bloc. Toujours ≥ 1.
    pub morceaux: u32,
    /// Index absolu de la première sortie DE CE MORCEAU.
    pub decalage: u64,
    /// Les sorties de ce morceau, dans l'ordre d'insertion.
    pub sorties: Vec<Sortie>,
}

impl MorceauHistorique {
    /// Un bloc tenant en UN morceau (genèse de test, bloc court, amorçage local).
    ///
    /// Porte les mêmes invariants que ce que `synchroniser` vérifie — `fin` et
    /// `decalage` sont DÉRIVÉS ici plutôt que fournis, pour qu'un appelant local ne
    /// puisse pas fabriquer un lot que le rejeu refusera.
    pub fn bloc_entier(
        hauteur: u64,
        debut: u64,
        racine_apres: Digest,
        sorties: Vec<Sortie>,
    ) -> Self {
        MorceauHistorique {
            hauteur,
            debut,
            fin: debut.saturating_add(sorties.len() as u64),
            racine_apres,
            morceau: 0,
            morceaux: 1,
            decalage: debut,
            sorties,
        }
    }
}

/// Ce qui a mal tourné pendant un rejeu.
///
/// Chaque variante est NOMMÉE : le lot vient du réseau, et « nœud en retard »,
/// « nœud bogué » et « nœud hostile » ne doivent pas se confondre entre eux, ni avec
/// un silence.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SynchroError {
    #[error("lot vide : aucun morceau à rejouer")]
    LotVide,
    #[error("morceaux incohérents entre eux (hauteur, plage, racine ou index dupliqué)")]
    MorceauxIncoherents,
    #[error("lot incomplet : {recus} morceaux reçus sur {attendus} annoncés")]
    LotIncomplet { recus: usize, attendus: u32 },
    #[error("plage de bloc inversée ({debut} > {fin})")]
    PlageInversee { debut: u64, fin: u64 },
    #[error("découpage non contigu : morceau à {recu}, {attendu} attendu")]
    DecoupageNonContigu { recu: u64, attendu: u64 },
    #[error("hauteur hors séquence : {recue} reçue, {attendue} attendue")]
    HauteurHorsSequence { recue: u64, attendue: u64 },
    #[error("feuille hors séquence : le lot débute à {recue}, {attendue} attendue")]
    FeuilleHorsSequence { recue: u64, attendue: u64 },
    #[error("arbre du wallet plein : {feuilles} feuilles, {ajout} à insérer")]
    ArbrePlein { feuilles: u64, ajout: u64 },
    #[error("index divergent : {rendu} rendu par l'arbre, {attendu} annoncé par le lot")]
    IndexDivergent { rendu: u64, attendu: u64 },
    #[error("racine reconstruite différente de celle annoncée à la hauteur {hauteur}")]
    RacineDesaccord { hauteur: u64 },
}

/// Ce qu'un lot a fait au wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Statut {
    /// Le bloc a été rejoué : la position a avancé.
    Applique,
    /// Le bloc était DÉJÀ rejoué (livraison en double) : rien n'a bougé.
    ///
    /// C'est un résultat explicite, pas un silence — l'appelant doit pouvoir
    /// distinguer « j'ai avancé » de « on m'a redonné le passé », sans quoi une boucle
    /// de synchronisation croirait progresser.
    DejaApplique,
}

/// Résultat d'un rejeu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progression {
    pub statut: Statut,
    /// Hauteur du bloc concerné.
    pub hauteur: u64,
    /// Nombre de sorties réellement rejouées (0 si déjà appliqué).
    pub entrees: u64,
    /// Notes RECONNUES comme nôtres dans ce lot.
    pub notes_recues: usize,
    /// Solde après rejeu.
    pub solde: u64,
    /// Prochaine hauteur à demander.
    pub prochaine_hauteur: u64,
}

impl Wallet {
    /// Prochaine hauteur à demander au nœud. C'est LA position de synchronisation.
    pub fn prochaine_hauteur(&self) -> u64 {
        self.prochaine_hauteur
    }

    /// Nombre de feuilles à la dernière FRONTIÈRE DE BLOC adoptée.
    ///
    /// Redondant avec `arbre.len()` tant que rien n'ajoute de feuille hors rejeu — et
    /// c'est précisément la redondance qui fait de l'ancre une garantie vérifiable :
    /// voir [`Wallet::construire`].
    pub fn feuilles_ancrees(&self) -> u64 {
        self.feuilles_ancrees
    }

    /// Rejoue UN bloc de l'historique, donné par TOUS ses morceaux.
    ///
    /// Ordre des contrôles = ordre du coût, comme partout dans le projet : cohérence
    /// interne des morceaux (O(k)), puis séquence, puis reconstruction de l'arbre, puis
    /// vérification de la racine — et le SCAN (une décapsulation KEM hybride par
    /// sortie, de loin le plus cher) seulement une fois la racine acceptée. Un nœud
    /// hostile ne peut donc pas nous faire brûler des décapsulations avec un lot qui ne
    /// tient pas debout.
    ///
    /// L'application est ATOMIQUE : si la racine reconstruite diffère de celle
    /// annoncée, l'arbre est ramené à son préfixe exact et aucune note n'est retenue.
    pub fn synchroniser(
        &mut self,
        morceaux: &[MorceauHistorique],
    ) -> Result<Progression, SynchroError> {
        let premier = morceaux.first().ok_or(SynchroError::LotVide)?;
        let (hauteur, debut, fin) = (premier.hauteur, premier.debut, premier.fin);
        let attendus = premier.morceaux;

        // 1. Les morceaux décrivent-ils tous LE MÊME bloc ?
        for m in morceaux {
            if m.hauteur != hauteur
                || m.debut != debut
                || m.fin != fin
                || m.racine_apres != premier.racine_apres
                || m.morceaux != attendus
            {
                return Err(SynchroError::MorceauxIncoherents);
            }
        }
        if fin < debut {
            return Err(SynchroError::PlageInversee { debut, fin });
        }

        // 2. Séquence. Un bloc DÉJÀ rejoué est une livraison en double : on ne le
        //    réapplique pas (les index se décaleraient) et on le dit explicitement.
        //    Un bloc du FUTUR est un TROU : le refuser est ce qui empêche le wallet
        //    d'insérer des feuilles à la mauvaise place.
        if hauteur < self.prochaine_hauteur {
            return Ok(Progression {
                statut: Statut::DejaApplique,
                hauteur,
                entrees: 0,
                notes_recues: 0,
                solde: self.solde(),
                prochaine_hauteur: self.prochaine_hauteur,
            });
        }
        if hauteur > self.prochaine_hauteur {
            return Err(SynchroError::HauteurHorsSequence {
                recue: hauteur,
                attendue: self.prochaine_hauteur,
            });
        }
        let feuilles = self.arbre.len() as u64;
        if debut != feuilles {
            return Err(SynchroError::FeuilleHorsSequence {
                recue: debut,
                attendue: feuilles,
            });
        }

        // 3. Le lot est-il COMPLET ? Le nombre de morceaux reçus borne l'allocation du
        //    rangement : on ne réserve jamais d'après un champ du réseau.
        if attendus == 0 || morceaux.len() != attendus as usize {
            return Err(SynchroError::LotIncomplet {
                recus: morceaux.len(),
                attendus,
            });
        }
        // 4. RANGEMENT par index de morceau — jamais une concaténation dans l'ordre
        //    d'arrivée. Comptes égaux + indices dans les bornes + aucun doublon ⇒ tous
        //    les index sont présents exactement une fois (principe des tiroirs).
        let mut ordre: Vec<Option<&MorceauHistorique>> = vec![None; morceaux.len()];
        for m in morceaux {
            let rang = usize::try_from(m.morceau).map_err(|_| SynchroError::MorceauxIncoherents)?;
            let place = ordre
                .get_mut(rang)
                .ok_or(SynchroError::MorceauxIncoherents)?;
            if place.is_some() {
                return Err(SynchroError::MorceauxIncoherents);
            }
            *place = Some(m);
        }

        // 5. Le découpage couvre-t-il le bloc exactement, sans trou ni recouvrement ?
        //    Vérifié par CUMUL, sans supposer la taille de morceau du serveur : le
        //    wallet n'a pas à connaître la politique de découpage pour la contrôler.
        let mut curseur = debut;
        for place in &ordre {
            let m = place.ok_or(SynchroError::MorceauxIncoherents)?;
            if m.decalage != curseur {
                return Err(SynchroError::DecoupageNonContigu {
                    recu: m.decalage,
                    attendu: curseur,
                });
            }
            curseur = curseur
                .checked_add(m.sorties.len() as u64)
                .ok_or(SynchroError::MorceauxIncoherents)?;
        }
        if curseur != fin {
            return Err(SynchroError::DecoupageNonContigu {
                recu: curseur,
                attendu: fin,
            });
        }

        // 6. Capacité AVANT insertion : `ProvedMerkleTree::append` panique sur un arbre
        //    plein, et un lot vient du réseau.
        let ajout = fin - debut;
        let capacite = 1u128 << self.arbre.depth();
        if u128::from(feuilles) + u128::from(ajout) > capacite {
            return Err(SynchroError::ArbrePlein { feuilles, ajout });
        }

        // 7. Rejeu proprement dit : CHAQUE commitment observé, DANS L'ORDRE, et l'index
        //    rendu par l'arbre confronté à celui que le lot annonce. Si les deux
        //    divergeaient, tous nos chemins seraient faux en silence.
        let avant = self.arbre.len();
        for place in &ordre {
            let m = place.ok_or(SynchroError::MorceauxIncoherents)?;
            for (i, sortie) in m.sorties.iter().enumerate() {
                let attendu = m.decalage.saturating_add(i as u64);
                let rendu = self.arbre.append(&sortie.commitment);
                if rendu != attendu {
                    self.rembobiner(avant);
                    return Err(SynchroError::IndexDivergent { rendu, attendu });
                }
            }
        }

        // 8. La racine reconstruite doit être celle annoncée — sinon on n'a pas rejoué
        //    la même chaîne, et l'arbre revient à son préfixe EXACT.
        if self.arbre.root() != premier.racine_apres {
            self.rembobiner(avant);
            return Err(SynchroError::RacineDesaccord { hauteur });
        }

        // 9. SEULEMENT MAINTENANT le scan (le coût réel : une décapsulation hybride par
        //    sortie). `scanner` pousse la note reconnue avec son index d'arbre.
        let mut notes_recues = 0usize;
        for place in &ordre {
            let m = place.ok_or(SynchroError::MorceauxIncoherents)?;
            for (i, sortie) in m.sorties.iter().enumerate() {
                let index = m.decalage.saturating_add(i as u64);
                if self.scanner(&sortie.commitment, &sortie.enc_note, index) {
                    notes_recues += 1;
                }
            }
        }

        self.feuilles_ancrees = fin;
        // `saturating_add` : à `u64::MAX` la position cesserait d'avancer, ce qui vaut
        // mieux que de repartir à 0 et de rejouer la chaîne sur un arbre déjà rempli.
        self.prochaine_hauteur = hauteur.saturating_add(1);

        Ok(Progression {
            statut: Statut::Applique,
            hauteur,
            entrees: ajout,
            notes_recues,
            solde: self.solde(),
            prochaine_hauteur: self.prochaine_hauteur,
        })
    }

    /// Ramène l'arbre au préfixe qu'il avait avant le lot en cours.
    ///
    /// `expect` licite : `avant` vient de `self.arbre.len()` lu quelques lignes plus
    /// haut, et rien entre-temps n'a pu RACCOURCIR l'arbre — la seule opération
    /// intercalée est `append`.
    fn rembobiner(&mut self, avant: usize) {
        self.arbre
            .tronquer(avant)
            .expect("l'arbre n'a fait que grandir depuis la mesure");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_communs::{lot_de_genese, secret};
    use circuit::SpendNote;
    use proved_hash::rescue;

    const PROFONDEUR: usize = 4;

    /// UN LOT HORS SÉQUENCE EST REFUSÉ — dans les deux dimensions.
    ///
    /// C'est l'invariant qui rend l'ordre STRUCTUREL. Sans lui, un nœud (bogué ou
    /// hostile) qui saute un bloc ferait insérer les feuilles suivantes à des index
    /// décalés de tout le bloc manquant : les chemins produits seraient faux, les
    /// transactions refusées pour « ancre inconnue », et RIEN n'indiquerait la cause.
    #[test]
    fn lot_hors_sequence_refuse() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, _etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);

        // Hauteur du futur : le bloc 0 n'a pas été rejoué.
        let futur = MorceauHistorique::bloc_entier(1, 0, lot.racine_apres, lot.sorties.clone());
        assert!(matches!(
            w.synchroniser(&[futur]),
            Err(SynchroError::HauteurHorsSequence {
                recue: 1,
                attendue: 0
            })
        ));
        assert_eq!(w.arbre.len(), 0, "rien n'a été inséré");

        // Bonne hauteur, mais commençant à la mauvaise FEUILLE.
        let decale = MorceauHistorique::bloc_entier(0, 7, lot.racine_apres, lot.sorties.clone());
        assert!(matches!(
            w.synchroniser(&[decale]),
            Err(SynchroError::FeuilleHorsSequence {
                recue: 7,
                attendue: 0
            })
        ));
        assert_eq!(w.arbre.len(), 0);
        assert_eq!(w.prochaine_hauteur(), 0, "la position n'a pas bougé");
    }

    /// REJOUER LE MÊME LOT EST IDEMPOTENT, ET LE DIT.
    ///
    /// Une livraison en double est normale sur un réseau. La réappliquer insérerait les
    /// mêmes commitments une seconde fois : l'arbre divergerait de celui du nœud, et le
    /// solde compterait deux fois la même note. Le résultat est `DejaApplique` plutôt
    /// qu'un `Ok` muet, pour qu'une boucle de synchronisation ne croie pas progresser.
    #[test]
    fn rejouer_le_meme_lot_est_idempotent() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);

        let p = w.synchroniser(std::slice::from_ref(&lot)).expect("rejeu");
        assert_eq!(p.statut, Statut::Applique);
        assert_eq!(p.entrees, 2);
        assert_eq!(p.notes_recues, 2);
        assert_eq!(p.solde, 1_500);
        assert_eq!(w.racine(), etat.tree.root(), "même arbre que le nœud");

        let p2 = w.synchroniser(&[lot]).expect("livraison en double");
        assert_eq!(p2.statut, Statut::DejaApplique);
        assert_eq!(p2.entrees, 0);
        assert_eq!(p2.notes_recues, 0);
        assert_eq!(w.solde(), 1_500, "rien n'a été compté deux fois");
        assert_eq!(w.notes().len(), 2);
        assert_eq!(w.arbre.len(), 2, "aucune feuille dupliquée");
        assert_eq!(w.racine(), etat.tree.root());
    }

    /// UNE SYNCHRONISATION INTERROMPUE NE LAISSE RIEN DERRIÈRE ELLE.
    ///
    /// Il n'existe aucun tampon de morceaux partiels : un lot amputé est refusé et le
    /// wallet reste exactement où il était. Sans cette atomicité, un wallet coupé au
    /// milieu d'un bloc s'ancrerait au milieu d'un bloc — et son `anchor`, qui est
    /// PUBLIC, deviendrait un pseudonyme quasi unique.
    #[test]
    fn lot_incomplet_ne_laisse_aucune_trace() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, _etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);

        // Le nœud annonce deux morceaux, un seul arrive.
        let ampute = MorceauHistorique {
            hauteur: 0,
            debut: 0,
            fin: 2,
            racine_apres: lot.racine_apres,
            morceau: 0,
            morceaux: 2,
            decalage: 0,
            sorties: vec![lot.sorties[0].clone()],
        };
        assert!(matches!(
            w.synchroniser(&[ampute]),
            Err(SynchroError::LotIncomplet {
                recus: 1,
                attendus: 2
            })
        ));
        assert_eq!(w.arbre.len(), 0, "aucune feuille insérée");
        assert_eq!(w.solde(), 0, "aucune note retenue");
        assert_eq!(w.prochaine_hauteur(), 0);

        // Le lot complet passe ensuite normalement : rien n'a été « consommé ».
        assert_eq!(w.synchroniser(&[lot]).expect("rejeu").entrees, 2);
        assert_eq!(w.solde(), 1_500);
    }

    /// DEUX MORCEAUX RANGÉS PAR INDEX, PAS PAR ORDRE D'ARRIVÉE.
    ///
    /// Les morceaux arrivent dans l'ordre sur une session TCP donnée, mais RIEN dans le
    /// format ne l'impose. Un `extend` naïf dans l'ordre d'arrivée donnerait des index
    /// inversés — un arbre à la mauvaise racine, donc une erreur bruyante ici, mais en
    /// production une divergence que seule la première dépense révélerait.
    #[test]
    fn morceaux_desordonnes_ranges_par_index() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);
        let (a, b) = (lot.sorties[0].clone(), lot.sorties[1].clone());

        let m0 = MorceauHistorique {
            hauteur: 0,
            debut: 0,
            fin: 2,
            racine_apres: lot.racine_apres,
            morceau: 0,
            morceaux: 2,
            decalage: 0,
            sorties: vec![a],
        };
        let m1 = MorceauHistorique {
            hauteur: 0,
            debut: 0,
            fin: 2,
            racine_apres: lot.racine_apres,
            morceau: 1,
            morceaux: 2,
            decalage: 1,
            sorties: vec![b],
        };
        // Livrés à l'ENVERS.
        let p = w.synchroniser(&[m1, m0]).expect("rangement par index");
        assert_eq!(p.entrees, 2);
        assert_eq!(w.racine(), etat.tree.root(), "arbre identique à celui du nœud");
        assert_eq!(w.solde(), 1_500);
    }

    /// UN LOT DONT LA RACINE NE CORRESPOND PAS NE LAISSE PAS L'ARBRE ENTAMÉ.
    ///
    /// C'est le seul contrôle qui attrape un historique incohérent avec lui-même. S'il
    /// échouait sans rembobiner, l'arbre garderait des feuilles qu'aucun nœud n'a et
    /// tous les index suivants seraient décalés — sans qu'aucune erreur ultérieure ne
    /// désigne la cause.
    #[test]
    fn racine_desaccord_rembobine_l_arbre() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, _etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);
        let menteur = MorceauHistorique::bloc_entier(
            0,
            0,
            rescue::note_commitment(1, &w.owner(), &w.owner(), &w.owner()),
            lot.sorties.clone(),
        );
        assert!(matches!(
            w.synchroniser(&[menteur]),
            Err(SynchroError::RacineDesaccord { hauteur: 0 })
        ));
        assert_eq!(w.arbre.len(), 0, "arbre rembobiné à son préfixe");
        assert_eq!(w.solde(), 0, "aucune note retenue sur un lot refusé");
        assert_eq!(w.prochaine_hauteur(), 0);

        // Et le vrai lot passe ensuite : l'arbre n'a pas été empoisonné.
        assert_eq!(w.synchroniser(&[lot]).expect("rejeu").entrees, 2);
    }

    /// UN BLOC SANS SORTIE FAIT QUAND MÊME AVANCER LA POSITION.
    ///
    /// Un bloc vide est le cas courant d'une chaîne au repos. Le sauter (« rien à
    /// rejouer ») laisserait le wallet redemander éternellement la même hauteur, et
    /// surtout lui ferait perdre l'ancre : la seule valeur utile d'un bloc vide est sa
    /// `racine_apres`.
    #[test]
    fn bloc_vide_fait_avancer_la_position() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, _etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);
        let racine_apres_genese = lot.racine_apres;
        w.synchroniser(&[lot]).expect("genèse");

        // Bloc 1 : aucune sortie, donc même racine.
        let vide = MorceauHistorique::bloc_entier(1, 2, racine_apres_genese, Vec::new());
        let p = w.synchroniser(&[vide]).expect("bloc vide");
        assert_eq!(p.entrees, 0);
        assert_eq!(p.statut, Statut::Applique);
        assert_eq!(w.prochaine_hauteur(), 2, "la position a avancé");
        assert_eq!(w.feuilles_ancrees(), 2);
    }

    /// Lots dégénérés : jamais de panique, toujours une erreur nommée.
    #[test]
    fn lots_degeneres_refuses_sans_panique() {
        let mut w = Wallet::depuis_secret(secret(700), PROFONDEUR);
        let (lot, _etat) = lot_de_genese(&w, &[1_000, 500], PROFONDEUR);

        assert!(matches!(w.synchroniser(&[]), Err(SynchroError::LotVide)));

        // Plage inversée.
        let inverse = MorceauHistorique {
            hauteur: 0,
            debut: 5,
            fin: 2,
            racine_apres: lot.racine_apres,
            morceau: 0,
            morceaux: 1,
            decalage: 5,
            sorties: Vec::new(),
        };
        assert!(matches!(
            w.synchroniser(&[inverse]),
            Err(SynchroError::PlageInversee { debut: 5, fin: 2 })
        ));

        // Deux morceaux portant le MÊME index : le second écraserait le premier.
        let doublon = |k: u32| MorceauHistorique {
            hauteur: 0,
            debut: 0,
            fin: 2,
            racine_apres: lot.racine_apres,
            morceau: k,
            morceaux: 2,
            decalage: 0,
            sorties: vec![lot.sorties[0].clone()],
        };
        assert!(matches!(
            w.synchroniser(&[doublon(0), doublon(0)]),
            Err(SynchroError::MorceauxIncoherents)
        ));

        // Morceaux annonçant des blocs différents.
        let a = MorceauHistorique::bloc_entier(0, 0, lot.racine_apres, vec![lot.sorties[0].clone()]);
        let b = MorceauHistorique::bloc_entier(1, 0, lot.racine_apres, vec![lot.sorties[1].clone()]);
        assert!(matches!(
            w.synchroniser(&[a, b]),
            Err(SynchroError::MorceauxIncoherents)
        ));

        // Découpage laissant un TROU entre deux morceaux.
        let troue = |k: u32, decalage: u64| MorceauHistorique {
            hauteur: 0,
            debut: 0,
            fin: 2,
            racine_apres: lot.racine_apres,
            morceau: k,
            morceaux: 2,
            decalage,
            sorties: vec![lot.sorties[k as usize].clone()],
        };
        assert!(matches!(
            w.synchroniser(&[troue(0, 0), troue(1, 9)]),
            Err(SynchroError::DecoupageNonContigu { recu: 9, attendu: 1 })
        ));

        assert_eq!(w.arbre.len(), 0, "aucun lot dégénéré n'a touché l'arbre");
    }

    /// L'ARBRE PLEIN EST UNE ERREUR, PAS UNE PANIQUE.
    ///
    /// `ProvedMerkleTree::append` panique sur un arbre saturé, et le lot vient du
    /// réseau : un nœud n'a pas à pouvoir tuer un wallet en lui servant un bloc de plus.
    #[test]
    fn arbre_plein_refuse_sans_paniquer() {
        // Profondeur 1 : deux feuilles au plus.
        let mut w = Wallet::depuis_secret(secret(700), 1);
        let (lot, _etat) = lot_de_genese(&w, &[1, 2], 1);
        w.synchroniser(&[lot]).expect("deux feuilles");

        let note = SpendNote {
            value: 3,
            owner: w.owner(),
            rho: w.owner(),
            r: w.owner(),
        };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        let sortie = ledger::historique::Sortie {
            commitment: cm,
            enc_note: ledger::proved_wallet::encrypt_note(&w.adresse().kem, &cm, &note),
        };
        let trop = MorceauHistorique::bloc_entier(1, 2, w.racine(), vec![sortie]);
        assert!(matches!(
            w.synchroniser(&[trop]),
            Err(SynchroError::ArbrePlein {
                feuilles: 2,
                ajout: 1
            })
        ));
    }
}
