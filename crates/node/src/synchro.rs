//! Protocole de SYNCHRONISATION du wallet : servir l'historique des sorties.
//!
//! `ledger::historique` conserve, dans l'ordre d'insertion, chaque sortie entrée dans
//! l'arbre. Ce module est ce qui la met sur le fil — et rien d'autre : la décision de
//! servir (étranglement, silence) est dans [`crate::etranglement`] et
//! [`crate::orchestration`], le rejeu est côté wallet.
//!
//! # L'unité est le BLOC, jamais la plage de feuilles
//!
//! `ProvedTx::anchor` est PUBLIC et vaut la racine de l'arbre du wallet, c'est-à-dire
//! sa position exacte de synchronisation. Des wallets s'arrêtant chacun à une feuille
//! différente publieraient donc chacun une ancre quasi unique — un pseudonyme
//! permanent, exactement le défaut corrigé pour la clé d'intention. Ancrés sur une
//! frontière de bloc, tous les wallets à jour partagent la MÊME ancre.
//!
//! Conséquence de format : une réponse porte toujours **un bloc entier** (`debut`,
//! `fin`, `racine_apres` du bloc), même quand elle est découpée en plusieurs morceaux.
//!
//! # Aucun champ choisi par le client, hormis sa position
//!
//! La demande est `tag ‖ hauteur` : 9 octets, et rien d'autre. Pas de `max` d'entrées,
//! pas de plage. Un tel paramètre serait une **empreinte de client** qui survit à
//! l'identité de transport éphémère : le nœud séparerait les wallets par leur `max`,
//! puis suivrait chacun par sa position. Le débit se règle par la FRÉQUENCE des
//! demandes, pas par un champ sur le fil. `demandes_identiques_a_position_egale` le
//! vérifie octet pour octet.
//!
//! # Le découpage est décidé par le SERVEUR
//!
//! Un bloc plein produit 1024 sorties, soit ≈1,4 Mio — au-delà du cadre réseau de
//! 1 Mio. Il faut donc découper, et c'est le serveur qui le fait : le client
//! n'exprime jamais d'index de morceau, sans quoi on rouvrirait la porte fermée
//! ci-dessus. Une demande produit N réponses `Historique`, chacune portant
//! (`morceau`, `morceaux`, `decalage`) pour que le wallet sache où la ranger.
//!
//! Le découpage est **canonique** : `morceaux` et `decalage` sont entièrement
//! déterminés par (`debut`, `fin`) et vérifiés au décodage. Un serveur ne peut donc
//! pas choisir une autre segmentation — ce qui aurait offert un canal de marquage à
//! bas bruit, et surtout un moyen d'envoyer des morceaux qui se recouvrent.
//!
//! # La borne tient compte du surcoût AEAD
//!
//! Ce que `net::MAX_CADRE` (1 Mio) borne est la quantité **chiffrée**. La cascade
//! XChaCha20∘AES-GCM ajoute [`crypto::aead::SURCOUT`] = 68 octets (deux nonces, deux
//! tags). [`MAX_SORTIES_PAR_REPONSE`] se calcule donc sur `MAX_CADRE − SURCOUT −
//! en-tête`, et l'oublier aurait produit un service qui échoue précisément sur ses
//! réponses pleines.
//!
//! # ⚠️ `hauteur_tete` : une indication, jamais un moteur
//!
//! La réponse porte la hauteur de tête du serveur, sans quoi un wallet ne saurait
//! jamais s'il lui reste des blocs à demander. C'est aussi un champ **non
//! vérifiable** : un nœud peut y écrire `u64::MAX`.
//!
//! Ce qui empêche ce mensonge de faire boucler un wallet indéfiniment est que
//! `hauteur_tete` ne **pilote** rien : la position du wallet n'avance que lorsqu'il
//! reçoit la tranche de la hauteur qu'il a demandée. Une tête gonflée lui fait donc
//! demander une hauteur que le nœud n'a pas, obtenir le SILENCE, et s'arrêter — une
//! requête inutile, exactement le dégât borné qu'on accepte déjà pour
//! `Noeud::hauteur_max_vue`. Le décodage refuse en outre `hauteur_tete < hauteur` :
//! un serveur ne peut pas prétendre être en retard sur la tranche qu'il vient de
//! servir.
//!
//! ⚠️ Le mensonge INVERSE — annoncer une tête plus courte que la vraie — reste
//! impossible à détecter auprès d'un nœud unique : c'est le même trou que
//! « mentir par omission » (docs/THREAT_MODEL.md). Un wallet qui prend historique ET
//! identifiants de blocs au même nœud n'a rien vérifié.

use crypto::aead;
use ledger::historique::{Sortie, TrancheBloc, TAILLE_SORTIE_MAX};
use proved_hash::digest::{Digest, DIGEST_BYTES};

use circuit::tx::{KEM_CT_LEN, MAX_ENC_NOTE_LEN};
use circuit::EncNote;

/// Version du format de réponse de synchronisation.
pub const VERSION_SYNCHRO: u8 = 0x01;

/// Taille de l'en-tête d'une réponse, tag applicatif et version compris.
///
/// `tag ‖ version ‖ hauteur ‖ debut ‖ fin ‖ racine ‖ hauteur_tete ‖ morceau ‖
/// morceaux ‖ decalage ‖ nombre de sorties`.
pub const TAILLE_ENTETE_REPONSE: usize = 1 + 1 + 8 + 8 + 8 + DIGEST_BYTES + 8 + 4 + 4 + 8 + 4;

/// Budget de CLAIR disponible dans un cadre réseau.
///
/// `net::MAX_CADRE` borne la quantité chiffrée : le surcoût de la cascade AEAD doit
/// être retiré ici, pas supposé nul.
pub const BUDGET_CLAIR: usize = net::MAX_CADRE - aead::SURCOUT;

/// Nombre maximal de sorties dans UNE réponse.
///
/// Calculé, pas choisi : c'est le plus grand nombre d'entrées de taille maximale qui
/// tient dans un cadre une fois retirés le surcoût AEAD et l'en-tête.
pub const MAX_SORTIES_PAR_REPONSE: usize =
    (BUDGET_CLAIR - TAILLE_ENTETE_REPONSE) / TAILLE_SORTIE_MAX;

/// CONSIGNÉ À LA COMPILATION : une réponse PLEINE doit tenir dans un cadre une fois
/// chiffrée. Si `TAILLE_SORTIE_MAX` ou `MAX_CADRE` changent, c'est la compilation qui
/// casse — pas le service, en production, sur ses seules réponses pleines.
const _: () = assert!(MAX_SORTIES_PAR_REPONSE > 0);
const _: () = assert!(
    TAILLE_ENTETE_REPONSE + MAX_SORTIES_PAR_REPONSE * TAILLE_SORTIE_MAX + aead::SURCOUT
        <= net::MAX_CADRE
);
/// CONSIGNÉ À LA COMPILATION : un bloc PLEIN (512 tx × 2 sorties) ne tient pas dans
/// une réponse. Le découpage n'est donc pas un cas théorique qu'on pourrait laisser
/// non testé — il est atteint dès qu'un bloc se remplit.
const _: () = assert!(MAX_SORTIES_PAR_REPONSE < ledger::bloc::MAX_TX_PAR_BLOC * 2);

/// Nombre CANONIQUE de morceaux pour un bloc de `entrees` sorties.
///
/// Un bloc SANS sortie vaut quand même un morceau : sa `racine_apres` est ce qui
/// permet au wallet de s'ancrer, et un bloc vide est le cas courant d'une chaîne au
/// repos. Rendre 0 le rendrait insynchronisable en silence.
pub fn nombre_de_morceaux(entrees: u64) -> u64 {
    if entrees == 0 {
        1
    } else {
        entrees.div_ceil(MAX_SORTIES_PAR_REPONSE as u64)
    }
}

/// Erreur de décodage d'une réponse de synchronisation.
///
/// Elle arrive du RÉSEAU, chez un wallet qui n'a aucun moyen de savoir si le nœud est
/// honnête : aucune variante ne peut naître d'une panique, et chaque incohérence a un
/// nom distinct pour que « nœud bogué » et « nœud hostile » ne se confondent pas avec
/// « lien coupé ».
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReponseDecodeError {
    #[error("réponse tronquée")]
    Tronque,
    #[error("octets résiduels après la fin de la réponse")]
    OctetsResiduels,
    #[error("version de synchronisation inconnue : {0:#04x}")]
    VersionInconnue(u8),
    #[error("plage de bloc inversée ({debut} > {fin})")]
    PlageInversee { debut: u64, fin: u64 },
    #[error("tête annoncée ({tete}) en retard sur la hauteur servie ({hauteur})")]
    TeteEnRetard { tete: u64, hauteur: u64 },
    #[error("découpage non canonique (morceau {morceau} sur {morceaux})")]
    DecoupageNonCanonique { morceau: u32, morceaux: u32 },
    #[error("trop de sorties dans une réponse (borne : {MAX_SORTIES_PAR_REPONSE})")]
    TropDeSorties,
    #[error("sortie {0} indécodable ou hors bornes")]
    SortieInvalide(u64),
    #[error("racine ou commitment non canonique")]
    DigestNonCanonique,
}

/// UN MORCEAU de l'historique d'UN bloc.
///
/// Ni `Debug` ni `PartialEq` : elle porte des `Sortie`, donc des `EncNote`. Les tests
/// filtrent avec `matches!`.
pub struct ReponseHistorique {
    /// Hauteur servie — toujours celle qui a été demandée.
    pub hauteur: u64,
    /// Index absolu de la première feuille DU BLOC (inclus).
    pub debut: u64,
    /// Index absolu de fin DU BLOC (exclu).
    pub fin: u64,
    /// Racine de l'arbre après application complète du bloc : l'ancre du wallet.
    pub racine_apres: Digest,
    /// Dernière hauteur que le serveur peut servir. ⚠️ Non vérifiable — cf. tête de
    /// module (« une indication, jamais un moteur »).
    pub hauteur_tete: u64,
    /// Index de ce morceau (0-based).
    pub morceau: u32,
    /// Nombre total de morceaux pour ce bloc. Toujours ≥ 1.
    pub morceaux: u32,
    /// Index absolu de la première sortie DE CE MORCEAU.
    pub decalage: u64,
    /// Les sorties de ce morceau, dans l'ordre d'insertion.
    pub sorties: Vec<Sortie>,
}

impl ReponseHistorique {
    /// Découpe la tranche d'un bloc en réponses transmissibles.
    ///
    /// C'est le CONSTRUCTEUR, et il porte exactement les bornes que `from_bytes`
    /// vérifie — règle du projet : une borne présente au seul décodage ne protège que
    /// l'entrant. Un serveur ne peut donc pas fabriquer une réponse que son propre
    /// pair refusera, ni une réponse qui dépasse le cadre.
    ///
    /// `None` quand les entrées sont incohérentes entre elles (plage inversée, tête en
    /// retard, nombre de sorties différent de la plage annoncée) : c'est un bug LOCAL,
    /// pas une faute du demandeur, et il vaut mieux ne rien servir que servir faux.
    pub fn decouper(
        tranche: &TrancheBloc,
        sorties: &[Sortie],
        hauteur_tete: u64,
    ) -> Option<Vec<ReponseHistorique>> {
        if tranche.fin < tranche.debut || hauteur_tete < tranche.hauteur {
            return None;
        }
        let etendue = tranche.fin - tranche.debut;
        if etendue != sorties.len() as u64 {
            return None;
        }
        let morceaux = nombre_de_morceaux(etendue);
        let morceaux = u32::try_from(morceaux).ok()?;

        let mut reponses = Vec::with_capacity(morceaux as usize);
        for k in 0..morceaux {
            let saut = (k as usize).checked_mul(MAX_SORTIES_PAR_REPONSE)?;
            let a = saut.min(sorties.len());
            let b = saut
                .checked_add(MAX_SORTIES_PAR_REPONSE)?
                .min(sorties.len());
            let tranche_sorties = sorties.get(a..b)?.to_vec();
            reponses.push(ReponseHistorique {
                hauteur: tranche.hauteur,
                debut: tranche.debut,
                fin: tranche.fin,
                racine_apres: tranche.racine_apres,
                hauteur_tete,
                morceau: k,
                morceaux,
                decalage: tranche.debut.checked_add(a as u64)?,
                sorties: tranche_sorties,
            });
        }
        Some(reponses)
    }

    /// Traduit la réponse en morceau REJOUABLE par le wallet.
    ///
    /// `hauteur_tete` est laissée ici, délibérément : elle n'existe pas dans le type que
    /// le wallet rejoue, et c'est la forme la plus forte de l'invariant « une indication,
    /// jamais un moteur » — la logique de rejeu ne peut pas la lire, même par erreur.
    ///
    /// Les champs de découpage, eux, sont TRANSMIS et non recalculés : le wallet les
    /// revérifie de son côté, par cumul, sans supposer la taille de morceau du serveur.
    /// Un client qui ferait confiance à ce que le serveur lui a dit du découpage serait
    /// exactement le client que `MAX_SORTIES_PAR_REPONSE` ne protège pas.
    pub fn pour_le_wallet(&self) -> wallet::synchro::MorceauHistorique {
        wallet::synchro::MorceauHistorique {
            hauteur: self.hauteur,
            debut: self.debut,
            fin: self.fin,
            racine_apres: self.racine_apres,
            morceau: self.morceau,
            morceaux: self.morceaux,
            decalage: self.decalage,
            sorties: self.sorties.clone(),
        }
    }

    /// Encodage canonique (l'octet de tag applicatif est écrit par `Message`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(TAILLE_ENTETE_REPONSE);
        b.push(VERSION_SYNCHRO);
        b.extend_from_slice(&self.hauteur.to_le_bytes());
        b.extend_from_slice(&self.debut.to_le_bytes());
        b.extend_from_slice(&self.fin.to_le_bytes());
        b.extend_from_slice(&self.racine_apres.to_bytes());
        b.extend_from_slice(&self.hauteur_tete.to_le_bytes());
        b.extend_from_slice(&self.morceau.to_le_bytes());
        b.extend_from_slice(&self.morceaux.to_le_bytes());
        b.extend_from_slice(&self.decalage.to_le_bytes());
        b.extend_from_slice(&(self.sorties.len() as u32).to_le_bytes());
        for s in &self.sorties {
            b.extend_from_slice(&s.commitment.to_bytes());
            b.extend_from_slice(&(s.enc_note.kem_ct.len() as u32).to_le_bytes());
            b.extend_from_slice(&s.enc_note.kem_ct);
            b.extend_from_slice(&(s.enc_note.enc_note.len() as u32).to_le_bytes());
            b.extend_from_slice(&s.enc_note.enc_note);
        }
        b
    }

    /// Décode une réponse reçue du réseau. Curseur borné, jamais de panique.
    ///
    /// # L'ordre des contrôles est celui du coût
    ///
    /// Le compteur de sorties est confronté à [`MAX_SORTIES_PAR_REPONSE`] **avant**
    /// toute réservation, puis aux octets réellement présents. Sans le premier
    /// contrôle, un en-tête annonçant 10⁹ entrées coûterait ≈1,4 Tio pour 85 octets
    /// reçus ; sans le second, il suffirait d'annoncer la borne pour faire réserver
    /// 1 Mio à chaque message.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ReponseDecodeError> {
        let mut pos = 0usize;
        fn prendre<'a>(
            b: &'a [u8],
            pos: &mut usize,
            n: usize,
        ) -> Result<&'a [u8], ReponseDecodeError> {
            let fin = pos.checked_add(n).ok_or(ReponseDecodeError::Tronque)?;
            let s = b.get(*pos..fin).ok_or(ReponseDecodeError::Tronque)?;
            *pos = fin;
            Ok(s)
        }
        fn u64_de(b: &[u8], pos: &mut usize) -> Result<u64, ReponseDecodeError> {
            let o: [u8; 8] = prendre(b, pos, 8)?
                .try_into()
                .map_err(|_| ReponseDecodeError::Tronque)?;
            Ok(u64::from_le_bytes(o))
        }
        fn u32_de(b: &[u8], pos: &mut usize) -> Result<u32, ReponseDecodeError> {
            let o: [u8; 4] = prendre(b, pos, 4)?
                .try_into()
                .map_err(|_| ReponseDecodeError::Tronque)?;
            Ok(u32::from_le_bytes(o))
        }

        let version = prendre(b, &mut pos, 1)?[0];
        if version != VERSION_SYNCHRO {
            return Err(ReponseDecodeError::VersionInconnue(version));
        }
        let hauteur = u64_de(b, &mut pos)?;
        let debut = u64_de(b, &mut pos)?;
        let fin = u64_de(b, &mut pos)?;
        let racine: [u8; DIGEST_BYTES] = prendre(b, &mut pos, DIGEST_BYTES)?
            .try_into()
            .map_err(|_| ReponseDecodeError::Tronque)?;
        let racine_apres =
            Digest::from_bytes(&racine).map_err(|_| ReponseDecodeError::DigestNonCanonique)?;
        let hauteur_tete = u64_de(b, &mut pos)?;
        let morceau = u32_de(b, &mut pos)?;
        let morceaux = u32_de(b, &mut pos)?;
        let decalage = u64_de(b, &mut pos)?;
        let n = u32_de(b, &mut pos)? as usize;

        if fin < debut {
            return Err(ReponseDecodeError::PlageInversee { debut, fin });
        }
        // Un serveur ne peut pas prétendre être EN RETARD sur ce qu'il vient de servir.
        if hauteur_tete < hauteur {
            return Err(ReponseDecodeError::TeteEnRetard {
                tete: hauteur_tete,
                hauteur,
            });
        }
        // BORNE AVANT ALLOCATION.
        if n > MAX_SORTIES_PAR_REPONSE {
            return Err(ReponseDecodeError::TropDeSorties);
        }

        // DÉCOUPAGE CANONIQUE : `morceaux`, `decalage` et `n` sont entièrement
        // déterminés par (debut, fin, morceau). Les recalculer plutôt que les croire
        // interdit les morceaux qui se recouvrent, les morceaux fantômes, et le
        // marquage d'un wallet par une segmentation choisie.
        let etendue = fin - debut;
        let attendus = nombre_de_morceaux(etendue);
        let incoherent = ReponseDecodeError::DecoupageNonCanonique { morceau, morceaux };
        if u64::from(morceaux) != attendus || morceau >= morceaux {
            return Err(incoherent);
        }
        let saut = u64::from(morceau)
            .checked_mul(MAX_SORTIES_PAR_REPONSE as u64)
            .ok_or(ReponseDecodeError::DecoupageNonCanonique { morceau, morceaux })?;
        let attendu_decalage = debut
            .checked_add(saut.min(etendue))
            .ok_or(ReponseDecodeError::DecoupageNonCanonique { morceau, morceaux })?;
        let attendu_n = etendue
            .saturating_sub(saut)
            .min(MAX_SORTIES_PAR_REPONSE as u64);
        if decalage != attendu_decalage || n as u64 != attendu_n {
            return Err(ReponseDecodeError::DecoupageNonCanonique { morceau, morceaux });
        }
        // Second garde-fou avant réservation : le compteur est confronté aux octets
        // réellement présents, pas seulement à la borne constante.
        if n.saturating_mul(DIGEST_BYTES + 4 + KEM_CT_LEN + 4) > b.len().saturating_sub(pos) {
            return Err(ReponseDecodeError::Tronque);
        }

        let mut sorties: Vec<Sortie> = Vec::with_capacity(n);
        for j in 0..n {
            let cm: [u8; DIGEST_BYTES] = prendre(b, &mut pos, DIGEST_BYTES)?
                .try_into()
                .map_err(|_| ReponseDecodeError::Tronque)?;
            let commitment =
                Digest::from_bytes(&cm).map_err(|_| ReponseDecodeError::SortieInvalide(j as u64))?;

            let lk = u32_de(b, &mut pos)? as usize;
            if lk != KEM_CT_LEN {
                return Err(ReponseDecodeError::SortieInvalide(j as u64));
            }
            let kem_ct = prendre(b, &mut pos, lk)?.to_vec();

            let le = u32_de(b, &mut pos)? as usize;
            if le > MAX_ENC_NOTE_LEN {
                return Err(ReponseDecodeError::SortieInvalide(j as u64));
            }
            let enc_note = prendre(b, &mut pos, le)?.to_vec();

            sorties.push(Sortie {
                commitment,
                enc_note: EncNote { kem_ct, enc_note },
            });
        }

        if pos != b.len() {
            return Err(ReponseDecodeError::OctetsResiduels);
        }

        Ok(ReponseHistorique {
            hauteur,
            debut,
            fin,
            racine_apres,
            hauteur_tete,
            morceau,
            morceaux,
            decalage,
            sorties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::felt::Felt;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    /// Sorties SYNTHÉTIQUES : le contenu d'une enveloppe est opaque au format de fil,
    /// et fabriquer 1481 vraies enveloppes coûterait autant d'encapsulations Kyber pour
    /// tester des octets que personne ne déchiffre ici. La forme réelle (émission de
    /// genèse vs sortie de transaction, longueurs identiques) est éprouvée par
    /// `ledger::historique::emission_et_sortie_ont_la_meme_forme`.
    fn sorties(n: usize) -> Vec<Sortie> {
        (0..n)
            .map(|i| Sortie {
                commitment: digest(1_000 + i as u64 * 10),
                enc_note: EncNote {
                    kem_ct: vec![(i % 251) as u8; KEM_CT_LEN],
                    enc_note: vec![0xEE; 32],
                },
            })
            .collect()
    }

    fn tranche(hauteur: u64, debut: u64, n: u64) -> TrancheBloc {
        TrancheBloc {
            hauteur,
            debut,
            fin: debut + n,
            racine_apres: digest(77),
        }
    }

    /// UNE ENTRÉE DE TAILLE MAXIMALE PÈSE EXACTEMENT `TAILLE_SORTIE_MAX`.
    ///
    /// C'est la constante sur laquelle repose tout le calcul de `MAX_SORTIES_PAR_REPONSE`.
    /// Si l'encodage d'une sortie gagnait un champ sans que la constante bouge, le
    /// service construirait des réponses au-delà du cadre — et échouerait précisément
    /// sur ses réponses pleines, c'est-à-dire dans le cas qu'on avait pris la peine de
    /// découper.
    #[test]
    fn une_sortie_maximale_pese_exactement_la_constante() {
        let maximale = Sortie {
            commitment: digest(1),
            enc_note: EncNote {
                kem_ct: vec![7u8; KEM_CT_LEN],
                enc_note: vec![9u8; MAX_ENC_NOTE_LEN],
            },
        };
        let r = ReponseHistorique {
            hauteur: 1,
            debut: 0,
            fin: 1,
            racine_apres: digest(2),
            hauteur_tete: 1,
            morceau: 0,
            morceaux: 1,
            decalage: 0,
            sorties: vec![maximale],
        };
        // +1 : le tag applicatif est écrit par `Message`, pas par `to_bytes`.
        assert_eq!(
            r.to_bytes().len() + 1,
            TAILLE_ENTETE_REPONSE + TAILLE_SORTIE_MAX
        );
    }

    /// LA BORNE EST CALCULÉE SUR LE CHIFFRÉ, PAS SUR LE CLAIR.
    ///
    /// Ce que `net::MAX_CADRE` borne est ce qui sort du canal AEAD. Une réponse PLEINE
    /// de sorties maximales, une fois le surcoût de cascade ajouté, doit encore tenir.
    /// Le jour où quelqu'un « simplifiera » `BUDGET_CLAIR` en `MAX_CADRE`, ce test
    /// tombe — sinon, seul un bloc plein en production l'aurait révélé.
    #[test]
    fn une_reponse_pleine_tient_dans_un_cadre_une_fois_chiffree() {
        let maximale = || Sortie {
            commitment: digest(3),
            enc_note: EncNote {
                kem_ct: vec![7u8; KEM_CT_LEN],
                enc_note: vec![9u8; MAX_ENC_NOTE_LEN],
            },
        };
        let r = ReponseHistorique {
            hauteur: 5,
            debut: 0,
            fin: MAX_SORTIES_PAR_REPONSE as u64,
            racine_apres: digest(4),
            hauteur_tete: 5,
            morceau: 0,
            morceaux: nombre_de_morceaux(MAX_SORTIES_PAR_REPONSE as u64) as u32,
            decalage: 0,
            sorties: (0..MAX_SORTIES_PAR_REPONSE).map(|_| maximale()).collect(),
        };
        let clair = 1 + r.to_bytes().len(); // + le tag applicatif
        assert!(
            clair + aead::SURCOUT <= net::MAX_CADRE,
            "clair {clair} + surcoût {} > cadre {}",
            aead::SURCOUT,
            net::MAX_CADRE
        );
    }

    /// Aller-retour canonique d'un morceau, y compris à vide.
    #[test]
    fn aller_retour_canonique() {
        for n in [0u64, 1, 3] {
            let t = tranche(4, 10, n);
            let s = sorties(n as usize);
            let morceaux = ReponseHistorique::decouper(&t, &s, 9).expect("découpage");
            assert_eq!(morceaux.len(), 1, "{n} sorties tiennent en un morceau");
            let octets = morceaux[0].to_bytes();
            let relu = ReponseHistorique::from_bytes(&octets).expect("aller-retour");
            assert_eq!(relu.to_bytes(), octets, "canonique");
            assert_eq!(relu.hauteur, 4);
            assert_eq!((relu.debut, relu.fin), (10, 10 + n));
            assert_eq!(relu.hauteur_tete, 9);
            assert_eq!(relu.sorties.len(), n as usize);
            assert_eq!(relu.decalage, 10);
        }
    }

    /// UN BLOC SANS SORTIE PRODUIT QUAND MÊME UNE RÉPONSE.
    ///
    /// Un bloc vide est le cas courant d'une chaîne au repos, et sa `racine_apres` est
    /// précisément l'ancre que le wallet doit adopter. Rendre zéro morceau le laisserait
    /// bloqué sur une hauteur qu'il redemanderait indéfiniment, sans qu'aucune erreur ne
    /// le dise.
    #[test]
    fn un_bloc_vide_produit_un_morceau() {
        assert_eq!(nombre_de_morceaux(0), 1);
        let t = tranche(2, 5, 0);
        let m = ReponseHistorique::decouper(&t, &[], 2).expect("découpage");
        assert_eq!(m.len(), 1);
        assert!(m[0].sorties.is_empty());
        assert_eq!(m[0].racine_apres.to_bytes(), digest(77).to_bytes());
    }

    /// LE DÉCOUPAGE COUVRE EXACTEMENT LE BLOC, SANS TROU NI RECOUVREMENT.
    ///
    /// C'est la propriété dont dépend l'index de chaque feuille chez le wallet : un
    /// morceau qui se recouvre décalerait tous les index suivants, et un index faux
    /// produit un chemin de Merkle faux — que rien ne signale, la transaction du wallet
    /// est simplement refusée pour « ancre inconnue ».
    #[test]
    fn le_decoupage_couvre_exactement_le_bloc() {
        let n = MAX_SORTIES_PAR_REPONSE as u64 * 2 + 3;
        let t = tranche(7, 100, n);
        let s = sorties(n as usize);
        let morceaux = ReponseHistorique::decouper(&t, &s, 7).expect("découpage");
        assert_eq!(morceaux.len(), 3, "deux morceaux pleins et un reste");

        let mut curseur = t.debut;
        for (k, m) in morceaux.iter().enumerate() {
            assert_eq!(m.morceau as usize, k);
            assert_eq!(m.morceaux as usize, morceaux.len());
            assert_eq!(m.decalage, curseur, "les morceaux se suivent sans trou");
            assert!(m.sorties.len() <= MAX_SORTIES_PAR_REPONSE);
            curseur += m.sorties.len() as u64;
            // Chaque morceau doit survivre au fil tel quel.
            let octets = m.to_bytes();
            assert!(ReponseHistorique::from_bytes(&octets).is_ok());
        }
        assert_eq!(curseur, t.fin, "la couverture s'arrête exactement à la fin");
    }

    /// UN DÉCOUPAGE NON CANONIQUE EST REFUSÉ.
    ///
    /// `morceaux`, `decalage` et le nombre de sorties sont déterminés par (debut, fin,
    /// morceau) : les recalculer plutôt que les croire est ce qui ferme trois abus d'un
    /// coup — morceaux qui se recouvrent, morceaux fantômes au-delà du bloc, et
    /// segmentation choisie servant de marqueur discret d'un wallet.
    #[test]
    fn decoupage_non_canonique_refuse() {
        let t = tranche(3, 0, 2);
        let s = sorties(2);
        let bon = ReponseHistorique::decouper(&t, &s, 3).expect("découpage");
        let octets = bon[0].to_bytes();

        // `morceaux` gonflé : la plage n'en exige qu'un.
        let mut faux = octets.clone();
        faux[1 + 8 + 8 + 8 + DIGEST_BYTES + 8 + 4] = 9;
        assert!(matches!(
            ReponseHistorique::from_bytes(&faux),
            Err(ReponseDecodeError::DecoupageNonCanonique { .. })
        ));

        // `morceau` hors du nombre annoncé.
        let mut faux = octets.clone();
        faux[1 + 8 + 8 + 8 + DIGEST_BYTES + 8] = 4;
        assert!(matches!(
            ReponseHistorique::from_bytes(&faux),
            Err(ReponseDecodeError::DecoupageNonCanonique { .. })
        ));

        // `decalage` déplacé : les feuilles seraient rangées ailleurs.
        let mut faux = octets.clone();
        let d = 1 + 8 + 8 + 8 + DIGEST_BYTES + 8 + 4 + 4;
        faux[d] = 5;
        assert!(matches!(
            ReponseHistorique::from_bytes(&faux),
            Err(ReponseDecodeError::DecoupageNonCanonique { .. })
        ));
    }

    /// UNE TÊTE EN RETARD SUR LA TRANCHE SERVIE EST REFUSÉE.
    ///
    /// `hauteur_tete` n'est pas vérifiable, mais elle n'a pas le droit d'être
    /// incohérente avec la réponse qui la porte : un serveur qui sert la hauteur 9 en
    /// se disant à la hauteur 3 ferait conclure au wallet qu'il est en avance sur la
    /// chaîne, donc à jour, donc qu'il peut cesser de se synchroniser.
    #[test]
    fn tete_en_retard_refusee() {
        let t = tranche(9, 0, 1);
        let s = sorties(1);
        // Le constructeur refuse déjà (la borne existe des DEUX côtés).
        assert!(ReponseHistorique::decouper(&t, &s, 3).is_none());

        let bon = ReponseHistorique::decouper(&t, &s, 9).expect("découpage");
        let mut octets = bon[0].to_bytes();
        octets[1 + 8 + 8 + 8 + DIGEST_BYTES] = 3; // hauteur_tete = 3
        assert!(matches!(
            ReponseHistorique::from_bytes(&octets),
            Err(ReponseDecodeError::TeteEnRetard { tete: 3, hauteur: 9 })
        ));
    }

    /// ANTI-DoS : un compteur de sorties aberrant est rejeté AVANT allocation.
    ///
    /// Le test n'envoie que l'en-tête. Si le code réservait d'après le compteur, il
    /// tenterait ≈1,4 Tio pour 85 octets reçus.
    #[test]
    fn compteur_aberrant_rejete_sans_allouer() {
        let mut b = vec![VERSION_SYNCHRO];
        b.extend_from_slice(&1u64.to_le_bytes()); // hauteur
        b.extend_from_slice(&0u64.to_le_bytes()); // debut
        b.extend_from_slice(&0u64.to_le_bytes()); // fin
        b.extend_from_slice(&digest(1).to_bytes()); // racine
        b.extend_from_slice(&1u64.to_le_bytes()); // hauteur_tete
        b.extend_from_slice(&0u32.to_le_bytes()); // morceau
        b.extend_from_slice(&1u32.to_le_bytes()); // morceaux
        b.extend_from_slice(&0u64.to_le_bytes()); // decalage
        b.extend_from_slice(&1_000_000_000u32.to_le_bytes()); // n hors borne
        assert!(matches!(
            ReponseHistorique::from_bytes(&b),
            Err(ReponseDecodeError::TropDeSorties)
        ));

        // Juste au-dessus de la borne : rejeté aussi.
        let mut b2 = b.clone();
        let fin = b2.len() - 4;
        b2[fin..].copy_from_slice(&((MAX_SORTIES_PAR_REPONSE + 1) as u32).to_le_bytes());
        assert!(matches!(
            ReponseHistorique::from_bytes(&b2),
            Err(ReponseDecodeError::TropDeSorties)
        ));
    }

    /// Matrice de malformations : vide, version, troncature à chaque offset, octets
    /// résiduels, enveloppe hors bornes. `Result` partout, jamais de panique.
    #[test]
    fn reponses_malformees_rejetees_sans_panique() {
        assert!(matches!(
            ReponseHistorique::from_bytes(&[]),
            Err(ReponseDecodeError::Tronque)
        ));
        assert!(matches!(
            ReponseHistorique::from_bytes(&[0x02]),
            Err(ReponseDecodeError::VersionInconnue(0x02))
        ));

        let t = tranche(1, 0, 2);
        let s = sorties(2);
        let bon = ReponseHistorique::decouper(&t, &s, 1).expect("découpage")[0].to_bytes();

        // Troncature à CHAQUE longueur possible : aucune ne doit paniquer.
        for n in 0..bon.len() {
            assert!(
                ReponseHistorique::from_bytes(&bon[..n]).is_err(),
                "préfixe de {n} octets accepté à tort"
            );
        }
        let mut trop = bon.clone();
        trop.push(0);
        assert!(matches!(
            ReponseHistorique::from_bytes(&trop),
            Err(ReponseDecodeError::OctetsResiduels)
        ));

        // Une enveloppe dont le `kem_ct` n'a pas la longueur du KEM hybride.
        let mut faux = bon.clone();
        let offset_lk = TAILLE_ENTETE_REPONSE - 1 + DIGEST_BYTES;
        faux[offset_lk..offset_lk + 4].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            ReponseHistorique::from_bytes(&faux),
            Err(ReponseDecodeError::SortieInvalide(0))
        ));
    }

    /// CE QUE LE NŒUD SERT, LE WALLET LE REJOUE — à travers les octets.
    ///
    /// Les deux moitiés du protocole de synchronisation vivent dans des crates
    /// différents et ne partagent aucun type : `wallet` ne peut pas dépendre de `node`,
    /// qui dépend de lui. Rien ne garantit donc leur accord SAUF un test qui fait le
    /// tour complet — découpage, encodage, décodage, traduction, rejeu. Un champ
    /// renommé ou un décalage d'un cran ne se verrait nulle part ailleurs : le wallet
    /// reconstruirait un autre arbre, et seule sa première dépense refusée le dirait.
    #[test]
    fn une_reponse_serialisee_est_rejouee_par_le_wallet() {
        const PROFONDEUR: usize = 8;
        let s = sorties(3);
        // Racine attendue : celle qu'obtient un arbre ayant vu ces feuilles dans l'ordre.
        let mut arbre = proved_hash::merkle::ProvedMerkleTree::new(PROFONDEUR);
        for x in &s {
            arbre.append(&x.commitment);
        }
        let t = TrancheBloc {
            hauteur: 0,
            debut: 0,
            fin: s.len() as u64,
            racine_apres: arbre.root(),
        };

        // Le trajet réel : découpage serveur → octets → décodage client → rejeu.
        let rejoues: Vec<_> = ReponseHistorique::decouper(&t, &s, 0)
            .expect("découpage")
            .iter()
            .map(|m| {
                ReponseHistorique::from_bytes(&m.to_bytes())
                    .expect("aller-retour")
                    .pour_le_wallet()
            })
            .collect();

        let mut w = wallet::Wallet::nouveau(PROFONDEUR);
        let p = w.synchroniser(&rejoues).expect("rejeu");
        assert_eq!(p.entrees, 3);
        assert_eq!(p.notes_recues, 0, "ces enveloppes ne visent personne");
        assert_eq!(w.racine(), arbre.root(), "même arbre des deux côtés");
        assert_eq!(w.prochaine_hauteur(), 1);
        assert_eq!(w.feuilles_ancrees(), 3);
    }

    /// Un constructeur incohérent rend `None` plutôt que de servir faux.
    #[test]
    fn constructeur_refuse_les_entrees_incoherentes() {
        // Plage inversée.
        let inversee = TrancheBloc {
            hauteur: 1,
            debut: 5,
            fin: 2,
            racine_apres: digest(1),
        };
        assert!(ReponseHistorique::decouper(&inversee, &[], 1).is_none());
        // Nombre de sorties différent de la plage.
        let t = tranche(1, 0, 3);
        assert!(ReponseHistorique::decouper(&t, &sorties(2), 1).is_none());
    }
}
