//! Publication d'une clé d'autorité de scellement — les DEUX bouts d'un seul geste.
//!
//! `obscura-genese --autorite-hex <hex>` est la voie recommandée pour monter une
//! fédération : chaque opérateur publie sa clé PUBLIQUE, personne ne transmet son
//! fichier d'identité (qui contient le secret du nœud). Encore faut-il pouvoir
//! l'obtenir — et jusqu'ici rien dans l'outillage ne l'imprimait. La voie
//! recommandée était donc inutilisable sans écrire du Rust, sur l'artefact le moins
//! rattrapable du projet.
//!
//! Ce module tient les deux moitiés du geste — ce que `obscura-node --identite`
//! IMPRIME et ce que `obscura-genese --autorite-hex` RELIT — pour qu'un test puisse
//! les confronter. Séparées, elles pourraient dériver (un préfixe `0x`, une
//! majuscule, un retour à la ligne au milieu) et l'échec n'apparaîtrait qu'au
//! moment de graver une chaîne.

use crypto::sig::SigPublicKey;

/// Encode une clé publique d'autorité, telle qu'elle doit être publiée.
///
/// Hexadécimal minuscule, sans préfixe ni séparateur : la forme qui se recopie
/// sans être interprétée par un shell.
pub fn encoder(pk: &SigPublicKey) -> String {
    hex::encode(pk.to_bytes())
}

/// Relit une clé publique d'autorité publiée par [`encoder`].
///
/// Les espaces de bordure sont TOLÉRÉS : une clé arrive presque toujours par
/// copier-coller depuis un terminal ou un courriel, donc avec un retour à la ligne
/// au bout. Refuser là-dessus ferait perdre du temps sans rien protéger — la clé
/// elle-même reste vérifiée par `SigPublicKey::from_bytes`, qui refuse toute
/// version d'algorithme périmée par son nom.
pub fn decoder(texte: &str) -> Result<SigPublicKey, ErreurAutorite> {
    let octets = hex::decode(texte.trim()).map_err(|_| ErreurAutorite::NonHexadecimal)?;
    SigPublicKey::from_bytes(&octets).map_err(|_| ErreurAutorite::CleInvalide)
}

/// Pourquoi une clé d'autorité a été refusée. Les deux cas se distinguent parce
/// qu'ils appellent des gestes différents : recopier à nouveau, ou remonter à
/// l'opérateur qui l'a publiée.
#[derive(Debug, PartialEq, Eq)]
pub enum ErreurAutorite {
    /// La chaîne contient autre chose que des chiffres hexadécimaux — copier-coller
    /// tronqué, guillemets avalés par le shell.
    NonHexadecimal,
    /// Hexadécimal valide, mais ce ne sont pas les octets d'une clé publique
    /// hybride courante (longueur, ou version d'algorithme périmée).
    CleInvalide,
}

impl std::fmt::Display for ErreurAutorite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonHexadecimal => write!(f, "caractères non hexadécimaux"),
            Self::CleInvalide => write!(
                f,
                "ce n'est pas une clé publique hybride courante (longueur ou \
                 version d'algorithme)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::sig::SigKeypair;

    /// L'invariant qui justifie ce module : ce que le nœud IMPRIME est exactement ce
    /// que la genèse ACCEPTE. Les deux extrémités du seul geste par lequel une
    /// fédération se constitue.
    #[test]
    fn ce_que_le_noeud_publie_est_ce_que_la_genese_accepte() {
        let paire = SigKeypair::generate();
        let publie = encoder(&paire.public);
        let relue = decoder(&publie).expect("la clé publiée doit se relire");
        assert_eq!(relue.to_bytes(), paire.public.to_bytes());
    }

    /// Une clé arrive par copier-coller : retour à la ligne, espaces, tabulation.
    /// Elle doit passer — sinon l'opérateur cherche une faute qui n'existe pas.
    #[test]
    fn une_cle_collee_depuis_un_terminal_passe() {
        let paire = SigKeypair::generate();
        let publie = encoder(&paire.public);
        for orne in [
            format!("{publie}\n"),
            format!("  {publie}  "),
            format!("\t{publie}\r\n"),
        ] {
            let relue = decoder(&orne).expect("les espaces de bordure sont tolérés");
            assert_eq!(relue.to_bytes(), paire.public.to_bytes());
        }
    }

    /// Une entrée abîmée est REFUSÉE, nommément, jamais paniquée : `--autorite-hex`
    /// est lu depuis une ligne de commande, donc depuis une frappe humaine.
    ///
    /// (`SigPublicKey` n'implémente ni `Debug` ni `PartialEq` — délibéré : une clé ne
    /// doit pas se retrouver dans un journal par inadvertance, et la comparer se fait
    /// sur ses octets. D'où `unwrap_err` plutôt qu'un `assert_eq!` sur le `Result`.)
    #[test]
    fn une_entree_abimee_est_refusee_par_son_nom() {
        let refus = |t: &str| decoder(t).err().expect("doit être refusé");
        assert_eq!(refus("pas de l'hexa"), ErreurAutorite::NonHexadecimal);
        assert_eq!(refus("0xabcd"), ErreurAutorite::NonHexadecimal);
        // Hexadécimal valide, mais bien trop court pour une clé hybride.
        assert_eq!(refus("00ff"), ErreurAutorite::CleInvalide);
        assert_eq!(refus(""), ErreurAutorite::CleInvalide);
    }

    /// Une clé TRONQUÉE d'un seul octet est refusée. C'est le mode de défaillance
    /// réel d'un copier-coller sur ~2 Kio d'hexadécimal : la sélection s'arrête un
    /// caractère trop tôt et rien ne le signale à l'œil.
    #[test]
    fn une_cle_tronquee_est_refusee() {
        let paire = SigKeypair::generate();
        let publie = encoder(&paire.public);
        let ampute = &publie[..publie.len() - 2];
        assert_eq!(
            decoder(ampute).err().expect("doit être refusé"),
            ErreurAutorite::CleInvalide
        );
    }
}
