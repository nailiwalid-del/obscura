//! Wallet du chemin PROUVÉ : chiffrement et scan des sorties d'une `ProvedTx`.
//!
//! Une sortie prouvée est un `circuit::SpendNote` (owner = `H_owner(secret)`, un
//! `Digest` Rescue — PAS l'owner BLAKE3 du mode transparent). Ces helpers chiffrent la
//! note vers la clé KEM du destinataire (`enc_note`) et permettent au destinataire de
//! scanner : décapsuler → déchiffrer → vérifier commitment + owner. Ils réutilisent le
//! KEM hybride et l'AEAD en cascade du crate `crypto`, comme le mode transparent.
//!
//! Les `EncNote` produits ici sont liés dans `tx_digest` v3 (cf. `circuit::tx`) :
//! un relais PASSIF ne peut pas les substituer sans casser le digest → la signature
//! d'intention (sur le digest) échoue. ⚠️ La preuve STARK ne lie pas `tx_digest`/
//! `signer` : un relais ACTIF peut re-signer un substitut (déni de scan du
//! destinataire, PAS de vol — voir `circuit::tx`).
//!
//! Prend des arguments EXPLICITES (clé KEM du destinataire, owner prouvé attendu) plutôt
//! qu'un `WalletKeys` complet — le modèle d'identité prouvé (owner Rescue) diffère du
//! modèle transparent (owner BLAKE3) ; ce découplage évite de mélanger les deux.

use circuit::{EncNote, SpendNote};
use crypto::{aead, kem};
use proved_hash::digest::Digest;
use proved_hash::rescue;

/// Chiffre `note` (sortie prouvée) vers `recipient_kem_pk`. `commitment` (public) sert
/// d'`aad` AEAD → lie cryptographiquement le chiffré à SON commitment (au-delà du digest).
/// Précondition : `commitment == rescue::note_commitment(note.value, note.owner, note.rho, note.r)`.
pub fn encrypt_note(
    recipient_kem_pk: &kem::KemPublicKey,
    commitment: &Digest,
    note: &SpendNote,
) -> EncNote {
    let (kem_ct, ss) = kem::encapsulate(recipient_kem_pk);
    let enc_note = aead::encrypt(&ss, &commitment.to_bytes(), &note.to_bytes());
    EncNote { kem_ct: kem_ct.to_bytes(), enc_note }
}

/// Scanne une sortie prouvée : tente de déchiffrer `e` avec la paire KEM `receive`, et
/// ne rend la note QUE si (1) elle déchiffre, (2) son commitment recalculé == `commitment`
/// (le public de la tx), et (3) son owner == `expected_owner` (l'owner prouvé du wallet,
/// `H_owner(secret)`). Retourne `None` si la sortie n'est pas destinée à ce wallet ou est
/// incohérente (expéditeur malveillant — P8 non prouvé, cf. STARK_STATEMENT).
pub fn scan_proved_output(
    receive: &kem::KemKeypair,
    expected_owner: &Digest,
    commitment: &Digest,
    e: &EncNote,
) -> Option<SpendNote> {
    let ct = kem::KemCiphertext::from_bytes(&e.kem_ct).ok()?;
    let ss = kem::decapsulate(receive, &ct);
    let pt = aead::decrypt(&ss, &commitment.to_bytes(), &e.enc_note).ok()?;
    let note = SpendNote::from_bytes(&pt)?;
    let recomputed = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
    (recomputed == *commitment && note.owner == *expected_owner).then_some(note)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            proved_hash::felt::Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    // ================================================================================
    // KEY PRIVACY (IK-CCA) — test distingueur
    // ================================================================================
    //
    // Exigence (PROTOCOL.md, « Chiffrement des notes ») : `enc_note` ne doit pas
    // permettre de deviner le destinataire, même parmi une liste de clés publiques
    // CONNUES. IND-CCA seul ne suffit pas.
    //
    // ⚠️ PORTÉE HONNÊTE DE CES TESTS. Un test unitaire ne peut PAS établir IK-CCA :
    // c'est une réduction cryptographique, qui repose ici sur (a) l'éphémère X25519
    // indistinguable d'un point aléatoire, (b) l'anonymat (ANO-CCA) de Kyber768 à
    // rejet implicite, (c) l'absence d'identifiant de clé dans l'AEAD cascade. Ces
    // arguments sont dans PROTOCOL.md et NE sont pas vérifiés ici.
    //
    // Ce que ces tests établissent, c'est l'absence de fuite STRUCTURELLE — la
    // classe d'erreur qu'une implémentation introduit réellement : une longueur qui
    // dépend du destinataire, un fragment de clé publique recopié en clair, un
    // chiffrement déterministe, ou un octet dont la valeur trahit le destinataire.
    // Aucun de ces défauts n'est exclu par les arguments théoriques ci-dessus : ils
    // relèvent du code, donc du test.

    /// Nombre d'échantillons par destinataire pour le jeu du distingueur. Un octet
    /// réellement aléatoire est constant sur 24 tirages avec probabilité 256⁻²³ —
    /// le test est donc déterministe en pratique, sans seuil statistique arbitraire.
    const ECHANTILLONS: usize = 24;

    /// Chiffre `n` fois LA MÊME note, sous LE MÊME commitment, vers `dest`.
    ///
    /// Note et commitment sont FIXES : la seule variable est la clé du destinataire,
    /// donc toute différence observable est imputable à lui — c'est ce qui fait du
    /// test un distingueur et pas une simple comparaison de chiffrés.
    fn echantillons_vers(dest: &kem::KemPublicKey, n: usize) -> Vec<EncNote> {
        let note = SpendNote {
            value: 1_000,
            owner: digest(777),
            rho: digest(20),
            r: digest(30),
        };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        (0..n).map(|_| encrypt_note(dest, &cm, &note)).collect()
    }

    /// (1) INVARIANCE DE LONGUEUR : une longueur qui dépendrait du destinataire
    /// serait un distingueur immédiat, lisible sans aucune cryptanalyse.
    #[test]
    fn key_privacy_longueurs_invariantes() {
        let a = kem::KemKeypair::generate();
        let b = kem::KemKeypair::generate();
        let ea = echantillons_vers(&a.public, 4);
        let eb = echantillons_vers(&b.public, 4);

        let (lk, ln) = (ea[0].kem_ct.len(), ea[0].enc_note.len());
        for e in ea.iter().chain(eb.iter()) {
            assert_eq!(e.kem_ct.len(), lk, "longueur kem_ct dépendante du destinataire");
            assert_eq!(e.enc_note.len(), ln, "longueur enc_note dépendante du destinataire");
        }
    }

    /// (2) AUCUNE MATIÈRE DU DESTINATAIRE EN CLAIR : le chiffré ne doit contenir
    /// aucun fragment de la clé publique visée. C'est la fuite la plus grossière —
    /// et la plus facile à introduire par mégarde en sérialisant « pour déboguer ».
    #[test]
    fn key_privacy_aucun_fragment_de_cle_en_clair() {
        let a = kem::KemKeypair::generate();
        let e = &echantillons_vers(&a.public, 1)[0];
        let pk = a.public.to_bytes();
        let mut corpus = e.kem_ct.clone();
        corpus.extend_from_slice(&e.enc_note);

        // Toute fenêtre de 8 octets consécutifs de la clé publique serait déjà une
        // signature exploitable (8 octets = 2^64 possibilités, la collision fortuite
        // est négligeable).
        for fenetre in pk.windows(8) {
            assert!(
                !corpus.windows(8).any(|w| w == fenetre),
                "fragment de la clé publique du destinataire présent en clair"
            );
        }
    }

    /// (3) CHIFFREMENT RANDOMISÉ : deux envois de la MÊME note au MÊME destinataire
    /// doivent différer. Un chiffrement déterministe rendrait les paiements
    /// répétés liables entre eux, indépendamment de toute question de destinataire.
    #[test]
    fn key_privacy_chiffrement_randomise() {
        let a = kem::KemKeypair::generate();
        let e = echantillons_vers(&a.public, 2);
        assert_ne!(e[0].kem_ct, e[1].kem_ct, "kem_ct déterministe");
        assert_ne!(e[0].enc_note, e[1].enc_note, "enc_note déterministe");
    }

    /// (4) JEU DU DISTINGUEUR, position par position.
    ///
    /// Pour CHAQUE position d'octet du chiffré, on rejette le cas où elle serait
    /// constante à l'intérieur du groupe A, constante à l'intérieur du groupe B,
    /// et DIFFÉRENTE entre les deux — c'est exactement la forme d'un octet
    /// « empreinte du destinataire ».
    ///
    /// Formulation déterministe et sans seuil : les positions structurellement
    /// constantes (byte de version 0x01) sont constantes dans les DEUX groupes avec
    /// la MÊME valeur, donc non séparantes et légitimement acceptées.
    #[test]
    fn key_privacy_aucune_position_ne_separe_les_destinataires() {
        let a = kem::KemKeypair::generate();
        let b = kem::KemKeypair::generate();
        let ea = echantillons_vers(&a.public, ECHANTILLONS);
        let eb = echantillons_vers(&b.public, ECHANTILLONS);

        // Concaténation kem_ct ‖ enc_note : tout ce qu'un observateur voit passer.
        let aplati = |v: &[EncNote]| -> Vec<Vec<u8>> {
            v.iter()
                .map(|e| {
                    let mut o = e.kem_ct.clone();
                    o.extend_from_slice(&e.enc_note);
                    o
                })
                .collect()
        };
        let (fa, fb) = (aplati(&ea), aplati(&eb));
        let taille = fa[0].len();

        let constante_a = |g: &[Vec<u8>], i: usize| -> Option<u8> {
            let v = g[0][i];
            g.iter().all(|x| x[i] == v).then_some(v)
        };

        for i in 0..taille {
            if let (Some(va), Some(vb)) = (constante_a(&fa, i), constante_a(&fb, i)) {
                assert_eq!(
                    va, vb,
                    "l'octet {i} est constant par destinataire et DIFFÈRE entre eux : \
                     c'est une empreinte du destinataire (fuite de key privacy)"
                );
            }
        }
    }

    /// Roundtrip : le destinataire retrouve SA note ; un tiers échoue.
    #[test]
    fn enc_note_roundtrip_prouve() {
        let alice = kem::KemKeypair::generate();
        let bob = kem::KemKeypair::generate();
        // Owner prouvé d'Alice (arbitraire pour ce test : le scan compare owner == expected).
        let owner_alice = digest(777);
        let note = SpendNote { value: 1_000, owner: owner_alice, rho: digest(20), r: digest(30) };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);

        let e = encrypt_note(&alice.public, &cm, &note);
        // Alice, avec son owner prouvé, retrouve la note.
        assert_eq!(scan_proved_output(&alice, &owner_alice, &cm, &e), Some(note.clone()));
        // Bob (autre clé KEM) échoue à déchiffrer.
        assert_eq!(scan_proved_output(&bob, &owner_alice, &cm, &e), None);
        // Même Alice, mais owner attendu différent → rejet (la note ne lui appartient pas).
        assert_eq!(scan_proved_output(&alice, &digest(888), &cm, &e), None);
    }

    /// Un `commitment` public qui ne correspond pas à la note chiffrée → rejet (aad AEAD
    /// diffère ET le commitment recalculé diffère).
    #[test]
    fn commitment_incoherent_rejete() {
        let alice = kem::KemKeypair::generate();
        let owner = digest(777);
        let note = SpendNote { value: 1_000, owner, rho: digest(20), r: digest(30) };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        let e = encrypt_note(&alice.public, &cm, &note);
        // Scanner avec un mauvais commitment public.
        assert_eq!(scan_proved_output(&alice, &owner, &digest(999), &e), None);
    }
}
