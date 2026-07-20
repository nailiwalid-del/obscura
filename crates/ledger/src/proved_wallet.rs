//! Wallet du chemin PROUVÉ : chiffrement et scan des sorties d'une `ProvedTx`.
//!
//! Une sortie prouvée est un `circuit::SpendNote` (owner = `H_owner(secret)`, un
//! `Digest` Rescue — PAS l'owner BLAKE3 du mode transparent). Ces helpers chiffrent la
//! note vers la clé KEM du destinataire (`enc_note`) et permettent au destinataire de
//! scanner : décapsuler → déchiffrer → vérifier commitment + owner. Ils réutilisent le
//! KEM hybride et l'AEAD en cascade du crate `crypto`, comme le mode transparent.
//!
//! Les `EncNote` produits ici sont liés dans `tx_digest` v3 (cf. `circuit::tx`) :
//! une substitution par un relais casse le digest → la signature d'intention échoue.
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
