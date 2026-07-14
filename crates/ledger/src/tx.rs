//! Transactions : construction (côté wallet) et encodage canonique.
//!
//! Le format actuel (`TxInput` avec commitment, chemin de Merkle et spend_pk en
//! clair) est le MODE TRANSPARENT de développement. La transaction cible ne
//! publie que { proof, root, nullifiers, output_commitments, enc_notes, fee } —
//! voir docs/STARK_STATEMENT.md.

use crate::keys::{Address, WalletKeys};
use crate::merkle::{MerklePath, MerkleTree};
use crate::note::Note;
use crate::{Commitment, LedgerError};
use crypto::{aead, hash, kem};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub root: [u8; 32],
    pub commitment: Commitment,
    pub path: MerklePath,
    pub nullifier: [u8; 32],
    pub spend_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub commitment: Commitment,
    /// Encapsulation KEM hybride vers la clé de réception du destinataire.
    pub kem_ct: Vec<u8>,
    /// Note chiffrée (AEAD cascade, aad = commitment).
    pub enc_note: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
}

pub const SIG_DOMAIN: &str = "obscura/tx-sig/v1";

impl Transaction {
    /// Digest canonique (exclut les signatures, couvre tout le reste).
    pub fn digest(&self) -> [u8; 32] {
        let mut b = Vec::new();
        b.extend_from_slice(&self.fee.to_le_bytes());
        b.extend_from_slice(&(self.inputs.len() as u64).to_le_bytes());
        for i in &self.inputs {
            b.extend_from_slice(&i.root);
            b.extend_from_slice(&i.commitment.to_bytes());
            b.extend_from_slice(&i.nullifier);
            b.extend_from_slice(&i.path.index.to_le_bytes());
            for s in &i.path.siblings {
                b.extend_from_slice(s);
            }
            b.extend_from_slice(&(i.spend_pk.len() as u64).to_le_bytes());
            b.extend_from_slice(&i.spend_pk);
        }
        b.extend_from_slice(&(self.outputs.len() as u64).to_le_bytes());
        for o in &self.outputs {
            b.extend_from_slice(&o.commitment.to_bytes());
            b.extend_from_slice(&(o.kem_ct.len() as u64).to_le_bytes());
            b.extend_from_slice(&o.kem_ct);
            b.extend_from_slice(&(o.enc_note.len() as u64).to_le_bytes());
            b.extend_from_slice(&o.enc_note);
        }
        hash::blake3_domain("obscura/tx-digest/v1", &b)
    }
}

/// Note à dépenser : la note en clair + son index dans l'arbre.
pub struct SpendInfo {
    pub note: Note,
    pub index: u64,
}

/// Construit une transaction en MODE TRANSPARENT (dev uniquement).
///
/// L'équilibre Σ entrées = Σ sorties + fee n'est vérifié qu'ici, côté wallet :
/// le consensus transparent NE PEUT PAS le vérifier. C'est le statement STARK
/// (P5, P6) qui en fera une règle de consensus.
pub fn build_transparent_transaction(
    wallet: &WalletKeys,
    tree: &MerkleTree,
    spends: &[SpendInfo],
    recipients: &[(Address, u64)],
    fee: u64,
) -> Result<Transaction, LedgerError> {
    let total_in: u64 = spends.iter().map(|s| s.note.value).sum();
    let total_out: u64 = recipients.iter().map(|(_, v)| v).sum();
    if total_in != total_out + fee {
        return Err(LedgerError::Unbalanced);
    }

    let root = tree.root();
    let mut inputs = Vec::with_capacity(spends.len());
    for s in spends {
        let path = tree.path(s.index).ok_or(LedgerError::UnknownIndex)?;
        inputs.push(TxInput {
            root,
            commitment: s.note.commitment(),
            path,
            nullifier: s.note.nullifier(&wallet.nk),
            spend_pk: wallet.spend.public.to_bytes(),
            sig: Vec::new(), // rempli après calcul du digest
        });
    }

    let mut outputs = Vec::with_capacity(recipients.len());
    for (addr, value) in recipients {
        let note = Note::new(*value, addr.owner);
        let commitment = note.commitment();
        let (kem_ct, ss) = kem::encapsulate(&addr.kem_pk);
        let enc_note = aead::encrypt(&ss, &commitment.to_bytes(), &note.to_bytes());
        outputs.push(TxOutput { commitment, kem_ct: kem_ct.to_bytes(), enc_note });
    }

    let mut tx = Transaction { inputs, outputs, fee };
    let digest = tx.digest();
    let sig = wallet.spend.sign(SIG_DOMAIN, &digest).to_bytes();
    for i in &mut tx.inputs {
        i.sig = sig.clone();
    }
    Ok(tx)
}

/// Scan d'une sortie par un destinataire : essaie de déchiffrer avec ses clés.
/// Retourne la note si elle lui est destinée (et vérifie le commitment).
pub fn scan_output(wallet: &WalletKeys, out: &TxOutput) -> Option<Note> {
    let ct = kem::KemCiphertext::from_bytes(&out.kem_ct).ok()?;
    let ss = kem::decapsulate(&wallet.receive, &ct);
    let pt = aead::decrypt(&ss, &out.commitment.to_bytes(), &out.enc_note).ok()?;
    let note = Note::from_bytes(&pt).ok()?;
    if note.commitment() == out.commitment && note.owner == wallet.address().owner {
        Some(note)
    } else {
        None
    }
}
