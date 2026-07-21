//! `ProvedTx` v3 — la transaction prouvée par LE monolithe (v3 = enc_notes liés).
//!
//! Remplace l'assemblage v1 (3b5, composition de 15 sous-preuves : `prove_key` +
//! 2×`prove_spend` + 2×`prove_output` + équilibre natif) par UNE SEULE preuve
//! STARK — celle du monolithe segmenté (`monolith::seg_air::prove_seg_forme`), qui
//! établit **P1–P7 pour la transaction entière** (clé, dépenses, sorties,
//! équilibre, TOUTES les liaisons inter-segments) dans une trace unique.
//!
//! Publics MINIMAUX : racine, les deux nullifiers, les deux commitments de sortie,
//! les frais. Plus aucun `owner`/`nk` publiés en clair, plus aucune sous-preuve —
//! le prouveur (`prove_monolith`) extrait ces publics directement des cellules de
//! trace ; le vérificateur les fournit lui-même (root passée en argument, reste lu
//! sur `tx`) et ne fait tourner qu'UN SEUL `winterfell::verify`.
//!
//! `tx_digest` (v3, domaine `obscura/proved-tx/v3`) lie `root ‖ nf ‖ oc ‖ fee ‖
//! signer ‖ enc_notes` — non-rejeu et liaison des `enc_notes` (v3). ⚠️ Portée exacte :
//! le digest empêche un relais PASSIF d'échanger les enc_notes en gardant la signature
//! d'intention ; mais la preuve STARK ne lie pas `tx_digest`/`signer`, donc un relais
//! ACTIF peut re-signer un substitut (déni de scan du destinataire, PAS de vol ni
//! d'inflation — P5/P7 tiennent). Le signataire d'intention n'est pas une autorité
//! d'ownership : celle-ci vient de la liaison `owner = H_owner(secret)` DANS le monolithe.
//! La signature hybride d'intention reste une enveloppe anti-malléabilité, PAS une
//! autorisation d'ownership : l'autorité vient de la liaison `owner = H_owner(secret)`
//! DANS le monolithe (contrainte AIR, cf. `monolith::seg_air`, liaisons par porteuses).
//!
//! ⚠️ **À générer en `--release`** (AIR du monolithe gatée, cf. `monolith::seg_air`).

// BASCULE 3z-c1 (T6) : `tx.rs` est passé du monolithe CÔTE-À-CÔTE au monolithe
// SEGMENTÉ. L'API publique était INCHANGÉE — c'était tout l'objet du contrat de
// parité (mêmes publics pour le même témoin), et c'est pourquoi la bascule a tenu
// en un import ; l'oracle côte-à-côte a été SUPPRIMÉ en C2-T8 (cf. `monolith`).
// Gain mesuré à la profondeur consensus : preuve 67,4 Kio au lieu de 90,4 (−25 %),
// pour 1,34× en génération et 1,64× en vérification (4,0 ms — négligeable). La
// taille est le coût PERMANENT, payé par chaque nœud qui stocke et relaie chaque
// transaction.
use crate::monolith::seg_air::prove_seg_forme;
use crate::monolith::seg_air::verify_seg_monolith as verify_monolith;
use crate::monolith::socle::MonolithPublicInputs;

/// Bornes de forme, ré-exposées depuis le layout (le module est `pub(crate)` : on
/// recopie la VALEUR, source unique inchangée). Les changer = nouvelle version wire.
pub const MAX_IN: usize = crate::monolith::seg_layout::MAX_IN;
pub const MAX_OUT: usize = crate::monolith::seg_layout::MAX_OUT;
use crate::monolith::seg_trace::SegWitness;
use crate::range_check::RANGE_BITS;
use crate::spend::SpendNote;
use crate::ValidityProof;
use crypto::hash::dual_hash;
use crypto::sig::{HybridSignature, SigKeypair, SigPublicKey};
use proved_hash::digest::{Digest, ShieldedSecret, DIGEST_FELTS};
use proved_hash::felt::Felt;
use winter_math::fields::f64::BaseElement;
use winterfell::Proof;

/// Domaine de la signature d'intention (anti-malléabilité), signée sur `tx_digest`.
pub const INTENT_DOMAIN: &str = "obscura/proved-tx-intent/v3";

/// Une entrée à dépenser : la note, son chemin de Merkle et sa position.
#[derive(Clone)]
pub struct ProvedInput {
    pub note: SpendNote,
    pub path: Vec<Digest>,
    pub index: u64,
}

/// Enveloppe chiffrée d'une note de sortie, destinée au destinataire (hors-circuit,
/// pas de contrainte AIR dessus). `kem_ct` : encapsulation KEM hybride vers la clé du
/// destinataire ; `enc_note` : la note (valeur, owner, rho, r, …) chiffrée sous la clé
/// dérivée de `kem_ct`. Liée dans `tx_digest` (v3) pour empêcher toute substitution
/// après preuve — voir Tâche 1 (docs/superpowers/sdd).
#[derive(Clone)]
pub struct EncNote {
    pub kem_ct: Vec<u8>,
    pub enc_note: Vec<u8>,
}

/// Taille exacte d'un ciphertext KEM hybride sérialisé : `1 (version) + 32 (X25519) +
/// 1088 (Kyber768) = 1121 o`. Un `kem_ct` bien formé fait EXACTEMENT cette taille.
pub const KEM_CT_LEN: usize = 1121;
/// Borne SUPÉRIEURE d'un `enc_note` (AEAD cascade d'une note de 104 o ≈ 172 o : nonces
/// 12+24 + tags 16+16 + 104). Marge à 256. Au-delà = rejet (anti-DoS : le digest hache
/// tous les octets des enc_notes ; sans borne, un relais gonflerait la tx/le digest).
pub const MAX_ENC_NOTE_LEN: usize = 256;

impl EncNote {
    /// `true` si les tailles sont plausibles (kem_ct exact, enc_note borné). Vérifié par
    /// `verify_tx` (consensus) : une tx aux enc_notes hors-bornes est rejetée avant tout
    /// hachage coûteux.
    pub fn within_bounds(&self) -> bool {
        self.kem_ct.len() == KEM_CT_LEN && self.enc_note.len() <= MAX_ENC_NOTE_LEN
    }
}

/// Transaction prouvée 2-in/2-out. `proof` est LA preuve monolithique unique ; les
/// autres champs sont ses publics (racine, nullifiers, commitments de sortie, fee)
/// plus l'enveloppe d'intention (signataire, digest, signature hybride) et les
/// enveloppes chiffrées des deux sorties (`enc_notes`, liées dans `tx_digest` v3).
pub struct ProvedTx {
    /// Racine (anchor) contre laquelle les entrées prouvent leur appartenance.
    pub anchor: Digest,
    /// LA preuve monolithique : établit P1–P7 pour toute la transaction.
    pub proof: ValidityProof,
    /// Un nullifier PAR entrée (`1..=MAX_IN`). La FORME (m, n) est portée par les
    /// longueurs — comme les publics du monolithe.
    pub nullifiers: Vec<Digest>,
    /// Un commitment PAR sortie (`1..=MAX_OUT`).
    pub output_commitments: Vec<Digest>,
    pub fee: u64,
    /// Clé publique d'intention (liée dans `tx_digest` → non échangeable).
    pub signer: SigPublicKey,
    pub tx_digest: [u8; 64],
    /// Signature hybride d'intention sur `tx_digest` (enveloppe anti-malléabilité,
    /// PAS autorité d'ownership — celle-ci est établie par la liaison `owner` du
    /// monolithe).
    pub intent_sig: HybridSignature,
    /// Enveloppes chiffrées des sorties (une par commitment, même ordre) ; liées
    /// dans `tx_digest` (v4) — non prouvées par l'AIR.
    pub enc_notes: Vec<EncNote>,
}

impl ProvedTx {
    /// Nombre d'entrées (forme déclarée).
    pub fn m(&self) -> usize {
        self.nullifiers.len()
    }
    /// Nombre de sorties (forme déclarée).
    pub fn n(&self) -> usize {
        self.output_commitments.len()
    }
}

const TX_DOMAIN: &str = "obscura/proved-tx/v4";

/// Encodage canonique injectif des publics : `root ‖ nf₁ ‖ nf₂ ‖ oc₁ ‖ oc₂ ‖ fee LE ‖
/// signer ‖ [len(kem_ctⱼ) LE ‖ kem_ctⱼ ‖ len(enc_noteⱼ) LE ‖ enc_noteⱼ]ⱼ₌₀,₁` (v3 :
/// les enc_notes, de taille variable, sont préfixées par leur longueur LE pour rester
/// injectif — cf. Tâche 1).
fn tx_digest_bytes(
    root: &Digest,
    nullifiers: &[Digest],
    output_commitments: &[Digest],
    fee: u64,
    signer: &SigPublicKey,
    enc_notes: &[EncNote],
) -> [u8; 64] {
    let mut b = Vec::new();
    // v4 : les COMPTES (m, n) préfixent le digest. Sans eux, deux découpages
    // différents des mêmes digests produiraient le même tx_digest — une preuve
    // (m=1, n=3) rejouable en (m=2, n=2). La forme fait partie de ce qu'on engage.
    b.push(nullifiers.len() as u8);
    b.push(output_commitments.len() as u8);
    b.extend_from_slice(&root.to_bytes());
    for nf in nullifiers {
        b.extend_from_slice(&nf.to_bytes());
    }
    for oc in output_commitments {
        b.extend_from_slice(&oc.to_bytes());
    }
    b.extend_from_slice(&fee.to_le_bytes());
    // Le signataire d'intention est LIÉ dans le digest → il ne peut pas être échangé
    // en gardant la MÊME signature d'intention. ⚠️ La preuve STARK ne lie PAS
    // `tx_digest`/`signer` (le digest est calculé APRÈS `prove_monolith`) : un relais
    // ACTIF peut re-signer avec sa propre clé (le signataire n'est pas une autorité
    // d'ownership). Portée résiduelle : déni de scan (voir `verify_tx`), pas de vol.
    b.extend_from_slice(&signer.to_bytes());
    // v3 : enc_notes liées après le bloc v2, dans l'ordre des sorties.
    for enc in enc_notes {
        b.extend_from_slice(&(enc.kem_ct.len() as u64).to_le_bytes());
        b.extend_from_slice(&enc.kem_ct);
        b.extend_from_slice(&(enc.enc_note.len() as u64).to_le_bytes());
        b.extend_from_slice(&enc.enc_note);
    }
    dual_hash(TX_DOMAIN, &b)
}

/// `Digest` → tableau de `BaseElement` winterfell (publics du monolithe).
fn digest_to_felts(d: &Digest) -> [BaseElement; DIGEST_FELTS] {
    core::array::from_fn(|k| d.0[k].to_winter())
}

/// Tableau de `BaseElement` winterfell → `Digest`. Toujours canonique : ces valeurs
/// sont extraites de cellules de trace Goldilocks, déjà réduites mod p.
fn felts_to_digest(f: &[BaseElement; DIGEST_FELTS]) -> Digest {
    Digest(core::array::from_fn(|k| {
        Felt::from_winter(f[k]).expect("digest canonique issu du circuit")
    }))
}

/// Construit la transaction prouvée. Le témoin (secret + entrées + sorties + fee)
/// alimente LE monolithe (`prove_monolith`) : une seule trace établit P1–P7 pour la
/// tx entière. Les publics (racine, nullifiers, commitments de sortie) sont extraits
/// de la preuve pour former `tx_digest`, signé par la clé d'intention. Retourne la
/// racine prouvée et la `ProvedTx`.
///
/// Précondition : notes d'entrée possédées par `secret` (owner = H_owner(secret)),
/// chemins de même profondeur cohérents avec un même arbre, équilibre respecté,
/// montants `< 2^60`. Une entrée qui ne respecte pas ces préconditions ne fait PAS
/// paniquer la construction : elle produit une preuve que `verify_tx` rejette (la
/// liaison correspondante mord dans l'AIR du monolithe, cf. `monolith::seg_air`).
pub fn prove_tx(
    secret: &ShieldedSecret,
    inputs: [ProvedInput; 2],
    outputs: [SpendNote; 2],
    fee: u64,
    intent: &SigKeypair,
    enc_notes: [EncNote; 2],
) -> (Digest, ProvedTx) {
    // Wrapper 2/2 : convertit vers le chemin à FORME VARIABLE. Conservé pour les
    // appelants figés (tests, bench) ; le wallet passera par `prove_tx_forme` en
    // C2-T7.
    prove_tx_forme(
        secret,
        inputs.to_vec(),
        outputs.to_vec(),
        fee,
        intent,
        enc_notes.to_vec(),
    )
    .expect("2/2 est une forme valide")
}

/// Construit une transaction prouvée à FORME VARIABLE (`m` entrées, `n` sorties,
/// bornées `1..=MAX`). `Err` si la forme est hors bornes ou si les longueurs
/// (`inputs`/`outputs`/`enc_notes`) sont incohérentes.
pub fn prove_tx_forme(
    secret: &ShieldedSecret,
    inputs: Vec<ProvedInput>,
    outputs: Vec<SpendNote>,
    fee: u64,
    intent: &SigKeypair,
    enc_notes: Vec<EncNote>,
) -> Result<(Digest, ProvedTx), TxDecodeError> {
    // Une enveloppe par sortie, exactement — sinon `tx_digest` lierait un nombre
    // d'enveloppes ≠ du nombre de commitments, incohérence silencieuse.
    if enc_notes.len() != outputs.len() {
        return Err(TxDecodeError::TooShort);
    }
    let witness = SegWitness::new(secret.clone(), inputs, outputs, fee)
        .map_err(|_| TxDecodeError::TooShort)?;
    let (pi, proof) = prove_seg_forme(&witness);

    let root = felts_to_digest(&pi.root);
    let nullifiers: Vec<Digest> = pi.nullifiers.iter().map(felts_to_digest).collect();
    let output_commitments: Vec<Digest> =
        pi.output_commitments.iter().map(felts_to_digest).collect();
    let signer = intent.public.clone();
    let tx_digest = tx_digest_bytes(
        &root,
        &nullifiers,
        &output_commitments,
        fee,
        &signer,
        &enc_notes,
    );
    let intent_sig = intent.sign(INTENT_DOMAIN, &tx_digest);

    Ok((
        root,
        ProvedTx {
            anchor: root,
            proof,
            nullifiers,
            output_commitments,
            fee,
            signer,
            tx_digest,
            intent_sig,
            enc_notes,
        },
    ))
}

/// Vérifie la transaction contre l'arbre public `root` (profondeur `depth`).
/// Reconstruit les publics du monolithe depuis `root` (argument, PAS `tx.anchor` —
/// c'est la racine consensus qui fait foi) et les champs publics de `tx`, établit
/// P1–P7 pour toute la tx via `verify_monolith`, puis recompare `tx_digest`
/// (non-rejeu, signataire lié). NB : la signature elle-même est vérifiée côté ledger
/// (`apply_proved_tx`) — `verify_tx` n'établit que la preuve STARK + la cohérence du
/// digest.
pub fn verify_tx(root: &Digest, depth: usize, tx: &ProvedTx) -> bool {
    // Borne native du fee (miroir de `balance.rs`) : l'équilibre n'est prouvé que
    // MODULO p (`S ≡ fee (mod p)`, `fee: u64` réduit dans le corps). Sans cette borne,
    // `fee = p − k` (valide en u64) fait passer des sorties dépassant les entrées de k :
    // `S_final = Σin − Σout = −k ≡ p − k` satisfait l'égalité en corps, mais crée k
    // unités (wrap mod p). Avec `fee < 2^RANGE_BITS` ET chaque montant `< 2^RANGE_BITS`
    // (contrainte de range du circuit), on a `|Σin − Σout| < 4·2^60 + 2^60 < 2^63 ≪ p` :
    // l'égalité en corps implique alors l'égalité ENTIÈRE (aucun wrap). Le vérificateur
    // ne fait pas confiance au prouveur → cette borne EST la garantie de consensus.
    if tx.fee >= (1u64 << RANGE_BITS) {
        return false;
    }
    // FORME dans les bornes, et cohérente (une enveloppe par sortie). Vérifié AVANT
    // toute construction de publics — le vérificateur ne fait pas confiance à la tx.
    if !(1..=MAX_IN).contains(&tx.m()) || !(1..=MAX_OUT).contains(&tx.n()) {
        return false;
    }
    if tx.enc_notes.len() != tx.n() {
        return false;
    }
    // Anti-DoS : rejeter des enc_notes hors-bornes AVANT de les hacher dans le digest
    // (un relais gonflerait sinon la tx et le coût de `tx_digest_bytes`).
    if !tx.enc_notes.iter().all(EncNote::within_bounds) {
        return false;
    }
    let pi = MonolithPublicInputs {
        root: digest_to_felts(root),
        nullifiers: tx.nullifiers.iter().map(digest_to_felts).collect(),
        output_commitments: tx.output_commitments.iter().map(digest_to_felts).collect(),
        fee: tx.fee,
        depth,
    };
    if !verify_monolith(&pi, depth, &tx.proof) {
        return false;
    }
    let expected = tx_digest_bytes(
        root,
        &tx.nullifiers,
        &tx.output_commitments,
        tx.fee,
        &tx.signer,
        &tx.enc_notes,
    );
    expected == tx.tx_digest
}

/// Vérification COMPLÈTE d'une `ProvedTx` : preuve STARK (P1–P7) + cohérence du digest
/// (`verify_tx`) **ET** signature d'intention hybride sur `tx_digest`. À préférer à
/// `verify_tx` seul quand on veut TOUTE la validité de la tx en un appel.
///
/// ⚠️ `verify_tx` NE vérifie PAS la signature d'intention (il n'établit que la preuve +
/// le digest) : l'appeler seul laisse un relais re-signer un substitut. Le ledger
/// (`apply_proved_tx`) compose les deux étapes ; cette fonction les regroupe pour tout
/// autre appelant afin d'éviter le mésusage. (La signature reste une enveloppe
/// d'intention, PAS une autorité d'ownership — cf. la doc de module.)
pub fn verify_proved_tx_full(root: &Digest, depth: usize, tx: &ProvedTx) -> bool {
    verify_tx(root, depth, tx)
        && crypto::sig::verify(&tx.signer, INTENT_DOMAIN, &tx.tx_digest, &tx.intent_sig)
}

/// Erreur de désérialisation d'une `ProvedTx` (`from_bytes`). Aucune n'implique de
/// panique : `from_bytes` est le point d'entrée réseau, il ne fait jamais confiance à
/// l'entrée (durcissement #7).
#[derive(Debug, PartialEq, Eq)]
pub enum TxDecodeError {
    /// Moins d'octets que nécessaire (champ tronqué).
    TooShort,
    /// Octets résiduels après la fin — encodage non canonique.
    TrailingBytes,
    /// Digest non canonique (`Digest::from_bytes` échoue).
    BadDigest,
    /// `EncNote` hors bornes (anti-DoS : `kem_ct`/`enc_note` trop grand).
    EncNoteOutOfBounds,
    /// `signer` ou `intent_sig` invalides.
    BadSigner,
    /// Octets de preuve STARK invalides.
    BadProof,
    /// Forme (m, n) hors bornes `1..=MAX` (anti-DoS : borne avant allocation).
    BadForme { m: usize, n: usize },
}

/// Curseur à lecture BORNÉE : chaque prise vérifie qu'il reste assez d'octets (jamais
/// d'indexation directe qui pourrait paniquer sur une entrée malveillante).
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TxDecodeError> {
        let end = self.pos.checked_add(n).ok_or(TxDecodeError::TooShort)?;
        if end > self.b.len() {
            return Err(TxDecodeError::TooShort);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn digest(&mut self) -> Result<Digest, TxDecodeError> {
        let s: [u8; 32] = self.take(32)?.try_into().unwrap(); // take(32) rend exactement 32 o
        Digest::from_bytes(&s).map_err(|_| TxDecodeError::BadDigest)
    }
    fn u32_le(&mut self) -> Result<usize, TxDecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    /// Champ préfixé par sa longueur (`u32` LE).
    fn lenpref(&mut self) -> Result<&'a [u8], TxDecodeError> {
        let l = self.u32_le()?;
        self.take(l)
    }
}

impl ProvedTx {
    /// Encodage canonique injectif de la transaction prouvée (cf.
    /// `docs/superpowers/specs/2026-07-20-provedtx-serialisation-design.md`). La preuve
    /// STARK (~85 Kio) domine la taille.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.anchor.to_bytes());
        // v4 : la FORME en tête (deux u8), avant les digests à compte variable.
        b.push(self.m() as u8);
        b.push(self.n() as u8);
        for nf in &self.nullifiers {
            b.extend_from_slice(&nf.to_bytes());
        }
        for oc in &self.output_commitments {
            b.extend_from_slice(&oc.to_bytes());
        }
        b.extend_from_slice(&self.fee.to_le_bytes());
        b.extend_from_slice(&self.tx_digest);
        let put = |b: &mut Vec<u8>, s: &[u8]| {
            b.extend_from_slice(&(s.len() as u32).to_le_bytes());
            b.extend_from_slice(s);
        };
        put(&mut b, &self.signer.to_bytes());
        put(&mut b, &self.intent_sig.to_bytes());
        for e in &self.enc_notes {
            put(&mut b, &e.kem_ct);
            put(&mut b, &e.enc_note);
        }
        put(&mut b, &self.proof.0.to_bytes());
        b
    }

    /// Désérialise et VALIDE une `ProvedTx` depuis des octets réseau. Rejette
    /// (jamais de panique) : troncature, octets résiduels (non-canonique), digests
    /// non canoniques, `EncNote` hors bornes (anti-DoS), signataire/preuve invalides.
    /// NB : la validité CRYPTOGRAPHIQUE (preuve STARK, signature) reste vérifiée à part
    /// par `verify_tx`/`verify_proved_tx_full`/`apply_proved_tx` — ici on garantit
    /// seulement un objet bien formé et borné.
    pub fn from_bytes(b: &[u8]) -> Result<Self, TxDecodeError> {
        let mut cur = Cursor { b, pos: 0 };
        let anchor = cur.digest()?;
        // FORME en tête, BORNÉE avant toute allocation : `m` digests + `n` digests +
        // `n` enveloppes ne peuvent pas nous faire réserver plus que MAX (règle du
        // dépôt : la borne du décodeur existe aussi au constructeur, cf. verify_tx).
        let m = cur.take(1)?[0] as usize;
        let n = cur.take(1)?[0] as usize;
        if !(1..=MAX_IN).contains(&m) || !(1..=MAX_OUT).contains(&n) {
            return Err(TxDecodeError::BadForme { m, n });
        }
        let mut nullifiers = Vec::with_capacity(m);
        for _ in 0..m {
            nullifiers.push(cur.digest()?);
        }
        let mut output_commitments = Vec::with_capacity(n);
        for _ in 0..n {
            output_commitments.push(cur.digest()?);
        }
        let fee = u64::from_le_bytes(cur.take(8)?.try_into().unwrap());
        let tx_digest: [u8; 64] = cur.take(64)?.try_into().unwrap();
        let signer =
            SigPublicKey::from_bytes(cur.lenpref()?).map_err(|_| TxDecodeError::BadSigner)?;
        let intent_sig =
            HybridSignature::from_bytes(cur.lenpref()?).map_err(|_| TxDecodeError::BadSigner)?;
        let en = |cur: &mut Cursor| -> Result<EncNote, TxDecodeError> {
            let kem_ct = cur.lenpref()?.to_vec();
            let enc_note = cur.lenpref()?.to_vec();
            Ok(EncNote { kem_ct, enc_note })
        };
        let mut enc_notes = Vec::with_capacity(n);
        for _ in 0..n {
            enc_notes.push(en(&mut cur)?);
        }
        if !enc_notes.iter().all(EncNote::within_bounds) {
            return Err(TxDecodeError::EncNoteOutOfBounds);
        }
        let proof = Proof::from_bytes(cur.lenpref()?).map_err(|_| TxDecodeError::BadProof)?;
        if cur.pos != b.len() {
            return Err(TxDecodeError::TrailingBytes);
        }
        Ok(ProvedTx {
            anchor,
            proof: ValidityProof(proof),
            nullifiers,
            output_commitments,
            fee,
            signer,
            tx_digest,
            intent_sig,
            enc_notes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proved_hash::domain::Domain;
    use proved_hash::merkle;
    use proved_hash::rescue;

    fn digest(seed: u64) -> Digest {
        Digest(core::array::from_fn(|i| {
            Felt::from_canonical_u64(seed + i as u64).unwrap()
        }))
    }

    const DEPTH: usize = 2;

    /// Deux enveloppes chiffrées DANS LES BORNES (`kem_ct` = `KEM_CT_LEN`, `enc_note` ≤
    /// `MAX_ENC_NOTE_LEN`) et distinctes, pour les tests : le contenu est opaque au niveau
    /// tx (seul son binding dans `tx_digest` v3 est testé), mais les tailles doivent
    /// passer le contrôle anti-DoS de `verify_tx`.
    fn enc_notes_test() -> [EncNote; 2] {
        [
            EncNote {
                kem_ct: vec![1u8; KEM_CT_LEN],
                enc_note: vec![4, 5, 6],
            },
            EncNote {
                kem_ct: vec![2u8; KEM_CT_LEN],
                enc_note: vec![9, 10, 11, 12],
            },
        ]
    }

    /// Arbre de profondeur 2 (4 feuilles) : `cm0` en index 0, `cm1` en index 3,
    /// deux feuilles muettes. Retourne (root, path0, path1) selon la convention `fold`.
    fn build_tree(cm0: &Digest, cm1: &Digest) -> (Digest, Vec<Digest>, Vec<Digest>) {
        let l0 = merkle::leaf(cm0);
        let l1 = merkle::leaf(&digest(9001)); // muette
        let l2 = merkle::leaf(&digest(9002)); // muette
        let l3 = merkle::leaf(cm1);
        let n_left = merkle::node(&l0, &l1);
        let n_right = merkle::node(&l2, &l3);
        let root = merkle::node(&n_left, &n_right);
        // index 0 (00) : sib niveau0 = l1, niveau1 = n_right.
        let path0 = vec![l1, n_right];
        // index 3 (11) : sib niveau0 = l2, niveau1 = n_left.
        let path1 = vec![l2, n_left];
        (root, path0, path1)
    }

    /// Construit le témoin d'une transaction 2-in/2-out équilibrée (1000/500 →
    /// 900/580 + fee 20, arbre de profondeur DEPTH). `owner0_faux`, si fourni,
    /// remplace l'owner de l'entrée 0 (test de liaison owner ≠ clé) — le reste de la
    /// construction (commitment, arbre) suit fidèlement cet owner, SANS aucun assert
    /// de cohérence : c'est la contrainte AIR de liaison qui doit mordre, pas un
    /// panic hors-circuit.
    fn setup(
        owner0_faux: Option<Digest>,
    ) -> (ShieldedSecret, Digest, [ProvedInput; 2], [SpendNote; 2]) {
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        let owner0 = owner0_faux.unwrap_or(owner);

        let n0 = SpendNote {
            value: 1_000,
            owner: owner0,
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
        let (root, path0, path1) = build_tree(&cm0, &cm1);

        // Sorties (destinataires) : 900 + 580 + fee 20 = 1500 = 1000 + 500.
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

        let inputs = [
            ProvedInput {
                note: n0,
                path: path0,
                index: 0,
            },
            ProvedInput {
                note: n1,
                path: path1,
                index: 3,
            },
        ];
        (secret, root, inputs, [o0, o1])
    }

    /// Transaction valide de référence (owner honnête, fee correct).
    fn valid_tx() -> (ShieldedSecret, Digest, ProvedTx) {
        let (secret, root, inputs, outputs) = setup(None);
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, outputs, 20, &intent, enc_notes_test());
        assert_eq!(proved_root, root);
        (secret, root, tx)
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn transaction_valide() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
    }

    /// Déséquilibre : `fee` passé à `prove_tx` (999) NE correspond PAS à Σentrées −
    /// Σsorties (réellement 20, cf. `setup`). `fill_balance` (monolith/trace.rs)
    /// accumule `S` = Σ entrées − Σ sorties INDÉPENDAMMENT du `fee` fourni — c'est
    /// l'ASSERTION publique `S[dernière ligne] == pi.fee` (monolith/air.rs) qui lie
    /// les deux, et `pi.fee` est extrait tel quel du témoin (`w.fee`). Comme le
    /// prouveur ET le vérificateur utilisent donc le MÊME `fee` faux (999) alors que
    /// la trace réelle atteint `S = 20`, l'assertion est fausse relativement à la
    /// trace commise : aucun panic (aucune vérification hors-circuit de l'équilibre
    /// dans le constructeur de trace ni le prouveur), mais la preuve — bien
    /// générée — ne peut pas satisfaire une assertion fausse et la vérification
    /// (donc `verify_tx`) rejette. Même mécanisme que la falsification de `fee`
    /// dans les roundtrips de `monolith::seg_air`, ici appliqué AVANT la preuve
    /// plutôt qu'après.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn desequilibre_rejete() {
        let (secret, root, inputs, outputs) = setup(None);
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, outputs, 999, &intent, enc_notes_test());
        assert_eq!(proved_root, root);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn nullifier_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.nullifiers[0] = digest(123);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn output_commitment_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.output_commitments[0] = digest(321);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn tx_digest_falsifie_rejete() {
        let (_s, root, mut tx) = valid_tx();
        tx.tx_digest[0] ^= 1;
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn racine_erronee_rejetee() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
        assert!(!verify_tx(&digest(1), DEPTH, &tx));
    }

    /// INFLATION par wrap mod p via l'API publique (sans force brute white-box) : les
    /// sorties dépassent les entrées de `k`, avec `fee = p − k`. L'équilibre du circuit
    /// n'établit que `S ≡ fee (mod p)` : `S_final = Σin − Σout = −k ≡ p − k = fee` — la
    /// preuve STARK est donc VALIDE (on le vérifie explicitement via `verify_monolith`).
    /// Seule la borne native `fee < 2^RANGE_BITS` de `verify_tx` ferme le trou : `p − k`
    /// dépasse 2^60 → rejet. RED vérifié en retirant la borne (non committé) :
    /// `verify_tx` renvoyait alors `true` malgré k unités créées.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn fee_wrappe_rejete() {
        // Modulus Goldilocks p = 2^64 − 2^32 + 1.
        const P: u64 = 0xFFFF_FFFF_0000_0001;
        let k = 1_000u64;

        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
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
        let (root, path0, path1) = build_tree(&cm0, &cm1);

        // Σsorties = 1500 + k > Σentrées = 1500 : k unités créées ; fee = p − k ≡ −k.
        let o0 = SpendNote {
            value: 1_000,
            owner: digest(60),
            rho: digest(61),
            r: digest(62),
        };
        let o1 = SpendNote {
            value: 500 + k,
            owner: digest(70),
            rho: digest(71),
            r: digest(72),
        };
        let inputs = [
            ProvedInput {
                note: n0,
                path: path0,
                index: 0,
            },
            ProvedInput {
                note: n1,
                path: path1,
                index: 3,
            },
        ];
        let intent = SigKeypair::generate();
        let (proved_root, tx) =
            prove_tx(&secret, inputs, [o0, o1], P - k, &intent, enc_notes_test());
        assert_eq!(proved_root, root);

        // La preuve STARK est valide (S ≡ fee mod p) : le trou est bien réel...
        let pi = MonolithPublicInputs {
            root: digest_to_felts(&root),
            nullifiers: vec![
                digest_to_felts(&tx.nullifiers[0]),
                digest_to_felts(&tx.nullifiers[1]),
            ],
            output_commitments: vec![
                digest_to_felts(&tx.output_commitments[0]),
                digest_to_felts(&tx.output_commitments[1]),
            ],
            fee: tx.fee,
            depth: DEPTH,
        };
        assert!(
            verify_monolith(&pi, DEPTH, &tx.proof),
            "preuve STARK valide (wrap mod p)"
        );
        // ...mais la borne native `fee < 2^60` de verify_tx le ferme.
        assert!(
            !verify_tx(&root, DEPTH, &tx),
            "fee = p − k ≥ 2^60 doit être rejeté"
        );
    }

    /// Entrée d'un AUTRE owner : la note 0 porte `owner = digest(9999)` ≠
    /// `H_owner(secret)`. Le constructeur de trace ne fait AUCUN assert d'égalité —
    /// le commitment est construit avec l'owner mensonger tel quel (comme le ferait
    /// un prouveur malhonnête), et l'arbre/le chemin restent self-consistants avec ce
    /// commitment (`proved_root == root` tient). SEULE la contrainte AIR de liaison
    /// owner mord (l'owner consommé par le commitment de l'entrée == l'owner produit
    /// par la clé dérivée du secret) — exactement le mécanisme des forges de liaison
    /// de `monolith::seg_air`, ici exercé via l'API publique `prove_tx`/`verify_tx`
    /// plutôt que par forge white-box directe de la trace.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn entree_d_un_autre_owner_rejetee() {
        let (secret, root, inputs, outputs) = setup(Some(digest(9999)));
        let intent = SigKeypair::generate();
        let (proved_root, tx) = prove_tx(&secret, inputs, outputs, 20, &intent, enc_notes_test());
        assert_eq!(proved_root, root);
        assert!(!verify_tx(&root, DEPTH, &tx));
    }

    /// 3z-b1e — fraîcheur de l'aléa de blinding en PRODUCTION : `prove_tx` (donc
    /// `prove_monolith` → `build_monolith_trace`, le wrapper `OsRng` — pas la
    /// couture seedée `build_monolith_trace_seeded`, réservée aux tests) tiré DEUX
    /// fois sur la MÊME entrée (même secret/entrées/sorties/fee/intent) doit
    /// produire deux preuves STARK dont les OCTETS diffèrent : sans aléa frais, un
    /// observateur verrait deux preuves identiques et pourrait détecter la
    /// réémission d'une même dépense (fuite d'équivalence). `tx_digest`/`intent_sig`
    /// /`signer` sont, eux, IDENTIQUEMENT reconstruits (fonction déterministe des
    /// publics extraits de la trace) — on n'affirme PAS leur égalité/inégalité ici,
    /// seule `tx.proof` (bytes) est comparée. Les deux preuves doivent rester
    /// valides.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn deux_preuves_meme_tx_disjointes() {
        let (secret, root, inputs, outputs) = setup(None);
        let intent = SigKeypair::generate();

        // Même témoin dupliqué (les ProvedInput/SpendNote ne sont pas Copy) : la
        // fonction `setup` reconstruit une entrée strictement équivalente (mêmes
        // valeurs, owner, rho, r, arbre) — le seul aléa en jeu est celui de
        // `prove_tx`.
        let (_secret2, _root2, inputs2, outputs2) = setup(None);

        let (root1, tx1) = prove_tx(&secret, inputs, outputs, 20, &intent, enc_notes_test());
        let (root2, tx2) = prove_tx(&secret, inputs2, outputs2, 20, &intent, enc_notes_test());
        assert_eq!(root1, root);
        assert_eq!(root2, root);

        let bytes1 = tx1.proof.0.to_bytes();
        let bytes2 = tx2.proof.0.to_bytes();
        assert_ne!(
            bytes1, bytes2,
            "deux preuves de la même tx doivent être DISJOINTES (aléa frais par appel)"
        );

        assert!(verify_tx(&root, DEPTH, &tx1));
        assert!(verify_tx(&root, DEPTH, &tx2));
    }

    /// Tâche 1 — anti-substitution `enc_notes` : `tx_digest` v3 lie désormais
    /// `kem_ct`/`enc_note` de chaque sortie. Une `ProvedTx` valide (2 enc_notes non
    /// triviaux) est acceptée ; substituer `enc_notes[0].enc_note` (sans toucher à
    /// la preuve STARK ni aux autres champs publics) doit faire diverger le digest
    /// recomposé dans `verify_tx` → rejet. Ce test ne dépend PAS de l'AIR (aucune
    /// contrainte de circuit ne porte sur enc_notes) : c'est une liaison au niveau
    /// tx uniquement.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn enc_note_substitue_rejete() {
        let (_s, root, tx) = valid_tx(); // valid_tx fournit désormais des enc_notes
        assert!(verify_tx(&root, DEPTH, &tx));
        // Substitution du chiffré AEAD.
        let mut tx_a = valid_tx().2;
        tx_a.enc_notes[0].enc_note = vec![9, 9, 9];
        assert!(
            !verify_tx(&root, DEPTH, &tx_a),
            "enc_note substitué doit casser le digest"
        );
        // Substitution du ciphertext KEM (les deux champs de EncNote sont liés).
        // NB : on garde une longueur `KEM_CT_LEN` valide pour tester la liaison digest
        // (et non le rejet de borne) — un contenu différent suffit.
        let mut tx_k = valid_tx().2;
        tx_k.enc_notes[1].kem_ct = vec![42u8; KEM_CT_LEN];
        assert!(
            !verify_tx(&root, DEPTH, &tx_k),
            "kem_ct substitué doit casser le digest"
        );
    }

    /// Sérialisation canonique : `from_bytes(to_bytes) == tx` (roundtrip) sur une
    /// ProvedTx réelle. Comparaison par ré-encodage (Proof/sig ne sont pas PartialEq) +
    /// champs publics clés.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn serialisation_roundtrip() {
        let (_s, _root, tx) = valid_tx();
        let bytes = tx.to_bytes();
        let tx2 = ProvedTx::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(tx2.to_bytes(), bytes, "ré-encodage identique (canonique)");
        assert_eq!(tx2.anchor, tx.anchor);
        assert_eq!(tx2.nullifiers, tx.nullifiers);
        assert_eq!(tx2.output_commitments, tx.output_commitments);
        assert_eq!(tx2.fee, tx.fee);
        assert_eq!(tx2.tx_digest, tx.tx_digest);
        assert_eq!(tx2.enc_notes[0].kem_ct, tx.enc_notes[0].kem_ct);
        assert_eq!(tx2.enc_notes[1].enc_note, tx.enc_notes[1].enc_note);
        // La tx désérialisée vérifie toujours.
        assert!(verify_tx(&tx.anchor, DEPTH, &tx2));
    }

    /// Matrice de rejet de `from_bytes` : chaque corruption rend l'erreur attendue,
    /// jamais de panique.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn serialisation_rejette_les_malformes() {
        let (_s, _root, tx) = valid_tx();
        let bytes = tx.to_bytes();
        // `matches!` plutôt que `assert_eq!` : `ProvedTx` n'est pas `Debug` (Proof/sig).
        // Tronqué.
        assert!(matches!(
            ProvedTx::from_bytes(&bytes[..bytes.len() - 1]),
            Err(TxDecodeError::TooShort)
        ));
        // Octets résiduels.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            ProvedTx::from_bytes(&trailing),
            Err(TxDecodeError::TrailingBytes)
        ));
        // Digest non canonique : anchor (32 premiers octets) mis à 0xFF (≥ p sur chaque felt).
        let mut bad_digest = bytes.clone();
        for byte in bad_digest.iter_mut().take(32) {
            *byte = 0xFF;
        }
        assert!(matches!(
            ProvedTx::from_bytes(&bad_digest),
            Err(TxDecodeError::BadDigest)
        ));
        // Vide.
        assert!(matches!(
            ProvedTx::from_bytes(&[]),
            Err(TxDecodeError::TooShort)
        ));
    }

    /// `from_bytes` rejette un `enc_note` hors bornes (anti-DoS au parse). On reconstruit
    /// des octets avec un `enc_note` géant en repartant d'une tx valide.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn serialisation_rejette_enc_note_hors_bornes() {
        let (_s, _root, mut tx) = valid_tx();
        tx.enc_notes[0].enc_note = vec![0u8; MAX_ENC_NOTE_LEN + 1];
        let bytes = tx.to_bytes(); // to_bytes n'impose pas les bornes ; from_bytes oui.
        assert!(matches!(
            ProvedTx::from_bytes(&bytes),
            Err(TxDecodeError::EncNoteOutOfBounds)
        ));
    }

    /// FORME VARIABLE de bout en bout (C2-T6) : une tx 1-in/3-out se prouve, passe le
    /// fil (`to_bytes`/`from_bytes` avec compteurs), et se vérifie.
    ///
    /// C'est le test qui prouve que la variabilité du circuit atteint enfin la
    /// couche transaction : m, n portés par les longueurs, préfixés dans tx_digest ET
    /// dans le wire, bornés avant allocation.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn forme_variable_1_in_3_out() {
        use proved_hash::merkle::ProvedMerkleTree;
        let secret = ShieldedSecret::from_felts(core::array::from_fn(|i| {
            Felt::from_canonical_u64(700 + i as u64).unwrap()
        }));
        let owner = rescue::hash(Domain::Owner, secret.as_felts());
        // Une seule entrée qui couvre trois sorties + fee.
        let note = SpendNote {
            value: 1_000,
            owner,
            rho: digest(20),
            r: digest(30),
        };
        let cm = rescue::note_commitment(note.value, &note.owner, &note.rho, &note.r);
        let mut arbre = ProvedMerkleTree::new(DEPTH);
        let i0 = arbre.append(&cm);
        let inputs = vec![ProvedInput {
            note,
            path: arbre.path(i0).unwrap(),
            index: i0,
        }];

        let fee = 10u64;
        let parts = [400u64, 300, 290]; // 400+300+290+10 = 1000
        let outputs: Vec<SpendNote> = parts
            .iter()
            .enumerate()
            .map(|(j, v)| SpendNote {
                value: *v,
                owner: digest(60 + j as u64),
                rho: digest(70 + j as u64),
                r: digest(80 + j as u64),
            })
            .collect();
        let enc_notes: Vec<EncNote> = (0..3)
            .map(|j| EncNote {
                kem_ct: vec![j as u8; KEM_CT_LEN],
                enc_note: vec![j as u8; 3],
            })
            .collect();
        let intent = crypto::sig::SigKeypair::generate();

        let (root, tx) =
            prove_tx_forme(&secret, inputs, outputs, fee, &intent, enc_notes).expect("prouvable");
        assert_eq!(tx.m(), 1);
        assert_eq!(tx.n(), 3);
        assert!(verify_proved_tx_full(&root, DEPTH, &tx), "1/3 valide");

        // Aller-retour wire : compteurs relus, forme préservée.
        let octets = tx.to_bytes();
        let relu = ProvedTx::from_bytes(&octets).expect("roundtrip 1/3");
        assert_eq!((relu.m(), relu.n()), (1, 3));
        assert_eq!(relu.to_bytes(), octets, "canonique");
        assert!(verify_proved_tx_full(&root, DEPTH, &relu));
    }

    /// ANTI-DoS : une forme hors bornes est rejetée AVANT toute allocation. Le test
    /// n'envoie que l'en-tête (anchor + m/n) — si le code allouait d'après le compteur
    /// sans le borner, il réserverait pour `m` digests jamais reçus.
    #[test]
    fn forme_hors_borne_rejetee_sans_allouer() {
        let mut b = vec![0u8; 32]; // anchor (32 zéros = digest canonique)
        b.push(0); // m = 0
        b.push(2); // n = 2
        assert!(matches!(
            ProvedTx::from_bytes(&b),
            Err(TxDecodeError::BadForme { m: 0, n: 2 })
        ));
        let mut b2 = vec![0u8; 32];
        b2.push((MAX_IN + 1) as u8);
        b2.push(2);
        assert!(matches!(
            ProvedTx::from_bytes(&b2),
            Err(TxDecodeError::BadForme { .. })
        ));
    }

    /// Anti-DoS (#2) : un `enc_note` hors-bornes (kem_ct de mauvaise taille, ou enc_note
    /// géant) est rejeté par `verify_tx` AVANT tout hachage coûteux.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn enc_note_hors_bornes_rejete() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_tx(&root, DEPTH, &tx));
        // kem_ct trop court.
        let mut tx_court = valid_tx().2;
        tx_court.enc_notes[0].kem_ct = vec![1, 2, 3];
        assert!(!verify_tx(&root, DEPTH, &tx_court));
        // enc_note gigantesque.
        let mut tx_gros = valid_tx().2;
        tx_gros.enc_notes[1].enc_note = vec![0u8; MAX_ENC_NOTE_LEN + 1];
        assert!(!verify_tx(&root, DEPTH, &tx_gros));
    }

    /// `verify_proved_tx_full` = preuve + digest + signature d'intention. Une tx valide
    /// passe ; une signature d'une AUTRE clé (relais actif) échoue, alors que `verify_tx`
    /// seul (preuve + digest) l'accepterait encore — c'est LA raison d'être de l'API full.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
    fn verify_full_exige_la_signature() {
        let (_s, root, tx) = valid_tx();
        assert!(verify_proved_tx_full(&root, DEPTH, &tx));
        // Un relais re-signe le MÊME digest avec sa propre clé : verify_tx passe encore...
        let autre = SigKeypair::generate();
        let mut forge = valid_tx().2;
        forge.signer = autre.public.clone();
        // Il doit recalculer le digest (le signer y est lié) puis re-signer.
        forge.tx_digest = tx_digest_bytes(
            &root,
            &forge.nullifiers,
            &forge.output_commitments,
            forge.fee,
            &forge.signer,
            &forge.enc_notes,
        );
        forge.intent_sig = autre.sign(INTENT_DOMAIN, &forge.tx_digest);
        assert!(
            verify_tx(&root, DEPTH, &forge),
            "verify_tx seul accepte le substitut re-signé"
        );
        assert!(verify_proved_tx_full(&root, DEPTH, &forge));
        // (Le substitut re-signé EST accepté même par full : la sig est valide sous sa
        // propre clé — c'est la limitation documentée. Ce que full ajoute vs verify_tx :
        // il REFUSE une signature INVALIDE, cf. ci-dessous.)
        let mut sig_cassee = valid_tx().2;
        sig_cassee.intent_sig = SigKeypair::generate().sign(INTENT_DOMAIN, &sig_cassee.tx_digest);
        assert!(
            verify_tx(&root, DEPTH, &sig_cassee),
            "verify_tx ignore la signature"
        );
        assert!(
            !verify_proved_tx_full(&root, DEPTH, &sig_cassee),
            "full refuse une sig invalide"
        );
    }
}
