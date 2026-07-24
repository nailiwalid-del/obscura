# Liaison de l'intention dans les publics du monolithe — design

> Statut : design validé (brainstorming), prêt pour plan d'implémentation.
> Axe de revue concerné : « Fermer la malléabilité active des `enc_notes` »
> (P8/`tx_digest`, axe 2). Ce document est la spec ; l'autorité reste le code +
> `docs/PROTOCOL.md` / `docs/STARK_STATEMENT.md`, que ce changement met à jour.

## Problème

La preuve STARK du monolithe ne lie ni `signer` ni `enc_notes` : ce ne sont pas
des publics (`MonolithPublicInputs`, `crates/circuit/src/monolith/socle.rs`). Ils
ne sont attachés à la transaction que par `tx_digest` (domaine
`obscura/proved-tx/v4`) et la **signature d'intention** (`crates/circuit/src/tx.rs`).

Conséquence — malléabilité active du relais, documentée et testée
(`verify_full_exige_la_signature`, `tx.rs`) : un relais garde la preuve intacte,
substitue les `enc_notes` (garbage), remplace `signer` par sa propre clé,
recalcule `tx_digest`, re-signe. `verify_tx` **accepte** ce substitut (il ne
vérifie pas la signature ; la preuve est agnostique au `signer`). Impact borné :
**déni de scan** du destinataire — PAS de vol ni d'inflation (P5/P7 tiennent).

`STARK_STATEMENT.md` (section « Malléabilité hors intention ») désigne déjà la
correction : « lier le signataire (ou le digest) dans les publics du monolithe ».
On ne peut pas lier `tx_digest` directement — il est calculé **après** la preuve,
à partir de publics extraits de la trace (circularité). On lie donc les deux
entrées libres et indépendantes de la trace : `signer` **et** `enc_notes`.

## Idée directrice

Ajouter un **binding Fiat-Shamir** de `(signer, enc_notes)` aux publics du
monolithe. Ce n'est **pas** une contrainte AIR : on ajoute des éléments de corps
à `MonolithPublicInputs::to_elements()`, qui ensemence le public coin (le code
s'appuie déjà sur ce mécanisme pour lier `m`/`n`, cf. commentaire `socle.rs`
lignes ~133–137 : « c'est CE QUI EST HACHÉ par Fiat-Shamir »).

Une preuve devient alors invalide pour tout autre `(signer, enc_notes)` que ceux
fixés à la génération : un relais qui les modifie change la graine du coin, donc
tous les défis, donc la vérification échoue — et il ne peut pas **re-prouver**
sans le témoin (secret, notes, chemins).

**Chaîne de liaison après correction :**

```
proof  ── lie ──▶  (signer ‖ enc_notes)          (nouveau : binding Fiat-Shamir)
signer ── via signature d'intention ──▶  tx_digest
tx_digest ── lie ──▶  root ‖ nf ‖ oc ‖ fee ‖ signer ‖ enc_notes
```

Les deux maillons auparavant libres (`signer`, `enc_notes`) sont fermés **au
niveau preuve**.

## Ce que ça N'est PAS

Ce n'est **pas** P8 (prouver en circuit que `enc_note` déchiffre vers la note
engagée). Un **expéditeur malhonnête** peut toujours chiffrer du garbage vers son
propre destinataire : auto-préjudice, aucune création de monnaie. P8 reste
**différé** (`STARK_STATEMENT.md`, « Cohérence commitment ↔ note chiffrée »). On
ferme la malléabilité **du relais** (tiers actif), pas l'honnêteté de
l'expéditeur. La doc doit distinguer les deux nettement.

## Gain concret du périmètre choisi (signer + enc_notes, pas signer seul)

Comme `enc_notes` est **aussi** lié dans les publics, `verify_tx` seul (preuve +
digest, sans la signature) devient **non-malléable** : un `signer`/`enc_notes`
modifié fait diverger la graine du coin → `winterfell::verify` échoue → rejet.
Le footgun « appeler `verify_tx` sans `verify_proved_tx_full` » disparaît. C'est
le bénéfice propre au choix de lier les deux plutôt que `signer` seul.

La signature d'intention et le binding `enc_notes` de `tx_digest` sont
**conservés** (défense en profondeur ; la signature prouve aussi la possession /
l'intention). Leur éventuelle simplification est **hors périmètre**.

## Architecture

### Composant 1 — `MonolithPublicInputs` (socle.rs) : champ opaque

Ajouter un champ **opaque** :

```rust
pub(crate) struct MonolithPublicInputs {
    pub root: [BaseElement; DIGEST_FELTS],
    pub nullifiers: Vec<[BaseElement; DIGEST_FELTS]>,
    pub output_commitments: Vec<[BaseElement; DIGEST_FELTS]>,
    pub fee: u64,
    pub depth: usize,
    /// Binding Fiat-Shamir de l'enveloppe d'intention `(signer, enc_notes)`.
    /// OPAQUE ici (le socle ne connaît aucun témoin) : sa sémantique et son
    /// calcul vivent dans `tx.rs`. `ABSENT` (zéros) au niveau AIR, où l'enveloppe
    /// n'existe pas.
    pub liaison_intention: LiaisonIntention,
}
```

Le socle ne sait **pas** ce que ces felts signifient — fidèle à « aucun témoin
ici ». `to_elements()` les ajoute **en queue** (après `fee`/`depth`) :

```rust
fn to_elements(&self) -> Vec<BaseElement> {
    // ... m, n, root, nullifiers, output_commitments, fee, depth (inchangé) ...
    v.extend_from_slice(&self.liaison_intention.0);
    v
}
```

`LiaisonIntention([BaseElement; K])` est un newtype avec une constante
`ABSENT = [ZERO; K]`. `K = 10` (justifié plus bas). L'ajout en queue préserve
l'ordre existant (non-régression des preuves de même `liaison`).

### Composant 2 — `tx.rs` : sémantique du binding

`tx.rs` possède la connaissance de `signer` et `enc_notes`. Il expose :

```rust
/// Binding Fiat-Shamir de l'enveloppe d'intention. Injectif, jamais tronqué.
/// Préimage canonique (hash consensus, `dual_hash`) :
///   len(signer) LE(u32) ‖ signer.to_bytes()
///   ‖ [ len(kem_ctⱼ) LE(u64) ‖ kem_ctⱼ ‖ len(enc_noteⱼ) LE(u64) ‖ enc_noteⱼ ]ⱼ
/// (même encodage des enc_notes que `tx_digest_bytes`, injectif par préfixage).
fn liaison_intention(signer: &SigPublicKey, enc_notes: &[EncNote]) -> LiaisonIntention
```

- Domaine : `obscura/monolith-liaison-intention/v1` (domaine **hash consensus** —
  ce binding est calculé hors-circuit par prouveur ET vérifieur, jamais dans
  l'AIR ; il relève donc de `dual_hash` BLAKE3‖SHA3, comme `tx_digest`).
- Empaquetage des 64 octets du digest en `K = 10` felts, par **limbes de 7
  octets** little-endian (9 limbes de 7 o + 1 limbe de 1 o = 64 o). Chaque limbe
  `< 2^56 < p` : canonique, **sans réduction**, injectif sur les 64 octets → la
  résistance aux collisions de `dual_hash` est intégralement reportée dans la
  graine. (La réduction mod p d'un empaquetage 8×u64 aurait suffi en pratique —
  aucun avantage pour un attaquant qui n'a de toute façon pas le témoin — mais
  l'empaquetage injectif est plus simple à argumenter et respecte « jamais
  tronqué ».)

Note : on ne rejoue PAS `root/nf/oc/fee/m/n` dans cette préimage — ils sont déjà
liés comme publics. La `liaison` n'ajoute que `signer` + `enc_notes`.

### Composant 3 — chemin PREUVE

`prove_seg_forme(w)` (seg_air.rs) reste le point d'entrée **AIR** : il construit
`pi` avec `liaison_intention: LiaisonIntention::ABSENT`. Les ~12 appelants de
tests AIR restent **inchangés** (ils n'ont ni `signer` ni `enc_notes` — l'enveloppe
n'existe pas à ce niveau).

Une variante liée porte le binding réel :

```rust
pub(crate) fn prove_seg_forme_lie(
    w: &SegWitness,
    liaison: LiaisonIntention,
) -> (MonolithPublicInputs, ValidityProof)
```

`prove_seg_forme(w)` devient un mince wrapper : `prove_seg_forme_lie(w, ABSENT)`.
Le prouveur `SegMonolithProver` porte déjà `pi` (donc la `liaison`) et
`get_pub_inputs` renvoie `self.pi.clone()` → l'ensemencement prouveur est correct
sans autre changement.

`tx::prove_tx_forme` calcule `liaison_intention(&signer, &enc_notes)` **avant** de
prouver (les deux sont connus dès l'entrée), puis appelle `prove_seg_forme_lie`.
Ordre : `signer`/`enc_notes` étant indépendants de la trace, il n'y a pas de
circularité (contrairement à `tx_digest`).

### Composant 4 — chemin VÉRIFICATION

`verify_seg_monolith` **inchangé** : il vérifie le `pi` qu'on lui donne
(`winterfell::verify` reséme le coin depuis `pi.to_elements()`).

`tx::verify_tx` reconstruit le binding depuis les champs de la tx et le place dans
le `pi` :

```rust
let pi = MonolithPublicInputs {
    root: ..., nullifiers: ..., output_commitments: ..., fee: ..., depth: ...,
    liaison_intention: liaison_intention(&tx.signer, &tx.enc_notes),
};
if !verify_monolith(&pi, depth, &tx.proof) { return false; }
```

Si un relais a modifié `signer` ou `enc_notes`, la `liaison` reconstruite diffère
de celle de la génération → coin divergent → `verify_monolith` **rejette**. Les
contrôles existants (bornes `fee`, forme, `within_bounds`, recompute `tx_digest`)
restent, dans le même ordre : la `liaison` se reconstruit après les gardes
anti-DoS (`within_bounds`), puisqu'elle hache les octets des `enc_notes`.

## Versioning (changement cassant le consensus)

Lier `(signer, enc_notes)` change ce que la preuve engage : **les preuves
antérieures ne vérifient plus**, et le nouveau vérifieur rejette les anciennes.
C'est un **bump de version de statement**. Actions :

- Domaine proved-tx : `obscura/proved-tx/v4` → `v5` (et `INTENT_DOMAIN` en
  cohérence si la convention l'exige — à trancher au plan, en une seule bascule).
- `STARK_STATEMENT.md` : la section « Malléabilité hors intention » passe de
  « trou résiduel » à « fermé pour le relais par binding des publics » ; « P8
  différé » **reste** (distinguer relais vs expéditeur).
- `PROTOCOL.md` : acter le nouveau public `liaison_intention` dans la description
  du statement/format.
- Testnet non ouvert → aucune migration de preuves en vol ; le bump est sans
  coût opérationnel.

## Points de contact (touch-list vérifiée)

Ajouter un champ au struct force la mise à jour de tous ses constructeurs — filet
de compilation, pas risque. Construits à 8 endroits :

- `tx.rs:305` (`verify_tx`) — binding réel depuis `tx.signer`/`tx.enc_notes`.
- `tx.rs:730` (test `fee_wrappe_rejete`) — placeholder `ABSENT`.
- `seg_air.rs:1089` (`prove_seg_forme_lie`) — reçoit la `liaison`.
- `seg_air.rs:1256` (`publics_de_forme`, helper de test) — `ABSENT`.
- `seg_air.rs:1606, 1711, 1847, 2105` (tests forgeant un `pi`) — `ABSENT`.

`to_elements` (socle.rs:159) : ajout en queue. `get_pub_inputs` (seg_air.rs:1007) :
inchangé (renvoie `self.pi.clone()`). ~12 appelants de `prove_seg_forme(w)` :
inchangés (wrapper `ABSENT`).

## Tests (TDD)

RED d'abord, chaque test échoue sans le binding et passe avec.

1. **Phare — bascule du trou** : le substitut re-signé de
   `verify_full_exige_la_signature` est désormais **rejeté par `verify_tx`**
   (aujourd'hui accepté, `tx.rs:1037`). On réécrit ce test : `verify_tx` du
   substitut (`signer` = autre clé, `enc_notes` = garbage) doit renvoyer `false`.
   C'est le signal direct de fermeture.
2. **`enc_notes` sans signature** : substituer `enc_notes[j]` sur une tx valide,
   sans re-signer, est rejeté par `verify_tx` (binding preuve, pas seulement
   digest).
3. **Spike de mécanisme** : prouver avec `liaison = X`, vérifier avec `Y ≠ X`
   (à `prove_seg_forme_lie`/`verify_seg_monolith` niveau) → rejet. Confirme
   empiriquement l'hypothèse porteuse (Fiat-Shamir lie un public non contraint
   par l'AIR).
4. **Injectivité de `liaison_intention`** : `(signer, enc_notes)` distincts →
   `liaison` distincte (test unitaire pur, hors preuve).
5. **Non-régression** :
   - `decompte_des_contraintes` inchangé (aucune contrainte AIR ajoutée).
   - `securite_par_forme` / seuil 78 bits inchangé (trace inchangée).
   - Round-trips valides (`transaction_valide`, `forme_variable_1_in_3_out`,
     `serialisation_roundtrip`) verts.
   - Tests AIR (`prove_seg_forme(w)` → `verify_seg_monolith`) verts (binding
     `ABSENT` cohérent des deux côtés).

## Hypothèse porteuse (unique)

Winterfell ensemence le public coin depuis `pub_inputs.to_elements()`, **y
compris** pour des éléments non référencés par une contrainte/assertion AIR. Le
code s'y fie déjà pour `m`/`n`. Le test 3 (spike) la confirme avant de bâtir le
reste — à écrire et faire passer en premier.

## Hors périmètre (YAGNI)

- P8 en circuit (enc_note ↔ note engagée).
- Suppression/allègement de la signature d'intention ou du binding `enc_notes`
  dans `tx_digest` (défense en profondeur conservée).
- Toute liaison de `root/nf/oc/fee` (déjà publics).
