# Transport chiffré post-quantique — design

**Date :** 2026-07-21
**Contexte :** phase 4, brique 1/4 (voir décomposition en fin de document).
**Statut :** design approuvé (utilisateur, 2026-07-21).

## Objectif

Un canal authentifié et chiffré entre deux nœuds, avec **forward secrecy** et
**masquage d'identité**, réutilisant les primitives hybrides existantes. Exigence
du modèle de menace : « chiffrement hybride PQ de **tous** les liens ».

Nouveau crate `crates/net`. **Aucune primitive cryptographique nouvelle** :
`crypto::{kem, sig, aead, hash}` sont réutilisés tels quels, donc la défense en
profondeur (2 familles mathématiques par fonction) est héritée sans arbitrage.

## Non-objectifs (briques suivantes)

Sockets, découverte de pairs, mempool, Dandelion++. Ce design couvre la **machine
à états** du handshake et le **canal** ; il se teste intégralement en mémoire.

## Handshake — 3 passes

```
1.  I → R :  eph_pk_I
2.  R → I :  eph_pk_R ‖ ct_R ‖ AEAD_k1{ id_pk_R ‖ sig_R(T2) }
3.  I → R :  ct_I ‖ AEAD_k2{ id_pk_I ‖ sig_I(T3) }
```

- `eph_pk_*` : `KemPublicKey` ÉPHÉMÈRE (X25519 + Kyber768), fraîche par session,
  jetée après le handshake → **forward secrecy**.
- `ct_R` = `kem::encapsulate(eph_pk_I)` → `ss₁` ; `ct_I` = `kem::encapsulate(eph_pk_R)`
  → `ss₂`. **Contribution mutuelle** : aucun des deux ne choisit seul le secret de
  session, donc un pair biaisé ne peut pas l'imposer.
- `id_pk_*` : `SigPublicKey` d'identité (long terme), transmise **chiffrée**.

### Transcript

Haché de façon incrémentale sur TOUS les octets échangés, dans l'ordre :

```
T₀ = dual_hash("obscura/net/transcript/v1", [])
Tᵢ₊₁ = dual_hash("obscura/net/transcript/v1", Tᵢ ‖ messageᵢ)
```

`dual_hash` (BLAKE3‖SHA3-256, jamais tronqué) — même discipline que le consensus.
Les signatures portent sur le transcript **courant**, donc sur tout ce qui précède :
tout champ modifié en vol invalide la signature.

### Dérivation de clés

```
k₁       = derive_key("obscura/net/hs1/v1",     T₂ ‖ ss₁)
k₂       = derive_key("obscura/net/hs2/v1",     T₃ ‖ ss₁ ‖ ss₂)
k_I→R    = derive_key("obscura/net/sess-i2r/v1", T₄ ‖ ss₁ ‖ ss₂)
k_R→I    = derive_key("obscura/net/sess-r2i/v1", T₄ ‖ ss₁ ‖ ss₂)
```

Clés **directionnelles distinctes** : un message ne peut pas être réfléchi vers son
émetteur (attaque par réflexion).

## Propriétés — et leurs limites, explicitement

| propriété | tenue par |
|---|---|
| Confidentialité | AEAD cascade sous clés issues de `ss₁ ‖ ss₂` |
| Authentification mutuelle | signatures hybrides sur le transcript |
| **Forward secrecy** | éphémères jetés ; une clé d'identité compromise ne déchiffre aucune session passée |
| Anti-MitM | signatures couvrant le transcript complet |
| Anti-rejeu (handshake) | éphémères frais ⇒ transcript unique par session |
| Anti-rejeu (canal) | compteur de séquence par direction, dans l'AAD |

**Masquage d'identité — portée exacte :**

| adversaire | identité de I | identité de R |
|---|---|---|
| observateur PASSIF | masquée | masquée |
| MitM ACTIF | masquée (I parle après avoir vérifié R) | **RÉVÉLÉE** |

Un nœud en écoute révèle son identité à quiconque se connecte : c'est inhérent au
rôle de répondeur, pas un défaut d'implémentation. Le fermer exigerait que
l'initiateur connaisse la clé du répondeur à l'avance (motif type Noise-IK),
envisageable plus tard pour les connexions SORTANTES vers des pairs connus. À ne
pas laisser implicite.

**Hors périmètre assumé** : analyse de trafic (tailles, horaires, volumes). Le
padding et le cover traffic relèvent de Dandelion++/mixnet (briques 3-4).

## Canal établi

```rust
pub struct Session { k_envoi: [u8; 32], k_reception: [u8; 32], seq_envoi: u64, seq_reception: u64 }
pub fn chiffrer(&mut self, message: &[u8]) -> Vec<u8>;
pub fn dechiffrer(&mut self, cadre: &[u8]) -> Result<Vec<u8>, NetError>;
```

Le numéro de séquence sert d'**AAD** (il n'est donc pas transmis : il est déduit du
compteur local, ce qui rend un message hors-ordre ou rejoué indéchiffrable). Le
compteur n'avance qu'en cas de succès.

`seq` saturant : à `u64::MAX` la session est close plutôt que de réutiliser un
compteur (`NetError::SessionEpuisee`).

## Surface réseau : aucune panique

Comme `ProvedTx::from_bytes`, tout décodage est un **point d'entrée hostile** :
curseur borné, longueurs vérifiées avant allocation, aucun `unwrap` sur l'entrée,
`Result` partout. Bornes explicites sur chaque champ de taille variable
(anti-DoS mémoire).

```rust
pub enum NetError {
    Tronque, OctetsResiduels, MauvaisEtat, TailleInvalide,
    DechiffrementEchoue, SignatureInvalide, EncodageInvalide, SessionEpuisee,
}
```

## Machine à états

`Initiateur` et `Repondeur` comme types distincts, transitions consommant `self`
(`typestate`) : un handshake ne peut pas être utilisé hors séquence, et une session
ne peut pas être obtenue avant la fin — garanti à la COMPILATION plutôt que par
des vérifications à l'exécution.

## Tests

**Nominal** : handshake complet en duplex mémoire → les deux dérivent les MÊMES
clés de session ; aller-retour de messages dans les deux sens.

**Négatifs (chacun doit ÉCHOUER)** :
- altération d'un octet de n'importe quel message → signature ou AEAD rejette ;
- MitM substituant son identité → signature invalide (transcript divergent) ;
- rejeu d'un message de canal → déchiffrement échoue (seq consommé) ;
- message hors-ordre → échec ;
- réflexion d'un message vers son émetteur → échec (clés directionnelles) ;
- messages tronqués / octets résiduels / longueurs aberrantes → `Result`, pas de panique.

**Propriétés** :
- deux handshakes entre les MÊMES pairs → clés de session DIFFÉRENTES (PFS) ;
- **masquage d'identité** : aucune clé publique d'identité n'apparaît en clair
  dans les octets du handshake — test de non-fuite structurelle, même discipline
  que les tests key-privacy de `proved_wallet` (fenêtres de 8 octets).

## Décomposition de la phase 4

| | brique | statut |
|---|---|---|
| 0 | test distingueur key-privacy | ✅ fait |
| **1** | **transport chiffré PQ** | **ce design** |
| 2 | découverte et gestion de pairs | à faire |
| 3 | relais de transactions (mempool) | à faire |
| 4 | Dandelion++ (stem/fluff) | à faire |
