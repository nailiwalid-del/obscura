# 3z-a — Monolithe privé : une trace, une preuve

> Première tranche de la **Phase 3z**. Fusionne les 15 preuves de l'assemblage 3b5d
> en UNE SEULE trace STARK. Prérequis de l'unlinkability (3z-b) et levier de
> compression identifié par le bench 3d (~219 Kio dominés par la non-agrégation).
>
> ⚠️ **Toujours validity-only** : sans masquage de trace (3z-b), les requêtes FRI
> ouvrent des cellules de trace qui peuvent fuiter des témoins. Ce que 3z-a change,
> c'est le *statement* : plus AUCUNE donnée de liaison n'est publiée. Ne jamais
> présenter cette preuve comme `zk`/`private`/`shielded`.

## 1. Pourquoi une trace unique est forcée (pas un choix)

Le statement final (STARK_STATEMENT.md) ne publie que `root`, `nullifiers[]`,
`output_commitments[]`, `fee`, `tx_digest`. Conséquences mécaniques :

- `owner`/`nk` deviennent témoins → la liaison clé↔dépenses ne peut plus passer par
  des valeurs publiques partagées (leçon 3b5a : deux preuves séparées ne forcent PAS
  l'égalité de leurs témoins). Clé + dépenses doivent partager une trace.
- Les montants deviennent témoins → P5 (équilibre) doit être prouvé en circuit en
  reliant les montants des dépenses ET des sorties → les sorties rejoignent la même
  trace.

Donc : **tout P1–P7 pour la tx 2-in/2-out entière dans un seul AIR**.

## 2. Statement v2

```
Entrées PUBLIQUES : root, nullifiers[2], output_commitments[2], fee
Témoins           : shielded_secret, owner, nk, pour chaque entrée
                    (note, cm_in, rho, chemin de Merkle, index), pour chaque
                    sortie (note, rho, r), tous les montants
La preuve établit : P1–P7 (identiques au statement v0.2)
```

`tx_digest` v2 = `dual_hash("obscura/proved-tx/v2", root(32) ‖ nf₁(32) ‖ nf₂(32) ‖
oc₁(32) ‖ oc₂(32) ‖ fee(8 LE) ‖ signer)` — publics seuls, calculé nativement
(hash consensus, hors circuit), injectif (tailles fixes). La signature d'intention
hybride sur `tx_digest` est inchangée (`signer` lié dans le digest).

## 3. Layout : large, côte à côte, 512 lignes

Un seul AIR juxtapose les gadgets 3b existants en **groupes de colonnes** ; la
longueur de trace est alignée sur le plus long (chemin de Merkle profondeur 32
= 512 lignes) ; les éponges plus courtes sont idle-padded (transition désactivée
par flag périodique au-delà de leur segment utile).

Budget mesuré sur les briques actuelles (limite winterfell : 255 colonnes) :

| Groupe | Colonnes | Lignes utiles |
|---|---|---|
| Clé (P2∧P4, 3b5a) | 24 | 8 |
| Dépense ×2 : commitment (20) + feuille (20) + chemin (29) + nullifier (20) | 2×89 | 32 / 8 / 512 / 16 |
| Sortie ×2 : commitment (20) | 2×20 | 32 |
| Équilibre P5 + range P6 embarqué (3b3b) | 4 | 64×blocs |
| **Base** | **≈246** | |

**Liaisons inter-gadgets** : technique éprouvée 3b2/3b5a — colonnes porteuses
CONSTANTES + contraintes d'égalité gatées à des lignes précises. Porteuses :
`owner` (4), `nk` (4), `rho`ᵢ (2×4), `cm_in`ᵢ (2×4), montants (liés au gadget
équilibre). Chaque porteuse est égalée (1) là où la valeur est PRODUITE (ex.
sortie du sponge clé, ligne finale gatée) et (2) là où elle est CONSOMMÉE (ex.
cellules d'injection du commitment, ligne 0). Aucune porteuse n'est assertée à
une valeur publique.

**Fallback décidé d'avance** : base + porteuses ≈ 266-274 > 255 probable. Si
dépassement : empiler séquentiellement les 3 éponges internes d'une dépense
(commitment 32 lignes → feuille 8 → nullifier 16) dans UN groupe de 20 colonnes
avec sélecteurs périodiques de segment — les 512 lignes offrent la place ; gain
~40 colonnes/dépense, sémantique inchangée. Le plan mesure d'abord le
côte-à-côte pur, bascule sur le fallback si le budget déborde.

**Contrainte héritée** : colonnes constantes → degrés input-dépendants → le
`debug_assert` winterfell peut mordre en debug → **preuves à générer en
`--release`** (bornes déclarées ≥ mesurées, soundness préservée), tests gatés
`#[ignore]` en debug, comme 3b2b.

## 4. API et intégration

```rust
// crates/circuit/src/tx.rs — mêmes signatures qu'en v1, UNE preuve
pub struct ProvedTx {
    pub proof: ValidityProof,          // LA preuve monolithique
    pub anchor: Digest,
    pub nullifiers: [Digest; 2],
    pub output_commitments: [Digest; 2],
    pub fee: u64,
    pub signer: SigPublicKey,
    pub intent_sig: HybridSignature,
    pub tx_digest: [u8; 64],
}
pub fn prove_tx(secret, inputs: [ProvedInput; 2], outputs: [SpendNote; 2],
                fee: u64, intent: &SigKeypair) -> (Digest, ProvedTx);
pub fn verify_tx(root: &Digest, depth: usize, tx: &ProvedTx) -> bool;
```

- L'assemblage composition 15-preuves (v1) est **supprimé** — un seul validateur,
  pas d'ambiguïté de consensus. Les gadgets 3b restent : briques du monolithe +
  tests différentiels individuels.
- `apply_proved_tx` : logique inchangée (anchor récent → `verify_tx` → nullifiers
  non dépensés → application atomique) ; seule la vérification interne change.
- Bench 3d mis à jour (`tx_bench.rs`) : mesure du gain attendu ~219 Kio → une
  preuve (ordre de grandeur visé : 15-30 Kio ; le bench tranche).

## 5. Tests

1. **Différentiels** vs `proved_hash` : mêmes vecteurs que 3b5d (cm, nf, root).
2. **Matrice de sabotage 3b5d reprise intégralement** : déséquilibre, nk falsifié,
   `output_commitment` falsifié, `tx_digest` falsifié, racine erronée, note d'un
   autre owner — tout rejeté.
3. **Liaison white-box par porteuse** (release) : pour chaque porteuse (`owner`,
   `nk`, `rho`, `cm_in`, montants), une trace forgée où la valeur produite ≠ la
   valeur consommée doit être REJETÉE — la contrainte de liaison mord.
4. **Non-régression e2e ledger** : `apply_proved_tx` (application, double-dépense,
   anchor inconnu, preuve falsifiée, signature d'intention).
5. Aucune assertion ne référence un témoin (revue systématique, comme 3a2b).

## 6. Hors périmètre → 3z-b / 3z-c

- **3z-b witness-hiding** : masquage de trace + salage des engagements. Fait
  vérifié (sources 0.13.1) : winterfell n'a AUCUN support zk → fork/extension du
  prouveur ou changement de stack, à trancher dans le spec 3z-b.
- **3z-c M-in/N-out** : le layout large plafonne à 2-in/2-out (budget colonnes) ;
  la généralisation passera par l'empilement systématique (structure VM légère).
