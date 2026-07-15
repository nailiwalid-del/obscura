# Phase 3 — Stratégie de preuve et tranche 3a0

- Date : 2026-07-15
- Statut : décisions de design actées, implémentation 3a0 à lancer
- Portée : fixer la stratégie de preuve de la Phase 3, le découpage en tranches et le contrat technique de la tranche 3a0

## 1. Résumé exécutif

La Phase 3 construit d'abord un circuit de validité transparent et post-quantique. Ce circuit garantit l'intégrité du système : pas de forge, pas de double dépense, conservation des montants et cohérence Merkle/nullifier.

La confidentialité n'est pas livrée dans cette première étape. Les preuves STARK visées par les bibliothèques Rust disponibles ne doivent pas être considérées witness-hiding tant que le masquage complet de la trace, du quotient DEEP et des arguments de permutation n'est pas fourni et audité.

Décision centrale : construire les contraintes de validité maintenant, sous un étiquetage explicite `validity-only`, puis ajouter la couche zero-knowledge comme couche additive. Les contraintes P1-P7 doivent rester identiques avec ou sans masquage.

## 2. Contraintes non négociables

Le système cible Obscura doit respecter les contraintes suivantes :

| Contrainte | Décision |
|---|---|
| Setup | Transparent, aucun trusted setup |
| Sécurité post-quantique | Hash/FRI, pas de courbes elliptiques comme dépendance de preuve |
| Confidentialité cible | Montants, owner et secret doivent être cachés à terme |
| Circuit | Custom : Rescue, Merkle profondeur 32, range/équilibre u64 |
| Langage | Rust |
| Corps | Goldilocks, `p = 2^64 - 2^32 + 1` |
| Hash prouvé | Rescue-Prime `Rp64_256` |

## 3. Frontière de sécurité

### Ce que Phase 3 validité garantit

- Une note consommée correspond à un engagement valide.
- Un nullifier est dérivé correctement.
- Une racine Merkle est respectée.
- Les montants sont encodés en `u64` via 4 limbs de 16 bits.
- Les entrées et sorties équilibrent la transaction.
- Le `tx_digest` lie la preuve à la transaction attendue.

### Ce que Phase 3 validité ne garantit pas encore

- La preuve ne cache pas forcément le témoin.
- Les montants, secrets et owners ne doivent pas être supposés privés.
- Aucune preuve non masquée ne doit être présentée comme `zk`, `private`, `shielded production` ou équivalente.

Règle de nommage : tant que la couche ZK n'est pas livrée, le code et la documentation doivent utiliser `ValidityProof`, `ValidityCircuit` et `validity-only`. Le terme `ZkProof` est réservé à une preuve witness-hiding auditée.

## 4. Décision ZK

Un STARK n'est pas zero-knowledge par défaut. Pour obtenir du witness-hiding robuste, il faut au minimum :

- masquer chaque colonne de trace par de l'aléa suffisant ;
- masquer le polynôme de composition, y compris la décomposition DEEP ;
- traiter explicitement les arguments de permutation ;
- auditer l'entropie, les degrés, les tirages aléatoires et le transcript Fiat-Shamir.

État de décision : aucune dépendance Rust ne doit être considérée acceptable pour la confidentialité production sans preuve documentaire et audit couvrant ces points. La Phase 3 avance donc en mode validité d'abord.

Gate ZK futur :

- soit adoption d'une lib Rust auditée qui couvre circuits custom, FRI/STARK, Goldilocks ou corps compatible, et witness-hiding complet ;
- soit implémentation interne du recipe ZK, suivie d'audit cryptographique dédié ;
- dans les deux cas, ajouter des tests de non-fuite structurelle et un modèle de menace mis à jour.

## 5. Découpage Phase 3

```text
3a0  Encodage canonique Felt/bytes + digest types + domaines + MSRV
3a1  Rescue-Prime prouvé partagé, vecteurs et cross-tests Rp64_256
3a2  Validity skeleton P2 : owner = H_owner(secret), prove/verify
3b1  Gadgets nk/nullifier
3b2  Gadget Merkle path profondeur 32
3b3  Gadgets u64 balance/range via limbs 16 bits
3b4  Gadget note commitment
3b5  Circuit P1-P7 complet + binding tx_digest + test non-rejeu
3c   Format transaction prouvée + apply_proved
3d   Bench 2-in/2-out, Merkle profondeur 32
ZK   Gate séparé : masquage trace + DEEP + permutations + audit
```

Structure cible :

- `crates/proved-hash` : encodage, domaines, types digest, Rescue 3a1 ; aucune dépendance au prouveur.
- `crates/circuit` : AIR, witness generation, prove/verify ; dépend de `proved-hash`.
- `crates/ledger` : vérification applicative et application des transactions ; dépend de `proved-hash`, et seulement si nécessaire de `circuit`.

## 6. Objectif 3a0

La tranche 3a0 fige les représentations canoniques avant d'écrire les contraintes. Le but est d'éviter les reworks coûteux sur les engagements, racines Merkle, nullifiers, secrets et montants.

Livrable : un crate `proved-hash` minimal, sans Rescue et sans AIR, exposé uniquement les types, conversions canoniques, constantes de domaine et helpers de préambule.

## 7. Décisions 3a0

| Élément | Décision |
|---|---|
| Felt | Goldilocks, modulus `0xFFFFFFFF00000001` |
| Encodage Felt | 8 octets little-endian, valeur strictement `< p` |
| Digest | `[Felt; 4]`, soit 32 octets canoniques |
| Secret shielded | `[Felt; 4]`, serialization identique à `Digest`, rejet si un limb `>= p` |
| Montant | `AmountLimbs([u16; 4])`, ordre little-endian low-to-high |
| Circuit amount | 4 Felts, chacun contraint `< 2^16` |
| Hash domains | tags Felt distincts, non nuls, documentés et testés |
| Préambule sponge | séquence de champs canonique : version, domaine, longueur, payload, padding |
| MSRV | à fixer définitivement en 3a1 selon la dépendance prouveur retenue |

## 8. Contrat d'encodage

### 8.1 Felt

Un `Felt` est l'entier canonique `x` tel que `0 <= x < p`, avec `p = 18446744069414584321`.

Wire format :

```text
felt_bytes = le_u64(x)
```

Règles :

- `from_bytes([u8; 8])` rejette toute valeur `>= p` ;
- aucune réduction modulo `p` n'est autorisée au décodage ;
- `to_bytes` produit toujours la forme little-endian canonique.

### 8.2 Digest

Un `Digest` est exactement 4 Felts ordonnés :

```text
Digest = [d0, d1, d2, d3]
DigestBytes = bytes(d0) || bytes(d1) || bytes(d2) || bytes(d3)
```

Règles :

- le décodage rejette si un des 4 Felts est invalide ;
- l'ordre des membres est stable et couvert par vecteurs de test ;
- `Digest` peut être affiché en hex, mais sa serialization normative reste les 32 octets canoniques.

### 8.3 ShieldedSecret

Un `ShieldedSecret` est représenté comme `[Felt; 4]`.

Règles :

- même encodage que `Digest` ;
- rejet si un des 4 Felts est `>= p` ;
- ne jamais convertir un `[u8; 32]` wallet par réduction modulo ;
- l'adaptateur wallet de 3b devra utiliser un mapping canonique, idéalement rejection sampling ou dérivation hash-to-field documentée ;
- `Debug` doit être rédigé ou masqué ;
- ajouter `zeroize` si le crate accepte cette dépendance.

### 8.4 AmountLimbs

Un montant `u64` est décomposé en 4 limbs de 16 bits :

```text
amount = limb0 + limb1 * 2^16 + limb2 * 2^32 + limb3 * 2^48
```

Ordre : little-endian, `limb0` est le moins significatif.

Conversions :

- `AmountLimbs::from_u64(u64) -> AmountLimbs` ne peut pas échouer ;
- `AmountLimbs::to_u64() -> u64` recompose exactement ;
- `AmountLimbs::try_from_felts([Felt; 4])` rejette tout limb `>= 2^16` ;
- le mapping direct `u64 -> Felt` est interdit pour les contraintes de range/balance.

## 9. Domain separation

Tags v1 :

| Domaine | Tag |
|---|---:|
| Reserved | 0 |
| Owner | 1 |
| Nk | 2 |
| NoteCommitment | 3 |
| MerkleLeaf | 4 |
| MerkleNode | 5 |
| Nullifier | 6 |

Règles :

- `0` est réservé et ne doit jamais être utilisé pour hasher ;
- les tags sont des constantes publiques stables ;
- chaque tag a un test de non-régression ;
- tout nouveau domaine doit être ajouté par changement explicite de spec.

Préambule logique v1 :

```text
[ENCODING_VERSION, DOMAIN_TAG, LEN_FIELDS, payload..., PAD_ONE, PAD_ZERO*]
```

Avec :

- `ENCODING_VERSION = 1` ;
- `LEN_FIELDS` = nombre de Felts de payload avant padding ;
- `PAD_ONE = Felt(1)` ;
- `PAD_ZERO = Felt(0)` jusqu'à alignement sur le rate du sponge retenu en 3a1.

Note : 3a0 fige la séquence logique. 3a1 devra fixer le rate/state exact de Rescue-Prime `Rp64_256` et produire des vecteurs de hash complets.

## 10. Non-goals 3a0

3a0 ne livre pas :

- la permutation Rescue-Prime ;
- l'AIR ;
- `prove` / `verify` ;
- la migration du ledger ;
- le format transaction prouvée ;
- la confidentialité ;
- un protocole hash-to-field wallet final.

## 11. Critères d'acceptation 3a0

Implémentation :

- crate `crates/proved-hash` compile seul ;
- API minimale : `Felt`, `Digest`, `ShieldedSecret`, `AmountLimbs`, `Domain`, `SpongePreamble` ou équivalent ;
- aucune dépendance au prouveur ;
- aucune conversion modulo implicite ;
- erreurs explicites pour longueurs invalides, Felt non canonique et limbs hors range.

Tests obligatoires :

- round-trip `Felt <-> bytes` avec `0`, `1`, `p-1` ;
- rejet de `p`, `p+1`, `u64::MAX` ;
- round-trip `Digest <-> [u8; 32]` ;
- round-trip `ShieldedSecret <-> [u8; 32]` ;
- round-trip `u64 <-> AmountLimbs` avec `0`, `1`, `2^16-1`, `2^16`, `u64::MAX` ;
- rejet de limbs Felt `>= 2^16` ;
- préambules distincts pour tous les domaines ;
- vecteurs figés pour tags et préambules ;
- les tests existants du repo restent inchangés.

Qualité :

- documenter le modèle de menace dans `THREAT_MODEL` ou équivalent ;
- ajouter une note `STARK_STATEMENT` indiquant que la preuve est `validity-only` ;
- ajouter un fichier de golden vectors lisible par d'autres langages ;
- envisager `proptest` pour les round-trips et bornes.

## 12. Risques et mitigations

| Risque | Impact | Mitigation |
|---|---|---|
| Confusion validité/ZK | Fausse promesse privacy | Noms `Validity*`, doc claire, gate ZK séparé |
| Réduction modulo silencieuse | Collisions ou valeurs non canoniques | `try_from`, tests de rejet, interdiction documentée |
| Migration 64o -> 32o incomplète | Incompatibilité ledger/Merkle/API | plan de migration lockstep en 3b, pas d'arbre mixte |
| Tags de domaine insuffisants | Collision sémantique entre usages | tags non nuls, version d'encodage, golden vectors |
| Secrets loggés | Fuite hors preuve | `Debug` masqué, `zeroize`, hygiène logs |
| MSRV mouvante | CI instable | fixer en 3a1, vérifier dans CI |
| Dépendances ZK mal comprises | fuite silencieuse | audit obligatoire avant tout label privacy |

## 13. Pistes d'amélioration prioritaires

1. Ajouter une section `Security Claims` dans la doc publique.
   Elle doit dire explicitement : intégrité oui, confidentialité non tant que le gate ZK n'est pas fermé.

2. Ajouter un fichier `vectors/encoding_v1.json`.
   Il doit contenir les bytes de `Felt`, `Digest`, `ShieldedSecret`, `AmountLimbs` et préambules de chaque domaine.

3. Décider la politique secrets Rust.
   Pour `ShieldedSecret`, éviter `Debug` brut, envisager `Zeroize`, et auditer les logs.

4. Décider le statut `serde`.
   Si `serde` est exposé, imposer une forme canonique en bytes/hex, pas des tableaux ambigus d'entiers.

5. Nommer le gate ZK comme un jalon séparé.
   Exemple : `Phase 3z - Witness-hiding STARK layer`, avec critères d'audit et tests de non-fuite.

6. Préparer la migration commitment 64o -> 32o.
   Lister les structures impactées : note IDs, Merkle leaves/nodes, nullifiers, DB schema, serialization, RPC, wallet cache.

7. Ajouter des tests différentiels en 3a1.
   Le même preimage doit produire le même hash via implémentation native, implémentation circuit et éventuellement référence externe.

8. Interdire l'usage mainnet privacy tant que ZK est absent.
   Ajouter un flag de config ou une constante de protocole qui empêche d'activer des transactions présentées comme privées.

## 14. Références vérifiées

- Habock, Al Kindi, "A note on adding zero-knowledge to STARKs" : https://eprint.iacr.org/2024/1037
- Least Authority, audit Plonky3 : https://leastauthority.com/blog/audit-of-plonky3/
- Plonky3-recursion README, production warning : https://github.com/Plonky3/Plonky3-recursion
- Winterfell README, perfect zero-knowledge planned/not current : https://github.com/facebook/winterfell
- Hexens, overview ZK in STARKs : https://hexens.io/blog/zk-in-starks
