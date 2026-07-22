# Conformité et vérification par un tiers

Point d'entrée pour qui veut vérifier Obscura **sans lire le code**. Il énumère
ce qui est démontré, comment le rejouer, et — surtout — ce qui ne l'est pas.

## Statut

Prototype **non audité**. Les fonds n'ont aucune valeur. Ce document décrit ce
qui est *vérifiable*, ce qui n'est pas la même chose que ce qui est *vérifié*.

## 1. Primitives post-quantiques

| Primitive | Opération | Vecteurs | Rejouer |
|---|---|---|---|
| ML-KEM-768 (FIPS 203) | décapsulation | **10 officiels NIST** | `cargo test -p crypto --test acvp_mlkem768` |
| ML-DSA-65 (FIPS 204) | vérification | **1 officiel + 3 dérivés** | `cargo test -p crypto --test acvp_mldsa65` |

Ce sont **exactement les deux opérations que le consensus exécute** : un nœud
vérifie des signatures et décapsule. Il ne rejoue jamais la génération de clés
d'autrui, ni l'encapsulation d'autrui, ni la signature d'autrui.

⚠️ **Ce sont des vecteurs ACVP _ciblés_, pas des KAT FIPS complets.** Quatre
opérations sur six sont hors de portée avec le backend actuel :

| Hors couverture | Cause |
|---|---|
| `keyGen`, `encap` | `keypair()` ne prend aucun argument — l'aléa officiel n'est pas injectable |
| `sigGen` | `detached_sign` est hedgé, **mesuré** : les signatures diffèrent des vecteurs déterministes |
| ML-DSA à contexte non vide | l'API ne prend pas de chaîne de contexte |

C'est aussi pourquoi le jeu ML-DSA ne compte qu'**un** vecteur officiel : un seul
test ACVP `ML-DSA-65` / `external` / `pure` a un contexte vide. Les 14 autres ne
sont pas faux — ils sont invérifiables ici. Les 3 cas dérivés sont des mutations
d'un bit du vecteur officiel valide, étiquetées `derive-*`, qui testent le rejet.

Détail complet, comptes de groupes retenus et exclus, et la mesure qui a
déterminé la variante FIPS 204 implémentée par le backend :
[`crates/crypto/tests/vecteurs/PROVENANCE.md`](../crates/crypto/tests/vecteurs/PROVENANCE.md).

Ces vecteurs valident le **backend** (`pqcrypto-*`), pas la couche hybride
d'Obscura — `kem::decapsulate` et `sig::verify` combinent deux primitives et ne
peuvent pas consommer un vecteur brut. La couche hybride est couverte par les
tests unitaires de `crates/crypto`.

## 2. Consensus

Fixture rejouable : [`docs/fixtures/conformite-v2/`](fixtures/conformite-v2/README.md).

```bash
cargo test -p node --test conformite
```

Couvre : décodage de bloc **`0x04`**, identifiant de genèse (autorités
comprises), amorçage d'état, chaînage, élection de producteur, vérification de
scellement, **certificat de quorum**, avancée de la tête. **Ne couvre aucune
transaction ni preuve STARK**, et son quorum n'a qu'**un seul votant** (`n = 1`,
donc `f = 0`) — voir le README de la fixture, qui dit aussi pourquoi.

## 3. Suite complète

```bash
cargo test --all-features --release
```

`--release` est nécessaire : les preuves STARK sont trop lentes en profil de
débogage. `--all-features` ajoute les sous-circuits autonomes et le mode
transparent de développement, tous deux **hors du consensus** — le build par
défaut n'expose que la surface de consensus, et c'est un invariant vérifié en CI.

## 4. Où fait autorité la spécification

| Sujet | Document |
|---|---|
| Protocole, formats, versioning | [`PROTOCOL.md`](PROTOCOL.md) |
| Modèle de menace et limites connues | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| Énoncé prouvé par le circuit, argument HVZK | [`STARK_STATEMENT.md`](STARK_STATEMENT.md) |
| Post-quantique : thèse et quantification | [`POST_QUANTIQUE.md`](POST_QUANTIQUE.md) |
| Dette de backend PQ et critères de re-test | [`BACKEND_PQ.md`](BACKEND_PQ.md) |
| Exploitation d'un nœud | [`OPERATEUR.md`](OPERATEUR.md) |
| Limites du testnet, reset, réaction à la valeur | [`TESTNET.md`](TESTNET.md) |

⚠️ **`CLAUDE.md` et `AGENTS.md` ne font pas autorité.** Ce sont des notes de
travail destinées à des agents. En cas de divergence avec `docs/`, **`docs/` a
raison**, et la divergence est un défaut à signaler.

## 5. Ce qui n'est pas démontré

- L'argument HVZK est **honnête-vérifieur** et non audité
  ([`STARK_STATEMENT.md`](STARK_STATEMENT.md)).
- **Aucun audit externe n'a eu lieu.**
- `keyGen`, `encap`, `sigGen` et le contexte ML-DSA ne sont pas couverts par
  vecteurs officiels (§1).
- La fixture de consensus ne couvre aucune transaction (§2), ni un quorum à
  plusieurs votants.
- **Le protocole de vue n'est pas livré** (jalon J1-b) : le format du certificat
  et sa vérification le sont, mais aucun vote ne circule sur le fil. Une chaîne à
  `n ≥ 4` ne produit donc aucun bloc aujourd'hui
  ([`PROTOCOL.md`](PROTOCOL.md), « Finalité : le bloc »).
- Le backend PQ est marqué `unmaintained` en amont — dette ouverte, assumée et
  datée ([`BACKEND_PQ.md`](BACKEND_PQ.md)).
- Les limites connues du réseau sont listées dans
  [`THREAT_MODEL.md`](THREAT_MODEL.md) et ne sont pas répétées ici.
