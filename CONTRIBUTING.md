# Contribuer à Obscura

Merci de l'intérêt. Ce document dit trois choses : sous quelle licence votre
contribution est reçue, ce que vous devez attester en la soumettant, et ce qui
coûte cher à ce projet — parce qu'une partie du coût n'est pas visible dans le
code.

## Avant tout : ce qu'est ce dépôt

Un **prototype pédagogique, non audité**. Les fonds n'ont aucune valeur. Ce qui
est démontré, ce qui ne l'est pas, et comment le rejouer sans lire le code :
[`docs/CONFORMITE.md`](docs/CONFORMITE.md).

**`docs/` fait autorité.** `CLAUDE.md` et `AGENTS.md` sont des notes de travail.
En cas de divergence, `docs/` a raison, et la divergence est un défaut à
signaler.

## Licence : entrant = sortant

Toute contribution est reçue sous **`MIT OR Apache-2.0`**, la licence du dépôt.

**Il n'y a pas de CLA et pas de cession de droits.** Vous conservez votre droit
d'auteur sur ce que vous écrivez ; vous le publiez simplement sous la même
double licence que le reste. C'est la convention *inbound = outbound*, et elle
est délibérée — voir
[l'ADR de politique de licence](docs/superpowers/specs/2026-07-26-politique-de-licence-adr.md)
pour le raisonnement et son critère de renversement.

## Le DCO : ce que vous attestez

Chaque commit doit porter une ligne `Signed-off-by`. Elle s'ajoute
automatiquement :

```bash
git commit -s
```

Elle produit une ligne de la forme :

```
Signed-off-by: Prénom Nom <adresse@example.org>
```

En la signant, vous attestez le **Developer Certificate of Origin 1.1**
([developercertificate.org](https://developercertificate.org/)) — en substance :
vous avez le droit de soumettre ce code, soit parce que vous l'avez écrit, soit
parce qu'il vous parvient sous une licence appropriée ; et vous comprenez que la
contribution et votre nom sont publics et conservés indéfiniment.

Utilisez un nom et une adresse réels. Les pseudonymes anonymes ne permettent pas
d'attester quoi que ce soit.

### Pourquoi un DCO et pas un CLA

Un CLA servirait à obtenir le droit de **re-licencier le projet en bloc**. Ce
n'est pas nécessaire ici : un entrant permissif (`MIT OR Apache-2.0`) autorise
déjà la sous-licence, donc il ne ferme aucune option de licence future.

Ce qui manquerait sans le DCO, c'est la **provenance** — l'attestation que le
contributeur avait le droit de soumettre. C'est précisément ce qu'une revue de
chaîne d'approvisionnement logicielle interroge. Le DCO le donne pour une ligne
par commit, sans friction et sans document à signer.

## Ce qui coûte cher — à annoncer AVANT de coder

Le dépôt tient une **horloge de stabilité** ([`docs/STABILITE.md`](docs/STABILITE.md)).
Certains changements la remettent à zéro, et cette horloge conditionne des
décisions bien plus lourdes qu'une revue de code.

**Remettent le compteur à zéro** — donc à discuter en amont, dans une issue ou un
ADR, **jamais découverts dans une PR** :

- `VERSION_BLOC` ou tout format de fil ;
- l'énoncé prouvé par le circuit STARK ([`docs/STARK_STATEMENT.md`](docs/STARK_STATEMENT.md)) ;
- le backend post-quantique ([`docs/BACKEND_PQ.md`](docs/BACKEND_PQ.md)) ;
- le mécanisme économique ;
- les formats de fichier wallet ou nœud ;
- les invariants de consensus ([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), les ⚠️).

Ce n'est pas une interdiction : c'est un préalable. Une bonne idée qui touche à
cette liste mérite un ADR, pas une PR surprise.

## Conventions du dépôt

- **Commentaires et documentation en français**, y compris les messages de
  commit (convention du dépôt).
- **Tests unitaires dans chaque module**, tests de bout en bout dans
  `crates/ledger/tests/`.
- **Tout nouveau hash ou PRF doit être séparé par domaine et non tronqué.**
- Les chemins de développement (`dev-transparent`, `dev-circuits`) sont **hors
  consensus** et derrière des features. Le build par défaut n'expose que la
  surface de consensus — c'est un invariant vérifié en CI.

## Vérifier avant de proposer

La CI fait tourner exactement ceci ; l'exécuter en local évite un aller-retour.

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --release -- -D warnings
```

```bash
cargo clippy --workspace --all-targets --release --all-features -- -D warnings
```

```bash
cargo test --workspace --release --all-features
```

`--release` est nécessaire : les preuves STARK sont trop lentes en profil de
débogage et leurs tests sont ignorés en build de debug.

## Ce que la CI vérifie sur une PR

| Contrôle | Ce qui échoue |
|---|---|
| `dco` | un commit sans `Signed-off-by` valide |
| `rapide` | format, clippy (deux passes), invariant des features de dev |
| `test` | la suite complète en `--release --all-features` |
| `msrv` | compilation sous Rust 1.87 |
| `deny` | avis de sécurité et licences des dépendances |

Le job `dco` ignore les commits de fusion, qui n'ont pas à être signés.

## Signaler un problème de sécurité

Ne pas ouvrir d'issue publique. Le modèle d'adversaire et les limites **déjà
connues et assumées** sont dans [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) —
le lire d'abord évite de signaler ce qui est documenté. Pour le reste, contacter
l'auteur directement.
