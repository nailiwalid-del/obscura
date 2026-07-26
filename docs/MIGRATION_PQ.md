# Migrer une chaîne vers FIPS 203/204 — retour d'expérience

> **Ce document n'est pas normatif.** L'autorité sur le versioning et les formats
> est [`PROTOCOL.md`](PROTOCOL.md) ; l'autorité sur la dette de backend est
> [`BACKEND_PQ.md`](BACKEND_PQ.md). Ce texte-ci raconte **comment la migration a été
> faite**, ce qu'elle a coûté, et ce qui s'en généralise. En cas de divergence, les
> deux documents cités ont raison.

Obscura a migré des primitives post-quantiques **round-3** (Kyber, Dilithium) vers
les normes **FIPS 203 (ML-KEM-768)** et **FIPS 204 (ML-DSA-65)**. La migration est
livrée. Ce document existe parce que la partie difficile n'était pas de changer de
bibliothèque.

## Ce qui est réellement en place

**L'hybridation, pas le remplacement.** Les deux primitives sont combinées avec leur
équivalent classique :

| Rôle | Composition | Identifiant |
|---|---|---|
| Échange de clé | X25519 **+** ML-KEM-768 | `x25519+mlkem768-fips203` |
| Signature | Ed25519 **+** ML-DSA-65 | FIPS 204 |

Le secret partagé combine les deux moitiés par KDF ; casser une seule des deux ne
suffit pas. C'est de la défense en profondeur : les primitives post-quantiques sont
jeunes, les classiques sont éprouvées mais mortelles à terme, et rien n'oblige à
choisir laquelle décevra.

## La décision qui commande tout : refuser l'ancien PAR SON NOM

C'est ici que se joue une migration de chaîne, et c'est ce qui se transpose ailleurs.

Chaque enveloppe porte un octet de version d'algorithme. `0x02` désigne FIPS ;
`0x01` désignait le round-3. **Le `0x01` n'est pas simplement inconnu : il est
reconnu, nommé, et refusé** — `CryptoError::AlgoPerime { quoi, version }`, dans
`crates/crypto/src/kem.rs` et `sig.rs`, avec des tests dédiés qui vérifient
l'erreur exacte.

**Aucune cohabitation.** Un nœud ne parle pas les deux versions « le temps de la
transition ». La raison est qu'une période de cohabitation est un état pendant lequel
le réseau accepte la primitive qu'on cherche justement à retirer — et cet état, en
pratique, ne se termine jamais tout seul.

La différence entre « version inconnue » et « version périmée » n'est pas cosmétique :

- **Inconnue** produit un message d'erreur générique, et l'opérateur conclut à un bug
  ou à un pair corrompu. Il perd des heures.
- **Périmée** produit un diagnostic qui se lit tout seul : *cette version a existé,
  elle est refusée, mettez à jour.* L'erreur nomme la cause.

Le même motif est appliqué au format de bloc côté ledger
(`BlocDecodeError::VersionPerimee`).

## L'identifiant d'algorithme entre dans le domaine du KDF

La chaîne de séparation de domaine contient le nom complet de la construction :

```
obscura/kem/x25519+mlkem768-fips203/combine/v1
```

Conséquence : **un domaine ne peut pas être réutilisé accidentellement d'une version
d'algorithme à l'autre.** Une clé dérivée sous round-3 et une clé dérivée sous FIPS
ne peuvent pas entrer en collision, même si tout le reste de l'entrée coïncide. Le
coût est nul ; l'oubli aurait été silencieux.

## L'écart assumé, et pourquoi il est écrit

La migration **n'a pas fermé** la couverture par vecteurs officiels. `pqcrypto`
n'expose aucune API dérandomisée — `keypair()` ne prend aucun argument, la signature
est hedgée — donc l'aléa officiel des vecteurs ACVP n'est pas injectable.

**Sont couverts** : `decap` et `sigVer`, les deux seules opérations déterministes —
et, précisément, **les deux seules que le consensus exécute**. Un nœud vérifie des
signatures et décapsule ; il ne rejoue jamais la génération de clés d'autrui.

**Ne sont pas couverts** : `keyGen`, `encap`, `sigGen`, et ML-DSA à contexte non vide.

Le détail, les comptes de groupes retenus et exclus, et la mesure qui a déterminé la
variante FIPS 204 réellement implémentée par le backend sont dans
[`CONFORMITE.md`](CONFORMITE.md) §1 et dans
[`crates/crypto/tests/vecteurs/PROVENANCE.md`](../crates/crypto/tests/vecteurs/PROVENANCE.md).

**L'écart est écrit plutôt que comblé en apparence.** L'apparition d'un backend
permettant l'injection d'aléa officiel est d'ailleurs un **critère de déclenchement**
de ré-évaluation, consigné dans [`BACKEND_PQ.md`](BACKEND_PQ.md).

## Ce que la migration n'a pas résolu

Elle a **déplacé** la dette de backend, pas supprimée : les crates `pqcrypto-mlkem`
et `pqcrypto-mldsa` portent leurs propres avis `unmaintained`, au même titre que les
round-3 qu'elles remplacent. Les avis sont ignorés **nommément** dans `deny.toml`,
jamais par un filtre large qui masquerait une vraie vulnérabilité de la même famille.

Le raisonnement complet — pourquoi ne pas migrer vers RustCrypto, libcrux ou
aws-lc-rs, et les quatre critères qui renverseraient cette conclusion — est dans
[`BACKEND_PQ.md`](BACKEND_PQ.md), avec un journal des re-tests datés.

## Ce qui se généralise

Trois points ne dépendent ni de Rust, ni d'Obscura, ni même d'une blockchain :

1. **Refuser l'ancienne version par son nom, sans période de cohabitation.** Le coût
   est une constante et une variante d'erreur ; le bénéfice est un diagnostic qui se
   lit tout seul et une transition qui se termine.
2. **Mettre l'identifiant d'algorithme dans le domaine de dérivation.** Gratuit à
   l'écriture, impossible à rattraper après coup.
3. **Écrire la dette avec ses critères de re-test et un journal daté**, plutôt que de
   la présenter comme résolue. Une décision « ne pas migrer » n'est valable qu'à sa
   date — la graver dans une chaîne exige de la re-confirmer, ce qu'impose
   explicitement l'étape 1 du runbook [`OUVERTURE.md`](OUVERTURE.md).
