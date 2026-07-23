# J1-b2 — Changement de vue : une autorité absente ne fige plus la chaîne

**Date :** 2026-07-23
**Jalon :** J1-b2 de l'ADR `2026-07-22-j1-consensus-adr.md`.
**Prérequis :** J1-b1 livré (votes sur le fil, registre persisté, certificat de
quorum). Ce document décrit le protocole de vue qui **ferme la liveness**.
**Statut :** design validé sur ses décisions structurantes.

---

## Décisions prises (utilisateur, ne pas remettre en cause)

1. **Sûreté : un vote par HAUTEUR** (modèle A), pas par `(hauteur, vue)`. La vue
   sort de la clé de sûreté. Sûreté triviale à prouver, aucune machinerie de
   verrouillage. On préfère l'arrêt à la divergence — posture déjà écrite dans
   l'ADR et dans `docs/TESTNET.md`.
2. **Liveness : battement, blocs vides permis.** Le producteur du tour propose à
   la cadence, vide si le mempool l'est. Le détecteur de panne lit un fait local
   et objectif — « la hauteur a-t-elle avancé » — sans jamais consulter un état
   partagé et manipulable.
3. **Pas de certificat de changement de vue.** C'est un objet du modèle B. Sous A
   avec des délais indépendants, il n'existe pas.

---

## Le problème que ce jalon ferme

Depuis J1-b1, une chaîne à `n ≥ 4` autorités produit des blocs — **tant que le
producteur du tour répond**. `producteur_attendu(h, vue) = autorites[(h−1+vue)
mod n]` est une fonction pure : si l'autorité du tour est absente, personne ne
peut produire `h`, et rien ne fait avancer la vue. La chaîne fige jusqu'au retour
de l'autorité (`docs/TESTNET.md`, limite connue).

J1-b2 introduit le **délai de vue** : passé un temps sans bloc à la hauteur
attendue, chaque nœud incrémente sa vue localement, ce qui désigne un nouveau
producteur. Une autorité absente est ainsi contournée sans intervention humaine.

---

## Partie I — La sûreté (le modèle A réalisé)

### Le registre change de clé

Le registre persisté de J1-b1 a pour clé `(hauteur, vue) → id`. Sous le modèle A,
**la vue disparaît de la clé de sûreté** :

```
peut_voter(hauteur, id) =
      hauteur > derniere_hauteur_votee
   OU (hauteur == derniere_hauteur_votee ET id == dernier_id)   // idempotent
```

Le registre devient `{ derniere_hauteur_votee: u64, dernier_id: [u8; 64] }` —
monotone en hauteur seule. Le champ `vue` est **retiré** du format persisté, qui
passe de `VERSION_VOTES 0x01` à `0x02`. Un `0x01` est refusé par son nom, jamais
réinterprété (même discipline que partout).

⚠️ **Migration** : aucune. Un registre `0x01` d'un nœud J1-b1 est refusé au
démarrage — l'opérateur supprime `votes.bin`, qui se recrée vierge. Le **format
de bloc ne change pas** (le `0x04` de J1-a porte déjà la vue) ; ce qui change est
la **règle de consensus** (clé du registre, et le protocole de vue). Un réseau
mixte J1-b1/J1-b2 divergerait, donc la mise à niveau est coordonnée — comme tout
changement de règle sur un réseau sur invitation.

⚠️ **Précision sur « supprimer `votes.bin` »** : c'est sûr **uniquement** lors
d'une mise à niveau coordonnée où le nœud n'a encore rien voté sous la nouvelle
règle. En fonctionnement normal, un `votes.bin` illisible reste **fatal** (il
autoriserait l'équivocation) — la discipline de J1-b1 est inchangée. La
suppression est un geste d'opérateur explicite, pas un repli automatique.

### La preuve de sûreté, en trois lignes

Deux blocs A et B distincts à la même hauteur `h` qui atteindraient tous deux
`2f+1` votes auraient, sur `3f+1` nœuds, au moins `(2f+1)+(2f+1)−(3f+1) = f+1`
votants communs. Au moins un de ces `f+1` est honnête. Cet honnête aurait voté
pour deux `id` différents à la hauteur `h` — ce que le registre interdit.
Contradiction. **La vue n'entre jamais dans l'argument.**

### Ce qui NE change pas

Le protocole applicatif de J1-b1 est intact : `Message::{Proposition, Vote}`, le
type `Certificat`, l'assemblage au quorum, la vérification `2f+1` avant tout
STARK. Seule la **clé** que `peut_voter` compare change. Il n'y a **pas** de
nouveau message, **pas** de certificat de changement de vue.

---

## Partie II — La liveness (le détecteur de panne)

### L'état ajouté au nœud

```rust
/// Vue de la hauteur qu'on essaie d'atteindre. Remise à 0 à chaque hauteur
/// appliquée.
vue_courante: u32,
/// Uptime (ms) auquel la fenêtre (hauteur, vue) courante a commencé.
debut_vue_ms: u64,
```

Les deux se réinitialisent (`vue = 0`, `debut = maintenant`) **à chaque hauteur
appliquée** — dans `sur_vote` (le collecteur), `sur_bloc` (réception d'un bloc
certifié) et `sur_proposition`/`sceller` quand la hauteur avance. C'est le seul
couplage du détecteur avec le reste : une hauteur qui avance le remet à zéro.

### Le battement, dans `tick(maintenant_ms)`

`tick` est le point d'entrée temporel qui existe déjà (embargos Dandelion). On y
ajoute le délai de vue :

```
si maintenant_ms − debut_vue_ms >= delai_vue(vue_courante):
    vue_courante += 1
    debut_vue_ms = maintenant_ms
    si producteur_attendu(prochaine_hauteur, vue_courante) == notre_identite:
        // proposer un bloc pour (prochaine_hauteur, vue_courante), vide si besoin
        <même chemin que `sceller`, mais à la vue courante>
```

Le producteur du tour propose **une fois** en devenant producteur (hauteur qui
avance pour `v = 0`, ou vue qui monte pour `v > 0`) — jamais en boucle. Les
autres attendent. Producteur absent ⇒ tous les délais expirent ⇒ tous passent à
`v+1` ⇒ le producteur de `(h, v+1)` propose. C'est ce qui défige la chaîne.

⚠️ Le temps est **injecté** (`maintenant_ms`), jamais lu de l'horloge dans
l'orchestration. Le changement de vue est donc déterministe et testable sans
dormir.

### Deux paramètres de temps, jamais un

| | Rôle | Valeur |
|---|---|---|
| **cadence** | intervalle minimal entre blocs : le producteur ne propose pas plus vite | `--sceller <ms>` |
| **délai de vue** | combien les autres attendent avant d'abandonner le producteur | `cadence × FACTEUR_VUE`, `FACTEUR_VUE ≥ 3` |

Le délai **doit** dépasser la cadence, sinon un producteur qui marche serait
tourné avant d'avoir eu le temps de proposer. Un seul bouton opérateur
(`--sceller`) ; le délai en est dérivé par une constante.

⚠️ **Conséquence sur `--sceller`** : sur une chaîne à autorités, le délai de vue
doit être actif pour **toutes** les autorités, pas seulement pour le producteur.
Le détecteur de panne est une nécessité de consensus, pas une cadence
d'opérateur. Une autorité sans `--sceller` explicite prend donc un délai de vue
par défaut. Un non-autorité ne propose pas et ne fait pas tourner de délai (il
applique les blocs qu'il reçoit).

### Backoff exponentiel

```
delai_vue(vue) = min(BASE × 2^vue, PLAFOND)
```

Les horloges des nœuds ne sont pas synchronisées : ils appliquent la hauteur `h`
à des instants différents, donc leurs délais ne tirent pas ensemble. Sans
backoff, un décalage persistant peut faire se rater les vues indéfiniment
(livelock). Le backoff garantit qu'une vue finit par durer assez longtemps pour
que tous les nœuds s'alignent. `PLAFOND` borne l'attente maximale.

---

## Partie III — Accepter une proposition sous les vues

`sur_proposition` gagne le contrôle de vue. Cinq contrôles, ordre de coût
préservé (rien de coûteux avant d'avoir voté) :

1. le bloc s'enchaîne sur notre tête, `hauteur == notre_hauteur + 1` — O(1) ;
2. le proposeur est le producteur légitime de `(bloc.hauteur, bloc.vue)` :
   `autorites[(h−1+vue) mod n]` — O(1), **vérifiable quelle que soit notre vue
   locale** ;
3. `bloc.vue >= vue_courante` — hygiène de liveness : on ne vote pas pour une vue
   abandonnée. Si `bloc.vue > vue_courante`, on **adopte** `vue_courante =
   bloc.vue` (une proposition légitime peut nous tirer en avant) ;
4. le registre autorise : pas déjà voté à `h` pour un autre `id` — **le contrôle
   de sûreté** ;
5. persister le vote (action `PersisterVotes`), puis l'émettre.

**Ce qui tombe tout seul du modèle A** : un nœud peut voter pour une proposition
à la vue `v` **sans avoir lui-même atteint la vue `v`**. La sûreté étant fondée
sur la hauteur, il suffit qu'il n'ait pas voté à `h`. Un nœud en retard contribue
donc au quorum sans qu'on synchronise les vues avant de voter — ce qui serait
tout le poids du modèle B, et qu'on s'épargne.

---

## Partie IV — Limites connues, écrites plutôt que découvertes

- **A défige contre un producteur ABSENT — le but visé — et rien de plus.** Si
  les votes se **partitionnent** (un nœud vote A à `v=0`, un autre B à `v=1`
  parce que le producteur était « à moitié là » à la frontière du délai), aucun
  des deux n'atteint forcément `2f+1`. Comme les votants sont **verrouillés à
  vie** par le registre, la hauteur peut **caler définitivement**. Recovery :
  nouvelle chaîne. C'est le prix assumé de « arrêt plutôt que divergence », et
  c'est un cas **bien plus rare** que l'absence : il exige un producteur
  partiellement joignable pile au basculement.

- **`docs/TESTNET.md` change.** La ligne « Une autorité absente fige la chaîne
  jusqu'à son retour » devient **fausse** et doit être remplacée par :
  > Une autorité **absente** est contournée par changement de vue : la chaîne
  > continue avec le producteur suivant. En revanche, un **partitionnement des
  > votes** (rare, producteur à moitié joignable au basculement) peut caler une
  > hauteur définitivement — recovery par nouvelle chaîne.

- **Blocs vides au repos.** Le battement produit un bloc à la cadence même si le
  mempool est vide. La chaîne grossit au repos ; sur un testnet consommable,
  sans conséquence, et réglable par `--sceller`.

- **Ce que J1-b2 ne fait pas :** J1-c (changement d'ensemble d'autorités certifié
  par l'ancienne liste) reste ouvert. Le comité est fixe.

---

## Partie V — Tests

Discipline du dépôt : sur sockets réelles quand il s'agit du protocole, temps
injecté pour le déterminisme.

1. **`producteur_absent_la_chaine_avance` (sockets)** — 4 autorités, on ne
   démarre pas l'autorité 0. Les trois autres doivent produire la hauteur 1 en
   `vue = 1`, sous le producteur `autorites[1]`, et converger vers la même
   racine. **C'est le test qui prouve la liveness**, et le critère de sortie du
   jalon.
2. **`producteur_qui_marche_jamais_tourne`** — la chaîne avance en `vue = 0` ;
   aucun bloc appliqué n'a de vue > 0 tant que le producteur répond.
3. **`sureté_preservee_a_travers_les_vues`** — un nœud qui a voté à `h` refuse de
   voter pour un autre bloc à `h`, **même à une vue supérieure**. Vérifié par
   mutation (retirer la persistance doit casser le test).
4. **`changement_de_vue_deterministe`** — `tick(maintenant_ms)` avec des temps
   injectés fait monter la vue exactement au franchissement du délai, backoff
   compris. Aucun `sleep`.
5. **`delai_de_vue_depasse_la_cadence`** — assertion de cohérence : `FACTEUR_VUE
   ≥ 3`, le délai dérivé est toujours strictement supérieur à la cadence.

---

## Critère de sortie de J1-b2

- Sur une chaîne à 4 autorités, le producteur du tour absent, la chaîne **produit
  quand même** la hauteur suivante par changement de vue, sur de vraies sockets.
- Un producteur qui répond n'est jamais tourné.
- Un nœud ne vote jamais deux fois différemment à la même hauteur, **toutes vues
  confondues** — vérifié par mutation.
- `docs/TESTNET.md` reflète la nouvelle réalité de liveness.
- CI verte avec les commandes exactes (fmt, clippy défaut ET all-features, tests).
