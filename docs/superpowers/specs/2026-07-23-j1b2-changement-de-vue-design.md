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

---

## Partie 0 — Prérequis de sûreté : le QUORUM (P0, à corriger avant tout code)

**Faille pré-existante, indépendante du changement de vue.** Le quorum est
calculé `2·⌊(n−1)/3⌋+1` (`crates/ledger/src/proved_state.rs:513`). Cette formule
n'est correcte que si `n = 3f+1`. Pour **n=5** elle donne 3, et deux blocs A={1,2,3}
et B={3,4,5} n'ont que le nœud 3 en commun : s'il est fautif, A et B atteignent
tous deux le quorum → **deux blocs finalisés à la même hauteur, divergence
définitive.** La preuve de sûreté de ce document est donc **fausse** pour n=5, n=6,
et — subtilement — n=2 (quorum 1 = chaque nœud finalise seul).

**Correction : généraliser à `quorum = ⌊2n/3⌋+1`.**

| n | ⌊2n/3⌋+1 | 2·⌊(n−1)/3⌋+1 (ancien) | sûr ? |
|---|---|---|---|
| 1 | 1 | 1 | oui (trivial) |
| 2 | **2** | 1 ⚠️ | corrigé |
| 4 | 3 | 3 | oui (= 2f+1) |
| 5 | **4** | 3 ⚠️ | corrigé |
| 6 | **5** | 3 ⚠️ | corrigé |
| 7 | 5 | 5 | oui (= 2f+1) |
| 10 | 7 | 7 | oui (= 2f+1) |

`⌊2n/3⌋+1` **égale `2f+1` exactement quand `n=3f+1`** (donc n'change rien à
n=4/7/10), et est sûre pour tout autre n : deux quorums de cette taille se
recoupent en `> f` nœuds, dont au moins un honnête. Elle satisfait aussi la
liveness (`quorum ≤ n−f` toujours).

**Pourquoi généraliser plutôt que refuser les tailles non-`3f+1` (l'option
« refuser » proposée en revue).** Refuser rendrait **n=2 illégal**, or n=2 est
utilisé (`finalite.rs::deux_autorites_alternent_sur_sockets`) et documenté
(alternance à deux autorités). La généralisation **corrige** n=2 au lieu de
l'interdire. Le dilemme « n=2 ou la sûreté » disparaît.

⚠️ **Effet de bord à traiter** : à n=2, le quorum passe de 1 à 2. Le test
d'alternance passe donc désormais par le **chemin de vote** (le producteur seul ne
suffit plus), pas par l'auto-application. `finalite.rs` doit être adapté.

**Ce prérequis est la première tâche du plan, avec son propre commit** : c'est une
correction de sûreté autonome, testable seule, qui doit atterrir avant le
protocole de vue.

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

Deux blocs A et B distincts à la même hauteur `h` qui atteindraient tous deux le
quorum `q = ⌊2n/3⌋+1` (partie 0) auraient au moins `2q − n` votants communs. Comme
`2q − n = 2⌊2n/3⌋+2 − n > f` (pour `f = ⌊(n−1)/3⌋`), l'intersection compte au moins
`f+1` nœuds, dont au moins un honnête. Cet honnête aurait voté pour deux `id`
différents à la hauteur `h` — ce que le registre interdit. Contradiction. **La vue
n'entre jamais dans l'argument, et la borne tient pour tout `n`, pas seulement
`n = 3f+1`.**

### Ce qui NE change pas

Le protocole applicatif de J1-b1 est intact : `Message::{Proposition, Vote}`, le
type `Certificat`, l'assemblage au quorum, la vérification du quorum avant tout
STARK. Seule la **clé** que `peut_voter` compare change. Il n'y a **pas** de
nouveau message, **pas** de certificat de changement de vue.

### Certificat CANONIQUE : exactement le quorum, pas de surplus (point 8 de la revue)

Les signatures PQ ne s'agrègent pas : le certificat pèse `quorum × 3374` octets,
et chaque vote surnuméraire est de la bande passante et une vérification en plus,
pour rien. À l'assemblage, le collecteur construit donc un certificat avec
**exactement `quorum_requis()` votes** — les plus petits index disponibles —
triés par index. Pas de surplus.

Côté vérification, `appliquer_bloc` reste tolérant (`>= quorum` valides), car un
bloc reçu d'un pair pourrait légitimement porter un assemblage différent ; mais un
bloc que **nous** produisons est toujours canonique. Un test vérifie qu'un bloc
scellé par nous porte **exactement** le quorum.

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

### Un helper UNIQUE pour l'avancée de hauteur (point 5 de la revue)

Le reset de vue a lieu par **plusieurs** chemins (`sur_vote` quand on assemble,
`sur_bloc` quand on reçoit un bloc certifié, `sceller`/`sur_proposition` quand
notre hauteur avance). Oublier le reset dans **un seul** de ces chemins est
exactement le genre de bug qui laisse un nœud désynchronisé. On centralise donc :

```rust
/// À appeler APRÈS chaque `appliquer_bloc` réussi, par TOUS les chemins.
/// Point d'entrée unique du reset de vue — DRY, et pas d'oubli possible.
fn hauteur_avancee(&mut self, maintenant_ms: u64) {
    self.vue_courante = 0;
    self.debut_vue_ms = maintenant_ms;
    self.votes_recus.clear();
    self.proposition_en_cours = None;
}
```

Aucun chemin ne réinitialise ces champs à la main : ils appellent tous
`hauteur_avancee`.

### Débordement de `vue_courante` (point 3 de la revue)

`vue_courante` est un `u32` et un `+1` implicite au tick déborderait. On plafonne :

```rust
const MAX_VUE_PAR_HAUTEUR: u32 = 1000;
```

Atteindre `MAX_VUE_PAR_HAUTEUR` **sans** avoir avancé la hauteur, c'est le cas de
**calage** (partie IV) : plus aucun incrément, journal `CRITIQUE`, compteur
`hauteurs_calees` incrémenté, et le nœud cesse de proposer pour cette hauteur.
Jamais de `wraparound`. Le plafond est bien en dessous de `u32::MAX` et généreux :
1000 vues à backoff plafonné, c'est déjà des heures — une chaîne qui l'atteint est
calée, pas lente.

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
3. **`vue_courante <= bloc.vue <= vue_courante + FENETRE_VUE`** — borné des DEUX
   côtés (point 2 de la revue). En bas : on ne vote pas pour une vue abandonnée.
   En haut : un producteur légitime d'une vue très lointaine (jusqu'à
   `MAX_VUE_PAR_HAUTEUR`) pourrait sinon tirer tout le monde en avant d'un coup et
   désynchroniser le réseau. `FENETRE_VUE` est petit (**1**) : on n'adopte qu'un
   pas de vue au-delà du nôtre. Une proposition à `vue_courante + 2` ou plus est
   **ignorée** — on la re-verra quand nos propres délais nous y auront amenés.
   ⚠️ Ce plafond ne concerne QUE les propositions **non certifiées**. Un
   `Message::Bloc` déjà **certifié** est appliqué quelle que soit sa vue : il est
   final ailleurs, le refuser nous ferait diverger ;
4. si `bloc.vue > vue_courante`, on **adopte** : `vue_courante = bloc.vue` **ET
   `debut_vue_ms = maintenant_ms`** (point 4 de la revue). Réinitialiser le timer
   est indispensable — sans lui, on adopterait la vue puis on l'expirerait au tick
   suivant, la faisant monter en boucle ;
5. le registre autorise : pas déjà voté à `h` pour un autre `id` — **le contrôle
   de sûreté** ;
6. persister le vote (action `PersisterVotes`), puis l'émettre.

**Ce qui tombe tout seul du modèle A** : un nœud peut voter pour une proposition
à la vue `v` **sans avoir lui-même atteint la vue `v`** (dans la limite de
`FENETRE_VUE`). La sûreté étant fondée sur la hauteur, il suffit qu'il n'ait pas
voté à `h`. Un nœud légèrement en retard contribue donc au quorum sans qu'on
synchronise les vues avant de voter — ce qui serait tout le poids du modèle B.

### Le changement dans `Noeud::sceller` / la proposition (point 6 de la revue)

`sceller` aujourd'hui (`orchestration.rs:319`) ne scelle qu'en `vue = 0` et rend
`None` si le mempool est vide. J1-b2 exige l'**inverse** sur une chaîne à
autorités :

- proposer à **`vue_courante`**, pas à `vue = 0` en dur ;
- **bloc vide permis** : un mempool vide ne rend plus `None`, il produit un bloc
  vide (le battement). Sur une chaîne OUVERTE (sans autorités), le comportement
  historique est conservé (pas de bloc vide spontané).

La proposition émise par le battement (`tick`) et celle émise par le chemin
opérateur passent par le **même** constructeur de bloc, à la vue courante.

### `--sceller` : cadence de consensus, pas option de participation (point 7)

Sur une chaîne à autorités, le délai de vue doit tourner chez **toutes** les
autorités — le détecteur de panne est une nécessité de consensus. Conséquence :
`--sceller` ne signifie plus « je participe » ; toute autorité prend une
**cadence par défaut** (`CADENCE_CONSENSUS_MS_DEFAUT`) même sans le drapeau, et
`--sceller <ms>` ne fait que la régler. Le nom du drapeau est conservé (éviter la
rotation de CLI), mais son sens conceptuel est « cadence de consensus ». Un
**non-autorité** ne propose pas et ne fait tourner aucun délai — il applique les
blocs reçus.

---

## Partie IV — Limites connues, écrites plutôt que découvertes

- **A défige contre un producteur ABSENT — le but visé — et rien de plus.** Si
  les votes se **partitionnent** (un nœud vote A à `v=0`, un autre B à `v=1`
  parce que le producteur était « à moitié là » à la frontière du délai), aucun
  des deux n'atteint forcément le quorum. Comme les votants sont **verrouillés à
  vie** par le registre, la hauteur peut **caler définitivement**. Recovery :
  nouvelle chaîne. C'est le prix assumé de « arrêt plutôt que divergence », et
  c'est un cas **bien plus rare** que l'absence : il exige un producteur
  partiellement joignable pile au basculement.

  ⚠️ **Le calage doit être VISIBLE, jamais silencieux (point 9 de la revue).** Un
  arrêt muet serait le pire mode d'échec : un opérateur croirait sa chaîne lente
  alors qu'elle est morte. Trois signaux, aucun optionnel :
  - **journal `CRITIQUE`** quand `vue_courante` atteint `MAX_VUE_PAR_HAUTEUR` :
    « hauteur h calée après N vues — split de votes probable, une nouvelle chaîne
    est nécessaire » ;
  - **compteur `hauteurs_calees`** sur le nœud, à côté de `blocs_desaccordes` ;
  - **ligne de statut** : le compteur y figure, et la ligne passe en `AVERT`
    (comme pour `liens = 0` et `désaccords > 0`) dès qu'il est non nul.
  Un test provoque le calage et vérifie les trois.

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

Tests ajoutés en revue (point 10) :

6. **`quorum_generalise`** — `quorum_requis()` vaut `⌊2n/3⌋+1` pour n ∈
   {1,2,4,5,6,7,10}, et l'ancienne faille est fermée : à n=5, deux blocs à 3
   votes ne peuvent PAS être tous deux acceptés (le quorum est 4). C'est le test
   du prérequis P0.
7. **`vue_future_trop_lointaine_refusee`** — une proposition à `vue_courante + 2`
   est ignorée ; à `vue_courante + 1` elle est adoptée.
8. **`adoption_vue_reset_le_timer`** — après adoption d'une vue future, un tick
   immédiat ne fait PAS monter la vue (le timer a bien été réarmé).
9. **`bloc_vide_produit_sur_chaine_a_autorites`** — mempool vide, chaîne à
   autorités : `sceller`/`tick` produit un bloc vide, ne rend pas `None`.
10. **`certificat_scelle_par_nous_est_canonique`** — un bloc que nous produisons
    porte **exactement** le quorum de votes, triés par index, aucun surplus.
11. **`overflow_vue_plafonne_et_signale`** — `vue_courante` s'arrête à
    `MAX_VUE_PAR_HAUTEUR`, `hauteurs_calees` s'incrémente, le journal `CRITIQUE`
    est émis, aucun `wraparound`.
12. **`n2_passe_par_le_chemin_de_vote`** — à n=2, quorum 2 : l'alternance de
    `finalite.rs` passe désormais par Proposition/Vote et non par
    l'auto-application. (Adaptation du test existant.)

---

## Critère de sortie de J1-b2

- Sur une chaîne à 4 autorités, le producteur du tour absent, la chaîne **produit
  quand même** la hauteur suivante par changement de vue, sur de vraies sockets.
- Un producteur qui répond n'est jamais tourné.
- Un nœud ne vote jamais deux fois différemment à la même hauteur, **toutes vues
  confondues** — vérifié par mutation.
- `docs/TESTNET.md` reflète la nouvelle réalité de liveness.
- CI verte avec les commandes exactes (fmt, clippy défaut ET all-features, tests).
