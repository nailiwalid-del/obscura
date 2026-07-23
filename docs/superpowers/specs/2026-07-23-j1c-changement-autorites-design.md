# J1-c — Changement d'ensemble d'autorités, sans refaire la chaîne

**Date :** 2026-07-23
**Jalon :** J1-c de l'ADR `2026-07-22-j1-consensus-adr.md` (point 7). **Dernière
brique de la porte J1.**
**Prérequis :** J1-a (format `0x04`, vue + certificat) et J1-b (votes, changement
de vue, modèle A) sont dans `master`.
**Statut :** design validé sur ses décisions structurantes.

---

## Décisions prises (utilisateur, ne pas remettre en cause)

1. **`K` fixe, un seul changement en vol.** La hauteur d'effet est `h + K` avec
   `K` constante de protocole. Un nouveau changement est **refusé** tant qu'un est
   en attente. L'invariant « un seul en vol » élimine tout raisonnement sur des
   changements empilés — le piège classique des protocoles de reconfiguration.
2. **Liste nouvelle de taille variable, `[1, MAX_AUTORITES]`, liste vide
   INTERDITE.** Échanger, ajouter, retirer un membre passent tous par le même
   canal. Une liste vide rebasculerait en mode ouvert (plus de finalité) : c'est
   un changement de nature, pas de membres, et il ne passe pas par ici.

---

## Le problème que ce jalon ferme

Aujourd'hui les autorités sont posées **uniquement par la genèse**
(`ProvedLedgerState::depuis_genese` copie `genese.autorites`), et un bloc à
`hauteur > 0` portant des autorités est **refusé** (`AutoritesHorsGenese`,
`crates/ledger/src/proved_state.rs:641`). Changer un participant impose donc une
**nouvelle genèse = nouvelle chaîne** — ce qui, sur un réseau sur invitation,
oblige chaque participant à re-transmettre son adresse.

J1-c permet à l'ensemble d'autorités d'évoluer **sur la même chaîne**, certifié
par le quorum de l'ancienne liste.

---

## Partie I — Le champ de bloc et l'activation

### Le champ, `VERSION_BLOC 0x05`

```rust
/// La NOUVELLE liste d'autorités, si ce bloc annonce une reconfiguration.
/// `None` pour un bloc ordinaire.
pub changement_autorites: Option<Vec<SigPublicKey>>,
```

Trois décisions condensées :

- **Seule la nouvelle liste est portée, pas la hauteur d'effet.** `effective =
  hauteur + K` est **dérivée** d'une constante. Un producteur ne peut pas mentir
  sur *quand* le changement prend effet — il n'y a rien à mentir, un champ de
  moins à valider.
- **Le champ entre dans `corps_bytes`, donc dans l'identifiant.** C'est la
  condition de sûreté : le certificat de l'ancienne liste signe l'identifiant,
  donc signe **sur** la nouvelle liste. L'ancien comité approuve explicitement le
  nouveau. Encodage sans drapeau de présence séparé — la longueur (`0` = absent)
  suffit, même discipline que `scellement` et `certificat`.
- **`Option`, jamais un drapeau + liste séparés.** Un bloc ordinaire n'a pas de
  changement, un bloc de reconfiguration en a un ; deux formes distinctes,
  décodage sans ambiguïté.

### Le flux, celui de J1-b2, inchangé

Le bloc `h` qui annonce le changement est produit par le producteur du tour
(**ancienne** liste), scellé par lui, et **certifié par le quorum de l'ancienne
liste** — exactement un bloc normal, avec un champ de plus. **Aucun nouveau
message, aucune nouvelle machinerie de vote.** La nouvelle liste étant dans
l'identifiant, les votes de l'ancien comité portent sur elle.

### L'activation, à `h + K`

```
[h+1, h+K)   → ANCIENNE liste élit les producteurs, ancien quorum
h+K et après → NOUVELLE liste, nouveau quorum
```

⚠️ **Synergie avec J1-b2, et la raison de l'ordre J1-b avant J1-c.** Si la
nouvelle autorité n'est pas prête à `h+K` (pas encore synchronisée, hors ligne),
elle est le producteur de `(h+K, 0)` mais absente — et **le changement de vue de
J1-b2 la contourne** : `(h+K, 1)` revient à l'autorité suivante de la nouvelle
liste. J1-b2 rend J1-c robuste à un nouveau membre en retard, gratuitement.

### La valeur de `K`

Le délai n'achète pas de la sûreté (sous finalité BFT, appliquer `h+1` exige
d'avoir appliqué `h`, donc tout le monde connaît la nouvelle liste avant de juger
`h+1` — `K=1` serait déjà sûr). Il achète de la **coordination** : le temps que la
nouvelle autorité soit en ligne et synchronisée. `K` est donc une constante
**généreuse**, dimensionnée pour un réseau fédéré coordonné hors bande. Valeur
proposée : `K = 8` blocs (ajustable ; ce qui compte est `K ≥ 1` et « assez pour
qu'un opérateur mette en ligne le nouveau nœud »).

---

## Partie II — La machine à états

### L'état, `VERSION_ETAT 0x05`

```rust
autorites: Vec<SigPublicKey>,                             // liste ACTIVE (existe déjà)
changement_en_attente: Option<(Vec<SigPublicKey>, u64)>,  // (nouvelle liste, hauteur d'effet)
```

### Les trois gestes de `appliquer_bloc`, dans cet ordre

1. **Activation d'abord.** Au tout début du traitement du bloc de hauteur `h`, si
   `changement_en_attente` a une hauteur d'effet `== h`, on bascule :
   `autorites := nouvelle_liste`, `changement_en_attente := None`. **Avant** de
   valider producteur et quorum. Conséquence : le bloc à `h+K` est le **premier**
   jugé sous le nouveau régime — producteur de la nouvelle liste, certificat de
   la nouvelle liste. `h+K` inaugure le nouveau comité.

2. **Enregistrement du changement annoncé.** Après avoir validé le bloc `h`
   (chaînage, producteur, quorum de la liste active), s'il porte un
   `changement_autorites`, on enregistre `changement_en_attente := (nouvelle,
   h + K)`.

3. **Le verrou « un seul en vol ».** Un bloc qui porte un changement **alors qu'un
   changement est déjà en attente** est refusé (`ChangementDejaEnAttente`).

⚠️ **Atomicité.** `appliquer_bloc` est déjà atomique (un bloc à moitié appliqué
est interdit). L'activation et l'enregistrement du changement rejoignent cette
atomicité : ils font partie de l'instantané restauré en cas d'échec en aval. Un
bloc refusé ne laisse ni liste basculée, ni changement enregistré.

### Déterminisme

`producteur_attendu(h, vue)` et `quorum_requis()` lisent `self.autorites`, la
liste active de la hauteur courante. Tous les nœuds appliquent la même chaîne
finale et basculent **à la même hauteur** (hauteur d'effet, pas temps) : ils
calculent tous le même producteur et le même quorum. Le changement de vue traverse
le basculement sans cas particulier.

### Persistance

`changement_en_attente` entre dans `to_bytes`/`from_bytes` de l'état (`0x05`). Un
nœud qui redémarre dans la fenêtre `[h+1, h+K)` retrouve son changement en attente
— sinon il raterait le basculement et divergerait. Un dump `0x04` est refusé par
son nom.

---

## Partie III — Validité, sûreté, tests

### Validité d'un `changement_autorites`, dans l'ordre de coût

- **liste non vide** (`ChangementListeVide`) — sinon rebascule en mode ouvert ;
- **taille ≤ `MAX_AUTORITES`** — bornée avant toute allocation, comme la genèse ;
- **aucun changement déjà en attente** (`ChangementDejaEnAttente`) ;
- **seulement sur une chaîne à autorités** (`ChangementSurChaineOuverte`) — une
  chaîne ouverte n'a pas de comité à reconfigurer.

Le bloc reste soumis à **tout** le reste : chaînage, producteur légitime de
l'ancienne liste, certificat `2f+1` de l'ancienne liste, **avant** un éventuel
STARK. Le changement n'en court-circuite aucun ; il en ajoute.

### La limite à écrire, pas à cacher

Un changement est certifié par le quorum de l'**ancienne** liste : l'ancien comité
décide collectivement du nouveau, **y compris se réduire à `n=1`** ou se remplacer
entièrement. Ce n'est pas une faille nouvelle — un quorum d'anciens malveillants
contrôle déjà la chaîne — mais un participant doit savoir que sa place dépend du
quorum, pas d'un droit acquis. À écrire dans `docs/TESTNET.md`.

### Tests

- **Unité** : un bloc de changement enregistre l'attente ; un second changement
  pendant l'attente est refusé (`ChangementDejaEnAttente`) ; l'attente **bascule
  exactement à `h+K`** ; la nouvelle liste change `quorum_requis()` ; liste vide /
  hors borne / sur chaîne ouverte refusées par leur variante ; un dump d'état
  `0x04` refusé par son nom ; l'atomicité (un bloc refusé après enregistrement du
  changement ne laisse pas de trace).
- **Sockets — critère de sortie** : 4 autorités, l'une annonce le remplacement de
  l'autorité 3 par une clé neuve, certifié par l'ancien quorum ; à `h+K`, un bloc
  est **produit et certifié par la NOUVELLE liste** ; l'ancienne autorité 3 ne
  peut plus voter, la neuve le peut. Vraies sockets, temps injecté.
- **Synergie J1-b2** : à `h+K`, la nouvelle autorité absente, le changement de vue
  la contourne et le bloc sort quand même — les deux briques composent.
- **Redémarrage** : un nœud qui redémarre dans `[h+1, h+K)` retrouve son
  changement en attente et bascule correctement (même racine que les autres).

### Ce que J1-c ne fait pas

C'est la **dernière** brique de la porte J1. Après elle, le consensus est complet
pour l'état cible B — reconfigurable sans refaire la chaîne. Les portes suivantes
(économie J2, ouverture de l'appartenance en A) restent hors périmètre.

---

## Critère de sortie de J1-c

- Un ensemble d'autorités peut être remplacé **sur la même chaîne**, certifié par
  le quorum de l'ancienne liste, effectif à `h+K` — prouvé sur de vraies sockets.
- Un changement non certifié / à liste vide / hors borne / empilé est refusé par
  une variante qui le nomme.
- Le basculement est déterministe et survit au redémarrage.
- `docs/TESTNET.md` reflète que le comité est reconfigurable, et que l'ancien
  quorum décide du nouveau.
- CI verte, commandes exactes, passe par défaut comprise.
