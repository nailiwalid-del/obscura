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

## Partie 0 — Corrections de revue intégrées

Cette section résume les dix points de revue et où ils atterrissent. Deux
corrigeaient des **erreurs** du premier jet, pas des raffinements.

| # | Point | Traitement |
|---|---|---|
| 1 | **Doublons d'autorités interdits** | contrôle `sans doublon` en genèse ET dans le changement (faille latente : une clé à deux index vote deux fois) |
| 2 | **Contradiction `0 = absent` vs « liste vide refusée »** | corrigé : `0 = absent` sur le fil, `Some(vec![])` refusé au **constructeur** seulement, jamais au décodage |
| 3 | **Ne pas muter l'état avant validation** | liste active **locale** pendant la validation, `autorites`/`changement_en_attente` commités seulement après succès complet |
| 4 | **Overflow `h + K`** | `checked_add(K)` → `ChangementHauteurOverflow` |
| 5 | **Bloc de reconfig VIDE** | un bloc portant `changement_autorites` ne porte **aucune transaction** (`ChangementAvecTransactions`) |
| 6 | **Certificat minimal** | **déjà fait** (J1-b2 T7, `votants.truncate(requis)`) |
| 7 | **Budget bloc avec la nouvelle liste** | `MAX_OCTETS_BLOC` compte la liste ; le point 5 la rend presque gratuite mais elle est bornée |
| 8 | **Liveness selon la taille** | table `n → quorum` dans les limites |
| 9 | **Invariants au chargement d'état** | `from_bytes` refuse liste vide / hors borne / doublons / effet `≤` hauteur |
| 10 | **Position exacte dans `corps_bytes`** | figée : après `autorites`, avant `extension` (réservée à l'économie) |

---

## Partie I — Le champ de bloc et l'activation

### Le champ, `VERSION_BLOC 0x05`

```rust
/// La NOUVELLE liste d'autorités, si ce bloc annonce une reconfiguration.
/// `None` pour un bloc ordinaire.
pub changement_autorites: Option<Vec<SigPublicKey>>,
```

Décisions condensées :

- **Seule la nouvelle liste est portée, pas la hauteur d'effet.** `effective =
  hauteur.checked_add(K)` (point 4 : refus `ChangementHauteurOverflow` si une
  hauteur proche de `u64::MAX` déborderait). Dérivée d'une constante : un
  producteur ne peut pas mentir sur *quand* le changement prend effet.
- **Le champ entre dans `corps_bytes`, donc dans l'identifiant** — condition de
  sûreté : le certificat de l'ancienne liste signe l'identifiant, donc **sur** la
  nouvelle liste. **Position figée (point 10) : après le bloc d'`autorites` de
  genèse, avant `extension`.** `extension` reste réservée à l'économie/coinbase —
  la reconfiguration ne s'y mêle pas.
- **Encodage `0 = absent` (point 2).** La longueur préfixée : `0` ⇒ pas de
  changement, `n > 0` ⇒ liste de `n` clés. Une liste **vide** n'existe donc PAS
  sur le fil (elle serait indistinguable d'un bloc ordinaire). Le refus de la
  liste vide est **au constructeur** (`Some(vec![])` → `ChangementListeVide`),
  jamais au décodage. Même discipline que `scellement` et `certificat`.
- **`Option`, jamais un drapeau + liste séparés** — deux formes distinctes,
  décodage sans ambiguïté.

### Validité STRUCTURELLE de la liste (points 1, 5)

Vérifiée au décodage du bloc (avant allocation lourde) et re-vérifiée au
constructeur :

- **taille `1..=MAX_AUTORITES`** — bornée avant allocation ;
- **aucun doublon** (`ChangementAutoriteDupliquee`) — sinon une clé à deux index
  compterait deux votes dans le masque de quorum. ⚠️ **La même règle manque à la
  genèse aujourd'hui** : `genese_avec_autorites` ne rejette pas les doublons.
  J1-c la corrige aux **deux** endroits ;
- **le bloc ne porte AUCUNE transaction** (`ChangementAvecTransactions`, point
  5). Un bloc de gouvernance vide simplifie l'audit, évite de mêler
  reconfiguration et coût STARK, et écarte le risque d'un changement rejeté après
  vérification lourde. Un bloc vide de reconfiguration tous les X blocs ne coûte
  rien à l'usage.

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

### Liste active LOCALE, commit après validation (point 3 de la revue)

⚠️ **Correction d'une erreur du premier jet.** Il disait « activation d'abord »,
au sens de muter `self.autorites` avant de valider. Or l'instantané d'atomicité de
`appliquer_bloc` clone `tree`, `recent_roots`, `roots_order` — **pas
`autorites`**. Muter `self.autorites` puis échouer en aval laisserait la liste
basculée par erreur.

La forme correcte n' touche pas `self` avant le succès :

1. **Calculer une liste active LOCALE** pour ce bloc :
   ```
   autorites_du_bloc =
       si changement_en_attente = Some((nouvelle, e)) et e == h  → nouvelle
       sinon                                                      → self.autorites
   ```
   Le bloc à `h+K` est ainsi jugé sous le nouveau régime — producteur de la
   nouvelle liste, certificat de la nouvelle liste — **sans rien avoir muté**.

2. **Valider tout le bloc** contre `autorites_du_bloc` : chaînage, producteur
   légitime, quorum (`⌊2n/3⌋+1` de la liste locale), puis, s'il porte un
   `changement_autorites`, sa validité structurelle (partie I) **et** le verrou
   « un seul en vol » (`ChangementDejaEnAttente` si `changement_en_attente` est
   déjà `Some`). Plus, le cas échéant, le STARK.

3. **COMMIT, seulement après succès complet.** Dans l'ordre :
   - si l'activation locale a eu lieu (`e == h`) : `self.autorites := nouvelle`,
     `changement_en_attente := None` ;
   - si le bloc annonce un changement : `changement_en_attente := (nouvelle,
     h + K)`.

Un bloc refusé ne mute donc **rien** — ni liste, ni changement en attente. Ces
deux champs n'ont pas besoin de rejoindre l'instantané de la frontier : ils ne
sont écrits qu'au tout dernier moment, quand plus rien ne peut échouer. C'est
l'atomicité rendue **plus simple**, pas plus compliquée.

⚠️ **Le cas back-to-back** (point vérifié en revue) : à `h+K`, le bloc peut à la
fois **activer** le changement précédent (étape 1 : `e == h`) **et** en annoncer
un nouveau (étape 3 : `changement_en_attente := (encore_nouvelle, h+K+K)`). Le
verrou « un seul en vol » de l'étape 2 est évalué **avant** le commit, donc contre
l'état d'*avant* activation — mais comme l'activation vide le pendant, il faut que
le verrou teste « le pendant survivra-t-il à ce bloc ». Règle précise : le bloc
peut annoncer un changement **si et seulement si** aucun changement ne restera en
attente après ce bloc, c'est-à-dire `changement_en_attente` est `None` **ou** est
activé par ce bloc (`e == h`). Un test dédié couvre ce back-to-back.

### Déterminisme

`producteur_attendu(h, vue)` et `quorum_requis()` lisent `self.autorites`, la
liste active de la hauteur courante. Tous les nœuds appliquent la même chaîne
finale et basculent **à la même hauteur** (hauteur d'effet, pas temps) : ils
calculent tous le même producteur et le même quorum. Le changement de vue traverse
le basculement sans cas particulier.

### Persistance et invariants au chargement (point 9)

`changement_en_attente` entre dans `to_bytes`/`from_bytes` de l'état (`0x05`). Un
nœud qui redémarre dans la fenêtre `[h+1, h+K)` retrouve son changement en attente
— sinon il raterait le basculement et divergerait. Un dump `0x04` est refusé par
son nom.

⚠️ **`from_bytes` ne fait pas confiance au fichier** (il peut être corrompu ou
forgé). Un `changement_en_attente` présent est refusé si :

- **liste vide** (invariant du constructeur, jamais un état légitime) ;
- **taille hors `[1, MAX_AUTORITES]`** ;
- **doublons** dans la liste ;
- **hauteur d'effet `≤` hauteur courante de l'état** — un changement déjà dépassé
  est incohérent (il aurait dû être activé), et l'accepter laisserait un
  basculement qui ne se produira jamais.

Variante : `EtatInvalide` avec la cause nommée.

### Budget de bloc avec la nouvelle liste (point 7)

Une liste de `MAX_AUTORITES = 64` clés hybrides pèse ~127 Kio. `MAX_OCTETS_BLOC`
doit la compter : `SURCOUT_BLOC_VIDE` + transactions + scellement + certificat +
**la nouvelle liste**. Le bloc de reconfiguration étant **vide de transactions**
(point 5), le budget se réduit à en-tête + liste + scellement + certificat —
toujours largement sous le cadre réseau, mais **borné explicitement** au
constructeur (`Bloc::sceller` refuse un bloc indiffusable) et re-vérifié au
décodage, même discipline que `MAX_TX_PAR_BLOC`.

---

## Partie III — Validité, sûreté, tests

### Variantes de refus (récapitulatif)

- `ChangementListeVide` — `Some(vec![])` **au constructeur** (jamais au décodage,
  `0` = absent sur le fil) ;
- `ChangementAutoriteDupliquee` — deux fois la même clé, en changement ET en
  genèse ;
- `ChangementAvecTransactions` — un bloc de reconfiguration porte des tx ;
- `ChangementDejaEnAttente` — un changement resterait en attente après ce bloc ;
- `ChangementSurChaineOuverte` — pas de comité à reconfigurer ;
- `ChangementHauteurOverflow` — `hauteur + K` déborderait `u64`.

Le bloc reste soumis à **tout** le reste : chaînage, producteur légitime de la
liste active (locale), certificat `2f+1` de cette liste, **avant** un éventuel
STARK. Le changement n'en court-circuite aucun ; il en ajoute.

### Liveness selon la taille du comité (point 8)

Le quorum est `⌊2n/3⌋+1`. Toutes les tailles ne tolèrent pas une absence :

| n | quorum | tolère `f` absent(s) |
|---|---|---|
| 1 | 1 | 0 |
| 2 | 2 | 0 |
| 3 | 3 | 0 |
| 4 | 3 | 1 |
| 7 | 5 | 2 |
| 10 | 7 | 3 |

⚠️ **J1-b2 ne « sauve » pas une nouvelle liste dont un membre est absent si `n ≤
3`** : le quorum vaut alors `n`, tous doivent voter, et le changement de vue ne
peut pas contourner une absence (il n'y a pas de marge). Un opérateur qui réduit
le comité à `n ≤ 3` accepte donc de perdre la tolérance aux fautes — à écrire
dans les limites.

### La limite à écrire, pas à cacher

Un changement est certifié par le quorum de l'**ancienne** liste : l'ancien comité
décide collectivement du nouveau, **y compris se réduire à `n=1`** ou se remplacer
entièrement. Ce n'est pas une faille nouvelle — un quorum d'anciens malveillants
contrôle déjà la chaîne — mais un participant doit savoir que sa place dépend du
quorum, pas d'un droit acquis. À écrire dans `docs/TESTNET.md`, avec la table de
liveness (point 8) : réduire à `n ≤ 3` sacrifie la tolérance aux fautes.

### Tests

- **Unité** : un bloc de changement enregistre l'attente ; un second changement
  pendant l'attente est refusé (`ChangementDejaEnAttente`) ; l'attente **bascule
  exactement à `h+K`** ; la nouvelle liste change `quorum_requis()` ; liste vide /
  doublon / hors borne / avec transactions / sur chaîne ouverte / overflow refusés
  par leur variante ; **doublon en genèse refusé** ; un dump d'état `0x04` refusé
  par son nom ; un `changement_en_attente` corrompu au chargement (vide, doublon,
  effet dépassé) refusé ; **le back-to-back** (un bloc à `h+K` active ET annonce)
  accepté ; l'atomicité — un bloc refusé à la hauteur d'effet ne laisse **ni**
  liste basculée **ni** changement enregistré (vérifié par mutation : forcer un
  échec en aval et constater que `autorites` n'a pas bougé).
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
