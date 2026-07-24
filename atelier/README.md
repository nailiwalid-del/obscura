# Atelier local Obscura — de la création d'un wallet au paiement prouvé

Un atelier **pratique** : on monte une petite chaîne Obscura sur sa propre machine
et on la manipule en vrai — deux wallets, une genèse, deux nœuds, un paiement avec
preuve STARK, corroboré par un témoin. En six étapes, ~2 minutes une fois le
projet compilé.

> ⚠️ **Prototype non audité, chaîne sans valeur.** Les wallets de cet atelier sont
> écrits **en clair** (jetables). Rien de tout cela ne doit servir à détenir quoi
> que ce soit. Voir *Sécurité* en fin de document.

C'est le pendant **au terminal** de l'atelier conceptuel
[`docs/obscura-atelier.html`](../docs/obscura-atelier.html) (« comprendre en
manipulant ») : ici on ne regarde pas des animations, on lance les vraies
commandes.

---

## Ce que l'atelier démontre

| Propriété | Où on la voit |
|---|---|
| La monnaie n'existe que par la **genèse** | étape 2 : allocation gravée dans le bloc 0 |
| Un wallet **reçoit par scan**, pas par crédit hors bande | étape 4 : Alice découvre son allocation |
| Le **témoin** défend contre l'omission | étapes 4/6 : « chaque bloc corroboré par le témoin » |
| Un paiement est une **preuve**, pas un aveu | étape 5 : preuve STARK ~1 s, forme 1-in/2-out |
| La **monnaie rendue** revient par la synchro | étape 6 : Alice repasse à 999 700 |
| La **masse se conserve** sous montants cachés | bilan : 999 700 + 300 = 1 000 000 |

---

## Prérequis

- **Rust** (édition stable) et `cargo`.
- **Windows + PowerShell** pour les scripts `.ps1`. Sous Linux/macOS, voir
  *Autres plateformes* plus bas — les commandes brutes y sont listées.
- La première exécution **compile en `--release`** (la preuve STARK est gatée en
  release) : plusieurs minutes, une seule fois. Les scripts s'en chargent
  (`Assurer-Build`), ou faites-le à la main :

  ```
  cargo build --release
  ```

---

## Démarrage rapide

Tout enchaîner :

```
.\atelier\00-tout.ps1
```

À la fin, les deux nœuds tournent encore. Pour tout arrêter et nettoyer :

```
.\atelier\99-reset.ps1
```

---

## Les six étapes (pas à pas)

Chaque script est **autonome et relançable**. On peut les jouer un par un pour
lire chaque sortie, ou tout enchaîner avec `00-tout.ps1`.

### 1 · Deux wallets — `01-wallets.ps1`

Crée `alice.wallet` (le payeur) et `bob.wallet` (le bénéficiaire), et imprime les
deux adresses `obs1…` à communiquer hors chaîne.

```
Alice : obs1024e380020ea1c23c…   (≈1,4 Kio d'adresse : owner prouvé + clé de réception PQ)
Bob   : obs10200aff0161d0257f…
```

### 2 · Genèse — `02-genese.ps1`

Fabrique le bloc 0 : **1 000 000 unités allouées à Alice**, chaîne **ouverte**
(aucune autorité — testnet local). L'identifiant est l'identité de la chaîne :
deux nœuds sur des genèses différentes se refusent tous leurs blocs.

```
identifiant : 1164ed803ba6f7fa…   (128 hex — à comparer entre opérateurs)
allocations : 1
racine      : 5c5131a8aef8136d…
```

### 3 · Deux nœuds — `03-noeuds.ps1`

- **A** (`127.0.0.1:9333`) : `--archiver --sceller 3000` — le producteur.
- **B** (`127.0.0.1:9334`) : `--archiver --pair A` — l'archiviste **témoin**,
  relié à A ; il recevra les blocs scellés par diffusion.

Le script vérifie que **les deux affichent le même identifiant de genèse**. Un
nœud ne scelle **pas** de bloc vide : la hauteur reste 0 jusqu'au paiement.

> Les nœuds tournent en arrière-plan, journaux dans `travail\A.err.log` /
> `travail\B.err.log`, PID mémorisés pour `99-reset`.

### 4 · Alice synchronise, corroborée par le témoin — `04-synchroniser.ps1`

Alice rejoue l'historique servi par A, et `--temoin B` redemande chaque hauteur à
B pour comparer la racine. Alice **découvre son allocation par scan** :

```
corroboration auprès du témoin 127.0.0.1:9334
  bloc 0 : 1 sorties, 1 pour vous — solde 1000000
à jour — chaque bloc corroboré par le témoin.
```

Sans `--temoin`, la sortie dirait « à jour **SELON CE NŒUD** » : A pourrait taire
un paiement en servant un historique parfaitement cohérent.

### 5 · Alice paie 300 à Bob, avec une preuve — `05-payer.ps1`

- `--noeud A` soumet la transaction ; `--noeud-synchro B` fait la synchro préalable
  via un nœud **différent** (ne pas révéler à A « je me synchronise puis j'émets »).
- `--frais 0` : seul 0 est accepté (le champ `fee` est public et brûlé).

```
preuve générée en 0.7 s (87.6 Kio) — forme 1-in/2-out
transaction soumise à 127.0.0.1:9333
1 notes retirées de la réserve — solde connu : 0
```

Le solde local tombe à **0** : la **monnaie rendue** (999 700) est partie chiffrée
vers Alice, mais son index dans l'arbre n'existera qu'une fois le bloc scellé. A
scelle le **bloc 1** sous 3 s et le diffuse à B.

### 6 · Resynchronisation — `06-resync.ps1`

Alice et Bob rejouent le bloc 1 :

```
Alice — bloc 1 : 2 sorties, 1 pour vous — solde 999700   (la monnaie rendue REVIENT)
Bob   — bloc 1 : 2 sorties, 1 pour vous — solde 300      (le paiement APPARAÎT)
```

**Bilan : 999 700 + 300 = 1 000 000.** La masse se conserve, sous des montants qui
restent cachés sur la chaîne. Cycle payer → recevoir bouclé.

---

## Deux détails à connaître

### « désaccords 1 » sur le nœud A — bénin

Après le premier bloc, la ligne de statut de A passe en **AVERT** avec
`désaccords 1`, alors que B reste à `désaccords 0`. Ce **n'est pas** une
divergence : A a scellé le bloc 1, B l'a appliqué **puis relayé à A**, qui le
reçoit en **doublon** et ne peut pas le rechaîner (il est déjà à cette hauteur).
Le compteur l'enregistre (branche « ni faute ni relais » de
[`orchestration.rs`](../crates/node/src/orchestration.rs)), ce qui suffit à teinter
le statut. La preuve que c'est inoffensif : **la corroboration témoin réussit à
chaque bloc** — A et B servent exactement les mêmes racines, et tous deux sont à la
même hauteur.

### Le bug Windows qui a motivé cet atelier

En montant ce flux, `synchroniser` échouait d'abord : `handshake post-quantique
échoué : ConnectionAborted`, côté nœud `WouldBlock`. Cause : sous Windows, une
socket issue de `accept()` **hérite** du mode non-bloquant de son listener ;
`obscura-node` met son listener en non-bloquant, mais ne remettait pas la socket
acceptée en bloquant avant le handshake (qui fait des lectures bloquantes).
Invisible sous Linux. Corrigé dans `Runtime::poser_echeances`
([`runtime.rs`](../crates/node/src/runtime.rs)) : la socket est remise en bloquant
avant tout handshake. Un test documentait déjà le contournement — mais le binaire
de production, lui, ne l'appliquait pas.

---

## Autres plateformes (Linux / macOS)

Pas de scripts `.sh` fournis (atelier « petit »), mais les commandes brutes sont
les mêmes. Depuis la racine du dépôt, avec `export
OBSCURA_WALLET_SANS_CHIFFREMENT=1` et les binaires dans `target/release/` :

```
# 1. wallets
obscura-wallet creer   --fichier alice.wallet
obscura-wallet creer   --fichier bob.wallet
ALICE=$(obscura-wallet adresse --fichier alice.wallet)
BOB=$(obscura-wallet adresse --fichier bob.wallet)

# 2. genèse
obscura-genese --sortie genese.bin --allocation "$ALICE:1000000"

# 3. deux nœuds (dans deux terminaux)
obscura-node --ecoute 127.0.0.1:9333 --genese genese.bin --archiver --sceller 3000 --donnees donnees-A
obscura-node --ecoute 127.0.0.1:9334 --genese genese.bin --archiver --pair 127.0.0.1:9333 --donnees donnees-B

# 4. Alice synchronise (avec témoin)
obscura-wallet synchroniser --fichier alice.wallet --noeud 127.0.0.1:9333 --temoin 127.0.0.1:9334

# 5. Alice paie Bob
obscura-wallet envoyer --fichier alice.wallet --a "$BOB" --montant 300 --frais 0 \
    --noeud 127.0.0.1:9333 --noeud-synchro 127.0.0.1:9334

# 6. resync (après ~3 s de scellement)
obscura-wallet synchroniser --fichier alice.wallet --noeud 127.0.0.1:9333 --temoin 127.0.0.1:9334
obscura-wallet synchroniser --fichier bob.wallet   --noeud 127.0.0.1:9333 --temoin 127.0.0.1:9334
```

Sous Linux, le bug de handshake ci-dessus ne se manifeste pas (les sockets
acceptées n'héritent pas de `O_NONBLOCK`).

---

## Sécurité (ne pas sauter)

- **Wallets en clair.** Les scripts posent `OBSCURA_WALLET_SANS_CHIFFREMENT=1` :
  l'autorité de dépense est sur le disque **non chiffrée**. Acceptable pour un
  atelier jetable, **jamais** pour un vrai wallet. En vrai : `OBSCURA_WALLET_PHRASE`
  (une phrase de passe), et cette phrase ne doit jamais transiter par un tiers.
- **Chaîne sans valeur, consommable.** C'est le fonctionnement prévu
  ([`docs/TESTNET.md`](../docs/TESTNET.md)).
- **`travail/` est gitignoré.** Wallets, genèse, données de nœuds et journaux n'y
  entrent pas dans le dépôt — et se recréent d'un `00-tout`.
- **Un seul témoin ici**, sur la même machine : pédagogique. La valeur réelle de
  `--temoin` suppose un second opérateur **indépendant**
  ([`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md)).

---

## Fichiers

| Script | Rôle |
|---|---|
| `00-tout.ps1` | enchaîne les 6 étapes |
| `01-wallets.ps1` | crée alice.wallet + bob.wallet |
| `02-genese.ps1` | genèse allouant à Alice |
| `03-noeuds.ps1` | démarre A (scelle+archive) et B (témoin) |
| `04-synchroniser.ps1` | Alice synchronise, corroborée par B |
| `05-payer.ps1` | Alice paie Bob (preuve STARK) |
| `06-resync.ps1` | monnaie rendue + paiement reçu |
| `99-reset.ps1` | arrête les nœuds, efface `travail/` |
| `lib.ps1` | fonctions partagées (chemins, nœuds, attente) |
