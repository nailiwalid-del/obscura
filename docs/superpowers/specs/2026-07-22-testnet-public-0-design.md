# Obscura Public Testnet 0 — plan de mise en réseau

**Date :** 2026-07-22
**Jalon :** `Obscura Public Testnet 0 — sans valeur, expérimental`
**Statut :** design validé sur les décisions structurantes ; **partie II** (T0+T1)
est le premier spec implémentable, le reste est feuille de route.

---

## Décisions prises (utilisateur, ne pas remettre en cause)

1. **Thèse : post-quantique assumé.** Obscura ne prétend pas battre Zcash sur la
   taille ni Monero sur l'adoption. Il prétend être la seule monnaie privée dont
   la confidentialité survit à une machine quantique. Tout le reste s'y plie.
2. **Scellement : autorité(s) gravée(s) en genèse.** Cas `n = 1` du spec
   `2026-07-21-election-producteur-design.md`, qui reste la référence.
3. **Émission : en-tête de bloc extensible maintenant, coinbase plus tard.** On
   décide le FORMAT sans décider la politique monétaire.
4. **Exploitation : dimensionnement différé.** Ce document expose le coût de
   chaque brique ; il ne choisit pas la taille de la flotte.
5. **Premier spec implémentable : T0 + T1.**

---

## Partie I — Le plan

### Pourquoi cette thèse, et pas une autre

| | Obscura (2/2) | Zcash Orchard | Monero |
|---|---|---|---|
| Taille d'une tx privée | ~68 Kio | ~9,2 Kio | ~2,5 Kio |
| Ensemble d'anonymat | tout l'arbre | pool *shielded* | 16 (leurres) |
| Confidentialité | obligatoire | optionnelle | obligatoire |
| Setup de confiance | jamais | retiré (Orchard) | jamais |
| Post-quantique | **oui** | non | non |
| Élection de producteur | aucune | PoW | PoW |
| Audité | non | oui | oui |

> Chiffres concurrents : ordre de grandeur, **à revérifier avant toute
> publication**. Ils suffisent à l'argument : l'écart de taille est de 7× à 27×
> et n'est pas rattrapable par de l'optimisation — c'est le prix des STARK.

Trois positions que ni Zcash ni Monero ne peuvent reprendre sans tout redessiner :

1. **Le post-quantique.** Les deux reposent sur le logarithme discret. Une
   machine quantique cryptographiquement pertinente rend Monero traçable
   **rétroactivement** — les transactions déjà publiées, pas seulement les
   futures. Leur réponse coûte « repartir de zéro ».
2. **L'absence de pool transparent.** Zcash ne peut pas supprimer le sien sans
   casser l'existant ; il rogne en permanence son ensemble d'anonymat réel.
3. **L'absence de leurres.** L'anonymat de Monero est 15 leurres par entrée, et
   il a été attaqué statistiquement à plusieurs reprises.

**Corollaire discipline :** aucun document public ne doit revendiquer un avantage
de taille, de maturité ou d'audit. La thèse est étroite et doit le rester.

### La contrainte d'ordre qui commande le calendrier

Trois choses gèlent un format et **ne sont pas rattrapables après l'ouverture** :

- **le KEM/la signature**, parce que `kem_pk` est dans `adresse` — changer le KEM
  change toutes les adresses, tous les fichiers de wallet, tous les `enc_note` ;
- **le format de bloc**, parce que la genèse est figée et diffusée ;
- **la place réservée à la coinbase et au collecteur de frais**, faute de quoi
  les ajouter coûtera un nouveau fork du testnet.

D'où : **T1 (FIPS) et T2 (autorité) → gel de la genèse → ouverture.** Rien de
public avant.

**T1 et T2 sont indépendants**, contrairement à une première lecture. Le champ
`scellement` du bloc v0x03 est borné en longueur (`TAILLE_SCELLEMENT_MAX =
4 + 4096`, déjà suffisant pour ML-DSA-65) et `HybridSignature::from_bytes`
refuse toute version d'algo qui n'est pas la sienne. Migrer FIPS après T2 ne
coûte donc **pas** un nouveau `VERSION_BLOC` : seulement la régénération de la
genèse — gratuite tant qu'elle n'est pas figée. La contrainte réelle est
**« FIPS avant le GEL de la genèse »**, pas « FIPS avant T2 ».

### Feuille de route

| # | Chantier | Gèle un format ? | Coût d'exploitation |
|---|---|---|---|
| **T0** | Pousser vers `origin`, CI stricte, fuzzing anneau 1 | non | CI gratuite (dépôt public) |
| **T1** | Migration FIPS 203/204 + zeroize PQ | **oui** | — |
| **T2** | Autorité de scellement (**en cours**) + en-tête extensible | **oui** | — |
| **T3** | Argument PQ écrit et quantifié | non | — |
| **T4** | Nœud exploitable : config, logs, métriques, Docker/systemd | non | — |
| **T5** | **Ouverture** : genèse figée, bootnodes, releases signées, docs | — | voir ci-dessous |
| **T6** | Faucet, explorateur, monitoring, status page, process incident | non | voir ci-dessous |
| **T7** | Wallet UX : phrase masquée, mnémonique, backup/restore, frais, Tor | non | — |

T4 est parallélisable avec T2–T3. T6 et T7 suivent l'ouverture.

### Coûts d'exploitation (pour décider plus tard, pas maintenant)

Le chiffre qui commande tout : **l'historique des sorties pèse ≈1,4 Kio/sortie,
≈1,4 Mio par bloc plein, ≈12 Gio/jour sous charge, et n'est jamais élagué.**

- **Bootnode sans `--archiver`** : petit VPS, disque quasi stable (l'état de
  consensus est une frontier, pas un historique). C'est le rôle bon marché, et
  celui qui sert l'anti-eclipse. **La majorité des bootnodes doivent être ceux-là.**
- **Nœud archiviste (`--archiver`)** : disque qui croît sans borne. Un ou deux
  suffisent, et ils sont la dépendance du faucet, de l'explorateur et de tout
  wallet qui se synchronise. **C'est le point de centralisation réel du réseau**,
  et il doit être nommé comme tel dans les limites connues.
- **Faucet** : un wallet pré-financé à la genèse + un point HTTP + un
  étranglement par IP. Aucun changement de consensus : `Bloc::genese_avec`
  suffit. Doit se synchroniser, donc dépend d'un archiviste.
- **Explorateur** : dépend d'un archiviste. À concevoir en sachant qu'il ne
  peut montrer que des commitments, des nullifiers et des digests — **tout
  affichage plus riche serait une fuite**, et c'est la contrainte de conception
  principale, pas un détail d'interface.

### Portes vers le mainnet (ce ne sont pas des tâches)

Ces éléments ne sont pas planifiables comme du développement. Ils conditionnent
le passage à une valeur réelle et rien d'autre.

- **Consensus public défendable** : élection ouverte, fork-choice ou modèle sans
  réorg défendu, gestion des partitions, anti-Sybil, procédure d'upgrade,
  négociation de version wire formelle. Aujourd'hui `Message::version_inconnue()`
  distingue déjà « version future » de « malformation » et ne sanctionne pas la
  première — suffisant pour ne pas partitionner un testnet, insuffisant pour un
  mainnet.
- **Modèle économique** : coinbase prouvée, destin des frais (aujourd'hui
  **brûlés** : `Σin = Σout + fee`, aucun collecteur), politique d'émission.
  Sans récompense de producteur, le budget de sécurité est nul.
- **Deux audits indépendants au moins**, dont un spécialisé circuit/AIR.
  Fuzzing massif, vecteurs de test officiels, spec figée, bug bounty.
- **Cadre légal** : FinCEN (US), qualification securities/commodities, MiCA (UE).
  Conseil juridique, pas de décision au feeling.

### Critères de sortie du jalon Testnet 0

- CI 100 % verte, y compris le job d'invariant de features.
- Genèse figée, publiée, identifiant comparé entre opérateurs.
- Bootnodes en marche, dont au moins un archiviste.
- Faucet fonctionnel.
- Releases signées, checksums, tag Git.
- Docs opérateur + wallet.
- Page « limitations connues » publiée **avant** l'ouverture.
- Aucune communication du type « monnaie utilisable » ou « sécurité garantie ».

---

## Partie II — Design détaillé : T0 + T1

### T0.1 — Assainir l'état du dépôt

État vérifié le 2026-07-22 : `HEAD = 1cdd985`. C2-T8, D8, le spec d'élection et
les threads d'écriture sont **commités** — il n'y a rien à « solder » de ce
côté. Deux faits, en revanche, doivent être traités avant toute CI :

1. **`master` est en avance de 10 commits sur `origin/master`.** Rien n'est
   poussé. Un jalon public commence par rendre le dépôt distant faisant
   autorité : sans cela, la CI ne s'exécute sur rien, aucune release n'est
   possible, et le travail n'existe que sur une machine.
2. **T2 est en cours dans l'arbre de travail** (`bloc.rs`, `proved_state.rs`,
   `orchestration.rs`, +647/−35) : `VERSION_BLOC 0x03`, `MAX_AUTORITES = 64`,
   `DOMAINE_SCELLEMENT`, `producteur_attendu(h) = autorites[(h−1) mod n]`.
   À terminer et commiter avant que la CI ait un sens.

**Ordre non négociable : aucune CI tant que l'arbre est sale.** Une CI qui
verdit sur un arbre partiel ne prouve rien, et c'est précisément le genre de
vert qui donne confiance à tort.

### T0.2 — Intégration continue

`.github/workflows/ci.yml`, sur push et *pull request* :

| Job | Contenu | Raison d'être |
|---|---|---|
| `fmt` | `cargo fmt --all --check` | — |
| `clippy` | `-D warnings`, **deux passes** : défaut puis `--all-features` | la passe *par défaut* garde l'invariant « build nu = surface consensus seule » |
| `test` | `--release`, puis `--release --all-features` | les preuves STARK sont gatées release |
| `msrv` | épingle 1.87 (déjà déclaré dans `Cargo.toml`) | — |
| `deny` | `cargo-deny` : avis RUSTSEC + licences | dépendances `pqcrypto` peu maintenues, et T1 en change |
| `invariant-features` | vérifie que le build par défaut ne tire aucun code gaté dev | **CLAUDE.md l'énonce comme invariant et rien ne le fait respecter** |

Matrice **ubuntu + windows**. Le développement se fait sous Windows et le code
de permissions `0600` est gaté Unix : une CI Linux seule laisserait pourrir la
moitié réellement utilisée, une CI Windows seule ne verrait jamais le code de
permissions. Cache via `Swatinem/rust-cache`.

`.github/workflows/lourd.yml`, planté la nuit : les deux tests profondeur 32,
les benches, et le budget de fuzzing. Trop lents pour une *pull request*.

### T0.3 — Fuzzing des décodeurs

Quinze `from_bytes` dans le dépôt, en deux anneaux. `cargo-fuzz` (libFuzzer),
corpus amorcé par les encodages valides des tests existants, budget de temps
dans `lourd.yml`, tout *crash* reversé en test de non-régression.

- **Anneau 1 — atteignables par un inconnu** (priorité absolue) :
  `Message::from_bytes`, `ProvedTx::from_bytes`, `Bloc::from_bytes`,
  `ReponseHistorique::from_bytes`.
- **Anneau 2 — disque** : `ProvedState`, `HistoriqueSorties`,
  `WalletFichier::from_bytes_secret`, `MerkleTree`/`Frontier`.

Propriétés vérifiées : **jamais de panique**, **jamais d'allocation au-delà de
la borne annoncée**, et `from_bytes(to_bytes(x)) == x` sur les entrées valides.

L'anneau 1 est écrit **avant** T1, parce que T1 réécrit les tailles que ces
décodeurs bornent : le fuzzing sert alors de filet pendant la migration.

### T1 — Migration FIPS 203/204 (version d'algo `0x02`)

`KEM_ALGO_ID = "x25519+kyber768-round3"` et `SIG_ALGO_ID =
"ed25519+dilithium3-round3"` sont les **paramètres round-3**, pas ML-KEM/ML-DSA.
Sous la thèse post-quantique, ouvrir un réseau public là-dessus est
l'incohérence la plus visible possible.

Cibles : `pqcrypto-mlkem` (0.1.1) et `pqcrypto-mldsa` (0.1.2), même lignée
PQClean que les crates actuelles. **Risque à surveiller : versions 0.1.x,
API jeune.** Épingler des versions exactes.

#### T1.1 — Refus par leur nom, pas cohabitation

`KEM_ALGO_VERSION` et `SIG_ALGO_VERSION` passent à `0x02`. Un objet `0x01`
est **reconnu et refusé par une variante d'erreur qui le nomme** — jamais
réinterprété, jamais accepté. Aucune cohabitation en écriture ni en lecture.

Raison : aucun réseau public n'existe encore, donc il n'y a rien à migrer sauf
des fichiers locaux, qui se recréent. Supporter deux versions coûterait une
surface d'attaque de confusion de version pour zéro utilisateur. La discipline
du projet est déjà celle-là (« un `0x01` est refusé par sa propre variante »).

#### T1.2 — Ce que la séparation de domaine protège déjà

`combine()` intègre `KEM_ALGO_VERSION` dans la dérivation, et `sign()` préfixe
`SIG_ALGO_ID` par sa longueur dans le message signé. **Changer les identifiants
change donc automatiquement toutes les clés dérivées et tous les domaines de
signature** : une confusion inter-version est structurellement impossible. C'est
un acquis du design, à ne pas défaire pendant la migration.

À vérifier explicitement : qu'aucun test ne fige en dur ces identifiants.

#### T1.3 — Les tailles changent, et elles sont câblées ailleurs

ML-DSA-65 ne produit pas des signatures de la même taille que Dilithium3
round-3. Or des tailles sont dérivées, bornées ou assertées à la compilation
dans tout le dépôt :

- `MAX_SORTIES_PAR_REPONSE` (739) est **calculé** sur
  `MAX_CADRE − crypto::aead::SURCOUT − en-tête` ;
- `MAX_OCTETS_BLOC` soustrait le surcoût AEAD ;
- `RECENT_ROOTS_WINDOW` porte une assertion de compilation ;
- `combine()` contient une capacité en dur (`1184`) ;
- les bornes anti-DoS d'`EncNote` et de `ProvedTx`.

**Règle de la migration : toute taille en dur est remplacée par la constante de
la crate, et toutes les assertions de compilation sont re-dérivées.** C'est
exactement ce que la CI de T0 attrape — d'où l'ordre T0 avant T1.

#### T1.4 — L'adresse

`adresse` = `obs1‖hex(version‖owner‖kem_pk‖somme)`. Le byte `version` de
l'adresse passe lui aussi à `0x02`, pour qu'une adresse d'ancienne version soit
refusée par son nom plutôt que mal découpée. La somme de contrôle est
recalculée sur le nouveau domaine.

Rappel de son périmètre, inchangé : elle détecte **l'accident, pas
l'adversaire**.

#### T1.5 — Zeroize des clés PQ

Les `SecretKey` pqcrypto ne s'effacent pas aujourd'hui (limitation de crate).
Sous la thèse post-quantique, ce n'est plus une dette : c'est une contradiction.

**À vérifier pendant l'implémentation, pas à supposer** : `pqcrypto-mlkem` et
`pqcrypto-mldsa` exposent-elles des secrets effaçables ? Si non, repli nommé :
stocker les secrets en `Zeroizing<Vec<u8>>` et reconstruire le type de la crate
à chaque usage (coût : un décodage par opération, mesurable et acceptable hors
chemin chaud). Le repli est un choix explicite, pas un abandon silencieux.

#### T1.6 — Vecteurs de test

Vecteurs KAT/ACVP officiels ML-KEM-768 et ML-DSA-65, en test. C'est ce qui
distingue « on a changé d'import » de « on implémente bien FIPS 203/204 », et
c'est la première chose qu'un auditeur demandera.

### Tests de sortie de T0 + T1

- CI verte sur les six jobs, sur les deux plateformes.
- Les quatre cibles de fuzz de l'anneau 1 tournent sans crash sur le budget nocturne.
- Vecteurs KAT ML-KEM-768 et ML-DSA-65 passent.
- Un objet d'algo `0x01` (clé, adresse, `enc_note`) est refusé par une variante
  d'erreur **qui le nomme**.
- Aucune taille de PQ en dur ne subsiste (revue + assertions de compilation).
- Cycle complet payer → sceller → recevoir → redépenser sur sockets réelles,
  inchangé (`crates/node/tests/cycle_wallet.rs`), en ML-KEM/ML-DSA.
- Secrets PQ effacés au drop, ou repli documenté et testé.

---

## T2 — en cours d'implémentation, pas à spécifier

`2026-07-21-election-producteur-design.md` est le spec, et le code en vol le
suit : autorités en genèse (`MAX_AUTORITES = 64`), tour de rôle
`autorites[(h−1) mod n]`, signature hybride sur l'`id` du bloc
(`DOMAINE_SCELLEMENT`), contrôle avant tout coût STARK, `VERSION_BLOC 0x03`.
La décision « autorité gravée en genèse » en est le cas `n = 1` ;
`producteur_attendu` rend `None` sur une liste vide, ce qui **préserve le
comportement ouvert actuel** — la migration est donc non destructive.

Ce qui reste à porter :

1. **En-tête extensible** : réserver dès `VERSION_BLOC 0x03` la place d'une
   coinbase prouvée et d'un collecteur de frais, pour que les ajouter plus tard
   ne soit pas un nouveau fork du testnet. **C'est maintenant ou jamais** — le
   format est en train d'être écrit.
2. **Liveness** : le code implémente l'**option A** (aucun certificat de saut).
   Avec `n = 1`, cela signifie explicitement : **si le nœud scelleur tombe, le
   testnet s'arrête jusqu'à son retour.** Les transactions s'accumulent en
   mempool, rien n'est perdu. Prix visible et honnête pour un testnet sans
   valeur — à condition qu'il figure dans les limites connues.
3. **Rien à faire côté ML-DSA** : le champ est borné et étiqueté par version,
   la migration FIPS le traversera sans changer le format de bloc.

## Limites connues à publier avant l'ouverture

- Prototype **non audité**. Fonds sans aucune valeur.
- **Fédéré, pas décentralisé** : la liste des autorités est statique ; en
  changer = nouvelle genèse = nouvelle chaîne.
- **Aucune réorganisation possible** : toute divergence est définitive.
- **Aucune résistance à la censure du producteur** : le tri par `tx_digest` est
  une convention de reproductibilité, pas une défense.
- **Le nœud servant l'historique apprend IP, cadence et position** du wallet, et
  **peut mentir par omission** — la racine annoncée reste cohérente. Une seule
  source de synchronisation est un point de confiance.
- **L'archiviste est le point de centralisation réel** du réseau.
- **La forme m/n d'une transaction est publique.**
- L'arbre du wallet est en O(n) ; pas de client léger.
- L'argument HVZK est **honnête-vérifieur** et non audité.
- Pas de Tor/I2P intégré au lancement.
