# Obscura — monnaie numérique privée post-quantique (prototype, v0.2)

Prototype d'une cryptomonnaie à confidentialité totale, construit sur le principe de
**défense en profondeur** : chaque fonction de sécurité combine deux primitives de
familles mathématiques indépendantes — la sécurité tient si AU MOINS UNE tient.

| Fonction | Primitive 1 | Primitive 2 |
|---|---|---|
| Échange de clés | X25519 (courbes elliptiques) | ML-KEM-768 / FIPS 203 (réseaux euclidiens) |
| Signatures | Ed25519 | ML-DSA-65 / FIPS 204 (les DEUX exigées) |
| Chiffrement | AES-256-GCM | XChaCha20-Poly1305 (cascade) |
| Hachage | BLAKE3 | SHA3-256 (concaténés, jamais tronqués) |

Les algorithmes portent une **version explicite** sur le fil : `0x02` = FIPS, seule
version courante. Le round-3 pré-FIPS (`0x01`) est refusé **par son nom** — les deux
n'ont jamais cohabité, parce qu'une négociation de version est une surface d'attaque
là où un refus n'en est pas une. Détail : [docs/POST_QUANTIQUE.md](docs/POST_QUANTIQUE.md).

## Ce que ce dépôt est, et ce qu'il n'est pas

C'est un **prototype pédagogique, sans audit de sécurité**. Le code est complet et
testé de bout en bout — on peut geler une chaîne, lancer des nœuds, payer, sceller,
recevoir — mais rien ici n'a été soumis à un cryptanalyste. **Ne lui confiez aucune
valeur réelle.**

Ce qu'il démontre : qu'une chaîne à confidentialité totale (montants, expéditeurs et
destinataires jamais publiés) peut tenir sur des primitives post-quantiques, avec un
circuit STARK qui n'est pas *une option* mais **la définition même du consensus**.

## Démarrage rapide

```sh
cargo build --release

# 1. Chaque futur scelleur publie la clé publique de SON nœud. Personne ne
#    transmet son fichier d'identité — il contient le secret.
./target/release/obscura-node --identite --donnees noeud-a   # → 3970 caractères hex

# 2. Geler la chaîne, en gravant les clés reçues. SANS --autorite, elle est
#    OUVERTE (voir « Limites » ci-dessous). L'identifiant imprimé est à COMPARER
#    entre opérateurs avant tout démarrage.
./target/release/obscura-genese --sortie genese.bin \
    --autorite-hex 02a1b2… --autorite-hex 02c3d4… \
    --allocation obs1abc…:1000

# 3. Lancer un nœud. --archiver est un rôle d'OPÉRATEUR, off par défaut :
#    sans archiviste sur le réseau, aucun wallet ne peut s'amorcer.
./target/release/obscura-node --genese genese.bin --donnees noeud-a \
    --ecoute 0.0.0.0:9977 --pair 203.0.113.4:9977 --archiver --sceller 5000

# 4. Un wallet.
./target/release/obscura-wallet creer --fichier moi.wallet
./target/release/obscura-wallet adresse --fichier moi.wallet
./target/release/obscura-wallet synchroniser --fichier moi.wallet --noeud 127.0.0.1:9977
./target/release/obscura-wallet envoyer --fichier moi.wallet --a obs1xyz… --montant 42 \
    --noeud 127.0.0.1:9977 --noeud-synchro 198.51.100.7:9977
```

Au démarrage, le nœud dit s'il est autorité et à quel rang — le découvrir au premier
tour de scellement manqué serait un silence inexplicable :

```
INFO   genèse b3200f256397c399 (0 émissions) — tête courante b3200f256397c399
INFO   chaîne à 2 autorités — cette identité est l'autorité n° 0
INFO   élection par tour de rôle : ce nœud ne scelle qu'à son tour
```

Deux options méritent d'être comprises avant d'être tapées :

- **`--sceller <ms>` est OFF par défaut.** Produire des blocs est une décision
  d'opérateur, pas un défaut. Sur une chaîne à autorités, un nœud qui n'en est pas une
  refuse de sceller et le dit.
- **`--noeud-synchro` doit être DIFFÉRENT de `--noeud`.** Se synchroniser puis payer
  depuis la même adresse relie les deux et désigne l'émetteur : un relais Dandelion++
  ne vient jamais de se synchroniser. Le CLI avertit quand ils coïncident.

Exploitation en conditions réelles (journalisation, unité systemd, image Docker
non-root) : [docs/OPERATEUR.md](docs/OPERATEUR.md).

## Structure

- [docs/STARK_STATEMENT.md](docs/STARK_STATEMENT.md) — **le statement de preuve = la règle de consensus** (P1–P7)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — adversaires, garanties, périmètre
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — spécification v0.2 (notes, nullifiers, transactions, versioning)
- [docs/POST_QUANTIQUE.md](docs/POST_QUANTIQUE.md) — ce que « post-quantique » veut dire ici, et ce que ça ne dit pas
- [docs/BACKEND_PQ.md](docs/BACKEND_PQ.md) — la dette de backend PQ, son évaluation et ses critères de sortie
- [docs/OPERATEUR.md](docs/OPERATEUR.md) — faire tourner un nœud
- `crates/crypto` — primitives hybrides : `hash`, `kem`, `sig`, `aead`
- `crates/circuit` — le circuit STARK monolithe, `m`-in/`n`-out (`1..=4`)
- `crates/ledger` — notes engagées, arbre de Merkle, nullifiers, blocs, historique
- `crates/net` — transport chiffré PQ, pairs anti-eclipse, Dandelion++
- `crates/wallet` — détention de notes, scan, construction de transactions
- `crates/node` — le câblage : protocole applicatif, runtime, quatre binaires

## Modèle de confidentialité (à la Zerocash)

On-chain, il n'y a QUE des commitments (64 o) et des nullifiers (32 o).
Montants, expéditeurs, destinataires : jamais publiés. Le destinataire retrouve
ses notes en scannant le ledger avec sa clé de réception (KEM hybride + AEAD cascade).

## Build & tests

```
cargo test --release                  # SURFACE CONSENSUS seule : monolithe, ProvedTx, ledger prouvé
cargo test --release --all-features   # + mode transparent (dev) et sous-circuits standalone
```

Par défaut, seule la **surface consensus** est compilée. Les chemins de développement sont
derrière des features **désactivées par défaut** — pour ne pas les confondre avec le
consensus : `dev-transparent` (ledger transparent, non-privé) et `dev-circuits`
(sous-circuits autonomes `prove_*`/`verify_*`). Les preuves STARK sont gatées `--release`.

La CI vérifie format, clippy (deux passes), tests, MSRV et avis de sécurité à chaque
PR ; le fuzzing des neuf décodeurs, la vérification Windows et les mesures de preuve à
la profondeur de consensus tournent une fois par semaine (`.github/workflows/lourd.yml`).

## Feuille de route (v0.2 : le STARK est le centre, pas une option)

1. ✅ Primitives crypto hybrides (versioning d'algorithmes, migration FIPS 203/204)
2. ✅ Ledger **transparent de dev** (explicitement non-privé, fonctions `_transparent`)
3. ✅ **Circuit STARK = définition du consensus** (P1–P7 monolithe, Rescue-Prime des
   commitments/Merkle, spend_pk/path retirés, witness-hiding, **forme variable
   M-in/N-out ≤ 4 — 3z-c2 soldée**)
4. ✅ Réseau P2P chiffré PQ + Dandelion++ + test de key privacy
5. ✅ Nœud, wallet CLI, testnet local multi-nœuds
6. ✅ **Finalité** : bloc + application atomique + convergence entre nœuds ;
   synchronisation wallet ↔ nœud (le wallet REÇOIT) ; **élection du producteur**
7. ⬜ Ouverture d'une chaîne publique : gel de genèse, points de contrôle hors bande

> Phase 3 : intégrité prouvée (P1–P7, monolithe **m-in/n-out**, `1..=4`) ; depuis 3z-b1
> la preuve de consensus est **witness-hiding (HVZK dans le modèle de l'oracle
> aléatoire)** — caveat : honnête-vérifieur, prototype non audité
> (docs/STARK_STATEMENT.md, « Argument HVZK »). `ProvedTx` **v4** porte les `enc_notes`
> (scan wallet, liés au digest, comptes m/n préfixés). Un wallet à note UNIQUE peut
> payer, `consolider` regroupe les notes ; la forme est publique (2/2 par défaut, cf.
> docs/THREAT_MODEL).

> Phases 4–5 : transport PQ 3 passes (forward secrecy, identités masquées), pairs
> anti-eclipse, mempool ordonné par coût, Dandelion++, nœud réel et testnet local.
> Quatre binaires : `obscura-genese`, `obscura-node`, `obscura-wallet`, `obscura-demo`.

## Limites connues

Le cycle complet est exercé de bout en bout sur de vraies sockets : une transaction
prouvée se propage, entre dans un bloc, s'applique atomiquement, et le wallet du
bénéficiaire la découvre en rejouant l'historique — monnaie rendue comprise
(`crates/node/tests/cycle_wallet.rs`).

Ce qui reste ouvert, en détail dans [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) :

1. **L'autorité de sceller est FÉDÉRÉE, pas décentralisée.** La genèse peut graver une
   liste d'autorités (≤ 64) ; le producteur légitime de la hauteur `h` est
   `autorites[(h−1) mod n]`, et son bloc est signé. Un scellement manquant, hors tour ou
   étranger est sanctionné. Mais cette liste est **figée dans l'identifiant de la
   chaîne** — en changer, c'est changer de chaîne — et une autorité absente **fige la
   chaîne à son tour** (liveness assumée, option A). Une genèse SANS autorités donne une
   chaîne OUVERTE : l'ordre y est *convenu* entre participants coopératifs, jamais
   *défendu*. C'est le défaut, et c'est bon pour un testnet local, pas pour un réseau
   public.
2. **Le nœud qui sert l'historique en apprend long, et l'omission demande maintenant
   une COLLUSION.** Il voit l'IP du wallet, la CADENCE de ses demandes et sa POSITION
   de chaîne. Taire une sortie donnait une chaîne parfaitement close dont la racine est
   celle qu'il annonce — le paiement omis restait invisible, et aucun contrôle *local*
   ne pouvait le démentir. `obscura-wallet synchroniser --temoin <ip:port>` interroge un
   **second nœud** sur la même hauteur et compare sa racine de fin de bloc : un
   désaccord arrête tout **avant** application. Le témoin ferme aussi le mensonge
   inverse — se taire plus tôt que la vraie tête, indistinguable d'une chaîne épuisée :
   la même question lui est reposée quand le nœud servant se tait. Trois limites : le témoin n'a de valeur
   que choisi indépendamment (deux nœuds d'un même opérateur n'en valent qu'un, et le
   protocole ne peut pas le vérifier) ; un désaccord ne dit pas *lequel* des deux ment ;
   l'option est **off par défaut**, et sans elle le CLI dit « à jour **selon ce nœud** »
   plutôt que « à jour ». Servir l'historique
   est en outre un rôle d'ARCHIVISTE coûteux et optionnel (`obscura-node --archiver`,
   ≈1,4 Kio/sortie, jamais élagué) : un nœud qui ne l'active pas est valide mais ne peut
   pas amorcer de wallet.
3. **La monnaie ne naît que dans la GENÈSE**, et il n'y a pas de coinbase. La règle de
   consensus est `hauteur > 0 ⇒ aucune émission` : c'est ce qui empêche l'inflation
   d'être *diffusée et acceptée*. Une chaîne s'amorce donc sur un bloc 0 paramétré
   (`obscura-genese`, puis `obscura-node --genese <fichier>`, échec franc s'il manque) et
   sa monnaie initiale est fixée une fois pour toutes. Une récompense de producteur
   supposerait d'abord une règle qui BORNE le montant émis — or ce montant est ce que le
   chiffrement cache.
4. **La soundness annoncée est de 78 bits, en régime PROUVÉ.** Le vérifieur exige
   `MinProvenSecurity(78)` et non une borne conjecturée : la conjecture donnerait un
   chiffre plus flatteur pour la même preuve. 78 bits est un niveau de PROTOTYPE — il
   faudrait le relever avant tout usage sérieux, au prix de preuves plus grosses.
5. **La dette de backend PQ est ouverte et assumée.** Toute la famille `pqcrypto` est
   marquée *unmaintained* (PQClean est archivé en amont), y compris les crates FIPS.
   L'évaluation des alternatives conclut à **ne pas migrer maintenant** : aucune n'est
   meilleure que le statu quo, et « non maintenu » n'est pas « vulnérable ». Les critères
   de déclenchement sont écrits dans [docs/BACKEND_PQ.md](docs/BACKEND_PQ.md), à relire
   avant tout gel de genèse publique.

Et une conséquence structurelle à connaître : **aucune réorganisation n'est
possible**. L'état est append-only de bout en bout ; supporter les réorganisations
exigerait de redessiner le ledger, pas d'ajouter une fonction.

**Prototype pédagogique — pas d'audit de sécurité, ne pas utiliser en production.**

## Licence

Double licence, au choix de l'utilisateur :

- MIT ([LICENSE-MIT](LICENSE-MIT))
- Apache-2.0 ([LICENSE-APACHE](LICENSE-APACHE))

C'est le double standard de l'écosystème Rust : le MIT est le plus permissif, et
l'Apache-2.0 ajoute une **concession de brevets** explicite que le MIT n'a pas —
utile pour un projet cryptographique, où le risque de brevet n'est pas théorique.

Sauf mention contraire, toute contribution soumise à ce dépôt sera double-licenciée
de la même façon, sans condition supplémentaire.
