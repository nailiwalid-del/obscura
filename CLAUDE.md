# Obscura — contexte projet pour Claude Code

Monnaie numérique privée post-quantique. Prototype Rust — les phases 1 à 5 sont
prototypées et testées : nœud fonctionnel, testnet local validé (sans persistance).

## Principe directeur (décision utilisateur, ne pas remettre en cause)

Défense en profondeur : chaque fonction de sécurité combine 2 primitives de familles
mathématiques indépendantes (la sécurité tient si l'une des deux tient).
KEM = X25519+Kyber768 · Sig = Ed25519 ET Dilithium3 · AEAD = cascade XChaCha20∘AES-GCM ·
Hash = BLAKE3‖SHA3-256 jamais tronqué. Séparation de domaine partout ("obscura/<usage>/v1").

## État

- `crates/crypto` : hash, kem, sig, aead — testés
- `crates/net` : **transport chiffré PQ** (phase 4, brique 1/4) — handshake hybride
  3 passes avec **forward secrecy** (éphémères jetés) et **masquage d'identité**
  (identités chiffrées sur le fil), machine à états en typestate, canal anti-rejeu
  par compteur de séquence en AAD, **cadrage sur le fil** (longueur préfixée, borne
  anti-DoS vérifiée AVANT allocation) et `Connexion` générique sur `Read + Write`
  (testée sur tuyau mémoire, prête pour TcpStream). Réutilise kem/sig/aead sans
  primitive nouvelle. Cadrage SYNCHRONE délibéré : il fixe le FORMAT DE FIL, pas la
  stratégie d'E/S — un runtime async plus tard ne changera pas un octet sur le fil.
  **Pairs** (brique 2) : sélection sortante par groupes réseau DISTINCTS (IPv4 /16,
  IPv6 /32) — anti-ECLIPSE, car un adversaire qui éclipse un nœud neutralise
  entièrement Dandelion++. **Dandelion++** (brique 4) : successeur stable par
  ÉPOQUE (la correction qui distingue ++ de v1 — un successeur par transaction
  laissait apprendre la topologie), décision stem/fluff par HACHAGE de
  (époque, tx, secret) pour résister au sondage, embargo contre le black-holing.
  ⚠️ L'anonymat de Dandelion++ REPOSE sur la diversité des pairs (brique 2).
  ⚠️ L'identité du RÉPONDEUR reste révélée à un MitM actif (inhérent au rôle ;
  fermable par un motif Noise-IK pour les sorties) — cf. spec transport-pq.
- `crates/ledger` : notes engagées, nullifiers, Merkle (BLAKE3, prof. 16), tx, validation — testés.
  **Mempool** (phase 4, brique 3) : contrôles ordonnés du MOINS au PLUS coûteux —
  l'asymétrie de coût (~4 ms de vérification STARK pour ~68 Kio envoyés) est LE
  vecteur de DoS du projet, donc les 5 filtres O(1) précèdent la vérification.
  Capacité bornée SANS éviction (une éviction permettrait de chasser les tx
  honnêtes). `Refus::couteux()` distingue les refus gratuits de celui qui a brûlé
  du CPU, pour pénaliser le pair en conséquence.
- `crates/circuit` : circuit STARK **monolithe** (`monolith/`) — P1–P7 d'une tx
  2-in/2-out en UNE SEULE trace/preuve, publics minimaux (root, nullifiers,
  output_commitments, fee), `ProvedTx` **v3** — **witness-hiding (HVZK en ROM)**
  depuis 3z-b1 (lignes de blinding, gating global `blind_off`, aléa OsRng frais
  par preuve) — testé et benché. ⚠️ **Deux dispositions coexistent** : le
  **SEGMENTÉ** (`seg_*`, 92 col × 2048 lignes) est celui que `tx.rs` utilise
  depuis la bascule 3z-c1 — ≈1783 ms génération, ≈4,1 ms vérification,
  ≈67,9 Kio/preuve à profondeur 32 ; le **côte-à-côte** (201 col × 1024 lignes,
  ≈1260 ms / 2,8 ms / 89,3 Kio) n'est plus sur le chemin de production et ne sert
  plus qu'à l'oracle de parité.
  Caveat : honnête-vérifieur, prototype non audité (voir docs/STARK_STATEMENT.md,
  « Argument HVZK »). Les gadgets autonomes du crate restent validity-only.
  `ProvedTx` v3 porte les `enc_notes` (enveloppes chiffrées des sorties, scan wallet
  via `ledger::proved_wallet`), liées dans `tx_digest` v3 (anti-substitution) ; P8
  différé, IK-CCA = phase 4. Sérialisation wire **canonique**
  `ProvedTx::{to_bytes, from_bytes}` (+`TxDecodeError`) : `from_bytes` = point
  d'entrée réseau validant (curseur borné sans panique, digests canoniques,
  bornes EncNote anti-DoS, rejet des octets résiduels), pas de serde
- `crates/wallet` : détention de notes, scan, construction de transactions. Tient
  son PROPRE `ProvedMerkleTree` — le nœud n'ayant qu'une frontier, il ne peut pas
  produire les chemins d'appartenance qu'exigent les preuves (partage de rôles
  décidé en brique frontier). ⚠️ `observer()` doit être appelé pour CHAQUE
  commitment dans le MÊME ordre que le nœud, sinon les index divergent.
  Monnaie rendue toujours produite ET chiffrée vers soi-même.
- `crates/node` : **câblage** des briques réseau et consensus (phase 5). `message`
  = protocole applicatif (Annonce/Demande/Transaction) : on annonce des DIGESTS
  (~64 o), jamais les transactions (~68 Kio) — envoyer spontanément la tx à chaque
  pair offrirait une amplification à l'attaquant. Décodage borné (MAX_DIGESTS)
  vérifié AVANT allocation. Il dépend de `net` ET du consensus, ce qui garde
  justement `net` PUR TRANSPORT. `orchestration` = ce qu'un nœud FAIT d'un message,
  en fonction PURE (retourne des Actions, aucune E/S) — c'est ce qui rend toute la
  politique testable sans réseau. `runtime` = l'EXÉCUTION (sockets, un thread de
  lecture par connexion, boucle d'événements). Lecture et écriture d'une connexion
  sont DÉCOUPLÉES (`Session::separer`, possible grâce aux clés directionnelles) :
  sinon un pair silencieux figerait aussi les envois vers lui.
  ✅ Testnet local validé : une transaction PROUVÉE se propage entre nœuds réels
  sur de vraies sockets, y compris à travers un INTERMÉDIAIRE (A→B→C). Chemin
  exercé : sérialisation → cadrage → chiffrement → socket → déchiffrement →
  décodage → admission (5 filtres O(1) puis STARK) → mempool.
  `Noeud::soumettre` = point d'entrée d'une transaction LOCALE (wallet) : part en
  TIGE Dandelion++, pas en diffusion — c'est là que l'origine est protégée.
  **Binaires** : `obscura-node` (nœud autonome) et `obscura-demo` (démonstration
  locale : wallet → preuve → handshake PQ → socket → mempool, chaque étape
  annoncée). **Persistance** (`node::persistance`) : identité + état survivent aux
  redémarrages (`--donnees`) — sans quoi les pairs ne reconnaîtraient pas le nœud
  et un nœud malveillant se blanchirait en redémarrant. Fichier d'identité en
  `0600` sur Unix, écriture atomique, JAMAIS régénéré en silence si corrompu.
  ⚠️ Mempool non persisté (sans gravité : réannoncé par les pairs) ; clé NON
  chiffrée au repos (une phrase de passe supposerait une saisie interactive).
- `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md` et `docs/STARK_STATEMENT.md` : spécification de référence
- `cargo test --all-features --release` : suite verte (crypto/net/ledger/circuit/wallet/node)

## Prochaine étape : 3z-c2, et industrialiser le nœud (persistance, wallet CLI)

**Tout ce qui précède est TERMINÉ** : phase 3 (validity P1–P7 + witness-hiding
3z-b1 + monolithe segmenté 3z-c1 fusionné), durcissement pré-testnet (#7 bouclé :
sérialisation canonique, zeroize, panic→Result, Merkle frontier, persistance
disque, test distingueur key-privacy), phases 4–5 (les 4 briques réseau câblées
dans un nœud réel, testnet local validé, binaires) — voir « État » ci-dessus ;
pour le circuit, le journal de tête de docs/STARK_STATEMENT.md est LA référence.
Cap actuel (décision utilisateur) : **complétude/cohérence protocole avant
sophistication crypto**. Reste :
1. **3z-c2 — variabilité M-in/N-out ≤ MAX** : la couture `SegKind`/schedule est
   en place depuis 3z-c1 ; la bascule supprimera le côte-à-côte (aujourd'hui
   conservé comme oracle de parité — mêmes publics, même témoin). Restent aussi
   2 forges non portées (`PaddingMerkle`, `VaccInitial` fine) et les forges à
   reconstruction d'arbre qui restent en profondeur 2.
   ⚠️ Piège identifié à ne pas rejouer : mutualiser des colonnes peut SUPPRIMER
   une garantie que la redondance offrait gratuitement (cf. « Liaison de racine »
   dans STARK_STATEMENT.md) — auditer chaque fusion sous cet angle.
2. **Industrialiser le nœud** : PERSISTANCE entre lancements — identité du nœud
   et état ledger (`ProvedLedgerState::{save, load}` existe côté ledger depuis
   #7, PAS encore câblé dans `obscura-node`) — et **wallet CLI** (le crate
   `wallet` est une bibliothèque ; seul `obscura-demo` l'exerce aujourd'hui).

## Décisions v0.2 (revue intégrée — ne pas régresser)

- Nullifier lié au commitment : nf = PRF_nk(rho ‖ cm), domaine "obscura/nullifier/v2"
- Identité shielded : secret racine `shielded_secret` (32 o, jamais publié, témoin
  STARK) ; `owner = H_owner(secret)` et `nk = H_nk(secret)` sont des hachages PROUVÉS
  (Rescue-Prime avec le circuit), pas des KDF wallet. La signature hybride `spend` =
  enveloppe d'intention / anti-malléabilité, PAS autorisation d'ownership tant qu'elle
  n'est pas liée au secret (phase 3). Spec :
  `docs/superpowers/specs/2026-07-14-hierarchie-shielded-secret-design.md`
- Merkle : profondeur 32 consensus / 16 dev (`MerkleTree::consensus()` / `new_dev()`)
- Versioning d'algos partout : byte 0x01 = round-3 en tête des sérialisations
  KEM/sig ; la migration FIPS 203/204 = nouvelle version 0x02, PAS un simple import
- spend_pk publié = fuite acceptée UNIQUEMENT en mode transparent dev
- Key privacy (IK-CCA) exigée pour enc_note — test distingueur ÉCRIT (non-fuite
  structurelle ; la réduction IK-CCA elle-même reste un argument, cf. PROTOCOL.md)
- Hash consensus (BLAKE3‖SHA3) ≠ hash prouvé (Rescue-Prime, migration avec le circuit)

## Notes de build

- **Features de dev, OFF par défaut** (le build/test nu = surface CONSENSUS seule) :
  `dev-transparent` (ledger : mode transparent non-privé, `apply_transparent`,
  `build_transparent_transaction`, `merkle`/`note` BLAKE3) et `dev-circuits` (circuit :
  sous-circuits autonomes `prove_*`/`verify_*`). La suite complète = `cargo test
  --all-features --release`. Ne jamais ajouter de dépendance du consensus vers du code
  gaté (l'invariant « défaut = consensus seul » doit tenir). Les modules gadgets restent
  compilés (le monolithe réutilise leurs helpers `pub(crate)`) ; seules leurs entrées
  publiques standalone sont gatées.
- Migration vers `pqcrypto-mlkem`/`pqcrypto-mldsa` (FIPS 203/204 finaux) : ce n'est
  PAS un simple changement d'import. FIPS 203/204 diffèrent de Kyber/Dilithium round-3
  (dérivation, encodages, errata NIST) → c'est une **nouvelle version d'algo `0x02`**
  qui cohabite avec `0x01`, pas un remplacement (voir PROTOCOL.md, versioning). Prévoir
  crates FIPS, byte de version, et vecteurs de test croisés.
- **Zeroize (durcissement #7)** : `ShieldedSecret` (volatile non élidable),
  `WalletKeys::{shielded_secret, nk}` et les clés AEAD dérivées s'effacent au drop ;
  les moitiés dalek (X25519/Ed25519) aussi. ⚠️ Les `SecretKey` pqcrypto (Kyber768/
  Dilithium3) NE s'effacent PAS (limitation crate) — à fermer à la migration FIPS 0x02.
- Prototype pédagogique : pas d'audit, ne pas utiliser en production.

## Conventions

- Code et commentaires : les commentaires/docs sont en français
- Tests unitaires dans chaque module + e2e dans `crates/ledger/tests/`
- Tout nouveau hash/PRF doit être séparé par domaine et non tronqué
