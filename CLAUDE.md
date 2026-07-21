# Obscura — contexte projet pour Claude Code

Monnaie numérique privée post-quantique. Prototype Rust, phases 1-2 terminées et testées.

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
  plus qu'à l'oracle de parité. (Sur master non fusionné : le côte-à-côte reste
  actif — voir point 2 ci-dessous.)
  Caveat : honnête-vérifieur, prototype non audité (voir docs/STARK_STATEMENT.md,
  « Argument HVZK »). Les gadgets autonomes du crate restent validity-only.
  `ProvedTx` v3 porte les `enc_notes` (enveloppes chiffrées des sorties, scan wallet
  via `ledger::proved_wallet`), liées dans `tx_digest` v3 (anti-substitution) ; P8
  différé, IK-CCA = phase 4. Sérialisation wire **canonique**
  `ProvedTx::{to_bytes, from_bytes}` (+`TxDecodeError`) : `from_bytes` = point
  d'entrée réseau validant (curseur borné sans panique, digests canoniques,
  bornes EncNote anti-DoS, rejet des octets résiduels), pas de serde
- `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md` et `docs/STARK_STATEMENT.md` : spécification de référence
- `cargo test` : suite verte (crypto/ledger/circuit)

## Prochaine étape : durcissement pré-testnet (#7), puis généralisation 3z-c

Phase 3 validity (statement P1–P7, monolithe, intégration ledger, bench) ET
**3z-b witness-hiding sont terminés** — voir le journal de tête de
docs/STARK_STATEMENT.md, c'est LA référence. **3z-b1 fait** : lignes de blinding
au niveau AIR (voie du spike 3z-b0, ni fork winterfell ni migration) — trace
1024, gating global `blind_off`, OsRng frais par preuve, argument HVZK-ROM écrit
(STARK_STATEMENT.md, « Argument HVZK »), bench ≈2× (1477,7 ms / 3,0 ms /
90,5 Kio). Cap actuel (décision utilisateur) : **complétude/cohérence protocole
avant sophistication crypto**. Reste :
1. **Durcissement pré-testnet (#7)** — **quasi terminé** : sérialisation canonique
   de `ProvedTx` **faite** ; `zeroize` des secrets au drop **fait**
   (`ShieldedSecret` volatile, `WalletKeys`, clés AEAD ; trou pqcrypto documenté) ;
   audit `panic→Result` de la surface réseau **fait** (from_bytes/verify/scan/
   apply sans panique) ; **Merkle frontier fait** (`proved_hash::MerkleFrontier`,
   append-only O(depth), mémoire bornée, `TreeFull` en `Result` — plus de panique
   « arbre plein » ; racine identique à `ProvedMerkleTree`, test différentiel) ;
   **persistance disque faite** (`ProvedLedgerState::{to_bytes, from_bytes, save,
   load}` — dump canonique frontier+nullifiers+racines, écriture atomique
   tmp+rename) ; **test distingueur key-privacy fait** (`ledger::proved_wallet` :
   invariance de longueur, aucun fragment de clé en clair, chiffrement randomisé,
   et aucun octet ne sépare deux destinataires sur 24 échantillons — RED vérifié
   en injectant une empreinte). ⚠️ Portée : non-fuite STRUCTURELLE, PAS une preuve
   d'IK-CCA (qui repose sur X25519/ANO-CCA Kyber, cf. PROTOCOL.md). **#7 bouclé.**
2. **3z-c — généralisation M-in/N-out**. La 1re tranche **3z-c1 (monolithe
   segmenté) est LIVRÉE et fusionnée** : trace en segments séquentiels
   `[KEY][IN][IN][OUT][OUT]` (`monolith/seg_{layout,trace,air}.rs`), largeur
   **92 vs 201**, **209 slots de contraintes vs 263**, preuve **67,9 Kio vs 89,3
   (−24 %)** à profondeur 32 pour ×1,41 en génération et ×1,46 en vérification
   (4,1 ms). `tx.rs` a basculé ; l'API et tous les tests préexistants sont
   inchangés. Le côte-à-côte est conservé pour l'**oracle de parité** (mêmes
   publics, même témoin) et sera supprimé avec 3z-c2.
   Reste : **3z-c2** (variabilité M/N ≤ MAX — la couture `SegKind`/schedule est en
   place), plus 2 forges non portées (`PaddingMerkle`, `VaccInitial` fine) et les
   forges à reconstruction d'arbre qui restent en profondeur 2.
   ⚠️ Piège identifié à ne pas rejouer : mutualiser des colonnes peut SUPPRIMER
   une garantie que la redondance offrait gratuitement (cf. « Liaison de racine »
   dans STARK_STATEMENT.md) — auditer chaque fusion sous cet angle.
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
  ✅ Test d'intégration : deux nœuds réels sur une vraie socket TCP.

**Phase 4 : les 4 briques sont livrées** (key-privacy, transport PQ + cadrage,
pairs anti-eclipse, mempool ordonné par coût, Dandelion++). Reste à les CÂBLER
dans un nœud réel — c'est la phase 5 (nœud/wallet/testnet), qui suppose une boucle
d'événements, des sockets et l'orchestration des quatre.

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
