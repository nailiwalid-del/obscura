# Modèle de menace — Obscura (nom provisoire)

## Adversaires considérés

| Adversaire | Capacités | Contre-mesure |
|---|---|---|
| Observateur passif du réseau | Capture tout le trafic, analyse de métadonnées | Chiffrement hybride PQ de tous les liens + (phase 4) routage Dandelion++/mixnet |
| Attaquant actif (MitM) | Injection, rejeu, modification | AEAD authentifié, transcript binding dans le KEM, signatures hybrides |
| Analyste de chaîne | Lit tout le ledger public | Notes engagées, nullifiers non-liables, montants/destinataires jamais en clair |
| Nœud malveillant / Sybil | Nœuds espions | Rien de sensible en clair ; la confidentialité du CONTENU ne dépend pas de l'honnêteté des nœuds |
| **Eclipse** (adversaire contrôlant TOUS nos pairs) | Isole le nœud du reste du réseau | Sélection sortante par **groupes réseau distincts** (IPv4 /16, IPv6 /32), bannissement par score — `net::pairs`. ⚠️ Voir la nuance ci-dessous |
| Ordinateur quantique (futur) | Casse ECC (Shor), affaiblit les hash (Grover) | Hybride PQ partout (ML-KEM, ML-DSA), hash 256-bit, STARKs (hash uniquement) |
| Cryptanalyse d'une primitive | Casse UNE primitive (ex : Kyber ou AES) | **Défense en profondeur** : chaque fonction repose sur ≥2 primitives indépendantes |

## Principe central : défense en profondeur (choix validé)

Chaque fonction de sécurité combine deux primitives de familles mathématiques indépendantes :
la sécurité tient tant qu'AU MOINS UNE des deux tient.

- **Échange de clés** : X25519 (courbes elliptiques) + ML-KEM-768 (réseaux euclidiens), secrets combinés par KDF sur le transcript complet.
- **Signatures** : Ed25519 + ML-DSA-65 — la vérification exige les DEUX signatures.
- **Chiffrement** : cascade XChaCha20-Poly1305 ∘ AES-256-GCM, clés indépendantes dérivées.
- **Hachage / commitments** : dual_hash = BLAKE3(x) ‖ SHA3-256(x) — résistant aux collisions si l'un des deux l'est (ARX vs éponge Keccak).

Règle : la combinaison ne doit jamais être PIRE que la meilleure primitive seule
(pas de troncature du hash combiné, clés de cascade indépendantes, KDF liant tout le transcript).

## Garanties visées

1. **Confidentialité des montants** : jamais en clair on-chain (phase 3 : prouvés par STARK).
2. **Non-liabilité expéditeur/destinataire** : adresses jamais publiées, notes à usage unique.
3. **Anti double-dépense** : nullifiers déterministes mais non-liables sans la clé.
4. **Confidentialité des métadonnées réseau** : phase 4 (Dandelion++ puis mixnet).

⚠️ **Nuance importante sur le Sybil.** La ligne « la confidentialité ne dépend pas de
l'honnêteté des nœuds » vaut pour le CONTENU (notes engagées, montants, destinataires
— garantis par la cryptographie seule). Elle NE vaut PAS pour les MÉTADONNÉES dès que
Dandelion++ est le mécanisme : un adversaire qui éclipse un nœud voit toute sa phase
*stem* passer par lui, et apprend donc l'origine de ses transactions. La confidentialité
réseau dépend donc bien, elle, de la diversité des pairs — d'où la sélection par groupes
réseau distincts de `net::pairs`, qui rend l'eclipse coûteuse (il faut de l'adressage
réparti, traçable) sans la rendre impossible (un opérateur ou un cloud multi-régions
reste capable).
5. **Résistance post-quantique** de bout en bout.

## Hors périmètre (assumé)

- Sécurité de l'endpoint (malware sur la machine du wallet).
- Canaux auxiliaires des implémentations (prototype).
- Économie/gouvernance du consensus (PoS simplifié).

## Limitations du mode transparent (dev) — v0.2

Le mode transparent actuel N'EST PAS le protocole : c'est un échafaudage.
Il ne peut pas vérifier la liaison nullifier↔note, l'autorité de dépense réelle,
ni l'équilibre des montants, et il révèle commitment dépensé, chemin de Merkle et
clé publique (dépenses reliables). La règle de consensus réelle est le statement
STARK (docs/STARK_STATEMENT.md) — P1 à P7. Aucun déploiement, même testnet public,
avant la phase 3.

## Garanties additionnelles exigées (v0.2)

- **Key privacy (IK-CCA)** du chiffrement des notes : une enc_note ne doit pas
  permettre de deviner le destinataire parmi des clés connues (test distingueur prévu).
- **Non-malléabilité des preuves** : la preuve STARK est liée à tx_digest.
- **Versioning d'algorithmes** dans tout transcript et toute sérialisation
  (la migration round-3 → FIPS n'est pas transparente : FIPS 203/204 + errata NIST).
- **Anti-sabotage de notes** : nullifier lié au commitment (nf = PRF_nk(rho ‖ cm)) —
  deux notes de même rho ne partagent plus le même nullifier.
- **Aucun pseudonyme public stable par wallet.** Tout champ en clair réutilisé d'une
  transaction à l'autre est un identifiant, et la confidentialité vaut son maillon le
  plus faible : un seul champ stable annule montants engagés, destinataires chiffrés,
  witness-hiding et Dandelion++ à la fois. Deux applications aujourd'hui :
  `ProvedTx::signer` (clé d'intention **neuve à chaque transaction** — cf.
  PROTOCOL.md) et l'identité de transport d'un wallet qui soumet à un nœud
  (**éphémère**, sinon le nœud d'entrée relie toutes nos soumissions).

## Ce que le wallet ne protège PAS (état actuel)

- **Le fichier de wallet n'est pas chiffré au repos.** Il contient l'autorité de
  DÉPENSE en clair ; sa confidentialité repose entièrement sur les permissions du
  système de fichiers (`0600` sur Unix, posé avant écriture ; rien sur les plateformes
  sans permissions POSIX). Une phrase de passe supposerait Argon2 + saisie
  interactive — à faire correctement plutôt qu'à moitié.
- **Le nœud d'entrée sait que la transaction vient de nous** (niveau IP). Dandelion++
  protège la propagation, pas le premier saut : le pair auquel on soumet observe
  directement l'origine. Se connecter à son propre nœud, ou via un réseau anonymisant,
  reste à la charge de l'utilisateur.
- **Aucune réception.** Voir « Finalité » ci-dessous.

## Finalité : ce qui existe, et ce qui n'existe pas

Une transaction devient définitive en entrant dans un **bloc** (`ledger::bloc`) : un
lot de transactions dans un ordre écrit, chaîné à son parent par un identifiant
`dual_hash` non tronqué. `ProvedLedgerState::appliquer_bloc` l'applique **atomiquement**
et deux nœuds acceptant la même chaîne convergent vers la même racine — vérifié sur de
vraies sockets (`crates/node/tests/finalite.rs`).

L'atomicité n'est pas un raffinement : un bloc à moitié appliqué placerait le nœud dans
un état qu'aucun autre n'a, sans qu'il le sache. Il refuserait ensuite toutes les
transactions pour « ancre inconnue », et rien dans les messages d'erreur ne désignerait
le bloc fautif.

### ⚠️ Personne n'a autorité pour sceller

Aucune élection de producteur n'existe — c'est explicitement hors périmètre (économie et
gouvernance du consensus). Tout nœud lancé avec `--sceller` fabrique donc des blocs, et
la chaîne obtenue est un ordre **convenu** entre participants coopératifs, jamais un
ordre **défendu** contre un adversaire. Un participant hostile peut sceller ce qu'il
veut, quand il veut. Testnet local uniquement.

L'ordre interne d'un bloc est le tri par `tx_digest` : deux nœuds scellant le même
mempool produisent le même bloc, ce qui rend les collisions inoffensives. Ce critère est
*grindable* (on peut faire varier une transaction jusqu'à obtenir un digest favorable) ;
sans marché de frais cela n'achète rien, mais devra changer le jour où l'ordre aura de
la valeur.

### ⚠️ Aucune réorganisation n'est possible, par construction

L'état repose sur une `MerkleFrontier` append-only et un ensemble de nullifiers sans
historique : **rien ne peut être défait**. Ce n'est pas un choix d'implémentation qu'on
lèverait plus tard sans y toucher — supporter les réorganisations exigerait de
redessiner l'état du ledger (arbre versionné, nullifiers datés par hauteur, journal de
défaisage). La chaîne est linéaire et un bloc accepté est définitif.

### Trou restant : un wallet ne peut toujours pas RECEVOIR

Il lui faut rejouer dans l'ordre tous les commitments insérés dans l'arbre pour en
connaître les index et produire ses chemins de Merkle ; or le nœud n'en conserve pas
l'historique (`MerkleFrontier` = bord droit seulement) et n'a rien à servir. Le paiement
fonctionne de bout en bout (`crates/node/tests/paiement_wallet.rs`), mais la monnaie
rendue sort de la vue du wallet faute d'index.

C'est le prochain manque structurel : un nœud doit conserver et servir l'historique des
sorties, et un wallet doit pouvoir le rejouer.

## Security Claims — Phase 3 (validité + witness-hiding 3z-b1)

Le circuit de la Phase 3 garantit l'**intégrité** (pas de forge, pas de double
dépense, équilibre des montants, cohérence Merkle/nullifier). Depuis **3z-b1**,
la preuve MONOLITHIQUE — le chemin de consensus `prove_tx`/`verify_tx` — est en
outre **witness-hiding (HVZK dans le modèle de l'oracle aléatoire)** : lignes de
blinding au niveau AIR, argument en deux étages (comptage par colonne de trace
`q+2 = 34 < b = 40` + taille de la région de blinding pour les ouvertures de
composition/quotient et FRI, heuristique) + esquisse de simulateur dans
`docs/STARK_STATEMENT.md` (« Witness-hiding du monolithe — argument HVZK »).
Limites précises de cette revendication :

- **honnête-vérifieur** (Fiat-Shamir en ROM) — PAS de malicious-verifier ZK ni
  de « perfect ZK » ; argument non formalisé au niveau publication ;
- **prototype non audité** : ne pas présenter comme `shielded production` ;
- les **gadgets autonomes** du crate circuit (sponge, balance, spend, … — hors
  chemin de consensus) restent **validity-only** : ils ne masquent pas leur
  témoin ;
- types nommés `ValidityProof` / `ValidityCircuit` conservés ; `ZkProof` reste
  réservé à une preuve witness-hiding AUDITÉE.

Voir `docs/superpowers/specs/2026-07-15-phase3-decision-et-3a0-design.md` et
`docs/superpowers/specs/2026-07-20-3zb1-witness-hiding-design.md`.
