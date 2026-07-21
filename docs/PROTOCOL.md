# Protocole Obscura — spécification v0.2

## Changements v0.1 → v0.2 (suite à revue)

1. **La preuve STARK est la règle de consensus** (voir `STARK_STATEMENT.md`) ; la
   validation actuelle est un *mode transparent de développement* explicitement
   marqué non-privé et non-sound.
2. Profondeur de Merkle : **32 en consensus** (2^32 notes), 16 en mode dev uniquement.
3. Nullifier lié au commitment : `nf = PRF_nk(rho ‖ commitment)`.
4. Versioning explicite des algorithmes dans transcripts et sérialisations.
5. Exigence de **key privacy** sur le chiffrement des notes.
6. Séparation hash consensus / hash prouvé (voir `STARK_STATEMENT.md`).

## Modèle : UTXO privé à la Zerocash

État public : arbre de Merkle des commitments + ensemble des nullifiers. Rien d'autre.

## Note

```
Note { value: u64, owner: [u8;32], rho: [u8;32], r: [u8;32] }
```

- **Commitment** (64 o) : `dual_hash("obscura/note/v1", encode(note))`.
  (Migrera vers Rescue-Prime en même temps que le circuit — jamais avant.)
- **Nullifier v2** (32 o) : `PRF_nk("obscura/nullifier/v2", rho ‖ commitment)`.
  Lier le commitment neutralise l'attaque « deux notes, même rho, même destinataire
  → même nullifier » (un expéditeur malveillant pouvait rendre une note indépensable).
  Même approche qu'Orchard qui lie le nullifier au contexte complet de la note.

## Clés d'un wallet

| Clé | Construction | Rôle |
|---|---|---|
| Secret shielded `shielded_secret` | aléa 32 o, jamais publié | racine de l'identité ; témoin du circuit (P2/P4) |
| Réception/vue | hybride X25519 + Kyber768 | déchiffrer les notes reçues |
| Nullifier `nk` | `nk = H_nk(shielded_secret)` (**hash prouvé**) | calculer les nullifiers, liée à l'autorité (P4) |
| Signature `spend` | hybride Ed25519 + Dilithium3, **NEUVE à chaque transaction** | enveloppe d'intention / anti-malléabilité sur `tx_digest` (PAS autorisation d'ownership tant que non liée au secret — phase 3) |

### La clé d'intention ne doit JAMAIS être réutilisée

`ProvedTx::signer` est un champ **public**, sérialisé sur le fil. Une clé d'intention
stable serait donc un pseudonyme permanent : un observateur relierait entre elles
toutes les transactions d'un wallet par simple regroupement sur `signer`, sans casser
aucune primitive — annulant de fait montants engagés, destinataires chiffrés, preuve
witness-hiding et Dandelion++ pour ce wallet.

C'est licite parce que la signature d'intention est une **enveloppe
d'anti-malléabilité**, pas une autorisation de propriété : l'autorité de dépense vient
du `shielded_secret` prouvé dans le circuit. Rien n'a besoin de reconnaître une clé
d'intention d'une transaction à l'autre — donc rien n'empêche de la renouveler.
`wallet::Wallet::construire` en tire une neuve à chaque appel, et ne la persiste pas.

## Adresse

Adresse = (`owner = H_owner(shielded_secret)`, clé publique KEM). Jamais publiée on-chain.
`owner` et `nk` appartiennent au domaine **« hash prouvé »** : BLAKE3 domain-séparé en
v0.2 dev, migration vers Rescue-Prime avec le circuit (jamais figés en BLAKE3).

### Encodage textuel (`wallet::adresse`)

```text
obs1 ‖ hex( version(1 o) ‖ owner(32 o) ‖ kem_pk(1 217 o) ‖ somme(4 o) )
```

- **Version de FORMAT** distincte de la version d'ALGORITHME portée par `kem_pk` ; les
  deux sont vérifiées. Une adresse `0x02` (future migration FIPS 203) doit être
  REFUSÉE par un décodeur round-3, jamais réinterprétée.
- **Somme de contrôle** : 4 octets de `dual_hash("obscura/adresse/v1", corps)`. Elle
  existe parce qu'un paiement vers une adresse abîmée est **irréversible et
  silencieux** — le `owner` altéré ne correspond à aucun secret, la note est engagée
  et personne ne peut la dépenser. Le protocole ne peut rien rattraper ; la seule
  défense possible est en amont de la preuve.
- ⚠️ **La somme détecte l'ACCIDENT, pas l'ADVERSAIRE** : courte et non clefée,
  quiconque fabrique une adresse en recalcule la somme. L'authenticité d'une adresse
  vient du CANAL qui l'a transmise, jamais de son encodage.
- ~2,5 Kio en hexadécimal — le prix des clés post-quantiques (Kyber768 pk = 1 184 o),
  non réductible par troncature.

## Versioning des algorithmes (obligatoire)

La migration round-3 → FIPS n'est PAS un simple changement d'import : FIPS 203/204
diffèrent de Kyber/Dilithium round-3 (dérivation, encodages, errata NIST suivis).
Tout objet sérialisé et tout transcript inclut donc un identifiant d'algorithme :

| ID | Signification |
|---|---|
| `x25519+kyber768-round3` (byte 0x01) | KEM hybride actuel |
| `x25519+ml-kem-768-fips203` (byte 0x02) | après migration |
| `ed25519+dilithium3-round3` (byte 0x01) | signature hybride actuelle |
| `ed25519+ml-dsa-65-fips204` (byte 0x02) | après migration |

Deux versions peuvent cohabiter sur la chaîne pendant une transition ; un objet
sans identifiant ou avec un identifiant inconnu est invalide.

## Chiffrement des notes : exigence de key privacy

`enc_note` ne doit pas permettre de deviner le destinataire, même parmi une liste
de clés publiques connues (IK-CCA, cf. exigence analogue de la spec Zcash).
IND-CCA seul ne suffit pas.

Construction actuelle et arguments :
- l'éphémère X25519 est indistinguable d'un point aléatoire ;
- Kyber768 avec rejet implicite est réputé anonyme (ANO-CCA) dans la littérature
  post-Round-3 — à re-vérifier sur ML-KEM final lors de la migration ;
- l'AEAD cascade ne contient aucun identifiant de clé ; `aad = commitment` seulement ;

Vérification côté implémentation (`ledger::proved_wallet`, tests `key_privacy_*`) :
les arguments ci-dessus sont THÉORIQUES et ne couvrent pas les fuites qu'une
implémentation introduit réellement. Quatre tests ferment cette classe : invariance
de longueur, absence de tout fragment de clé publique en clair, chiffrement
randomisé, et — jeu du distingueur — aucun octet du chiffré n'est constant par
destinataire et différent entre deux destinataires (24 échantillons chacun, même
note et même commitment, seul le destinataire varie). Ils établissent la non-fuite
STRUCTURELLE ; ils n'établissent PAS IK-CCA, qui reste adossé aux arguments
ci-dessus.
- le scan se fait par essai de déchiffrement, identique pour toutes les sorties.

Test à écrire (phase réseau) : un distingueur avec 2 adresses candidates et une
`enc_note` ne doit pas faire mieux que 1/2.

## Transaction

### Règle de consensus (cible, phase STARK)

```
Tx { proof, root, nullifiers[], output_commitments[], enc_notes[], fee }
```
Validation = vérifier la preuve STARK (statement P1–P7) contre tx_digest + unicité
des nullifiers. Aucune clé publique, aucun chemin de Merkle, aucun montant d'entrée publié.

**État (2-in/2-out, implémenté) :** `circuit::ProvedTx` v3 porte tous ces champs, dont
`enc_notes` (liés dans `tx_digest` v3, anti-substitution). Scan des destinataires :
`ledger::proved_wallet::{encrypt_note, scan_proved_output}`. Arité fixe 2/2 (la
généralisation M-in/N-out = phase 3z-c). P8 (cohérence enc_note↔commitment) différé.

### Mode transparent (DEV UNIQUEMENT — actuel)

```
Tx { inputs: [ {root, commitment, path, nullifier, spend_pk, sig} ], outputs, fee }
```
Ce mode révèle le commitment dépensé, le chemin de Merkle et la clé publique
(dépenses reliables) et NE PEUT PAS vérifier : liaison nullifier↔note, owner↔clé,
équilibre des montants. Il n'existe que pour développer le ledger et les wallets en
attendant le circuit. Fonctions suffixées `_transparent` dans le code.

## Arbre de Merkle

- Profondeur **32** (consensus), 16 (mode dev). Hash de nœud : BLAKE3 domain-séparé
  (migrera vers Rescue-Prime avec le circuit).
- Racines récentes conservées pour valider des tx construites sur un état légèrement ancien.

## Primitives (crate `crypto`) — inchangées en v0.2

| Fonction | Construction | Sécurité |
|---|---|---|
| dual_hash | BLAKE3 ‖ SHA3-256 (64 o) | collision-résistant si l'un des deux tient |
| prf | BLAKE3 keyed + domaine | PRF |
| HybridKem | X25519 + Kyber768, ss = KDF(ss1‖ss2‖transcript‖algo-id) | IND-CCA si l'un tient |
| HybridSig | Ed25519 ET Dilithium3 | EUF-CMA si l'un tient |
| CascadeAead | XChaCha20-Poly1305( AES-256-GCM(m) ) | confidentialité si l'un tient |

## Phases (recentrées)

1. ✅ Primitives crypto hybrides
2. ✅ Ledger transparent de développement (explicitement non-privé)
3. ✅ **Circuit STARK = définition du consensus** (P1–P7, monolithe segmenté
   witness-hiding, `apply_proved_tx` = règle de consensus) + migration
   Rescue-Prime des commitments/Merkle + retrait de spend_pk/path des
   transactions (le mode transparent est gaté `dev-transparent`, hors consensus).
   Reste dans ce chantier : **3z-c2**, la variabilité M-in/N-out (voir
   STARK_STATEMENT.md)
4. ✅ Réseau P2P chiffré PQ + Dandelion++ + test de key privacy — briques livrées
   (crate `net` : transport, cadrage, pairs anti-eclipse, Dandelion++ ;
   `ledger::mempool`) ET câblées dans le nœud (phase 5)
5. ✅ Nœud, wallet CLI, testnet local — **nœud fonctionnel** (`crates/node` :
   protocole applicatif, orchestration en fonction pure, runtime sockets+threads).
   Testnet local validé : une transaction PROUVÉE se propage entre nœuds réels sur
   de vraies sockets, y compris à travers un intermédiaire. **Binaires livrés** :
   `obscura-node` (nœud autonome), `obscura-demo` (démonstration locale) et
   `obscura-wallet` (`creer`/`adresse`/`synchroniser`/`solde`/`envoyer`). PERSISTANCE
   câblée (identité + état du nœud, position du wallet). **Synchronisation wallet ↔
   nœud** livrée : le wallet REÇOIT (cycle payer → sceller → recevoir → redépenser
   exercé sur sockets, `crates/node/tests/cycle_wallet.rs`).

## Protocole applicatif de synchronisation (crate `node`)

Messages circulant DANS le canal chiffré (le premier octet est un tag applicatif ; le
cadrage réseau — longueur préfixée, borne anti-DoS — est celui de `net::frame`).

- `DemandeHistorique { hauteur: u64 }` — **9 octets**, longueur EXACTE : `tag(1) ‖
  hauteur(8, LE)`. Émise par un wallet, en clair de bout en bout pour le nœud qui la
  sert. Un seul champ, la POSITION : tout autre paramètre choisi par le client (un
  `max`, une plage) serait une empreinte qui survit à l'identité de transport éphémère.
  Le débit se règle par la FRÉQUENCE des demandes. Deux wallets à la même position
  émettent des octets identiques.
- `Historique` — un MORCEAU des sorties d'un bloc (réponse à `DemandeHistorique`).
  En-tête : `tag(1) ‖ version(1=0x01) ‖ hauteur(8) ‖ debut(8) ‖ fin(8) ‖ racine_apres(64)
  ‖ hauteur_tete(8) ‖ morceau(4) ‖ morceaux(4) ‖ decalage(8) ‖ n_sorties(4)`, puis `n`
  entrées `commitment(64) ‖ len(kem_ct)(4) ‖ kem_ct(1121) ‖ len(enc_note)(4) ‖ enc_note`.
  L'unité est le BLOC (jamais la plage de feuilles : `ProvedTx::anchor` est public, et un
  wallet arrêté à mi-bloc publierait une ancre quasi unique). Découpage décidé par le
  SERVEUR et **canonique** : `morceaux`/`decalage`/`n_sorties` sont RECALCULÉS au
  décodage à partir de (`debut`, `fin`, `morceau`), fermant recouvrements, morceaux
  fantômes et segmentation-marqueur. `hauteur_tete` est une indication NON vérifiable qui
  ne pilote rien (refus au décodage si `hauteur_tete < hauteur`). `MAX_SORTIES_PAR_REPONSE`
  est CALCULÉ sur `MAX_CADRE − surcoût AEAD − en-tête` : le cadrage borne le CHIFFRÉ.
- `DemandeBloc { hauteur: u64 }` / réponse `Bloc` — **rattrapage** d'un nœud qui a manqué
  une hauteur (même discipline : un seul champ, débit par fréquence).

Côté wallet, la BOUCLE (`node::client`) demande `hauteur = prochaine_hauteur()`,
rassemble tous les morceaux du bloc, les rejoue en UNE fois (`Wallet::synchroniser`),
enregistre après chaque bloc, et s'arrête au premier silence. Elle ne lit jamais
`hauteur_tete` ; `DejaApplique` n'est pas un pas ; le travail est borné par invocation.
