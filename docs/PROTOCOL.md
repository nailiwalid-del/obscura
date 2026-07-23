# Protocole Obscura — spécification v0.2

> **Pour vérifier cette implémentation plutôt que la lire :**
> [`CONFORMITE.md`](CONFORMITE.md) — vecteurs ACVP ciblés, fixture rejouable, et
> la liste de ce qui n'est **pas** démontré.

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
| Réception/vue | hybride X25519 + ML-KEM-768 (FIPS 203) | déchiffrer les notes reçues |
| Nullifier `nk` | `nk = H_nk(shielded_secret)` (**hash prouvé**) | calculer les nullifiers, liée à l'autorité (P4) |
| Signature `spend` | hybride Ed25519 + ML-DSA-65 (FIPS 204), **NEUVE à chaque transaction** | enveloppe d'intention / anti-malléabilité sur `tx_digest` (PAS autorisation d'ownership tant que non liée au secret — phase 3) |

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
  deux sont vérifiées. La version courante est `0x02` (FIPS 203) ; une adresse `0x01`
  (round-3) est REFUSÉE PAR SON NOM (`AdresseError::VersionPerimee`, qui dit quoi
  regénérer), jamais réinterprétée.
- **Somme de contrôle** : 4 octets de `dual_hash("obscura/adresse/v2", corps)` — le
  domaine a changé avec la version, donc une adresse d'ancienne version échoue de
  toute façon sur sa somme, avant même le contrôle de version. Elle
  existe parce qu'un paiement vers une adresse abîmée est **irréversible et
  silencieux** — le `owner` altéré ne correspond à aucun secret, la note est engagée
  et personne ne peut la dépenser. Le protocole ne peut rien rattraper ; la seule
  défense possible est en amont de la preuve.
- ⚠️ **La somme détecte l'ACCIDENT, pas l'ADVERSAIRE** : courte et non clefée,
  quiconque fabrique une adresse en recalcule la somme. L'authenticité d'une adresse
  vient du CANAL qui l'a transmise, jamais de son encodage.
- ~2,5 Kio en hexadécimal — le prix des clés post-quantiques (ML-KEM-768 pk = 1 184 o),
  non réductible par troncature.

## Versioning des algorithmes (obligatoire)

Tout objet sérialisé et tout transcript inclut un identifiant d'algorithme, et cet
identifiant entre dans les DOMAINES de dérivation (`combine`) et de signature
(`frame`) : deux versions ne peuvent donc pas se confondre, structurellement.

| ID | Signification |
|---|---|
| `x25519+kyber768-round3` (byte 0x01) | KEM round-3 — **PÉRIMÉ, refusé par son nom** |
| `x25519+mlkem768-fips203` (byte 0x02) | KEM hybride COURANT |
| `ed25519+dilithium3-round3` (byte 0x01) | signature round-3 — **PÉRIMÉE, refusée par son nom** |
| `ed25519+mldsa65-fips204` (byte 0x02) | signature hybride COURANTE |

**Aucune cohabitation** (décision T1.1, plan Testnet 0) : un objet `0x01` est reconnu
et REFUSÉ par une variante d'erreur qui le nomme (`CryptoError::AlgoPerime`), jamais
réinterprété ni accepté. Aucun réseau public n'a existé en round-3 : il n'y avait rien
à migrer sauf des fichiers locaux, qui se recréent — supporter deux versions aurait
coûté une surface de confusion de version pour zéro utilisateur. Un objet sans
identifiant ou avec un identifiant inconnu est invalide.

## Chiffrement des notes : exigence de key privacy

`enc_note` ne doit pas permettre de deviner le destinataire, même parmi une liste
de clés publiques connues (IK-CCA, cf. exigence analogue de la spec Zcash).
IND-CCA seul ne suffit pas.

Construction actuelle et arguments :
- l'éphémère X25519 est indistinguable d'un point aléatoire ;
- ML-KEM-768 avec rejet implicite est réputé anonyme (ANO-CCA) dans la littérature
  post-Round-3. ⚠️ Les analyses publiées visent Kyber round-3, et FIPS 203 n'en est
  pas la copie (dérivation, encodages) : l'argument est RECONDUIT, pas re-démontré ;
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

**État (implémenté, forme variable — 3z-c2) :** `circuit::ProvedTx` v4 porte tous ces
champs à forme variable m-in/n-out (`1..=4`) : Vec bornés (comptes vérifiés avant
allocation), comptes portés au wire et liés dans `tx_digest` v4 avec les `enc_notes`
(anti-substitution), et forme PRÉFIXÉE dans la graine Fiat-Shamir — deux découpages
des mêmes digests ne partagent pas leur transcript. La forme est PUBLIQUE (au plus
16 seaux, cf. THREAT_MODEL) ; le wallet vise 2/2 par défaut. Scan des destinataires :
`ledger::proved_wallet::{encrypt_note, scan_proved_output}`. P8 (cohérence
enc_note↔commitment) différé.

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

## Finalité : le bloc (`VERSION_BLOC = 0x05`)

L'unité d'application n'est pas la transaction isolée mais le **bloc** : un lot
*ordonné* de transactions, chaîné à son parent, appliqué **atomiquement**
(`ProvedLedgerState::appliquer_bloc`). L'état est **append-only de bout en bout :
aucune réorganisation n'est possible**, et c'est la finalité instantanée décrite
plus bas qui rend cette limite défendable plutôt que subie.

### Contenu et identifiant

```
Bloc { parent, hauteur, vue, transactions[], emissions[], scellement?, certificat? }
id = dual_hash("obscura/bloc/v1", encode_sans_signatures(bloc))   // 64 o, jamais tronqué
```

- **Entrent dans l'identifiant** : `parent`, `hauteur`, **`vue`**, les
  transactions dans leur ordre, les émissions.
- **N'entrent PAS dans l'identifiant** : `scellement` et `certificat` — ce sont
  des signatures *sur* l'identifiant ; elles ne peuvent pas y entrer. Elles
  voyagent néanmoins sur le fil.
- **Émission** : `hauteur > 0 ⇒ emissions.is_empty()`. La création de monnaie est
  confinée à la genèse (aucune coinbase).
- **Bornes** : `MAX_TX_PAR_BLOC` borne le NOMBRE, `MAX_OCTETS_BLOC` (≈ 1 Mio =
  cadre réseau − surcoût AEAD − marge message) borne le POIDS. Les deux sont
  vérifiées **au scellement ET au décodage** — un bloc valide est toujours
  diffusable en un cadre.

**Versions périmées refusées par leur nom.** Un bloc `0x03` ou `0x04` (J1-a/b —
autorités de scellement gravées, mais sans le changement d'autorités en
attente de J1-c) rend `BlocDecodeError::VersionPerimee`, jamais une
réinterprétation. Même discipline que `CryptoError::AlgoPerime` et
`VERSION_ETAT`. Aucune chaîne publique n'a existé en `0x03` ni en `0x04` : il
n'y avait rien à migrer.

### Élection de producteur et vue

La genèse peut **graver une liste d'autorités de scellement** (≤ `MAX_AUTORITES`
= 64, clés hybrides Ed25519 + ML-DSA-65), et cette liste entre dans
**l'identifiant de genèse** : deux listes initiales = deux chaînes.

```
producteur_attendu(h, vue) = autorites[(h − 1 + vue) mod n]
scellement = HybridSig("obscura/bloc/scellement/v1", id)   // du producteur du tour
```

La **vue** est le numéro de tentative à une hauteur donnée, et elle **entre dans
l'identifiant**. C'est ce qui interdit qu'un même bloc soit présenté sous deux
vues : deux vues donnent deux blocs *différents*, jamais deux encodages du même.
Le certificat porte donc sur `(hauteur, vue)` sans ambiguïté.

Une genèse **sans autorités** donne une chaîne **OUVERTE** : aucun scellement n'y
est accepté (`ScellementInattendu`), aucun certificat non plus
(`CertificatInattendu`) — la canonicité interdit deux encodages valides du même
bloc.

#### J1-b : le protocole de vue (votes sur le fil, changement de vue)

Le format de `0x04` ne suffisait pas à faire avancer une chaîne à `n ≥ 4` : il
fallait que les votes circulent et que la vue change. **J1-b le livre.**

```
Message::Proposition(Bloc)   // le producteur du tour diffuse son bloc
Message::Vote(Vote)          // chaque autorité vote sur l'id qu'elle a reçu
vote = HybridSig("obscura/bloc/vote/v1", id)
```

- **Délai de vue à backoff exponentiel** : `delai_vue(vue) = base × 2^vue`,
  plafonné (`PLAFOND_DELAI_VUE_MS`). Passé ce délai sans quorum, l'autorité
  passe à la vue suivante : `producteur_attendu(h, vue + 1)` prend la main.
  Sans backoff, un décalage persistant referait rater les vues indéfiniment
  (livelock) ; le backoff garantit qu'une vue finit par durer assez longtemps
  pour aboutir.
- **Fenêtre d'adoption** : une proposition à une vue strictement future n'est
  adoptée que si elle reste dans une fenêtre étroite au-delà de la vue
  courante (`FENETRE_VUE`) — un producteur d'une vue lointaine ne peut pas
  tirer tout le monde en avant d'un coup. Adopter une vue future réarme le
  minuteur, sinon elle expirerait au tick suivant et la vue remonterait en
  boucle.
- **Plafond de vues par hauteur** (`MAX_VUE_PAR_HAUTEUR`) : au-delà, la
  hauteur est déclarée CALÉE (split de votes) — aucun incrément de plus,
  journal CRITIQUE, compteur exposé. C'est un aveu explicite plutôt qu'une
  boucle silencieuse.
- **Sûreté du vote (modèle A, J1-b2)** : un nœud ne vote **qu'une fois par
  HAUTEUR, toutes vues confondues** (`node::votes::RegistreVotes`, persisté
  AVANT l'émission). Revoter le même id à la même hauteur est idempotent
  (un vote peut se perdre) ; voter un autre id à la même hauteur — même à une
  vue supérieure — est refusé. C'est ce qui rend la preuve de sûreté triviale :
  deux quorums à la même hauteur partagent un votant honnête, qui n'a signé
  qu'un id, quelle que soit la vue. **La vue n'entre jamais dans la décision
  de voter** — le format COURANT est `0x02` (`VERSION_VOTES`, clé `hauteur`
  seule) ; l'ancien format `0x01` de J1-b1 avait pour clé `(hauteur, vue)`.
- **Conséquence directe** : une chaîne à `n ≥ 4` produit désormais des blocs —
  la liveness que J1-a laissait ouverte est fermée par J1-b.

#### J1-c : changement d'ensemble d'autorités certifié

Reconfigurer un comité (ajouter, retirer, remplacer une autorité) sans J1-c
imposait de graver une nouvelle genèse — donc une nouvelle chaîne. **J1-c le
ferme** : le changement est un CHAMP du bloc, certifié par le quorum de
l'**ancienne** liste, effectif après un délai.

```
Bloc { …, changement_autorites: Option<Vec<SigPublicKey>> }
```

- **Certifié par l'ancienne liste** : un bloc portant `changement_autorites`
  doit réunir le quorum de l'ensemble d'autorités ACTUELLEMENT en vigueur —
  l'ancienne liste autorise sa propre succession, jamais la nouvelle
  elle-même.
- **Effet différé à `h + K`**, `K = DELAI_CHANGEMENT_AUTORITES = 8` : le délai
  n'achète pas de la sûreté (sous finalité BFT, juger `h+1` suppose déjà avoir
  appliqué `h`, donc tout le monde connaît la nouvelle liste — `K = 1` serait
  sûr) mais de la COORDINATION, le temps qu'une nouvelle autorité soit en
  ligne et synchronisée. Généreux à dessein, pensé pour un réseau fédéré
  coordonné hors bande.
- **Un seul changement en vol** : `changement_en_attente` est un
  `Option<(Vec<SigPublicKey>, u64)>` — tant qu'un basculement n'a pas pris
  effet, aucun second ne peut être proposé.
- **Comité actif height-aware** (`autorites_a(hauteur)`) : entre `h` (annonce)
  et `h + K` (effet), l'ancien comité reste actif ; à `h + K` et au-delà, le
  nouveau prend le relais — pour l'élection de producteur ET pour le quorum
  requis, dérivé du comité en vigueur à CETTE hauteur.
- **Bloc de gouvernance vide de transactions** : un bloc portant
  `changement_autorites` ne porte aucune transaction, pour que la
  reconfiguration reste un événement isolé, jamais mêlé à l'activité normale
  du ledger.
- **Persistance** : `VERSION_ETAT = 0x05` grave `changement_en_attente` dans le
  dump — sans quoi un nœud redémarré entre `h+1` et `h+K` oublierait le
  basculement en cours.

### Certificat de quorum

```
Certificat { masque: u64, signatures: [HybridSig] }
vote = HybridSig("obscura/bloc/vote/v1", id)
```

- **Quorum** : `⌊2n/3⌋ + 1` signatures valides et **distinctes**
  (`quorum_pour`), sûr pour tout `n` — et égal à `2f + 1` quand `n = 3f + 1`,
  donc `f = (n − 1) / 3`. À `n = 4` (`f = 1`) il faut 3 votes ; à `n ≤ 3`
  (`f = 0`) un seul suffit — c'est ce que « tolérer zéro faute » signifie, pas une
  faiblesse du calcul. Depuis J1-c, le comité et donc `n` peuvent changer d'une
  hauteur à l'autre (`quorum_a(hauteur)`) : le quorum requis est TOUJOURS dérivé
  du comité en vigueur à CETTE hauteur, jamais d'un `n` figé à la genèse.
- **Masque de bits** plutôt que liste d'index : 8 octets pour 64 autorités, et
  surtout les **doublons deviennent structurellement impossibles** — un bit est
  mis ou ne l'est pas. C'est ce qui rend le comptage de votants distincts sûr
  sans déduplication.
- **Encodage canonique** : le nombre de signatures est **DÉRIVÉ du masque**,
  jamais annoncé séparément ; les signatures sont rangées dans l'ordre croissant
  des index. Deux encodages du même certificat sont impossibles, et le nombre est
  borné avant toute allocation.
- ⚠️ **`DOMAINE_VOTE` est distinct de `DOMAINE_SCELLEMENT`, et ce n'est pas
  cosmétique** : les deux signent le même identifiant. Sans domaines séparés, le
  scellement du producteur pourrait être compté comme un vote, et `2f` votes
  réels suffiraient à afficher `2f+1`.
- ⚠️ **Aucune agrégation** : aucune signature post-quantique n'en offre. Le
  certificat pèse `popcount(masque) × 3374` octets — 1,0 % d'un bloc à `n = 4`,
  13,8 % à `n = 64`. **La taille du comité est donc bornée par le budget du
  bloc**, définitivement.

### Ordre de vérification — non négociable

`appliquer_bloc` va du moins cher au plus cher, et l'ordre est une défense
anti-DoS, pas une élégance :

1. contrôles O(1) (version, émission hors genèse, bornes) ;
2. **chaînage** (parent, hauteur) — un bloc d'une autre chaîne tombe en
   `ParentInattendu` sans rien coûter et **sans accusation** ;
3. **scellement** du producteur du tour ;
4. **certificat de quorum** — jusqu'à 43 vérifications hybrides au pire ;
5. **puis seulement** les preuves STARK.

Inverser 4 et 5 offrirait à un pair hostile de déclencher la vérification de
preuves avec un certificat bidon.

### État de la mise en œuvre (J1 complet)

La porte de consensus **J1 est close** — format, protocole de vue et
changement d'autorités sont livrés et testés sur sockets réelles :

- **J1-a (format)** : un bloc porte sa vue et son certificat, et un bloc sans
  quorum est refusé (`QuorumInsuffisant`, `VoteInvalide`, `VotantInconnu`).
- **J1-b1 (votes sur le fil)** : `Message::Proposition` et `Message::Vote`
  circulent réellement entre nœuds — un producteur rassemble les votes des
  autres autorités, pas seulement le sien.
- **J1-b2 (changement de vue, liveness fermée)** : délai de vue à backoff
  exponentiel, fenêtre d'adoption d'une vue future, plafond de vues par
  hauteur (hauteur CALÉE au-delà), et registre de votes persisté qui
  n'autorise qu'un id par hauteur toutes vues confondues (modèle A). **Une
  chaîne à `n ≥ 4` produit désormais des blocs** — ce que J1-a laissait
  ouvert est fermé.
- **J1-c (reconfiguration certifiée)** : `changement_autorites` certifié par
  le quorum de l'ancienne liste, effectif à `h + K` (`K = 8`), un seul
  basculement en vol, comité height-aware (`autorites_a`/`quorum_a`),
  `VERSION_ETAT = 0x05`. Changer une autorité n'impose plus une nouvelle
  chaîne.

Modèle et arbitrages : `docs/superpowers/specs/2026-07-22-j1-consensus-adr.md`
(ADR-001, accepté).

## Primitives (crate `crypto`) — inchangées en v0.2

| Fonction | Construction | Sécurité |
|---|---|---|
| dual_hash | BLAKE3 ‖ SHA3-256 (64 o) | collision-résistant si l'un des deux tient |
| prf | BLAKE3 keyed + domaine | PRF |
| HybridKem | X25519 + ML-KEM-768, ss = KDF(ss1‖ss2‖transcript‖algo-id) | IND-CCA si l'un tient |
| HybridSig | Ed25519 ET ML-DSA-65 | EUF-CMA si l'un tient |
| CascadeAead | XChaCha20-Poly1305( AES-256-GCM(m) ) | confidentialité si l'un tient |

**Contributivité du KEM** : `encapsulate` rejette une clé publique X25519 d'ordre
faible, `decapsulate` rejette un éphémère d'ordre faible (`CryptoError::NonContributif`,
points de RFC 7748 §6.1). Sans ce contrôle, un point de petit sous-groupe force un DH
nul : la moitié courbes du KEM disparaît EN SILENCE et ML-KEM porte seul la sécurité —
la défense en profondeur serait perdue sans qu'aucune erreur ne le dise.

## Phases (recentrées)

1. ✅ Primitives crypto hybrides
2. ✅ Ledger transparent de développement (explicitement non-privé)
3. ✅ **Circuit STARK = définition du consensus** (P1–P7, monolithe segmenté
   witness-hiding, `apply_proved_tx` = règle de consensus) + migration
   Rescue-Prime des commitments/Merkle + retrait de spend_pk/path des
   transactions (le mode transparent est gaté `dev-transparent`, hors consensus).
   **3z-c2** (variabilité M-in/N-out ≤ 4) livrée ; reste C2-T8 partiel — suppression
   du côte-à-côte et forges à reconstruction d'arbre en profondeur 32 (voir
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
  une hauteur (même discipline : un seul champ, débit par fréquence). Un bloc est borné
  en OCTETS au scellement ET au décodage (`MAX_OCTETS_BLOC` = cadre réseau − surcoût
  AEAD − marge message, ≈ 1 Mio) : un bloc valide est toujours diffusable en un cadre.

Côté wallet, la BOUCLE (`node::client`) demande `hauteur = prochaine_hauteur()`,
rassemble tous les morceaux du bloc, les rejoue en UNE fois (`Wallet::synchroniser`),
enregistre après chaque bloc, et s'arrête au premier silence. Elle ne lit jamais
`hauteur_tete` ; `DejaApplique` n'est pas un pas ; le travail est borné par invocation.
