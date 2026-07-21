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

- **La FORME (m, n) d'une transaction est PUBLIQUE (3z-c2).** Le circuit accepte
  `1..=4` entrées et sorties, et le nombre de chacune est lisible sur le fil (les
  publics le portent). Un observateur range donc les transactions par forme, et les
  formes rares partitionnent l'ensemble d'anonymat — au plus 16 seaux (4×4), à
  comparer à un pseudonyme par wallet, donc une fuite BORNÉE. Atténuation, pas
  suppression : `Wallet::construire` vise **2/2 par défaut** (le seau le plus
  peuplé) et n'en sort que par nécessité (une seule note → 1-in ; deux notes qui ne
  couvrent pas → plus d'entrées). La consolidation (`consolider`, forme M/1) est un
  geste VOLONTAIRE, distinctif, dont l'alternative — ne pas pouvoir dépenser — est
  pire. C'est le même arbitrage que Zcash Sapling, qui expose aussi son nombre de
  spends/outputs. Uniformiser (bourrer tout à 4/4) coûterait ×2 de preuve à tous.
- **Le fichier de wallet n'est pas chiffré au repos.** Il contient l'autorité de
  DÉPENSE en clair ; sa confidentialité repose entièrement sur les permissions du
  système de fichiers (`0600` sur Unix, posé avant écriture ; rien sur les plateformes
  sans permissions POSIX). Une phrase de passe supposerait Argon2 + saisie
  interactive — à faire correctement plutôt qu'à moitié.
- **Le nœud d'entrée sait que la transaction vient de nous** (niveau IP). Dandelion++
  protège la propagation, pas le premier saut : le pair auquel on soumet observe
  directement l'origine. Se connecter à son propre nœud, ou via un réseau anonymisant,
  reste à la charge de l'utilisateur.
- **La réception EXISTE, mais le nœud servant en apprend long.** Le nœud CONSERVE
  l'historique des sorties (`--archiver`), le SERT sur le fil (`Message::DemandeHistorique`,
  étranglé par `GroupeReseau`), et le wallet le REJOUE par une boucle câblée
  (`obscura-wallet synchroniser`, `node::client`). Le cycle payer → recevoir est donc
  fermé. Ce qui reste : le nœud servant voit notre IP, la CADENCE des demandes et la
  POSITION de chaîne, et il peut MENTIR PAR OMISSION (voir « Le wallet REJOUE
  l'historique » ci-dessous). Servir est un rôle d'ARCHIVISTE coûteux et optionnel.

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

### Defauts trouves par revue adversariale et corriges

Une revue multi-agents (4 concepteurs + 3 critiques : divergence, DoS, vie privee) a
trouve six defauts dans la finalite telle que livree. Consignes parce que leur forme se
reproduira :

1. **Une borne verifiee au decodage ne protege que l'entrant.** `Noeud::sceller` ne
   plafonnait pas `MAX_TX_PAR_BLOC` : le mempool tenant 5 000 transactions, un noeud
   pouvait sceller un bloc localement valide, indiffusable et inacceptable par
   quiconque - partition definitive, l'etat etant append-only. Regle qui en decoule :
   *toute borne de `from_bytes` doit exister aussi dans le constructeur*.
2. **La fenetre d'ancres etait plus courte qu'un bloc.** `RECENT_ROOTS_WINDOW = 100`
   contre `MAX_TX_PAR_BLOC = 512`, `remember_root` appele a chaque insertion : un
   bloc charge purgeait toutes les ancres. Un wallet passant environ 1,8 s a prouver
   voyait sa transaction refusee pour « ancre inconnue » - message qui designe l'ancre
   et jamais la cause. Vecteur adverse : n'importe qui pouvant sceller, on purgeait la
   fenetre a partir du mempool honnete, sans fabriquer une preuve. Censure a cout nul.
3. **Une version inconnue faisait bannir.** Un bloc d'une autre version devenait un
   message indecodable, penalise -10, banni au dixieme bloc, soit 100 s. Les bannis
   quittant la selection sortante, la diversite de groupes reseau s'effondrait - donc
   l'anti-eclipse, donc l'anonymat de Dandelion++. Une mise a jour partitionnait le
   reseau en degradant sa propre defense. On distingue desormais « version que je ne
   connais pas » (aucune sanction) de « malformation dans une version connue »
   (sanction).
4. **Aucune echeance sur les sockets.** Un pair ouvrant une connexion sans jamais
   parler figeait la boucle principale dans le handshake ; un pair cessant de lire
   figeait `executer`, verrou tenu. Le noeud restait debout et muet. Correction
   partielle : les echeances transforment le blocage en lien mort, mais `executer`
   tient toujours le verrou pendant l'ecriture.
5. **`apply_proved_tx` etait publique** : une seconde porte d'insertion dans l'arbre,
   hors de tout bloc. Desormais `pub(crate)` - son seul appelant legitime est
   `appliquer_bloc`.
6. **Un bloc manque figeait le noeud en silence.** `ParentInattendu` ne produit ni
   sanction (correct) ni signal (faux) : un noeud ayant manque un bloc refuse tous les
   suivants pour toujours, indiscernable d'un noeud au repos. Un compteur
   (`blocs_desaccordes`) le rend visible. **Le rattrapage de bloc a ete ecrit depuis**
   — voir la section suivante.

## Rattrapage de bloc : ce qui existe, et ce qu'il ne protege pas

Un noeud figé n'était pas seulement indisponible : il servait un historique plus court
mais parfaitement COHÉRENT — racine valide, tête valide, transactions acceptées contre
son ancre. Tout wallet qui s'y synchronisait concluait à tort qu'il était à jour. C'est
pourquoi le rattrapage précède la synchronisation du wallet et non l'inverse.

Le protocole tient en trois pièces (`crates/node`) :

- `Message::DemandeBloc { hauteur }` — un seul champ, 9 octets sur le fil, longueur
  EXACTE au décodage. Aucun `max` ni aucune plage choisis par le client : conformément
  à la contrainte de la section suivante, un paramètre client est une empreinte qui
  survit à une identité de transport éphémère. Le débit se règle par la FRÉQUENCE.
  La réponse réutilise `Message::Bloc` : un bloc rattrapé passe par `appliquer_bloc`,
  avec les mêmes contrôles que n'importe quel bloc diffusé — aucun chemin parallèle.
- `node::archive::ArchiveBlocs` — les N derniers blocs APPLIQUÉS, sous forme
  sérialisée. Bornée **deux fois** : 64 blocs et 64 Mio. Une seule borne ne suffirait
  pas — un bloc plein pèse ≈ 34 Mio, donc 64 blocs pleins vaudraient ≈ 2,1 Gio décidés
  par les producteurs de blocs et pas par nous ; à l'inverse, borner les seuls octets
  laisserait des blocs vides remplir l'archive. L'état de CONSENSUS reste borné et
  inchangé (frontier) : l'archive vit à côté, n'entre dans aucune règle de validation,
  et un noeud qui la vide reste valide.
- `Noeud::sur_bloc` / `sur_demande_bloc` — un bloc en avance déclenche une demande de
  la PREMIÈRE hauteur manquante, sans aucune sanction ; une demande pour une hauteur
  qu'on n'a pas reçoit le SILENCE, sans sanction non plus.

### Pourquoi cela ne boucle pas

Trois propriétés, et il faut les trois :

1. **Une demande ne naît que d'un bloc REÇU.** Recevoir une demande n'en produit jamais
   une autre ; le silence est une réponse terminale.
2. **Le déclencheur est une inégalité STRICTE** (`recue > notre_hauteur + 1`). Deux
   noeuds à la même hauteur sur des chaînes divergentes — le cas normal de deux
   scellements simultanés — se refusent mutuellement leurs blocs sans rien se demander.
3. **Un rattrapage infructueux s'arrête au premier pas.** Si le pair sert un bloc issu
   d'une AUTRE chaîne, ce bloc arrive exactement à la hauteur attendue : l'inégalité
   stricte est fausse, aucune nouvelle demande ne part. Le noeud reste figé — ce qui est
   honnête — mais ne saigne pas de bande passante.

Vérifié sur de vraies sockets dans `crates/node/tests/rattrapage.rs` (rattrapage de deux
hauteurs jusqu'à égalité de racine ET de tête ; deux noeuds désaccordés dont l'échange
s'éteint ; demande de hauteur inconnue sans réponse ni sanction).

### Ce que le rattrapage NE ferme PAS

- **Aucun étranglement.** Servir un bloc (34 Kio à 34 Mio) pour une demande de 9 octets
  est une asymétrie d'AMPLIFICATION. Le seul frein actuel est le score de pair et
  l'échéance d'écriture ; l'étranglement par `GroupeReseau` exigé plus bas pour le
  service d'historique n'est PAS écrit ici. Limite consignée, pas fermée.
- **Aucune réorganisation, donc aucune réparation d'un fork réel.** Le rattrapage rend
  un noeud EN RETARD à sa chaîne. Un noeud sur une chaîne divergente reste divergent
  pour toujours : l'état est append-only (voir plus haut). Le rattrapage rend cet état
  observable, il ne le corrige pas.
- **L'archive n'est pas persistée** et repart vide à chaque lancement : un noeud
  fraîchement redémarré ne peut pas servir les blocs qu'il avait appliqués avant.
- **Un pair peut mentir sur sa hauteur.** `hauteur_max_vue` n'est pas vérifiée ; le
  dégât est borné à une demande supplémentaire par bloc reçu, jamais une boucle.
- **Aucune borne de hauteur au-delà de laquelle on refuse de rattraper** : un noeud très
  en retard obtient le silence de tout le monde (archive bornée) et ne rattrape pas.
  Le resynchroniser demande le rôle d'archiviste complet, décrit plus bas.

## Émission de monnaie : la genèse, et rien d'autre

### Ce qui protégeait avant, et pourquoi ce n'était pas une règle

`ProvedLedgerState::mint` existait, publique, et n'était appelée par **aucun** chemin de
consensus ni de réseau — seulement par des tests et par `obscura-demo`. Ce qui empêchait
l'inflation n'était donc pas une règle : c'était la **divergence**. Un nœud qui émettait
obtenait une racine que personne d'autre n'avait ; sa monnaie était inutilisable parce
qu'invisible, et ses transactions étaient refusées partout pour « ancre inconnue ».

C'est un accident heureux, pas une défense. Sa conséquence est décisive pour la suite :
**ajouter un champ `emissions` applicable à toute hauteur aurait SUPPRIMÉ cette
protection** et transformé l'inflation en événement diffusé et *accepté par tous*, sans
qu'aucune erreur ne soit levée. La conception retenue s'interdit donc explicitement ce
chemin.

### La règle

- `Bloc` porte `emissions: Vec<Emission>`, et le consensus impose
  **`hauteur > 0 ⇒ emissions.is_empty()`** (`BlocRefus::EmissionHorsGenese`).
- Ce contrôle est O(1) et placé **avant tout le reste** dans `appliquer_bloc` : avant
  l'instantané, avant le chaînage, avant la boucle de vérification. Placé après, un bloc
  de 512 transactions valides accompagnées d'une émission illégitime coûterait ≈2 s de
  vérification STARK avant refus — un déni de service au prix d'un octet.
- Il précède aussi le refus de chaînage parce que les deux ne sont pas de même nature :
  « ne prolonge pas MA chaîne » est relatif et n'accuse personne (deux scellements
  simultanés), « crée de la monnaie » est invalide pour tout le monde. `node` sanctionne
  donc le second (`PENALITE_BLOC_INVALIDE`) sans jamais sanctionner le premier.
- La genèse **ne s'applique pas, elle AMORCE** : `ProvedLedgerState::depuis_genese`. Il
  n'y a rien à défaire, donc l'atomicité durement acquise d'`appliquer_bloc` n'a pas été
  compliquée pour ce cas.
- `mint` est désormais **privée**, son seul appelant étant l'amorçage. Même discipline
  que `apply_proved_tx` : une seconde porte d'insertion dans l'arbre ne doit pas exister.
- `MAX_EMISSIONS_PAR_BLOC = 512`, vérifiée avant allocation dans `Bloc::from_bytes`
  **et** dans `Bloc::genese_avec` — une borne de décodage ne protège que l'entrant. Une
  assertion de compilation consigne qu'une genèse pleine reste sous le cadre réseau.

### `Emission` ne porte JAMAIS un `Option<EncNote>`

Une émission sans bénéficiaire porte une enveloppe **factice** chiffrée vers une clé KEM
**jetable** (la moitié secrète meurt avec l'appel : le contenu n'est déchiffrable par
personne, pas même par son auteur). Un drapeau de présence partitionnerait publiquement
les feuilles de l'arbre en « émises » et « transférées », et ce gabarit serait recopié
le jour d'une coinbase shielded — le witness-hiding du circuit annulé par un octet de
sérialisation. `SpendNote` ayant un encodage de taille fixe, la longueur d'une émission
factice est exactement celle d'une émission réelle (testé).

### La genèse est un paramètre d'opérateur, jamais une valeur par défaut silencieuse

`obscura-node --genese <fichier>` charge la genèse par `Bloc::from_bytes`, le décodeur
borné du réseau — un fichier de genèse vient d'un tiers. Si le fichier demandé manque ou
est corrompu, le démarrage **échoue franchement** : aucun repli, parce qu'un nœud amorcé
sur la mauvaise genèse est indiscernable d'un nœud neuf en bonne santé (hauteur 0, refus
silencieux de tout bloc). Sans `--genese`, la genèse VIDE sert de défaut pour le testnet
local, et elle est **affichée** comme telle. L'identifiant de genèse (8 premiers octets)
est imprimé au démarrage pour que deux opérateurs comparent une ligne.

Deux nœuds amorcés sur la même genèse ont la même racine ET la même tête ; sur des
genèses différentes, ils ont la même hauteur (0) mais des têtes **différentes** — c'est
ce qui rend l'erreur détectable.

### Ce que cela ne ferme PAS

- **Aucune coinbase, donc aucune récompense de producteur.** C'est cohérent avec
  l'absence d'élection de producteur (hors périmètre). Le jour où une coinbase shielded
  aura un sens, elle exigera une règle qui **borne le montant émis** — or ce montant est
  précisément ce que le chiffrement cache. C'est une brique de conception, pas un champ
  à débloquer.
- **FERMÉ — l'état grave désormais sa genèse** (`VERSION_ETAT` 0x03) : l'identifiant du
  bloc 0 est sérialisé dans `etat.bin` et confronté au `--genese` demandé À CHAQUE
  démarrage. Un répertoire peuplé par une autre chaîne est refusé avec les deux
  identifiants dans le message (`GeneseDifferente`) — avant toute confrontation
  d'archive, pour que la cause affichée soit la vraie. C'était la dernière divergence
  silencieuse connue du démarrage.
- **Rien n'atteste QUI a écrit la genèse.** Le fichier n'est ni signé ni authentifié ;
  sa distribution est hors bande et à la charge des opérateurs. La comparaison
  d'identifiants détecte le désaccord, pas la substitution par un tiers qui contrôlerait
  le canal de distribution.
- **Rien ne vérifie que les émissions d'une genèse sont déchiffrables par quiconque.**
  Une genèse peut n'être faite que d'émissions factices : la chaîne est alors valide et
  sans monnaie utilisable. C'est voulu (indistinguabilité), et cela signifie qu'aucun
  contrôle automatique ne remplace la lecture des paramètres.

### La persistance de l'archive est un JOURNAL en ajout (fait)

`historique.bin` porte un octet de version : `0x01` = dump intégral hérité (migré une
fois, atomiquement, à l'identique), `0x02` = journal par enregistrements de bloc. Une
sauvegarde n'écrit que les tranches NOUVELLES puis `sync_all` — le dump intégral
réécrivait tout, soit des Gio par jour sous charge, toutes les 30 s.

Le prix du journal : l'ajout n'est pas atomique. Un crash en plein ajout laisse un
enregistrement PARTIEL en fin de fichier, écarté et tronqué au chargement suivant. Ce
n'est PAS la troncature « réparatrice » que ce document interdit : l'ordre d'écriture
« historique d'abord, état ensuite » garantit qu'un enregistrement partiel correspond à
des blocs que l'état persisté ne couvre pas encore — l'écarter ne retire rien que
quiconque possédait, et ne PAS l'écarter rendrait le fichier entier illisible au
redémarrage suivant. Toute autre incohérence (hauteur non contiguë, digest non
canonique, plage non chaînée) reste une CORRUPTION : refus, jamais de troncature — là,
les enregistrements sont complets et ont pu être relayés au réseau.

### Le noeud CONSERVE l'historique des sorties (fait) — il ne le SERT pas encore

`ledger::historique::HistoriqueSorties` conserve, dans l'ordre d'insertion, chaque
sortie entrée dans l'arbre — `(commitment, enc_note)`, jamais un `Option` — découpée par
BLOC : chaque `TrancheBloc` porte la plage de feuilles du bloc et **la racine de fin de
bloc**. Un wallet qui rejoue ces entrées reconstruit exactement l'arbre du noeud, donc
ses index, donc ses chemins ; et il s'ancre sur une frontière de bloc, ce qui empêche son
`anchor` public de devenir un pseudonyme.

Ce qui EXISTE :

- **Une seule porte d'insertion.** L'historique n'est écrit que par
  `ProvedLedgerState::{amorcer, appliquer_bloc}`, exactement là où l'arbre grandit.
  `mint` et `apply_proved_tx` restent privées.
- **Atomicité structurelle.** Les sorties d'un bloc sont accumulées localement et ne
  rejoignent l'historique qu'après l'application complète : un bloc refusé n'a rien à
  défaire. Un historique plus long que l'arbre serait une divergence silencieuse — tous
  les index suivants décalés, aucun message d'erreur.
- **Rôle SÉPARÉ et OPTIONNEL.** `Option<HistoriqueSorties>`, `None` par défaut ;
  `obscura-node --archiver` l'active, et l'activation ne change **aucun octet** de l'état
  de consensus (testé). Un noeud qui n'archive pas est valide.
- **Coût chiffré et assumé** : ≈1,4 Kio par sortie (dominé par le `kem_ct` hybride de
  1121 o), ≈1,4 Mio par bloc plein, ≈12 Gio/jour à un bloc plein toutes les 10 s.
  Jamais élagué aujourd'hui : le champ `debut` existe pour que l'élagage soit un
  changement de VALEUR et non de FORMAT, et un historique élagué est REFUSÉ tant que
  rien ne sait reconstruire son préfixe.
- **Persistance dans un fichier séparé** (`historique.bin`), écrit AVANT `etat.bin` :
  un crash entre les deux laisse l'archive en avance (récupérable) plutôt qu'en retard
  (irrécupérable — la frontier ne garde que le bord droit). Au chargement,
  `adopter_historique` confronte hauteur, nombre de feuilles et racine de fin de bloc ;
  **un écart n'est jamais réparé en silence** : il est nommé, journalisé, et le noeud
  tourne en mode DÉGRADÉ (sans archive) sans que le fichier soit tronqué ni effacé — le
  bloc en trop a peut-être été relayé à tout le réseau.

#### Decision tranchee : `racine_apres` et `fin` n'entrent PAS dans `Bloc::to_bytes`

La question etait de savoir si ces deux valeurs devaient entrer dans le bloc, donc dans
`Bloc::id()`, pour qu'un wallet puisse verifier autre chose que la parole du noeud.
**Non, parce que le bloc les engage deja** : son encodage canonique contient ses
transactions entieres, donc leurs `output_commitments` et `enc_notes` dans l'ordre (et,
pour la genese, ses emissions). La liste des sorties d'une hauteur est donc integralement
liee a l'identifiant du bloc — verifie mecaniquement par
`historique_est_exactement_ce_que_le_bloc_engage`. `racine_apres` et `fin` sont DERIVEES
de (etat avant ‖ contenu du bloc) : les inscrire changerait le format de consensus
(`VERSION_BLOC` 0x03) et obligerait le scelleur a appliquer son bloc speculativement,
sans ajouter un seul bit d'authentification.

⚠️ **Ce que cela laisse ouvert.** Un wallet qui prend l'historique ET les identifiants de
blocs aupres du MEME noeud n'a rien verifie : ce noeud peut lui servir une chaine
coherente et fausse. La verification ne devient reelle que si les identifiants de blocs
viennent d'ailleurs — plusieurs noeuds, ou un point de controle hors bande. C'est le meme
trou que « personne n'a autorite pour sceller », pas un trou de format.

#### Ce qui MANQUE encore

- Le noeud ne **sert** pas l'historique : aucun message de protocole ne l'expose, et
  l'etranglement par `GroupeReseau` reste a ecrire.
- Le wallet ne le **rejoue** pas encore : `Wallet::observer` + `Wallet::scanner` sont le
  chemin, exerce par `wallet::emission_de_genese_scannee_par_son_beneficiaire`, mais
  rien ne les alimente depuis un noeud.
- `HistoriqueSorties::save` reecrit le dump ENTIER a chaque sauvegarde. Sans consequence
  au prototype, inutilisable a l'echelle chiffree ci-dessus : il faudra un journal en
  ajout.

**Contraintes de conception deja etablies par la revue** - a respecter quand la brique
de SERVICE sera ecrite, car chacune corrige un defaut identifie dans les premieres
propositions :

- **L'unite de synchronisation doit etre le BLOC, pas la plage de feuilles.** Raison :
  `ProvedTx::anchor` est public et vaut la racine de l'arbre du WALLET, c'est-a-dire sa
  position de synchronisation exacte. Des wallets s'arretant chacun a une feuille
  differente publieraient donc chacun une ancre quasi unique - un pseudonyme permanent,
  exactement le defaut corrige pour la cle d'intention. Ancres sur une frontiere de
  bloc, tous les wallets a jour partagent la meme ancre.
- **Aucun champ choisi par le client sur le fil**, hormis sa position. Un `max`
  d'entrees par reponse est une empreinte de client qui survit a l'identite de
  transport ephemere : le noeud separe les wallets par leur `max`, puis suit chacun par
  sa position. Le debit se regle par la FREQUENCE des demandes.
- **Jamais d'`Option<EncNote>`** : un drapeau de presence partitionnerait publiquement
  les feuilles en emises et transferees. Une emission sans beneficiaire doit porter une
  enveloppe FACTICE, indistinguable d'une vraie - c'est precisement la propriete que
  les tests IK-CCA verifient deja.
- **L'etranglement s'indexe sur `GroupeReseau` (/16, /32), jamais sur `PeerId`** : une
  identite de pair est gratuite, et le wallet en tire une neuve a chaque commande. Le
  groupe reseau est deja l'unite de cout Sybil du projet.
- **Aucune indexation directe d'un indice venu du reseau** : `usize::try_from`,
  `saturating_sub`, `get(..)` - jamais `&journal[i..i+n]`.
- **Un noeud servant l'historique apprend l'IP, la cadence et la position de chaine** du
  wallet, et peut MENTIR PAR OMISSION (taire une sortie : le paiement reste invisible,
  la racine est intacte, rien ne l'attrape). Il ne peut ni fabriquer de credit ni
  apprendre quelles notes sont les notres - le balayage est local. A ecrire tel quel.
- **Le role d'archiviste est SEPARE et optionnel** : l'etat consensus reste borne
  (frontier). Un noeud qui n'archive pas est valide, il ne peut simplement pas amorcer
  de wallet. Ne jamais faire dependre l'admission d'une transaction du fait de servir
  l'historique, sans quoi la confidentialite deviendrait un privilege d'operateur.

### Le noeud SERT l'historique (fait) — protocole de synchronisation

Les contraintes ci-dessus sont desormais implementees. Trois pieces, dans `crates/node` :

- **`node::message`** — `Message::DemandeHistorique { hauteur }` (9 octets, longueur
  EXACTE) et `Message::Historique(ReponseHistorique)`. La demande porte **la position et
  rien d'autre** : aucun `max`, aucune plage, aucun index de morceau. Deux wallets a la
  meme position emettent des octets IDENTIQUES, verifie octet pour octet
  (`demandes_identiques_a_position_egale`, `deux_wallets_a_la_meme_position_...`).
- **`node::synchro`** — le format de fil de la reponse. L'unite servie est **un bloc
  entier** (`debut`, `fin`, `racine_apres`), jamais une plage de feuilles.
- **`node::etranglement`** — seaux a jetons indexes sur `GroupeReseau`.

#### Le decoupage est decide par le SERVEUR

Un bloc plein pese ≈1,4 Mio, au-dela du cadre reseau de 1 Mio. Une demande peut donc
produire PLUSIEURS messages. Le client n'exprime jamais d'index de morceau — ce serait
rouvrir la porte que « aucun champ client » ferme. `MAX_SORTIES_PAR_REPONSE` (739) est
**calcule**, pas choisi : `(MAX_CADRE − SURCOUT_AEAD − en-tete) / TAILLE_SORTIE_MAX`. Ce
que le cadrage borne est la quantite CHIFFREE, et la cascade XChaCha20∘AES-GCM ajoute 68
octets (`crypto::aead::SURCOUT`, exactitude testee) : l'ignorer aurait produit un service
qui echoue precisement sur ses reponses pleines. Une assertion de compilation le consigne.

Le decoupage est **canonique** : `morceaux`, `decalage` et le nombre d'entrees sont
entierement determines par (`debut`, `fin`, `morceau`) et RECALCULES au decodage plutot
que crus. Cela ferme trois abus d'un coup — morceaux qui se recouvrent (index decales en
silence), morceaux fantomes au-dela du bloc, et segmentation choisie servant de marqueur
discret d'un wallet.

#### L'etranglement, et pourquoi il porte sur les REQUETES

Seau a jetons par `GroupeReseau` : 4 096 entrees-equivalent de capacite, 256/s de
recharge, **8 debites par requete avant meme de savoir s'il y a quelque chose a servir**.
Une reponse « courte » n'est pas gratuite (allocation, double chiffrement, ecriture,
flush) : sans cout fixe, sonder des hauteurs inexistantes serait gratuit pour l'attaquant
et couteux pour nous. La recharge est comptee en milliemes d'entree — tronquee a
l'entier, un pair interrogeant toutes les 3 ms ne regagnerait jamais un seul jeton et
s'auto-bannirait du service a vie sans qu'aucune ligne ne l'ait decide.

**A credit epuise : le SILENCE**, indistinguable de « hauteur inconnue » et de « je
n'archive pas ». Un refus distinct ferait du credit une information sondable, et
couterait exactement ce qu'on cherche a eviter. **Aucune sanction, jamais** : demander
son historique est le comportement normal d'un wallet, et le score gouverne la selection
sortante — penaliser degraderait notre propre anti-eclipse.

L'adresse d'un pair vient du runtime (`Noeud::noter_adresse`, appele a l'acceptation
comme a la connexion) et vit dans une table **distincte de `TablePairs`** : verser les
pairs entrants dans la table anti-eclipse leur ouvrirait nos emplacements SORTANTS. Sans
adresse connue, **on ne sert pas** (fail-closed) : sans groupe, pas d'etranglement
possible, et servir quand meme offrirait un contournement complet.

#### `hauteur_tete` : une indication, jamais un moteur

La reponse porte la hauteur de tete du serveur, sans quoi un wallet ne saurait jamais
s'il lui reste des blocs a demander. C'est un champ **non verifiable**. Ce qui empeche le
mensonge de faire boucler un wallet est que `hauteur_tete` ne PILOTE rien : la position
du wallet n'avance que lorsqu'il recoit la tranche de la hauteur qu'il a demandee. Une
tete gonflee lui fait demander une hauteur absente, obtenir le silence, et s'arreter —
une requete inutile, le meme degat borne qu'on accepte deja pour `hauteur_max_vue`. Le
decodage refuse en outre `hauteur_tete < hauteur` : un serveur ne peut pas pretendre etre
en retard sur la tranche qu'il vient de servir. Le nœud annonce la tete qu'il peut
reellement SERVIR (`historique.hauteur_max()`), pas `etat.hauteur()` : promettre une
hauteur non archivee ferait boucler le wallet sur une demande eternellement silencieuse.

⚠️ Le mensonge INVERSE — annoncer une tete plus courte que la vraie — reste indetectable
aupres d'un noeud unique. C'est le meme trou que « mentir par omission » : un wallet qui
prend historique ET identifiants de blocs au MEME noeud n'a rien verifie.

#### Ce qui MANQUE encore, ecrit franchement

- **Le decoupage a plusieurs morceaux n'est teste qu'au niveau du FORMAT DE FIL.** Une
  genese est plafonnee a `MAX_EMISSIONS_PAR_BLOC` (512) < 739, donc l'atteindre de bout en
  bout exigerait ≈370 preuves STARK. La couverture est reelle sur `ReponseHistorique`,
  pas sur le chemin socket.
- **`HistoriqueSorties::save` reecrit le dump ENTIER** a chaque sauvegarde (limite deja
  consignee) — servir n'y change rien.
- **La table de seaux est bornee** (`MAX_GROUPES_SUIVIS` = 1 024) et, a saturation, un
  groupe inconnu n'est pas servi tant qu'aucun seau n'est revenu a plein. Occuper toutes
  les places exige 1 024 groupes reseau distincts ; le deni obtenu ne porte que sur le
  service d'historique, jamais sur le consensus, la propagation ou le rattrapage.
- **Le service de BLOCS (`sur_demande_bloc`) n'est toujours pas etrangle.** Son
  amplification (9 octets → jusqu'a 34 Mio) reste ouverte : le seau ecrit ici lui est
  applicable tel quel, il n'y est pas branche.
- L'etranglement se fonde sur l'adresse SOURCE observee : un adversaire derriere un NAT
  partage le seau de son voisin, et un adversaire disposant reellement de nombreux
  prefixes obtient autant de seaux. Rendre l'attaque chere et visible, pas impossible.

### Le wallet REJOUE l'historique (fait) — le cycle payer → recevoir est ferme

`wallet::synchro` est la derniere piece : le wallet rejoue les sorties servies par le
noeud, retrouve les INDEX de ses notes, et adopte l'ancre du bloc. C'est ce qui lui
permet enfin de RECEVOIR — y compris sa propre monnaie rendue, qui sortait de sa vue a
chaque paiement faute d'index.

#### L'invariant d'ordre est STRUCTUREL

Rejouer dans un autre ordre que le noeud ne produit aucune erreur : cela produit
d'autres index, donc d'autres chemins de Merkle, donc des transactions refusees pour
« ancre inconnue » sans que rien ne designe la cause. C'est la panne silencieuse la plus
couteuse du protocole, et elle est fermee par construction :

- Le wallet **memorise sa position** (`prochaine_hauteur`) et refuse tout lot qui ne
  commence pas exactement la ou il s'est arrete, dans les DEUX dimensions : la hauteur
  (`HauteurHorsSequence`) et la feuille (`FeuilleHorsSequence`, confrontee a
  `arbre.len()`). Un trou de bloc n'est jamais comble en silence.
- Un bloc **deja rejoue** (livraison en double) rend `Statut::DejaApplique` sans rien
  muter : idempotent, et **dit** — un `Ok` muet ferait croire a une boucle de
  synchronisation qu'elle progresse.
- L'index rendu par l'arbre est **confronte** a celui que le lot annonce
  (`decalage + i`), feuille par feuille.
- L'application est **atomique** : racine reconstruite differente de `racine_apres` ⇒
  l'arbre est ramene a son prefixe exact (`ProvedMerkleTree::tronquer`) et aucune note
  n'est retenue. Le SCAN — une decapsulation KEM hybride par sortie, de loin le poste le
  plus cher — n'a lieu qu'APRES l'acceptation de la racine : un noeud hostile ne peut pas
  faire bruler des decapsulations avec un lot qui ne tient pas debout.

#### Aucun tampon de morceaux partiels

`Wallet::synchroniser` recoit TOUS les morceaux d'une hauteur d'un coup. Un tampon
partiel serait un etat a moitie applique qu'il faudrait persister, et un wallet recharge
au milieu d'un bloc s'ancrerait au milieu d'un bloc. Une synchronisation interrompue est
donc un lot INCOMPLET (`LotIncomplet`) : refuse, rien n'est applique. Les morceaux sont
**ranges par leur index**, jamais concatenes dans l'ordre d'arrivee, et leur couverture
est verifiee par CUMUL — le wallet n'a pas besoin de connaitre la taille de morceau du
serveur pour la controler.

#### `hauteur_tete` est structurellement absente du rejeu

Le type que le wallet rejoue (`MorceauHistorique`) ne porte PAS ce champ. Ce n'est pas
un oubli ni une politique : la logique de rejeu ne peut pas le lire, meme par erreur.
Une tete gonflee ne peut donc que provoquer une requete sans reponse.

#### L'ancre est celle d'une FRONTIERE DE BLOC, ou rien

`ProvedTx::anchor` est public et vaut la racine de l'arbre du wallet. Le wallet retient
donc le nombre de feuilles de la derniere frontiere adoptee (`feuilles_ancrees`), et
`construire` REFUSE de prouver quand l'arbre a deborde de cette frontiere
(`ArbreHorsFrontiereDeBloc`). Rien en aval ne pourrait distinguer une ancre a mi-bloc
d'une ancre legitime : la transaction serait acceptee et le pseudonyme publie pour de
bon. `deux_wallets_a_jour_publient_la_meme_ancre` verifie la propriete sur deux
transactions REELLEMENT prouvees, par deux wallets aux notes differentes.

#### Le fichier de wallet passe en 0x02

La position entre dans le fichier. Sans elle, un wallet redemarre repartirait de la
hauteur 0 et rejouerait tout l'historique **par-dessus son propre arbre** : chaque
commitment insere deux fois, tous les index decales, aucune erreur. Un fichier `0x01`
est refuse par une variante qui lui est propre (`VersionSansPosition`), jamais
reinterprete avec une position par defaut.

#### Ce que cela ne ferme PAS

- **Le mensonge par omission reste indetectable.** La racine reconstruite est confrontee
  a celle que le noeud ANNONCE : taire une sortie donne une chaine parfaitement close
  dont la racine est bien celle annoncee, et le paiement omis reste invisible. Fermer ce
  trou exige des identifiants de blocs venus d'AILLEURS (plusieurs noeuds, point de
  controle hors bande) — meme trou que « personne n'a autorite pour sceller ».
- **La boucle de synchronisation est cablee** (`node::client::synchroniser_par_connexion`,
  exposee par `obscura-wallet synchroniser`). Elle demande `hauteur = prochaine_hauteur()`,
  rassemble tous les morceaux du bloc, rejoue UNE fois, enregistre APRES chaque bloc, et
  s'arrete au premier SILENCE. Elle ne consulte JAMAIS `hauteur_tete` (le wallet ne la
  voit pas) ; `DejaApplique` n'est pas un pas (arret, sinon boucle sur place) ; et le
  travail est BORNE par invocation (`MAX_BLOCS_PAR_INVOCATION`, abandon nomme plutot que
  boucle infinie sur un noeud qui sert sans fin). La frequence des demandes est le seul
  levier de debit cote client — un `max` sur le fil serait une empreinte. `envoyer`
  REFUSE tant que le wallet n'a jamais ete synchronise, et propose `--noeud-synchro`
  distinct de `--noeud` : synchroniser puis envoyer depuis la MEME IP relie les deux et
  designe l'emetteur, alors qu'un relais Dandelion++ ne vient jamais de se synchroniser.
  Le cycle payer → sceller → recevoir → redepenser est exerce sur de vraies sockets
  (`crates/node/tests/cycle_wallet.rs`).
- **`observer` reste public et n'avance pas l'ancre.** C'est une primitive de bas
  niveau ; un wallet alimente par cette seule porte verra `construire` refuser, ce qui
  est bruyant mais reste un piege pour qui l'appelle sans lire.
- **Le rejeu est en O(n) memoire et l'arbre du wallet aussi** (il garde toutes les
  feuilles — c'est ce qui lui permet de produire des chemins). A l'echelle chiffree plus
  haut (≈12 Gio/jour de sorties), un wallet ne peut pas rejouer la chaine entiere : il
  faudra un arbre creux ou des points de controle. Rien ne le limite aujourd'hui.

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

### Portee exacte de la garantie « meme ancre » (revue finale)

« Tous les wallets a jour partagent la meme ancre » ne vaut qu'entre wallets
synchronises a la MEME hauteur. Un wallet en retard, arrete a un bloc ancien encore
dans la fenetre d'ancres, publie la racine de fin de CE bloc : acceptee par le
consensus, mais partagee seulement par les wallets arretes au meme bloc. L'ancre
partitionne donc l'ensemble d'anonymat par hauteur de derniere synchronisation, en
autant de seaux que la fenetre contient de blocs. Fuite acceptee faute de mieux,
bornee par la taille de la fenetre ; parade pratique : se resynchroniser juste avant
d'emettre. De meme, la protection contre la correlation synchro/envoi est
CONSULTATIVE : l'outil ne memorise pas d'une invocation a l'autre quel noeud a servi
l'historique, il rappelle donc l'avertissement inconditionnellement sur `envoyer`.
