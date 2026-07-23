# Architecture d'Obscura — rôles et invariants par crate

> **Source normative.** Ce fichier décrit ce que fait chaque crate et
> **pourquoi** sa structure est ce qu'elle est (les ⚠️ sont des invariants à ne
> pas régresser). Pour les FORMATS et RÈGLES, l'autorité est `docs/PROTOCOL.md` ;
> pour le modèle d'adversaire, `docs/THREAT_MODEL.md` ; pour l'énoncé STARK,
> `docs/STARK_STATEMENT.md`. Les constantes citées ici sont **informatives** :
> l'autorité est le code.

## Vue d'ensemble

Monnaie numérique privée post-quantique. Prototype Rust, phases 1 à 5
prototypées et testées : nœud persistant, cycle complet payer → sceller →
recevoir validé sur testnet local, consensus BFT fédéré (**porte J1 close** :
format, protocole de vue et changement d'autorités livrés — une chaîne à
`n ≥ 4` produit des blocs).

**Principe directeur** (décision utilisateur, ne pas remettre en cause) —
défense en profondeur : chaque fonction de sécurité combine 2 primitives de
familles mathématiques indépendantes (la sécurité tient si l'une des deux
tient). KEM = X25519+ML-KEM-768 (FIPS 203) · Sig = Ed25519 ET ML-DSA-65
(FIPS 204) · AEAD = cascade XChaCha20∘AES-GCM · Hash = BLAKE3‖SHA3-256 jamais
tronqué. Séparation de domaine partout (`"obscura/<usage>/v1"`). Depuis T1 :
version d'algo `0x02` (FIPS), le round-3 (`0x01`) est REFUSÉ PAR SON NOM
(`CryptoError::AlgoPerime`), jamais cohabité.

Références de synthèse : `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md` et
`docs/STARK_STATEMENT.md` sont la spécification de référence ; la suite est
verte sous `cargo test --all-features --release`
(crypto/net/ledger/circuit/wallet/node).

## crate `crypto` (`crates/crypto`)

hash, kem, sig, aead — testés. KEM **contributif** : les points X25519 d'ordre
faible sont rejetés à l'encapsulation ET à la décapsulation
(`CryptoError::NonContributif`) — sinon un pair hostile force un DH nul et la
moitié courbes disparaît en silence, ML-KEM portant seul la sécurité.

## crate `net` (`crates/net`)

**Transport chiffré PQ** (phase 4, brique 1/4) — handshake hybride 3 passes
avec **forward secrecy** (éphémères jetés) et **masquage d'identité** (identités
chiffrées sur le fil), machine à états en typestate, canal anti-rejeu par
compteur de séquence en AAD, **cadrage sur le fil** (longueur préfixée, borne
anti-DoS vérifiée AVANT allocation) et `Connexion` générique sur `Read + Write`
(testée sur tuyau mémoire, prête pour TcpStream). Réutilise kem/sig/aead sans
primitive nouvelle. Cadrage SYNCHRONE délibéré : il fixe le FORMAT DE FIL, pas
la stratégie d'E/S — un runtime async plus tard ne changera pas un octet sur le
fil.

**Pairs** (brique 2) : sélection sortante par groupes réseau DISTINCTS
(IPv4 /16, IPv6 /32) — anti-ECLIPSE, car un adversaire qui éclipse un nœud
neutralise entièrement Dandelion++.

**Dandelion++** (brique 4) : successeur stable par ÉPOQUE (la correction qui
distingue ++ de v1 — un successeur par transaction laissait apprendre la
topologie), décision stem/fluff par HACHAGE de (époque, tx, secret) pour
résister au sondage, embargo contre le black-holing.

⚠️ L'anonymat de Dandelion++ REPOSE sur la diversité des pairs (brique 2).

⚠️ L'identité du RÉPONDEUR reste révélée à un MitM actif (inhérent au rôle ;
fermable par un motif Noise-IK pour les sorties) — cf. spec transport-pq.

## crate `ledger` (`crates/ledger`)

Notes engagées, nullifiers, Merkle (BLAKE3, prof. 16 dev / 32 consensus), tx,
validation — testés.

### `bloc` (finalité)

Lot ORDONNÉ chaîné au parent, id = `dual_hash` non tronqué, décodage borné
(`MAX_TX_PAR_BLOC` vérifié AVANT allocation ; `const _: () = assert!` consigne à
la compilation qu'un bloc plein dépasse 30× le cadre réseau).

**Plafond de scellement en OCTETS** : `MAX_OCTETS_BLOC` = cadre réseau −
`crypto::aead::SURCOUT` − marge message (≈ 1 Mio), vérifié au scellement ET au
décodage — `MAX_TX_PAR_BLOC` borne le NOMBRE, pas le POIDS (~9 tx de 105 Kio
suffisent à déborder le cadre), et le cadre borne le CHIFFRÉ, d'où la
soustraction du surcoût AEAD (sans elle, un bloc scellé à la borne était
indiffusable de 5 o).

**Émission (genèse seule)** : `Bloc` porte `emissions: Vec<Emission>` et la règle
est `hauteur > 0 ⇒ emissions.is_empty()` (`BlocRefus::EmissionHorsGenese`),
contrôle O(1) fait AVANT le chaînage, l'instantané et toute vérification STARK.
`mint` est PRIVÉE : la seule création de monnaie est
`ProvedLedgerState::depuis_genese` (la genèse AMORCE, elle ne s'applique pas —
rien à défaire, l'atomicité d'`appliquer_bloc` reste simple).

⚠️ Ce qui protégeait avant n'était pas une règle mais la DIVERGENCE (un mineur
clandestin obtenait une racine que personne n'avait) ; un champ `emissions`
valable à toute hauteur aurait rendu l'inflation diffusée et ACCEPTÉE — ne
jamais l'introduire.

`Emission { commitment, enc_note }` — JAMAIS `Option<EncNote>` : un drapeau de
présence partitionnerait publiquement les feuilles et viderait le
witness-hiding le jour d'une coinbase. Une émission sans bénéficiaire porte une
enveloppe FACTICE chiffrée vers une clé KEM jetable
(`proved_wallet::emission_factice`), de longueur identique à une vraie.
`MAX_EMISSIONS_PAR_BLOC` vérifiée au décodage ET dans `Bloc::genese_avec`.

`VERSION_BLOC` = **0x05** et `VERSION_ETAT` = **0x05** (chaque bump change
l'identifiant de la genèse vide, donc un ancien dump porte une tête périmée :
refusé, pas relu ; un bloc `0x04` rend `BlocDecodeError::VersionPerimee`, refusé
PAR SON NOM). Coinbase toujours hors périmètre (l'élection en est le prérequis,
pas le début).

### Élection de producteur

La genèse peut graver des AUTORITÉS (`genese_avec_autorites`, ≤ 64, dans
l'identifiant — deux listes = deux chaînes) ; producteur légitime de (h, vue) =
`autorites[(h−1+vue) mod n]`, bloc signé (`signer_scellement`, signature sur
l'ID, hors de l'id mais sur le fil), vérifié par `appliquer_bloc` APRÈS le
chaînage (bloc d'une autre chaîne = `ParentInattendu`, pas d'accusation) et
AVANT tout STARK. Scellement manquant/hors tour/étranger = faute sanctionnée ;
genèse SANS autorités = chaîne OUVERTE (défaut, testnet local — un scellement y
est refusé, canonicité).

### Consensus BFT (ADR-001 accepté, J1 complet)

`vue: u32` DANS l'identifiant (deux vues = deux blocs, jamais deux encodages du
même — c'est ce qui permet au certificat de porter sur `(hauteur, vue)` sans
ambiguïté) et `certificat: Option<Certificat>` HORS de l'identifiant (comme le
scellement : une signature sur l'id ne peut pas y entrer).
`Certificat { masque: u64, signatures }` — MASQUE DE BITS, donc doublons de
votant structurellement impossibles, et nombre de signatures DÉRIVÉ du masque au
décodage (jamais annoncé : deux encodages du même certificat seraient
possibles).

`appliquer_bloc` exige le quorum `⌊2n/3⌋ + 1` (`quorum_pour`, égal à `2f+1`
quand `n = 3f+1`), APRÈS le chaînage et le scellement et AVANT tout STARK
(`QuorumInsuffisant`/`VoteInvalide`/`VotantInconnu` ; un certificat sur chaîne
ouverte = `CertificatInattendu`, même raison de canonicité que le scellement).

⚠️ `DOMAINE_VOTE` ≠ `DOMAINE_SCELLEMENT` et ce n'est PAS cosmétique : les deux
signent le même id, donc sans séparation le scellement du producteur compterait
comme un vote et `2f` votes réels afficheraient `2f+1` (test dédié :
`scellement_rejoue_comme_vote_refuse`).

⚠️ AUCUNE agrégation PQ n'existe : le certificat pèse `popcount(masque) × 3374`
o, LINÉAIREMENT et pour toujours (1,0 % du bloc à n=4, 13,8 % à n=64) — la taille
du comité est BORNÉE par le budget du bloc.

**J1-b — protocole de vue (liveness fermée)** : les votes circulent réellement
sur le fil (`Message::Proposition`/`Message::Vote`, cf. `crate node`), la vue
change par délai à backoff exponentiel (`delai_vue(vue) = base × 2^vue`,
plafonné), une proposition d'une vue future n'est adoptée que dans une fenêtre
étroite (`FENETRE_VUE`), et au-delà de `MAX_VUE_PAR_HAUTEUR` la hauteur est
déclarée CALÉE (aveu explicite plutôt que boucle silencieuse). Un nœud ne vote
qu'une fois par HAUTEUR toutes vues confondues (registre persisté, cf.
`node::votes`). **Une chaîne à `n ≥ 4` produit désormais des blocs** — la
liveness que J1-a laissait ouverte est fermée.

**J1-c — changement d'ensemble d'autorités certifié** : `Bloc` porte
`changement_autorites: Option<Vec<SigPublicKey>>`, certifié par le quorum de
l'**ancienne** liste (elle autorise sa propre succession, jamais la nouvelle
elle-même), effectif à `h + K` (`DELAI_CHANGEMENT_AUTORITES = 8`, choisi pour la
COORDINATION d'un réseau fédéré, pas pour la sûreté). Un seul basculement en vol
(`changement_en_attente: Option<(Vec<SigPublicKey>, u64)>`), comité actif
height-aware (`autorites_a(hauteur)`/`quorum_a(hauteur)` : entre `h` et `h + K`
l'ancien comité reste actif, à `h + K` le nouveau prend le relais, pour
l'élection ET le quorum). Un bloc de gouvernance ne porte AUCUNE transaction
(la reconfiguration reste un événement isolé). `VERSION_ETAT = 0x05` grave
`changement_en_attente` (un nœud redémarré entre `h+1` et `h+K` oublierait
sinon le basculement). Changer une autorité n'impose plus une nouvelle chaîne.

### Atomicité et ordre

`ProvedLedgerState::appliquer_bloc` est ATOMIQUE — un bloc à moitié appliqué
placerait le nœud dans un état qu'AUCUN autre n'a, et il refuserait ensuite tout
pour « ancre inconnue » sans que rien ne désigne la cause. Restauration bon
marché grâce à la frontier (clone O(depth)). Les tx s'appliquent DANS L'ORDRE
(une tx peut s'ancrer sur une racine née dans le même bloc — tout valider
d'abord rejetterait ce cas). L'état porte tête + hauteur, sérialisées (sinon un
nœud rechargé ne saurait plus quel bloc attendre).

⚠️ AUCUNE réorganisation possible : l'état est append-only de bout en bout ; les
supporter exigerait de redessiner le ledger.

### Historique des sorties (`ledger::historique`, synchronisation wallet 1/2)

Les sorties insérées dans l'arbre, dans l'ORDRE, découpées par BLOC — chaque
`TrancheBloc` porte la plage de feuilles ET la **racine de fin de bloc** (sans
elle un wallet s'ancrerait au milieu d'un bloc, et `ProvedTx::anchor` étant
public, son ancre deviendrait un pseudonyme). Une entrée =
`(commitment, enc_note)`, JAMAIS d'`Option` — même raison que pour `Emission`.
Rôle SÉPARÉ et OPTIONNEL (`Option<HistoriqueSorties>`, `None` par défaut,
`obscura-node --archiver`) : l'archivage ne change **aucun octet** de l'état de
consensus (testé), et un nœud qui n'archive pas est valide. Écrit UNIQUEMENT par
`amorcer` et `appliquer_bloc` (une seule porte d'insertion) et seulement APRÈS
succès → atomicité structurelle, rien à défaire.

⚠️ **Décision tranchée** : `racine_apres`/`fin` n'entrent PAS dans
`Bloc::to_bytes`, parce que le bloc engage DÉJÀ ses sorties (ses transactions
entières y sont, donc leurs `output_commitments` et `enc_notes` dans l'ordre) —
ce sont des valeurs DÉRIVÉES, les inscrire ne coûterait qu'un bump de
`VERSION_BLOC` et un scellement spéculatif pour zéro bit d'authentification. Ce
qui reste ouvert est écrit : un wallet qui prend historique ET identifiants de
blocs au MÊME nœud n'a rien vérifié.

Coût chiffré : ≈1,4 Kio/sortie, ≈1,4 Mio/bloc plein, ≈12 Gio/jour sous charge ;
jamais élagué (le champ `debut` existe pour que l'élagage soit un changement de
VALEUR, et un historique élagué est REFUSÉ tant que rien ne reconstruit son
préfixe). Persistance : fichier SÉPARÉ (`historique.bin`), écrit AVANT
`etat.bin` (un crash entre les deux laisse l'archive en AVANCE, récupérable, et
non en retard — irrécupérable). `adopter_historique` confronte hauteur, nombre
de feuilles et racine ; un écart n'est JAMAIS réparé en silence (mode dégradé
explicite, fichier intact).

### Mempool (phase 4, brique 3)

Contrôles ordonnés du MOINS au PLUS coûteux — l'asymétrie de coût (~4 ms de
vérification STARK pour ~105 Kio envoyés) est LE vecteur de DoS du projet, donc
les 5 filtres O(1) précèdent la vérification. Capacité bornée SANS éviction (une
éviction permettrait de chasser les tx honnêtes). `Refus::couteux()` distingue
les refus gratuits de celui qui a brûlé du CPU, pour pénaliser le pair en
conséquence.

## crate `circuit` (`crates/circuit`)

Circuit STARK **monolithe** (`monolith/`) — P1–P7 d'une tx en UNE SEULE
trace/preuve, publics minimaux (root, nullifiers, output_commitments, fee).
Depuis **3z-c2** : FORME VARIABLE `m`-in/`n`-out (`1..=MAX = 4`). Une `Forme`
validée pilote schedule, colonnes (`seg_layout::Forme::{rho_c, vout_c, s_col,
width}`), trace (`SegWitness`), AIR (`seg_air`, sélecteurs + assertions +
NOMBRE de contraintes dérivés de la forme).

⚠️ **La forme est portée par les LONGUEURS des publics et PRÉFIXÉE dans
Fiat-Shamir** (`MonolithPublicInputs::to_elements`) : sans ça, deux découpages
des mêmes digests donneraient la même graine (preuve 1/3 rejouable en 2/2).
Robustesse : l'AIR dérive sa forme de la LARGEUR de trace commise (bijective,
`forme_depuis_largeur`), pas des publics — une forme mentie est rejetée, jamais
un accès hors cadre.

`ProvedTx` **v4** (Vec bornés, comptes au wire + `tx_digest`, bornés avant
allocation). **witness-hiding (HVZK en ROM)** depuis 3z-b1, re-vérifié sur 1/1
et 4/4 (le gating `blind_off` couvre toute porteuse nouvelle sans liste).
Soundness variable (C2-T4) : 3 forges D7 (forme liée, fin d'équilibre variable,
ordre publics↔segments), RED sur chacune.

Re-bench prof. 32 : 1/1 ≈ 78 Kio / 1,9 ms ; 2/2 ≈ 97 Kio / 4,0 ms ; 4/4 ≈
114 Kio / 12,3 ms (une `ProvedTx` 2/2 complète pèse ≈105 Kio sur le fil).

⚠️ À ±1,5 Kio près : le masquage tire de l'aléa FRAIS à chaque preuve — une
non-régression de taille est une BANDE, jamais une égalité.

⚠️ Ces tailles intègrent le DURCISSEMENT de soundness du 2026-07-22 (32 → 48
requêtes FRI) : les chiffres antérieurs (55,7 / 67,7 / 80,3) sont CADUQUES — ils
valaient 62 bits prouvés.

Le **côte-à-côte** (201 col, oracle de parité 2/2) est SUPPRIMÉ (C2-T8) : ses
helpers partagés (`MonolithPublicInputs`, `push_preamble`,
`key_rows`/`sponge_rows_for`, témoins de test) vivent dans `monolith/socle.rs`
(module SANS layout — pur déplacement, zéro octet de comportement changé), et la
géométrie 2/2 reste ÉPINGLÉE par des constantes `#[cfg(test)]` de `seg_layout`
(`forme_2_2_identique_aux_constantes` : un refactor de `Forme` ne peut pas
déplacer un offset 2/2 en silence — la 2/2 est du consensus). Forges à
reconstruction d'arbre rejouées à la profondeur CONSENSUS (D8 soldée : arbre
synthétique index 0/3 + frères muets, RED × 5 forges à prof. 32).

Caveat : honnête-vérifieur, prototype non audité (voir
`docs/STARK_STATEMENT.md`, « Argument HVZK »). Les gadgets autonomes du crate
restent validity-only.

`ProvedTx` v4 porte les `enc_notes` (enveloppes chiffrées des sorties, une par
sortie, scan wallet via `ledger::proved_wallet`), liées dans `tx_digest` v4
(anti-substitution + comptes m/n) ; P8 différé, IK-CCA = phase 4. Sérialisation
wire **canonique** `ProvedTx::{to_bytes, from_bytes}` (+`TxDecodeError`) :
`from_bytes` = point d'entrée réseau validant (curseur borné sans panique,
digests canoniques, bornes EncNote anti-DoS, rejet des octets résiduels), pas de
serde.

## crate `wallet` (`crates/wallet`)

Détention de notes, scan, construction de transactions. Tient son PROPRE
`ProvedMerkleTree` — le nœud n'ayant qu'une frontier, il ne peut pas produire
les chemins d'appartenance qu'exigent les preuves (partage de rôles décidé en
brique frontier).

⚠️ `observer()` doit être appelé pour CHAQUE commitment dans le MÊME ordre que
le nœud, sinon les index divergent.

Monnaie rendue toujours produite ET chiffrée vers soi-même.

**Clé d'intention NEUVE à chaque transaction** : `ProvedTx::signer` est public et
circule en clair — une clé stable serait un pseudonyme permanent reliant toutes
nos transactions, annulant montants engagés, destinataires chiffrés,
witness-hiding et Dandelion++ d'un seul coup. Licite car la signature d'intention
est une enveloppe d'anti-malléabilité, pas une autorité de propriété. Même raison
pour l'identité de transport du CLI, éphémère elle aussi.

**`adresse`** : encodage textuel `obs1‖hex(version‖owner‖kem_pk‖somme)` — la
somme de contrôle existe parce qu'un paiement vers une adresse abîmée est
irréversible et SILENCIEUX (aucun secret ne correspond au owner altéré) ;
⚠️ elle détecte l'accident, PAS l'adversaire (courte, non clefée). ~2,5 Kio, prix
des clés PQ.

**`persistance`** : `to_bytes_secret`/`charger`/`enregistrer` — le fichier le
plus sensible du projet (autorité de DÉPENSE). `0600` posé avant écriture,
atomique, empreinte `dual_hash` NON tronquée (un octet retourné dans un montant
donnerait sinon un solde faux sans erreur), cohérence croisée note↔arbre au
chargement. Aucune variante « charger ou créer » : un fichier illisible ne doit
jamais devenir un wallet vide. Chiffré au repos (Argon2id + cascade AEAD,
`Protection` obligatoire et explicite — `Aucune` est un choix assumé, jamais un
défaut) ; un fichier en clair n'est relu QUE sous `Protection::Aucune` (phrase
fournie ⇒ `FichierEnClair`, la migration est un geste : `OBSCURA_WALLET_MIGRER=1`
côté CLI). `oublier_depensees(&tx)` reconnaît nos notes en RECALCULANT leurs
nullifiers — marche donc sur toute transaction observée, pas seulement les
nôtres.

**`synchro`** (rejeu de l'historique, synchronisation 3/3) :
`Wallet::synchroniser` rejoue UN bloc donné par TOUS ses morceaux — il n'existe
aucun tampon partiel, donc rien de « à moitié appliqué » à persister.
L'invariant d'ordre est STRUCTUREL : la position (`prochaine_hauteur`) est
mémorisée et un lot qui ne commence pas exactement là où le wallet s'est arrêté
est REFUSÉ, en hauteur ET en feuille ; un bloc déjà rejoué rend
`Statut::DejaApplique` (idempotent, et DIT — un `Ok` muet ferait croire à une
boucle qu'elle progresse). Morceaux RANGÉS par index (jamais concaténés),
couverture vérifiée par CUMUL (le client n'a pas à connaître la taille de
morceau du serveur), index rendu par l'arbre confronté à `decalage + i`.
Application ATOMIQUE : racine ≠ `racine_apres` ⇒ `ProvedMerkleTree::tronquer`
ramène l'arbre à son préfixe exact ; le SCAN (une décapsulation KEM par sortie,
le vrai coût) n'a lieu qu'APRÈS l'acceptation de la racine. `hauteur_tete` est
**absente du type rejoué** — la forme la plus forte de « elle ne pilote rien ».

**L'ANCRE** : `feuilles_ancrees` retient la dernière frontière de bloc et
`construire` refuse (`ArbreHorsFrontiereDeBloc`) de prouver contre un arbre qui
l'a dépassée — une ancre à mi-bloc serait un pseudonyme, et rien en aval ne
pourrait la distinguer d'une ancre légitime. Fichier de wallet en **0x02** (la
position y entre) ; un 0x01 est refusé par sa propre variante, jamais
réinterprété.

⚠️ Le mensonge par OMISSION reste indétectable côté wallet seul (la racine
annoncée est cohérente) — il est fermé par le TÉMOIN côté client (cf.
`crate node`) ; l'arbre du wallet reste en O(n). La BOUCLE de synchronisation
est câblée (voir `node::client` et `obscura-wallet synchroniser` sous
`crates/node`).

## crate `node` (`crates/node`)

**Câblage** des briques réseau et consensus (phase 5).

`message` = protocole applicatif (Annonce/Demande/Transaction, plus
Proposition/Vote pour le consensus) : on annonce des DIGESTS (~64 o), jamais les
transactions (~105 Kio) — envoyer spontanément la tx à chaque pair offrirait une
amplification à l'attaquant. Décodage borné (`MAX_DIGESTS`) vérifié AVANT
allocation. Il dépend de `net` ET du consensus, ce qui garde justement `net` PUR
TRANSPORT.

`orchestration` = ce qu'un nœud FAIT d'un message, en fonction PURE (retourne
des Actions, aucune E/S) — c'est ce qui rend toute la politique testable sans
réseau. `runtime` = l'EXÉCUTION (sockets, un thread de lecture par connexion,
boucle d'événements). Lecture et écriture d'une connexion sont DÉCOUPLÉES
(`Session::separer`, possible grâce aux clés directionnelles) : sinon un pair
silencieux figerait aussi les envois vers lui.

✅ Testnet local validé : une transaction PROUVÉE se propage entre nœuds réels
sur de vraies sockets, y compris à travers un INTERMÉDIAIRE (A→B→C). Chemin
exercé : sérialisation → cadrage → chiffrement → socket → déchiffrement →
décodage → admission (5 filtres O(1) puis STARK) → mempool. `Noeud::soumettre` =
point d'entrée d'une transaction LOCALE (wallet) : part en TIGE Dandelion++, pas
en diffusion — c'est là que l'origine est protégée.

### Exploitation (T4)

`node::journal` — journalisation à NIVEAUX sur stderr
(`OBSCURA_LOG=erreur|avert|info|debug`, une valeur inconnue AVERTIT et retombe
sur info plutôt que de faire taire le nœud), horodatée en UPTIME et non en date
absolue (systemd/Docker horodatent déjà ; l'uptime, lui, n'est pas dérivable de
leurs logs). Aucune dépendance ajoutée. **Ligne de STATUT toutes les 30 s**
(hauteur, pairs, liens, mempool, désaccords) qui passe en AVERT si `liens = 0` ou
`désaccords > 0` — les deux pannes SILENCIEUSES du protocole, un nœud isolé ou
décroché servant sinon un historique cohérent mais tronqué. Déploiement :
`deploiement/{obscura-node.service,Dockerfile}` (systemd durci, image non-root en
deux étapes) et `docs/OPERATEUR.md`.

### Binaires

- **`obscura-node`** (nœud autonome) et **`obscura-demo`** (démonstration
  locale : wallet → preuve → handshake PQ → socket → mempool, chaque étape
  annoncée).
- **`obscura-genese`** (4e binaire) : fabrique le bloc 0 — autorités
  (`--autorite <identite.cle>` ou `--autorite-hex`, la bonne voie en fédération)
  et allocations chiffrées vers des adresses `obs1…`. REFUSE d'écraser (une
  genèse remplacée = chaîne perdue), AUTO-VÉRIFIE (relit + réamorce ce qu'il
  écrit), borne les montants à 2^60 (au-delà la note serait INDÉPENSABLE —
  range-check), et imprime l'identifiant court À COMPARER entre opérateurs avant
  démarrage. Sans lui, geler une chaîne exigeait d'écrire du Rust ad hoc pour
  l'artefact le moins rattrapable du projet.
- **`obscura-node --identite`** (imprime la clé publique du nœud sur stdout, puis
  SORT) : sans elle, `--autorite-hex` — la voie recommandée, celle où personne ne
  transmet son fichier d'identité — n'avait AUCUNE source d'entrée, et la
  fédération était donc inaccessible sans écrire du Rust. Les deux moitiés du
  geste vivent dans `node::autorite` (`encoder`/`decoder`, utilisé par les DEUX
  binaires) précisément pour qu'un test les confronte : séparées, un préfixe ou
  une majuscule les feraient diverger, et l'échec n'apparaîtrait qu'au moment de
  graver une chaîne.
- **`obscura-wallet`** (3e binaire) : `creer` (REFUSE d'écraser — un wallet
  écrasé est irrécupérable, aucune option ne force), `adresse`, `synchroniser`,
  `solde`, `envoyer` (preuve → handshake PQ éphémère → socket → mempool ; envoie
  AVANT d'oublier les notes, l'ordre inverse perdrait des notes jamais dépensées
  si l'envoi échouait). Chemin couvert par
  `crates/node/tests/paiement_wallet.rs`, qui va de l'adresse TEXTUELLE jusqu'au
  déchiffrement par le bénéficiaire.

### Persistance du nœud

`node::persistance` : identité + état survivent aux redémarrages (`--donnees`) —
sans quoi les pairs ne reconnaîtraient pas le nœud et un nœud malveillant se
blanchirait en redémarrant. Fichier d'identité en `0600` sur Unix, écriture
atomique, JAMAIS régénéré en silence si corrompu.

⚠️ Mempool non persisté (sans gravité : réannoncé par les pairs) ; clé NON
chiffrée au repos (une phrase de passe supposerait une saisie interactive).

### Boucle de synchronisation (`node::client`)

`obscura-wallet synchroniser --noeud` demande `hauteur = prochaine_hauteur()` et
RIEN d'autre, rassemble tous les morceaux du bloc, rejoue UNE fois par
`Wallet::synchroniser`, enregistre APRÈS chaque bloc, et s'arrête au premier
SILENCE. `hauteur_tete` ne pilote rien (le wallet ne la voit même pas) ;
`DejaApplique` n'est PAS un pas (arrêt, sinon boucle sur place) ; le travail est
BORNÉ par invocation (`MAX_BLOCS_PAR_INVOCATION`, abandon nommé plutôt que boucle
sur un nœud qui sert sans fin). Débit réglé par la FRÉQUENCE des demandes, jamais
par un champ sur le fil.

**TÉMOIN** (`synchroniser_avec_temoin`, `obscura-wallet synchroniser --temoin`) :
un SECOND nœud interrogé sur la MÊME hauteur, dont on ne retient que
`racine_apres`. Ferme le mensonge par OMISSION — qui était indétectable auprès
d'un nœud unique, parce que taire une sortie donne une chaîne close dont la
racine annoncée est cohérente ; aucun contrôle LOCAL ne pouvait le démentir, il
fallait un identifiant venu d'AILLEURS. La comparaison a lieu AVANT application
(vérifier après coup laisserait l'arbre peuplé d'index faux, et `synchroniser` ne
défait que ce qu'il vient d'insérer). Un témoin MUET n'est PAS un accord
(`Arret::TemoinMuet` : arrêt sans appliquer — un nœud sans `--archiver` ou à
crédit épuisé se tait, et poursuivre serait un placebo). Toute anomalie du témoin
vaut MUET, jamais désaccord : `Arret::Desaccord` est le seul arrêt qui accuse, et
il dit qu'un des deux ment sans dire lequel. Ferme AUSSI la tête RACCOURCIE :
quand le servant se TAIT, la même question est reposée au témoin, et s'il sert
cette hauteur le wallet n'est pas à jour (`Arret::TeteRetenue`) — c'était le pire
mode d'échec, parce qu'un silence est indistinguable d'une chaîne épuisée et
qu'un nœud sans `--archiver` produisait « à jour, 0 bloc » avec l'air satisfait ;
deux silences valent à jour, sinon toute synchronisation finirait par un
avertissement.

⚠️ Le témoin n'a de valeur que choisi INDÉPENDAMMENT (le protocole ne peut pas
vérifier l'indépendance). Le prix est le doublement de la BANDE PASSANTE, pas du
scan (une seule décapsulation KEM par sortie, côté servant). `envoyer` REFUSE si
`prochaine_hauteur() == 0` (jamais synchronisé) et propose `--noeud-synchro`
DISTINCT de `--noeud` (avertissement quand ils coïncident) : enchaîner synchro
puis envoi depuis la même IP relie les deux et désigne l'émetteur, alors qu'un
relais Dandelion++ ne vient jamais de se synchroniser.

Cycle complet payer → sceller → recevoir → monnaie rendue → redépenser exercé
sur de vraies sockets (`crates/node/tests/cycle_wallet.rs`).

### Finalité et consensus câblés

**Finalité** : `Message::Bloc` (diffusé ENTIER — un bloc neuf n'est connu de
personne, l'aller-retour annonce/demande ne ferait que retarder), `Noeud::sceller`
(tri par `tx_digest` → deux nœuds scellant le même mempool produisent le MÊME
bloc ; ⚠️ grindable, à changer quand l'ordre aura de la valeur), `sur_bloc`
(bloc non chaîné = AUCUNE sanction — c'est le cas normal de deux scellements
simultanés ou d'un retard ; seule une tx invalide dans un bloc bien chaîné
pénalise). `obscura-node --sceller <ms>`, **OFF par défaut** : produire des blocs
est une décision d'opérateur.

**Élection de producteur CÂBLÉE** : sur une chaîne à autorités, `Noeud::sceller`
refuse hors de son tour (rien ne part) et SIGNE à son tour de l'identité
persistante du nœud (plus une identité jetable — une autorité re-clefée à chaque
démarrage ne serait jamais reconnue) ; `sur_bloc` sanctionne un scellement
manquant/hors tour/étranger comme une transaction invalide. Chaîne ouverte
(genèse sans autorités) : comportement historique, ordre CONVENU pas DÉFENDU.
Testé sur sockets (`finalite.rs::deux_autorites_alternent_sur_sockets`).

**Protocole de vue (J1-b, `node::orchestration` + `node::votes`)** : un
producteur diffuse `Message::Proposition(Bloc)`, chaque autorité répond par
`Message::Vote`, et le producteur rassemble les votes des AUTRES autorités (plus
seulement le sien) jusqu'au quorum, qu'il grave dans le certificat du bloc. La
vue avance par délai à backoff exponentiel quand le quorum n'arrive pas
(`producteur_attendu(h, vue+1)` prend la main), avec fenêtre d'adoption d'une vue
future et plafond `MAX_VUE_PAR_HAUTEUR` au-delà duquel la hauteur est déclarée
CALÉE (split de votes, journal CRITIQUE). `node::votes::RegistreVotes` (format
`VERSION_VOTES = 0x02`, clé `hauteur` seule) est persisté AVANT l'émission et
n'autorise qu'UN id par HAUTEUR toutes vues confondues : deux quorums à la même
hauteur partagent un votant honnête qui n'a signé qu'un id — c'est ce qui rend
la sûreté triviale. **Une chaîne à `n ≥ 4` produit des blocs.**

**Changement d'autorités CÂBLÉ (J1-c)** : `changement_autorites` proposé par un
producteur, certifié par le quorum de l'ancienne liste, appliqué à `h + K` par le
comité height-aware — testé sur sockets réelles
(`crates/node/tests/reconfiguration.rs`). Reconfigurer un comité ne crée plus une
nouvelle chaîne.

### Corrections issues de la revue adversariale

(Détail : `docs/THREAT_MODEL.md`, « Défauts trouvés par revue adversariale ».)
`sceller` PLAFONNE à `MAX_TX_PAR_BLOC` ET à `MAX_OCTETS_BLOC` (une borne de
`from_bytes` doit exister aussi dans le CONSTRUCTEUR, sinon elle ne protège que
l'entrant — et la variante OCTETS du même défaut est fermée par le plafond de
scellement, cf. `crate ledger`) ; `RECENT_ROOTS_WINDOW` = 4 blocs pleins +
assertion de compilation (à 100, un bloc chargé purgeait toutes les ancres →
transactions en vol refusées, et censure à coût nul par un scelleur adverse) ;
une VERSION inconnue ne pénalise plus (sinon une mise à jour bannit les nœuds en
arrière et effondre l'anti-eclipse) ; échéances lecture/écriture sur chaque
socket AVANT le handshake (⚠️ une échéance de LECTURE = pair silencieux, PAS lien
mort — la confondre couperait tous les liens toutes les 20 s) ;
`blocs_desaccordes` rend visible un nœud figé.

### Rattrapage de bloc

`Message::DemandeBloc { hauteur }` + `node::archive` : un nœud qui manque une
hauteur la REDEMANDE et rejoint la chaîne — prérequis, car un nœud figé sert un
historique plus court mais parfaitement COHÉRENT, donc tout wallet qui s'y
synchronise se croit à jour. Réponse = `Message::Bloc`, appliquée par le chemin
NORMAL (aucun raccourci). `ArchiveBlocs` = N derniers blocs appliqués, bornée
DEUX fois (64 blocs ET 64 Mio : un bloc plein pèse ~34 Mio, donc 64 blocs pleins
vaudraient ~2,1 Gio) et distincte de l'état consensus. Anti-boucle : une demande
ne naît que d'un bloc REÇU, le déclencheur est une inégalité STRICTE
(`recue > hauteur+1`), et un rattrapage infructueux s'arrête au premier pas —
sinon deux nœuds désaccordés se demanderaient des blocs à l'infini. Testé sur
sockets réelles (`crates/node/tests/rattrapage.rs`).

### Genèse explicite

`obscura-node --genese <fichier>` (décodé par `Bloc::from_bytes`, ÉCHEC FRANC si
absent/corrompu — aucun repli, un nœud mal amorcé est indiscernable d'un nœud
neuf sain). Sans l'option : genèse VIDE par défaut, AFFICHÉE. L'identifiant de
genèse (8 o hex) est imprimé au démarrage pour être comparé entre opérateurs.
`persistance::charger_ou_amorcer_etat(&genese)`. L'état GRAVE sa genèse
(`VERSION_ETAT` 0x05) : un répertoire peuplé par une AUTRE chaîne est REFUSÉ au
démarrage avec les deux identifiants (`GeneseDifferente`) — plus de divergence
silencieuse par mauvais `--donnees`.

### Archivage des sorties

`obscura-node --archiver` (OFF par défaut, rôle d'opérateur),
`persistance::charger_ou_amorcer_archive` + `historique.bin` écrit AVANT
`etat.bin` — en JOURNAL EN AJOUT (`VERSION_JOURNAL` 0x02, dump 0x01 migré une
fois) : seules les tranches nouvelles sont écrites, puis `sync_all`. Queue
partielle (crash en plein ajout) écartée + tronquée au chargement — inoffensif
par l'ordre historique-avant-état ; corruption interne = REFUS, jamais de
troncature. Le test anti-régression utilise un CANARI `.tmp` en lecture seule
(une mesure de taille est tautologique : réécriture et ajout produisent le même
delta). Une archive absente ou désaccordée fait démarrer le nœud en mode
DÉGRADÉ (sans archive), bruyamment, sans rien tronquer. Activer l'archivage TROP
TARD (état déjà avancé, pas de fichier) est REFUSÉ : une archive partielle
servirait des index décalés de tout le préfixe manquant sans que rien ne le
dise.

### Service d'historique (synchronisation wallet 2/2, côté nœud)

`node::synchro` (format de fil) + `node::etranglement` (seaux à jetons) +
`Message::{DemandeHistorique, Historique}`. La demande porte **la position et
RIEN d'autre** (9 o, longueur exacte) : un `max` ou une plage seraient une
empreinte de client qui survit à l'identité de transport éphémère. L'unité
servie est **le BLOC** (`debut`/`fin`/`racine_apres`), pas la plage de feuilles —
`ProvedTx::anchor` étant public, un wallet arrêté à une feuille publierait une
ancre quasi unique. Le **découpage est décidé par le SERVEUR** (un bloc plein
≈1,4 Mio > cadre de 1 Mio) et **canonique** : `morceaux`/`decalage`/nombre
d'entrées sont RECALCULÉS au décodage, ce qui ferme recouvrements, morceaux
fantômes et segmentation-marqueur. `MAX_SORTIES_PAR_REPONSE` (739) est **calculé**
sur `MAX_CADRE − crypto::aead::SURCOUT (68) − en-tête` : le cadrage borne le
CHIFFRÉ.

**Étranglement indexé sur `GroupeReseau`, JAMAIS sur `PeerId`** (une identité est
gratuite, le wallet en tire une neuve à chaque commande) ; le **nombre de
requêtes** est facturé (`COUT_REQUETE` débité avant de savoir si on sert),
recharge comptée en millièmes (tronquée à l'entier, un pair bavard ne regagnerait
jamais rien) ; à crédit épuisé **SILENCE**, jamais de réponse courte, et **AUCUNE
sanction** (le score gouverne la sélection sortante). Adresse fournie par le
runtime dans une table SÉPARÉE de `TablePairs` (y verser les entrants leur
ouvrirait nos emplacements sortants) ; sans adresse connue → **fail-closed**.
`hauteur_tete` est une INDICATION non vérifiable qui ne pilote rien (la position
n'avance que sur la tranche demandée) ; `hauteur_tete < hauteur` est refusé au
décodage. Testé sur sockets réelles (`crates/node/tests/synchronisation.rs`).

Le REJEU côté wallet est fait (`wallet::synchro`) et le pont est
`ReponseHistorique::pour_le_wallet` ; la BOUCLE est câblée dans `node::client`
(`synchroniser_par_connexion`) et exposée par `obscura-wallet synchroniser` (cf.
« Boucle de synchronisation » ci-dessus).

⚠️ Restent ouverts : `ArchiveBlocs` (blocs récents, rattrapage) NON persistée —
à ne pas confondre avec l'historique des sorties, qui l'est ; un nœud sur une
chaîne DIVERGENTE ne se répare pas (état append-only) ; le découpage
multi-morceaux n'est testé qu'au niveau du FORMAT (une genèse plafonne à
512 < 739 ; l'atteindre sur socket exigerait ≈370 preuves STARK).

## Notes de build (features dev / consensus)

- **Features de dev, OFF par défaut** (le build/test nu = surface CONSENSUS
  seule) : `dev-transparent` (ledger : mode transparent non-privé,
  `apply_transparent`, `build_transparent_transaction`, `merkle`/`note` BLAKE3)
  et `dev-circuits` (circuit : sous-circuits autonomes `prove_*`/`verify_*`). La
  suite complète = `cargo test --all-features --release`. Ne jamais ajouter de
  dépendance du consensus vers du code gaté (l'invariant « défaut = consensus
  seul » doit tenir, et il est vérifié en CI). Les modules gadgets restent
  compilés (le monolithe réutilise leurs helpers `pub(crate)`) ; seules leurs
  entrées publiques standalone sont gatées.
- **Migration FIPS 203/204 : FAITE** (T1, `858da4a`) — `pqcrypto-mlkem` et
  `pqcrypto-mldsa`, version d'algo `0x02`. Ce ne fut pas un changement d'import :
  FIPS 203/204 diffèrent du round-3 (dérivation, encodages, errata NIST). ⚠️ Le
  `0x01` ne COHABITE PAS : il est refusé par son nom (`CryptoError::AlgoPerime`)
  — aucun réseau public n'ayant existé en round-3, supporter deux versions
  n'aurait acheté qu'une surface de confusion. Autorité : `docs/PROTOCOL.md`,
  versioning. Reste ouvert : les vecteurs de conformité officiels (voir
  `docs/CONFORMITE.md` §1 et `docs/superpowers/plans/2026-07-22-porte-aud.md`).
- ⚠️ **DETTE DE BACKEND PQ (ouverte)** : TOUTE la famille `pqcrypto` est marquée
  `unmaintained` (RUSTSEC 2026-0161/0166/0162/0163) — PQClean est ARCHIVÉ en
  amont. La migration FIPS (T1) a DÉPLACÉ cette dette, pas supprimée :
  `pqcrypto-mlkem` et `pqcrypto-mldsa` portent leurs propres avis, au même titre
  que les round-3 qu'elles remplacent. Les avis sont ignorés PAR LEUR NOM dans
  `deny.toml` (jamais par un filtre large, qui masquerait une vraie vulnérabilité
  de la même famille). Sortie propre = backend hors pqcrypto. Évaluation, thèse
  (« unmaintained » n'est pas une vulnérabilité) et critères de re-test avant le
  gel de genèse : **`docs/BACKEND_PQ.md`** fait autorité.
- **Zeroize (durcissement #7)** : `ShieldedSecret` (volatile non élidable),
  `WalletKeys::{shielded_secret, nk}` et les clés AEAD dérivées s'effacent au
  drop ; les moitiés dalek (X25519/Ed25519) aussi. Les secrets **ML-KEM et
  ML-DSA aussi**, par le repli T1.5 : stockés en `Zeroizing<Vec<u8>>`, le type
  pqcrypto étant RECONSTRUIT à chaque usage (`crypto::kem`, `crypto::sig`) —
  coût, un `from_bytes` par opération, hors chemin chaud. Autorité :
  `docs/PROTOCOL.md`.
- **Prototype pédagogique** : pas d'audit, ne pas utiliser en production.
