# Obscura — contexte projet pour Claude Code

Monnaie numérique privée post-quantique. Prototype Rust — les phases 1 à 5 sont
prototypées et testées : nœud persistant, cycle complet payer → sceller → recevoir
validé sur testnet local.

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
  **`bloc`** (finalité) : lot ORDONNÉ chaîné au parent, id = `dual_hash` non tronqué,
  décodage borné (MAX_TX_PAR_BLOC vérifié AVANT allocation ; `const _: () = assert!`
  consigne à la compilation qu'un bloc plein dépasse 30× le cadre réseau).
  **Émission (genèse seule)** : `Bloc` porte `emissions: Vec<Emission>` et la règle est
  `hauteur > 0 ⇒ emissions.is_empty()` (`BlocRefus::EmissionHorsGenese`), contrôle O(1)
  fait AVANT le chaînage, l'instantané et toute vérification STARK. `mint` est PRIVÉE :
  la seule création de monnaie est `ProvedLedgerState::depuis_genese` (la genèse AMORCE,
  elle ne s'applique pas — rien à défaire, l'atomicité d'`appliquer_bloc` reste simple).
  ⚠️ Ce qui protégeait avant n'était pas une règle mais la DIVERGENCE (un mineur
  clandestin obtenait une racine que personne n'avait) ; un champ `emissions` valable à
  toute hauteur aurait rendu l'inflation diffusée et ACCEPTÉE — ne jamais l'introduire.
  `Emission { commitment, enc_note }` — JAMAIS `Option<EncNote>` : un drapeau de
  présence partitionnerait publiquement les feuilles et viderait le witness-hiding le
  jour d'une coinbase. Une émission sans bénéficiaire porte une enveloppe FACTICE
  chiffrée vers une clé KEM jetable (`proved_wallet::emission_factice`), de longueur
  identique à une vraie. `MAX_EMISSIONS_PAR_BLOC` vérifiée au décodage ET dans
  `Bloc::genese_avec`. `VERSION_BLOC` = 0x02 et `VERSION_ETAT` = 0x02 (l'identifiant de
  la genèse vide change, donc un ancien dump porte une tête périmée : refusé, pas relu).
  `ProvedLedgerState::appliquer_bloc` est ATOMIQUE — un bloc à moitié appliqué
  placerait le nœud dans un état qu'AUCUN autre n'a, et il refuserait ensuite tout
  pour « ancre inconnue » sans que rien ne désigne la cause. Restauration bon marché
  grâce à la frontier (clone O(depth)). Les tx s'appliquent DANS L'ORDRE (une tx peut
  s'ancrer sur une racine née dans le même bloc — tout valider d'abord rejetterait ce
  cas). L'état porte tête + hauteur, sérialisées (sinon un nœud rechargé ne saurait
  plus quel bloc attendre). ⚠️ AUCUNE réorganisation possible : l'état est append-only
  de bout en bout ; les supporter exigerait de redessiner le ledger.
  **Historique des sorties** (`ledger::historique`, synchronisation wallet 1/2) : les
  sorties insérées dans l'arbre, dans l'ORDRE, découpées par BLOC — chaque `TrancheBloc`
  porte la plage de feuilles ET la **racine de fin de bloc** (sans elle un wallet
  s'ancrerait au milieu d'un bloc, et `ProvedTx::anchor` étant public, son ancre
  deviendrait un pseudonyme). Une entrée = `(commitment, enc_note)`, JAMAIS d'`Option` —
  même raison que pour `Emission`. Rôle SÉPARÉ et OPTIONNEL (`Option<HistoriqueSorties>`,
  `None` par défaut, `obscura-node --archiver`) : l'archivage ne change **aucun octet**
  de l'état de consensus (testé), et un nœud qui n'archive pas est valide. Écrit
  UNIQUEMENT par `amorcer` et `appliquer_bloc` (une seule porte d'insertion) et
  seulement APRÈS succès → atomicité structurelle, rien à défaire.
  ⚠️ **Décision tranchée** : `racine_apres`/`fin` n'entrent PAS dans `Bloc::to_bytes`,
  parce que le bloc engage DÉJÀ ses sorties (ses transactions entières y sont, donc
  leurs `output_commitments` et `enc_notes` dans l'ordre) — ce sont des valeurs DÉRIVÉES,
  les inscrire ne coûterait qu'un `VERSION_BLOC` 0x03 et un scellement spéculatif pour
  zéro bit d'authentification. Ce qui reste ouvert est écrit : un wallet qui prend
  historique ET identifiants de blocs au MÊME nœud n'a rien vérifié.
  Coût chiffré : ≈1,4 Kio/sortie, ≈1,4 Mio/bloc plein, ≈12 Gio/jour sous charge ; jamais
  élagué (le champ `debut` existe pour que l'élagage soit un changement de VALEUR, et un
  historique élagué est REFUSÉ tant que rien ne reconstruit son préfixe).
  Persistance : fichier SÉPARÉ (`historique.bin`), écrit AVANT `etat.bin` (un crash
  entre les deux laisse l'archive en AVANCE, récupérable, et non en retard —
  irrécupérable). `adopter_historique` confronte hauteur, nombre de feuilles et racine ;
  un écart n'est JAMAIS réparé en silence (mode dégradé explicite, fichier intact).
  **Mempool** (phase 4, brique 3) : contrôles ordonnés du MOINS au PLUS coûteux —
  l'asymétrie de coût (~4 ms de vérification STARK pour ~68 Kio envoyés) est LE
  vecteur de DoS du projet, donc les 5 filtres O(1) précèdent la vérification.
  Capacité bornée SANS éviction (une éviction permettrait de chasser les tx
  honnêtes). `Refus::couteux()` distingue les refus gratuits de celui qui a brûlé
  du CPU, pour pénaliser le pair en conséquence.
- `crates/circuit` : circuit STARK **monolithe** (`monolith/`) — P1–P7 d'une tx
  en UNE SEULE trace/preuve, publics minimaux (root, nullifiers, output_commitments,
  fee). Depuis **3z-c2** : FORME VARIABLE `m`-in/`n`-out (`1..=MAX = 4`). Une `Forme`
  validée pilote schedule, colonnes (`seg_layout::Forme::{rho_c, vout_c, s_col,
  width}`), trace (`SegWitness`), AIR (`seg_air`, sélecteurs + assertions + NOMBRE de
  contraintes dérivés de la forme). ⚠️ **La forme est portée par les LONGUEURS des
  publics et PRÉFIXÉE dans Fiat-Shamir** (`MonolithPublicInputs::to_elements`) : sans
  ça, deux découpages des mêmes digests donneraient la même graine (preuve 1/3
  rejouable en 2/2). Robustesse : l'AIR dérive sa forme de la LARGEUR de trace
  commise (bijective, `forme_depuis_largeur`), pas des publics — une forme mentie est
  rejetée, jamais un accès hors cadre. `ProvedTx` **v4** (Vec bornés, comptes au wire
  + `tx_digest`, bornés avant allocation). **witness-hiding (HVZK en ROM)** depuis
  3z-b1, re-vérifié sur 1/1 et 4/4 (le gating `blind_off` couvre toute porteuse
  nouvelle sans liste). Soundness variable (C2-T4) : 3 forges D7 (forme liée, fin
  d'équilibre variable, ordre publics↔segments), RED sur chacune. Re-bench prof. 32 :
  1/1 = 55,7 Kio / 1,6 ms ; 2/2 = 67,7 Kio / 3,8 ms (non-régression) ; 4/4 =
  80,3 Kio / 12,6 ms. ⚠️ Le **côte-à-côte** (201 col, oracle de parité 2/2) n'est
  PAS encore supprimé — retrait = extraire ses helpers partagés (`MonolithPublicInputs`,
  `push_preamble`), refactor transverse différé pour ne pas toucher le consensus à la
  hâte ; il est `#[allow(dead_code)]`, hors chemin de prod. Forges à reconstruction
  d'arbre encore en profondeur 2 (dette D8).
  Caveat : honnête-vérifieur, prototype non audité (voir docs/STARK_STATEMENT.md,
  « Argument HVZK »). Les gadgets autonomes du crate restent validity-only.
  `ProvedTx` v4 porte les `enc_notes` (enveloppes chiffrées des sorties, une par
  sortie, scan wallet via `ledger::proved_wallet`), liées dans `tx_digest` v4
  (anti-substitution + comptes m/n) ; P8
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
  **Clé d'intention NEUVE à chaque transaction** : `ProvedTx::signer` est public et
  circule en clair — une clé stable serait un pseudonyme permanent reliant toutes
  nos transactions, annulant montants engagés, destinataires chiffrés,
  witness-hiding et Dandelion++ d'un seul coup. Licite car la signature d'intention
  est une enveloppe d'anti-malléabilité, pas une autorité de propriété. Même raison
  pour l'identité de transport du CLI, éphémère elle aussi.
  **`adresse`** : encodage textuel `obs1‖hex(version‖owner‖kem_pk‖somme)` — la somme
  de contrôle existe parce qu'un paiement vers une adresse abîmée est irréversible
  et SILENCIEUX (aucun secret ne correspond au owner altéré) ; ⚠️ elle détecte
  l'accident, PAS l'adversaire (courte, non clefée). ~2,5 Kio, prix des clés PQ.
  **`persistance`** : `to_bytes_secret`/`charger`/`enregistrer` — le fichier le plus
  sensible du projet (autorité de DÉPENSE). `0600` posé avant écriture, atomique,
  empreinte `dual_hash` NON tronquée (un octet retourné dans un montant donnerait
  sinon un solde faux sans erreur), cohérence croisée note↔arbre au chargement.
  Aucune variante « charger ou créer » : un fichier illisible ne doit jamais devenir
  un wallet vide. ⚠️ NON chiffré au repos.
  `oublier_depensees(&tx)` reconnaît nos notes en RECALCULANT leurs nullifiers —
  marche donc sur toute transaction observée, pas seulement les nôtres.
  **`synchro`** (rejeu de l'historique, synchronisation 3/3) : `Wallet::synchroniser`
  rejoue UN bloc donné par TOUS ses morceaux — il n'existe aucun tampon partiel, donc
  rien de « à moitié appliqué » à persister. L'invariant d'ordre est STRUCTUREL : la
  position (`prochaine_hauteur`) est mémorisée et un lot qui ne commence pas exactement
  là où le wallet s'est arrêté est REFUSÉ, en hauteur ET en feuille ; un bloc déjà rejoué
  rend `Statut::DejaApplique` (idempotent, et DIT — un `Ok` muet ferait croire à une
  boucle qu'elle progresse). Morceaux RANGÉS par index (jamais concaténés), couverture
  vérifiée par CUMUL (le client n'a pas à connaître la taille de morceau du serveur),
  index rendu par l'arbre confronté à `decalage + i`. Application ATOMIQUE : racine ≠
  `racine_apres` ⇒ `ProvedMerkleTree::tronquer` ramène l'arbre à son préfixe exact ; le
  SCAN (une décapsulation KEM par sortie, le vrai coût) n'a lieu qu'APRÈS l'acceptation
  de la racine. `hauteur_tete` est **absente du type rejoué** — la forme la plus forte de
  « elle ne pilote rien ». **L'ANCRE** : `feuilles_ancrees` retient la dernière frontière
  de bloc et `construire` refuse (`ArbreHorsFrontiereDeBloc`) de prouver contre un arbre
  qui l'a dépassée — une ancre à mi-bloc serait un pseudonyme, et rien en aval ne pourrait
  la distinguer d'une ancre légitime. Fichier de wallet en **0x02** (la position y entre) ;
  un 0x01 est refusé par sa propre variante, jamais réinterprété.
  ⚠️ Le mensonge par OMISSION reste indétectable (la racine annoncée est cohérente) ;
  l'arbre du wallet reste en O(n). La BOUCLE de synchronisation est câblée (voir
  `node::client` et `obscura-wallet synchroniser` sous `crates/node`).
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
  **`obscura-wallet`** (3e binaire) : `creer` (REFUSE d'écraser — un wallet écrasé
  est irrécupérable, aucune option ne force), `adresse`, `synchroniser`, `solde`,
  `envoyer` (preuve → handshake PQ éphémère → socket → mempool ; envoie AVANT d'oublier
  les notes, l'ordre inverse perdrait des notes jamais dépensées si l'envoi échouait).
  Chemin couvert par `crates/node/tests/paiement_wallet.rs`, qui va de l'adresse
  TEXTUELLE jusqu'au déchiffrement par le bénéficiaire.
  **Boucle de synchronisation** (`node::client`) : `obscura-wallet synchroniser --noeud`
  demande `hauteur = prochaine_hauteur()` et RIEN d'autre, rassemble tous les morceaux
  du bloc, rejoue UNE fois par `Wallet::synchroniser`, enregistre APRÈS chaque bloc, et
  s'arrête au premier SILENCE. `hauteur_tete` ne pilote rien (le wallet ne la voit
  même pas) ; `DejaApplique` n'est PAS un pas (arrêt, sinon boucle sur place) ; le
  travail est BORNÉ par invocation (`MAX_BLOCS_PAR_INVOCATION`, abandon nommé plutôt que
  boucle sur un nœud qui sert sans fin). Débit réglé par la FRÉQUENCE des demandes,
  jamais par un champ sur le fil. `envoyer` REFUSE si `prochaine_hauteur() == 0` (jamais
  synchronisé) et propose `--noeud-synchro` DISTINCT de `--noeud` (avertissement quand
  ils coïncident) : enchaîner synchro puis envoi depuis la même IP relie les deux et
  désigne l'émetteur, alors qu'un relais Dandelion++ ne vient jamais de se synchroniser.
  Cycle complet payer → sceller → recevoir → monnaie rendue → redépenser exercé sur de
  vraies sockets (`crates/node/tests/cycle_wallet.rs`).
  **Finalité câblée** : `Message::Bloc` (diffusé ENTIER — un bloc neuf n'est connu de
  personne, l'aller-retour annonce/demande ne ferait que retarder), `Noeud::sceller`
  (tri par `tx_digest` → deux nœuds scellant le même mempool produisent le MÊME bloc ;
  ⚠️ grindable, à changer quand l'ordre aura de la valeur), `sur_bloc` (bloc non
  chaîné = AUCUNE sanction — c'est le cas normal de deux scellements simultanés ou
  d'un retard ; seule une tx invalide dans un bloc bien chaîné pénalise).
  `obscura-node --sceller <ms>`, **OFF par défaut** : produire des blocs est une
  décision d'opérateur. ⚠️ Aucune élection de producteur — ordre CONVENU, pas DÉFENDU.
  **Corrections issues de la revue adversariale** (détail : docs/THREAT_MODEL.md,
  « Défauts trouvés par revue adversariale ») : `sceller` PLAFONNE à MAX_TX_PAR_BLOC
  (une borne de `from_bytes` doit exister aussi dans le CONSTRUCTEUR, sinon elle ne
  protège que l'entrant) ; `RECENT_ROOTS_WINDOW` = 4 blocs pleins + assertion de
  compilation (à 100, un bloc chargé purgeait toutes les ancres → transactions en vol
  refusées, et censure à coût nul par un scelleur adverse) ; une VERSION inconnue ne
  pénalise plus (sinon une mise à jour bannit les nœuds en arrière et effondre
  l'anti-eclipse) ; échéances lecture/écriture sur chaque socket AVANT le handshake
  (⚠️ une échéance de LECTURE = pair silencieux, PAS lien mort — la confondre couperait
  tous les liens toutes les 20 s) ; `blocs_desaccordes` rend visible un nœud figé.
  **Rattrapage de bloc** (`Message::DemandeBloc { hauteur }` + `node::archive`) : un
  nœud qui manque une hauteur la REDEMANDE et rejoint la chaîne — prérequis, car un
  nœud figé sert un historique plus court mais parfaitement COHÉRENT, donc tout wallet
  qui s'y synchronise se croit à jour. Réponse = `Message::Bloc`, appliquée par le
  chemin NORMAL (aucun raccourci). `ArchiveBlocs` = N derniers blocs appliqués, bornée
  DEUX fois (64 blocs ET 64 Mio : un bloc plein pèse ~34 Mio, donc 64 blocs pleins
  vaudraient ~2,1 Gio) et distincte de l'état consensus. Anti-boucle : une demande ne
  naît que d'un bloc REÇU, le déclencheur est une inégalité STRICTE
  (`recue > hauteur+1`), et un rattrapage infructueux s'arrête au premier pas — sinon
  deux nœuds désaccordés se demanderaient des blocs à l'infini. Testé sur sockets
  réelles (`crates/node/tests/rattrapage.rs`).
  **Genèse explicite** : `obscura-node --genese <fichier>` (décodé par `Bloc::from_bytes`,
  ÉCHEC FRANC si absent/corrompu — aucun repli, un nœud mal amorcé est indiscernable
  d'un nœud neuf sain). Sans l'option : genèse VIDE par défaut, AFFICHÉE. L'identifiant
  de genèse (8 o hex) est imprimé au démarrage pour être comparé entre opérateurs.
  `persistance::charger_ou_amorcer_etat(&genese)`. L'état GRAVE sa genèse (`VERSION_ETAT` 0x03) :
  un répertoire peuplé par une AUTRE chaîne est REFUSÉ au démarrage avec les deux
  identifiants (`GeneseDifferente`) — plus de divergence silencieuse par mauvais
  `--donnees`.
  **Archivage des sorties** : `obscura-node --archiver` (OFF par défaut, rôle
  d'opérateur), `persistance::charger_ou_amorcer_archive` + `historique.bin` écrit AVANT
  `etat.bin` — en JOURNAL EN AJOUT (`VERSION_JOURNAL` 0x02, dump 0x01 migré une fois) :
  seules les tranches nouvelles sont écrites, puis `sync_all`. Queue partielle (crash en
  plein ajout) écartée + tronquée au chargement — inoffensif par l'ordre
  historique-avant-état ; corruption interne = REFUS, jamais de troncature. Le test
  anti-régression utilise un CANARI `.tmp` en lecture seule (une mesure de taille est
  tautologique : réécriture et ajout produisent le même delta).
  Une archive absente ou désaccordée fait démarrer le nœud en mode DÉGRADÉ
  (sans archive), bruyamment, sans rien tronquer. Activer l'archivage TROP TARD (état
  déjà avancé, pas de fichier) est REFUSÉ : une archive partielle servirait des index
  décalés de tout le préfixe manquant sans que rien ne le dise.
  **Service d'historique** (synchronisation wallet 2/2, côté nœud) : `node::synchro`
  (format de fil) + `node::etranglement` (seaux à jetons) + `Message::{DemandeHistorique,
  Historique}`. La demande porte **la position et RIEN d'autre** (9 o, longueur exacte) :
  un `max` ou une plage seraient une empreinte de client qui survit à l'identité de
  transport éphémère. L'unité servie est **le BLOC** (`debut`/`fin`/`racine_apres`), pas
  la plage de feuilles — `ProvedTx::anchor` étant public, un wallet arrêté à une feuille
  publierait une ancre quasi unique. Le **découpage est décidé par le SERVEUR** (un bloc
  plein ≈1,4 Mio > cadre de 1 Mio) et **canonique** : `morceaux`/`decalage`/nombre
  d'entrées sont RECALCULÉS au décodage, ce qui ferme recouvrements, morceaux fantômes et
  segmentation-marqueur. `MAX_SORTIES_PAR_REPONSE` (739) est **calculé** sur
  `MAX_CADRE − crypto::aead::SURCOUT (68) − en-tête` : le cadrage borne le CHIFFRÉ.
  **Étranglement indexé sur `GroupeReseau`, JAMAIS sur `PeerId`** (une identité est
  gratuite, le wallet en tire une neuve à chaque commande) ; le **nombre de requêtes** est
  facturé (`COUT_REQUETE` débité avant de savoir si on sert), recharge comptée en
  millièmes (tronquée à l'entier, un pair bavard ne regagnerait jamais rien) ; à crédit
  épuisé **SILENCE**, jamais de réponse courte, et **AUCUNE sanction** (le score gouverne
  la sélection sortante). Adresse fournie par le runtime dans une table SÉPARÉE de
  `TablePairs` (y verser les entrants leur ouvrirait nos emplacements sortants) ;
  sans adresse connue → **fail-closed**. `hauteur_tete` est une INDICATION non vérifiable
  qui ne pilote rien (la position n'avance que sur la tranche demandée) ; `hauteur_tete <
  hauteur` est refusé au décodage. Testé sur sockets réelles
  (`crates/node/tests/synchronisation.rs`).
  ⚠️ Restent : `executer` tient le verrou pendant l'écriture ; le service de BLOCS
  n'est **pas étranglé** (amplification 9 o → jusqu'à 34 Mio ; le seau écrit lui est
  applicable tel quel, il n'y est pas branché) ; `ArchiveBlocs` (blocs récents,
  rattrapage) NON persistée — à ne pas confondre avec l'historique des sorties, qui
  l'est ; un nœud sur une chaîne DIVERGENTE ne se répare pas (état append-only) ;
  le découpage multi-morceaux n'est testé qu'au niveau du FORMAT (une genèse plafonne à
  512 < 739 ; l'atteindre sur socket exigerait ≈370 preuves STARK).
  Le REJEU côté wallet est fait (`wallet::synchro`) et le pont est
  `ReponseHistorique::pour_le_wallet` ; la BOUCLE est câblée dans `node::client`
  (`synchroniser_par_connexion`) et exposée par `obscura-wallet synchroniser` — cf.
  `crates/node`, « Boucle de synchronisation ».
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
1. **3z-c2 — variabilité M-in/N-out ≤ MAX — LIVRÉE (C2-T1..T7)** : circuit,
   trace, AIR, soundness, masquage, ProvedTx v4, wallet (note unique paie,
   `consolider`, défaut 2/2). Reste C2-T8 partiel : la SUPPRESSION du côte-à-côte
   (refactor transverse d'extraction de helpers, différé) et les forges à
   reconstruction d'arbre en profondeur 32 (dette D8). — Ancien texte de suivi :
   la couture `SegKind`/schedule était
   en place depuis 3z-c1 ; la bascule supprimera le côte-à-côte (aujourd'hui
   conservé comme oracle de parité — mêmes publics, même témoin). Restent aussi
   2 forges non portées (`PaddingMerkle`, `VaccInitial` fine) et les forges à
   reconstruction d'arbre qui restent en profondeur 2.
   ⚠️ Piège identifié à ne pas rejouer : mutualiser des colonnes peut SUPPRIMER
   une garantie que la redondance offrait gratuitement (cf. « Liaison de racine »
   dans STARK_STATEMENT.md) — auditer chaque fusion sous cet angle.
2. **SYNCHRONISATION WALLET ↔ NŒUD — CONSERVE ✅, SERT ✅, REJOUE ✅, BOUCLE ✅.**
   `ledger::historique` conserve et persiste ; `node::{synchro, etranglement}` le SERVENT
   sur le fil ; `wallet::synchro` le REJOUE ; `node::client` + `obscura-wallet
   synchroniser` câblent la BOUCLE. **Le wallet REÇOIT**, monnaie rendue comprise, et le
   cycle payer → sceller → recevoir → redépenser est exercé sur de vraies sockets
   (`crates/node/tests/cycle_wallet.rs`). ⚠️ L'émission est RÉGLÉE (genèse seule, `mint`
   privée) ; une coinbase reste hors périmètre. Ce qui reste ouvert (cf.
   docs/THREAT_MODEL.md) : le nœud servant apprend IP/cadence/position et peut MENTIR PAR
   OMISSION ; le rôle d'archiviste est coûteux ; l'arbre du wallet reste en O(n).
3. Persistance du wallet ✅ / du nœud ✅ / CLI ✅ / genèse paramétrée ✅ (faits) ;
   reste le chiffrement au repos du fichier de wallet (Argon2 + saisie interactive).

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
