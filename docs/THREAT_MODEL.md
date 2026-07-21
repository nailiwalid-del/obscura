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
   (`blocs_desaccordes`) le rend visible. **Le rattrapage de bloc reste a ecrire** :
   il n'existe aucun moyen de redemander une hauteur manquante.

### Trou restant : un wallet ne peut toujours pas RECEVOIR

Il lui faut rejouer dans l'ordre tous les commitments insérés dans l'arbre pour en
connaître les index et produire ses chemins de Merkle ; or le nœud n'en conserve pas
l'historique (`MerkleFrontier` = bord droit seulement) et n'a rien à servir. Le paiement
fonctionne de bout en bout (`crates/node/tests/paiement_wallet.rs`), mais la monnaie
rendue sort de la vue du wallet faute d'index.

C'est le prochain manque structurel : un noeud doit conserver et servir l'historique des
sorties, et un wallet doit pouvoir le rejouer.

**Contraintes de conception deja etablies par la revue** - a respecter quand cette
brique sera ecrite, car chacune corrige un defaut identifie dans les premieres
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
