# Élection de producteur — design (chantier « point 5 »)

**Date :** 2026-07-21
**Contexte :** dernier verrou avant un déploiement public (la preuve est faite,
la gouvernance du scellement ne l'est pas) ; prérequis de toute coinbase.
**Statut :** approuvé (« ok go », 2026-07-22) et IMPLÉMENTÉ — option A retenue
pour la liveness (la chaîne attend). Écarts d'implémentation par rapport au texte :
une genèse SANS autorités reste une chaîne OUVERTE (comportement historique du
testnet local, un scellement y est refusé pour préserver la canonicité) ;
`VERSION_ETAT` est passé à 0x04 (les autorités entrent dans le dump d'état).
Tests : unités ledger/node + `deux_autorites_alternent_sur_sockets` (finalite.rs).

## Le problème, exactement

Aujourd'hui `obscura-node --sceller <ms>` donne à N'IMPORTE QUEL opérateur le
pouvoir de fabriquer des blocs. Sur un testnet local entre nos propres nœuds,
c'est un choix d'opérateur ; sur un réseau public, c'est une absence de règle :
l'ordre des transactions est CONVENU (tri par `tx_digest`), pas DÉFENDU. Deux
nœuds qui scellent en même temps produisent deux blocs de même hauteur, et
l'état étant **append-only sans aucune réorganisation**, le premier bloc reçu
gagne — la « règle » de consensus est alors la latence réseau.

## La contrainte qui commande tout le design

**AUCUNE réorganisation possible** (décision d'architecture du ledger, coûteuse
à défaire). Toute divergence est donc DÉFINITIVE. Conséquence : l'élection ne
peut pas être un mécanisme de *résolution* de fourches (longest chain, poids,
fork choice) — il n'y a rien à résoudre après coup. Elle doit garantir
l'**unicité du bloc par hauteur PAR CONSTRUCTION**, avant diffusion.

Cela disqualifie d'emblée, pour ce ledger :
- toute élection par loterie (PoW, VRF-PoS) : deux gagnants simultanés y sont
  un événement NORMAL, résolu par fork choice — que nous n'avons pas ;
- tout slot purement temporel sans attestation : deux vues de l'horloge font
  deux chaînes, définitivement.

## Proposition : autorités gravées en genèse, tour de rôle par hauteur

La forme la plus simple qui donne l'unicité par construction — et cohérente
avec le cap « complétude/cohérence protocole avant sophistication crypto » :

1. **La genèse porte la liste des autorités de scellement** : `Vec<SigPublicKey>`
   (identités hybrides Ed25519+Dilithium3, celles que `node::persistance` gère
   déjà). Comme les émissions, la liste entre dans l'encodage de la genèse, donc
   dans son IDENTIFIANT : deux réseaux aux autorités différentes sont deux
   chaînes distinctes dès l'octet zéro, et `GeneseDifferente` refuse déjà le
   mélange. Borne `MAX_AUTORITES` (64 ?) vérifiée au décodage ET au constructeur.
2. **Producteur légitime de la hauteur h** : `autorites[(h − 1) mod n]` — tour
   de rôle déterministe, zéro octet de protocole nouveau pour l'élection
   elle-même. (h − 1 : la genèse n'a pas de producteur, elle AMORCE.)
3. **Le bloc est signé par son producteur** : `Bloc` v0x03 gagne un champ
   `scellement : HybridSignature` sur `dual_hash("obscura/bloc/scellement/v1" ‖
   id_du_bloc)`. L'id engage déjà parent, hauteur, transactions et émissions —
   signer l'id suffit, aucun champ nouveau n'entre dans l'id lui-même.
4. **Règle de validation** (dans `sur_bloc`, AVANT le chaînage et tout coût
   STARK, O(1) + une vérification de signature) : un bloc de hauteur h dont la
   signature ne vérifie pas sous `autorites[(h − 1) mod n]` est REFUSÉ — et
   c'est une FAUTE (pénalisation du pair relayeur), contrairement au bloc non
   chaîné qui reste sans sanction (cas normal du retard).
5. **`--sceller` devient conditionnel** : le nœud refuse de sceller si son
   identité n'est pas l'autorité de la prochaine hauteur. Produire hors de son
   tour n'est même pas diffusable — chaque récepteur le refuse en O(1).

L'équivocation (une autorité signe DEUX blocs à la même hauteur) reste
possible physiquement mais devient une **faute prouvable** : deux signatures
valides du même producteur sur deux ids différents de même hauteur sont une
preuve portable, à consigner (bannissement local immédiat ; l'exclusion de la
liste est une décision de gouvernance, cf. limites).

## La décision qui reste à trancher : la LIVENESS

C'est LE point que ce design ne peut pas trancher seul, parce que chaque option
achète l'unicité à un prix différent :

- **Option A — la chaîne attend.** Producteur absent ⇒ aucune hauteur produite
  jusqu'à son retour. Unicité parfaite, zéro hypothèse d'horloge, zéro octet de
  protocole en plus. Prix : un seul nœud en panne fige le réseau (les
  transactions s'accumulent en mempool, rien n'est perdu). **Recommandée pour
  le premier réseau public** : le prix est visible et honnête, et c'est la
  seule option qui n'introduit AUCUNE hypothèse nouvelle.
- **Option B — certificat de saut.** Après une échéance locale, les autorités
  signent « la hauteur h est sautée » ; un quorum (⌈2n/3⌉) forme un certificat
  qui s'insère dans le bloc suivant (le bloc de h+1 embarque le certificat de
  saut de h). L'échéance reste une affaire LOCALE (chacun décide quand signer) ;
  seule la pièce SIGNÉE fait foi, donc pas d'hypothèse d'horloge commune dans
  la règle de validation. Prix : un embryon de BFT (collecte, quorum, format de
  certificat, anti-rejeu) — précisément la sophistication que le cap actuel
  diffère.
- **Option C — slots temporels.** Rejetée : sans certificat, elle réintroduit
  l'horloge dans la règle de consensus, et deux vues du temps forkeraient un
  ledger qui ne sait pas fusionner.

Chemin proposé : **A maintenant, B comme évolution** (le format v0x03 réserve
la place : un octet de version de scellement dans le champ, pour que B soit une
version de BLOC, pas un redémarrage de chaîne).

## Ce que ce design NE fait PAS (garde-fous)

- **Pas de coinbase.** Les émissions hors genèse restent refusées
  (`EmissionHorsGenese`). Ce design est le PRÉREQUIS d'une coinbase (il rend
  « le producteur de h » vérifiable, donc un bénéficiaire légitime nommable),
  mais l'émission par bloc est un chantier SÉPARÉ — monnaie, halving, enveloppe
  factice par bloc — à n'ouvrir qu'une fois le producteur stabilisé.
- **Pas d'élection ouverte** (PoS, enchères, rotation dynamique). La liste est
  STATIQUE ; en changer = nouvelle genèse = nouvelle chaîne, assumé et affiché.
  C'est une fédération, et le README doit le dire avec ces mots.
- **Pas de résistance à la censure du producteur.** L'autorité du jour choisit
  ses transactions ; le tri canonique par `tx_digest` reste une CONVENTION de
  reproductibilité, pas une défense. Documenté dans THREAT_MODEL (le mempool
  borné sans éviction limite déjà le coût d'une censure : la tx attend le
  producteur suivant).

## Impacts code (estimation, dans l'ordre)

1. `ledger::bloc` : champ `scellement` + `autorites` en genèse, `VERSION_BLOC`
   0x03, bornes au décodage ET aux constructeurs, id de genèse changé →
   `VERSION_ETAT` 0x04 (le motif exact du passage 0x01→0x02 se rejoue).
2. `ledger::proved_state` : `appliquer_bloc` vérifie producteur + signature
   (sauf genèse) — le contrôle le MOINS cher d'abord, comme au mempool.
3. `node::orchestration` : `sur_bloc` pénalise le bloc mal scellé ; `sceller`
   refuse hors tour ; `Noeud` connaît son identité de signature (déjà le cas).
4. `obscura-node` : message clair au démarrage (« autorité 3/7, prochaine
   hauteur à sceller : 12 »), `--sceller` sans être autorité = avertissement
   au lancement, refus au moment de sceller.
5. Tests : refus mauvais producteur / mauvaise signature / équivocation
   détectée ; rotation sur n autorités ; rattrapage et synchronisation wallet
   INCHANGÉS (aucun octet nouveau hors du bloc) ; testnet local à 2 autorités
   sur sockets réelles.

## Tests de soundness du design (avant d'écrire du code)

- Deux autorités scellent la même hauteur (réseau partitionné) : chacune signe
  SON bloc → équivocation impossible sans faute (un seul producteur légitime),
  divergence impossible sans équivocation. À rejouer sur sockets.
- Un opérateur non-autorité lance `--sceller` : aucun octet ne part.
- Une autorité relaie un bloc d'une autre chaîne (genèse différente) :
  `GeneseDifferente` le refuse AVANT la vérification de scellement.
