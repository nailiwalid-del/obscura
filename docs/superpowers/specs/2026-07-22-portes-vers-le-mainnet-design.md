# Portes vers le mainnet — carte de décision

**Date :** 2026-07-22
**Objet :** les quatre portes que `2026-07-22-testnet-public-0-design.md` avait
écartées comme « non planifiables » — audits, consensus public défendable,
économie, durcissement.
**Statut :** carte d'arbitrage validée. **Ce document ne contient aucun spec
implémentable** ; chaque porte obtient ensuite son propre cycle spec → plan.

---

## Décisions prises (utilisateur, ne pas remettre en cause)

1. **Destination : B comme état cible livrable, A comme norme de conception.**
   On construit sous le modèle d'adversaire d'un mainnet — quelqu'un qui a un
   motif de profit — parce que c'est le seul modèle qui rende le travail
   honnête. On ne livre que jusqu'à B, et on n'engage aucune dépense externe
   tant que B n'est pas atteint et stable.
2. **Posture publique : B. Norme interne : A.** Viser A en ingénierie ne coûte
   rien ; *l'annoncer* crée l'attente, l'exposition juridique, et contredit la
   règle déjà écrite (« aucune communication du type monnaie utilisable »).
3. **Ordonnancement : deux voies séparées par leur réversibilité** (option 3),
   et non une séquence unique.
4. **Branchement : ouvrir d'abord** (T5–T7), les portes s'appliquent ensuite à
   un réseau vivant. Une chaîne de testnet est **consommable**.
5. **Ce document est une carte, pas un plan.** Le premier spec implémentable
   sera celui de la porte que cette carte désigne.

### Ce que A et B exigent, et où ils divergent

| Porte | Commun à A et B | Ce que **A seul** ajoute |
|---|---|---|
| **Durcissement** | tout | **rien** |
| **Audits** | être auditable : spec gelée, vecteurs officiels, surface réduite, bug bounty | passer commande (argent, calendrier subi) |
| **Économie** | le **mécanisme** : coinbase prouvée, collecteur de frais, marché de frais | la **politique** : courbe d'émission, halving, queue |
| **Consensus** | élection ouverte, absence de réorg défendue, partitions, négociation de version | **anti-Sybil à coût réel** |

Trois lectures de ce tableau, et elles fondent tout le reste :

- Sur deux portes et demie, **A et B ne divergent pas du tout**. « Être
  auditable » est un préfixe strict de « être audité » : aucun travail n'est
  perdu si la commande vient plus tard.
- La divergence se réduit à **deux décisions** — la courbe d'émission et le coût
  de l'anti-Sybil — et ce sont les deux dernières dans l'ordre de toute façon,
  la seconde dépendant de la première.
- **Dans les deux portes qui divergent, la partie difficile est celle qui est
  commune.** La coinbase prouvée est du travail de circuit ; la courbe
  d'émission est un tableur.

D'où : viser A en exigence, livrer B, laisser les deux décisions divergentes
ouvertes avec des critères écrits.

---

## Constats de vérification (2026-07-22, `HEAD = 1f73e46`)

L'état réel du dépôt ne correspond pas à ce que les documents annoncent sur deux
points. Les deux sont des faits, vérifiés dans le code, pas des impressions.

### Constat 1 — `CLAUDE.md` annonce une dette qui est fermée

`CLAUDE.md` écrit encore : « les `SecretKey` pqcrypto NE s'effacent PAS
(limitation crate) — à fermer à la migration FIPS `0x02` ». **C'est fait.** Le
repli prévu par T1.5 est implémenté : les secrets ML-KEM et ML-DSA sont stockés
en `Zeroizing<Vec<u8>>` et le type pqcrypto est reconstruit à chaque usage
(`crates/crypto/src/kem.rs:54`, `crates/crypto/src/sig.rs:51`).

**Action :** corriger `CLAUDE.md`. Une dette annoncée ouverte alors qu'elle est
fermée fait perdre du temps à un auditeur, et fait douter du reste du document.

### Constat 2 — les vecteurs KAT n'existent pas

Aucun fichier de `crates/` ne contient de vecteurs KAT/ACVP ;
`crates/crypto/tests/` n'existe pas. Or c'était un **critère de sortie de T1**
(§T1.6 du spec Testnet 0), dont le texte disait : « c'est la première chose
qu'un auditeur demandera ».

**T1 a donc été déclaré terminé sans son critère de sortie le plus important
pour la suite.** Le fait est consigné ici parce qu'il est le premier travail de
la porte AUD, et parce qu'il rappelle qu'un critère de sortie non vérifié ne
vaut pas mieux que pas de critère.

---

## Partie I — La structure de la carte

### Ce qu'est une porte

Pas une tâche : une fiche à six entrées, toujours les mêmes.

1. **État vérifié** — ce que le code fait, avec fichier et ligne. Pas ce que la
   doc affirme (cf. constats ci-dessus).
2. **Ce qui manque** — l'écart énoncé comme un **défaut**, jamais comme une
   fonctionnalité. Un défaut se ferme ou s'inscrit dans les limites connues ; une
   fonctionnalité se reporte indéfiniment.
3. **Dépend de** — quelles portes précèdent.
4. **Gèle quoi** — format de fil, format de bloc, énoncé STARK, genèse. C'est
   cette colonne qui rend l'ordre non négociable.
5. **Critère de franchissement** — une phrase **falsifiable**. « Le fuzzing
   tourne » n'en est pas un ; « les quatre cibles de l'anneau 1 tournent 24 h
   sans crash » en est un.
6. **Coût, et qui le paie** — en particulier ce qui n'est pas du temps
   d'ingénierie.

### Les deux voies

```
VOIE SANS REGRET  ──────────────────────────────────────────►  (continue)
  D. Durcissement · AUD. Auditabilité
  ne gèle rien · ne dépend de rien · jamais jeté

VOIE IRRÉVERSIBLE  ──►  J1 Modèle  ──►  J2 Mécanisme  ──►  J3 Consensus
                        de consensus     économique        implémenté
  gèle des formats · strictement séquencée en interne
```

La voie sans regret n'a pas de fin : c'est un **régime de travail**, pas un
chantier. Elle **démarre immédiatement et tourne en parallèle de T5–T7** — elle
n'attend pas l'ouverture, puisqu'elle ne dépend de rien. La voie irréversible a
trois jalons et s'arrête à B.

**Pourquoi cette séparation plutôt qu'une séquence.** Durcissement et
auditabilité ne dépendent réellement de rien : les bloquer derrière une décision
de consensus qui peut prendre des mois est du gaspillage pur, et ce sont
justement les deux dont le résultat n'est jamais perdu. À l'inverse, la voie
irréversible est fortement couplée en interne — voir J1 → J2 ci-dessous, où le
modèle de consensus détermine un *champ* du mécanisme économique et pas
seulement son paramétrage.

### Le branchement : ouvrir d'abord

`T5` (ouverture), `T6` (faucet, explorateur, monitoring) et `T7` (wallet UX) ne
sont pas faits, mais l'outillage l'est (`obscura-genese`, `--identite`, témoin
de synchronisation). Ils s'exécutent **avant** les portes.

Le prix est réel et doit être écrit : la genèse sera figée **avant** que
l'économie soit décidée, donc le mécanisme économique arrivera par une nouvelle
chaîne. L'`extension` réservée du bloc `0x03` permet de ne pas refondre le
format ; elle ne permet pas de ne pas repartir de zéro.

**Ce prix est acceptable parce que, sous B, une chaîne de testnet est
consommable.** La documentation dit déjà que changer la liste d'autorités =
nouvelle genèse = nouvelle chaîne, et que les fonds n'ont aucune valeur. Refaire
une genèse quand l'économie sera prête n'est donc pas un échec : c'est le
fonctionnement normal d'un testnet — **à condition que ce soit écrit d'avance
dans les limites connues, et pas subi.**

En échange, on obtient ce qu'aucune quantité de spec ne remplace : un réseau qui
tombe, des wallets qui se désynchronisent, un archiviste qui grossit.

⚠️ Le seul cas où ce branchement est mauvais est celui où la chaîne serait
annoncée comme durable. La posture publique fixée l'interdit.

---

## Partie II — Les cinq fiches

### Porte D — Durcissement

**État vérifié.** Beaucoup est fait, et c'est solide : fuzzing des deux anneaux,
CI à six jobs sur deux plateformes, décodage borné avant allocation partout,
échéances de socket posées avant le handshake, étranglement indexé sur
`GroupeReseau`, atomicité d'`appliquer_bloc`, zeroize — clés PQ comprises
(constat 1).

**Ce qui manque — quatre défauts.**

1. **Une autorité absente fige la chaîne définitivement.** L'option A (aucun
   certificat de saut) est assumée et documentée. Sous B, avec un réseau public,
   c'est la panne numéro un et non un cas limite : un opérateur qui redémarre son
   VPS arrête le réseau.
2. **Le fuzzing ne peut pas atteindre la logique de validation.** Un fuzzer
   aléatoire ne produira jamais une preuve STARK valide : `ProvedTx::from_bytes`
   est fuzzé, mais tout ce qui est **derrière** le décodeur ne l'est pas. Il
   manque du fuzzing *structure-aware* — générer des transactions valides puis
   muter les champs sémantiques (ancre, nullifiers, forme `m`/`n`) plutôt que les
   octets.
3. **La dette backend PQ n'a pas d'échéance portée par un jalon.**
   `docs/BACKEND_PQ.md` conclut « ne pas migrer maintenant » — décision non
   remise en cause — et écrit ses critères de re-test « avant le gel de genèse ».
   Rien aujourd'hui ne porte cette échéance. Voir partie III.
4. **Les canaux auxiliaires ne sont pas dans le modèle.** Sous une thèse
   post-quantique, le temps constant des opérations ML-KEM/ML-DSA est une
   question légitime, et `docs/THREAT_MODEL.md` ne la traite pas. Ce n'est
   peut-être pas un chantier — mais l'absence doit être **décidée**, pas subie.

**Dépend de :** rien. **Gèle :** rien.
**Critère de franchissement :** le réseau survit à l'arrêt **et au retour** de
son producteur ; le fuzzing sémantique tourne au budget nocturne sans crash ;
les quatre défauts sont soit fermés, soit inscrits dans les limites connues
**avec leur raison**.
**Coût :** temps d'ingénierie seul.

### Porte AUD — Auditabilité

**État vérifié.** `PROTOCOL.md` (235 l.), `THREAT_MODEL.md` (738 l.),
`STARK_STATEMENT.md` (695 l.) ; gating dev/consensus effectif ; double licence ;
dépôt public.

**Ce qui manque — trois défauts.**

1. **Les vecteurs KAT ML-KEM-768 et ML-DSA-65 (constat 2).** Le moins cher et le
   plus rentable des trois. C'est ce qui distingue « on a changé d'import » de
   « on implémente bien FIPS 203/204 ».
2. **La source de vérité est `CLAUDE.md`, et un auditeur ne le lira pas.** C'est
   le document le plus détaillé et le plus à jour du dépôt, et il est structuré
   comme des notes d'agent, pas comme une spécification. Tant que `docs/` en est
   un résumé, un audit porterait sur un texte incomplet. Il ne s'agit pas
   d'écrire plus, mais de **déplacer l'autorité** de `CLAUDE.md` vers `docs/`.
3. **L'argument HVZK est honnête-vérifieur et non audité.** C'est le seul
   morceau du projet qui ne peut pas être préparé seul : il exige un spécialiste
   circuit/AIR. Sous B, la préparation consiste à rendre l'énoncé **attaquable**
   — hypothèses isolées, ce qui est prouvé séparé de ce qui est supposé.

**Dépend de :** rien, pour (1) et (2). Le bug bounty dépend d'une cible
publique, donc de l'ouverture.
**Gèle :** rien — mais **consomme** un gel, un audit portant sur une spec figée.
**Critère de franchissement :** les vecteurs KAT passent en CI ; un tiers peut
vérifier un bloc de la chaîne publique **en n'ayant lu que `docs/`**.
**Coût :** temps d'ingénierie seul. **Zéro dépense externe** — c'est la
définition d'« être auditable » plutôt qu'« être audité ».

### Jalon J1 — Le modèle de consensus

**Livrable : un modèle choisi et défendu par écrit. Rien d'autre.** C'est le
jalon le moins coûteux en lignes et le plus coûteux en conséquences.

**État vérifié.** `crates/ledger/src/bloc.rs:33` — « Aucune réorganisation n'est
possible, par construction » ; aucun fork choice nulle part dans le dépôt. Un
producteur légitime par hauteur, tour de rôle `autorites[(h−1) mod n]`.

**L'espace de choix, et son asymétrie.**

| | Préserve l'acquis ? | Anti-Sybil | Coût |
|---|---|---|---|
| **(i) BFT à finalité instantanée, appartenance ouverte** | **oui, entièrement** | admission au comité (caution / stake) | protocole de vue, quorum, messages en O(n²) |
| **(ii) Nakamoto (chaîne la plus longue)** | **non** — exige un fork choice, donc des réorgs, donc la refonte du ledger, de l'historique, de la synchro wallet et des ancres | éprouvé, vraiment ouvert | énorme, et il jette une part importante de ce qui est livré |
| **(iii) Fédération à liste tournante** | oui | faible — la liste reste une autorité | modeste, mais ne satisfait pas « défendable » au sens fort |

**L'argument à ne pas manquer.** L'architecture actuelle — append-only, sans
réorg, un producteur légitime par hauteur — **est déjà un BFT dégénéré**.
L'évolution naturelle vers un consensus public n'est donc pas Nakamoto, mais un
BFT dont l'appartenance s'ouvre. Dans ce monde, « défendre un modèle sans
réorg » n'est pas une excuse : c'est la thèse.

Et surtout : **en (i), le jalon J1 et le défaut n°1 de la porte D sont le même
problème.** Un BFT a besoin d'un protocole de vue avec délais et changement de
vue — exactement le mécanisme qui fait qu'une autorité absente ne fige plus la
chaîne. Choisir (i) ferme la liveness par construction. Aucune des deux autres
options ne fait ça.

Ce document **ne tranche pas** : c'est le premier travail de la voie
irréversible. Il pose la décision avec son asymétrie visible, parce qu'elle
n'est pas symétrique du tout — (ii) est la seule qui détruise de l'acquis, et
elle le détruit largement.

**Dépend de :** rien. **Gèle :** l'architecture.
**Critère de franchissement :** un tiers hostile ne peut pas produire deux
chaînes valides divergentes de même hauteur sans violer une hypothèse **écrite** ;
et le réseau reprend après défaillance de `f` participants, avec `f` énoncé.
**Coût :** faible en lignes, élevé en lecture — c'est le seul jalon dont le
livrable est un argument. Aucune dépense externe.

### Jalon J2 — Le mécanisme économique

**Dépend de J1** — pas par principe, mais concrètement : *la maturité de
coinbase n'existe qu'en présence de réorgs*. Bitcoin impose 100 blocs de
maturité uniquement parce qu'une récompense sur un bloc orphelin doit pouvoir
être défaite. Avec une finalité instantanée, le champ disparaît. Spécifier
l'économie avant le modèle, c'est risquer d'écrire une règle qui n'a de sens que
dans un monde qu'on n'a pas choisi.

**La fourche réelle de ce jalon.** Aujourd'hui la règle est
`hauteur > 0 ⇒ emissions.is_empty()`, contrôle O(1)
(`crates/ledger/src/proved_state.rs:592`), et `mint` est privée. **C'est la
seule chose qui empêche l'inflation.** Une coinbase consiste à relâcher
précisément cette règle — et comme une `Emission` porte un *commitment*, le
montant est caché : rien n'empêcherait un producteur de s'émettre n'importe
quelle somme. Il faut donc que la coinbase **ouvre, de façon prouvée, sur
exactement la récompense autorisée**. Soit un nouvel énoncé STARK, soit un
montant transparent — et un montant transparent est une fuite.

C'est du travail de circuit, pas de politique. Le design l'a anticipé :
`Emission { commitment, enc_note }` est délibérément sans `Option`, précisément
pour ne pas vider le witness-hiding « le jour d'une coinbase »
(`crates/ledger/src/bloc.rs:73`).

**Le second point, trouvé en vérifiant.** `fee` est une **entrée publique du
STARK** (`crates/circuit/src/monolith/seg_air.rs:1423`) et un champ public de
`ProvedTx`. Aujourd'hui c'est sans conséquence : les frais sont brûlés
(`Σin = Σout + fee`, aucun collecteur) et personne n'a de raison de les faire
varier. **Le jour où un marché de frais existe, le montant des frais devient un
discriminant public — donc une empreinte**, sur un projet dont toute la thèse
est la confidentialité. Sous norme A, cela ne peut pas être découvert au moment
de l'implémentation.

**Dépend de :** J1. **Gèle :** le contenu de `extension`, l'énoncé STARK, la
règle d'émission.
**Critère de franchissement :** un producteur ne peut pas s'émettre plus que la
récompense autorisée sans produire une preuve invalide ; et le coût en
confidentialité du marché de frais est **mesuré et écrit**.
**Coût :** le plus élevé des cinq — travail de circuit (nouvel énoncé STARK),
donc re-bench, re-audit de soundness et regel de format. Aucune dépense externe.
**Hors périmètre (décision A) :** la courbe d'émission elle-même.

### Jalon J3 — Le consensus implémenté

**Dépend de J1 et J2.** Contenu : l'anti-Sybil câblé sur le mécanisme de J2, la
gestion des partitions, la procédure de mise à jour, et la **négociation de
version de fil formalisée**.

**État vérifié.** `Message::version_inconnue()` distingue déjà « version
future » de « malformation » et ne sanctionne pas la première — suffisant pour
ne pas partitionner un testnet, insuffisant au-delà.

**Critère de franchissement :** le réseau accepte un participant inconnu,
survit à une partition, et se met à jour sans fork non intentionnel.
**Coût :** élevé en réseau et en tests multi-nœuds ; c'est le jalon qui exige le
plus d'exploitation réelle. Première dépense d'infrastructure possible (flotte de
test), à dimensionner alors — pas ici.
**Hors périmètre (décision A) :** le coût **chiffré** d'une attaque Sybil.

---

## Partie III — Ce qui reste ouvert

### Décisions A, avec leurs critères de déclenchement

Sur le modèle de `docs/BACKEND_PQ.md` : une décision écrite « pas maintenant »,
accompagnée de ce qui la ferait rouvrir.

| Décision | Ne se pose qu'après | Critère de déclenchement |
|---|---|---|
| Courbe d'émission | J2 livré | quelqu'un propose d'attribuer une valeur ; sinon jamais |
| Coût chiffré de l'anti-Sybil | J3 livré | idem |
| Achat des audits | AUD franchie **et** spec gelée | budget disponible **et** spec stable depuis ≥ 3 mois |
| Cadre légal | — | toute valeur réelle, tout échange, tout faucet devenant marché |

### Une échéance à accrocher, sinon elle se perd

**La dette backend PQ doit être re-testée avant le gel de genèse.**
`BACKEND_PQ.md` l'écrit ; aucun jalon ne la portait. Elle est accrochée ici au
branchement : **avant d'exécuter `obscura-genese` en production**, les critères
de `BACKEND_PQ.md` sont rejoués et le résultat est écrit — **même si c'est
« toujours non »**.

### Une omission nommée

La liste des quatre portes remplace « cadre légal » du document de juillet par
« durcissement ». Sous B, c'est défendable : sans valeur réelle, l'exposition est
faible. Mais **ce doit être une décision écrite, pas une disparition** — le
faucet est précisément l'endroit où un testnet sans valeur peut en acquérir une
contre la volonté de son auteur, et c'est le déclencheur inscrit ci-dessus.

---

## Partie IV — Ce que la carte interdit

Quatre garde-fous, formulés comme des interdits parce que ce sont des erreurs
qu'on ne rattrape pas.

1. **Aucune communication laissant entendre un mainnet, une valeur ou une
   garantie.** A est une norme d'ingénierie interne ; B est la posture publique.
2. **Aucun champ `emissions` valable à toute hauteur.** Ce qui protégeait avant
   n'était pas une règle mais la **divergence** — un mineur clandestin obtenait
   une racine que personne n'avait. Une émission diffusée **et acceptée** est
   irréparable sur un ledger append-only. La coinbase passe par J2 ou ne passe
   pas.
3. **Aucun fork choice introduit sans J1 tranché par écrit.** C'est la porte par
   laquelle la refonte du ledger entrerait sans que personne l'ait décidé.
4. **Aucun audit commandé avant spec gelée.** Un audit sur une spec mouvante est
   de l'argent brûlé, et il produit un rapport qui rassure à tort.

---

## La carte, en une image

```
  OUVERTURE T5-T7  ──►  chaîne de testnet consommable, limites publiées
       │                 ↑ re-test dette PQ AVANT le gel de genèse
       │
  ═════╪══════════════════════════════════════════════════════════════
       │
  VOIE SANS REGRET   D. Durcissement  ·  AUD. Auditabilité   ────────►
       │             (4 défauts nommés)  (KAT, autorité docs, HVZK)
       │
  VOIE IRRÉVERSIBLE  J1 modèle ──► J2 mécanisme ──► J3 consensus
       │             (BFT ouvert ?)   (coinbase       (anti-Sybil,
       │              ferme aussi      prouvée,        partitions,
       │              la liveness)     frais public)   versions)
       │
  ═════╪══════════════════════════════════════════════════════════════
       ▼
     ÉTAT B atteint  ──►  [décision écrite]  ──►  A
                          courbe · coût Sybil · audits · juridique
```

---

## Ce que ce document ne fait pas

- Il **ne choisit pas** le modèle de consensus : c'est le livrable de J1.
- Il **ne dimensionne pas** la flotte, ni le calendrier. Aucune date n'y figure,
  volontairement — les portes sont ordonnées, pas planifiées.
- Il **ne remplace pas** `2026-07-22-testnet-public-0-design.md`, qui reste la
  référence pour T5–T7.
- Il **ne produit aucun code.** Chaque porte obtient son propre cycle
  spec → plan → implémentation.

## Suites immédiates

1. Corriger `CLAUDE.md` (constat 1 — la dette zeroize PQ est fermée).
2. Écrire les vecteurs KAT (constat 2 — critère de sortie de T1 non tenu).
3. Choisir la première porte à spécifier. Par défaut : **AUD**, parce que ses
   deux premiers défauts sont bon marché, sans dépendance, et que le constat 2
   est un critère de sortie déjà dû.
