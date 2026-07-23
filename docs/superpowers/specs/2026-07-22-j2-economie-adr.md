# ADR-002 (J2) : le mécanisme économique d'Obscura

**Statut :** **ACCEPTÉ** le 2026-07-23 (proposé le 2026-07-22).
**Date :** 2026-07-22
**Ce qui a permis l'acceptation :** l'action 4 (mesure de l'ouverture aux
paramètres de CONSENSUS — **21 227 o, 2,02 % du bloc**) a fermé le seul écart
qui rendait le point 6 conditionnel à une mesure manquante. Le résidu restant
(surcoût du masquage) est borné par une majoration ×3 laissant ~6,1 % de marge,
et il appartient à l'IMPLÉMENTATION derrière la porte A — pas à la décision de
mécanisme que tranche cet ADR.
**Décideur :** l'auteur du projet.
**Jalon :** J2 de `2026-07-22-portes-vers-le-mainnet-design.md`.
**Portée :** ce document tranche le **MÉCANISME** d'émission et laisse
délibérément ouverte la **POLITIQUE** monétaire. Il ne contient aucun code, et sa
mise en œuvre fera l'objet d'un plan séparé, derrière la porte A.

---

## Contexte

Quatre propriétés du dépôt contraignent tout ce qui suit. Elles sont vérifiées,
pas supposées.

**1. Il n'y a pas de « gaz », et ce n'est pas un manque.** Le gaz mesure
l'exécution d'un programme dont le coût n'est pas connu d'avance. Obscura n'a ni
machine virtuelle, ni script, ni boucle : une transaction est une preuve STARK de
forme `m`-in/`n`-out avec `m, n ∈ 1..=4`. Le coût est entièrement déterminé par
la forme, donc connu avant exécution. Mesuré à la profondeur de consensus
(`cargo test -p circuit --release --lib mesure_formes -- --ignored --nocapture`) :

| forme | preuve | vérification |
|---|---|---|
| 1/1 | 78,3 Kio | 1,8 ms |
| 2/2 | 96,9 Kio | 4,2 ms |
| 4/4 | 114,5 Kio | 12,4 ms |

Il n'y a donc **rien à mesurer, seulement un tarif à fixer**. C'est une grille,
pas un compteur — et c'est une simplification majeure par rapport à toute chaîne
programmable.

**2. Les frais sont publics, et aujourd'hui brûlés.** `fee` est un champ public
de `ProvedTx` **et une entrée publique du STARK** (assertion d'équilibre
`S = fee`, `crates/circuit/src/monolith/seg_air.rs`). Le circuit impose
`Σ entrées = Σ sorties + fee` en égalité stricte ; **aucun collecteur n'existe**,
donc `fee` est retiré de la circulation sans être recréé. La masse est
strictement décroissante dès qu'un frais non nul est payé.

**3. Une seule règle empêche l'inflation.** `hauteur > 0 ⇒ emissions.is_empty()`,
contrôle O(1) à `crates/ledger/src/proved_state.rs:591`, exécuté **avant** le
chaînage, l'instantané et toute vérification STARK. `mint` est privée. La seule
création de monnaie est `ProvedLedgerState::depuis_genese`.

**4. `extension` est réservé à ce mécanisme — par ADR-001.** Le champ existe,
entre dans l'identifiant du bloc, et est verrouillé vide. ADR-001 a explicitement
refusé de s'en servir comme refuge pour le certificat de quorum, au motif qu'il
est « réservé à la coinbase et au collecteur de frais » et que lui donner un
second usage rendrait sa sémantique dépendante du contexte. **Cet ADR est le
bénéficiaire désigné de cette réservation.**

### Ce que coûte une émission, en octets réels

Mesuré par `cargo run -p node --example dimensionner-ouverture --release
--features circuit/dev-circuits`, sur un budget de bloc de **1 048 444** octets.

L'énoncé d'ouverture est **déjà écrit** : prouver qu'un commitment ouvre sur une
valeur publique, bénéficiaire caché, c'est exactement le bundle de sortie 3b5c
(`prove_output`/`verify_output`), dont les publics sont `(oc, value)` et les
témoins `owner`, `rho`, `r`.

| composant | octets | part du bloc |
|---|---|---|
| ouverture P7 | 15 157 | 1,45 % |
| ~~range-check P6~~ | ~~9 237~~ | inutile — `R(h)` publique se vérifie en clair |
| enveloppe du bénéficiaire | 1 377 | 0,13 % |
| commitment | 32 | — |
| **émission complète** | **16 566** | **1,58 %** |

⚠️⚠️ **CE CHIFFRE N'EST PAS UNE MESURE DE CONSENSUS, et ne doit pas être cité
comme telle.** Deux écarts le séparent d'un devis, tous deux dans le sens de la
sous-estimation :

1. ~~**Paramètres de développement.**~~ **MESURÉ le 2026-07-23 — écart fermé.**
   Voir la mesure de consensus ci-dessous.
2. **Validity-only.** Les gadgets prouvent que l'énoncé est prouvable à cette
   taille, pas qu'il **cache son témoin**. Une émission de production exige le
   masquage (l'équivalent de 3z-b1), dont le surcoût n'est pas mesuré — et qui
   rend en outre la taille **variable à chaque preuve** (aléa frais), donc à lire
   comme une bande, jamais comme une égalité. **Cet écart demeure.**

### La mesure de consensus (2026-07-23) — action 4, premier volet

`cargo test -p circuit --all-features --release --lib mesure_ouverture --
--ignored --nocapture` (test `sponge::tests::mesure_ouverture`, ajouté pour
cela : `proof_options_hi` étant `pub(crate)`, la mesure devait vivre DANS
`crates/circuit`).

| paramètres | ouverture P7 | part d'un bloc |
|---|---|---|
| dev (32 requêtes, blowup 8) | 15 739 o | 1,50 % |
| **CONSENSUS (48 requêtes, blowup 16)** | **21 227 o** | **2,02 %** |

**L'effet des paramètres est ×1,35** — la majoration prudente par 2× retenue plus
haut était donc trop pessimiste, dans le bon sens. Le temps de génération ne bouge
pas (2,9 → 3,1 ms) : le durcissement se paie en OCTETS, comme sur le monolithe.

⚠️ **Pourquoi 15 739 ici et 15 157 dans la table plus haut, pour les mêmes
paramètres de dev.** Les deux mesures portent sur le même énoncé mais pas sur le
même témoin (valeur et digests différents), et une taille de preuve STARK varie
légèrement avec le témoin — positions de requêtes FRI et compression des chemins
de Merkle en dépendent. L'écart (~3,7 %) est du bruit de cette nature, pas une
contradiction. **C'est la même leçon que pour le masquage : une taille de preuve
se lit comme une BANDE, jamais comme une égalité** — le dépôt l'écrit déjà pour le
monolithe (« à ±1,5 Kio près »). Aucun des deux chiffres ne doit être cité comme
une constante.

**Borne resserrée.** En conservant la majoration ×3 pour le masquage — seul écart
restant — l'émission tiendrait sous **~64 Kio, soit ~6,1 % du bloc**, au lieu des
~9,5 % précédemment annoncés. Pour situer : un certificat de quorum à `n = 4`
coûte 10 122 o (1,0 %) selon ADR-001, et une transaction 2/2 complète pèse
≈105 Kio sur le fil.

**Ce que cela change pour le critère de franchissement.** L'écart « paramètres »
est mesuré et fermé ; il ne reste que le masquage, dont la majoration ×3 est
défendable et laisse une marge LARGE (6,1 %) là où le texte précédent ne
promettait que « confortable ». Le point 6 s'en trouve solidement étayé — mais il
reste, en toute rigueur, adossé à une majoration et non à une mesure complète,
tant que le circuit d'émission n'est pas écrit. Voir Actions, point 4.

### Le contexte d'exploitation

Le testnet fonctionne sur invitation, et **T5 a tranché des frais nuls**
(`938d469`) : `obscura-wallet envoyer --frais <n≠0>` est refusé, parce qu'un
montant choisi librement serait un marqueur quasi unique survivant à l'identité
de transport éphémère, au chiffrement des destinataires et au witness-hiding.

Conséquence directe : **quelle que soit la politique retenue ci-dessous, rien ne
change sur la chaîne actuelle**, puisque toutes les valeurs candidates de `R(h)`
coïncident à zéro quand les frais sont nuls.

---

## Décision

**Spécifier une émission de niveau bloc — valeur publiquement dérivable,
bénéficiaire caché, prouvée par un circuit d'ouverture — et laisser la fonction
d'émission `R(h)` explicitement NON TRANCHÉE.**

La politique monétaire est un **paramètre**, pas une architecture. Le même
mécanisme, au même format, pour le même coût, porte les trois politiques
candidates ; le choix entre elles est une décision numérique, reportable sans
coût et révisable sans changer un octet de format.

---

## La découverte qui justifie ce cadrage

La révision précédente de J2 traitait « collecteur de frais » et « coinbase »
comme deux sujets. **Ce sont le même mécanisme.**

Les frais sont brûlés parce que `Σin = Σout + fee` les retire de la circulation
sans que personne ne crée la sortie correspondante. Les collecter exige de créer
une sortie de niveau bloc dont la valeur est la somme des `fee` du bloc —
laquelle est **publiquement calculable**, puisque `fee` est public. C'est
exactement la structure d'une coinbase : une sortie de bloc, de valeur
publiquement dérivable, de bénéficiaire caché, avec une preuve d'ouverture.

Même format, même circuit, même place dans `extension`. La seule différence est
arithmétique :

| `R(h)` | effet sur la masse | nom usuel |
|---|---|---|
| `0` | décroissante dès qu'un marché de frais existe | statu quo |
| `Σ frais du bloc` | **constante** | collecte |
| `Σ frais + courbe(h)` | croissante | coinbase |

**Il en découle une conséquence qu'il faut écrire** : graver « jamais de
coinbase » interdirait aussi la collecte de frais, et condamnerait donc la masse
à décroître le jour où un marché de frais existera. Les deux refus sont liés, et
les traiter séparément aurait mené à en choisir un sans voir qu'on choisissait
l'autre.

---

## Les six points tranchés

**1. Logement — l'émission vit dans `emissions`, bornée ; sa preuve dans
`extension`.** La règle devient :

```
hauteur == 0  ⇒  emissions.len() ≤ MAX_EMISSIONS_PAR_BLOC   (inchangé, 512)
hauteur  > 0  ⇒  emissions.len() ≤ 1
emissions.len() == 1 à h > 0  ⇒  ouverture vérifiée contre R(h) RECALCULÉE
```

Aucun prédicat n'est lu *dans* le bloc : la règle n'inspecte que la hauteur, qui
est l'ancre de chaînage et non un champ libre. L'invariant reste
**inconditionnel**. Voir « Options considérées » pour ce qui a été écarté et
pourquoi.

**2. La valeur est RECALCULÉE, jamais inscrite.** `R(h)` n'est pas un champ du
bloc. Si le producteur l'écrivait, la vérification comparerait une prétention à
une prétention. Le nœud la calcule depuis la hauteur et le contenu du bloc, puis
vérifie que la preuve d'ouverture porte sur *sa* valeur.

C'est le raisonnement déjà appliqué à `racine_apres`, qui n'entre pas dans
`Bloc::to_bytes` parce qu'une valeur dérivée ne s'inscrit pas — l'inscrire
n'achète aucun bit d'authentification et ouvre une divergence. Ici l'enjeu n'est
plus une racine mais de l'inflation.

**3. L'inflation reste bornée par construction, à toute hauteur.** Sous la
politique actuelle `R(h) = 0`, une émission devrait ouvrir sur zéro — elle est
donc sans valeur, et aucun `is_empty()` n'est nécessaire pour l'empêcher de
nuire. La borne d'inflation cesse d'être un interdit de forme pour devenir une
**conséquence arithmétique de `R(h)`**.

**4. Ce que cache le bénéficiaire — et ce qu'il ne cache pas.** Sur une chaîne à
autorités, le producteur du bloc `h` est **publiquement connu**
(`autorites[(h − 1 + vue) mod n]`, et le bloc porte sa signature). Cacher « qui
est payé » n'achète donc **rien**.

Ce que le commitment cache, c'est **quelle adresse shielded** l'autorité utilise.
Sans lui, chaque émission publierait un lien `identité réseau d'une autorité ↔
owner shielded` : un pseudonyme permanent pour l'acteur le plus actif du réseau,
qui contaminerait ensuite toutes ses transactions ordinaires. **C'est cela que
paient les 15 157 octets**, et c'est la seule justification de la dépense.

**5. Aucune maturité n'est nécessaire.** Bitcoin impose 100 blocs de maturité
uniquement parce qu'une récompense sur un bloc orphelin doit pouvoir être défaite.
ADR-001 ayant retenu la finalité instantanée, le champ disparaît. C'est un
bénéfice acquis de l'ordre des jalons — spécifier l'économie avant le modèle de
consensus aurait produit une règle sans objet.

**6. `extension` suffit — l'écart de paramètres est mesuré, seul le masquage reste
majoré.** L'ouverture pèse **21 227 o (2,02 % du bloc) aux paramètres de
CONSENSUS** (mesure du 2026-07-23), et sous la majoration ×3 du masquage elle
tiendrait sous ~6,1 % du bloc. Le mécanisme est donc portable par le champ réservé
par ADR-001, et **aucun nouveau `VERSION_BLOC` n'est attendu** — c'est-à-dire pas
de `0x06` ; noter que `0x05`, cité par la révision du 2026-07-22 comme le prochain
bump hypothétique, est depuis devenu la version COURANTE (J1-c, changement
d'autorités).

Ce point n'est plus conditionnel à une mesure manquante : il est adossé à une
mesure pour l'écart « paramètres » et à une majoration défendable pour le
masquage, dont le surcoût n'est mesurable qu'une fois le circuit d'émission écrit.
C'est le résidu 1, et il est nommé plutôt que dissimulé.

---

## Ce qui n'est PAS tranché

**`R(h)`.** Les trois valeurs candidates sont listées plus haut. Le choix est une
décision numérique qui ne change ni le format, ni le circuit, ni le coût. Elle
est reportée sans coût, parce que les frais sont nuls sur le testnet et que les
trois politiques y coïncident.

**Ce que ce report NE reporte PAS** : le mécanisme ci-dessus est engageant. Il
grave que la monnaie peut naître ailleurs qu'en genèse, sous condition d'une
preuve d'ouverture sur une valeur recalculée. C'est le point de non-retour de cet
ADR, et il est délibéré — l'alternative (graver le refus définitif) fermait aussi
la collecte de frais, donc condamnait la masse à décroître.

---

## Options considérées — le logement de l'émission

Le choix du point 1 est le seul irréversible du document. Trois variantes ont été
comparées.

### Option A — chemin disjoint dans `extension`

`emissions.is_empty()` reste littéralement intact à `h > 0` ; l'émission entière
vit dans `extension`, avec sa règle propre.

**Écartée.** L'argument avancé pour elle — « deux portes indépendantes, donc
défense en profondeur » — **est faux**. La défense en profondeur suppose deux
mécanismes indépendants protégeant le *même* actif. Ici les deux règles gardent
des routes **disjointes** : `emissions.is_empty()` ne protège rien du chemin
`extension`. La sûreté reste la conjonction des deux, donc la plus faible des
deux. A produit deux points de défaillance uniques, pas de la redondance.

Coût réel supplémentaire : un **nouveau décodeur borné** face au réseau, à
l'endroit le plus dangereux du protocole, là où `emissions` en possède déjà un,
éprouvé, fuzzé, avec sa borne vérifiée avant allocation et son assertion de
compilation. A échangeait un risque de règle contre un risque de parsing.

### Option B — relâcher la règle existante

Réutiliser `emissions` à `h > 0` en conditionnant l'interdit :
`hauteur > 0 ∧ ¬coinbase(bloc) ⇒ emissions.is_empty()`.

**Écartée.** L'invariant devient **conditionnel**, et la condition devient
elle-même de la surface d'attaque — évaluée avant un contrôle que le projet exige
en tête de toute vérification. Le rayon d'explosion est le pire des trois : un
bug dans `coinbase(bloc)` rouvre le chemin d'**allocation de genèse** à hauteur
arbitraire, c'est-à-dire précisément la catastrophe que `THREAT_MODEL.md` décrit
— l'inflation diffusée *et acceptée par tous*, irréparable sur un ledger
append-only.

### Option C — bornée dans `emissions` (retenue)

| | décodeur | invariant | concepts de création |
|---|---|---|---|
| A disjoint | **nouveau** | inconditionnel | deux |
| B relâché | réutilisé | **conditionnel** | un |
| **C borné** | réutilisé | inconditionnel | un |

C domine A et B sur les trois dimensions. **Son prix, à écrire :** la phrase
`hauteur > 0 ⇒ emissions.is_empty()` disparaît en tant que phrase, remplacée par
une borne. Une relecture rapide du code ne verra plus « aucune émission après la
genèse » écrit noir sur blanc, et les tests d'`EmissionHorsGenese` deviennent des
tests de borne au lieu de disparaître. Sur un projet qui traite la lisibilité
d'un invariant comme une propriété de sécurité, ce n'est pas un coût nul.

---

## La tension avec ADR-001, point 6 — à résoudre avant J3

ADR-001 tranche que l'admission au comité se fera **par caution (`stake`)** sous
la porte A, et que cela « suppose le mécanisme économique de J2 ». Cet ADR doit
donc dire ce qu'il en pense, et ce qu'il en pense est un **avertissement**.

Une preuve d'enjeu pondère les votes par un enjeu, ce qui exige que les soldes
soient **publiquement attribuables**. C'est la négation exacte de la thèse
d'Obscura. Un consensus par enjeu anonyme existe dans la littérature (Ouroboros
Crypsinous), mais c'est de la recherche, et rien de tout cela n'est
post-quantique.

**Le mécanisme spécifié ici ne débloque donc pas le point 6 de ADR-001.** Il
fournit de quoi *rémunérer* un comité ; il ne fournit pas de quoi en *ouvrir
l'appartenance* sans renoncer à la confidentialité des soldes. Le budget de
sécurité et l'anti-Sybil sont deux problèmes, et J2 n'en résout qu'un.

C'est une correction de la carte, pas un défaut de cet ADR : **J3 ne peut pas
supposer que J2 lui livre l'anti-Sybil.** Si l'ouverture de l'appartenance est un
objectif, elle demande son propre ADR, et cet ADR devra affronter une
incompatibilité de fond entre le BFT à comité borné et la confidentialité des
soldes.

---

## Conséquences

**Ce qui devient plus facile**
- La masse cesse d'être condamnée à décroître : la collecte de frais devient
  possible sans jamais créer d'unité nouvelle.
- Un marché de frais devient concevable, donc la priorisation sous congestion.
- Rémunérer un comité devient possible le jour où ce sera nécessaire.

**Ce qui devient plus difficile**
- La monnaie peut naître ailleurs qu'en genèse. C'est un élargissement définitif
  de la surface la plus critique du ledger.
- Toute vérification de bloc porte potentiellement une vérification STARK
  supplémentaire, hors du chemin transactionnel.
- L'audit du ledger doit désormais raisonner sur `R(h)`, donc sur du code, là où
  il suffisait de lire une ligne.

**Ce qu'il faudra revisiter**
- Le coût réel du masquage sur l'ouverture, dès que le circuit sera écrit. L'outil
  de mesure existe.
- Le pouvoir discriminant du champ `fee` le jour où les frais cesseront d'être
  nuls. Le candidat le plus prometteur est un **tarif fonction de la forme**,
  `fee = tarif(m, n)` : `m` et `n` sont **déjà publics** (portés par les longueurs
  des publics et préfixés dans Fiat-Shamir), donc un tarif qui n'en dépend que
  n'ajoute **aucun** bit discriminant, tout en facturant un coût qui varie d'un
  facteur 7 entre 1/1 et 4/4. Son prix est l'absence de marché, donc de mécanisme
  de priorité sous congestion.
- L'auditabilité de la masse — voir résidu 3.

---

## Résidus, écrits et non résolus

1. **Le surcoût du MASQUAGE sur l'ouverture reste non mesuré.** Les paramètres de
   consensus, eux, sont désormais mesurés : **21 227 o (2,02 % du bloc)** à 48
   requêtes / blowup 16 (test `mesure_ouverture`, 2026-07-23), soit ×1,35 sur les
   paramètres de dev. Ce qui reste est le masquage (équivalent 3z-b1), majoré ×3
   faute de mieux, et qui rendra la taille **variable à chaque preuve** (aléa
   frais) — donc à lire comme une bande. Il n'est mesurable qu'une fois le circuit
   d'émission écrit ; c'est la seule chose qui sépare encore le point 6 d'un fait
   complet, et elle appartient à l'implémentation, derrière la porte A.

2. **La note d'émission a une valeur publiquement connue**, donc marquée au
   moment de sa dépense ultérieure. Zcash et Monero vivent avec. Atténuation
   disponible ici : l'autorité peut la consolider (`Wallet::consolider`) avant de
   la dépenser.

3. **L'auditabilité de la masse de genèse est inchangée, et c'est un trou.** Les
   allocations de genèse sont des commitments dont les aléas viennent d'`OsRng` :
   les montants sont cachés. Ce qui est public à jamais est le **nombre**
   d'allocations, pas leur somme. La promesse monétaire se décompose donc en deux
   moitiés très inégales :

   | affirmation | vérifiable ? |
   |---|---|
   | « aucune unité créée hors du mécanisme » | **oui** — chaque nœud l'impose |
   | « la genèse contenait exactement N unités » | **non** — parole de l'auteur |

   Corollaire contre-intuitif, à consigner : **une `R(h)` publique améliore
   l'auditabilité avec le temps**, puisque la part publiquement calculable de la
   masse croît et dilue la part opaque. Une masse strictement fixe reste opaque à
   100 % pour toujours. Ce n'est pas décisif — la dilution est ce que la masse
   fixe cherche à éviter — mais l'argument penche à l'inverse de l'intuition.

   Ce résidu n'appartient pas à J2 : il existe déjà, sans coinbase. Il devrait
   être publié dans `docs/TESTNET.md` avant l'ouverture, au titre des limites
   connues.

4. **Le point 6 de ADR-001 n'est pas débloqué par cet ADR.** Voir la section
   dédiée.

---

## Actions

1. [x] **Accepter ou amender cet ADR.** — **ACCEPTÉ le 2026-07-23**, sur la base
       de la mesure de consensus (action 4). Le mécanisme est engageant : la
       monnaie peut naître ailleurs qu'en genèse, sous condition d'une preuve
       d'ouverture sur une valeur RECALCULÉE. `R(h)` reste NON tranchée.
2. [ ] Corriger `2026-07-22-portes-vers-le-mainnet-design.md` : J2 ne livre pas
       l'anti-Sybil à J3, et « collecteur de frais » et « coinbase » y sont un
       seul mécanisme, pas deux.
3. [ ] Ajouter la non-auditabilité de la masse de genèse aux limites connues de
       `docs/TESTNET.md` (résidu 3) — indépendant de cet ADR, et exigible avant
       l'ouverture.
4. [x] **Mesurer l'ouverture aux paramètres de CONSENSUS — FAIT le 2026-07-23.**
       `21 227 o, 2,02 % du bloc` à 48 requêtes / blowup 16 (×1,35 sur les
       paramètres de dev). Le test vit dans `crates/circuit`
       (`sponge::tests::mesure_ouverture`) parce que `proof_options_hi` est
       `pub(crate)` ; il s'appuie sur un point d'entrée `prove_sponge_avec(…,
       options)` extrait pour cela — **le comportement de production est inchangé**,
       `prove_sponge` passant toujours `proof_options()`.
       ⬜ **Volet restant : la mesure AVEC MASQUAGE**, qui n'est possible qu'une
       fois le circuit d'émission écrit — donc derrière la porte A (résidu 1).
5. [ ] L'implémentation part derrière la porte A. Rien n'est gravé en B.
