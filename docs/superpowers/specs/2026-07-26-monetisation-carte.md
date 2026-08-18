# Carte d'arbitrage — monétisation d'Obscura

**Date :** 2026-07-26
**Objet :** cartographier les voies de monétisation d'Obscura **en gardant le socle
technique**, avec leurs prérequis, leur prix et ce que chacune engage
irréversiblement.
**Statut :** carte d'arbitrage. **Ce document ne tranche aucune décision.**
**Modèle :** `2026-07-24-decisions-A-carte.md`, dont il reprend la forme (quatre
champs par fiche) et la règle de fond.
**Autorité :** ADR-001 (J1), ADR-002 (J2) et ADR-003 (appartenance) font autorité sur
ce qu'ils ont tranché ; cette carte s'y adosse et ne les rouvre pas. `docs/` fait
autorité sur les faits techniques cités ici.

---

## La règle qui gouverne tout : CARTOGRAPHIER maintenant, ENGAGER plus tard

Transposition directe de la règle des décisions A (« concevoir maintenant, committer
plus tard ») :

- **Recenser une piste n'est pas la poursuivre.** Une fiche ci-dessous n'engage ni
  dépense, ni contrat, ni posture publique.
- **La contrainte de la carte A tient intégralement :** aucune dépense externe avant
  que B soit **ouvert ET stable**. Cette carte ne la contourne pas — elle cherche
  précisément ce qui est monétisable *sans* la franchir.

---

## Le problème central : la circularité

C'est ce que cette carte doit résoudre, et c'est ce qui en dicte l'ordre.

> Les cas d'usage à fort alignement (V1–V3) **exigent un audit**. L'audit **exige du
> budget**, et D-A4 en interdit l'achat avant B ouvert et stable — au plus tôt
> **~fin octobre 2026**, et seulement si rien de la liste de stabilité ne bouge
> (`docs/STABILITE.md`). Le budget **exige un revenu**.
>
> **Donc le premier euro ne peut pas venir de ce qui a besoin d'un audit.**

Toute piste réaliste à court terme doit donc être monétisable **sans audit**, **sans
chaîne ouverte**, et **sans franchir la liste rouge de D-A5**. C'est le critère qui
sépare la section 2 de la section 3.

---

## La contrainte dominante n'est pas technique : c'est le temps

Les pistes ne sont pas commensurables sur l'axe du chiffre d'affaires. Elles le sont
sur celui des heures :

- **S1 et S2 paient maintenant, en soustrayant exactement les heures qui ouvriraient
  B.** Elles vendent le présent.
- **S3, S4 et S5 ne paient pas immédiatement mais n'hypothèquent pas l'avenir.** S3
  achète même du temps futur ; S4 le préserve.
- **S6 paie bien et peut coûter l'avenir**, par le seul jeu d'une clause d'exclusivité.

L'arbitrage réel n'est donc pas « quelle option est la meilleure », mais **quelle
fraction des heures disponibles est vendue, et à quel moment on arrête** — parce que
tout ce qui a de la valeur en section 3 suppose B ouvert et stable, et que B ne
s'ouvre pas pendant qu'on facture des jours.

---

# Section 1 — Inventaire : les quatre actifs séparables

Le socle n'est pas un bloc unique. Chiffres relevés dans le dépôt le 2026-07-26 :
≈ 43 000 lignes de Rust, **616 tests**, 8 crates.

| Actif | Contenu | Rareté | Délai avant le premier euro |
|---|---|---|---|
| **① Méthode & pédagogie** | une trentaine d'ADR/specs, `CONFORMITE.md`, runbook `OUVERTURE.md` à critères de passage, `THREAT_MODEL.md`, horloge `STABILITE.md`, `atelier/` (8 scripts séquencés + `repetition-generale.ps1`), `deploiement/` (Dockerfile, unit systemd, signature minisign vérifiée par un tiers), 3 pages HTML d'atelier | Faible en crypto, **élevée en ingénierie** | **Semaines** |
| **② Brique PQ** | `crates/crypto`, 1 436 lignes : hybridation ML-KEM-768 + ML-DSA-65, séparation de domaines, zeroize, **14 vecteurs ACVP rejouables** (10 ML-KEM officiels ; 1 ML-DSA officiel + 3 dérivés) et `PROVENANCE.md` qui énonce ce qui n'est *pas* couvert | Moyenne — l'intégration et la **preuve de conformité**, pas la primitive | **Semaines** (référence), mois (composant) |
| **③ Circuit STARK** | `crates/circuit`, 10 506 lignes : monolithe witness-hiding, forme variable m/n ≤ 4, masquage. `ProvedTx` 2/2 ≈ **105 Kio** sur le fil, vérification **3,8 ms** (12,6 ms au pire 4/4), génération ≈ **1,48 s** | **Très élevée** — un circuit de paiement confidentiel *post-quantique qui tourne* | **12–24 mois** (verrou audit) |
| **④ Registre complet** | `ledger` (7 996) + `net` (2 098) + `node` (16 213) + `wallet` (2 735) : BFT à finalité instantanée, reconfiguration d'autorités certifiée (J1-c), transport PQ, Dandelion++, anti-éclipse, wallet portable mobile | Élevée en assemblage | **18–24 mois** (audit + chaîne ouverte + D-A5) |

## Le renversement à voir

**L'actif le plus monétisable à court terme est celui qui contient le moins de
nouveauté cryptographique.** ① ne prouve rien sur la crypto ; il prouve qu'un projet
cryptographique difficile a été conduit jusqu'au bout — et c'est ce qu'achète un
client de conseil. Il est **déjà emballé** : `atelier/00-tout.ps1` déroule wallets →
genèse → nœuds → synchronisation → paiement → resynchronisation, et
`repetition-generale.ps1` rend un bilan critère par critère.

Symétriquement, ③ — le seul actif réellement rare — est le plus lent à payer, parce
que **personne n'achète un circuit ZK non audité**. Sa rareté ne devient de la valeur
qu'après une dépense que la carte A interdit avant B ouvert et stable.

## Deux nuances à ne pas laisser passer

- **② n'est pas une invention.** ML-KEM n'est pas écrit ici : le dépôt s'appuie sur
  `pqcrypto`, que `BACKEND_PQ.md` documente comme `unmaintained`. Ce qui se vend, ce
  sont les **vecteurs ACVP** et la **décision de dette écrite et datée** — donc,
  encore, de la méthode. Présenté comme « notre implémentation PQ », ce serait faux.
- **④ contient un point de centralisation assumé** : l'archiviste, qui peut mentir par
  omission sans qu'aucun contrôle local ne le démente (`TESTNET.md` §0). C'est écrit et
  honnête ; ça devient une **question de client** dès qu'un registre est facturé. À ne
  pas découvrir en réunion.

## Deux faits de propriété, relevés dans le dépôt

- **100 % du droit d'auteur est détenu par un seul auteur** (`git shortlog` : 404
  commits, deux identités de la même personne). **Aucun accord de tiers n'est requis
  pour changer de licence** — ni CLA à rétro-obtenir, ni consentement à collecter.
- **Le dépôt est PUBLIC depuis le 2026-07-14 sous `MIT OR Apache-2.0`**, avec 1 étoile
  et **0 fork** ; aucun crate n'est publié sur crates.io (`publish = false` partout).
  L'instantané déjà diffusé reste disponible sous ces termes pour toujours — cela,
  c'est irréversible. Mais à 0 fork, re-licencier les versions *futures* ne coûte
  aujourd'hui presque rien. **Ce prix monte à chaque contributeur et à chaque fork.**

---

# Section 2 — Pistes SANS VERROU

Monétisables sans audit, sans chaîne ouverte, sans franchir la liste rouge de D-A5.

## S1 — Conseil « migration post-quantique »

Vendre l'expertise, pas le produit : audit de migration PQC, conception de
crypto-agilité, stratégie d'hybridation et de versioning d'algorithmes.

**Ce qui distingue d'un consultant qui a lu la norme :** la migration n'a pas été
*recommandée*, elle a été *exécutée*. T1 : round-3 → FIPS 203/204, version d'algo
`0x02`, **refus du `0x01` par son nom** (`AlgoPerime` / `VersionPerimee`), sans
cohabitation. C'est l'artefact que peu de gens ont, et c'est exactement là que les
équipes butent : refuser l'ancien format sans casser le réseau.

| | |
|---|---|
| **Choix par défaut** | Ne rien vendre — le projet reste personnel |
| **Critère qui le renverse** | Un premier prospect nommé |
| **Sans regret maintenant** | ✅ **Fait** : [`docs/MIGRATION_PQ.md`](../../MIGRATION_PQ.md) — retour d'expérience T1 (hybridation, refus par son nom, identifiant d'algorithme dans le domaine, écart ACVP assumé), non normatif et déférant à `PROTOCOL.md` / `BACKEND_PQ.md` |
| **Engage irréversiblement** | Rien de contractuel — mais consomme des heures directement soustraites à l'ouverture de B |

## S2 — Formation / atelier

`atelier/` contient déjà 8 scripts séquencés, une répétition générale à bilan
critère par critère, et trois pages HTML. **C'est un support fini, pas un support à
écrire.** Deux jours « cryptographie post-quantique appliquée » ou « ZK-STARK par la
pratique » sont à portée de reformatage. Meilleur ratio revenu/heure que S1 dès la
deuxième session, le coût marginal étant proche de zéro.

| | |
|---|---|
| **Choix par défaut** | L'atelier reste un outil interne de répétition |
| **Critère qui le renverse** | Une équipe d'ingénieurs demandant à comprendre le PQ concrètement |
| **Sans regret maintenant** | Rien à produire — seulement sortir le matériel du contexte Obscura |
| **Engage irréversiblement** | Peu. Un financement OPCO/CPF exigerait **Qualiopi**, évitable en sous-traitant à un organisme déjà certifié |

## S3 — Financement public non dilutif — **la piste qui casse la circularité**

CIR, JEI, BPI (Deeptech, i-Lab, Bourse French Tech), France 2030, Horizon Europe /
EIC, lignes cyber-PQC européennes. **Elle finance l'audit sans exiger l'audit** — la
seule piste de la carte qui le finance *directement* sans en dépendre. (V6 casse la
circularité autrement : il produit une référence et alimente S3, sans payer l'audit.)

**L'atout structurel :** un dossier CIR doit démontrer l'état de l'art, les verrous
scientifiques rencontrés et la démarche suivie. Le dépôt contient **une trentaine
d'ADR/specs datés, un journal de décisions, une horloge de stabilité et des critères de
renversement écrits**. La plupart des entreprises reconstruisent cette narration
*a posteriori* et se font redresser dessus ; elle existe ici nativement.
`BACKEND_PQ.md` — une dette décidée, datée, avec ses critères de re-test — est un
document de verrou scientifique presque idéal.

| | |
|---|---|
| **Choix par défaut** | Ne rien demander |
| **Critère qui le renverse** | Les deux prérequis sont **déjà remplis** : structure juridique existante, résidence UE |
| **Sans regret maintenant** | Vérifier l'éligibilité JEI (âge de la structure, part des dépenses de R&D) et cadrer le CIR sur l'exercice en cours. Aucune dépense |
| **Engage irréversiblement** | Rigueur comptable et délais de plusieurs mois ; risque de contrôle faible, la R&D étant réelle et documentée |

## S4 — Politique de licence et provenance — ✅ **TRANCHÉE (ADR-004, 2026-07-26)**

> **Décidée** par `2026-07-26-politique-de-licence-adr.md` (ACCEPTÉ) : le dépôt reste
> `MIT OR Apache-2.0`, entrant = sortant, **DCO obligatoire vérifié en CI**, pas de
> CLA. Livré : `CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md`, job `dco`.

**⚠️ Correction d'une erreur de la première rédaction de cette fiche.** Il y était
écrit que fusionner une PR externe sans CLA rendrait « toute stratégie de licence
future négociable avec un tiers ». **C'est faux.** MIT autorise la sous-licence et
Apache-2.0 accorde les droits de reproduction, d'œuvre dérivée et de distribution :
une contribution reçue sous `MIT OR Apache-2.0` **peut être incluse dans une offre
commerciale ou une double licence**, mentions préservées. Un entrant permissif ne
forclôt ni l'open core, ni la double licence. Un CLA sert à autre chose — re-licencier
le projet **en bloc** — dont rien n'établit le besoin aujourd'hui.

**L'urgence réelle était donc ailleurs, et elle demeure : la provenance.** Sans
instrument, rien n'atteste que le contributeur avait le *droit* de soumettre ce qu'il
soumet. C'est exactement ce qu'interroge une revue de chaîne d'approvisionnement
logicielle — le même mécanisme qui fait remonter `unmaintained` en rouge chez un
acheteur institutionnel (section 3). La fiche se raccroche à V1/V6, pas à la stratégie
de licence.

| | |
|---|---|
| **Choix par défaut** | Rester `MIT OR Apache-2.0` — **retenu**, et parfaitement défendable |
| **Critère qui le renverse** | Un acheteur exigeant la faculté de re-licencier **en bloc** — un CLA serait alors ajouté, valable pour les contributions postérieures seulement |
| **Sans regret maintenant** | ✅ **Fait** : DCO vérifié en CI, politique écrite en ADR-004 |
| **Engage irréversiblement** | Rien. (L'instantané `MIT OR Apache-2.0` déjà publié l'est, mais à 0 fork sa portée pratique est nulle — elle croît avec chaque fork.) |

## S5 — Publication — crédibilité convertible

Un article sur l'énoncé STARK witness-hiding, ou un retour d'expérience sur la
migration T1. **Ne paie pas directement** : c'est l'intrant de S1, S3 et V6. Bon
marché, `STARK_STATEMENT.md` et `BACKEND_PQ.md` étant déjà écrits.

**Le point notable :** publier l'énoncé invite un examen extérieur qui pourrait
trouver une faille. C'est un risque, et c'est surtout **le plus proche substitut
gratuit d'un audit accessible**. `STARK_STATEMENT.md` reconnaît déjà que l'argument
HVZK est honnête-vérifieur et non audité ; le soumettre à des yeux compétents est
cohérent avec cette honnêteté, non contradictoire avec elle.

## S6 — Licencier le circuit ③ à un tiers disposant du budget d'audit

Laisser l'audit être payé par un acteur qui auditera le circuit dans le cadre de sa
propre diligence. N'exige aucune chaîne ouverte.

⚠️ **Le piège :** une clause d'exclusivité peut forclore ④ pour des années. Un
acheteur du circuit demandera naturellement l'exclusivité sur le domaine « paiement
confidentiel post-quantique » — c'est-à-dire précisément le marché futur du projet.
**Licence non exclusive, ou champ d'application étroitement délimité.**

---

# Section 3 — Pistes DERRIÈRE LES VERROUS

## Les deux verrous ne sont pas de même nature

- **Le verrou « audit » s'achète** : de l'argent et du délai. D-A4 en fixe la porte
  (spec stable ≥ 3 mois au sens strict, donc au plus tôt ~fin octobre 2026, et pas
  avant B ouvert et stable).
- **Le verrou « backend PQ » ne s'achète pas — et il peut bloquer plus tôt que
  l'audit.** `pqcrypto` est `unmaintained` en amont ; `cargo-deny` tourne en CI,
  `BACKEND_PQ.md` documente la dette, et `OUVERTURE.md` étape 1 en fait un **bloquant
  du gel de genèse**.

**Le renversement de priorité :** dans une vente institutionnelle, la revue de chaîne
d'approvisionnement logicielle passe **avant** la discussion cryptographique. Le
scanner de dépendances du client remonte `unmaintained` en rouge **avant que
quiconque ait ouvert `STARK_STATEMENT.md`**. Aujourd'hui la migration du backend est
une dette technique délibérément différée ; le jour où l'on vend, elle devient un
**prérequis commercial**, et passe donc **devant** l'audit dans l'ordre des dépenses.

## V1 — Registre confidentiel de consortium (le cap retenu)

Règlement interbancaire, registre classifié, santé longue durée. Ce qui se vend : une
**licence + intégration**, éventuellement l'exploitation (V5).

**La distinction juridique qui change tout, à faire valider :** la liste rouge de
D-A5 concerne **la chaîne Obscura** — son testnet, sa genèse, ses jetons. Un
déploiement de consortium est une **chaîne différente** (autre genèse, autres
autorités), opérée par le client sous son propre régime réglementaire. Le rôle est
alors celui d'un **éditeur de logiciel, pas d'un émetteur de crypto-actif**.
Autrement dit : **le meilleur débouché commercial ne franchit aucun déclencheur de la
liste rouge.** À faire confirmer par un conseil qualifié — exactement ce que D-A5
prescrit — et à ne pas tenir pour acquis : un fournisseur logiciel critique d'un
établissement financier européen peut être happé par ses propres obligations (DORA,
encadrement de la sous-traitance TIC).

| | |
|---|---|
| **Choix par défaut** | Ne rien vendre avant B ouvert, stable et audité (~18–24 mois) |
| **Critère qui le renverse** | Un interlocuteur nommé — voir V6, qui n'attend pas l'audit |
| **Sans regret maintenant** | Ouvrir la conversation. Le cycle de vente institutionnel dure lui-même 12–24 mois et tourne **en parallèle** de l'audit : l'audit est un livrable de la diligence, pas un préalable au premier rendez-vous |
| **Engage irréversiblement** | Un engagement de support long terme sur un logiciel non audité, si la vente est faite trop tôt |

## V2 — Défense / souverain · V3 — Santé longue durée

**C'est là que la thèse PQ est la plus forte**, pour une raison précise : « harvest
now, decrypt later » n'y est pas un argument marketing mais un modèle de menace
écrit. Une donnée classifiée cinquante ans, un dossier médical à vie : la
confidentialité doit survivre à l'ordinateur quantique.

**Le prix, à ne pas sous-estimer :** le souverain ne se contente pas d'un audit privé.
Une **qualification ANSSI** est un processus d'un tout autre ordre (durée, coût,
exigences de structure), et le marché public suppose des références, un effectif,
parfois des habilitations. La santé ajoute son propre appareil (HDS, RGPD données de
santé). **Ces deux débouchés ne sont pas atteignables par un auteur seul** : ils
supposent une société constituée avec une équipe. Sur la carte comme cible, pas comme
piste active.

## V4 — CBDC de gros, trade finance, vote

Alignement conditionnel, cycles politiques longs, concurrence installée et bien
financée. **Rien à entreprendre avant d'avoir une référence client.** Sur la carte
pour être complet.

## V5 — Exploiter le réseau comme service

Héberger autorités et archivistes pour un consortium : revenu récurrent, la meilleure
forme économiquement. Exige V1 franchi, un SLA, et surtout **d'assumer
commercialement le point de centralisation de l'archiviste** (`TESTNET.md` §0). Se
placer là où le propre threat model du projet dit qu'un nœud peut mentir par omission
sans être démenti, cela se vend — à condition d'être écrit au contrat, pas découvert
après.

## La branche jeton — REJETÉE, et il faut l'écrire

`R(h) ≠ 0`, rémunération de scelleur, listing, achat/vente OTC, promesse de valeur
future : chacun est un déclencheur de la liste rouge D-A5. ADR-003 a rejeté le PoS
public ; la carte A interdit toute attribution de valeur réelle.

Elle figure ici **pour que la décision reste traçable**, pas comme option vivante. Et
le fait notable : **la branche rejetée n'est pas celle qui rapporte le plus.** Rien
d'économiquement significatif n'est abandonné en la rejetant.

## V6 — Le PoC financé sur budget d'innovation — **la pièce manquante**

Entre « conseil qui vend des heures » et « produit qui exige un audit » existe un
intermédiaire : une **preuve de concept payée sur le budget d'innovation d'une
institution** (direction innovation, laboratoire, agence). Budgets modestes comparés
à un achat de production, mais cycle de **quelques mois, pas deux ans**.

Pourquoi c'est la pièce qui manquait :

- **Un PoC n'exige pas d'audit** : rien ne va en production, aucune valeur réelle ne
  circule. Le verrou principal ne s'applique pas.
- Il utilise **③ et ④** — les actifs rares — au lieu de ① seul. Ce ne sont plus
  seulement des heures qui se vendent.
- Il produit ce que V1 exige et qui manque aujourd'hui : **une référence client
  nommée**.
- Il renforce S3 en retour : un PoC institutionnel signé pèse lourd dans un dossier
  BPI ou EIC, où la preuve d'un intérêt marché est systématiquement demandée.

**Le risque à nommer :** un PoC peut dégénérer en développement sur mesure gratuit qui
ne mène nulle part. La contre-mesure est un périmètre écrit avec un critère de sortie
— exactement le principe sur lequel `OUVERTURE.md` est bâti.

| | |
|---|---|
| **Choix par défaut** | Ne pas démarcher |
| **Critère qui le renverse** | Un contact institutionnel disposé à financer une exploration |
| **Sans regret maintenant** | **Rien à écrire** : `CONFORMITE.md` §5 *est* déjà cette note. Un second document redirait la même chose et créerait exactement la divergence que le dépôt traite comme un défaut. Ne reste qu'une page de garde, le jour où il y a un interlocuteur |
| **Engage irréversiblement** | Rien, **si** le périmètre et le critère de sortie sont écrits d'avance |

---

# Séquence, si l'on relie les trois sections

```
maintenant ──► S4 ✅ FAIT (DCO + ADR-004)     ─┐
               S3 (CIR/JEI, dossier)          ├─► ne coûtent pas d'heures futures
               S5 (publication)              ─┘
                    │
     S1/S2 ─────────┤ paient, mais consomment les heures de B
                    │
                    ▼
             V6  PoC institutionnel  ◄── utilise ③ et ④ ; aucun audit requis ;
                    │                    produit la référence et alimente S3
                    ▼
             B ouvert et stable ──► migration backend PQ ──► audit (D-A4)
                    │
                    ▼
                   V1  consortium ──► V5  exploitation
                    (V2/V3 : seulement avec une société et une équipe)
```

**Le chemin critique n'est pas « gagner de l'argent » : c'est ouvrir B.** Rien au-delà
de V6 n'existe sans lui, et B ne s'ouvre pas pendant qu'on facture des jours.

---

# Ce que cette carte interdit encore

Les interdits de la carte A restent intégralement en vigueur ; celle-ci en ajoute
trois propres au registre commercial.

1. **Aucune dépense externe** avant B ouvert **et** stable (carte A, inchangé).
2. **Aucune attribution de valeur réelle** ; la branche jeton reste rejetée.
3. **Aucune vente présentant ② comme une implémentation cryptographique propre** —
   ce serait faux et vérifiable.
4. **Aucun engagement de support de production sur un logiciel non audité.**
5. **Aucune clause d'exclusivité sur ③** sans champ d'application étroitement
   délimité, sous peine de forclore ④.

---

# Résidus, écrits et non résolus

1. ~~**Le moteur commercial de S1 n'est pas vérifié dans ce document.**~~ ✅ **SOLDÉ
   le 2026-08-18** par [`2026-08-18-moteur-s1-sources.md`](2026-08-18-moteur-s1-sources.md).
   Les échéances sont désormais sourcées et datées. Trois corrections en sont sorties :
   le levier fort est l'entrée en qualification ANSSI **à partir de 2027** (hybridation
   obligatoire en visa phase 2), pas « l'échéance 2030 » ; les « trois phases » de
   l'ANSSI concernent la **délivrance des visas**, pas la transition nationale ; et
   NIST IR 8547 est **toujours un brouillon**, donc son calendrier 2030/2035 n'est pas
   arrêté. Et un fait nouveau, **vérifié dans le texte** : COM(2026) 13 (proposition du
   20 janvier 2026) ajoute à l'article 7(2) de NIS2 un point (k) « for the transition
   to post-quantum cryptography » — obligation portant sur les **États membres**, et
   proposition encore en procédure, non du droit en vigueur.
2. **Le coût réel d'un audit n'est pas chiffré ici.** Aucun devis n'a été demandé — et
   ne doit pas l'être avant B (carte A, interdit 1). L'ordre de grandeur reste donc
   inconnu, ce qui rend le dimensionnement de S3 approximatif.
3. **La qualification juridique de V1 (« éditeur de logiciel, pas émetteur ») n'est
   pas validée.** Elle est plausible et décisive ; elle relève d'un conseil qualifié,
   hors de ce dépôt, conformément à D-A5.
4. **Le conflit temps est posé, pas résolu.** Cette carte rend l'arbitrage explicite ;
   elle ne dit pas quelle fraction des heures vendre. C'est une décision, pas une
   analyse.
5. **Aucune de ces pistes n'a de client.** Tout ce qui précède décrit un espace
   d'options, non un pipeline commercial.

---

# Ce que ce document ne fait pas

- Il **ne tranche** aucune piste — chacune garderait son propre cycle de décision.
- Il **n'engage** aucune dépense, aucun contrat, aucune posture publique.
- Il **ne rouvre** ni ADR-001, ni ADR-002, ni ADR-003, ni la carte des décisions A —
  dont les interdits restent tous en vigueur.
- Il **ne modifie aucun code** et n'a aucune conséquence sur le consensus.
