# ADR-003 (D-A3) : l'appartenance et l'anti-Sybil d'Obscura

**Statut :** **PROPOSÉ** le 2026-07-24.
**Décideur :** l'auteur du projet.
**Décision A :** D-A3 de `2026-07-24-decisions-A-carte.md`.
**Portée :** tranche la POSITION d'appartenance (qui peut faire quoi, et à quelles
conditions le comité de scellement peut évoluer). Ne contient aucun code : le
mécanisme d'évolution du comité existe déjà (J1-c). Ce document défend une position,
il n'en implémente pas.

---

## Contexte

Quatre faits contraignent la décision. Ils sont vérifiés, pas supposés.

**1. Le consensus est un BFT à comité borné, à finalité instantanée** (ADR-001).
Un bloc n'est valide qu'avec un certificat de quorum `⌊2n/3⌋+1`. Il n'y a ni fork
choice ni course : la sûreté vient de l'impossibilité de deux quorums divergents à
la même hauteur.

**2. Le comité est DÉJÀ reconfigurable sur la même chaîne** (J1-c). Le quorum de
l'ancienne liste certifie collectivement l'ajout, le retrait ou le remplacement d'un
membre, effectif à `h + K`. **Le mécanisme d'admission au comité existe donc déjà** —
ce qui manque n'est pas une machinerie, c'est une *position* sur son ouverture.

**3. La thèse du projet est la confidentialité des montants et de la propriété.**
Soldes cachés, bénéficiaires chiffrés, preuve witness-hiding. C'est ce que tout le
protocole protège.

**4. Une preuve d'enjeu exige des soldes PUBLIQUEMENT attribuables.** Pondérer les
votes par un `stake` suppose de savoir qui détient combien — la **négation exacte**
du fait 3. Ce point, déjà relevé par ADR-002, est le cœur de la tension.

### Ce que cette décision doit corriger

**ADR-001, point 6**, écrit : « Pour A, l'admission se fera par **caution
(`stake`)**, ce qui suppose le mécanisme économique de J2 ». **Deux erreurs, dont
une déjà corrigée :**

- ADR-002 a corrigé « suppose J2 » : le mécanisme de J2 (coinbase) *rémunère* un
  comité, il n'*ouvre pas* son appartenance sans solde public.
- **Cet ADR corrige le reste :** l'admission ne se fera **pas par `stake`**. Un
  enjeu public est incompatible avec la thèse (fait 4). ADR-001 point 6 est
  **superséé** par la présente décision.

De même, ADR-001 disait « la liste reste gravée en genèse pour B » : **c'est
dépassé depuis J1-c** — la liste est reconfigurable sur la même chaîne, en B comme en
A.

---

## Décision

**Obscura est OUVERTE en usage, et NON permissionless en production de blocs.**
Précisément, selon les trois cercles d'appartenance :

| Cercle | Position | Mécanisme |
|---|---|---|
| **Réseau** (se connecter, transiger, lire) | **OUVERT** — aucune autorisation | permissionless, déjà le cas |
| **Rôles utiles** (archiviste, témoin, relais, opérateur invité) | **OUVERT** en pratique | tout participant peut les tenir ; aucun n'est critique pour la sûreté du consensus |
| **Comité de scellement** (produire/certifier les blocs) | **FÉDÉRÉ, RECONFIGURABLE, CERTIFIÉ** | J1-c : le quorum de l'ancienne liste certifie l'évolution |

**L'admission au comité se fait par reconfiguration certifiée du quorum (J1-c), PAS
par enjeu.** C'est le mécanisme d'admission qu'ADR-001 point 6 cherchait — mais sans
solde public, donc sans renoncer à la thèse.

**Le PoS public est une option REJETÉE, pas différée** (voir Options).

**Le chemin d'ouverture futur reste AGNOSTIQUE.** Cet ADR défend « ne pas ouvrir le
comité » et pose son critère de renversement (ci-dessous). Il ne pré-choisit **aucun**
chemin d'ouverture : le jour où le critère serait rempli, on réévaluera les familles
à la lumière de la percée réelle. On ne grave pas un futur qu'on n'atteindra
peut-être pas.

**Critère de renversement :** une **percée cryptographique post-quantique** offrant un
anti-Sybil **sans solde public** (enjeu anonyme sobre et PQ, ou équivalent). En son
absence, ouvrir le sealing coûterait la thèse — le prix est trop élevé.

---

## La position n'est pas une impasse — c'est un choix, défendu

Le point à ne pas manquer, sur le modèle d'ADR-001 défendant la non-réorg : « fédéré
reconfigurable » n'est pas un aveu d'incapacité, c'est une **thèse**.

- **La distinction des trois cercles désamorce le faux dilemme.** « Ouvrir ou ne pas
  ouvrir » est mal posé tant qu'on ne dit pas *l'appartenance à quoi*. Obscura peut
  être **ouverte en usage** — quiconque se connecte, paie, reçoit, archive, relaie —
  **sans** que n'importe qui produise un bloc accepté. Seul le troisième cercle est
  borné, et c'est le seul dont la sûreté du consensus dépende.
- **La reconfiguration certifiée (J1-c) est une vraie ouverture, à son échelle.** Un
  nouvel opérateur PEUT rejoindre le comité : le quorum en place le certifie. Ce n'est
  pas « permissionless » (un inconnu ne s'auto-admet pas), mais ce n'est pas figé non
  plus. C'est une **fédération à appartenance évolutive**, ce que la définition de
  l'état B assume explicitement (« consensus PAS permissionless »).

---

## Options considérées

### (i) Ne pas ouvrir le comité de scellement — **RETENU**

Rester fédéré, l'appartenance étant une décision **certifiée** par le quorum (J1-c).

**Pour :** préserve intégralement la thèse ; s'appuie sur un mécanisme déjà livré et
testé ; cohérent avec ADR-001 (« BFT dont l'appartenance *pourra* s'ouvrir » —
*pourra*, pas *doit*) et avec la phrase falsifiable de B (« consensus PAS
permissionless »).
**Contre, assumé :** le comité décide de sa propre composition (risque de capture, cf.
Gouvernance) ; « non permissionless » est une limite de posture publique, à écrire, pas
à cacher.

### (ii) Anti-Sybil NON économique (PoW, preuve d'espace, identité attestée) — différé, non pré-choisi

Un coût anti-Sybil qui ne suppose pas de solde public.

**Pour :** ouvrirait l'appartenance sans dé-anonymiser les soldes.
**Contre :** chacun a un prix élevé — PoW = énergie et centralisation matérielle, à
rebours d'un projet sobre ; preuve d'espace = même dérive matérielle ; identité
attestée = un tiers de confiance, ce qui recrée une autorité centrale sous un autre
nom. Aucun ne s'impose comme évidemment supérieur au statu quo fédéré.
**Décision :** **non pré-choisi.** Si le critère de renversement s'active un jour,
cette famille sera réévaluée alors, à la lumière du besoin réel.

### (iii) Enjeu ANONYME — différé, mais lourdement handicapé

Un consensus par enjeu où les soldes restent cachés existe en littérature
(**Ouroboros Crypsinous**, [IACR ePrint 2018/1132](https://eprint.iacr.org/2018/1132)).

**Contre, et c'est dirimant pour Obscura :** Crypsinous repose notamment sur des
**SNARKs** et un **chiffrement key-private forward-secure** — donc **très loin d'un
chemin post-quantique sobre**. L'adopter importerait des hypothèses cryptographiques
fraîches **au cœur du consensus**, à rebours exact de la prudence qui a guidé tout le
reste du projet (versioning strict des algos, défense en profondeur, backend PQ
conservateur).
**Décision :** différé, et c'est le candidat le moins probable — sa réouverture
supposerait précisément la « percée PQ » du critère de renversement.

### (iv) PoS PUBLIC — **REJETÉ** (pas différé)

Pondérer les votes par un enjeu public.

**Rejeté par construction :** exige des soldes publiquement attribuables, la négation
exacte de la thèse (fait 4). Ce n'est pas une option symétrique aux autres : elle
dé-anonymise ce que tout le protocole cache. Rejetée **sauf percée** rendant l'enjeu
anonyme et PQ — c'est-à-dire jusqu'à ce qu'elle cesse d'être « publique ».

---

## Gouvernance du comité fédéré — mécanisme seul, délibérément

**J1-c fournit le MÉCANISME** (le quorum de l'ancienne liste certifie tout
changement). **La POLITIQUE** — qui admettre, qui retirer, selon quels critères —
**reste aux opérateurs, hors bande, et cet ADR ne la grave pas.**

C'est un choix, pas un oubli : une **fédération de volontaires** coordonnée hors bande
n'a pas besoin qu'un protocole lui impose sa politique d'admission, et lui en imposer
une créerait une rigidité que rien ne justifie en B. `docs/TESTNET.md` §1.2 documente
déjà les conséquences que le mécanisme rend visibles (l'ancien quorum décide du
nouveau ; réduire à `n ≤ 3` sacrifie la tolérance aux fautes).

**Le risque assumé, à écrire :** le comité décide de sa propre composition. Un quorum
malveillant peut se refermer ou exclure un membre légitime — c'est une **propriété de
la fédération**, pas un défaut à corriger en B, et c'est exactement pourquoi B n'est
« pas permissionless ». La défense est sociale (opérateurs qui se connaissent hors
bande), pas cryptographique.

---

## Conséquences

**Ce qui devient plus clair**
- La posture publique est nette et défendable : **ouvert en usage, fédéré en
  scellement**. Plus de faux dilemme.
- ADR-001 point 6 est corrigé : l'anti-Sybil n'est plus « supposé livré par J2 »
  derrière A ; il est **explicitement rejeté sous sa forme publique**, et différé sans
  chemin pré-choisi sous sa forme anonyme.
- J3 est déchargé d'une attente qu'il ne pouvait pas satisfaire (ADR-002 l'avait déjà
  noté) : **la négociation de version de fil de J3 n'a jamais eu à porter l'ouverture
  d'appartenance.**

**Ce qui reste assumé**
- « Non permissionless » est une limite de posture, à publier dans les limites
  connues (elle l'est déjà : `docs/TESTNET.md` §1.2, « Fédéré, pas décentralisé »).
- Le comité décide de sa composition (capture possible, défense sociale).

**Ce que ça n'empêche pas**
- Un opérateur PEUT rejoindre le comité (reconfiguration certifiée) — l'appartenance
  est évolutive, pas figée.
- Le chemin vers une vraie ouverture reste écrit (critère de renversement), donc la
  porte n'est pas clouée : elle attend une percée qui la rende compatible avec la
  thèse.

---

## Résidus, écrits et non résolus

1. **Le critère de renversement dépend d'un progrès externe** (une percée PQ pour
   l'anti-Sybil anonyme) sur lequel le projet n'a aucune prise. C'est assumé : la
   position par défaut ne coûte rien à tenir en attendant, et ne se paie pas d'un
   engagement.
2. **La capture du comité est une propriété de la fédération, pas un bug.** Aucune
   défense cryptographique n'est prévue en B ; la défense est sociale. À rouvrir
   seulement si l'appartenance s'ouvre réellement.
3. **Aucune famille anti-Sybil n'est conçue.** C'est le sens de « agnostique » : la
   conception d'un chemin d'ouverture n'aurait de sens qu'à la lumière d'une percée
   réelle, et la faire d'avance serait du travail perdu — le même raisonnement que
   `docs/BACKEND_PQ.md` applique au backend.

---

## Actions

1. [ ] **Accepter ou amender cet ADR.**
2. [ ] Corriger `2026-07-22-j1-consensus-adr.md` (ou l'annoter) : le point 6
   (« admission par `stake` », « liste gravée en genèse pour B ») est superséé —
   admission par reconfiguration certifiée (J1-c), PoS public rejeté.
3. [ ] Vérifier que `docs/TESTNET.md` §1.2 et la carte des décisions A restent
   cohérents avec cette décision (ils le sont a priori ; la posture « fédéré, pas
   décentralisé » y est déjà).
4. [ ] Rien à implémenter : le mécanisme (J1-c) existe. Cet ADR est une position, pas
   du code.
