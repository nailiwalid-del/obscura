# Décisions A — carte d'arbitrage

**Date :** 2026-07-24
**Objet :** successeur de la Partie III de `2026-07-22-portes-vers-le-mainnet-design.md`
(« Décisions A »). Ordonne les cinq décisions A, les distingue par **nature**, et
acte lesquelles sont attaquables **en conception** maintenant. **Ce document ne
tranche aucune décision** ; chacune obtient ensuite son propre cycle.
**Statut :** carte d'arbitrage, **révision 1** (arbitrage utilisateur intégré :
position par défaut « pas de permissionless sealing », distinction d'appartenance à
trois niveaux, quatre champs par décision).
**Autorité :** ADR-001 (J1) et ADR-002 (J2) font autorité sur ce qu'ils ont tranché ;
cette carte s'y adosse et ne les rouvre pas.

---

## La règle qui gouverne tout : CONCEVOIR maintenant, COMMITTER plus tard

- **A est la norme de conception, pas la posture publique.** « Viser A en ingénierie
  ne coûte rien » — on peut écrire les ADR A, et même du code de circuit, dès maintenant.
- **On n'engage aucune dépense externe tant que B n'est pas atteint ET stable.**

**Où en est B ?** Atteint **côté dépôt** (cinq cycles fusionnés, `docs/OUVERTURE.md`
éprouvé), mais **le testnet n'est pas ouvert** : aucune genèse de production, aucun
réseau vivant. B n'est donc pas encore *stable*.

| On PEUT, maintenant (interne, gratuit) | On NE PEUT PAS, avant B ouvert et stable |
|---|---|
| Écrire les ADR A (appartenance, courbe) | Commander/payer un audit externe |
| **Mesurer** le circuit de coinbase (spike hors consensus) | **Intégrer** la coinbase au ledger/consensus |
| Concevoir l'anti-Sybil | Ouvrir l'appartenance sur un réseau de production |

**Concevoir une décision A n'est pas la committer.** Un ADR `ACCEPTÉ` grave un
*mécanisme* ; il n'engage ni dépense ni ouverture.

---

## La distinction qui désamorce le faux dilemme : appartenance À QUOI ?

« Ouvrir ou ne pas ouvrir » est mal posé tant qu'on ne dit pas *l'appartenance à quoi*.
Obscura a **trois cercles d'appartenance**, de sûreté croissante :

| Cercle | Qui | Position visée |
|---|---|---|
| **Réseau** | quiconque se connecte, transige, lit | **OUVERT** — permissionless en usage, aucune autorisation pour rejoindre, payer, recevoir |
| **Rôles utiles** | archiviste, témoin, relais, opérateur invité | **OUVERT en pratique** — tout participant peut tenir ces rôles ; aucun n'est critique pour la sûreté du consensus |
| **Comité de scellement** | qui produit et certifie les blocs | **BORNÉ, CERTIFIÉ, CRITIQUE** — fédéré, reconfigurable par le quorum (J1-c) |

**Conséquence, et c'est la thèse de position de cette carte :** Obscura peut être
**ouverte en usage** sans être **permissionless en production de blocs**. Le faux
dilemme « ouvrir tout ou rester fermé » disparaît : seul le troisième cercle est en
jeu dans D-A3, et sa position par défaut est **fédéré reconfigurable**, pas ouvert.

---

## Les cinq décisions, en fiches

Chaque fiche porte, outre sa nature et son déclencheur, **quatre champs** :
**choix par défaut** · **critère qui le renverse** · **sans regret maintenant** ·
**engage irréversiblement**.

### D-A3 — Ouverture de l'appartenance + anti-Sybil — CONCEPTION (profonde) — *à attaquer en premier*

**Nature :** conception (ADR-003). **Prérequis :** J1 ✅ et J3 ✅.
**Déclencheur d'origine :** « quelqu'un propose d'attribuer une valeur ».

- **Choix par défaut :** **NE PAS ouvrir le comité de scellement.** ADR-003 se
  formalise autour de : *« permissionless pour les utilisateurs et les rôles
  non-consensus ; fédéré et reconfigurable pour le scellement. »* Ce n'est pas une
  impasse — J1-c donne déjà l'entrée/sortie **certifiée** du comité — c'est une
  **position assumée**, cohérente avec ADR-001 (« BFT dont l'appartenance *pourra*
  s'ouvrir » : *pourra*, pas *doit*).
- **Critère qui renverse ce choix :** une **percée cryptographique post-quantique**
  offrant un anti-Sybil **sans solde public** (voir la tension ci-dessous). En son
  absence, ouvrir le sealing coûterait la thèse.
- **Sans regret maintenant :** écrire ADR-003 qui défend la position par défaut,
  énumère les familles anti-Sybil et leur prix, et **classe le PoS public en option
  REJETÉE** (pas symétrique). Zéro dépense, zéro engagement.
- **Engage irréversiblement :** ouvrir réellement le sealing sur un réseau de
  production — ce qui crée le risque de « valeur réelle » et déclenche D-A5.

### D-A1 — Coinbase : mesure du masquage — CONCEPTION (spike, PAS intégration)

**Nature :** conception (un spike de mesure). **Prérequis :** ADR-002 livré ✅
(mécanisme tranché ; `R(h)` non tranchée). **Déclencheur :** « proposer d'attribuer
une valeur ».

- **Choix par défaut :** **un spike de MESURE seulement.** Écrire le circuit
  d'ouverture **masqué** (équivalent 3z-b1) **hors consensus**, pour mesurer le vrai
  surcoût du masquage — le seul résidu non chiffré d'ADR-002 (l'ouverture validity-only
  pèse 2,02 % du bloc ; le masquage reste majoré ×3, non mesuré). **Ne PAS** toucher la
  règle de bloc ni le ledger.
- **Critère qui renverse ce choix :** B a tourné et est stable, ET une valeur est
  proposée → alors seulement envisager l'intégration consensus (nouvel énoncé STARK,
  re-audit de soundness, re-gel de format — le poste le plus cher du projet).
- **Sans regret maintenant :** le spike. Il transforme une majoration en mesure et ne
  grave rien.
- **Engage irréversiblement :** changer `VERSION_BLOC`/l'énoncé STARK/la règle
  d'émission — à ne pas faire tant que B n'a pas tourné.

### D-A2 — Courbe d'émission `R(h)` — CONCEPTION (légère, policy) — *surveillée*

**Nature :** policy. **Prérequis :** coinbase intégrée (donc après D-A1 *intégration*,
pas le spike). **Déclencheur :** frais non nuls.

- **Choix par défaut :** **`R(h) = 0`** tant que les frais sont nuls (décision T5). Les
  trois candidates coïncident à zéro, donc rien ne dépend du choix aujourd'hui.
- **Critère qui renverse ce choix :** l'apparition de frais réels. **Premier candidat
  sain : `R(h) = Σ frais` du bloc** — masse **non décroissante**, pas de courbe
  monétaire, charge juridique et économique minimale. `Σ frais + courbe(h)` (inflation)
  reste **derrière une décision beaucoup plus lourde**, pas un pas par défaut.
- **Sans regret maintenant :** rien — c'est un paramètre reportable sans coût.
- **Engage irréversiblement :** publier une politique d'inflation (`Σ frais + courbe`) —
  une promesse monétaire quasi impossible à retirer.

### D-A4 — Achat des audits — APPROVISIONNEMENT — *surveillée, PAS active*

**Nature :** approvisionnement (engage de l'argent). **Prérequis :** AUD ✅ **et** spec
gelée **et** budget. **Déclencheur :** budget **et** spec stable **≥ 3 mois**.

- **Choix par défaut :** **ne pas acheter ; préparer.** La préparation (rendre
  auditable) est faite en AUD.
- **Critère qui renverse ce choix — définition STRICTE de « spec stable ≥ 3 mois » :**
  aucun changement, pendant 3 mois pleins, de **`VERSION_BLOC`**, de l'**énoncé STARK**,
  du **backend PQ**, du **mécanisme économique**, des **formats wallet/node**, ni des
  **invariants de consensus**. Sans cette définition, « stable » devient une impression.
  La spec s'est stabilisée le **2026-07-24** ; le compteur ne peut donc pas expirer avant
  **~fin octobre 2026**, et seulement si rien de la liste ci-dessus ne bouge d'ici là.
- **Sans regret maintenant :** tenir un journal des changements touchant cette liste
  (le premier remet le compteur à zéro).
- **Engage irréversiblement :** passer commande — dépense externe, interdite avant B
  stable.

### D-A5 — Cadre légal — JURIDIQUE — *surveillée, PAS active*

**Nature :** juridique (hors champ de conception technique). **Prérequis :** —
**Déclencheur :** l'ÉCHANGE (pas la distribution — il n'y a pas de faucet).

- **Choix par défaut :** **ne rien traiter en technique** ; `docs/TESTNET.md` §3 porte
  déjà la réaction technique (constat → arrêt des invitations → reset → fermeture).
- **Critère qui renverse ce choix — la LISTE ROUGE de déclencheurs** (l'un suffit à
  exiger un conseil juridique qualifié, hors de ce dépôt) :
  1. échange de jetons contre un bien ou un service ;
  2. toute promesse de valeur future ;
  3. rémunération d'un validateur/scelleur ;
  4. listing sur une plateforme d'échange ;
  5. achat/vente OTC ;
  6. communication laissant entendre un « mainnet » ;
  7. toute récompense de bloc **non nulle** (`R(h) ≠ 0` sur une chaîne à valeur).
- **Sans regret maintenant :** publier cette liste rouge (c'est fait ici) et la
  référencer depuis `docs/TESTNET.md` §3.
- **Engage irréversiblement :** rien de technique — mais franchir un déclencheur engage
  le projet dans un régime juridique qu'il faut alors traiter, pas subir.

---

## La tension centrale de D-A3 — pourquoi la position par défaut est « ne pas ouvrir »

C'est le point où la **thèse (confidentialité) percute le permissionless**.

**Le problème (ADR-002).** Une preuve d'enjeu (`stake`) pondère les votes par un enjeu,
donc exige des **soldes publiquement attribuables** — la **négation exacte** de la thèse
d'Obscura. Le PoS public n'est donc **pas une option symétrique** : c'est une option
**REJETÉE sauf percée cryptographique**, parce qu'elle dé-anonymise précisément ce que
tout le reste du protocole cache.

**Les trois familles, et pourquoi aucune ne renverse le défaut aujourd'hui :**

1. **Ne pas ouvrir (défaut retenu).** Rester fédéré, l'appartenance au comité étant une
   décision certifiée hors bande (J1-c). Défendable en B, cohérent avec ADR-001.
2. **Anti-Sybil NON économique** (PoW, preuve d'espace, identité attestée). Chacun a son
   prix — énergie et centralisation matérielle pour PoW, tiers de confiance pour
   l'identité — et aucun ne s'impose comme évidemment supérieur au statu quo fédéré.
3. **Enjeu ANONYME.** La littérature existe (**Ouroboros Crypsinous**,
   [IACR ePrint 2018/1132](https://eprint.iacr.org/2018/1132)), mais elle repose
   notamment sur des **SNARKs** et un **chiffrement key-private forward-secure** — donc
   **très loin d'un chemin post-quantique sobre** pour Obscura. L'adopter importerait des
   hypothèses cryptographiques fraîches au cœur du consensus, à rebours de la prudence
   qui a guidé tout le reste.

**Conclusion de position :** ADR-003 doit **défendre** « fédéré reconfigurable, pas de
permissionless sealing » comme un choix, pas s'en excuser — exactement comme ADR-001 a
défendu la non-réorg.

---

## Dépendances et ordre

```
  D-A3  Appartenance (ADR-003) ── défaut : PAS de permissionless sealing
        prêt (J1+J3) · à attaquer en PREMIER · si un jour « ouvrir » → déclenche D-A5
          │
  D-A1  Coinbase — SPIKE de mesure du masquage (hors consensus)
        prêt (J2) · sans regret · l'INTÉGRATION attend que B ait tourné
          │
  D-A2  Courbe R(h) ── défaut 0 ; 1er candidat Σ frais ; inflation = décision lourde
  D-A4  Audits ── surveillée : "stable ≥ 3 mois" au sens strict, pas avant ~fin oct. 2026
  D-A5  Cadre légal ── surveillée : liste rouge publiée, déclenchée par l'échange
  ═══════════════════════════════════════════════════════════════════════════════════
```

---

## Ce que cette carte interdit encore

1. **Aucune dépense externe** (audit, infra) avant B ouvert **et stable**.
2. **Aucune attribution de valeur réelle** ; `R(h) ≠ 0` sur une chaîne à valeur est une
   décision distincte, adossée à D-A5.
3. **Aucune ouverture du comité de scellement sur un réseau de production** avant qu'ADR-003
   ait tranché ET que le cadre légal (D-A5) soit traité.
4. **Aucun enjeu public importé** dans le consensus — le PoS public est rejeté sauf percée.
5. **Aucune intégration consensus de la coinbase** tant que B n'a pas tourné ; le spike de
   mesure, lui, est sans regret.

---

## Le meilleur choix maintenant

**Sobre, et cohérent avec la thèse :** ne pas importer un anti-Sybil qui détruit la
confidentialité pour pouvoir dire « permissionless ».

1. **Ouvrir ADR-003 en premier**, avec l'hypothèse de départ **« comité fédéré
   reconfigurable, pas de permissionless sealing »** — à défendre, PoS public en option
   rejetée.
2. **Lancer seulement un spike D-A1** pour mesurer le coût du masquage de la coinbase,
   **sans intégration consensus**.
3. **D-A2, D-A4, D-A5 restent surveillées, pas actives** — avec leurs critères de
   renversement écrits (défaut `R(h)=0` ; « stable ≥ 3 mois » strict ; liste rouge légale).

## Ce que ce document ne fait pas

- Il **ne tranche** aucune décision A — chacune garde son cycle (ADR-003 en premier).
- Il **n'engage** aucune dépense ni ouverture : concevoir n'est pas committer.
- Il **ne rouvre pas** ADR-001 ni ADR-002.
