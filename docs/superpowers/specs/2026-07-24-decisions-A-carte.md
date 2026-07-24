# Décisions A — carte d'arbitrage

**Date :** 2026-07-24
**Objet :** successeur de la Partie III de `2026-07-22-portes-vers-le-mainnet-design.md`
(« Décisions A »). Ordonne les cinq décisions A, les distingue par **nature**, et
acte lesquelles sont attaquables **en conception** maintenant. **Ce document ne
tranche aucune décision** ; chacune obtient ensuite son propre cycle.
**Statut :** carte d'arbitrage.
**Autorité :** ADR-001 (J1, consensus) et ADR-002 (J2, économie) font autorité sur
ce qu'ils ont tranché ; cette carte s'y adosse et ne les rouvre pas.

---

## La règle qui gouverne tout : CONCEVOIR maintenant, COMMITTER plus tard

La décision fondatrice (carte de juillet, « Destination ») pose deux choses qu'il
faut tenir ensemble sans les confondre :

- **A est la norme de conception, pas la posture publique.** « Viser A en ingénierie
  ne coûte rien » — on peut donc écrire les ADR A, et même le code de circuit, dès
  maintenant.
- **On n'engage aucune dépense externe tant que B n'est pas atteint ET stable.**

**Où en est B ?** Atteint **côté dépôt** (les cinq cycles sont fusionnés,
`docs/OUVERTURE.md` est éprouvé), mais **le testnet n'est pas ouvert** : aucune
genèse de production gelée, aucun réseau vivant, donc B n'est pas encore *stable* au
sens « tourne depuis un moment sans se casser ».

**Il en découle la ligne de partage de cette carte :**

| On PEUT, maintenant (interne, gratuit) | On NE PEUT PAS, avant B ouvert et stable |
|---|---|
| Écrire les ADR A (appartenance, courbe) | Commander/payer un audit externe |
| Écrire le circuit de coinbase et le mesurer | Attribuer une valeur réelle à quoi que ce soit |
| Concevoir l'anti-Sybil | Ouvrir l'appartenance sur un réseau de production |

**Concevoir une décision A n'est pas la committer.** Un ADR `ACCEPTÉ` grave un
*mécanisme* ; il n'engage ni dépense ni ouverture. C'est exactement le régime sous
lequel ADR-002 a été accepté (« l'implémentation part derrière la porte A »).

---

## Les cinq décisions, en fiches

Nature : **conception** (un ADR / du code, gratuit, faisable maintenant) ·
**approvisionnement** (engage de l'argent externe) · **juridique** (hors du champ de
conception technique).

### D-A1 — Implémentation de la coinbase — nature : CONCEPTION (lourde)

**Prérequis :** ADR-002 livré ✅ (le *mécanisme* est tranché : valeur publiquement
dérivable, bénéficiaire caché, preuve d'ouverture ; `R(h)` non tranchée).
**Déclencheur (carte de juillet) :** « quelqu'un propose d'attribuer une valeur ».
**Attaquable en conception maintenant ?** **Oui**, mais c'est le poste le plus cher du
projet : ADR-002 le chiffre — nouvel énoncé STARK, re-bench, **re-audit de soundness**,
re-gel de format. La mesure d'ouverture est déjà faite (2,02 % du bloc, ADR-002
action 4) ; ce qui reste est le circuit d'émission **avec masquage** et son intégration
à la validation de bloc.
**Ce que « décider » signifie ici :** un plan d'implémentation, pas une décision
ouverte — le mécanisme est déjà tranché. La seule question de conception résiduelle
est le **surcoût du masquage**, non mesurable avant d'écrire le circuit (résidu 1 de
ADR-002).

### D-A2 — Courbe d'émission `R(h)` — nature : CONCEPTION (légère, policy)

**Prérequis :** coinbase implémentée (D-A1).
**Déclencheur :** idem D-A1.
**Attaquable maintenant ?** Techniquement oui, mais **prématuré** : `R(h)` est un
*paramètre*, pas une architecture (ADR-002). Les trois candidates — `0`, `Σ frais`,
`Σ frais + courbe(h)` — coïncident à zéro tant que les frais sont nuls (décision T5), donc
**rien ne dépend de ce choix sur la chaîne actuelle**. Le reporter est gratuit et
révisable sans changer un octet de format.
**Ce que « décider » signifie ici :** un choix numérique, tranchable en une page le
jour où une valeur est en jeu. Pas un ADR structurant.

### D-A3 — Ouverture de l'appartenance + anti-Sybil — nature : CONCEPTION (profonde)

**Prérequis :** J1 ✅ et J3 ✅.
**Déclencheur :** « quelqu'un propose d'attribuer une valeur ».
**Attaquable maintenant ?** **Oui — et c'est la seule décision A de conception
PROFONDE dont les prérequis sont satisfaits.** ADR-002 l'a explicitement renvoyée à son
propre ADR : *« l'ouverture de l'appartenance exige son propre ADR, lequel devra
affronter une incompatibilité de fond entre le BFT à comité borné et la confidentialité
des soldes. »*
**Ce que « décider » signifie ici :** **ADR-003.** Trancher SI et COMMENT l'appartenance
au comité peut s'ouvrir sans renoncer à la thèse du projet. Voir la tension centrale
ci-dessous — c'est la décision la plus structurante de tout le versant A.

### D-A4 — Achat des audits — nature : APPROVISIONNEMENT

**Prérequis :** porte AUD franchie ✅ **et** spec gelée **et** budget.
**Déclencheur :** budget disponible **et** spec stable depuis **≥ 3 mois**.
**Attaquable maintenant ?** **NON.** La spec vient de se stabiliser (2026-07-24) ; le
critère « ≥ 3 mois de stabilité » n'est pas rempli avant fin octobre 2026 au plus tôt,
et il n'y a pas de budget engagé (règle « pas de dépense avant B stable »). **Ce n'est
pas une décision de conception** — la préparation (rendre auditable) est faite en AUD ;
ce qui reste est de passer commande, ce qui engage de l'argent.
**Ce que « décider » signifie ici :** rien à concevoir. Une échéance à surveiller.

### D-A5 — Cadre légal — nature : JURIDIQUE

**Prérequis :** —
**Déclencheur :** toute valeur réelle, tout échange (pas la distribution — il n'y a
pas de faucet ; le déclencheur est l'ÉCHANGE).
**Attaquable maintenant ?** **NON**, et **hors de mon champ de conception** : c'est une
question juridique, pas d'architecture. `docs/TESTNET.md` §3 porte déjà la règle de
réaction technique (constat, arrêt des invitations, reset, fermeture) ; le cadre légal
proprement dit relève d'un conseil qualifié, pas d'un ADR.
**Ce que « décider » signifie ici :** hors périmètre technique. À déclencher, pas à
concevoir ici.

---

## La tension centrale de D-A3 — pourquoi c'est la vraie décision

C'est le point où la **thèse du projet percute le permissionless**, et il faut le poser
net avant d'ouvrir ADR-003.

**Le problème, tel qu'ADR-002 l'a formulé.** Une preuve d'enjeu (`stake`) pondère les
votes par un enjeu — ce qui exige que les **soldes soient publiquement attribuables**.
C'est la **négation exacte** de la thèse d'Obscura (montants et propriété cachés). Donc
la voie anti-Sybil « évidente » (proof-of-stake) est **fermée par construction** : elle
demanderait de dé-anonymiser précisément ce que tout le reste du protocole cache.

**Ce que cela laisse comme espace de décision** — trois familles, à comparer dans
ADR-003 (pas ici) :

1. **Ne pas ouvrir.** Rester fédéré, l'appartenance restant une décision hors bande du
   comité (déjà possible via J1-c : le quorum certifie l'entrée d'un membre). C'est
   défendable en B et cohérent avec ADR-001 (« BFT dont l'appartenance *pourra*
   s'ouvrir » — *pourra*, pas *doit*).
2. **Anti-Sybil NON économique.** Preuve de travail, preuve d'espace, identité
   attestée, coût de calcul — des coûts anti-Sybil qui ne supposent pas un solde
   public. Chacun a son prix (PoW = énergie et centralisation matérielle ; identité =
   un tiers de confiance).
3. **Enjeu ANONYME.** La littérature existe (Ouroboros Crypsinous), mais c'est de la
   **recherche**, et — point dur pour ce projet — **rien de tout cela n'est
   post-quantique**. Adopter cette voie, ce serait importer une hypothèse cryptographique
   fraîche au cœur du consensus, à rebours de la prudence qui a guidé tout le reste.

**Pourquoi ADR-003 est une vraie décision et pas une évidence :** aucune des trois n'est
gratuite, et la première (« ne pas ouvrir ») est un choix légitime qu'il faut défendre
plutôt que subir — exactement comme ADR-001 a défendu la non-réorg au lieu de s'en
excuser.

---

## Dépendances et ordre

```
  D-A3  Appartenance + anti-Sybil (ADR-003)  ──┐  décision de conception PROFONDE
        prêt (J1+J3) · attaquable maintenant   │  → si « ouvrir », déclenche D-A5 (valeur réelle)
                                               │
  D-A1  Coinbase — implémentation  ───► D-A2  Courbe R(h)
        prêt (J2) · lourd              (policy, downstream, prématuré tant que frais nuls)
                                               │
  D-A4  Audits  ── gated (spec stable ≥ 3 mois + budget) ── PAS avant ~fin oct. 2026
  D-A5  Cadre légal ── juridique, déclenché par l'échange, hors conception technique
  ═══════════════════════════════════════════════════════════════════════════════
```

**Lecture.** Deux décisions de conception sont attaquables maintenant : **D-A3** (la
profonde) et **D-A1** (l'ingénierie lourde). D-A2 est downstream et prématurée. D-A4 et
D-A5 ne sont pas des décisions de conception et ne sont pas prêtes.

**Ordre recommandé.** **D-A3 d'abord.** C'est la décision structurante : son issue
détermine si le projet vise un jour le permissionless (et donc si D-A1/coinbase a un
intérêt au-delà de la collecte de frais), et elle est purement conceptuelle (un ADR,
zéro dépense). D-A1 (coinbase) peut suivre, ou partir en parallèle si l'envie est à
l'ingénierie plutôt qu'à l'arbitrage — mais son coût (re-audit de soundness) en fait un
engagement plus lourd que D-A3.

---

## Ce que cette carte interdit encore

Reprise des garde-fous, toujours valides sous A :

1. **Aucune dépense externe** (audit, infra) avant B ouvert **et stable**.
2. **Aucune attribution de valeur réelle.** La coinbase se conçoit et s'implémente ;
   `R(h) ≠ 0` sur une chaîne à valeur reste une décision distincte, adossée à D-A5.
3. **Aucune ouverture d'appartenance sur un réseau de production** avant qu'ADR-003 ait
   tranché, ET que le cadre légal (D-A5) soit traité — l'ouverture est précisément ce
   qui crée le risque de « valeur réelle ».
4. **Aucun enjeu public importé** dans le consensus sans qu'ADR-003 ait mesuré ce qu'il
   coûte à la thèse de confidentialité.

---

## Premier cycle recommandé

**ADR-003 — Ouverture de l'appartenance et anti-Sybil.** Décision de conception
profonde, prérequis satisfaits, zéro dépense, explicitement teed-up par ADR-002. Elle
tranchera, en défendant le choix : **ne pas ouvrir**, **anti-Sybil non économique**, ou
**enjeu anonyme** — avec, pour chacune, ce qu'elle coûte à la thèse et au modèle
post-quantique.

## Ce que ce document ne fait pas

- Il **ne tranche** aucune décision A — chacune garde son cycle.
- Il **n'engage** aucune dépense ni ouverture : concevoir n'est pas committer.
- Il **ne rouvre pas** ADR-001 ni ADR-002.
