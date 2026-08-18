# Moteur commercial de S1 — vérification aux textes-sources

**Date :** 2026-08-18
**Objet :** solder le résidu n° 1 de `2026-07-26-monetisation-carte.md`, qui note que
« le calendrier européen de transition PQC et la position ANSSI sur l'hybridation y
sont cités de mémoire » et demande de les vérifier avant d'en faire un argumentaire.
**Statut :** note de vérification. **Ce document ne tranche aucune décision** et
n'engage ni dépense, ni démarchage.
**Autorité :** aucune sur le protocole. `docs/` reste autorité sur les faits
techniques d'Obscura ; ce document n'a autorité que sur ce qu'il cite, et chaque
affirmation porte sa source et sa date.

---

## Ce que la vérification a changé

Quatre choses, dont trois corrigent la formulation spontanée de l'argumentaire.

0. **L'obligation PQC entre dans le texte de NIS2** — proposition COM(2026) 13,
   article 7(2) point (k). Vérifié dans le texte, pas repris d'un commentaire.
1. **Le levier fort n'est pas « l'échéance 2030 ».** C'est l'entrée en qualification
   ANSSI **à partir de 2027**, et le fait que l'hybridation soit **obligatoire** dans
   l'évaluation de visa de sécurité de phase 2. Une échéance de conformité datée, pas
   une exhortation.
2. **Les « trois phases » de l'ANSSI ne sont pas un plan de transition national.**
   C'est une feuille de route de **délivrance des visas de sécurité**. Présenter
   « la transition en 3 phases de l'ANSSI » serait faux, et un interlocuteur qualifié
   le verrait.
3. **NIST IR 8547 est toujours un brouillon.** Citer « obsolète en 2030, interdit en
   2035 » comme une politique américaine arrêtée serait une erreur.

---

## Établi — Union européenne

**Recommandation de la Commission du 11 avril 2024** — recommandation (UE) 2024/1101,
sur une feuille de route coordonnée de transition vers la cryptographie
post-quantique.

**Feuille de route du groupe de coopération NIS**, *Coordinated Implementation
Roadmap for the Transition to Post-Quantum Cryptography*, v1.1, 11 juin 2025 ;
annoncée par la Commission le **23 juin 2025**
([page officielle](https://digital-strategy.ec.europa.eu/en/news/eu-reinforces-its-cybersecurity-post-quantum-cryptography),
[document](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)).

Jalons, tels qu'énoncés :

| Échéance | Contenu |
|---|---|
| **fin 2026** | tous les États membres **commencent** la transition ; plan national attendu |
| **31 décembre 2030** | usages à **haut risque** transités ; planification faite pour le risque moyen |
| **31 décembre 2035** | risque moyen achevé ; risque faible autant que praticable |

⚠️ La page d'annonce de la Commission ne mentionne que 2026 et 2030. Les jalons
2030/2035 par niveau de risque viennent de la feuille de route elle-même. Ne pas
attribuer 2035 à la Commission.

**COM(2026) 13 final, 20 janvier 2026** — proposition de directive modifiant NIS2,
au sein d'un paquet cybersécurité. Contenu décrit officiellement : simplification,
alignement sur le Cybersecurity Act, règles de compétence, collecte de données sur
les rançongiciels, supervision transfrontalière, rôle renforcé de l'ENISA.

---

## Établi — l'obligation PQC entre dans le texte de NIS2

**Vérifié dans le texte le 2026-08-18.** COM(2026) 13 final, transmis au Conseil le
21 janvier 2026 (doc. Conseil 5627/26, dossier interinstitutionnel **2026/0012 (COD)**),
*Proposal for a Directive … amending Directive (EU) 2022/2555 as regards simplification
measures…*. Les 18 pages ont été extraites et lues.

L'article modificatif, mot pour mot :

> « (5) in Article 7(2), the following point (k) is added:
> ‘(k) **for the transition to post-quantum cryptography**, taking into account the
> transition timelines and relevant requirements set out in applicable Union legal
> acts and policies.’ »

L'exposé des motifs le range parmi les modifications de fond :

> « the requirement for Member States to adopt policies for the migration to
> post-quantum cryptography (PQC) as part of their national cybersecurity strategy »

Et le considérant 8 en donne le fondement, en nommant explicitement le modèle de
menace :

> « The possibility of ‘harvest now — decrypt later attacks’, **likely occurring
> already now**, and the future risks induced by quantum attacks on forging
> signatures, as well as the planned deprecation of certain algorithm implementations
> and full disallowance of current public-key cryptographic algorithms, increase the
> urgency of initiating actions for the migration to post-quantum cryptography. »

### Trois précisions qui changent l'usage qu'on peut en faire

1. **C'est une proposition, pas du droit.** Procédure législative ordinaire en cours
   depuis janvier 2026. Dire « NIS2 impose la PQC » reste faux aujourd'hui ; « la
   Commission propose de l'inscrire dans NIS2 » est exact.
2. **L'obligation porte sur les États membres**, pas directement sur les entités : une
   politique de migration PQC dans la *stratégie nationale de cybersécurité*. La
   contrainte sur les entités en découle, elle n'est pas écrite ici.
3. **Le considérant 8 nomme un débouché.** Il évoque le soutien à
   « the emergence and uptake of **formally verified and evaluated European PQC
   solutions** adhering to compliance frameworks ». C'est, littéralement, la catégorie
   que vise V1 — et cela figure dans l'exposé des motifs d'un texte européen, pas dans
   une plaquette.

### Note de méthode

Un premier balayage par mot-clé de ce PDF a renvoyé **zéro** occurrence de
« post-quantum », ce qui aurait conduit à conclure l'inverse. L'extraction insère une
coupure — « post - quantum », « post -quantum » — qu'un motif exact manque. La
conclusion vient de la lecture des contextes, pas du comptage. À retenir pour toute
vérification ultérieure sur PDF officiel.

---

## Établi — ANSSI

### Le document de fond

*ANSSI views on the Post-Quantum Cryptography transition (2023 follow up)*,
**21 décembre 2023**, addendum à la prise de position de 2022
([PDF](https://messervices.cyber.gouv.fr/documents-guides/follow_up_position_paper_on_post_quantum_cryptography.pdf)).
Texte intégral extrait et lu.

Ce qu'il dit, littéralement :

> « ANSSI intends to follow a 3-phase roadmap **for delivering security visas**. The
> start date of the second phase was initially planned around 2025. We recall that in
> the second phase, the cryptographic evaluation tasks of security visa evaluation
> comprise an analysis of all cryptographic algorithms including the post-quantum
> algorithms **with mandatory hybridation**. »

Et sur l'accélération :

> « ANSSI is currently speeding-up the original agenda. First phase-2 security visas
> for products implementing hybrid post-quantum cryptography are expected to be
> delivered around 2024-2025. »

Et sur le périmètre de la recommandation d'hybridation :

> « The use of hybrid post-quantum mitigation is recommended especially for security
> products aimed at offering a long-lasting protection of information (until after
> 2030) or that will potentially be used after 2030 without updates. »

### Les dates opérationnelles

FAQ PQC de l'ANSSI ([cyber.gouv.fr](https://cyber.gouv.fr/enjeux-technologiques/cryptographie-post-quantique/faq-pqc/)),
page à jour référençant des certifications d'octobre 2025 :

> « L'ANSSI vise la mise en place d'obligations PQC pour l'entrée en qualification de
> produits **à partir de 2027**. »

> « Il ne sera pas raisonnable d'acheter des produits qui n'intègrent pas de la PQC
> **après 2030**. »

> « L'ANSSI insiste fortement sur le caractère **essentiel de l'hybridation** des
> algorithmes de cryptographie post-quantique partout où ils sont déployés, à la fois
> à court et moyen terme. »

Faits datés complémentaires : premières certifications PQC françaises en **octobre
2025** (Thales, Samsung) ; mise à jour du guide des mécanismes cryptographiques
prévue fin 2025 ; mise à jour du référentiel IPsec DR prévue **courant 2026**.

---

## Établi — NIST

FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) sont publiées.

**NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* — brouillon
public initial**, publié le **12 novembre 2024**, commentaires clos le 10 janvier
2025, commentaires reçus publiés le 21 janvier 2025.
[Page CSRC](https://csrc.nist.gov/pubs/ir/8547/ipd) vérifiée le 2026-08-18 :
**aucune version finale ni second brouillon**.

Le calendrier qu'il **propose** — RSA / ECDSA / ECDH / DH en corps fini *deprecated*
après 2030, *disallowed* après 2035 — est donc, à ce jour, un projet vieux de vingt
et un mois sans version finale. C'est en soi un fait à connaître : un interlocuteur
technique américain le sait, et l'entendre présenté comme arrêté disqualifie.

---

## Ce que cela vaut pour S1

L'argumentaire tenable ne repose pas sur la menace quantique, qui est un lieu commun,
mais sur **deux gates datés et un problème d'exécution**.

**Les gates.** Entrée en qualification ANSSI avec obligations PQC **à partir de
2027** ; hybridation **obligatoire** en évaluation de visa phase 2. Pour un industriel
visant une qualification, 2027 n'est pas un horizon : c'est le prochain exercice
budgétaire.

**Le problème d'exécution**, et c'est là qu'est la rareté. Les textes disent *quoi*,
pas *comment ne pas casser le réseau en chemin*. Obscura a exécuté exactement ce
passage — T1 : round-3 → FIPS 203/204, identifiant d'algorithme `0x02`, **refus du
`0x01` par son nom** (`AlgoPerime` / `VersionPerimee`), sans cohabitation. Le retour
d'expérience est écrit dans [`docs/MIGRATION_PQ.md`](../../MIGRATION_PQ.md).

C'est la différence entre un consultant qui a lu la norme et quelqu'un qui a versionné
un algorithme dans un domaine de séparation, refusé l'ancien format par son nom, et
constaté ce que ça casse.

**Ce qu'il ne faut pas dire :**

- « la transition ANSSI en 3 phases » — ce sont les visas, pas la transition ;
- « le NIST interdit RSA en 2035 » — c'est un brouillon non finalisé ;
- « NIS2 impose la PQC » — **pas encore** : c'est une proposition de janvier 2026,
  en procédure ; et l'obligation vise les États membres, pas les entités ;
- « notre implémentation PQ » — interdit n° 3 de la carte de monétisation, et faux :
  le dépôt s'appuie sur `pqcrypto`, dette documentée dans `BACKEND_PQ.md`.

---

## Ce que ce document ne fait pas

- Il **ne tranche** aucune piste de la carte de monétisation et n'en rouvre aucune.
- Il **n'engage** ni dépense, ni démarchage, ni posture publique. Les garde-fous de la
  carte des décisions A restent intégralement en vigueur.
- Il **ne suit pas** la procédure législative de COM(2026) 13. Le texte cité est la
  proposition de la Commission ; il peut être amendé au Parlement et au Conseil. À
  revérifier avant tout usage engageant.
- Il **ne chiffre pas** le marché. Aucune de ces échéances n'est un client.
