# T5 — Ouverture du testnet public — conception

**Date :** 2026-07-23
**Objet :** franchir la porte T5 de la carte `2026-07-23-reste-a-faire-vers-B.md`
(cycle 4) — ouvrir une chaîne publique **expérimentale, sans valeur, sur
invitation**, qu'un tiers peut monter et vérifier depuis la seule documentation.
**Statut :** conception, en attente de revue utilisateur.
**Dépend de :** rien de bloquant ; **consomme** l'échéance PQ produite par la spec
`2026-07-23-cloture-voie-sans-regret-design.md` (chantier 3).
**Spec de référence :** carte `2026-07-22-portes-vers-le-mainnet-design.md`
(fiche T5) et `docs/TESTNET.md` (limites, reset, réaction à la valeur).
**Ne contient aucun code de consensus.** Un outil de signature, un runbook, une
publication d'ancre.

---

## Contexte vérifié (au 2026-07-23)

Le gros de T5 est **déjà écrit ou outillé** — à ne pas re-spécifier :

- **Décisions et limites publiées** : `docs/TESTNET.md` couvre §0 sur invitation,
  §1 limites connues, §2 procédure de reset, §3 réaction à la valeur, §4
  signalement. ✅
- **Outillage de genèse** : `obscura-genese` refuse d'écraser, auto-vérifie,
  imprime l'identifiant **complet** (32 o) ; `obscura-node --identite` ;
  `--archiver` ; témoin de synchronisation. ✅
- **Déploiement** : `deploiement/{Dockerfile, obscura-node.service}`,
  `docs/OPERATEUR.md`. ✅
- **Réseau sur invitation** (décision du 2026-07-22) : **aucun bootnode public,
  aucun faucet, aucun explorateur, aucune infra**. Les participants sont les
  opérateurs ; les fonds viennent des allocations de genèse. ✅

Restent **trois défauts**, traités comme trois chantiers.

---

## Chantier 1 — La release signée (le maillon manquant)

### Le défaut

Le dépôt est public et le code compile, mais **rien n'authentifie l'artefact
distribué**. `deploiement/` porte l'image et le service, pas une release vérifiable.
Tant que le binaire n'est ni tagué ni signé, il n'est **pas plus authentifié que la
genèse** — un tiers qui « monte un nœud depuis la release » ne monte rien de
vérifiable.

### Décision (tranchée par l'utilisateur, 2026-07-23) : **minisign**

Signature par **minisign** (format signify) : un outil unique et minuscule, **sans
PKI**. Une seule **clé publique publiée dans le dépôt** suffit à tout vérifier.

**Pourquoi minisign plutôt que GPG/SSH/PQ.** Cohérent avec l'éthos *sans-infra /
sur-invitation* : pas de trousseau, pas de serveur de clés, pas d'écosystème à
supposer chez le vérifieur. ⚠️ **Ironie assumée et à écrire** : un projet
post-quantique signe sa release avec de l'Ed25519 **classique** — comme le fait
déjà tout tag git. C'est acceptable parce que la signature de release protège la
*distribution* (modèle d'adversaire classique : un attaquant qui substitue un
binaire), pas le consensus (qui, lui, est hybride PQ). Le noter explicitement dans
la doc évite qu'un lecteur y voie une incohérence de thèse. *(Le critère de
déclenchement d'une signature PQ de release rejoint la liste de `BACKEND_PQ.md` :
le jour où un outil de vérification PQ ubiquitaire existe.)*

### Ce que la spec demande

1. **Ce qui est signé** : le(s) binaire(s) publié(s) **et** le fichier de genèse
   (`genese.bin`) **et** un manifeste de checksums (SHA3-256‖BLAKE3, cohérent avec
   le hash du projet — jamais tronqué). Une signature minisign par artefact, ou une
   signature du manifeste qui couvre tous les checksums (à trancher dans le plan ;
   recommandation : signer le manifeste, un artefact = une ligne de checksum).
2. **La clé publique minisign** vit dans le dépôt (`deploiement/release.pub` ou
   équivalent) et son empreinte est **aussi publiée hors bande** — sinon un
   attaquant qui remplace le binaire remplace la clé du même coup.
3. **La procédure de vérification** est documentée dans `docs/OPERATEUR.md` : la
   commande exacte qu'un tiers exécute pour vérifier binaire + genèse avant de
   démarrer.
4. **Pas d'automatisation CI de la release dans cette spec** : la signature est un
   geste d'opérateur (la clé privée n'entre pas en CI). Un script d'aide
   (`deploiement/signer-release.sh` ou `.ps1`) est acceptable, la clé restant hors
   dépôt.

### Critère de franchissement

Un tiers, avec la seule clé publique du dépôt, **vérifie la signature** du binaire
et de la genèse, et **rejette** un artefact modifié d'un octet. La commande de
vérification figure dans `docs/OPERATEUR.md`.

---

## Chantier 2 — Le runbook d'ouverture

### Le défaut

Les pièces existent (limites, reset, genèse, release, ancre), mais **rien ne les
séquence**. Ouvrir un réseau public à partir de fragments est exactement le moment
où un pas s'oublie. Il manque **un document-checklist unique** qui ordonne les
gestes irréversibles.

### Ce que la spec demande

Un runbook — **`docs/OUVERTURE.md`** (nouveau) — qui n'écrit **aucune règle
neuve** : il *séquence* et *renvoie*. Ordre imposé, chaque étape avec sa
pré-condition et son critère de vérification :

1. **Re-test de la dette PQ** (gate hérité de la voie sans regret) : rejouer les
   critères de `BACKEND_PQ.md`, **consigner le résultat dans le dépôt**, même
   « toujours non ». *Bloquant : ne pas graver la genèse sans cette trace.*
2. **Gel de la genèse** : `obscura-genese` avec autorités et allocations décidées ;
   il auto-vérifie et imprime l'identifiant complet. La genèse est **consommable**
   (rappel : elle sera refaite ; c'est écrit dans `TESTNET.md`).
3. **Publication de l'ancre** (chantier 3) : identifiant 32 o dans le dépôt + hors
   bande.
4. **Release signée** (chantier 1) : tag + checksums + signature minisign.
5. **Annonce** : limites publiées **avant** l'ouverture (renvoi `TESTNET.md`), y
   compris « chaîne consommable, elle sera refaite », et la **règle de réaction à
   la valeur** (renvoi `TESTNET.md` §3).

Le runbook porte aussi, en tête, les **trois points de centralisation assumés**
(déjà dans `TESTNET.md`, rappelés ici pour qu'ils soient sous les yeux au moment
d'ouvrir) : l'archiviste voit passer les demandes de tous ; `--temoin` n'a de
valeur qu'avec ≥ 2 archivistes indépendants ; rejoindre après le gel exige une
nouvelle chaîne.

### Critère de franchissement

`docs/OUVERTURE.md` existe, séquence les 5 étapes, et chaque étape renvoie à sa
source d'autorité (`BACKEND_PQ.md`, `obscura-genese`, `OPERATEUR.md`,
`TESTNET.md`) sans dupliquer de règle. Un tiers pourrait ouvrir la chaîne en le
suivant seul.

---

## Chantier 3 — Publication de l'ancre de genèse

### Le défaut

`THREAT_MODEL.md:381` : « **Rien n'atteste QUI a écrit la genèse. Le fichier n'est
ni signé ni authentifié.** » Le dépôt Git est hors bande vis-à-vis du réseau P2P ;
c'est précisément ce canal qu'il faut utiliser pour ancrer la genèse.

### Ce que la spec demande

1. **L'identifiant complet (32 o) publié dans le dépôt** — dans `docs/TESTNET.md`
   (ou un fichier `docs/GENESE.md` référencé) — accompagné de la **genèse signée**
   (chantier 1). C'est l'ancre qu'un opérateur compare avec ce qu'imprime son nœud
   au démarrage.
2. **La même valeur publiée hors bande** (le canal d'invitation), pour que la
   comparaison ait un sens : si l'attaquant contrôle le dépôt, le hors-bande le
   dément.
3. **Rappel dans le runbook** : `obscura-node` imprime déjà l'identifiant **complet**
   au démarrage (correctif `2e9e4df`) — la comparaison est donc un geste défini, pas
   une inspection de 8 octets.

### Critère de franchissement

L'identifiant 32 o de la genèse de *cette* chaîne est publié dans le dépôt **et**
signé ; un opérateur qui démarre `obscura-node --genese genese.bin` voit le même
identifiant et peut le confronter à la valeur hors bande.

---

## Ce que cette spec ne fait pas

- **Aucune infrastructure** : pas de bootnode, pas de faucet, pas d'explorateur,
  pas de CI de release avec clé privée. Décision du 2026-07-22, non rouverte.
- **Ne gèle pas le projet** : elle gèle la genèse de *cette* chaîne, consommable.
- **Ne décide pas** l'économie (J2) ni les partitions (J3).
- **Ne touche pas au consensus** : `obscura-genese` et `obscura-node` existent et
  ne changent pas. T5 ajoute de la *signature*, un *runbook*, une *ancre publiée*.
- **N'implémente pas** de signature PQ de release (critère de déclenchement écrit,
  renvoyé à `BACKEND_PQ.md`).

## Découpage suggéré pour le plan

Trois tâches ; la 1 et la 3 avant la 2 (le runbook les référence) :

1. **Release signée** : choisir binaire(s) + manifeste, générer clé minisign
   (privée hors dépôt), script d'aide, `release.pub` au dépôt, procédure de
   vérification dans `OPERATEUR.md`. Test : vérifier qu'un octet modifié est
   rejeté.
2. **Runbook** `docs/OUVERTURE.md` : séquence des 5 étapes + points de
   centralisation en tête.
3. **Ancre** : identifiant 32 o publié + signé, référencé depuis le runbook.

⚠️ **Ce que le plan doit vérifier avant d'écrire.** Le format exact de sortie de
`obscura-genese` (nom du fichier, forme de l'identifiant imprimé) et la présence
d'un éventuel `docs/GENESE.md` — ne pas inventer de chemins. Repartir du working
tree (8 fichiers en cours d'édition).

## Critère de franchissement global

Un tiers, muni du seul dépôt + un canal d'invitation hors bande, monte un nœud
depuis la **release signée**, rejoint la chaîne, et **vérifie l'identifiant de
genèse complet** contre la valeur publiée. À ce point la chaîne publique existe ;
il ne reste sur la voie irréversible que J2 (ADR) et J3.
