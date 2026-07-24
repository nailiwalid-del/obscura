# Reste à faire vers l'état B — carte remise à jour après la fermeture de J1

**Date :** 2026-07-23
**Objet :** successeur de `2026-07-22-portes-vers-le-mainnet-design.md`, remis à
jour après la **fermeture de la porte J1** (J1-c livré). Recense ce qui reste,
**vérifié dans le code au 2026-07-23**, et ordonne les cycles restants avec une
estimation de taille.
**Statut :** carte d'arbitrage. **Ce document ne contient aucun code** ; chaque
cycle conserve son propre cycle spec → plan → implémentation.
**Autorité :** la carte de juillet reste la référence pour la *définition* des
portes (fiche à six entrées, phrase falsifiable de B, garde-fous). Ce document ne
la remplace pas — il la **met à jour** là où le code a avancé.

---

## Décisions non rediscutées (rappel)

Elles fondent tout le reste ; elles ne sont pas rouvertes ici.

1. **B est la cible livrable, A la norme de conception.** On construit sous le
   modèle d'adversaire d'un mainnet, on ne *livre* que jusqu'à B, aucune dépense
   externe engagée tant que B n'est pas atteint et stable.
2. **Posture publique : B. Norme interne : A.**
3. **Deux voies séparées par leur réversibilité.** La voie sans regret (AUD, D) ne
   gèle rien et tourne en parallèle ; la voie irréversible (J2, T5, J3) gèle des
   formats.
4. **B, en une phrase falsifiable** (inchangée) : *un réseau public expérimental,
   sans valeur, dont un tiers peut vérifier l'état à partir de la seule
   documentation, redéployable à volonté, et dont le consensus n'est PAS
   permissionless.*

---

## Partie I — État au 2026-07-23

### Ce que J1-c a fermé

**La porte J1 est close.** Les quatre briques du consensus fédéré sont livrées et
testées sur sockets réelles :

| Brique | Livré | Ce qu'elle ferme |
|---|---|---|
| **J1-a** | format `0x04` : vue dans l'id, `Certificat` (masque de bits), quorum `2f+1` vérifié avant tout STARK | le FORMAT du consensus |
| **J1-b1** | `Vote`/`Proposition` sur le fil, assemblage du certificat, quorum `⌊2n/3⌋+1` | les votes CIRCULENT |
| **J1-b2** | délai de vue, backoff, changement de vue, fenêtre de vue future | la **liveness** — une chaîne `n ≥ 4` produit enfin des blocs, une autorité absente est contournée |
| **J1-c** | bloc `0x05` : `changement_autorites` certifié par l'ancien quorum, effet à `h+K` | reconfigurer le comité **sans refaire la genèse** |

**Ce que ça débloque.** J2 (économie) dépendait de J1 : la maturité de coinbase
n'a de sens que sous un modèle de consensus tranché — c'est fait. J3 (partitions,
version de fil) dépendait de J1 : débloqué.

**Loose end formel.** J1-c est atterri localement (`master` = `HEAD`) mais la PR
n'a jamais été poussée (`gh pr list` vide). À trancher : PR rétroactive, ou
« landed » assumé. Sans conséquence technique.

### Constats de vérification (le code a dépassé la carte de juillet)

Trois écarts entre la carte de juillet et l'état réel — **tous en faveur du
code**. À ne PAS re-spécifier comme s'ils restaient à faire.

1. **Les vecteurs ACVP ciblés existent.** La carte de juillet écrivait
   « `crates/crypto/tests/` n'existe pas ». C'est **faux aujourd'hui** :
   `crates/crypto/tests/acvp_mldsa65.rs`, `acvp_mlkem768.rs` et le dossier
   `vecteurs/` sont là. Le critère AUD sur `decap`/`sigVer` est **rempli**.
2. **La fixture de conformité existe.** `docs/fixtures/conformite-v3`,
   `crates/node/tests/conformite.rs`, `docs/CONFORMITE.md` : genèse + bloc +
   racine attendue, rejouable. Régénérée en v3 pendant J1-c. Le critère AUD
   « un tiers rejoue » est **outillé**.
3. **Chaos et fuzzing sémantique existent.** `crates/node/tests/chaos_producteur.rs`
   (producteur absent/retour) et `mutations_semantiques.rs` (fuzzing
   structure-aware) sont livrés. Les deux défauts D majeurs de la carte de
   juillet sont **fermés**.
4. **La décision « canaux auxiliaires » est écrite.** `THREAT_MODEL.md:794`
   (« Canaux auxiliaires : ce qui est traité, et ce qui ne l'est pas ») **existe**.
   Le défaut D « l'absence doit être décidée, pas subie » est **soldé** : la
   décision est prise et écrite.

**Conséquence.** AUD et D sont beaucoup plus proches de la fin que la carte de
juillet ne l'indiquait. Ce qui reste ci-dessous en tient compte.

---

## Partie II — Les cinq cycles restants

Chaque fiche : *état vérifié · défauts restants · dépend de · taille · critère de
franchissement*. Taille en S/M/L (effort d'ingénierie, pas calendaire).

### Cycle 1 — AUD-final *(voie sans regret)* — **taille S**

**État vérifié.** ACVP ciblés ✅, fixture de conformité ✅, `docs/PROTOCOL.md` /
`THREAT_MODEL.md` / `STARK_STATEMENT.md` présents, gating dev/consensus effectif,
double licence, dépôt public.

**Défauts restants — deux.**

1. **Deux sources de vérité normatives divergentes.** `CLAUDE.md` (≈457 l.) et
   `AGENTS.md` (≈345 l.) portent encore l'autorité de fait — un auditeur ne lira
   ni l'un ni l'autre, et ils dérivent séparément. Il faut **déplacer l'autorité
   vers `docs/`** et réduire `CLAUDE.md`/`AGENTS.md` à des pointeurs. *(Les diffs
   non commités sur `CLAUDE.md`, `AGENTS.md`, `POST_QUANTIQUE.md`,
   `STARK_STATEMENT.md`, `THREAT_MODEL.md` vont vraisemblablement déjà dans ce
   sens — à confronter avant d'écrire la spec.)*
2. **L'argument HVZK est honnête-vérifieur et non audité.** Sous B, le rendre
   **attaquable** : hypothèses isolées, ce qui est prouvé séparé de ce qui est
   supposé. Seul morceau qui exige un regard circuit/AIR.

**Dépend de :** rien. **Gèle :** rien (mais *consomme* un gel — un audit porte sur
une spec figée).
**Critère de franchissement :** `CLAUDE.md` et `AGENTS.md` ne contiennent plus
aucune affirmation normative (tout renvoie à `docs/`) ; l'énoncé HVZK sépare
explicitement hypothèses et preuves.
**Coût :** temps d'ingénierie seul.

### Cycle 2 — D-final *(voie sans regret)* — **taille S**

**État vérifié.** Fuzzing des deux anneaux, chaos producteur, fuzzing sémantique,
décodage borné avant allocation partout, atomicité d'`appliquer_bloc`, zeroize (PQ
compris), décision canaux auxiliaires écrite. C'est solide.

**Défaut restant — un seul, et c'est une échéance, pas du code.**

- **La dette backend PQ n'a pas d'échéance portée par un jalon.** `BACKEND_PQ.md`
  dit « pas maintenant » avec des critères de déclenchement, mais **rien ne force
  leur re-test avant de graver la genèse**. Il faut **accrocher ce re-test à
  T5** : avant d'exécuter `obscura-genese` en production, les critères de
  `BACKEND_PQ.md` sont rejoués et le résultat écrit — **même si c'est
  « toujours non »**. La stratégie ACVP ajoute un critère : *un backend permettant
  l'injection d'aléa officiel rendrait `keyGen`/`encap`/`sigGen` vérifiables.*

**Dépend de :** rien. **Gèle :** rien.
**Critère de franchissement :** l'échéance PQ est inscrite comme **gate de T5**
(pas comme intention), et la suite nocturne de fuzzing sémantique tourne sans
crash.
**Coût :** rédaction + câblage d'un rappel de procédure. Quasi nul.

> **Note.** AUD-final et D-final sont si petits qu'ils peuvent partager **une
> seule spec combinée** (« clôture de la voie sans regret »). C'est la
> recommandation ci-dessous.

### Cycle 3 — J2, le mécanisme économique *(voie irréversible, B = ADR seul)* — ✅ **CLOS le 2026-07-23**

**État (2026-07-23) : ✅ CYCLE CLOS — ADR-002 `ACCEPTÉ`.**
`docs/superpowers/specs/2026-07-22-j2-economie-adr.md`, commité. Il tranche le
*mécanisme* et laisse `R(h)` — la *politique* — explicitement NON tranchée.

Ce qui a permis l'acceptation : l'**action 4** est faite — l'ouverture d'émission
mesurée aux paramètres de CONSENSUS pèse **21 227 o, soit 2,02 % du bloc**
(`cargo test -p circuit --all-features --release --lib mesure_ouverture --
--ignored --nocapture`). L'effet des paramètres est ×1,35 et non ×2 comme majoré ;
sous la majoration ×3 du masquage, l'émission tient sous **~6,1 % du bloc**. La
suffisance d'`extension` est donc adossée à une mesure, et **aucun nouveau
`VERSION_BLOC` n'est attendu**.

⚠️ **Deux corrections que cet ADR apporte à la carte de juillet** : « coinbase » et
« collecteur de frais » sont **UN seul mécanisme** (les séparer menait à en refuser
un sans voir qu'on refusait l'autre) ; et **J2 ne livre PAS l'anti-Sybil à J3** —
une preuve d'enjeu exige des soldes publiquement attribuables, la négation de la
thèse d'Obscura.

**Résidu, nommé :** le surcoût du MASQUAGE sur l'ouverture n'est mesurable qu'une
fois le circuit d'émission écrit — donc derrière la porte A. Il ne conditionne pas
la décision de mécanisme.

<details><summary>Ce que l'ADR devait démontrer (rappel)</summary>
- coinbase à **montant public** (dérivable de la hauteur, ne fuit rien) et
  **bénéficiaire caché** (le commitment s'en charge) ; taille de la preuve
  d'ouverture qu'elle exige ;
- **destin des frais** (aujourd'hui brûlés) — comparer au moins frais fixes /
  paliers / retardés, pour réduire le pouvoir discriminant du champ public `fee` ;
- **preuve que `extension` telle que réservée suffit** à porter le mécanisme, sans
  nouveau `VERSION_BLOC`.

</details>

**Dépend de :** J1 ✅. **Gèle :** rien en B (l'ADR ne grave rien). En A : le contenu
d'`extension`, l'énoncé STARK, la règle d'émission.
**Critère de franchissement (B) : ✅ ATTEINT** — l'ADR est `ACCEPTÉ` et la
suffisance d'`extension` est démontrée par mesure (2,02 % du bloc aux paramètres
de consensus), non par majoration seule.
**Coût (B) :** rédaction. **Coût (A, hors périmètre) :** le plus élevé du projet
(nouvel énoncé STARK, re-bench, re-audit soundness).

⚠️ **Garde-fou (repris de juillet).** Aucune coinbase implémentée avant l'ADR ;
aucun champ `emissions` valable à toute hauteur — une émission diffusée **et
acceptée** est irréparable sur un ledger append-only.

### Cycle 4 — T5, ouverture du testnet — ✅ **MACHINERIE LIVRÉE le 2026-07-24** (PR #29)

**Livré — la MACHINERIE, pas l'ouverture.** Signature de release minisign
(`deploiement/signer-release.sh`/`verifier-release.sh` — manifeste de checksums,
signature vérifiée avant les checksums, testé par altération d'artefact ET de
manifeste), runbook `docs/OUVERTURE.md` (5 étapes, re-test PQ bloquant en tête), et
gabarit `docs/GENESE.md` pour publier l'ancre 32 o.

⚠️ **L'OUVERTURE elle-même n'est PAS faite, et c'est délibéré.** Aucune vraie genèse
gelée, aucune vraie release signée, aucun identifiant réel publié — ce sont des
gestes d'opérateur, guidés par le runbook, au moment choisi. La clé publique
(`deploiement/release.pub`) et l'ancre (`docs/GENESE.md`) sont des placeholders.
Le **gate hérité de D-final** — rejouer et consigner `BACKEND_PQ.md` avant
`obscura-genese` — est l'étape 1 du runbook, à honorer au moment réel.

<details><summary>État de l'outillage avant T5 (archive)</summary>

**État vérifié.** Outillage complet : `obscura-genese` (refuse d'écraser,
auto-vérifie, imprime l'id complet 32 o), `obscura-node --identite`, `--archiver`,
témoin de synchronisation, `deploiement/{Dockerfile,obscura-node.service}`,
`docs/OPERATEUR.md`. **Documentation d'ouverture largement écrite** :
`docs/TESTNET.md` couvre déjà §0 sur invitation, §1 limites connues, §2 procédure
de reset, §3 réaction à la valeur, §4 signalement.

**Défauts restants — deux.**

1. **Release taguée + checksums + signature.** `deploiement/` porte l'image et le
   service, mais **rien ne signe l'artefact publié** — le binaire n'est pas plus
   authentifié que la genèse tant que la release n'est ni taguée ni signée. C'est
   le maillon manquant entre « le code est public » et « un tiers monte un nœud de
   confiance ».
2. **Re-test de la dette PQ, exécuté avant le gel.** Le gate hérité de D-final :
   rejouer les critères de `BACKEND_PQ.md` et écrire le résultat **avant**
   `obscura-genese` en prod.

**Dépend de :** rien de bloquant (mais consomme l'échéance PQ de D-final).
**Gèle :** la genèse de *cette* chaîne — pas le projet (chaîne consommable).
**Critère de franchissement :** un tiers monte un nœud depuis la **release
signée**, rejoint la chaîne, et **vérifie l'identifiant de genèse complet contre
la valeur publiée hors bande**.
**Coût :** **nul en infrastructure** (réseau sur invitation, aucun bootnode, aucun
faucet, aucun explorateur) ; temps d'ingénierie pour la release signée.

⚠️ **Prix assumé.** La genèse sera figée **avant** que l'économie (J2 → A) soit
implémentée. `extension` est réservée et entre dans l'`id`, donc le format ne sera
pas refondu — mais la chaîne, elle, sera refaite. Fonctionnement normal d'un
testnet, **à condition que ce soit écrit d'avance** (c'est fait dans `TESTNET.md`).

</details>

**Critère de franchissement :** ⚠️ **la MACHINERIE est en place ; le critère
lui-même — « un tiers monte un nœud depuis la release signée et vérifie l'ancre » —
ne peut être ATTEINT qu'à l'ouverture réelle**, qui reste un geste d'opérateur. La
partie livrable en dépôt (les outils, le runbook, le gabarit) est complète.

### Cycle 5 — J3, consensus périmètre B — ✅ **CLOS le 2026-07-24** (PR #27)

**Livré.** Les trois chantiers sont faits et fusionnés :
- **Partitions** — la minorité scelle mais n'applique jamais, et converge à la
  guérison sur la MÊME tête ET la même racine (`crates/node/tests/partition.rs`,
  sockets réelles). Test à dents prouvées **par mutation du code de production**.
  Politique de minorité écrite. *Non couvert et dit comme tel : la partition
  ÉQUILIBRÉE (2/2) est documentée, pas testée.*
- **Mise à jour** — procédure *compatible fil* vs *rupture de consensus*
  (= nouvelle chaîne en périmètre B) dans `OPERATEUR.md`.
- **Négociation de version** — au niveau NODE, **`crates/net` intact** (invariant
  « pur transport » préservé). Règle **asymétrique** : seul le connecteur annonce,
  l'accepteur répond une fois ; refus sans sanction ; absence jamais exigée.

⚠️ **Deux erreurs trouvées par revue adversariale, à ne pas rejouer.** (1) Émettre
spontanément en tête casse les clients « envoie puis raccroche » : octets non lus →
`RST` → le nœud jette son tampon → **transaction perdue**. (2) L'argument qui
justifiait la parade — « un client muet ne reçoit jamais rien de non sollicité » —
était **FAUX** (`Action::Diffuser` atteint les liens ENTRANTS, pour des causes
indépendantes du client) et avait été promu au rang de **garantie normative**. Le
format était bon ; c'est l'argument qui ne l'était pas. Leçon : *un argument de
sûreté non vérifié qui entre dans `docs/` est pire que pas d'argument.*

**Limites publiées** : `VERSION_MIN_ACCEPTEE` n'est opposable qu'à qui annonce
(coordination, jamais contrôle d'accès) ; le budget de messages ignorés en
synchronisation n'est dimensionné par aucune mesure ; la fenêtre RST résiduelle est
réduite, pas fermée.

<details><summary>État avant livraison (archive)</summary>

**État vérifié.** `Message::version_inconnue()` distingue déjà « version future »
de « malformation » et ne sanctionne pas la première — suffisant pour ne pas
partitionner un testnet fédéré, insuffisant au-delà. Aucune gestion explicite de
partition / minorité.

**Défauts restants — trois.**

1. **Comportement en partition et en minorité** non spécifié ni testé : un nœud en
   minorité doit s'arrêter proprement (pas de fork silencieux), et rejoindre la
   majorité au retour.
2. **Procédure de mise à jour** (rolling upgrade) non formalisée.
3. **Négociation de version de fil** à formaliser au-delà du « ne pas sanctionner
   la version future ».

**Dépend de :** J1 ✅. **Gèle :** le format de fil.
**Critère de franchissement (B) :** le réseau survit à une partition et se met à
jour sans fork non intentionnel.
**Hors périmètre (A) :** admission ouverte, anti-Sybil économique, et leur coût.
**Coût :** le plus élevé en exploitation multi-nœuds réelle. C'est le seul cycle
de taille L.

</details>

**Critère de franchissement (B) : ✅ ATTEINT** — le réseau survit à une partition
(testé) et se met à jour sans fork non intentionnel (procédure écrite + négociation
de version livrée). **Hors périmètre (A), inchangé :** admission ouverte et
anti-Sybil économique — et ADR-002 a établi que **J2 ne les livre pas**.

---

## Partie III — Ordre recommandé et dépendances

```
  VOIE SANS REGRET (parallèle, ne gèle rien, jamais jetée)
  ┌─────────────────────────────────────────────────────┐
  │ Cycle 1  AUD-final ─┐                                │
  │ Cycle 2  D-final ───┴─► spec combinée « clôture SR » │
  └─────────────────────────────────────────────────────┘
                          │ (D-final produit l'échéance PQ, gate de T5)
                          ▼
  VOIE IRRÉVERSIBLE (séquencée)
  Cycle 3  J2 (ADR ACCEPTÉ)  ── ne gèle rien en B
        │
  Cycle 4  T5 (release signée · re-test PQ · GEL DE GENÈSE)
        │
  Cycle 5  J3 (partitions · mise à jour · négociation de version)
  ═══════════════════════════════════════════════════════
     ÉTAT B atteint  ──►  [décision écrite]  ──►  norme A
```

**Pourquoi cet ordre.**

- **AUD+D d'abord** parce qu'ils ne dépendent de rien, ne gèlent rien, et sont
  petits — les finir dégage l'horizon et produit l'échéance PQ dont T5 a besoin.
- **J2 avant T5** : l'ADR ne grave rien mais fixe que `extension` suffit ; le
  savoir **avant** de figer la genèse évite d'apprendre trop tard qu'un format
  manquait. Coût de reporter : nul (rédaction).
- **T5 avant J3** *(décision du 2026-07-23, option (a))* : sur un testnet **sur
  invitation et consommable**, une refonte de format de fil = une nouvelle chaîne,
  ce qui est le fonctionnement assumé. La négociation de version actuelle suffit
  tant qu'il n'y a **pas de participant inconnu** (et il n'y en a pas, par
  construction : réseau sur invitation). Bloquer l'ouverture derrière J3
  retarderait sans bénéfice réel. J3 durcit ensuite un réseau **déjà vivant**.
- **J3 en dernier** parce que c'est le plus lourd et le seul qui exige vraiment un
  réseau multi-nœuds à exercer.

> ⚠️ **Le point que cette décision assume.** Geler la genèse (T5) avant de figer
> la négociation de version (J3) signifie qu'un durcissement de format de fil en
> J3 pourra exiger une nouvelle chaîne. C'est acceptable **uniquement** parce que
> la chaîne est consommable et le réseau sur invitation. Si l'un de ces deux
> prérequis tombait, il faudrait inverser (J3 avant T5).

---

## Partie IV — Ce que ce document interdit *(garde-fous, repris de juillet, toujours valides)*

1. **Aucune communication laissant entendre un mainnet, une valeur ou une
   garantie.** A est une norme interne ; B est la posture publique.
2. **Aucun champ `emissions` valable à toute hauteur.** La coinbase passe par J2
   ou ne passe pas.
3. **Aucun fork choice introduit sans décision d'architecture explicite.** La
   non-réorg est la thèse, pas un manque.
4. **Aucun audit commandé avant spec gelée** (critère A, hors périmètre B).

---

## Partie V — Suite immédiate

**Mise à jour du 2026-07-23 — les trois points d'origine sont soldés :** les
fichiers en cours ont été commités puis migrés ; la spec combinée « clôture de la
voie sans regret » a été écrite, planifiée, **exécutée et fusionnée** (PR #25) ; et
le loose end J1-c s'est réglé du même geste. **Cycles 1, 2 et 3 clos.**

**Mise à jour du 2026-07-24 — LES CINQ CYCLES SONT CLOS.** AUD-final, D-final (#25),
J2 (#26), J3 (#27), T5 (#29). La partie **livrable en dépôt** de l'état B est
complète : `docs/` est l'unique source normative, le consensus survit aux partitions
et négocie sa version, l'économie est tranchée (ADR-002 accepté), et la machinerie
d'ouverture est prête et testée.

**Ce qui sépare encore d'un état B PLEINEMENT réalisé n'est plus de l'ingénierie, ce
sont des GESTES d'opérateur**, guidés par `docs/OUVERTURE.md` et irréversibles pour
la chaîne ouverte :

1. Rejouer et **consigner** le re-test de la dette PQ (`BACKEND_PQ.md`, gate hérité
   de D-final) — étape 1 du runbook, **avant** tout `obscura-genese`.
2. Geler la genèse (autorités + allocations décidées), publier l'ancre 32 o dans
   `docs/GENESE.md` **et** hors bande.
3. Générer la vraie paire de clés de release (hors dépôt), signer la release,
   remplacer le placeholder `deploiement/release.pub`, publier l'empreinte hors bande.
4. Annoncer, avec les limites de `docs/TESTNET.md` publiées d'avance.

Une fois ces gestes faits, **l'état B est pleinement atteint** ; il ne reste alors que
la décision écrite B → A (implémentation de la coinbase, ouverture de l'appartenance
+ anti-Sybil — dont ADR-002 a établi que **J2 ne les livre pas**).

## Ce que ce document ne fait pas

- Il **ne dimensionne pas** le calendrier — aucune date, les cycles sont ordonnés,
  pas planifiés.
- Il **ne produit aucun code** — chaque cycle garde sa spec → plan.
- Il **ne rouvre pas** les décisions de la carte de juillet ; il les met à jour là
  où le code a avancé.
