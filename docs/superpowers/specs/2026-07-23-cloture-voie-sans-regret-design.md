# Clôture de la voie sans regret (AUD-final + D-final) — conception

**Date :** 2026-07-23
**Objet :** fermer les deux portes « sans regret » de la carte
`2026-07-23-reste-a-faire-vers-B.md` — **AUD-final** (auditabilité) et **D-final**
(durcissement) — en une seule spec, parce que ce qu'il en reste est petit et sans
dépendance croisée.
**Statut :** conception, en attente de revue utilisateur.
**Spec de référence :** `2026-07-23-reste-a-faire-vers-B.md` (cycles 1 et 2) et,
pour la définition des portes, `2026-07-22-portes-vers-le-mainnet-design.md`.
**Ne contient aucun code.** Trois chantiers indépendants, chacun testable seul.

---

## Contexte vérifié (au 2026-07-23)

Ce qui était le gros de AUD et D est **déjà livré** — à ne pas re-spécifier :

- Vecteurs ACVP ciblés `decap`/`sigVer` : `crates/crypto/tests/acvp_mldsa65.rs`,
  `acvp_mlkem768.rs`, dossier `vecteurs/`. ✅
- Fixture de conformité rejouable : `docs/fixtures/conformite-v3`,
  `crates/node/tests/conformite.rs`, `docs/CONFORMITE.md`. ✅
- Chaos producteur + fuzzing sémantique : `crates/node/tests/chaos_producteur.rs`,
  `mutations_semantiques.rs`. ✅
- Décision « canaux auxiliaires » écrite : `docs/THREAT_MODEL.md:794`
  (« ce qui est traité, et ce qui ne l'est pas »). ✅ **Hors périmètre de cette spec.**

Reste **trois défauts**, traités ci-dessous comme trois chantiers.

---

## Chantier 1 — `docs/` devient l'unique source normative

### Le défaut, énoncé comme un défaut

`CLAUDE.md` (≈457 l.) et `AGENTS.md` (≈345 l.) sont les documents **les plus
détaillés du dépôt** ; ils portent l'autorité de fait ; ils **divergent** l'un de
l'autre (constat 1 de la carte de juillet) ; et ils sont structurés comme des
notes d'agent qu'un auditeur ne lira pas. **Deux sources de vérité qui dérivent
séparément valent moins que zéro.**

Un second défaut, découvert en préparant cette spec : **`docs/` lui-même est en
retard sur le code.** `docs/PROTOCOL.md:169` écrit encore `VERSION_BLOC = 0x04` et
sa section « État de la mise en œuvre » s'arrête à **J1-a**, alors que J1-b et J1-c
sont livrés (bloc `0x05`, changement d'autorités certifié). **On ne peut pas
déplacer l'autorité vers un texte périmé** — la migration doit donc *aussi*
mettre `docs/` à jour.

### Décision de cible (tranchée par l'utilisateur, 2026-07-23) : migration COMPLÈTE

`CLAUDE.md` et `AGENTS.md` sont réduits à de **purs pointeurs** ; **toute**
affirmation normative vit dans `docs/`. C'est le critère strict de la carte
(« ne contiennent plus aucune affirmation normative »), pas un allègement.

⚠️ **Le risque assumé, et sa mitigation.** `CLAUDE.md` est le fichier que Claude
Code charge à chaque session : le vider *dégrade le contexte agent* si `docs/`
n'est pas complet d'abord. **Mitigation, et ordre non négociable : `docs/` est
rendu complet ET courant AVANT que `CLAUDE.md`/`AGENTS.md` soient vidés.** Le
pointeur résiduel doit diriger la session vers le bon fichier `docs/` (déjà l'usage
annoncé : « commencer par `docs/CONFORMITE.md` »).

### Où atterrit chaque type de contenu

Audit de `CLAUDE.md` par nature de contenu, avec sa destination :

| Contenu de `CLAUDE.md` | Nature | Destination `docs/` |
|---|---|---|
| Principe directeur (défense en profondeur, primitives) | normatif | `PROTOCOL.md` (existe : § Primitives, § Versioning) |
| **État par crate** (crypto/net/ledger/circuit/wallet/node) | architecture/statut | **`docs/ARCHITECTURE.md` (NOUVEAU)** — voir ci-dessous |
| Décisions v0.2, hash consensus ≠ prouvé | normatif | `PROTOCOL.md` (existe : § Changements v0.1→v0.2) |
| Notes de build, features dev/consensus | normatif (invariant « défaut = consensus seul ») | `PROTOCOL.md` § Phases, ou `ARCHITECTURE.md` § Build |
| Dette backend PQ | normatif | `BACKEND_PQ.md` (existe) |
| Zeroize, secrets | normatif | `THREAT_MODEL.md` ou `PROTOCOL.md` |
| Prochaine étape / roadmap | **non normatif** | supprimé de `CLAUDE.md` (l'autorité est `docs/superpowers/specs/`) |
| Conventions (commentaires en français, tests) | méta-projet | **reste** dans `CLAUDE.md`/`AGENTS.md` (c'est leur rôle légitime) |

**Décision de structure : créer `docs/ARCHITECTURE.md`.** Le narratif « État par
crate » de `CLAUDE.md` (le plus riche) n'a pas de home aujourd'hui : `PROTOCOL.md`
est la spec des *formats et règles*, pas une description d'architecture. Un fichier
dédié — invariants et rôles par crate, avec les ⚠️ qui expliquent *pourquoi* une
structure est ce qu'elle est — reçoit ce contenu et devient référençable depuis
`CONFORMITE.md` §4.

**Ce qui RESTE légitimement dans `CLAUDE.md`/`AGENTS.md`** : les conventions de
travail (langue des commentaires, emplacement des tests, discipline de build) et
les pointeurs. Ce ne sont pas des affirmations normatives sur le *protocole* — ce
sont des consignes à l'agent. Le critère `grep` (ci-dessous) ne les compte pas.

### Résoudre la divergence AGENTS ↔ CLAUDE

Les deux fichiers divergent. Après migration, tous deux deviennent des pointeurs
vers `docs/` — la divergence disparaît d'elle-même **si et seulement si** ils
pointent vers la même autorité. Règle : `AGENTS.md` et `CLAUDE.md` contiennent le
**même bloc de pointeurs** (généré une fois), plus leurs conventions respectives
d'outil. Aucun contenu normatif dupliqué ⇒ rien à faire diverger.

### Critère de franchissement (falsifiable)

- `docs/PROTOCOL.md` reflète `VERSION_BLOC = 0x05` et son état couvre J1-a/b/c.
- `docs/ARCHITECTURE.md` existe et porte le narratif par crate.
- `CONFORMITE.md` §4 pointe vers l'ensemble `docs/` faisant autorité.
- **Test mécanique** : un `grep` d'affirmations normatives (mots-clés de format,
  constantes de protocole, invariants de consensus) sur `CLAUDE.md` + `AGENTS.md`
  ne renvoie que des pointeurs et des conventions — zéro affirmation autoportante.
  *Le motif exact du grep est fixé dans le plan* (p. ex. `VERSION_BLOC`,
  `MAX_OCTETS_BLOC`, `quorum`, `0x0[0-9]` hors bloc de pointeur).

---

## Chantier 2 — Rendre l'argument HVZK attaquable

### Le défaut

`docs/STARK_STATEMENT.md` porte l'argument de witness-hiding (HVZK en ROM). Il est
**honnête-vérifieur et non audité** — c'est écrit, mais l'énoncé mêle ce qui est
**prouvé** et ce qui est **supposé**, ce qui empêche un auditeur de cibler une
hypothèse précise.

### Ce que la spec demande

Restructurer la section HVZK de `STARK_STATEMENT.md` pour **isoler les
hypothèses**, sans rien prouver de neuf (c'est un durcissement d'énoncé, pas de
crypto) :

1. **Séparer trois registres**, visuellement distincts :
   - *Prouvé* — ce que le code et les forges RED établissent (soundness variable,
     liaison de forme, etc.).
   - *Supposé* — ROM, honnête-vérifieur, indépendance des primitives, absence
     d'audit. Chacun **nommé** et **isolé**, formulé de façon réfutable.
   - *Hors modèle* — canaux auxiliaires (renvoi à `THREAT_MODEL.md:794`),
     malléabilité hors intention.
2. **Chaque hypothèse porte sa conséquence si elle tombe** — un auditeur doit voir
   ce que l'énoncé perd si l'hypothèse est fausse.
3. **Aucune sur-promesse** : le mot « HVZK » n'apparaît jamais sans son qualificatif
   (honnête-vérifieur, ROM, prototype non audité), cohérent avec la discipline de
   nommage déjà appliquée aux ACVP.

### Critère de franchissement

La section HVZK de `STARK_STATEMENT.md` présente une liste d'hypothèses **isolées
et nommées**, chacune avec sa conséquence-si-fausse ; aucune affirmation ne mélange
prouvé et supposé dans la même phrase. *(Critère de revue, pas de test
automatique — c'est un texte.)*

---

## Chantier 3 — Accrocher le re-test de la dette PQ au gel de genèse

### Le défaut

`docs/BACKEND_PQ.md` décide « ne pas migrer maintenant » avec des critères de
déclenchement écrits, **mais rien ne force leur re-test avant de graver la
genèse.** La carte de juillet le notait : « une échéance à accrocher, sinon elle
se perd ». Aujourd'hui elle n'est portée par aucun jalon.

### Ce que la spec demande

Transformer l'intention en **gate procédural de T5** :

1. **Une procédure écrite** — dans `BACKEND_PQ.md` (section « Re-test avant gel »)
   ET référencée depuis `docs/TESTNET.md` (§2 procédure de reset / ou une nouvelle
   §5 « Avant de graver la genèse ») : *avant d'exécuter `obscura-genese` en
   production, rejouer les critères de déclenchement de `BACKEND_PQ.md` et
   **consigner le résultat dans le dépôt**, même s'il est « toujours non ».*
2. **Ajouter le critère ACVP** à la liste de `BACKEND_PQ.md` : *un backend
   permettant l'injection d'aléa officiel rendrait `keyGen`/`encap`/`sigGen`
   vérifiables et supprimerait le trou nommé en porte AUD* — donc son apparition
   est un déclencheur de re-évaluation.
3. **Ne rien décider d'autre** : la spec n'ordonne pas de migrer le backend. Elle
   garantit seulement que la question sera **re-posée et tracée** au bon moment.

### Critère de franchissement

`BACKEND_PQ.md` contient une section « re-test avant gel » avec le critère ACVP
ajouté ; `docs/TESTNET.md` référence cette procédure comme **pré-requis de
l'exécution de `obscura-genese`** (pas comme intention). Le futur cycle T5 n'aura
qu'à cocher cette procédure.

---

## Ce que cette spec ne fait pas

- Elle **ne commande aucun audit** (critère A, hors périmètre B).
- Elle **ne touche pas au circuit** ni à aucune primitive.
- Elle **n'implémente pas** de coinbase (J2) ni de gestion de partition (J3).
- Elle **ne re-décide pas** les canaux auxiliaires (déjà écrits).
- Elle **ne modifie aucun comportement de consensus** — c'est de la documentation
  et une procédure. Aucun test Rust ne change de résultat ; la suite reste verte
  par construction.

## Découpage suggéré pour le plan

Trois tâches indépendantes, exécutables dans n'importe quel ordre (aucune
dépendance croisée), la première étant la plus lourde :

1. **Docs normative** (le gros) : (a) mettre `docs/` à jour J1-b/J1-c
   (`PROTOCOL.md` → `0x05`, état à jour) ; (b) créer `docs/ARCHITECTURE.md` et y
   migrer le narratif par crate ; (c) migrer les autres affirmations normatives
   vers leurs fichiers `docs/` ; (d) réduire `CLAUDE.md`/`AGENTS.md` à pointeurs +
   conventions ; (e) vérifier le critère `grep`. **Ordre interne strict : (a)+(b)+(c)
   avant (d).**
2. **HVZK attaquable** : restructurer la section de `STARK_STATEMENT.md`.
3. **Échéance PQ** : section dans `BACKEND_PQ.md` + référence dans `TESTNET.md`.

⚠️ **Contrainte transverse.** Les 8 fichiers actuellement non commités par
l'utilisateur (dont `CLAUDE.md`, `AGENTS.md`, `THREAT_MODEL.md`,
`STARK_STATEMENT.md`) sont **en cours d'édition manuelle**. Le plan doit
**confronter l'état réel de ces fichiers au moment de l'exécution** et ne jamais
écraser une édition en cours — repartir du working tree, pas du dernier commit.

## Critère de franchissement global

Les trois critères de chantier sont remplis, et la suite `cargo test --all-features
--release` reste verte (aucun changement de comportement). AUD-final et D-final
sont alors clos ; il ne reste sur la voie irréversible que J2 (ADR à accepter), T5
et J3.
