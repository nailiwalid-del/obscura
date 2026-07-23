# Clôture de la voie sans regret (AUD-final + D-final) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Faire de `docs/` l'unique source normative (migration complète de `CLAUDE.md`/`AGENTS.md` vers des pointeurs), rendre l'argument HVZK attaquable, et accrocher le re-test de la dette PQ au gel de genèse.

**Architecture:** Trois chantiers **documentaires** sans dépendance croisée. Aucun code de consensus ne change — `cargo test --all-features --release` reste vert par construction. Le seul « test » exécutable est un **critère `grep`** (chantier 1) : les affirmations normatives disparaissent de `CLAUDE.md`/`AGENTS.md`. Les chantiers 2 et 3 se vérifient par revue de structure et par `grep` de présence.

**Tech Stack:** Markdown (docs), Rust (uniquement pour la vérification finale de non-régression). Aucune dépendance ajoutée.

**Spec de référence :** `docs/superpowers/specs/2026-07-23-cloture-voie-sans-regret-design.md`.

## Global Constraints

- **Repartir du WORKING TREE, jamais du dernier commit.** L'utilisateur a des éditions non commitées sur `CLAUDE.md`, `AGENTS.md`, `docs/THREAT_MODEL.md`, `docs/STARK_STATEMENT.md`, `docs/POST_QUANTIQUE.md`, `docs/obscura-overview.html`, `crates/node/examples/dimensionner-ouverture.rs`. La Tâche 0 les commite AVANT toute migration ; les tâches suivantes construisent dessus.
- **`git add` nomme TOUJOURS les fichiers explicitement — JAMAIS `git add -A`.**
- Travailler sur une branche dédiée (`docs/cloture-voie-sans-regret`), créée en Tâche 0. **Ne jamais commiter sur `master`.**
- **Ne pas fusionner** : la dernière tâche s'arrête après la vérification. La décision de fusion revient à l'utilisateur.
- Message de commit terminé par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Commentaires et docs en **français** (convention du dépôt).
- **`CLAUDE.md` ≡ `AGENTS.md` au corps près.** Toute modification du corps de l'un est répercutée sur l'autre le jour même (invariant écrit dans l'en-tête d'`AGENTS.md`). Seul l'en-tête (`Claude Code` vs `Codex`) diffère.
- **Ne RIEN supprimer d'une affirmation normative sans qu'elle existe dans `docs/`.** L'ordre est non négociable : `docs/` complété et courant (Tâches 1-3) AVANT de vider `CLAUDE.md`/`AGENTS.md` (Tâche 4).
- **Ce plan est judgment-heavy** (choisir quelle prose est normative, où elle va, comment la reformuler). Exécution **inline recommandée**, avec revue utilisateur, plutôt que subagents autonomes — voir le handoff en fin de plan.
- **Constante de vérification finale :** `cargo test --all-features --release` vert (aucun comportement changé).

---

### Task 0 : Pré-vol — base propre et branche

**Files:**
- Commit (contenu utilisateur, non modifié ici) : les 7 fichiers en cours d'édition + l'ADR J2 non tracké.

**Interfaces:**
- Produces: une branche `docs/cloture-voie-sans-regret` partant d'un working tree propre.

- [ ] **Step 1 : Confirmer avec l'utilisateur avant de commiter SON travail**

Les éditions en cours sont indépendantes de ce plan (corrections de tailles 104→105 Kio, `VERSION_ETAT 0x04`, caveat « bande ±1,5 Kio », statut consensus). **Demander à l'utilisateur** s'il veut les committer tel quel comme base, ou les committer lui-même. Ne PAS committer son travail sans accord.

- [ ] **Step 2 : Committer les éditions en cours (après accord)**

```bash
git add AGENTS.md CLAUDE.md crates/node/examples/dimensionner-ouverture.rs \
  docs/POST_QUANTIQUE.md docs/STARK_STATEMENT.md docs/THREAT_MODEL.md \
  docs/obscura-overview.html
git commit -m "$(cat <<'EOF'
docs: corrections de cohérence (tailles de preuve, VERSION_ETAT, statut consensus)

Base propre avant la migration docs/ (voie sans regret).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

Le fichier `docs/superpowers/specs/2026-07-22-j2-economie-adr.md` (ADR J2, non tracké) reste **hors de ce commit** — c'est un travail J2 séparé.

- [ ] **Step 3 : Créer la branche de travail**

```bash
git switch -c docs/cloture-voie-sans-regret
git status --short
```
Expected: working tree propre (hors l'ADR J2 non tracké, qu'on ne touche pas).

---

### Task 1 : Mettre `docs/PROTOCOL.md` à jour J1-b / J1-c

**Files:**
- Modify: `docs/PROTOCOL.md` (titre §169, section §265, + §Certificat/§Élection autour de 201-264)

**Interfaces:**
- Consumes: l'état réel du consensus (bloc `0x05`, changement d'autorités certifié à `h+K`, protocole de vue J1-b2).
- Produces: une spec de finalité **courante**, cible de migration pour les affirmations de consensus de `CLAUDE.md`.

- [ ] **Step 1 : Écrire le test de présence (grep)**

Créer un script de vérification jetable (ou une commande directe) qui échoue tant que `PROTOCOL.md` est périmé :

Run:
```bash
grep -q "VERSION_BLOC = 0x05" docs/PROTOCOL.md && \
grep -qi "changement d'autorités\|J1-c" docs/PROTOCOL.md && \
grep -qi "changement de vue\|J1-b" docs/PROTOCOL.md && \
! grep -q "VERSION_BLOC = 0x04" docs/PROTOCOL.md && echo OK || echo ECHEC
```
Expected: `ECHEC` (avant migration — la doc dit encore 0x04, état J1-a).

- [ ] **Step 2 : Mettre à jour le titre de section et la version**

Dans `docs/PROTOCOL.md`, remplacer le titre §169 :
`## Finalité : le bloc (`VERSION_BLOC = 0x04`)` → `## Finalité : le bloc (`VERSION_BLOC = 0x05`)`.
Dans le corps de cette section, partout où `0x04` désigne la version courante du bloc, écrire `0x05`, et noter que `0x04` (J1-a/b) est refusé par son nom (`VersionPerimee`).

- [ ] **Step 3 : Étendre §Certificat et §Élection à J1-b/J1-c**

Dans la section « Certificat de quorum » (~222) et « Élection de producteur et vue » (~201), ajouter :
- **J1-b (protocole de vue)** : votes sur le fil (`Vote`/`Proposition`), délai de vue + backoff, changement de vue (le producteur de `(h, vue+1)` est l'autorité suivante), quorum `⌊2n/3⌋+1`. C'est ce qui ferme la liveness — une chaîne `n ≥ 4` produit des blocs.
- **J1-c (changement d'autorités)** : champ `changement_autorites` dans l'identifiant, certifié par le quorum de l'**ancienne** liste, effet à `h+K` (K=8), un seul en vol, bloc de gouvernance vide de transactions. `VERSION_ETAT 0x05`.

- [ ] **Step 4 : Réécrire « État de la mise en œuvre »**

Remplacer le titre §265 `### État de la mise en œuvre (J1-a)` par `### État de la mise en œuvre (J1 complet)` et son corps : J1-a (format), J1-b1 (votes circulent), J1-b2 (changement de vue, liveness fermée), J1-c (reconfiguration certifiée) — **tous livrés et testés sur sockets**. La porte J1 est close.

- [ ] **Step 5 : Rejouer le test**

Run: (la commande du Step 1)
Expected: `OK`.

- [ ] **Step 6 : Commit**

```bash
git add docs/PROTOCOL.md
git commit -m "$(cat <<'EOF'
docs(protocol): finalité à jour J1-b/J1-c (bloc 0x05, vue, changement d'autorités)

VERSION_BLOC 0x05, protocole de vue et changement d'autorités certifié
décrits ; l'état de mise en œuvre reflète la fermeture de J1.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2 : Créer `docs/ARCHITECTURE.md` et y migrer le narratif par crate

**Files:**
- Create: `docs/ARCHITECTURE.md`
- Modify: `docs/CONFORMITE.md` (§4 « Où fait autorité la spécification » — ajouter le renvoi)
- Source (lecture) : `CLAUDE.md` §État (lignes ~22-406)

**Interfaces:**
- Consumes: le narratif par crate de `CLAUDE.md` (invariants et ⚠️ rationale de crypto/net/ledger/circuit/wallet/node).
- Produces: `docs/ARCHITECTURE.md`, home normatif du narratif d'architecture, référencé par `CONFORMITE.md`.

- [ ] **Step 1 : Écrire le test de présence**

Run:
```bash
test -f docs/ARCHITECTURE.md && \
for c in crypto net ledger circuit wallet node; do \
  grep -q "crates/$c" docs/ARCHITECTURE.md || { echo "manque $c"; break; }; \
done && grep -q "ARCHITECTURE.md" docs/CONFORMITE.md && echo OK || echo ECHEC
```
Expected: `ECHEC` (le fichier n'existe pas).

- [ ] **Step 2 : Créer le squelette de `docs/ARCHITECTURE.md`**

```markdown
# Architecture d'Obscura — rôles et invariants par crate

> **Source normative.** Ce fichier décrit ce que fait chaque crate et
> **pourquoi** sa structure est ce qu'elle est (les ⚠️ sont des invariants à ne
> pas régresser). Pour les FORMATS et RÈGLES, l'autorité est `docs/PROTOCOL.md` ;
> pour le modèle d'adversaire, `docs/THREAT_MODEL.md` ; pour l'énoncé STARK,
> `docs/STARK_STATEMENT.md`.

## Vue d'ensemble

Prototype Rust, phases 1 à 5 prototypées et testées : nœud persistant, cycle
complet payer → sceller → recevoir validé sur testnet local, consensus BFT fédéré
(J1 complet).

## crate `crypto`
## crate `net`
## crate `ledger`
## crate `circuit`
## crate `wallet`
## crate `node`
## Notes de build (features dev/consensus)
```

- [ ] **Step 3 : Migrer le contenu par crate**

Pour chaque crate, **déplacer** (couper de la source, coller ici) le paragraphe correspondant de `CLAUDE.md` §État, en **préservant les blocs ⚠️** (ce sont les invariants) et en **mettant à jour vers J1 complet** (le paragraphe `ledger`/`node` mentionne « J1-a livre le FORMAT » et « J1-b SUIVANT » : corriger — J1-b et J1-c sont livrés). Ne pas paraphraser au point de perdre une raison ; ce narratif EST l'autorité désormais.

Migrer aussi le contenu de `CLAUDE.md` §Notes de build (features `dev-transparent`/`dev-circuits`, invariant « défaut = consensus seul », zeroize, migration FIPS, dette PQ **par renvoi à `BACKEND_PQ.md`**) dans la section « Notes de build » d'`ARCHITECTURE.md`.

- [ ] **Step 4 : Référencer depuis `CONFORMITE.md` §4**

Dans `docs/CONFORMITE.md` §4 « Où fait autorité la spécification », ajouter `docs/ARCHITECTURE.md` à la liste des fichiers faisant autorité (rôles et invariants par crate).

- [ ] **Step 5 : Rejouer le test**

Run: (la commande du Step 1)
Expected: `OK`.

- [ ] **Step 6 : Commit**

```bash
git add docs/ARCHITECTURE.md docs/CONFORMITE.md
git commit -m "$(cat <<'EOF'
docs(architecture): narratif par crate migré de CLAUDE.md, mis à jour J1 complet

Nouveau docs/ARCHITECTURE.md : rôles et invariants (⚠️) de crypto/net/ledger/
circuit/wallet/node, référencé depuis CONFORMITE.md §4. Autorité déplacée hors
des notes d'agent.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3 : Migrer les affirmations normatives résiduelles

**Files:**
- Modify: `docs/PROTOCOL.md` (§Changements v0.1→v0.2 — combler les trous)
- Source (lecture) : `CLAUDE.md` §Décisions v0.2

**Interfaces:**
- Consumes: `CLAUDE.md` §Décisions v0.2 (nullifier v2, hiérarchie shielded_secret, Merkle prof. 32/16, versioning d'algos, key privacy IK-CCA, hash consensus ≠ prouvé).
- Produces: `PROTOCOL.md` couvrant chaque décision v0.2 — plus rien d'unique dans `CLAUDE.md`.

- [ ] **Step 1 : Auditer les trous**

Run:
```bash
for k in "nullifier" "shielded_secret" "profondeur 32" "IK-CCA" "Rescue-Prime"; do \
  echo -n "$k dans PROTOCOL.md: "; grep -qi "$k" docs/PROTOCOL.md && echo oui || echo NON; \
done
```
Expected: liste ; tout `NON` est un trou à combler au Step 2.

- [ ] **Step 2 : Combler chaque trou dans `PROTOCOL.md`**

Pour chaque décision v0.2 de `CLAUDE.md` **absente** de `PROTOCOL.md`, l'y ajouter (section §Changements v0.1→v0.2 ou la section thématique adéquate : nullifier → §Transaction, Merkle → §Arbre de Merkle, versioning → §Versioning, key privacy → §Chiffrement des notes). Reformuler comme spec (pas comme note d'agent). Ce qui est déjà couvert n'est pas dupliqué.

- [ ] **Step 3 : Rejouer l'audit**

Run: (la commande du Step 1)
Expected: tout `oui`.

- [ ] **Step 4 : Commit**

```bash
git add docs/PROTOCOL.md
git commit -m "$(cat <<'EOF'
docs(protocol): décisions v0.2 résiduelles migrées de CLAUDE.md

nullifier v2, hiérarchie shielded_secret, Merkle 32/16, key privacy IK-CCA,
hash consensus != prouvé — chaque décision a désormais son home normatif.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4 : Réduire `CLAUDE.md` et `AGENTS.md` à des pointeurs

**Files:**
- Modify: `CLAUDE.md`, `AGENTS.md`

**Interfaces:**
- Consumes: `docs/` désormais complet et courant (Tâches 1-3).
- Produces: deux fichiers réduits à en-tête + pointeurs + conventions ; corps identiques.

- [ ] **Step 1 : Écrire le test `grep` du critère AUD**

Le critère falsifiable : plus aucune affirmation normative **autoportante** dans `CLAUDE.md`/`AGENTS.md`. Test :

Run:
```bash
# Les constantes/formats de protocole ne doivent apparaître QUE dans un contexte
# de pointeur (ligne contenant "docs/"), jamais comme affirmation autonome.
faux=0
for f in CLAUDE.md AGENTS.md; do
  while IFS= read -r line; do
    echo "$line" | grep -qE "VERSION_BLOC|VERSION_ETAT|MAX_OCTETS_BLOC|MAX_TX_PAR_BLOC|quorum_requis|0x0[0-9]|2f\+1" || continue
    echo "$line" | grep -q "docs/" && continue   # pointeur : toléré
    echo "AFFIRMATION NORMATIVE RESIDUELLE dans $f: $line"; faux=1
  done < "$f"
done
[ "$faux" = 0 ] && echo OK || echo ECHEC
```
Expected: `ECHEC` (avant réduction — le corps est plein de ces constantes).

- [ ] **Step 2 : Composer le bloc de pointeurs (corps commun)**

Le nouveau corps (identique pour les deux fichiers, sous leur en-tête respectif) remplace les sections §Principe directeur, §État, §Prochaine étape, §Décisions v0.2, §Notes de build par :

```markdown
## Où est l'autorité

Ce fichier ne fait pas autorité (voir l'en-tête). La spécification vit dans
`docs/` :

- **Par où commencer :** `docs/CONFORMITE.md` (statut, où fait autorité quoi).
- **Formats et règles de consensus :** `docs/PROTOCOL.md` (bloc 0x05, vue,
  changement d'autorités, versioning, transaction, Merkle, key privacy).
- **Rôles et invariants par crate :** `docs/ARCHITECTURE.md` (crypto, net,
  ledger, circuit, wallet, node — et les ⚠️ à ne pas régresser).
- **Modèle d'adversaire :** `docs/THREAT_MODEL.md` (dont canaux auxiliaires).
- **Énoncé STARK et witness-hiding :** `docs/STARK_STATEMENT.md`.
- **Dette backend PQ :** `docs/BACKEND_PQ.md`. **Post-quantique :**
  `docs/POST_QUANTIQUE.md`.
- **Exploitation / testnet :** `docs/OPERATEUR.md`, `docs/TESTNET.md`.
- **Feuille de route :** `docs/superpowers/specs/2026-07-23-reste-a-faire-vers-B.md`.

## État en une ligne

Prototype Rust, phases 1-5 testées ; consensus BFT fédéré **J1 complet**
(finalité, liveness, reconfiguration d'autorités). Prototype pédagogique non
audité — ne pas utiliser en production.
```

Puis **garder tel quel** la section §Conventions (langue des commentaires, tests, hash séparé par domaine) — c'est une consigne d'agent légitime, pas une affirmation normative de protocole.

- [ ] **Step 3 : Appliquer à `CLAUDE.md`**

Remplacer les sections normatives de `CLAUDE.md` par le bloc du Step 2, en conservant l'en-tête `# Obscura — contexte projet pour Claude Code` + le paragraphe d'avertissement d'origine, et la §Conventions finale.

- [ ] **Step 4 : Appliquer à `AGENTS.md` (corps identique)**

Reproduire **exactement** le même corps dans `AGENTS.md`, sous son en-tête `# Obscura — contexte projet pour Codex` (et son avertissement de divergence). Vérifier l'identité des corps :

Run:
```bash
diff <(sed '1,/^## Où est l.autorité/d' CLAUDE.md) \
     <(sed '1,/^## Où est l.autorité/d' AGENTS.md) && echo "CORPS IDENTIQUES" || echo "DIVERGENCE"
```
Expected: `CORPS IDENTIQUES`.

- [ ] **Step 5 : Rejouer le test du critère AUD**

Run: (la commande du Step 1)
Expected: `OK`.

- [ ] **Step 6 : Commit**

```bash
git add CLAUDE.md AGENTS.md
git commit -m "$(cat <<'EOF'
docs(aud): CLAUDE.md et AGENTS.md réduits à des pointeurs vers docs/

L'autorité normative vit désormais dans docs/ (PROTOCOL, ARCHITECTURE,
THREAT_MODEL, STARK_STATEMENT). Les deux notes d'agent ne portent plus
d'affirmation normative autoportante ; corps identiques, seul l'en-tête
diffère. Ferme le critère AUD "deux sources de vérité divergentes".

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5 : Rendre l'argument HVZK attaquable (`STARK_STATEMENT.md`)

**Files:**
- Modify: `docs/STARK_STATEMENT.md` (section « Argument HVZK »)

**Interfaces:**
- Consumes: la section HVZK existante (honnête-vérifieur, ROM).
- Produces: un énoncé à trois registres (Prouvé / Supposé / Hors modèle), hypothèses isolées.

- [ ] **Step 1 : Écrire le test de structure**

Run:
```bash
grep -qi "## .*Prouvé\|### Prouvé\|\*\*Prouvé\*\*" docs/STARK_STATEMENT.md && \
grep -qi "Supposé\|hypothèse" docs/STARK_STATEMENT.md && \
grep -qi "si.*hypothèse.*tombe\|conséquence si\|si.*faux" docs/STARK_STATEMENT.md && \
echo OK || echo ECHEC
```
Expected: `ECHEC` (les registres ne sont pas séparés explicitement).

- [ ] **Step 2 : Restructurer la section HVZK en trois registres**

Réécrire (sans nouvelle preuve — durcissement d'énoncé) la section « Argument HVZK » en trois sous-parties **visuellement distinctes** :

1. **Prouvé** — ce que le code et les forges RED établissent (soundness variable, liaison de forme, D7/D8), avec renvoi aux tests.
2. **Supposé** — chaque hypothèse **nommée, isolée, réfutable**, avec **sa conséquence si elle tombe** :
   - ROM (Fiat-Shamir) — si fausse : la non-interactivité n'est plus sûre.
   - Honnête-vérifieur — si fausse : un vérifieur malicieux pourrait extraire de l'information du witness.
   - Indépendance des primitives (défense en profondeur) — si fausse : la marge « une des deux tient » s'effondre.
   - Absence d'audit — statut, pas hypothèse mathématique, mais à énoncer.
3. **Hors modèle** — canaux auxiliaires (renvoi `THREAT_MODEL.md` § canaux auxiliaires), malléabilité hors intention.

Règle de nommage : « HVZK » n'apparaît jamais sans qualificatif (honnête-vérifieur, ROM, prototype non audité).

- [ ] **Step 3 : Rejouer le test de structure**

Run: (la commande du Step 1)
Expected: `OK`.

- [ ] **Step 4 : Revue manuelle**

Relire : aucune phrase ne mélange « prouvé » et « supposé » ; chaque hypothèse a une conséquence-si-fausse. (Critère de revue — pas de test automatique.)

- [ ] **Step 5 : Commit**

```bash
git add docs/STARK_STATEMENT.md
git commit -m "$(cat <<'EOF'
docs(stark): énoncé HVZK rendu attaquable — Prouvé / Supposé / Hors modèle

Hypothèses (ROM, honnête-vérifieur, indépendance des primitives, non-audité)
isolées et nommées, chacune avec sa conséquence si elle tombe. Un auditeur
peut cibler une hypothèse précise.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6 : Accrocher le re-test de la dette PQ au gel de genèse

**Files:**
- Modify: `docs/BACKEND_PQ.md` (nouvelle section « Re-test avant gel »)
- Modify: `docs/TESTNET.md` (référence comme pré-requis de `obscura-genese`)

**Interfaces:**
- Consumes: les critères de déclenchement existants de `BACKEND_PQ.md`.
- Produces: une procédure référencée, gate de T5 ; le critère ACVP ajouté.

- [ ] **Step 1 : Écrire le test de présence**

Run:
```bash
grep -qi "re-test avant.*gel\|avant.*graver.*genèse\|avant.*obscura-genese" docs/BACKEND_PQ.md && \
grep -qi "injection d'aléa\|keyGen\|ACVP" docs/BACKEND_PQ.md && \
grep -qi "BACKEND_PQ\|dette.*PQ\|re-test" docs/TESTNET.md && echo OK || echo ECHEC
```
Expected: `ECHEC`.

- [ ] **Step 2 : Ajouter la section « Re-test avant gel » à `BACKEND_PQ.md`**

```markdown
## Re-test avant le gel de genèse (gate de T5)

**Avant d'exécuter `obscura-genese` en production**, rejouer les critères de
déclenchement ci-dessus et **consigner le résultat dans le dépôt**, même s'il est
« toujours non ». La décision « ne pas migrer » n'est valable qu'à sa date ; la
graver dans une chaîne exige de la re-confirmer.

**Critère ACVP ajouté :** un backend permettant l'**injection d'aléa officiel**
(graine de `keyGen`) rendrait `keyGen`/`encap`/`sigGen` vérifiables par vecteurs
ACVP complets — et supprimerait le trou nommé en porte AUD (aujourd'hui seuls
`decap`/`sigVer`, déterministes, sont couverts). Son apparition **déclenche** une
ré-évaluation du backend.
```

- [ ] **Step 3 : Référencer depuis `docs/TESTNET.md`**

Dans `docs/TESTNET.md` §2 (procédure de reset) ou une nouvelle sous-section « Avant de graver la genèse », ajouter : *pré-requis bloquant — rejouer et consigner le re-test de `docs/BACKEND_PQ.md` (« Re-test avant le gel de genèse ») avant toute exécution de `obscura-genese` en production.*

- [ ] **Step 4 : Rejouer le test**

Run: (la commande du Step 1)
Expected: `OK`.

- [ ] **Step 5 : Commit**

```bash
git add docs/BACKEND_PQ.md docs/TESTNET.md
git commit -m "$(cat <<'EOF'
docs(backend-pq): re-test de la dette PQ accroché au gel de genèse (gate T5)

Procédure "re-test avant gel" + critère ACVP (injection d'aléa) ; TESTNET.md
la référence comme pré-requis bloquant de obscura-genese. L'échéance ne se
perd plus.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7 : Vérification finale et non-régression

**Files:**
- Aucun (vérification seule)

**Interfaces:**
- Consumes: tout ce qui précède.

- [ ] **Step 1 : Critère AUD global (grep) une dernière fois**

Run: (la commande du critère AUD, Task 4 Step 1)
Expected: `OK`.

- [ ] **Step 2 : Corps `CLAUDE.md` ≡ `AGENTS.md`**

Run: (la commande de diff, Task 4 Step 4)
Expected: `CORPS IDENTIQUES`.

- [ ] **Step 3 : Non-régression — la suite reste verte**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --all-features --release
```
Expected: TOUT vert. (Aucun code n'a changé ; ce step prouve que la migration documentaire n'a rien cassé — p. ex. un doctest ou un chemin de fichier référencé.)

- [ ] **Step 4 : Couverture de spec (revue manuelle)**

Confronter au spec `2026-07-23-cloture-voie-sans-regret-design.md` : les 3 critères de chantier sont remplis (docs normative + grep ; HVZK trois registres ; échéance PQ référencée). Lister tout écart ; s'il y en a, ajouter une tâche.

- [ ] **Step 5 : S'ARRÊTER**

Ne pas fusionner. Rapporter à l'utilisateur l'état de la branche `docs/cloture-voie-sans-regret` et attendre sa décision (revue, PR, ou fusion).

---

## Notes transverses pour l'exécutant

- **Migration = déplacement, pas réécriture.** Le narratif par crate de `CLAUDE.md` est riche et *précis* (les ⚠️ encodent des invariants durement acquis). Le couper-coller vers `docs/ARCHITECTURE.md` en le mettant à jour (J1 complet) est le geste ; le paraphraser au point de perdre une raison est une régression.
- **L'ordre docs-avant-vidage est un invariant de sûreté.** Vider `CLAUDE.md` (Tâche 4) avant que `docs/` soit complet (Tâches 1-3) ferait perdre du contexte aux sessions futures. Ne jamais inverser.
- **Deux fichiers, un corps.** Chaque édition du corps de `CLAUDE.md` se répercute sur `AGENTS.md` le jour même. Le test de diff (Task 4 Step 4) le garantit.
- **Aucun comportement de consensus ne change.** Si un `cargo test` échoue en Tâche 7, la cause est un chemin de fichier ou un doctest référençant une doc déplacée — pas une régression de protocole.
