# T5 — Ouverture du testnet public — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construire la MACHINERIE d'ouverture d'un testnet public sur invitation — outil de signature de release (minisign), runbook d'ouverture, et scaffolding de publication de l'ancre de genèse — sans exécuter les actes irréversibles eux-mêmes (gel de la vraie genèse, signature de la vraie release, publication du vrai identifiant), qui sont des gestes d'opérateur au moment de l'ouverture.

**Architecture:** Trois livrables sans dépendance de consensus : (1) un script de signature + une clé publique au dépôt + une procédure de vérification, testables avec une clé JETABLE ; (2) un runbook `docs/OUVERTURE.md` qui SÉQUENCE des procédures déjà écrites ailleurs (il ne crée aucune règle) ; (3) un gabarit `docs/GENESE.md` pour publier l'ancre 64 o, référencé par le runbook. Aucun code Rust ne change.

**Tech Stack:** minisign (signify), Bash/PowerShell (scripts d'aide), Markdown (docs). Aucune dépendance Rust ajoutée.

**Spec de référence :** `docs/superpowers/specs/2026-07-23-t5-ouverture-testnet-design.md`.

## Global Constraints

- **DÉPEND de la branche `docs/cloture-voie-sans-regret`.** Ce plan édite `docs/OPERATEUR.md` et référence `docs/TESTNET.md §2.4` (gate PQ) et `docs/BACKEND_PQ.md` — tous modifiés par cette branche non encore fusionnée. **Brancher DEPUIS `docs/cloture-voie-sans-regret`** (ou depuis `master`/`feat/j1c` APRÈS sa fusion). Vérifier en Tâche 0 que `docs/TESTNET.md` contient bien §2.4 et que `docs/OUVERTURE.md` n'existe pas encore.
- **Aucune clé PRIVÉE au dépôt.** La clé privée minisign est un secret d'opérateur, générée hors dépôt, jamais commitée. Seule la clé PUBLIQUE (`deploiement/release.pub`) entre au dépôt. Les tests utilisent une clé JETABLE créée dans un répertoire temporaire et détruite.
- **N'exécute AUCUN acte d'ouverture irréversible.** Pas de `obscura-genese` en production, pas de signature d'une vraie release, pas de publication d'un vrai identifiant de chaîne. Le plan produit la machinerie ; l'ouverture est l'exécution du runbook par un humain.
- `git add` nomme TOUJOURS les fichiers explicitement — JAMAIS `git add -A`.
- Travailler sur une branche dédiée (`docs/t5-ouverture`), créée en Tâche 0. **Ne jamais commiter sur `master`.** Ne pas fusionner : la dernière tâche s'arrête après vérification.
- Message de commit terminé par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Commentaires et docs en **FRANÇAIS**.
- Ne pas toucher au fichier non tracké `docs/superpowers/specs/2026-07-22-j2-economie-adr.md`.
- **Décision de conception (verbatim de la spec) :** signature par **minisign** ; on signe un **manifeste de checksums** (un artefact = une ligne), pas chaque artefact séparément ; la clé publique est publiée au dépôt ET son empreinte hors bande.
- **Prérequis outil :** `minisign` doit être disponible sur la machine d'exécution. Si absent, l'installer (`scoop install minisign` / `choco install minisign` / `apt install minisign`) AVANT la Tâche 1 — ne pas contourner le test.

---

### Task 0 : Pré-vol — branche et prérequis

**Files:** aucun (vérification + branche).

**Interfaces:**
- Produces: branche `docs/t5-ouverture` partant de `docs/cloture-voie-sans-regret`.

- [ ] **Step 1 : Vérifier la base de dépendance**

Run:
```bash
git branch --list docs/cloture-voie-sans-regret && \
grep -q "2.4 Avant de graver la genèse" docs/TESTNET.md && \
grep -qi "re-test.*gel\|Re-test avant" docs/BACKEND_PQ.md && \
test ! -f docs/OUVERTURE.md && echo "BASE OK" || echo "BASE MANQUANTE"
```
Expected: `BASE OK`. Si `BASE MANQUANTE`, la branche voie-sans-regret n'est pas la base — s'arrêter et escalader (ce plan en dépend).

- [ ] **Step 2 : Vérifier la disponibilité de minisign**

Run:
```bash
command -v minisign && minisign -v || echo "MINISIGN ABSENT — l'installer avant Tâche 1"
```
Expected: une version. Si absent, installer minisign avant de continuer.

- [ ] **Step 3 : Créer la branche depuis voie-sans-regret**

```bash
git switch docs/cloture-voie-sans-regret
git switch -c docs/t5-ouverture
git status --short
```
Expected: working tree propre (hors le non-tracké J2).

---

### Task 1 : Outil de signature de release (minisign) + vérification

**Files:**
- Create: `deploiement/signer-release.sh` (script d'aide, signe un manifeste de checksums)
- Create: `deploiement/verifier-release.sh` (script de vérification pour un tiers)
- Create: `deploiement/release.pub` (**placeholder** documenté — remplacé par la vraie clé publique au moment de la première release)
- Create: `deploiement/tests/signer-release.test.sh` (test avec clé jetable)
- Modify: `docs/OPERATEUR.md` (section « Vérifier une release »)

**Interfaces:**
- Consumes: `minisign` (outil externe).
- Produces:
  - `signer-release.sh <repertoire-artefacts> <cle-privee>` → écrit `checksums.txt` (SHA-256 par artefact) + `checksums.txt.minisig` dans le répertoire.
  - `verifier-release.sh <repertoire-artefacts> <cle-publique>` → vérifie la signature du manifeste PUIS chaque checksum ; code de sortie non nul si l'un échoue.

- [ ] **Step 1 : Écrire le test (clé jetable, altération rejetée)**

Créer `deploiement/tests/signer-release.test.sh` :

```bash
#!/usr/bin/env bash
# Test de bout en bout de la signature de release, avec une clé JETABLE.
set -euo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# Répertoire d'artefacts factices.
mkdir artefacts
printf 'binaire factice obscura-node\n' > artefacts/obscura-node
printf 'genese factice\n' > artefacts/genese.bin

# Clé jetable minisign (sans mot de passe).
minisign -G -p rel.pub -s rel.key -W

# Signer.
bash "$OLDPWD/deploiement/signer-release.sh" artefacts rel.key
test -f artefacts/checksums.txt
test -f artefacts/checksums.txt.minisig

# Vérifier : doit PASSER.
bash "$OLDPWD/deploiement/verifier-release.sh" artefacts rel.pub

# Altérer un artefact d'un octet : la vérification doit ÉCHOUER.
printf 'X' >> artefacts/obscura-node
if bash "$OLDPWD/deploiement/verifier-release.sh" artefacts rel.pub 2>/dev/null; then
  echo "ECHEC : altération NON détectée"; exit 1
fi
echo "TEST OK : altération détectée, release saine vérifiée"
```

- [ ] **Step 2 : Lancer le test, vérifier l'échec**

Run: `bash deploiement/tests/signer-release.test.sh`
Expected: échec (`signer-release.sh` / `verifier-release.sh` n'existent pas encore).

- [ ] **Step 3 : Écrire `deploiement/signer-release.sh`**

```bash
#!/usr/bin/env bash
# Signe une release Obscura : produit un manifeste de checksums SHA-256 (un
# artefact = une ligne) et le signe avec minisign. La clé privée est un secret
# d'opérateur — jamais dans le dépôt. Usage : signer-release.sh <repertoire> <cle-privee>
set -euo pipefail
rep="${1:?répertoire d'artefacts requis}"
cle="${2:?clé privée minisign requise}"
cd "$rep"
# Manifeste : checksums de tous les fichiers sauf le manifeste lui-même.
: > checksums.txt
for f in *; do
  [ "$f" = checksums.txt ] && continue
  [ "$f" = checksums.txt.minisig ] && continue
  sha256sum "$f" >> checksums.txt
done
# Signer le manifeste.
minisign -S -s "$cle" -m checksums.txt
echo "Release signée : $(wc -l < checksums.txt) artefact(s), manifeste checksums.txt.minisig"
```

- [ ] **Step 4 : Écrire `deploiement/verifier-release.sh`**

```bash
#!/usr/bin/env bash
# Vérifie une release Obscura : (1) signature minisign du manifeste, (2) chaque
# checksum. Sortie non nulle si l'un échoue. Usage : verifier-release.sh <repertoire> <cle-publique>
set -euo pipefail
rep="${1:?répertoire d'artefacts requis}"
pub="${2:?clé publique minisign requise}"
cd "$rep"
# 1) Signature du manifeste.
minisign -V -p "$pub" -m checksums.txt
# 2) Checksums (sha256sum -c échoue si un fichier diffère).
sha256sum -c checksums.txt
echo "Release vérifiée : manifeste signé et checksums conformes."
```

- [ ] **Step 5 : Écrire `deploiement/release.pub` (placeholder documenté)**

```
# Clé publique minisign des releases Obscura testnet.
# PLACEHOLDER — à remplacer par la vraie clé publique au moment de la première
# release signée (générée hors dépôt : `minisign -G -p release.pub -s release.key`).
# L'empreinte de cette clé DOIT aussi être publiée hors bande (canal d'invitation),
# sinon un attaquant qui remplace le binaire remplace la clé du même coup.
RWQPLACEHOLDER0000000000000000000000000000000000000000000
```

- [ ] **Step 6 : Rendre les scripts exécutables et lancer le test**

Run:
```bash
chmod +x deploiement/signer-release.sh deploiement/verifier-release.sh deploiement/tests/signer-release.test.sh
bash deploiement/tests/signer-release.test.sh
```
Expected: `TEST OK : altération détectée, release saine vérifiée`.

- [ ] **Step 7 : Documenter la vérification dans `docs/OPERATEUR.md`**

Ajouter une section « Vérifier une release » : la commande exacte qu'un tiers exécute (`bash verifier-release.sh <repertoire> deploiement/release.pub`), l'exigence de confronter l'empreinte de `release.pub` à la valeur publiée hors bande, et le rappel que la clé privée ne quitte jamais l'opérateur.

- [ ] **Step 8 : CI locale + commit**

```bash
cargo fmt --all -- --check   # inchangé : aucun Rust touché, mais garde l'habitude
git add deploiement/signer-release.sh deploiement/verifier-release.sh \
  deploiement/release.pub deploiement/tests/signer-release.test.sh docs/OPERATEUR.md
git commit -m "$(cat <<'EOF'
t5(release): signature minisign d'un manifeste de checksums + vérification

Scripts signer/verifier-release, clé publique placeholder au dépôt (privée
hors dépôt), test à clé jetable (altération d'un octet rejetée), procédure
de vérification dans OPERATEUR.md.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2 : Runbook d'ouverture `docs/OUVERTURE.md`

**Files:**
- Create: `docs/OUVERTURE.md`

**Interfaces:**
- Consumes: procédures existantes (`BACKEND_PQ.md` re-test, `obscura-genese`, `verifier-release.sh` de Task 1, `TESTNET.md`).
- Produces: le runbook séquençant l'ouverture ; RÉFÉRENCÉ par aucun code (document opérateur).

- [ ] **Step 1 : Écrire le test de présence**

Run:
```bash
test -f docs/OUVERTURE.md && \
grep -qi "re-test.*PQ\|BACKEND_PQ" docs/OUVERTURE.md && \
grep -qi "obscura-genese" docs/OUVERTURE.md && \
grep -qi "verifier-release\|release signée" docs/OUVERTURE.md && \
grep -qi "hors bande" docs/OUVERTURE.md && \
grep -qi "consommable\|reset\|réaction" docs/OUVERTURE.md && echo OK || echo ECHEC
```
Expected: `ECHEC` (le fichier n'existe pas).

- [ ] **Step 2 : Écrire le runbook**

Créer `docs/OUVERTURE.md`. Il NE CRÉE AUCUNE RÈGLE : il séquence et renvoie. Structure imposée :

```markdown
# Runbook d'ouverture du testnet Obscura

> Ce document SÉQUENCE des procédures écrites ailleurs. En cas de divergence,
> la source renvoyée fait autorité. Chaque étape a une pré-condition et un
> critère de vérification. Les étapes 2 à 4 sont IRRÉVERSIBLES pour la chaîne
> ouverte (consommable, mais refaite = nouvelle chaîne).

## Points de centralisation assumés (à lire d'abord)
- L'archiviste voit passer les demandes de tous les autres (`docs/TESTNET.md`).
- `--temoin` n'a de valeur qu'avec ≥ 2 archivistes indépendants.
- Rejoindre après le gel exige une nouvelle chaîne (adresses/autorités gravées).

## Étape 1 — Re-test de la dette PQ (BLOQUANT)
Rejouer et CONSIGNER les critères de `docs/BACKEND_PQ.md` (« Re-test avant le gel
de genèse »). Ne pas passer à l'étape 2 sans cette trace écrite, même « toujours non ».

## Étape 2 — Gel de la genèse
`obscura-genese` avec autorités (`--autorite-hex`) et allocations décidées. Il
auto-vérifie et imprime l'identifiant COMPLET (64 o). Critère : l'identifiant imprimé.

## Étape 3 — Publication de l'ancre
Renseigner `docs/GENESE.md` (identifiant 64 o) et publier la MÊME valeur hors bande.
Voir `docs/GENESE.md`.

## Étape 4 — Release signée
Signer binaires + genèse (`deploiement/signer-release.sh`), publier la release et
`deploiement/release.pub`. Vérification tierce : `deploiement/verifier-release.sh`.

## Étape 5 — Annonce
Publier les limites AVANT l'ouverture (`docs/TESTNET.md` §1), la chaîne
consommable, et la règle de réaction à la valeur (`docs/TESTNET.md` §3).
```

Renseigner chaque section avec le renvoi exact (vérifier les titres/numéros réels de `TESTNET.md`, `BACKEND_PQ.md`).

- [ ] **Step 3 : Lancer le test**

Run: (commande du Step 1)
Expected: `OK`.

- [ ] **Step 4 : Commit**

```bash
git add docs/OUVERTURE.md
git commit -m "$(cat <<'EOF'
t5(runbook): docs/OUVERTURE.md séquence l'ouverture du testnet

Cinq étapes ordonnées (re-test PQ bloquant → gel genèse → ancre → release
signée → annonce), chacune renvoyant à sa source d'autorité. Aucune règle
neuve. Points de centralisation en tête.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3 : Gabarit de publication de l'ancre `docs/GENESE.md`

**Files:**
- Create: `docs/GENESE.md`
- Modify: `docs/TESTNET.md` (renvoi vers `GENESE.md` là où l'identifiant de genèse est évoqué)

**Interfaces:**
- Consumes: `obscura-node` imprime déjà l'identifiant complet au démarrage (correctif `2e9e4df`).
- Produces: le gabarit où l'ancre 64 o est publiée + la procédure de comparaison.

- [ ] **Step 1 : Écrire le test de présence**

Run:
```bash
test -f docs/GENESE.md && \
grep -qi "hors bande" docs/GENESE.md && \
grep -qi "obscura-node\|au démarrage" docs/GENESE.md && \
grep -q "GENESE.md" docs/TESTNET.md && echo OK || echo ECHEC
```
Expected: `ECHEC`.

- [ ] **Step 2 : Écrire le gabarit `docs/GENESE.md`**

```markdown
# Ancre de genèse du testnet Obscura

> Ce fichier publie l'identifiant de la genèse de la chaîne courante. C'est
> l'ancre hors bande vis-à-vis du réseau P2P : `THREAT_MODEL.md` rappelle que
> rien dans le protocole n'atteste QUI a écrit la genèse — cette publication,
> plus la release signée, y supplée.

## Chaîne courante

- **Identifiant complet (64 o, hex)** : `<À RENSEIGNER AU GEL — sortie de obscura-genese>`
- **Genèse signée** : voir la release (`deploiement/verifier-release.sh`).
- **Valeur hors bande** : la même chaîne hex est publiée sur le canal d'invitation.

## Comment un opérateur vérifie

Au démarrage, `obscura-node --genese genese.bin` imprime l'identifiant COMPLET.
Le confronter (1) à la valeur ci-dessus ET (2) à la valeur reçue hors bande. Un
écart = ne pas rejoindre.
```

- [ ] **Step 3 : Référencer depuis `docs/TESTNET.md`**

Là où `TESTNET.md` évoque l'identifiant de genèse / la comparaison hors bande, ajouter un renvoi vers `docs/GENESE.md` comme lieu de publication de l'ancre.

- [ ] **Step 4 : Lancer le test**

Run: (commande du Step 1)
Expected: `OK`.

- [ ] **Step 5 : Commit**

```bash
git add docs/GENESE.md docs/TESTNET.md
git commit -m "$(cat <<'EOF'
t5(ancre): gabarit docs/GENESE.md pour publier l'identifiant de genèse

Ancre 64 o + valeur hors bande + procédure de comparaison au démarrage
(obscura-node imprime l'identifiant complet). Référencé depuis TESTNET.md.
Valeur réelle renseignée au gel.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4 : Vérification finale

**Files:** aucun.

- [ ] **Step 1 : Le test de signature passe**

Run: `bash deploiement/tests/signer-release.test.sh`
Expected: `TEST OK`.

- [ ] **Step 2 : Runbook et ancre cohérents**

Run:
```bash
# Les renvois du runbook pointent vers des fichiers/sections réels.
for f in BACKEND_PQ OPERATEUR TESTNET GENESE; do test -f "docs/$f.md" || echo "MANQUE docs/$f.md"; done
grep -q "GENESE.md" docs/OUVERTURE.md && grep -q "verifier-release" docs/OUVERTURE.md && echo "renvois OK"
```
Expected: `renvois OK`, aucun « MANQUE ».

- [ ] **Step 3 : Non-régression Rust (aucun code touché)**

```bash
cargo build --all-features --release 2>&1 | tail -3
```
Expected: build OK (T5 ne touche aucun code ; ce step confirme que les ajouts `deploiement/` ne cassent aucun chemin de build).

- [ ] **Step 4 : Couverture de spec (revue manuelle)**

Confronter à `2026-07-23-t5-ouverture-testnet-design.md` : chantier 1 (release signée testée), chantier 2 (runbook), chantier 3 (ancre). Aucun acte d'ouverture irréversible exécuté. Lister tout écart.

- [ ] **Step 5 : S'ARRÊTER**

Ne pas fusionner. Rapporter à l'utilisateur : la machinerie d'ouverture est prête ; l'ouverture réelle (gel de genèse, signature de la vraie release, publication du vrai identifiant) reste un geste d'opérateur suivant `docs/OUVERTURE.md`.

---

## Notes transverses pour l'exécutant

- **T5 construit la machinerie, PAS l'ouverture.** Aucune vraie genèse gelée, aucune vraie release signée, aucun vrai identifiant publié — ce sont des gestes humains au moment de l'ouverture, guidés par `docs/OUVERTURE.md`. Le plan les rend POSSIBLES et VÉRIFIABLES.
- **La clé privée de release est un secret d'opérateur.** Elle n'entre jamais au dépôt ni en CI. Les tests utilisent une clé jetable en répertoire temporaire.
- **Le runbook ne crée aucune règle.** S'il contredit une source renvoyée, c'est un défaut du runbook, pas de la source.
- **Dépendance de branche.** Ce plan suppose `docs/cloture-voie-sans-regret` comme base (gate PQ dans TESTNET §2.4, verif dans OPERATEUR). Si cette branche est fusionnée avant exécution, brancher depuis `master`/`feat/j1c` à jour.
