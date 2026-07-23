# J3 — Consensus périmètre B — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rendre le consensus défendable en réseau public expérimental — prouver par test la survie aux partitions et le comportement en minorité, écrire la procédure de mise à jour, et ajouter une négociation de version de fil explicite avec coexistence ancien/nouveau.

**Architecture:** Trois chantiers. Chantiers 1-2 sont surtout des TESTS et de la DOC (la sûreté de partition est déjà offerte par le quorum BFT append-only ; on l'énonce et on la prouve). Chantier 3 porte du CODE : la négociation de version vit au **niveau NODE** (message applicatif optionnel en tête), PAS dans le handshake `net` — voir la décision ci-dessous.

**Tech Stack:** Rust, crates `node` (cœur du chantier 3 + tests sockets), `ledger` (comportement quorum, déjà en place). TDD, preuves STARK gatées derrière `--release`.

**Spec de référence :** `docs/superpowers/specs/2026-07-23-j3-consensus-perimetre-b-design.md`.

> ## ⚠️ DÉCISION DE CONCEPTION — déviation ASSUMÉE de la spec (à valider en revue)
>
> La spec écrit « échange de version **au handshake `crates/net`** après le
> chiffrement ». **Ce plan place la négociation au niveau NODE**, pas dans `net`,
> pour deux raisons :
> 1. **`net` est « pur transport »** (invariant d'architecture, `docs/ARCHITECTURE.md`).
>    Y injecter une version de PROTOCOLE APPLICATIF le pollue et casse la propriété
>    qui garde `net` réutilisable.
> 2. **La coexistence ancien/nouveau** est plus propre en applicatif : un message
>    `Message::Version` OPTIONNEL en tête ride la `Session` déjà chiffrée (donc
>    « après le chiffrement », exigence de la spec satisfaite), et un nœud ancien
>    qui n'en envoie pas est simplement présumé « version de base » — aucune
>    modification du format de handshake, donc aucun risque de casser `net`.
>
> Le critère de franchissement de la spec (échange explicite, refus sans sanction,
> coexistence) est intégralement tenu. **Si l'utilisateur préfère l'insertion dans
> `net`, réviser ce plan avant exécution.**

## Global Constraints

- **Preuves STARK gatées `--release`** : tests à preuves portent `#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]`.
- `git add` nomme TOUJOURS les fichiers explicitement — JAMAIS `git add -A`.
- Branche dédiée (`feat/j3-consensus-b`), créée en Tâche 0. **Ne jamais commiter sur `master`.** Ne pas fusionner : la dernière tâche s'arrête après vérification.
- Message de commit terminé par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Commentaires et docs en **FRANÇAIS**.
- Ne pas toucher au non-tracké `docs/superpowers/specs/2026-07-22-j2-economie-adr.md`.
- **Toute nouvelle borne vérifiée AVANT allocation** (discipline anti-DoS du dépôt).
- **`net` reste PUR TRANSPORT** : aucune dépendance de `net` vers le protocole applicatif ; le chantier 3 ne modifie PAS `crates/net`.
- **Coexistence = invariant** : un nœud AVEC négociation de version ne doit JAMAIS bannir un nœud SANS (pair en retard ≠ hostile) — c'est la logique de `version_inconnue()` généralisée.
- **Constantes de protocole (verbatim) :**
  - `TAG_VERSION: u8 = 10` (après `TAG_VOTE = 9` ; `DERNIER_TAG` devient `TAG_VERSION`).
  - `VERSION_PROTOCOLE: u16 = 1` (version de base courante).
  - `VERSION_MIN_ACCEPTEE: u16 = 1` (plancher accepté ; en dessous → refus propre sans sanction).
- **Commandes CI (vertes avant chaque commit de fin de tâche) :**
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-features --release`

---

### Task 0 : Pré-vol — branche

- [ ] **Step 1 : Créer la branche depuis `feat/j1c-changement-autorites`** (base à jour, J1 complet)

```bash
git switch feat/j1c-changement-autorites
git switch -c feat/j3-consensus-b
git status --short
```
Expected: propre (hors non-tracké J2).

- [ ] **Step 2 : Repérer le pattern de test sockets à réutiliser**

Run: `ls crates/node/tests/ && grep -c "fn " crates/node/tests/chaos_producteur.rs`
Expected: `chaos_producteur.rs` présent (le chantier 1 s'en inspire). Le lire pour le montage de nœuds sur sockets réelles.

---

### Task 1 : Partition et comportement en minorité (test + doc)

**Files:**
- Create: `crates/node/tests/partition.rs`
- Modify: `docs/PROTOCOL.md` (politique de minorité), `docs/TESTNET.md` (limite écrite)

**Interfaces:**
- Consumes: le montage multi-nœuds de `chaos_producteur.rs` ; le quorum BFT (`ProvedLedgerState::quorum_requis`).
- Produces: preuve testée que la minorité s'arrête sans forker et rejoint proprement.

- [ ] **Step 1 : Écrire le test de partition (RED)**

Créer `crates/node/tests/partition.rs`. S'inspirer du montage de `chaos_producteur.rs`. Scénario : un ensemble d'autorités à `n = 4` (quorum 3), coupé en deux groupes (3 nœuds « majorité », 1 « minorité »), puis reconnecté.

```rust
//! Partition (J3, chantier 1) : la minorité s'arrête sans forker, la majorité
//! avance, et au retour la minorité rattrape la MÊME tête. Sûreté par le quorum
//! BFT append-only — ce test l'ÉNONCE et la prouve.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn minorite_sarrete_majorite_avance_puis_convergence() {
    // 1. Monter 4 nœuds-autorités sur sockets (réutiliser le helper de chaos_producteur).
    // 2. Partitionner : couper les liens entre {A,B,C} (majorité, ≥ quorum 3) et {D} (minorité).
    // 3. Faire produire la majorité : elle scelle, atteint le quorum, avance de plusieurs hauteurs.
    // 4. Asserter : D (minorité) N'A PAS avancé (ne peut pas atteindre le quorum seul),
    //    et n'a produit AUCUN bloc concurrent (pas de fork).
    // 5. Guérir la partition (reconnecter D).
    // 6. Asserter : D rattrape par le chemin normal (DemandeBloc) et converge vers la
    //    tête de la majorité — MÊME identifiant de tête, MÊME hauteur.
    // (Le corps exact suit le montage de chaos_producteur.rs — helpers de nœud, de
    //  socket, et attendre_en_tiquant. Ne pas inventer d'API : réutiliser les siens.)
}
```

⚠️ Écrire le corps en réutilisant EXACTEMENT les helpers de `chaos_producteur.rs` (montage de nœuds, sockets, tic). Vérifier leurs noms par lecture avant d'appeler.

- [ ] **Step 2 : Lancer, vérifier l'échec (ou le montage)**

Run: `cargo test -p node --release --test partition 2>&1 | tail -20`
Expected: le test compile et exprime le scénario ; il échoue si l'assertion de convergence n'est pas encore satisfaite par un montage correct. (Si le comportement est déjà correct — probable, la sûreté est native — le test PASSE et devient une non-régression ; c'est acceptable pour ce chantier « énoncer + prouver ».)

- [ ] **Step 3 : Écrire la politique de minorité**

Dans `docs/PROTOCOL.md` (section consensus) : un nœud qui n'atteint pas le quorum s'ARRÊTE de produire (gel suspensif — cas général de l'autorité absente), CONTINUE de servir (lecture, historique, rattrapage), et ne FORK jamais (append-only). Cas sans majorité (partition équilibrée) : personne ne produit, la sûreté prime la liveness, reprise à la guérison.

Dans `docs/TESTNET.md` (limites) : ajouter la limite « une partition sans côté majoritaire fige la production jusqu'à la guérison — attendu, la chaîne reprend ».

- [ ] **Step 4 : Lancer le test, vérifier le vert**

Run: `cargo test -p node --release --test partition 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 5 : CI locale + commit**

```bash
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings
git add crates/node/tests/partition.rs docs/PROTOCOL.md docs/TESTNET.md
git commit -m "$(cat <<'EOF'
j3(partition): la minorité s'arrête sans forker, converge à la guérison

Test sockets : n=4 partitionné 3/1, la majorité avance, la minorité ne
produit rien (quorum inatteignable) ni ne forke, et rattrape la même tête
au retour. Politique de minorité écrite (PROTOCOL, TESTNET).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2 : Procédure de mise à jour (rolling upgrade)

**Files:**
- Modify: `docs/OPERATEUR.md`

**Interfaces:**
- Consumes: la tolérance de version réactive (`version_inconnue()`) + la négociation explicite (Task 3).
- Produces: une procédure écrite distinguant changement compatible / rupture.

- [ ] **Step 1 : Écrire le test de présence**

Run:
```bash
grep -qi "mise à jour\|rolling\|rupture.*consensus\|compatible.*fil" docs/OPERATEUR.md && \
grep -qi "rupture.*nouvelle chaîne\|nouvelle chaîne" docs/OPERATEUR.md && echo OK || echo ECHEC
```
Expected: `ECHEC`.

- [ ] **Step 2 : Écrire la procédure**

Dans `docs/OPERATEUR.md`, section « Mettre à jour le logiciel » :
- **Distinguer deux natures** : (a) *compatible fil* (n'affecte ni le format de bloc ni les règles de validation — déploiement nœud par nœud, ordre libre, appuyé sur la tolérance de version) ; (b) *rupture de consensus* (change une règle de validation ou le format de bloc).
- **La règle du testnet fédéré** : une rupture = **nouvelle chaîne** (cohérent avec « chaîne consommable », `docs/TESTNET.md`). Pas d'activation par hauteur en périmètre B.
- **Lien avec la négociation de version** : l'échange explicite (Task 3) permet de CONSTATER qui parle quelle version avant de déployer.

- [ ] **Step 3 : Lancer le test**

Run: (commande du Step 1) — Expected: `OK`.

- [ ] **Step 4 : Commit**

```bash
git add docs/OPERATEUR.md
git commit -m "$(cat <<'EOF'
j3(mise à jour): procédure rolling upgrade — compatible vs rupture

Un changement compatible fil se déploie nœud par nœud ; une rupture de
consensus = nouvelle chaîne (périmètre B, chaîne consommable).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3 : Négociation de version explicite (niveau NODE)

**Files:**
- Modify: `crates/node/src/message.rs`
- Modify: `crates/node/src/orchestration.rs` (traitement à la réception)
- Modify: `crates/node/src/runtime.rs` (émission en tête à l'établissement d'une connexion)
- Test: `crates/node/tests/negociation_version.rs` (sockets)

**Interfaces:**
- Consumes: le format `Message` tag-based existant (`TAG_ANNONCE..TAG_VOTE`, `version_inconnue()`), le montage sockets.
- Produces:
  - `pub const VERSION_PROTOCOLE: u16 = 1;`, `pub const VERSION_MIN_ACCEPTEE: u16 = 1;`, `const TAG_VERSION: u8 = 10;` (`DERNIER_TAG = TAG_VERSION`).
  - Variante `Message::Version { protocole: u16 }` (encodage `TAG_VERSION ‖ u16 LE`, décodage borné).
  - À la réception : `Message::Version` avec `protocole < VERSION_MIN_ACCEPTEE` → déconnexion NOMMÉE sans sanction de score ; sinon enregistrement. Absence de `Version` (pair ancien) → présumé version de base, aucune sanction.

- [ ] **Step 1 : Écrire les tests du format `Message::Version` (RED)**

Dans `mod tests` de `crates/node/src/message.rs` :

```rust
    /// Message::Version fait l'aller-retour wire (TAG_VERSION ‖ u16 LE).
    #[test]
    fn version_aller_retour() {
        let m = Message::Version { protocole: VERSION_PROTOCOLE };
        let relu = Message::from_bytes(&m.to_bytes()).expect("décodable");
        assert!(matches!(relu, Message::Version { protocole } if protocole == VERSION_PROTOCOLE));
    }

    /// TAG_VERSION est le dernier tag connu ; un tag au-delà reste « version future ».
    #[test]
    fn version_est_le_dernier_tag_connu() {
        assert_eq!(DERNIER_TAG, TAG_VERSION);
        assert!(erreur(&[TAG_VERSION + 1]).version_inconnue());
    }

    /// Un Message::Version tronqué est une MALFORMATION, pas une version future.
    #[test]
    fn version_tronquee_est_malformation() {
        assert!(!erreur(&[TAG_VERSION]).version_inconnue());
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec de compilation**

Run: `cargo test -p node --lib message:: 2>&1 | head -20`
Expected: échec (`Message::Version`, `TAG_VERSION`, `VERSION_PROTOCOLE` inexistants).

- [ ] **Step 3 : Ajouter le tag, les constantes et la variante**

Dans `crates/node/src/message.rs` :
- `const TAG_VERSION: u8 = 10;` après `TAG_VOTE`. Mettre `const DERNIER_TAG: u8 = TAG_VERSION;` et étendre l'assertion de compilation `tags_contigus` à `TAG_VERSION`.
- `pub const VERSION_PROTOCOLE: u16 = 1;` et `pub const VERSION_MIN_ACCEPTEE: u16 = 1;`.
- Variante `Version { protocole: u16 }` dans l'enum `Message`.
- Encodage dans `to_bytes` : `b.push(TAG_VERSION); b.extend_from_slice(&protocole.to_le_bytes());`.
- Décodage dans `from_bytes` : sur `TAG_VERSION`, lire 2 octets bornés (`prendre`/curseur, comme les autres tags), rejeter le résiduel, produire `Message::Version { protocole }`.

- [ ] **Step 4 : Lancer les tests message, vérifier le vert**

Run: `cargo test -p node --lib message:: 2>&1 | tail -15`
Expected: PASS (dont les 3 nouveaux ; `version_inconnue_distinguee_dune_malformation` et `tags_contigus` toujours verts).

- [ ] **Step 5 : Écrire le test de politique à la réception (RED)**

Dans `mod tests` d'`orchestration.rs` (fonction pure, sans I/O). Vérifier les noms réels de l'entrée d'orchestration par lecture préalable.

```rust
    /// Un pair annonçant une version < VERSION_MIN_ACCEPTEE est refusé PROPREMENT,
    /// SANS sanction de score (un pair en retard n'est pas hostile).
    #[test]
    fn version_trop_basse_refusee_sans_sanction() {
        // Construire l'entrée d'orchestration pour Message::Version { protocole: 0 }
        // (0 < VERSION_MIN_ACCEPTEE = 1). Attendu : une Action de déconnexion nommée
        // (p. ex. Action::Deconnecter{ raison } ou équivalent réel), et AUCUNE
        // pénalité de score. Suivre le type Action réel de ce module.
    }

    /// Un pair à version acceptée est enregistré, aucune déconnexion.
    #[test]
    fn version_acceptee_enregistree() {
        // Message::Version { protocole: VERSION_PROTOCOLE } → pas de déconnexion.
    }
```

⚠️ Lire `orchestration.rs` AVANT d'écrire : réutiliser son type `Action` réel et sa signature d'entrée. Ne pas inventer de variante — si une déconnexion nommée n'existe pas, l'ajouter explicitement (variante d'`Action`) est légitime, mais la NOMMER et l'implémenter, pas la supposer.

- [ ] **Step 6 : Câbler le traitement à la réception**

Dans `orchestration.rs`, traiter `Message::Version { protocole }` : si `protocole < VERSION_MIN_ACCEPTEE`, retourner l'action de déconnexion nommée SANS pénalité ; sinon enregistrer (ou ignorer proprement). L'absence de `Version` ne déclenche RIEN (présomption version de base — ne pas exiger le message).

- [ ] **Step 7 : Émettre `Version` en tête à l'établissement d'une connexion**

Dans `runtime.rs`, à l'établissement d'une connexion (sortante ET entrante), envoyer `Message::Version { protocole: VERSION_PROTOCOLE }` comme PREMIER message applicatif, avant tout autre. Vérifier le point exact par lecture (là où une `Connexion`/`Session` devient active). Un pair ancien qui reçoit ce `TAG_VERSION` inconnu le traite en « version future » (non sanctionné) et l'ignore — coexistence assurée dans les deux sens.

- [ ] **Step 8 : Test de coexistence sur sockets (RED puis vert)**

Créer `crates/node/tests/negociation_version.rs` :

```rust
//! Négociation de version (J3, chantier 3) sur sockets réelles.
//! - deux nœuds À JOUR échangent Version et se connectent normalement ;
//! - un nœud qui n'envoie JAMAIS Version (simule l'ancien) n'est PAS banni ;
//! - un nœud annonçant protocole=0 (< min) est déconnecté sans sanction.
```

Monter les scénarios avec le helper sockets existant. Pour « l'ancien », utiliser une connexion qui n'émet pas le message Version (ou un pair qui envoie directement une Annonce). Asserter : pas de bannissement, score inchangé.

- [ ] **Step 9 : Lancer toute la surface node**

Run: `cargo test -p node --release 2>&1 | tail -20`
Expected: PASS (message, orchestration, sockets, dont les nouveaux ; aucune régression sur `version_inconnue_*`, quorum, finalité).

- [ ] **Step 10 : Documenter le format et CI + commit**

Documenter dans `docs/PROTOCOL.md` (§protocole applicatif) : `TAG_VERSION`, `VERSION_PROTOCOLE`/`VERSION_MIN_ACCEPTEE`, message optionnel en tête, refus sans sanction, coexistence. C'est ce que J3 gèle du format de fil.

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --all-features --release
git add crates/node/src/message.rs crates/node/src/orchestration.rs \
  crates/node/src/runtime.rs crates/node/tests/negociation_version.rs docs/PROTOCOL.md
git commit -m "$(cat <<'EOF'
j3(version): négociation de version de fil explicite au niveau node

Message::Version optionnel en tête (TAG_VERSION, u16), sur la Session chiffrée.
Version < VERSION_MIN_ACCEPTEE refusée sans sanction ; absence présumée version
de base (coexistence ancien/nouveau, testée sur sockets). net reste pur transport.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4 : Vérification finale

- [ ] **Step 1 : Suite complète verte**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --all-features --release
```
Expected: TOUTE la suite verte (crypto/net/ledger/circuit/wallet/node), dont `partition` et `negociation_version`.

- [ ] **Step 2 : `net` non touché (invariant de pureté)**

Run: `git diff --name-only feat/j1c-changement-autorites..HEAD -- crates/net/`
Expected: AUCUN fichier — le chantier 3 n'a pas modifié `net`.

- [ ] **Step 3 : Couverture de spec (revue manuelle)**

Confronter à `2026-07-23-j3-consensus-perimetre-b-design.md` : chantier 1 (partition testée + politique écrite), chantier 2 (procédure de mise à jour), chantier 3 (version explicite, refus sans sanction, coexistence). Vérifier que la déviation « niveau node vs net » est bien celle validée. Lister tout écart.

- [ ] **Step 4 : S'ARRÊTER**

Ne pas fusionner. Rapporter : le réseau survit à une partition et se met à jour sans fork non intentionnel ; l'état B est atteint (reste la décision écrite B → A).

---

## Notes transverses pour l'exécutant

- **Chantier 1 = énoncer + prouver, pas construire.** La sûreté de partition est native au quorum BFT append-only. Le test peut PASSER d'emblée ; c'est voulu — il transforme une propriété implicite en non-régression explicite.
- **Chantier 3 vit au niveau NODE.** Ne PAS modifier `crates/net` (invariant de pureté, vérifié en Tâche 4 Step 2). Le message `Version` ride la `Session` déjà chiffrée.
- **Coexistence est l'invariant dur.** Un pair qui n'envoie pas `Version` n'est jamais banni ; un `TAG_VERSION` inconnu d'un ancien nœud tombe dans `version_inconnue()` (non sanctionné). Tester les DEUX sens.
- **Ne jamais inventer d'API.** Réutiliser les helpers de `chaos_producteur.rs` (sockets), le type `Action` réel d'`orchestration.rs`, le pattern d'encodage/décodage borné de `message.rs`. Lire avant d'appeler.
- **Déviation de spec à valider.** Si l'utilisateur veut l'insertion dans `net`, ce plan est à réviser AVANT exécution.
