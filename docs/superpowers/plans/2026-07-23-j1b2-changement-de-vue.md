# J1-b2 — Changement de vue : la liveness fermée

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sur une chaîne à autorités, un producteur absent est contourné par
changement de vue — la chaîne continue avec le producteur suivant.

**Architecture:** Le registre de votes passe à une clé « hauteur seule » (sûreté
triviale). Le nœud gagne un couple `(vue_courante, debut_vue_ms)` réinitialisé
par un helper unique `hauteur_avancee`. Un délai de vue à backoff exponentiel,
piloté par le `tick(maintenant_ms)` existant, incrémente la vue quand la hauteur
n'avance pas. `sceller` propose à la vue courante, bloc vide permis. Le calage est
rendu visible (journal `CRITIQUE`, compteur, statut).

**Tech Stack:** Rust 1.87, aucune dépendance nouvelle. Le P0 quorum
(`⌊2n/3⌋+1`) est **déjà dans master** (`6f94ca4`).

**Référence :** `docs/superpowers/specs/2026-07-23-j1b2-changement-de-vue-design.md`.

## Global Constraints

- **Code et commentaires en français.**
- **Aucune dépendance ajoutée.**
- **Le vote reste PERSISTÉ avant d'être émis** (acquis J1-b1, inchangé).
- **Format du registre `0x01 → 0x02`.** Un `0x01` est refusé par son nom. Pas de
  migration : suppression manuelle de `votes.bin` lors d'une mise à niveau
  coordonnée, geste d'opérateur explicite, jamais un repli automatique.
- **Le temps est INJECTÉ** (`maintenant_ms`), jamais lu de l'horloge dans
  l'orchestration. Tout test de vue utilise des temps injectés, aucun `sleep`.
- **Ordre de coût préservé** : rien de coûteux (STARK) avant d'avoir voté.
- **La CI se rejoue localement** avec ses commandes exactes, passe **par défaut**
  comprise (`cargo clippy --workspace --all-targets --release -- -D warnings`).
- **`git add` nomme les fichiers.** Jamais `-A` : l'arbre peut contenir du
  travail en cours étranger.

## File Structure

| Fichier | Rôle |
|---|---|
| `crates/node/src/votes.rs` | registre à clé hauteur seule, format `0x02` |
| `crates/node/src/orchestration.rs` | état de vue, `tick`, `hauteur_avancee`, `sur_proposition`, `sceller`, calage |
| `crates/node/src/journal.rs` | `Statut` gagne `hauteurs_calees` |
| `crates/node/src/bin/obscura-node.rs` | passe le compteur au statut |
| `crates/node/tests/vue_sockets.rs` | **nouveau** — producteur absent, la chaîne avance |
| `crates/node/tests/chaos_producteur.rs` | test de sûreté inter-vues (mutation) |

**Constantes** (dans `orchestration.rs`) :

```rust
/// Facteur entre la cadence (--sceller) et le délai de vue de BASE. ≥ 3 pour
/// qu'un producteur qui répond ne soit jamais tourné avant d'avoir proposé.
const FACTEUR_VUE: u64 = 3;
/// Cadence de consensus par défaut d'une autorité, même sans --sceller.
const CADENCE_CONSENSUS_MS_DEFAUT: u64 = 5_000;
/// Plafond de vues par hauteur : au-delà, la hauteur est déclarée CALÉE.
const MAX_VUE_PAR_HAUTEUR: u32 = 1_000;
/// Fenêtre d'adoption d'une vue future non certifiée : un seul pas au-delà.
const FENETRE_VUE: u32 = 1;
/// Plafond du backoff, pour borner l'attente maximale.
const PLAFOND_DELAI_VUE_MS: u64 = 60_000;
```

---

### Task 1: Le registre à clé « hauteur seule » (format 0x02)

**Files:**
- Modify: `crates/node/src/votes.rs`

**Interfaces:**
- Produces : `RegistreVotes::peut_voter(hauteur: u64, id: &[u8; 64]) -> bool`
  (la `vue` DISPARAÎT de la signature) ; `enregistrer(hauteur: u64, id: [u8; 64])` ;
  `VERSION_VOTES = 0x02` ; format `version ‖ hauteur ‖ id` (77 → 73 octets).

**Pourquoi la vue disparaît.** Sous le modèle A, un nœud ne vote qu'un `id` par
hauteur, toutes vues confondues. La sûreté ne dépend donc que de la hauteur. Le
champ `vue` du registre n'a plus de rôle et est retiré — le format rétrécit.

- [ ] **Step 1: Réécrire les tests du registre**

Remplacer, dans `mod tests` de `votes.rs`, les tests qui passent `vue` par :

```rust
    /// LA règle de sûreté, clé hauteur seule : un id par hauteur, toutes vues
    /// confondues.
    #[test]
    fn un_seul_id_par_hauteur() {
        let mut r = RegistreVotes::neuf();
        assert!(r.peut_voter(1, &[1u8; 64]));
        r.enregistrer(1, [1u8; 64]);

        // Même hauteur, MÊME id : idempotent (un vote peut se perdre).
        assert!(r.peut_voter(1, &[1u8; 64]));
        // Même hauteur, AUTRE id : refusé, MÊME à une vue supérieure — c'est tout
        // le point du modèle A, la vue n'entre pas dans la décision.
        assert!(!r.peut_voter(1, &[2u8; 64]));
        // Hauteur suivante : autorisée.
        assert!(r.peut_voter(2, &[3u8; 64]));

        r.enregistrer(2, [3u8; 64]);
        // Retour en arrière : refusé.
        assert!(!r.peut_voter(1, &[9u8; 64]));
    }

    #[test]
    fn le_registre_survit_a_laller_retour() {
        let mut r = RegistreVotes::neuf();
        r.enregistrer(7, [4u8; 64]);
        let relu = RegistreVotes::from_bytes(&r.to_bytes()).expect("relisible");
        assert_eq!(relu, r);
        assert!(!relu.peut_voter(7, &[5u8; 64]), "l'interdit survit");
        assert!(relu.peut_voter(8, &[5u8; 64]));
    }

    #[test]
    fn registre_0x01_refuse_par_son_nom() {
        // Un ancien registre J1-b1 (0x01, 77 octets) est refusé, pas réinterprété.
        let mut ancien = vec![0x01u8];
        ancien.extend_from_slice(&7u64.to_le_bytes());
        ancien.extend_from_slice(&0u32.to_le_bytes()); // vue, disparue
        ancien.extend_from_slice(&[4u8; 64]);
        assert!(matches!(
            RegistreVotes::from_bytes(&ancien),
            Err(VoteDecodeError::VersionInconnue(0x01)) | Err(VoteDecodeError::Taille { .. })
        ));
    }
```

Supprimer `enregistrer_ne_recule_pas` s'il testait la vue ; sinon l'adapter à la
signature sans vue.

- [ ] **Step 2: Lancer, vérifier l'échec** — `cargo test -p node --lib votes`
      (échec de compilation : signatures changées).

- [ ] **Step 3: Implémenter**

Dans `votes.rs` :

```rust
const VERSION_VOTES: u8 = 0x02;
/// version(1) + hauteur(8) + id(64).
const TAILLE: usize = 1 + 8 + 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistreVotes {
    hauteur: u64,
    id: [u8; 64],
}
```

`peut_voter` et `enregistrer` perdent le paramètre `vue` :

```rust
    pub fn peut_voter(&self, hauteur: u64, id: &[u8; 64]) -> bool {
        match hauteur.cmp(&self.hauteur) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => &self.id == id,
            std::cmp::Ordering::Less => false,
        }
    }

    pub fn enregistrer(&mut self, hauteur: u64, id: [u8; 64]) {
        if hauteur >= self.hauteur {
            self.hauteur = hauteur;
            self.id = id;
        }
    }

    /// Dernière hauteur votée — pour le journal.
    pub fn hauteur(&self) -> u64 {
        self.hauteur
    }
```

`neuf()`, `to_bytes()` et `from_bytes()` perdent le champ `vue`. `from_bytes`
exige la taille EXACTE 73 et refuse `0x01` par `VersionInconnue`.

- [ ] **Step 4: Lancer, vérifier le succès** — `cargo test -p node --lib votes`.

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/votes.rs
git commit -m "consensus(J1-b2): registre à clé HAUTEUR seule (format 0x02)

Sous le modèle A (un vote par hauteur), la vue sort de la clé de sûreté :
un nœud ne vote qu'un id par hauteur, toutes vues confondues. Le champ vue
du registre n'a plus de rôle, il est retiré, le format passe 0x01->0x02
(77->73 octets). Un 0x01 est refusé par son nom, jamais réinterprété."
```

---

### Task 2: L'état de vue et le helper `hauteur_avancee`

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes : le registre de la tâche 1.
- Produces : champs `vue_courante: u32`, `debut_vue_ms: u64`,
  `hauteurs_calees: u64` ; méthode privée `hauteur_avancee(&mut self,
  maintenant_ms: u64)` ; accesseurs `pub fn vue_courante(&self) -> u32` et
  `pub fn hauteurs_calees(&self) -> u64`.

**Le helper unique.** Le reset de vue a lieu par plusieurs chemins
d'application. Le centraliser évite l'oubli dans un seul d'entre eux.

- [ ] **Step 1: Écrire le test**

```rust
    #[test]
    fn hauteur_avancee_remet_la_vue_a_zero() {
        let mut n = noeud_de_test();
        n.vue_courante = 5;
        n.debut_vue_ms = 100;
        n.votes_recus.insert([1u8; 64], Default::default());
        n.proposition_en_cours =
            Some(ledger::bloc::Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap());

        n.hauteur_avancee(999);

        assert_eq!(n.vue_courante, 0);
        assert_eq!(n.debut_vue_ms, 999);
        assert!(n.votes_recus.is_empty());
        assert!(n.proposition_en_cours.is_none());
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec** — `cargo test -p node --lib
      orchestration::tests::hauteur_avancee`.

- [ ] **Step 3: Implémenter**

Ajouter au `struct Noeud`, près de `proposition_en_cours` :

```rust
    /// Vue de la hauteur qu'on essaie d'atteindre. Remise à 0 par
    /// `hauteur_avancee`.
    vue_courante: u32,
    /// Uptime (ms) auquel la fenêtre (hauteur, vue) courante a commencé. Réarmé à
    /// chaque avancée de hauteur ET à chaque adoption d'une vue future.
    debut_vue_ms: u64,
    /// Hauteurs déclarées CALÉES (vue plafonnée sans avancée). Non nul = un split
    /// de votes a figé une hauteur — une nouvelle chaîne est nécessaire.
    hauteurs_calees: u64,
```

Les initialiser dans `Noeud::new` (`vue_courante: 0, debut_vue_ms: 0,
hauteurs_calees: 0`).

```rust
    /// Point d'entrée UNIQUE du reset de vue. À appeler après CHAQUE
    /// `appliquer_bloc` réussi, par tous les chemins — DRY, pas d'oubli possible.
    fn hauteur_avancee(&mut self, maintenant_ms: u64) {
        self.vue_courante = 0;
        self.debut_vue_ms = maintenant_ms;
        self.votes_recus.clear();
        self.proposition_en_cours = None;
    }

    /// Vue courante — pour le journal et les tests.
    pub fn vue_courante(&self) -> u32 {
        self.vue_courante
    }

    /// Nombre de hauteurs calées — pour le statut d'exploitation.
    pub fn hauteurs_calees(&self) -> u64 {
        self.hauteurs_calees
    }
```

- [ ] **Step 4: Lancer, vérifier le succès.**

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/orchestration.rs
git commit -m "consensus(J1-b2): état de vue + helper unique hauteur_avancee

vue_courante, debut_vue_ms, hauteurs_calees. Le reset de vue passe par un
SEUL point d'entrée (hauteur_avancee), appelé après chaque appliquer_bloc
réussi : impossible d'oublier le reset dans un des chemins d'application."
```

---

### Task 3: `peut_voter` sans vue partout, et le reset câblé

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes : `hauteur_avancee` (tâche 2), `peut_voter(hauteur, id)` (tâche 1).

**But :** brancher la nouvelle signature `peut_voter`/`enregistrer` (sans vue)
partout, et remplacer les resets manuels de vue par `hauteur_avancee`.

- [ ] **Step 1: Adapter les appels**

Dans `sur_proposition`, `sur_vote` et `sceller`, remplacer :
- `self.votes.peut_voter(bloc.hauteur, vue, &id)` → `self.votes.peut_voter(bloc.hauteur, &id)` ;
- `self.votes.enregistrer(bloc.hauteur, vue, id)` → `self.votes.enregistrer(bloc.hauteur, id)`.

Après chaque `appliquer_bloc` réussi (dans `sur_vote` le collecteur, `sur_bloc`,
`sceller` chemin auto-application), appeler `self.hauteur_avancee(maintenant_ms)`
au lieu de tout reset manuel de `votes_recus`/`proposition_en_cours`.

⚠️ `sur_bloc` et `sur_vote` reçoivent-ils `maintenant_ms` ? `sur_bloc` non
aujourd'hui. Le lui passer depuis `traiter` (qui l'a déjà). Fil de la signature :
`sur_bloc(&mut self, de, bloc, maintenant_ms)`.

- [ ] **Step 2: Lancer la suite du crate** — `cargo test -p node --release`.
      Expected : les tests d'orchestration J1-b1 passent avec la nouvelle
      signature ; en corriger les appels de test (`peut_voter`/`enregistrer` sans
      vue) là où ils échouent à compiler.

- [ ] **Step 3: Commit**

```bash
git add crates/node/src/orchestration.rs
git commit -m "consensus(J1-b2): peut_voter sans vue partout, reset via hauteur_avancee

Toutes les décisions de vote passent à la clé hauteur seule. Chaque
appliquer_bloc réussi appelle hauteur_avancee(maintenant_ms) — un seul
point de reset. sur_bloc reçoit désormais maintenant_ms, fil depuis traiter."
```

---

### Task 4: Le délai de vue dans `tick`, avec backoff

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes : `producteur_attendu(hauteur, vue)`, `hauteur_avancee`.
- Produces : `delai_vue(vue: u32) -> u64` ; l'extension de `tick(maintenant_ms)`.

- [ ] **Step 1: Écrire les tests**

```rust
    #[test]
    fn delai_de_vue_depasse_la_cadence() {
        // Le délai de BASE (vue 0) vaut FACTEUR_VUE × cadence, donc STRICTEMENT
        // supérieur à la cadence — un producteur qui répond n'est jamais tourné.
        assert_eq!(delai_vue(0), FACTEUR_VUE * CADENCE_CONSENSUS_MS_DEFAUT);
        assert!(delai_vue(0) > CADENCE_CONSENSUS_MS_DEFAUT);
        // Backoff : la vue 1 attend plus que la vue 0, et tout est plafonné.
        assert!(delai_vue(1) > delai_vue(0));
        assert!(delai_vue(30) <= PLAFOND_DELAI_VUE_MS);
    }

    #[test]
    fn tick_incremente_la_vue_au_franchissement() {
        // 4 autorités, nous sommes l'autorité 1 (pas le producteur de (1,0)).
        let cles: Vec<SigKeypair> = (0..4).map(|_| SigKeypair::generate()).collect();
        let genese = ledger::bloc::Bloc::genese_avec_autorites(
            Vec::new(),
            cles.iter().map(|k| k.public.clone()).collect(),
        )
        .unwrap();
        let etat = ProvedLedgerState::depuis_genese_depth(&genese, 4).unwrap();
        let mut n = Noeud::new(
            SigKeypair::from_bytes_secret(&cles[1].to_bytes_secret()).unwrap(),
            etat,
            [7u8; 32],
        );
        n.debut_vue_ms = 0;

        // Avant le délai : rien.
        let _ = n.tick(delai_vue(0) - 1);
        assert_eq!(n.vue_courante, 0);

        // Au franchissement : la vue monte, le timer se réarme.
        let _ = n.tick(delai_vue(0));
        assert_eq!(n.vue_courante, 1);
        assert_eq!(n.debut_vue_ms, delai_vue(0), "le timer est réarmé");
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec.**

- [ ] **Step 3: Implémenter**

```rust
/// Délai de vue à backoff exponentiel : base × 2^vue, plafonné.
fn delai_vue(vue: u32) -> u64 {
    let base = FACTEUR_VUE * CADENCE_CONSENSUS_MS_DEFAUT;
    base.saturating_mul(1u64 << vue.min(20))
        .min(PLAFOND_DELAI_VUE_MS)
}
```

Étendre `tick` (qui rend déjà `Vec<Action>` pour Dandelion) :

```rust
    pub fn tick(&mut self, maintenant_ms: u64) -> Vec<Action> {
        let mut actions = self.tick_dandelion(maintenant_ms); // l'ancien corps

        // Détecteur de panne (chaîne à autorités seulement).
        if !self.etat.autorites().is_empty()
            && maintenant_ms.saturating_sub(self.debut_vue_ms) >= delai_vue(self.vue_courante)
        {
            if self.vue_courante >= MAX_VUE_PAR_HAUTEUR {
                // CALAGE — traité en tâche 6.
                actions.extend(self.declarer_calage());
            } else {
                self.vue_courante += 1;
                self.debut_vue_ms = maintenant_ms;
                // Si le nouveau producteur, c'est nous : proposer (tâche 5).
                if let Some(a) = self.proposer_si_notre_tour(maintenant_ms) {
                    actions.extend(a);
                }
            }
        }
        actions
    }
```

Renommer l'ancien corps de `tick` en `tick_dandelion`. `declarer_calage` et
`proposer_si_notre_tour` sont des stubs `Vec::new()` ici, remplis en tâches 5 et 6.

- [ ] **Step 4: Lancer, vérifier le succès.**

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/orchestration.rs
git commit -m "consensus(J1-b2): délai de vue à backoff dans tick

Passé le délai sans avancée de hauteur, la vue s'incrémente et le timer se
réarme. Backoff exponentiel (base × 2^vue, plafonné) contre le livelock dû
aux horloges non synchronisées. Actif sur chaîne à autorités seulement."
```

---

### Task 5: Proposer à `vue_courante`, blocs vides permis

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes : l'état de vue, `tick`.
- Produces : `proposer_si_notre_tour(&mut self, maintenant_ms: u64) ->
  Option<Vec<Action>>` ; `sceller` modifié.

**Deux changements de `sceller`** (spec III) : proposer à `vue_courante` (pas
`vue = 0` en dur) et **ne plus rendre `None` sur mempool vide** (bloc vide) sur
une chaîne à autorités.

- [ ] **Step 1: Écrire le test**

```rust
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn bloc_vide_produit_sur_chaine_a_autorites() {
        // Autorité unique (quorum 1), mempool VIDE : sceller produit quand même un
        // bloc vide et l'applique (le battement).
        let nous = SigKeypair::generate();
        let genese =
            ledger::bloc::Bloc::genese_avec_autorites(Vec::new(), vec![nous.public.clone()])
                .unwrap();
        let etat = ProvedLedgerState::depuis_genese_depth(&genese, 4).unwrap();
        let mut n = Noeud::new(nous, etat, [7u8; 32]);
        let (bloc, _) = n.sceller().expect("bloc vide produit");
        assert_eq!(bloc.hauteur, 1);
        assert!(bloc.transactions.is_empty(), "bloc vide");
        assert_eq!(n.etat.hauteur(), 1, "appliqué (quorum 1)");
    }

    #[test]
    fn proposition_porte_la_vue_courante() {
        // 4 autorités, nous sommes l'autorité 1. Après un changement de vue à 1,
        // c'est notre tour : la proposition porte vue 1.
        let cles: Vec<SigKeypair> = (0..4).map(|_| SigKeypair::generate()).collect();
        let genese = ledger::bloc::Bloc::genese_avec_autorites(
            Vec::new(),
            cles.iter().map(|k| k.public.clone()).collect(),
        )
        .unwrap();
        let etat = ProvedLedgerState::depuis_genese_depth(&genese, 4).unwrap();
        let mut n = Noeud::new(
            SigKeypair::from_bytes_secret(&cles[1].to_bytes_secret()).unwrap(),
            etat,
            [7u8; 32],
        );
        // Producteur de (1,1) = autorites[(1-1+1) mod 4] = autorites[1] = nous.
        let actions = n.tick(delai_vue(0));
        assert_eq!(n.vue_courante, 1);
        let a_propose = actions.iter().any(|a| {
            matches!(a, Action::Diffuser(Message::Proposition(b)) if b.vue == 1)
        });
        assert!(a_propose, "nous proposons à la vue 1, notre tour");
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec.**

- [ ] **Step 3: Implémenter**

Extraire le cœur de `sceller` (construction + scellement + vote + proposition/
application) dans `proposer_a_vue(&mut self, vue: u32, maintenant_ms: u64) ->
Option<(Bloc, Vec<Action>)>` :
- prochaine hauteur `h = etat.hauteur() + 1` ;
- producteur légitime de `(h, vue)` == nous ? sinon `None` ;
- construire le bloc à la vue `vue` (`Bloc::sceller` puis fixer `bloc.vue = vue`) ;
  **mempool vide autorisé** — ne pas rendre `None` ;
- signer scellement + notre vote ; règle de sûreté `peut_voter(h, &id)` ;
- quorum 1 → appliquer + `hauteur_avancee` + diffuser `Bloc` ; quorum > 1 →
  `proposition_en_cours`, diffuser `Proposition`, `PersisterVotes`.

`sceller()` devient `self.proposer_a_vue(self.vue_courante, 0)` (chemin
opérateur, `maintenant_ms` non critique pour ce chemin — le reset de vue à
l'application y suffit). `proposer_si_notre_tour(maintenant_ms)` appelle
`proposer_a_vue(self.vue_courante, maintenant_ms)` et renvoie ses actions.

⚠️ Sur une chaîne OUVERTE (sans autorités), conserver le comportement historique
de `sceller` : pas de bloc vide spontané, `None` si mempool vide.

- [ ] **Step 4: Lancer, vérifier le succès** — `cargo test -p node --release`.
      Corriger les tests J1-b1 de `sceller` si la signature interne a bougé.

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/orchestration.rs
git commit -m "consensus(J1-b2): proposer à vue_courante, bloc vide permis

sceller propose désormais à la vue courante et produit un bloc VIDE si le
mempool l'est (le battement) — sur chaîne à autorités. Chaîne ouverte :
comportement historique conservé. Le producteur du tour propose une fois en
devenant producteur (via tick au changement de vue, ou chemin opérateur)."
```

---

### Task 6: Fenêtre de vue future + calage visible

**Files:**
- Modify: `crates/node/src/orchestration.rs`, `crates/node/src/journal.rs`,
  `crates/node/src/bin/obscura-node.rs`

**Interfaces:**
- Consumes : `sur_proposition`, `tick`.
- Produces : `Statut { …, hauteurs_calees: u64 }` ; `declarer_calage(&mut self)
  -> Vec<Action>`.

- [ ] **Step 1: Écrire les tests**

```rust
    #[test]
    fn vue_future_trop_lointaine_refusee() {
        let (mut n, cles) = noeud_a_quatre_autorites();
        n.identite = SigKeypair::from_bytes_secret(&cles[1].to_bytes_secret()).unwrap();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        // vue_courante = 0. Une proposition à vue 2 (= 0 + 2 > 0 + FENETRE_VUE) est
        // ignorée ; à vue 1 elle est adoptée.
        let mut loin =
            ledger::bloc::Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap();
        loin.vue = 2;
        // Producteur de (1,2) = autorites[(1-1+2)%4] = autorites[2].
        loin.signer_scellement(&cles[2]);
        assert!(n.traiter(p, Message::Proposition(Box::new(loin)), 0).is_empty());
        assert_eq!(n.vue_courante, 0, "pas d'adoption d'une vue trop lointaine");
    }

    #[test]
    fn adoption_vue_reset_le_timer() {
        let (mut n, cles) = noeud_a_quatre_autorites();
        n.identite = SigKeypair::from_bytes_secret(&cles[3].to_bytes_secret()).unwrap();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        n.debut_vue_ms = 0;
        // Proposition légitime à vue 1 (producteur autorites[1]). On est l'autorité
        // 3, on n'a pas voté à h=1 : on vote et on adopte la vue 1.
        let mut v1 = ledger::bloc::Bloc::sceller(&n.etat.tete(), 1, Vec::new()).unwrap();
        v1.vue = 1;
        v1.signer_scellement(&cles[1]);
        let _ = n.traiter(p, Message::Proposition(Box::new(v1)), 500);
        assert_eq!(n.vue_courante, 1, "vue adoptée");
        assert_eq!(n.debut_vue_ms, 500, "TIMER RÉARMÉ — sinon montée en boucle");
    }

    #[test]
    fn overflow_vue_plafonne_et_signale() {
        let (mut n, cles) = noeud_a_quatre_autorites();
        n.identite = SigKeypair::from_bytes_secret(&cles[1].to_bytes_secret()).unwrap();
        n.vue_courante = MAX_VUE_PAR_HAUTEUR;
        n.debut_vue_ms = 0;
        let _ = n.tick(delai_vue(MAX_VUE_PAR_HAUTEUR).saturating_add(1_000_000));
        assert_eq!(n.vue_courante, MAX_VUE_PAR_HAUTEUR, "pas de wraparound");
        assert_eq!(n.hauteurs_calees, 1, "le calage est COMPTÉ");
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec.**

- [ ] **Step 3: Implémenter**

Dans `sur_proposition`, ajouter le contrôle 3 (spec III) **après** la légitimité
du producteur et **avant** le registre :

```rust
        // Fenêtre de vue : ni abandonnée (< vue_courante), ni trop lointaine.
        if bloc.vue < self.vue_courante || bloc.vue > self.vue_courante + FENETRE_VUE {
            return Vec::new();
        }
        // Adoption d'une vue future : réarmer le timer, sinon montée en boucle.
        if bloc.vue > self.vue_courante {
            self.vue_courante = bloc.vue;
            self.debut_vue_ms = maintenant_ms;
        }
```

`declarer_calage` :

```rust
    /// La hauteur est CALÉE (vue plafonnée sans avancée). Jamais silencieux :
    /// compteur + journal CRITIQUE. Le nœud cesse de proposer pour cette hauteur.
    fn declarer_calage(&mut self) -> Vec<Action> {
        // Une seule fois par calage : n'incrémente que si on vient d'atteindre le
        // plafond (le tick suivant ne re-compte pas).
        self.hauteurs_calees += 1;
        // Le journal CRITIQUE est émis par le runtime, qui a le journal ; ici on
        // signale par le compteur, lu au statut. Voir obscura-node.
        Vec::new()
    }
```

⚠️ `declarer_calage` ne doit compter qu'**une fois** par hauteur calée. Garder un
drapeau `calage_signale: bool` remis à `false` par `hauteur_avancee`, testé avant
d'incrémenter.

Dans `journal.rs`, ajouter `hauteurs_calees: u64` à `Statut`, l'afficher dans
`ligne()`, et l'inclure dans `preoccupant()` :

```rust
    pub fn preoccupant(&self) -> bool {
        self.liens == 0 || self.desaccords > 0 || self.hauteurs_calees > 0
    }
```

Dans `obscura-node.rs`, renseigner `hauteurs_calees:
rt.noeud().hauteurs_calees()` dans la construction du `Statut`, et émettre un
`journal.ligne(Niveau::Erreur, …)` « hauteur CALÉE — split de votes, nouvelle
chaîne nécessaire » quand le compteur passe de 0 à non nul.

- [ ] **Step 4: Lancer, vérifier le succès.**

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/orchestration.rs crates/node/src/journal.rs crates/node/src/bin/obscura-node.rs
git commit -m "consensus(J1-b2): fenêtre de vue future + calage VISIBLE

Une proposition non certifiée n'est adoptée que dans [vue_courante,
vue_courante+1] : un producteur d'une vue lointaine ne peut plus tirer tout
le monde en avant. L'adoption réarme le timer (sinon montée en boucle).

Le calage (vue plafonnée à MAX_VUE_PAR_HAUTEUR) est COMPTÉ une fois,
remonté au statut qui passe en AVERT, et journalisé CRITIQUE. Jamais un
arrêt silencieux — le pire mode d'échec."
```

---

### Task 7: Certificat canonique — exactement le quorum

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes : `sur_vote`, `quorum_requis`, `Bloc::poser_vote`.

**But (spec I) :** à l'assemblage, ne poser que `quorum_requis()` votes — les
plus petits index — triés. Pas de surplus sur le fil.

- [ ] **Step 1: Écrire le test**

```rust
    #[test]
    fn certificat_scelle_par_nous_est_canonique() {
        let (mut n, cles) = noeud_a_quatre_autorites();
        let (p, adr) = pair(1);
        n.pairs.ajouter(p, adr);
        let mut bloc = proposition_de(&n, &cles[0]);
        let id = bloc.id();
        bloc.signer_vote(0, &cles[0]);
        n.proposition_en_cours = Some(bloc);
        n.votes_recus
            .entry(id)
            .or_default()
            .insert(0, cles[0].sign(ledger::bloc::DOMAINE_VOTE, &id));
        // On envoie QUATRE votes alors que le quorum est 3.
        for i in 1..4u16 {
            let v = Vote {
                id,
                index: i,
                signature: cles[i as usize].sign(ledger::bloc::DOMAINE_VOTE, &id),
            };
            n.traiter(p, Message::Vote(Box::new(v)), 0);
        }
        let octets = n.archive().octets_a(1).expect("bloc 1 archivé");
        let certifie = Bloc::from_bytes(octets).unwrap();
        assert_eq!(
            certifie.certificat.as_ref().unwrap().nombre_de_votants(),
            n.etat.quorum_requis(),
            "EXACTEMENT le quorum, pas les 4 votes reçus"
        );
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec** (aujourd'hui l'assemblage prend TOUS
      les votes reçus).

- [ ] **Step 3: Implémenter**

Dans `sur_vote`, au moment de l'assemblage (quorum atteint), ne poser que les
`quorum_requis()` premiers votants par index :

```rust
        let requis = self.etat.quorum_requis();
        let mut votants: Vec<u16> = recus.keys().copied().collect();
        votants.sort_unstable();
        votants.truncate(requis); // EXACTEMENT le quorum, pas de surplus
        for index in votants {
            if let Some(sig) = recus.get(&index) {
                bloc.poser_vote(index as usize, sig.clone());
            }
        }
```

- [ ] **Step 4: Lancer, vérifier le succès.**

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/orchestration.rs
git commit -m "consensus(J1-b2): certificat canonique — exactement le quorum

Les signatures PQ ne s'agrègent pas : chaque vote surnuméraire est de la
bande passante et une vérification en plus, pour rien. À l'assemblage on ne
pose que quorum_requis() votes (plus petits index, triés). Un bloc que NOUS
produisons porte donc exactement le quorum, jamais de surplus."
```

---

### Task 8: Le producteur absent — la chaîne avance (sockets)

**Files:**
- Create: `crates/node/tests/vue_sockets.rs`

**Pourquoi sockets.** C'est le test qui prouve la liveness et le critère de
sortie du jalon. La logique est prouvée en unitaire (tâches 4–6) ; celui-ci
prouve que le protocole tient sur le vrai transport.

**Le scénario.** 4 autorités, quorum 3. On ne démarre **pas** l'autorité 0
(producteur de `(1, 0)`). Les autorités 1, 2, 3 tournent, leurs délais de vue
expirent, elles passent à la vue 1 dont le producteur est `autorites[1]`. Celle-ci
propose, les trois votent, le bloc 1 en **vue 1** se certifie et s'applique
partout.

- [ ] **Step 1: Écrire le test**

Modèle : `quorum_sockets.rs`, mais (a) l'autorité 0 n'est jamais lancée, (b) on
avance le temps par `tick(maintenant_ms)` avec des `maintenant_ms` croissants au
lieu d'attendre une horloge, (c) l'assertion finale porte sur `vue == 1`.

```rust
//! LIVENESS sur sockets : le producteur du tour est ABSENT, la chaîne avance.
//!
//! 4 autorités, quorum 3. L'autorité 0 (producteur de (1,0)) n'est jamais
//! démarrée. Les délais de vue des trois autres expirent, elles passent à la vue
//! 1 (producteur = autorites[1]), qui propose ; le bloc 1 en VUE 1 se certifie et
//! s'applique partout. C'est le critère de sortie de J1-b2.
```

Chaque nœud voteur, dans sa boucle de pompage, appelle aussi
`rt.tick(maintenant_ms)` avec un `maintenant_ms` qui croît d'assez pour franchir
`delai_vue(0)`. Assertions : les trois nœuds atteignent la **hauteur 1**, la
**même racine**, et le bloc appliqué a **`vue == 1`** et un certificat de **3
votants distincts**.

- [ ] **Step 2: Lancer, vérifier l'échec** (avant les tâches 4–6, il n'y aurait
      pas de changement de vue ; ici tout est en place, donc écrire d'abord le
      test et le voir passer sert de preuve d'intégration).

- [ ] **Step 3: Ajuster** jusqu'au vert. Aucun `sleep` pour piloter la vue : le
      temps est injecté via `tick`.

- [ ] **Step 4: Suite complète** — `cargo test --workspace --release
      --all-features`.

- [ ] **Step 5: Commit**

```bash
git add crates/node/tests/vue_sockets.rs
git commit -m "test(J1-b2): producteur absent, la chaîne avance (sockets)

Le critère de sortie du jalon. 4 autorités, l'autorité 0 (producteur de
(1,0)) jamais démarrée. Les délais de vue des trois autres expirent, elles
passent à la vue 1, autorites[1] propose, le bloc 1 en VUE 1 se certifie et
s'applique partout — même racine, certificat de 3 votants distincts. Le
temps est injecté via tick, aucun sleep."
```

---

### Task 9: Sûreté inter-vues + doc à jour

**Files:**
- Modify: `crates/node/tests/chaos_producteur.rs`, `docs/TESTNET.md`

- [ ] **Step 1: Test de sûreté inter-vues**

Étendre `chaos_producteur.rs` : un nœud vote pour A à la hauteur 1 (vue 0), puis
reçoit une proposition B ≠ A à la hauteur 1 **vue 1** (producteur légitime de
`(1,1)`). Il ne doit **pas** voter — la clé hauteur seule l'interdit, toutes vues
confondues. Vérifié par mutation (supprimer `votes.bin` avant réception de B
casse le test).

```rust
/// SÛRETÉ INTER-VUES : voter pour A à la hauteur 1 interdit de voter pour un
/// autre bloc à la hauteur 1, MÊME à une vue supérieure. C'est le cœur du
/// modèle A — la vue n'entre pas dans la décision.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn pas_de_double_vote_a_travers_les_vues() {
    // 1. Le nœud vote pour A à (1, 0). Registre persisté.
    // 2. Une proposition B ≠ A à (1, 1) — producteur légitime de (1,1) — n'obtient
    //    AUCUN vote.
    // 3. Mutation : supprimer votes.bin avant B doit CASSER le test.
}
```

- [ ] **Step 2: Mutation** — supprimer `votes.bin` entre les deux, vérifier
      l'échec, restaurer.

- [ ] **Step 3: `docs/TESTNET.md`**

Remplacer la ligne « Une autorité absente fige la chaîne jusqu'à son retour »
(§1.2) par :

```markdown
- **Une autorité absente est CONTOURNÉE par changement de vue** : la chaîne
  continue avec le producteur suivant, après un délai (backoff). En revanche, un
  **partitionnement des votes** (rare : producteur à moitié joignable au
  basculement) peut **caler une hauteur définitivement** — les votants sont
  verrouillés, recovery par nouvelle chaîne. Le calage est signalé (statut en
  AVERT, journal CRITIQUE), jamais silencieux.
```

- [ ] **Step 4: Suite complète + CI locale**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --release -- -D warnings
cargo clippy --workspace --all-targets --release --all-features -- -D warnings
cargo test --workspace --release --all-features
```

- [ ] **Step 5: Commit**

```bash
git add crates/node/tests/chaos_producteur.rs docs/TESTNET.md
git commit -m "test+docs(J1-b2): sûreté inter-vues, et TESTNET.md à jour

Un nœud qui a voté à la hauteur 1 ne vote pas pour un autre bloc à la
hauteur 1, MÊME à une vue supérieure — vérifié par mutation. TESTNET.md
cesse de dire qu'une autorité absente fige la chaîne : elle est contournée
par changement de vue. La limite restante (calage sur split de votes) y est
écrite, avec sa visibilité."
```

---

## Critère de sortie de J1-b2

- Sur 4 autorités, le producteur de `(1,0)` absent, la chaîne produit la hauteur
  1 en **vue 1** sur de vraies sockets, même racine partout.
- Un producteur qui répond n'est jamais tourné (délai > cadence).
- Un nœud ne vote jamais deux fois à la même hauteur, **toutes vues confondues** —
  mutation.
- Le calage est **visible** (compteur, statut AVERT, journal CRITIQUE).
- Le certificat produit par nous porte **exactement** le quorum.
- `docs/TESTNET.md` reflète la nouvelle liveness.
- CI verte, commandes exactes, passe par défaut comprise.

**Ce que J1-b2 ne fait pas :** J1-c (changement d'ensemble d'autorités) reste
ouvert. Le comité est fixe.
