# J1-c — Changement d'ensemble d'autorités — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permettre à l'ensemble d'autorités d'évoluer sur la MÊME chaîne, certifié par le quorum de l'ancienne liste, effectif à `h + K`, sans refaire la genèse.

**Architecture:** Un nouveau champ de bloc `changement_autorites: Option<Vec<SigPublicKey>>` (dans l'identifiant, donc couvert par le certificat de l'ancien comité). L'état gagne `changement_en_attente: Option<(Vec<SigPublicKey>, u64)>`. Un helper **height-aware** `autorites_a(hauteur)` renvoie la nouvelle liste ssi un changement prend effet EXACTEMENT à cette hauteur — `producteur_attendu` le consulte en interne (call sites inchangés), un nouveau `quorum_a(hauteur)` couvre le quorum. `appliquer_bloc` valide le bloc `h` contre cette liste locale et ne COMMITE `self.autorites`/`changement_en_attente` qu'après succès complet. Aucun nouveau message, aucune nouvelle machinerie de vote : un bloc de reconfiguration transite par le chemin propose/vote/certifie de J1-b2.

**Tech Stack:** Rust, crates `ledger` (cœur) et `node` (câblage + tests sockets). TDD, preuves STARK gatées derrière `--release`.

**Spec de référence :** `docs/superpowers/specs/2026-07-23-j1c-changement-autorites-design.md`.

## Global Constraints

- **NE JAMAIS toucher aux 8 fichiers non commités de l'utilisateur** : `AGENTS.md`, `CLAUDE.md`, `crates/node/examples/dimensionner-ouverture.rs`, `docs/POST_QUANTIQUE.md`, `docs/STARK_STATEMENT.md`, `docs/THREAT_MODEL.md`, `docs/obscura-overview.html`, `docs/superpowers/specs/2026-07-22-j2-economie-adr.md`.
- **`git add` nomme TOUJOURS les fichiers explicitement — JAMAIS `git add -A`.**
- Travailler sur la branche `feat/j1c-changement-autorites` (déjà créée). **Ne jamais commiter sur `master`.**
- **Ne pas fusionner** : la dernière tâche ouvre une PR et s'arrête là. La décision de fusion revient à l'utilisateur.
- Message de commit terminé par `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Corps de PR terminé par la ligne de génération Claude Code.
- Commentaires et docs en **français** (convention du dépôt).
- Toute nouvelle borne vérifiée **AVANT allocation** (discipline anti-DoS du dépôt).
- Le comportement par défaut (sans `--all-features`) = surface CONSENSUS seule ; ne jamais faire dépendre le consensus de code gaté.
- **Constantes de protocole (valeurs verbatim de la spec) :**
  - `DELAI_CHANGEMENT_AUTORITES: u64 = 8` (le `K` de `h + K`).
  - `MAX_AUTORITES = 64` (existe déjà).
  - `VERSION_BLOC` : `0x04` → `0x05` ; `VERSION_BLOC_PERIMEE` : `0x03` → `0x04`.
  - `VERSION_ETAT` : `0x04` → `0x05`.
  - Liste de changement : taille `[1, MAX_AUTORITES]`, **liste vide INTERDITE**, **aucun doublon**.
- **Commandes CI (exactes), vertes avant chaque commit de fin de tâche :**
  - `cargo fmt --all -- --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-features --release`
  - Les tests à preuves portent `#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]`.

---

### Task 1 : Le champ `changement_autorites`, `VERSION_BLOC 0x05`, corps + décodage

**Files:**
- Modify: `crates/ledger/src/bloc.rs`

**Interfaces:**
- Consumes: `SigPublicKey` (déjà importé), `MAX_AUTORITES`, `TAILLE_AUTORITE_MAX`, `prendre` (fonction locale de `from_bytes`).
- Produces:
  - Champ public `pub changement_autorites: Option<Vec<SigPublicKey>>` sur `struct Bloc`.
  - `pub(crate) fn liste_a_un_doublon(liste: &[SigPublicKey]) -> bool`.
  - Variantes `BlocDecodeError::{ChangementTropDAutorites, ChangementAutoriteInvalide(usize), ChangementDoublon}`.
  - `VERSION_BLOC = 0x05`, `VERSION_BLOC_PERIMEE = 0x04`.

- [ ] **Step 1 : Écrire les tests d'encodage/décodage du nouveau champ**

Ajouter dans `mod tests` de `crates/ledger/src/bloc.rs` :

```rust
    /// Le changement d'autorités entre dans l'IDENTIFIANT (le certificat de l'ancien
    /// comité doit signer SUR la nouvelle liste) et survit à l'aller-retour wire.
    #[test]
    fn changement_dans_lidentifiant_et_sur_le_fil() {
        let a = SigKeypair::generate().public;
        let b = SigKeypair::generate().public;
        let sans = Bloc::sceller(&Bloc::genese().id(), 1, Vec::new()).unwrap();
        let mut avec = Bloc::sceller(&Bloc::genese().id(), 1, Vec::new()).unwrap();
        avec.changement_autorites = Some(vec![a.clone(), b.clone()]);
        assert_ne!(sans.id(), avec.id(), "le changement doit entrer dans l'id");

        let relu = Bloc::from_bytes(&avec.to_bytes()).expect("décodable");
        assert_eq!(relu.id(), avec.id(), "identifiant stable au fil");
        let liste = relu.changement_autorites.expect("changement présent");
        assert_eq!(liste.len(), 2);
        assert_eq!(liste[0].to_bytes(), a.to_bytes());
        assert_eq!(liste[1].to_bytes(), b.to_bytes());
    }

    /// `0 = absent` : un bloc ordinaire n'a pas de changement, et le décodage le rend
    /// bien `None` (jamais `Some(vec![])`).
    #[test]
    fn absence_de_changement_decode_none() {
        let b = Bloc::sceller(&Bloc::genese().id(), 1, Vec::new()).unwrap();
        assert!(b.changement_autorites.is_none());
        let relu = Bloc::from_bytes(&b.to_bytes()).unwrap();
        assert!(relu.changement_autorites.is_none());
    }

    /// Une liste de changement trop longue est refusée AVANT allocation.
    #[test]
    fn changement_trop_dautorites_refuse_au_decodage() {
        let pk = SigKeypair::generate().public;
        let mut b = Bloc::sceller(&Bloc::genese().id(), 1, Vec::new()).unwrap();
        b.changement_autorites = Some((0..MAX_AUTORITES + 1).map(|_| pk.clone()).collect());
        assert!(matches!(
            Bloc::from_bytes(&b.to_bytes()),
            Err(BlocDecodeError::ChangementTropDAutorites)
        ));
    }

    /// Un doublon dans la liste de changement est refusé au décodage : sinon une clé
    /// à deux index compterait deux votes dans le masque de quorum.
    #[test]
    fn changement_doublon_refuse_au_decodage() {
        let pk = SigKeypair::generate().public;
        let mut b = Bloc::sceller(&Bloc::genese().id(), 1, Vec::new()).unwrap();
        b.changement_autorites = Some(vec![pk.clone(), pk.clone()]);
        assert!(matches!(
            Bloc::from_bytes(&b.to_bytes()),
            Err(BlocDecodeError::ChangementDoublon)
        ));
    }

    /// Un bloc de l'ANCIENNE version (0x04) est refusé par une variante qui le NOMME.
    #[test]
    fn version_0x04_refusee_par_son_nom() {
        let mut octets = Bloc::genese().to_bytes();
        octets[0] = 0x04;
        assert!(matches!(
            Bloc::from_bytes(&octets),
            Err(BlocDecodeError::VersionPerimee { version: 0x04 })
        ));
    }
```

- [ ] **Step 2 : Lancer les tests, vérifier l'échec de compilation**

Run: `cargo test -p ledger --lib bloc:: 2>&1 | head -30`
Expected: échec de COMPILATION (champ `changement_autorites` et variantes inexistants). C'est le « rouge » attendu.

- [ ] **Step 3 : Bumper les versions et ajouter les variantes d'erreur**

Dans `crates/ledger/src/bloc.rs`, remplacer la constante de version périmée et la version courante :

```rust
pub const VERSION_BLOC: u8 = 0x05;
/// Version PÉRIMÉE, refusée par son nom (J1-c). `0x04` a porté J1-a/J1-b mais aucune
/// chaîne publique n'a existé : rien à migrer, refus franc plutôt que relecture.
const VERSION_BLOC_PERIMEE: u8 = 0x04;
```

Mettre à jour la doc de `VERSION_BLOC` (une ligne suffit) : `` `0x05` : ajout du CHANGEMENT D'AUTORITÉS (reconfiguration certifiée, J1-c) dans le corps, donc dans l'identifiant. ``

Ajouter dans l'enum `BlocDecodeError` :

```rust
    #[error("liste de changement d'autorités trop longue (borne : {MAX_AUTORITES})")]
    ChangementTropDAutorites,
    #[error("autorité de changement indécodable ou hors bornes en position {0}")]
    ChangementAutoriteInvalide(usize),
    #[error("doublon dans la liste de changement d'autorités")]
    ChangementDoublon,
```

- [ ] **Step 4 : Ajouter le champ à la struct et à toutes les constructions littérales**

Ajouter le champ à `struct Bloc` (après `pub autorites`, avant `pub extension`) :

```rust
    /// La NOUVELLE liste d'autorités, si ce bloc annonce une reconfiguration (J1-c).
    /// `None` pour un bloc ordinaire. **Dans le corps → dans l'identifiant** : le
    /// certificat de l'ANCIEN comité signe donc SUR la nouvelle liste. Encodage
    /// `0 = absent` ; une liste VIDE n'existe pas sur le fil (indistinguable d'un bloc
    /// ordinaire) — le refus de la liste vide est au CONSTRUCTEUR.
    pub changement_autorites: Option<Vec<SigPublicKey>>,
```

Ajouter `changement_autorites: None` à CHAQUE littéral `Bloc { … }` de ce fichier : dans `genese()`, `genese_avec_autorites()`, `sceller()`, le bloc de retour de `from_bytes()`, et le bloc `hostile` du test `trop_dautorites_refusees_des_deux_cotes`. Les trouver :

Run: `grep -rn "Bloc {" crates/ledger/src/bloc.rs`
Ajouter le champ à chacun (valeur `None`).

- [ ] **Step 5 : Ajouter le helper de détection de doublon**

Ajouter, au niveau module de `crates/ledger/src/bloc.rs` (près des autres `fn` libres) :

```rust
/// `true` si deux clés de `liste` sont identiques (comparaison par encodage :
/// `SigPublicKey` n'est ni `Hash` ni `Ord`). O(n²), mais `n ≤ MAX_AUTORITES = 64`.
/// Partagé par le décodage, les constructeurs, la genèse et le chargement d'état.
pub(crate) fn liste_a_un_doublon(liste: &[SigPublicKey]) -> bool {
    let mut vues: Vec<Vec<u8>> = Vec::with_capacity(liste.len());
    for pk in liste {
        let o = pk.to_bytes();
        if vues.contains(&o) {
            return true;
        }
        vues.push(o);
    }
    false
}
```

- [ ] **Step 6 : Encoder le champ dans `corps_bytes`**

Dans `corps_bytes`, INSÉRER — après la boucle des `autorites`, AVANT l'en-tête `extension` (position figée, point 10 de la revue) :

```rust
        // CHANGEMENT D'AUTORITÉS (J1-c) : `0 = absent`, sinon `len ‖ [len(pk) ‖ pk]`.
        // DANS le corps → engagé par l'identifiant, donc couvert par le certificat.
        match &self.changement_autorites {
            None => b.extend_from_slice(&0u32.to_le_bytes()),
            Some(liste) => {
                b.extend_from_slice(&(liste.len() as u32).to_le_bytes());
                for pk in liste {
                    let o = pk.to_bytes();
                    b.extend_from_slice(&(o.len() as u32).to_le_bytes());
                    b.extend_from_slice(&o);
                }
            }
        }
```

- [ ] **Step 7 : Décoder le champ dans `from_bytes`**

Dans `from_bytes`, INSÉRER — après la boucle qui lit `autorites`, AVANT la lecture de l'en-tête `extension` (`let lx = …`) :

```rust
        // CHANGEMENT D'AUTORITÉS (J1-c). `0 = absent`. Bornes AVANT allocation, comme
        // partout dans ce décodeur, et doublons refusés (une clé à deux index voterait
        // deux fois).
        let nc = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let changement_autorites = if nc == 0 {
            None
        } else {
            if nc > MAX_AUTORITES {
                return Err(BlocDecodeError::ChangementTropDAutorites);
            }
            let mut liste = Vec::with_capacity(nc);
            for k in 0..nc {
                let lp = u32::from_le_bytes(prendre(b, &mut pos, 4)?.try_into().unwrap()) as usize;
                if lp > TAILLE_AUTORITE_MAX {
                    return Err(BlocDecodeError::ChangementAutoriteInvalide(k));
                }
                let pk = SigPublicKey::from_bytes(prendre(b, &mut pos, lp)?)
                    .map_err(|_| BlocDecodeError::ChangementAutoriteInvalide(k))?;
                liste.push(pk);
            }
            if liste_a_un_doublon(&liste) {
                return Err(BlocDecodeError::ChangementDoublon);
            }
            Some(liste)
        };
```

Puis, dans le `Ok(Bloc { … })` final de `from_bytes`, ajouter `changement_autorites,` (raccourci de champ).

- [ ] **Step 8 : Lancer les tests bloc, vérifier le vert**

Run: `cargo test -p ledger --lib bloc:: 2>&1 | tail -20`
Expected: PASS (tous les tests `bloc::`, dont les 5 nouveaux). Vérifier notamment que `autorites_dans_lidentifiant_et_sur_le_fil` et `certificat_sur_le_fil_hors_de_lidentifiant` passent toujours (l'ajout d'un champ `None` ne change pas leurs identifiants relatifs).

- [ ] **Step 9 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo test -p ledger --lib bloc::
```
Expected: tout vert.

```bash
git add crates/ledger/src/bloc.rs
git commit -m "$(cat <<'EOF'
protocole(J1-c): le champ changement_autorites entre dans l'identifiant

VERSION_BLOC 0x05. Encodage 0=absent, bornes et doublons refusés au
décodage avant allocation. 0x04 refusé par son nom.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2 : Constructeurs — `sceller_changement` et doublons en genèse

**Files:**
- Modify: `crates/ledger/src/bloc.rs`

**Interfaces:**
- Consumes: `liste_a_un_doublon` (Task 1), `MAX_AUTORITES`, `MAX_OCTETS_BLOC`, `TAILLE_SCELLEMENT_MAX`, `SURCOUT_BLOC_VIDE`.
- Produces:
  - `pub fn Bloc::sceller_changement(parent: &[u8; TAILLE_ID], hauteur: u64, nouvelles: Vec<SigPublicKey>) -> Result<Bloc, BlocConstructionError>`.
  - Variantes `BlocConstructionError::{ChangementListeVide, AutoriteDupliquee, ChangementTropDAutorites { recues }}`.
  - `genese_avec_autorites` refuse désormais les doublons.

- [ ] **Step 1 : Écrire les tests des constructeurs**

Ajouter dans `mod tests` :

```rust
    /// `sceller_changement` produit un bloc VIDE de transactions portant la nouvelle
    /// liste, diffusable, à identifiant stable.
    #[test]
    fn sceller_changement_construit_un_bloc_de_reconfig() {
        let a = SigKeypair::generate().public;
        let b = SigKeypair::generate().public;
        let bloc =
            Bloc::sceller_changement(&Bloc::genese().id(), 5, vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(bloc.hauteur, 5);
        assert!(bloc.transactions.is_empty(), "reconfig = aucune transaction");
        assert_eq!(bloc.changement_autorites.as_ref().unwrap().len(), 2);
        // Diffusable et stable au fil.
        let relu = Bloc::from_bytes(&bloc.to_bytes()).unwrap();
        assert_eq!(relu.id(), bloc.id());
    }

    /// Liste vide refusée AU CONSTRUCTEUR (elle n'existe pas sur le fil : `0 = absent`).
    #[test]
    fn sceller_changement_liste_vide_refusee() {
        assert!(matches!(
            Bloc::sceller_changement(&Bloc::genese().id(), 1, Vec::new()),
            Err(BlocConstructionError::ChangementListeVide)
        ));
    }

    /// Doublon refusé au constructeur de changement.
    #[test]
    fn sceller_changement_doublon_refuse() {
        let pk = SigKeypair::generate().public;
        assert!(matches!(
            Bloc::sceller_changement(&Bloc::genese().id(), 1, vec![pk.clone(), pk.clone()]),
            Err(BlocConstructionError::AutoriteDupliquee)
        ));
    }

    /// Liste trop longue refusée au constructeur (borne aussi côté fabricant, pas
    /// seulement au décodage).
    #[test]
    fn sceller_changement_trop_dautorites_refuse() {
        let pk = SigKeypair::generate().public;
        let trop: Vec<_> = (0..MAX_AUTORITES + 1).map(|_| pk.clone()).collect();
        assert!(matches!(
            Bloc::sceller_changement(&Bloc::genese().id(), 1, trop),
            Err(BlocConstructionError::ChangementTropDAutorites { .. })
        ));
    }

    /// FAILLE LATENTE FERMÉE : un doublon d'autorité en GENÈSE était accepté — une clé
    /// à deux index votait deux fois. Désormais refusé au constructeur de genèse.
    #[test]
    fn genese_doublon_dautorite_refuse() {
        let pk = SigKeypair::generate().public;
        assert!(matches!(
            Bloc::genese_avec_autorites(Vec::new(), vec![pk.clone(), pk.clone()]),
            Err(BlocConstructionError::AutoriteDupliquee)
        ));
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `cargo test -p ledger --lib bloc:: 2>&1 | head -20`
Expected: échec de compilation (`sceller_changement` et variantes inexistants).

- [ ] **Step 3 : Ajouter les variantes de `BlocConstructionError`**

```rust
    #[error("liste de changement d'autorités vide (interdite)")]
    ChangementListeVide,
    #[error("clé d'autorité en double dans la liste")]
    AutoriteDupliquee,
    #[error("{recues} autorités dans le changement (borne : {MAX_AUTORITES})")]
    ChangementTropDAutorites { recues: usize },
```

- [ ] **Step 4 : Refuser les doublons dans `genese_avec_autorites`**

Dans `genese_avec_autorites`, APRÈS le contrôle `autorites.len() > MAX_AUTORITES`, ajouter :

```rust
        if liste_a_un_doublon(&autorites) {
            return Err(BlocConstructionError::AutoriteDupliquee);
        }
```

- [ ] **Step 5 : Écrire `sceller_changement`**

Ajouter dans `impl Bloc`, à côté de `sceller` :

```rust
    /// Scelle un bloc de RECONFIGURATION : vide de transactions, portant la nouvelle
    /// liste d'autorités (J1-c). Un bloc de gouvernance vide simplifie l'audit et
    /// écarte le risque d'un changement rejeté après une vérification STARK coûteuse.
    ///
    /// Les bornes (non vide, taille, doublon, poids diffusable) sont vérifiées ICI et
    /// pas seulement au décodage — même discipline que `genese_avec_autorites` : une
    /// borne de `from_bytes` doit exister aussi dans le constructeur.
    pub fn sceller_changement(
        parent: &[u8; TAILLE_ID],
        hauteur: u64,
        nouvelles: Vec<SigPublicKey>,
    ) -> Result<Self, BlocConstructionError> {
        if nouvelles.is_empty() {
            return Err(BlocConstructionError::ChangementListeVide);
        }
        if nouvelles.len() > MAX_AUTORITES {
            return Err(BlocConstructionError::ChangementTropDAutorites {
                recues: nouvelles.len(),
            });
        }
        if liste_a_un_doublon(&nouvelles) {
            return Err(BlocConstructionError::AutoriteDupliquee);
        }
        let bloc = Bloc {
            parent: *parent,
            hauteur,
            vue: 0,
            transactions: Vec::new(),
            emissions: Vec::new(),
            autorites: Vec::new(),
            changement_autorites: Some(nouvelles),
            extension: Vec::new(),
            scellement: None,
            certificat: None,
        };
        // Budget vérifié SCELLEMENT COMPRIS et LISTE COMPRISE (point 7 de la revue) :
        // la nouvelle liste pèse jusqu'à ~127 Kio, le bloc doit rester diffusable.
        let octets = bloc.to_bytes().len() + TAILLE_SCELLEMENT_MAX;
        if octets > MAX_OCTETS_BLOC {
            return Err(BlocConstructionError::TropDOctets { octets });
        }
        Ok(bloc)
    }
```

- [ ] **Step 6 : Lancer, vérifier le vert**

Run: `cargo test -p ledger --lib bloc:: 2>&1 | tail -20`
Expected: PASS (dont les 5 nouveaux).

- [ ] **Step 7 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo test -p ledger --lib bloc::
```

```bash
git add crates/ledger/src/bloc.rs
git commit -m "$(cat <<'EOF'
protocole(J1-c): sceller_changement + doublons refusés en genèse

Constructeur de bloc de reconfiguration (vide de tx, budget liste comprise).
Ferme la faille latente : un doublon d'autorité en genèse votait deux fois.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3 : État — `changement_en_attente`, liste active locale, activation

**Files:**
- Modify: `crates/ledger/src/proved_state.rs`

**Interfaces:**
- Consumes: `Bloc.changement_autorites` (Task 1), `SigPublicKey`, `MAX_AUTORITES`.
- Produces:
  - Champ `changement_en_attente: Option<(Vec<crypto::sig::SigPublicKey>, u64)>` sur `ProvedLedgerState`.
  - `pub const DELAI_CHANGEMENT_AUTORITES: u64 = 8`.
  - `fn quorum_pour(n: usize) -> usize` (libre), `fn autorites_a(&self, hauteur: u64) -> &[SigPublicKey]`, `pub fn quorum_a(&self, hauteur: u64) -> usize`.
  - `producteur_attendu` devient height-aware (comportement inchangé hors activation).
  - `appliquer_bloc` : valide contre la liste active locale, commite `autorites`/`changement_en_attente` après succès.

- [ ] **Step 1 : Écrire les tests du chemin nominal**

Ajouter dans `mod tests` de `crates/ledger/src/proved_state.rs`. Ces tests utilisent `chaine_a` et `bloc_h1` (déjà présents), plus un helper local pour sceller/voter un bloc à une hauteur arbitraire. Ajouter d'abord ce helper dans `mod tests` :

```rust
    /// Bloc VIDE de hauteur `h` en vue 0, scellé et voté au quorum par les `q`
    /// premières autorités de `cles` (indices producteur = (h−1) mod n).
    fn bloc_certifie(
        parent: [u8; crate::bloc::TAILLE_ID],
        h: u64,
        cles: &[crypto::sig::SigKeypair],
        q: usize,
    ) -> crate::bloc::Bloc {
        let n = cles.len() as u64;
        let prod = ((h - 1) % n) as usize;
        let mut b = crate::bloc::Bloc::sceller(&parent, h, Vec::new()).unwrap();
        b.signer_scellement(&cles[prod]);
        for i in 0..q {
            b.signer_vote(i, &cles[i]);
        }
        b
    }
```

Puis les tests :

```rust
    /// Un bloc de changement enregistre l'attente, sans encore basculer la liste.
    #[test]
    fn changement_enregistre_lattente() {
        let (mut etat, cles) = chaine_a(4);
        let nouvelle: Vec<_> = (0..4)
            .map(|_| crypto::sig::SigKeypair::generate().public)
            .collect();
        let mut b = crate::bloc::Bloc::sceller_changement(&etat.tete(), 1, nouvelle.clone())
            .unwrap();
        b.signer_scellement(&cles[0]);
        for (i, c) in cles.iter().enumerate().take(3) {
            b.signer_vote(i, c);
        }
        etat.appliquer_bloc(&b).expect("changement accepté");
        assert_eq!(etat.hauteur(), 1);
        // La liste ACTIVE n'a pas bougé : le basculement est à h+K.
        assert_eq!(etat.autorites().len(), 4);
        assert_eq!(etat.autorites()[0].to_bytes(), cles[0].public.to_bytes());
    }

    /// L'attente bascule EXACTEMENT à h+K : avant, ancien producteur ; à h+K, nouveau
    /// quorum. On observe le basculement via `quorum_a`.
    #[test]
    fn le_changement_bascule_a_h_plus_k() {
        let (etat, _) = chaine_a(4);
        // K = DELAI_CHANGEMENT_AUTORITES. On vérifie la sémantique de `quorum_a`/
        // `autorites_a` directement, sans appliquer 8 blocs de preuves.
        let nouvelle: Vec<_> = (0..7)
            .map(|_| crypto::sig::SigKeypair::generate().public)
            .collect();
        let mut etat = etat;
        etat.injecter_changement_pour_test(nouvelle, 1 + DELAI_CHANGEMENT_AUTORITES);
        // Avant l'effet : quorum de l'ANCIENNE liste (n=4 → 3).
        assert_eq!(etat.quorum_a(2), 3);
        // À l'effet : quorum de la NOUVELLE liste (n=7 → 5).
        assert_eq!(etat.quorum_a(1 + DELAI_CHANGEMENT_AUTORITES), 5);
    }
```

Note : `injecter_changement_pour_test` est un point d'entrée `#[cfg(test)]` ajouté au Step 4 pour éprouver la sémantique height-aware sans dérouler K blocs prouvés.

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `cargo test -p ledger --lib proved_state:: 2>&1 | head -20`
Expected: échec de compilation (`sceller_changement` OK depuis Task 2, mais `injecter_changement_pour_test`, `quorum_a`, `DELAI_CHANGEMENT_AUTORITES` inexistants ; le champ `changement_en_attente` manque).

- [ ] **Step 3 : Ajouter le champ, la constante et les helpers**

Ajouter la constante près de `VERSION_ETAT` :

```rust
/// `K` de `h + K` : délai entre l'annonce d'un changement d'autorités et son effet.
///
/// N'achète pas de la sûreté (sous finalité BFT, juger `h+1` exige d'avoir appliqué
/// `h`, donc tout le monde connaît déjà la nouvelle liste ; `K=1` serait sûr) mais de
/// la COORDINATION : le temps qu'une nouvelle autorité soit en ligne et synchronisée.
/// Généreux à dessein — réseau fédéré coordonné hors bande.
pub const DELAI_CHANGEMENT_AUTORITES: u64 = 8;
```

Ajouter le champ à `struct ProvedLedgerState` (après `autorites`) :

```rust
    /// Changement d'autorités EN ATTENTE : `(nouvelle liste, hauteur d'effet)`.
    ///
    /// `None` en régime normal. Un seul en vol (invariant de protocole). Écrit
    /// uniquement au COMMIT d'`appliquer_bloc`, après succès complet — jamais avant,
    /// pour qu'un bloc refusé ne le mute pas (il n'a donc pas besoin de rejoindre
    /// l'instantané d'atomicité de la frontier). Persisté dans le dump d'état (0x05) :
    /// un nœud redémarré dans la fenêtre `[h+1, h+K)` doit retrouver le basculement.
    changement_en_attente: Option<(Vec<crypto::sig::SigPublicKey>, u64)>,
```

Ajouter `changement_en_attente: None` aux DEUX constructions littérales de `ProvedLedgerState` : `with_tree` et le `Ok(ProvedLedgerState { … })` de `from_bytes`.

Ajouter la fonction libre `quorum_pour` (remplace le calcul inline de `quorum_requis`) et les helpers height-aware. Remplacer le corps de `quorum_requis` et de `producteur_attendu`, et ajouter `autorites_a`/`quorum_a` :

```rust
/// Quorum `⌊2n/3⌋ + 1` (0 si `n = 0`). Sûr pour tout `n`, égal à `2f+1` quand
/// `n = 3f+1` (cf. `quorum_requis`).
fn quorum_pour(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (2 * n) / 3 + 1
    }
}
```

Dans `impl ProvedLedgerState` :

```rust
    /// Liste d'autorités ACTIVE pour un bloc à `hauteur` : la nouvelle liste SI un
    /// changement prend effet EXACTEMENT à cette hauteur, sinon la liste courante.
    ///
    /// C'est l'unique endroit qui « voit » le basculement avant qu'il ne soit commité.
    /// Producteur et quorum en dérivent, donc le nœud qui PROPOSE `h+K` et le nœud qui
    /// VALIDE `h+K` calculent le même comité — sans que `self.autorites` ait bougé.
    fn autorites_a(&self, hauteur: u64) -> &[crypto::sig::SigPublicKey] {
        match &self.changement_en_attente {
            Some((nouvelle, e)) if *e == hauteur => nouvelle,
            _ => &self.autorites,
        }
    }

    /// Quorum requis pour un bloc à `hauteur`, liste active de cette hauteur comprise.
    pub fn quorum_a(&self, hauteur: u64) -> usize {
        quorum_pour(self.autorites_a(hauteur).len())
    }
```

Remplacer le corps de `quorum_requis` par une délégation (comportement inchangé : liste courante) :

```rust
    pub fn quorum_requis(&self) -> usize {
        quorum_pour(self.autorites.len())
    }
```

Remplacer le corps de `producteur_attendu` pour lire la liste active de la hauteur :

```rust
    pub fn producteur_attendu(&self, hauteur: u64, vue: u32) -> Option<&crypto::sig::SigPublicKey> {
        let liste = self.autorites_a(hauteur);
        if liste.is_empty() || hauteur == 0 {
            return None;
        }
        let n = liste.len() as u64;
        let i = ((hauteur - 1 + vue as u64) % n) as usize;
        Some(&liste[i])
    }
```

- [ ] **Step 4 : Ajouter le point d'entrée de test `injecter_changement_pour_test`**

Ajouter dans `impl ProvedLedgerState`, gardé `#[cfg(test)]` :

```rust
    /// Installe un changement en attente SANS passer par un bloc — éprouve la
    /// sémantique height-aware (`autorites_a`/`quorum_a`) sans dérouler K blocs
    /// prouvés. Tests seulement.
    #[cfg(test)]
    fn injecter_changement_pour_test(&mut self, nouvelle: Vec<crypto::sig::SigPublicKey>, effet: u64) {
        self.changement_en_attente = Some((nouvelle, effet));
    }
```

- [ ] **Step 5 : Câbler l'activation et la registration dans `appliquer_bloc`**

Dans `appliquer_bloc`, la validation producteur + certificat doit se faire contre la LISTE ACTIVE LOCALE, et le commit à la toute fin. Modifier ainsi :

(a) Juste APRÈS le contrôle `bloc.transactions.len() > MAX_TX_PAR_BLOC` et AVANT le `match self.producteur_attendu(…)`, cloner la liste active du bloc :

```rust
        // LISTE ACTIVE LOCALE (point 3 de la revue) : le bloc à la hauteur d'effet est
        // jugé sous le NOUVEAU régime, sans rien muter avant le succès. Clonée (≤ 64
        // clés) pour n'avoir aucun emprunt de `self` en travers de la mutation finale.
        let autorites_actives: Vec<crypto::sig::SigPublicKey> =
            self.autorites_a(bloc.hauteur).to_vec();
```

(b) Le `match self.producteur_attendu(bloc.hauteur, bloc.vue)` reste correct tel quel : `producteur_attendu` est désormais height-aware et renvoie le producteur de la liste active. AUCUNE modification de ce bloc `match`. (Le recalcul d'index dans `ScellementInvalide` utilise `self.autorites.len()` — le remplacer par `autorites_actives.len()` pour rester cohérent à la hauteur d'effet.)

Remplacer, dans la branche `ScellementInvalide` :

```rust
                    let attendu = ((bloc.hauteur - 1 + bloc.vue as u64)
                        % self.autorites.len() as u64) as usize;
```

par :

```rust
                    let attendu = ((bloc.hauteur - 1 + bloc.vue as u64)
                        % autorites_actives.len() as u64) as usize;
```

(c) Le bloc de vérification du certificat : remplacer `self.autorites.is_empty()`, `self.quorum_requis()` et `self.autorites.get(index)` par leurs équivalents locaux. Précisément :

- `if self.autorites.is_empty() {` → `if autorites_actives.is_empty() {`
- `let requis = self.quorum_requis();` → `let requis = quorum_pour(autorites_actives.len());`
- `let Some(pk) = self.autorites.get(index) else {` → `let Some(pk) = autorites_actives.get(index) else {`

(d) Le COMMIT, à la toute fin, APRÈS `self.tete = bloc.id(); self.hauteur = bloc.hauteur;` et AVANT le bloc `if let Some(h) = self.historique.as_mut()`. Ajouter :

```rust
        // COMMIT DU CHANGEMENT D'AUTORITÉS (J1-c) — seulement après succès complet.
        // Ordre : activer d'abord (vider le pendant), annoncer ensuite. Ce couple rend
        // le cas back-to-back correct — un bloc à h+K peut activer le précédent ET en
        // annoncer un nouveau à h+2K.
        if let Some((nouvelle, e)) = self.changement_en_attente.clone() {
            if e == bloc.hauteur {
                self.autorites = nouvelle;
                self.changement_en_attente = None;
            }
        }
        if let Some(nouvelle) = &bloc.changement_autorites {
            let effet = bloc.hauteur + DELAI_CHANGEMENT_AUTORITES;
            self.changement_en_attente = Some((nouvelle.clone(), effet));
        }
```

Note : la validité du changement (tx vide, chaîne à autorités, un-seul-en-vol, overflow) est ajoutée en Task 4, AVANT ce commit. Pour l'instant, le chemin nominal (annonce simple + activation) suffit à faire passer les tests du Step 1.

- [ ] **Step 6 : Adapter les tests existants de quorum**

Le test `quorum_generalise` (ligne ~986) et `n5_ferme_la_divergence_par_un_seul_fautif` appellent `quorum_requis()` sans changement en attente : comportement inchangé, ils passent tels quels. Vérifier qu'aucun ajustement n'est nécessaire :

Run: `cargo test -p ledger --lib proved_state::tests::quorum 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 7 : Lancer les tests proved_state, vérifier le vert**

Run: `cargo test -p ledger --lib proved_state:: 2>&1 | tail -20`
Expected: PASS (dont `changement_enregistre_lattente`, `le_changement_bascule_a_h_plus_k`). Les tests à preuves (quorum_suffisant_accepte, etc.) sont ignorés en debug — c'est attendu.

- [ ] **Step 8 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo test -p ledger --lib proved_state::
```

```bash
git add crates/ledger/src/proved_state.rs
git commit -m "$(cat <<'EOF'
consensus(J1-c): liste active locale, activation à h+K, commit après succès

autorites_a(hauteur) rend la nouvelle liste ssi un changement prend effet
à cette hauteur ; producteur et quorum en dérivent. Le commit (bascule +
enregistrement) est à la toute fin d'appliquer_bloc — un bloc refusé ne
mute rien.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4 : Les gardes de refus du changement

**Files:**
- Modify: `crates/ledger/src/proved_state.rs`

**Interfaces:**
- Consumes: `Bloc.changement_autorites`, `autorites_actives` (Task 3), `DELAI_CHANGEMENT_AUTORITES`, `liste_a_un_doublon` (rendu accessible : `crate::bloc::liste_a_un_doublon`).
- Produces: variantes `BlocRefus::{ChangementAvecTransactions, ChangementSurChaineOuverte, ChangementDejaEnAttente, ChangementHauteurOverflow}`.

- [ ] **Step 1 : Écrire les tests des gardes**

Ajouter dans `mod tests` de `proved_state.rs`. Helper pour un bloc de changement scellé/voté :

```rust
    /// Bloc de changement à hauteur `h`, scellé par le producteur du tour et voté au
    /// quorum de la liste active de `h`.
    fn bloc_changement(
        etat: &ProvedLedgerState,
        h: u64,
        cles: &[crypto::sig::SigKeypair],
        nouvelle: Vec<crypto::sig::SigPublicKey>,
    ) -> crate::bloc::Bloc {
        let prod = ((h - 1) % cles.len() as u64) as usize;
        let mut b = crate::bloc::Bloc::sceller_changement(&etat.tete(), h, nouvelle).unwrap();
        b.signer_scellement(&cles[prod]);
        for i in 0..etat.quorum_a(h) {
            b.signer_vote(i, &cles[i]);
        }
        b
    }
```

Les tests :

```rust
    /// Un changement sur une CHAÎNE OUVERTE (sans autorités) n'a aucun sens : refusé.
    #[test]
    fn changement_sur_chaine_ouverte_refuse() {
        let mut etat = ProvedLedgerState::with_depth(4);
        let mut b =
            crate::bloc::Bloc::sceller_changement(&etat.tete(), 1, vec![
                crypto::sig::SigKeypair::generate().public,
            ])
            .unwrap();
        b.vue = 0; // chaîne ouverte : pas de scellement, pas de certificat
        assert!(matches!(
            etat.appliquer_bloc(&b),
            Err(BlocRefus::ChangementSurChaineOuverte)
        ));
    }

    /// Un bloc de changement PORTANT des transactions est refusé (gouvernance vide).
    /// Bloc HOSTILE par littéral (le constructeur l'interdit) ; la tx n'est jamais
    /// vérifiée — le refus O(1) précède tout STARK — mais il faut une `ProvedTx`
    /// décodable, d'où le gating release. Le motif `ProvedTx::from_bytes(&tx.to_bytes())`
    /// est celui de `bloc_hors_borne_refuse_avant_verification`, et `setup()` la fabrique
    /// (déjà présente dans ce module de tests).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn changement_avec_transactions_refuse() {
        let (mut etat, cles) = chaine_a(4);
        let (_, tx) = setup();
        let mut b = crate::bloc::Bloc {
            parent: etat.tete(),
            hauteur: 1,
            vue: 0,
            transactions: vec![circuit::ProvedTx::from_bytes(&tx.to_bytes()).unwrap()],
            emissions: Vec::new(),
            autorites: Vec::new(),
            changement_autorites: Some(vec![crypto::sig::SigKeypair::generate().public]),
            extension: Vec::new(),
            scellement: None,
            certificat: None,
        };
        b.signer_scellement(&cles[0]);
        for i in 0..etat.quorum_a(1) {
            b.signer_vote(i, &cles[i]);
        }
        assert!(matches!(
            etat.appliquer_bloc(&b),
            Err(BlocRefus::ChangementAvecTransactions { .. })
        ));
    }

    /// Deux changements empilés : le second est refusé tant que le premier est en vol.
    #[test]
    fn deuxieme_changement_pendant_lattente_refuse() {
        let (mut etat, cles) = chaine_a(4);
        // Installer un pendant à effet lointain (test, sans dérouler K blocs).
        etat.injecter_changement_pour_test(
            (0..4)
                .map(|_| crypto::sig::SigKeypair::generate().public)
                .collect(),
            1 + DELAI_CHANGEMENT_AUTORITES,
        );
        let b = bloc_changement(&etat, 1, &cles, vec![
            crypto::sig::SigKeypair::generate().public,
        ]);
        assert!(matches!(
            etat.appliquer_bloc(&b),
            Err(BlocRefus::ChangementDejaEnAttente)
        ));
    }

    /// `hauteur + K` qui déborderait u64 est refusé (jamais de wrap silencieux).
    #[test]
    fn changement_hauteur_overflow_refuse() {
        let (mut etat, cles) = chaine_a(4);
        // Forcer l'état près de u64::MAX pour que h+1 puis h+1+K déborde. On règle la
        // tête à une hauteur telle que prochaine + K > u64::MAX.
        etat.forcer_hauteur_pour_test(u64::MAX - 1, etat.tete());
        // prochaine = u64::MAX, +K déborde.
        let mut b = crate::bloc::Bloc::sceller_changement(&etat.tete(), u64::MAX, vec![
            crypto::sig::SigKeypair::generate().public,
        ])
        .unwrap();
        b.signer_scellement(&cles[((u64::MAX - 1) % 4) as usize]);
        for i in 0..etat.quorum_a(u64::MAX) {
            b.signer_vote(i, &cles[i]);
        }
        assert!(matches!(
            etat.appliquer_bloc(&b),
            Err(BlocRefus::ChangementHauteurOverflow { .. })
        ));
    }
```

Ces tests exigent deux points d'entrée de test (`tx_bidon`, `forcer_hauteur_pour_test`) définis au Step 4.

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `cargo test -p ledger --lib proved_state::tests::changement 2>&1 | head -20`
Expected: échec de compilation (variantes et helpers de test inexistants).

- [ ] **Step 3 : Ajouter les variantes de `BlocRefus`**

```rust
    /// Un bloc de reconfiguration ne porte AUCUNE transaction (gouvernance vide).
    #[error("bloc de changement d'autorités portant {recues} transactions")]
    ChangementAvecTransactions { recues: usize },
    /// Reconfiguration sur une chaîne OUVERTE : aucun comité à reconfigurer.
    #[error("changement d'autorités sur une chaîne ouverte (aucun comité)")]
    ChangementSurChaineOuverte,
    /// Un changement resterait en attente après ce bloc (un seul en vol).
    #[error("un changement d'autorités est déjà en attente")]
    ChangementDejaEnAttente,
    /// `hauteur + K` déborderait `u64`.
    #[error("hauteur d'effet du changement ({hauteur} + {k}) déborde u64")]
    ChangementHauteurOverflow { hauteur: u64, k: u64 },
```

- [ ] **Step 4 : Ajouter les points d'entrée de test**

Dans `impl ProvedLedgerState`, gardé `#[cfg(test)]` :

```rust
    /// Force tête + hauteur pour éprouver les débordements. Tests seulement.
    #[cfg(test)]
    fn forcer_hauteur_pour_test(&mut self, hauteur: u64, tete: [u8; TAILLE_ID]) {
        self.hauteur = hauteur;
        self.tete = tete;
    }
```

Le test `changement_avec_transactions_refuse` (Step 1) obtient sa `ProvedTx` via le helper `setup()` DÉJÀ présent dans ce module (utilisé par `bloc_hors_borne_refuse_avant_verification` et `sceller_refuse_un_bloc_trop_lourd…`), avec le motif `circuit::ProvedTx::from_bytes(&tx.to_bytes()).unwrap()`. **Ne pas inventer d'API circuit** ; aucun helper `tx_bidon` n'est nécessaire.

- [ ] **Step 5 : Câbler les gardes dans `appliquer_bloc`**

Insérer le bloc de validation du changement APRÈS la vérification du certificat (le `if autorites_actives.is_empty() { … } else { … }`) et AVANT l'instantané d'atomicité (`let arbre_avant = …`). Ainsi les gardes O(1) précèdent l'instantané et la boucle STARK :

```rust
        // VALIDITÉ DU CHANGEMENT D'AUTORITÉS (J1-c), si le bloc en porte un. Contrôles
        // O(1), placés AVANT l'instantané et la boucle STARK (frontière du coût).
        if let Some(nouvelle) = &bloc.changement_autorites {
            // Chaîne à autorités seulement : `autorites_actives` non vide (une chaîne
            // ouverte n'a rien à reconfigurer). NB : sur chaîne ouverte, la branche
            // certificat ci-dessus a déjà refusé un certificat ; ici on nomme la cause.
            if autorites_actives.is_empty() {
                return Err(BlocRefus::ChangementSurChaineOuverte);
            }
            // Bloc de gouvernance VIDE de transactions.
            if !bloc.transactions.is_empty() {
                return Err(BlocRefus::ChangementAvecTransactions {
                    recues: bloc.transactions.len(),
                });
            }
            // Validité structurelle (défense : `Bloc` a des champs publics).
            if nouvelle.is_empty() || nouvelle.len() > crate::bloc::MAX_AUTORITES {
                return Err(BlocRefus::ChangementSurChaineOuverte);
            }
            if crate::bloc::liste_a_un_doublon(nouvelle) {
                return Err(BlocRefus::ChangementSurChaineOuverte);
            }
            // UN SEUL EN VOL : le bloc peut annoncer SSI aucun changement ne restera en
            // attente après lui — soit `changement_en_attente` est None, soit il est
            // ACTIVÉ par ce bloc (effet == hauteur).
            let pendant_survit = match &self.changement_en_attente {
                None => false,
                Some((_, e)) => *e != bloc.hauteur,
            };
            if pendant_survit {
                return Err(BlocRefus::ChangementDejaEnAttente);
            }
            // `hauteur + K` ne doit pas déborder.
            if bloc
                .hauteur
                .checked_add(DELAI_CHANGEMENT_AUTORITES)
                .is_none()
            {
                return Err(BlocRefus::ChangementHauteurOverflow {
                    hauteur: bloc.hauteur,
                    k: DELAI_CHANGEMENT_AUTORITES,
                });
            }
        }
```

Note : la validité structurelle « liste vide / hors borne / doublon » retombe ici sur `ChangementSurChaineOuverte` uniquement par économie de variantes ? **Non** — c'est trompeur. Utiliser une variante dédiée. Remplacer les deux `return Err(BlocRefus::ChangementSurChaineOuverte)` de la validité structurelle par une variante `BlocRefus::ChangementInvalide` à ajouter au Step 3 :

```rust
    #[error("liste de changement d'autorités invalide (vide, hors borne ou doublon)")]
    ChangementInvalide,
```

et utiliser `return Err(BlocRefus::ChangementInvalide);` pour les trois cas structurels (vide, hors borne, doublon). Garder `ChangementSurChaineOuverte` pour le seul cas `autorites_actives.is_empty()`.

Corriger aussi le `bloc.hauteur.checked_add(...)` : la valeur d'effet est réutilisée au commit (Task 3 Step 5d). Remplacer, dans le commit, `let effet = bloc.hauteur + DELAI_CHANGEMENT_AUTORITES;` par un `checked_add().expect(...)` cohérent (le contrôle ci-dessus garantit l'absence de débordement) :

```rust
            let effet = bloc
                .hauteur
                .checked_add(DELAI_CHANGEMENT_AUTORITES)
                .expect("débordement déjà refusé par ChangementHauteurOverflow");
```

- [ ] **Step 6 : Lancer, vérifier le vert**

Run: `cargo test -p ledger --lib proved_state:: 2>&1 | tail -25`
Expected: PASS (dont les 4 nouveaux tests de garde). Vérifier qu'aucune régression sur les tests de quorum/scellement existants.

- [ ] **Step 7 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test -p ledger --lib proved_state::
```

```bash
git add crates/ledger/src/proved_state.rs
git commit -m "$(cat <<'EOF'
consensus(J1-c): gardes du changement (tx vide, un seul en vol, overflow)

Contrôles O(1) placés avant l'instantané et la boucle STARK. La règle
un-seul-en-vol autorise le back-to-back : annoncer ssi le pendant est
activé par ce bloc.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5 : Atomicité et back-to-back (par mutation)

**Files:**
- Modify: `crates/ledger/src/proved_state.rs`

**Interfaces:**
- Consumes: tout ce qui précède.
- Produces: aucun nouvel API ; deux tests de propriété.

- [ ] **Step 1 : Écrire le test d'atomicité**

Un bloc REFUSÉ à la hauteur d'effet ne doit laisser NI liste committée basculée NI pendant effacé. On installe un changement à effet 1, puis on présente un bloc au quorum INSUFFISANT à cette hauteur : refusé au contrôle du certificat (AVANT l'instantané, donc AVANT le commit d'activation). Aucune preuve requise (bloc vide) :

```rust
    /// ATOMICITÉ : un bloc REFUSÉ à la hauteur d'effet ne bascule NI la liste committée
    /// NI le pendant. Un changement est en attente à l'effet 1 ; un bloc au quorum
    /// INSUFFISANT à cette hauteur est refusé — le commit d'activation (postérieur au
    /// contrôle de quorum) n'est jamais atteint.
    #[test]
    fn bloc_refuse_a_leffet_ne_mute_rien() {
        let (mut etat, ancien) = chaine_a(4);
        let nouvelles: Vec<_> = (0..4)
            .map(|_| crypto::sig::SigKeypair::generate())
            .collect();
        etat.injecter_changement_pour_test(
            nouvelles.iter().map(|k| k.public.clone()).collect(),
            1,
        );
        // Bloc à la hauteur d'effet 1, jugé sous la NOUVELLE liste (producteur de (1,0)
        // = nouvelles[0]), mais seulement 2 votes alors que le quorum est 3.
        let mut b = crate::bloc::Bloc::sceller(&etat.tete(), 1, Vec::new()).unwrap();
        b.signer_scellement(&nouvelles[0]);
        b.signer_vote(0, &nouvelles[0]);
        b.signer_vote(1, &nouvelles[1]);
        assert!(matches!(
            etat.appliquer_bloc(&b),
            Err(BlocRefus::QuorumInsuffisant { obtenu: 2, requis: 3 })
        ));
        // La liste COMMITTÉE n'a pas basculé (toujours l'ancienne).
        assert_eq!(etat.autorites()[0].to_bytes(), ancien[0].public.to_bytes());
        assert_eq!(etat.hauteur(), 0, "la hauteur ne doit pas avoir avancé");
        // Le pendant est intact : un bloc valide à l'effet basculerait encore.
        assert_eq!(etat.quorum_a(1), 3);
    }
```

- [ ] **Step 2 : Écrire le test back-to-back (sémantique, sans dérouler K blocs)**

Le back-to-back complet exige K blocs prouvés ; on éprouve la RÈGLE (un bloc à la hauteur d'effet peut activer ET annoncer) au niveau de la logique de commit, via un état préparé :

```rust
    /// BACK-TO-BACK : un bloc à la hauteur d'effet ACTIVE le changement précédent ET
    /// en annonce un nouveau. Le verrou « un seul en vol » ne le refuse pas, parce que
    /// le pendant est activé par ce bloc même.
    #[test]
    fn back_to_back_active_et_annonce() {
        // n=4 → après activation, nouvelle liste n=4 (mêmes tailles pour simplifier le
        // scellement/vote). On installe un pendant à effet = 1 (activé par le bloc 1).
        let (mut etat, _cles_ancien) = chaine_a(4);
        let nouvelles_cles: Vec<_> = (0..4)
            .map(|_| crypto::sig::SigKeypair::generate())
            .collect();
        etat.injecter_changement_pour_test(
            nouvelles_cles.iter().map(|k| k.public.clone()).collect(),
            1,
        );
        // Le bloc 1 est jugé sous la NOUVELLE liste (effet == 1) : producteur et votes
        // viennent de `nouvelles_cles`. Il annonce ENCORE un changement.
        let encore: Vec<_> = (0..4)
            .map(|_| crypto::sig::SigKeypair::generate().public)
            .collect();
        let mut b =
            crate::bloc::Bloc::sceller_changement(&etat.tete(), 1, encore.clone()).unwrap();
        b.signer_scellement(&nouvelles_cles[0]);
        for i in 0..etat.quorum_a(1) {
            b.signer_vote(i, &nouvelles_cles[i]);
        }
        etat.appliquer_bloc(&b).expect("back-to-back accepté");
        // Activation : la liste courante est désormais `nouvelles_cles`.
        assert_eq!(etat.autorites()[0].to_bytes(), nouvelles_cles[0].public.to_bytes());
        // Annonce : un changement à effet 1 + K est enregistré (quorum de `encore`,
        // n=4 → 3).
        assert_eq!(etat.quorum_a(1 + DELAI_CHANGEMENT_AUTORITES), 3);
    }
```

- [ ] **Step 3 : Lancer, vérifier le vert (aucune implémentation nouvelle requise)**

Run: `cargo test -p ledger --lib proved_state::tests::bloc_refuse_a_leffet proved_state::tests::back_to_back 2>&1 | tail -15`
Expected: PASS. Si `back_to_back_active_et_annonce` échoue, c'est que l'ordre du commit (activer puis annoncer) est incorrect — revérifier Task 3 Step 5d.

- [ ] **Step 4 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo test -p ledger --lib proved_state::
```

```bash
git add crates/ledger/src/proved_state.rs
git commit -m "$(cat <<'EOF'
test(J1-c): atomicité et back-to-back du changement d'autorités

Un bloc refusé ne mute ni liste ni attente ; un bloc à la hauteur d'effet
peut activer le précédent et annoncer le suivant.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6 : Persistance `VERSION_ETAT 0x05` et invariants au chargement

**Files:**
- Modify: `crates/ledger/src/proved_state.rs`

**Interfaces:**
- Consumes: `changement_en_attente`, `liste_a_un_doublon`, `MAX_AUTORITES`, `TAILLE_AUTORITE_MAX`.
- Produces: `VERSION_ETAT = 0x05`, encodage/décodage du champ, `StateDecodeError::BadChangement`.

- [ ] **Step 1 : Écrire les tests de persistance**

```rust
    /// Le changement en attente survit à un aller-retour de dump (0x05).
    #[test]
    fn changement_en_attente_persiste() {
        let (mut etat, _cles) = chaine_a(4);
        let nouvelle: Vec<_> = (0..7)
            .map(|_| crypto::sig::SigKeypair::generate().public)
            .collect();
        etat.injecter_changement_pour_test(nouvelle.clone(), 1 + DELAI_CHANGEMENT_AUTORITES);
        let relu = ProvedLedgerState::from_bytes(&etat.to_bytes()).expect("relecture");
        // Le basculement est retrouvé : quorum de la nouvelle liste à la hauteur d'effet.
        assert_eq!(relu.quorum_a(1 + DELAI_CHANGEMENT_AUTORITES), 5);
    }

    /// Un dump d'état 0x04 est refusé par son nom.
    #[test]
    fn dump_0x04_refuse_par_son_nom() {
        let (etat, _cles) = chaine_a(4);
        let mut octets = etat.to_bytes();
        octets[0] = 0x04;
        assert!(matches!(
            ProvedLedgerState::from_bytes(&octets),
            Err(StateDecodeError::BadVersion(0x04))
        ));
    }

    /// Un `changement_en_attente` corrompu au chargement (hauteur d'effet DÉPASSÉE)
    /// est refusé : l'accepter laisserait un basculement qui ne se produira jamais.
    #[test]
    fn changement_a_effet_depasse_refuse_au_chargement() {
        let (mut etat, _cles) = chaine_a(4);
        etat.forcer_hauteur_pour_test(10, etat.tete());
        etat.injecter_changement_pour_test(
            (0..4)
                .map(|_| crypto::sig::SigKeypair::generate().public)
                .collect(),
            5, // effet 5 <= hauteur 10 : incohérent
        );
        let octets = etat.to_bytes();
        assert!(matches!(
            ProvedLedgerState::from_bytes(&octets),
            Err(StateDecodeError::BadChangement)
        ));
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `cargo test -p ledger --lib proved_state::tests::changement_en_attente_persiste proved_state::tests::dump_0x04 proved_state::tests::changement_a_effet 2>&1 | head -20`
Expected: échec (VERSION_ETAT encore 0x04, champ non sérialisé, `BadChangement` inexistant).

- [ ] **Step 3 : Bumper `VERSION_ETAT` et ajouter la variante d'erreur**

```rust
pub const VERSION_ETAT: u8 = 0x05;
```
Mettre à jour la doc (une ligne) : `` `0x05` : le CHANGEMENT D'AUTORITÉS EN ATTENTE entre dans le dump (J1-c) — un nœud redémarré dans `[h+1, h+K)` doit retrouver le basculement ; et `VERSION_BLOC` passant à 0x05, tous les identifiants changent. ``

Ajouter à `StateDecodeError` :

```rust
    /// Changement d'autorités en attente incohérent (vide, hors borne, doublon, ou
    /// hauteur d'effet déjà dépassée).
    BadChangement,
```

- [ ] **Step 4 : Encoder le champ dans `to_bytes`**

Dans `to_bytes`, APRÈS la boucle des `autorites` et AVANT le `b` final, ajouter :

```rust
        // Changement d'autorités en attente (0x05) : `count u32` (0 = absent), puis
        // `effet u64 ‖ [len(pk) ‖ pk]`. Canonique : count = 0 ⇔ absent (liste vide
        // interdite, donc jamais confondue).
        match &self.changement_en_attente {
            None => b.extend_from_slice(&0u32.to_le_bytes()),
            Some((liste, effet)) => {
                b.extend_from_slice(&(liste.len() as u32).to_le_bytes());
                b.extend_from_slice(&effet.to_le_bytes());
                for pk in liste {
                    let o = pk.to_bytes();
                    b.extend_from_slice(&(o.len() as u32).to_le_bytes());
                    b.extend_from_slice(&o);
                }
            }
        }
```

- [ ] **Step 5 : Décoder le champ dans `from_bytes` avec invariants**

Dans `from_bytes`, APRÈS la boucle qui lit `autorites` et AVANT le contrôle `if pos != b.len()`, ajouter :

```rust
        // Changement d'autorités en attente (0x05). `from_bytes` ne fait pas confiance
        // au fichier : liste vide / hors borne / doublon / effet déjà dépassé → refus.
        let nc = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
        let changement_en_attente = if nc == 0 {
            None
        } else {
            if nc > crate::bloc::MAX_AUTORITES {
                return Err(StateDecodeError::BadChangement);
            }
            let effet = u64::from_le_bytes(take(b, &mut pos, 8)?.try_into().unwrap());
            // Un effet déjà dépassé est un basculement qui ne se produira jamais.
            if effet <= hauteur {
                return Err(StateDecodeError::BadChangement);
            }
            let mut liste = Vec::with_capacity(nc);
            for _ in 0..nc {
                let lp = u32::from_le_bytes(take(b, &mut pos, 4)?.try_into().unwrap()) as usize;
                if lp > crate::bloc::TAILLE_AUTORITE_MAX {
                    return Err(StateDecodeError::BadChangement);
                }
                let pk = crypto::sig::SigPublicKey::from_bytes(take(b, &mut pos, lp)?)
                    .map_err(|_| StateDecodeError::BadChangement)?;
                liste.push(pk);
            }
            if crate::bloc::liste_a_un_doublon(&liste) {
                return Err(StateDecodeError::BadChangement);
            }
            Some((liste, effet))
        };
```

Ajouter `changement_en_attente,` (raccourci) au `Ok(ProvedLedgerState { … })` final (remplacer le `changement_en_attente: None` posé en Task 3 Step 3 pour `from_bytes`).

- [ ] **Step 6 : Lancer, vérifier le vert**

Run: `cargo test -p ledger --lib proved_state:: 2>&1 | tail -25`
Expected: PASS (dont les 3 nouveaux). Vérifier que les tests de persistance existants (`to_bytes`/`from_bytes` aller-retour) passent toujours.

- [ ] **Step 7 : CI locale + suite ledger complète + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test -p ledger --all-features --release
```
Expected: la suite `ledger` complète est verte (les tests à preuves tournent en `--release`).

```bash
git add crates/ledger/src/proved_state.rs
git commit -m "$(cat <<'EOF'
consensus(J1-c): le changement en attente persiste (VERSION_ETAT 0x05)

Dump et rechargement du pendant ; invariants au chargement (vide, borne,
doublon, effet dépassé refusés). 0x04 refusé par son nom.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7 : Nœud — câbler la production d'un bloc de reconfiguration

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes: `Bloc::sceller_changement` (Task 2), `ProvedLedgerState::quorum_a` (Task 3), `producteur_attendu` height-aware.
- Produces: `pub fn Noeud::proposer_changement(&mut self, nouvelles: Vec<SigPublicKey>, maintenant_ms: u64) -> Option<(Bloc, Vec<Action>)>`, via un paramètre `changement` ajouté à `proposer_a_vue`.

- [ ] **Step 1 : Écrire le test unitaire (n=1, auto-application d'une reconfiguration)**

Ajouter dans `mod tests` de `crates/node/src/orchestration.rs`. Le cas n=1 (quorum 1) applique directement, comme `sceller_signe_a_son_tour` :

```rust
    /// Une AUTORITÉ UNIQUE reconfigure la chaîne : elle scelle un bloc de changement,
    /// se certifie (quorum 1), l'applique, et le diffuse. Le pendant est enregistré.
    #[test]
    #[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
    fn proposer_changement_auto_applique_a_n1() {
        let nous = SigKeypair::generate();
        let nous_pub = nous.public.clone();
        let genese = ledger::bloc::Bloc::genese_avec_autorites(
            Vec::new(),
            vec![nous_pub.clone()],
        )
        .unwrap();
        let mut n = Noeud::new(
            nous,
            ProvedLedgerState::depuis_genese_depth(&genese, 4).unwrap(),
            [3u8; 32],
        );
        let nouvelle = SigKeypair::generate().public;
        let (bloc, actions) = n
            .proposer_changement(vec![nouvelle.clone()], 0)
            .expect("notre tour : un bloc de reconfiguration");
        assert_eq!(bloc.hauteur, 1);
        assert!(bloc.transactions.is_empty());
        assert_eq!(bloc.changement_autorites.as_ref().unwrap().len(), 1);
        assert_eq!(n.etat.hauteur(), 1, "appliqué à notre état");
        assert!(matches!(
            actions.as_slice(),
            [Action::Diffuser(Message::Bloc(_))]
        ));
        // Le changement est enregistré : quorum à la hauteur d'effet = 1 (nouvelle
        // liste n=1).
        assert_eq!(
            n.etat.quorum_a(1 + ledger::proved_state::DELAI_CHANGEMENT_AUTORITES),
            1
        );
    }
```

- [ ] **Step 2 : Lancer, vérifier l'échec**

Run: `cargo test -p node --lib proposer_changement 2>&1 | head -15`
Expected: échec de compilation (`proposer_changement` inexistant).

- [ ] **Step 3 : Ajouter le paramètre `changement` à `proposer_a_vue`**

Modifier la signature :

```rust
    fn proposer_a_vue(
        &mut self,
        vue: u32,
        maintenant_ms: u64,
        changement: Option<Vec<crypto::sig::SigPublicKey>>,
    ) -> Option<(Bloc, Vec<Action>)> {
```

Au début du corps, remplacer la SÉLECTION du mempool + `let mut bloc = Bloc::sceller(...)` par une construction conditionnelle. Concrètement, remplacer tout le bloc allant de `let mut digests = self.mempool.digests();` jusqu'à `let mut bloc = Bloc::sceller(&self.etat.tete(), prochaine, transactions).ok()?;` par :

```rust
        let (mut bloc, digests): (Bloc, Vec<[u8; 64]>) = if let Some(nouvelles) = changement {
            // RECONFIGURATION : bloc VIDE de transactions, changement attaché. Refusé
            // hors chaîne à autorités (rien à reconfigurer).
            if !a_autorites {
                return None;
            }
            let bloc = Bloc::sceller_changement(&self.etat.tete(), prochaine, nouvelles).ok()?;
            (bloc, Vec::new())
        } else {
            let mut digests = self.mempool.digests();
            digests.sort_unstable();

            // SÉLECTION SOUS DOUBLE BUDGET : nombre ET octets. (commentaire existant
            // conservé)
            let mut octets = ledger::bloc::SURCOUT_BLOC_VIDE;
            let mut transactions: Vec<circuit::ProvedTx> = Vec::new();
            let mut retenus: Vec<[u8; 64]> = Vec::new();
            for d in &digests {
                if transactions.len() >= ledger::bloc::MAX_TX_PAR_BLOC {
                    break;
                }
                let Some(brute) = self.mempool.get(d) else {
                    continue;
                };
                let o = brute.to_bytes();
                let cout = ledger::bloc::cout_transaction(o.len());
                if octets + cout > ledger::bloc::MAX_OCTETS_BLOC {
                    break;
                }
                let Ok(tx) = ProvedTx::from_bytes(&o) else {
                    continue;
                };
                octets += cout;
                transactions.push(tx);
                retenus.push(*d);
            }
            // Chaîne OUVERTE sans rien à sceller : pas de bloc vide spontané.
            if transactions.is_empty() && !a_autorites {
                return None;
            }
            let bloc = Bloc::sceller(&self.etat.tete(), prochaine, transactions).ok()?;
            (bloc, retenus)
        };
```

Le reste de la fonction (à partir de `bloc.vue = vue;`) est INCHANGÉ — le chemin sign/vote/propose/apply est commun. Vérifier que la variable `digests` (les retenus) est bien celle utilisée plus bas dans la branche d'auto-application (`for d in &digests { self.mempool.retirer(d); }`). Pour un bloc de reconfiguration, `digests` est vide, donc rien n'est retiré du mempool — correct.

- [ ] **Step 4 : Mettre à jour les appelants de `proposer_a_vue`**

Deux appelants existants passent désormais `None` :
- `sceller` : `self.proposer_a_vue(self.vue_courante, 0, None)`.
- `proposer_si_notre_tour` : `self.proposer_a_vue(self.vue_courante, maintenant_ms, None)`.

- [ ] **Step 5 : Ajouter `proposer_changement`**

Ajouter dans `impl Noeud`, à côté de `sceller` :

```rust
    /// Propose un CHANGEMENT D'AUTORITÉS (J1-c) : scelle un bloc de reconfiguration à
    /// notre tour, se certifie (quorum 1) ou le propose (au-delà). Décision d'opérateur,
    /// exactement comme `sceller`. `None` si ce n'est pas notre tour ou sur chaîne
    /// ouverte.
    pub fn proposer_changement(
        &mut self,
        nouvelles: Vec<crypto::sig::SigPublicKey>,
        maintenant_ms: u64,
    ) -> Option<(Bloc, Vec<Action>)> {
        self.proposer_a_vue(self.vue_courante, maintenant_ms, Some(nouvelles))
    }
```

- [ ] **Step 6 : Corriger le quorum height-aware dans le chemin de proposition**

Dans `proposer_a_vue`, la ligne `if self.etat.quorum_requis() > 1 {` doit tenir compte de la hauteur du bloc proposé (à la hauteur d'effet, la nouvelle liste peut avoir un autre quorum). Remplacer par :

```rust
            if self.etat.quorum_a(prochaine) > 1 {
```

Dans le chemin d'ASSEMBLAGE des votes reçus (les deux `self.etat.quorum_requis()` aux alentours des lignes 649 et 662), remplacer par `self.etat.quorum_a(self.etat.hauteur() + 1)`. Les localiser :

Run: `grep -n "quorum_requis()" crates/node/src/orchestration.rs`
Remplacer les occurrences des lignes ~492/649/662 par la forme height-aware ci-dessus. **Ne pas** toucher l'occurrence du test (ligne ~1141) ni celle de `conformite.rs`.

- [ ] **Step 7 : Lancer, vérifier le vert**

Run: `cargo test -p node --lib 2>&1 | tail -20`
Expected: PASS (le test `proposer_changement_auto_applique_a_n1` est ignoré en debug ; les autres tests unitaires du nœud passent).

Run (preuves) : `cargo test -p node --lib --release proposer_changement 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 8 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test -p node --lib --release
```

```bash
git add crates/node/src/orchestration.rs
git commit -m "$(cat <<'EOF'
consensus(J1-c): proposer_changement — un bloc de reconfiguration circule

proposer_a_vue gagne un paramètre changement ; le chemin sign/vote/propose
reste commun. Quorum height-aware au point de proposition et d'assemblage.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8 : Socket — critère de sortie (reconfiguration certifiée par l'ancien quorum)

**Files:**
- Create: `crates/node/tests/reconfiguration.rs`

**Interfaces:**
- Consumes: `Noeud::proposer_changement`, `Runtime`, `Donnees`, le motif de `vue_sockets.rs` (helper `attendre_en_tiquant`, `voteur`).
- Produces: le test de sortie de J1-c.

- [ ] **Step 1 : Écrire le test de sortie**

S'inspirer STRUCTURELLEMENT de `crates/node/tests/vue_sockets.rs` (mêmes imports, mêmes helpers `repertoire`/`attendre_en_tiquant`/`voteur`, recopiés en tête du fichier). Le scénario : 4 autorités, l'autorité 0 (producteur de la hauteur 1) annonce le remplacement de l'autorité 3 par une clé neuve ; l'ancien quorum (3 sur 4) certifie ; on vérifie que le bloc 1 est appliqué partout, que le pendant est enregistré, et que `quorum_a(1 + K)` reflète la nouvelle liste. Le basculement effectif à `h+K` est vérifié au niveau LEDGER (Task 3/6) ; le test socket prouve la CERTIFICATION par l'ancien comité et la propagation.

```rust
//! CRITÈRE DE SORTIE J1-c : un changement d'autorités est CERTIFIÉ par le quorum de
//! l'ANCIENNE liste et se propage sur de vraies sockets. Le basculement effectif à
//! h+K est prouvé au niveau ledger ; ici on prouve que l'ancien comité DÉCIDE du
//! nouveau et que le bloc de reconfiguration circule et s'applique partout.
//!
//! Temps INJECTÉ (aucun sleep ne pilote le consensus), comme vue_sockets.rs.

use crypto::sig::SigKeypair;
use ledger::bloc::Bloc;
use ledger::proved_state::{ProvedLedgerState, DELAI_CHANGEMENT_AUTORITES};
use node::orchestration::Noeud;
use node::persistance::Donnees;
use node::runtime::Runtime;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::{Duration, Instant};

const PROFONDEUR: usize = 4;
const MAINTENANT_MS: u64 = 1_000;

// … recopier `repertoire`, `attendre_en_tiquant`, `voteur` depuis vue_sockets.rs …

#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn reconfiguration_certifiee_par_lancien_quorum() {
    let cles: Vec<SigKeypair> = (0..4).map(|_| SigKeypair::generate()).collect();
    let genese =
        Bloc::genese_avec_autorites(Vec::new(), cles.iter().map(|k| k.public.clone()).collect())
            .expect("genèse");
    // La NOUVELLE liste remplace l'autorité 3 par une clé neuve.
    let neuve = SigKeypair::generate();
    let nouvelle_liste: Vec<_> = vec![
        cles[0].public.clone(),
        cles[1].public.clone(),
        cles[2].public.clone(),
        neuve.public.clone(),
    ];

    // Autorités 1, 2, 3 écoutent et votent ; l'autorité 0 (producteur de la hauteur 1)
    // se connecte à elles et PROPOSE le changement.
    // … montage sockets calqué sur producteur_absent_la_chaine_avance …
    // Après connexion, l'autorité 0 appelle proposer_changement(nouvelle_liste, MAINTENANT_MS)
    // via une entrée runtime (voir Step 3), puis on pompe jusqu'à hauteur == 1 partout.

    // Assertions :
    //  - toutes les autorités appliquent le bloc 1 (même tête, même racine) ;
    //  - le bloc 1 porte `changement_autorites` = nouvelle_liste ;
    //  - le certificat réunit >= 3 votants de l'ANCIENNE liste ;
    //  - sur chaque nœud, quorum_a(1 + K) reflète la nouvelle liste (n=4 → 3) et
    //    producteur_attendu(1 + K, 0) == neuve.public (l'autorité 3 remplacée).
}
```

Compléter le montage sockets en calquant EXACTEMENT `producteur_absent_la_chaine_avance` (threads voteurs, `ecoute.accept()`, `rt.accepter`, `rt.connecter`, `attendre_en_tiquant`). La seule différence de fond : au lieu d'attendre un battement, l'autorité 0 déclenche `proposer_changement`.

- [ ] **Step 2 : Vérifier comment déclencher la proposition via le runtime**

Le `Runtime` encapsule le `Noeud`. Vérifier l'API exacte exposée pour agir sur le nœud :

Run: `grep -n "pub fn\|proposer\|sceller\|noeud" crates/node/src/runtime.rs | head -40`

Si le `Runtime` expose `noeud_mut()` (ou équivalent), l'utiliser : `let (bloc, actions) = rt.noeud_mut().proposer_changement(nouvelle_liste, MAINTENANT_MS)?;` puis injecter `actions` dans la boucle d'émission. Si le runtime ne l'expose pas encore, ajouter une méthode minimale au runtime :

```rust
    /// Déclenche une proposition de changement d'autorités et engage ses actions
    /// (diffusion) dans la boucle d'émission. Rôle d'opérateur, comme `sceller`.
    pub fn proposer_changement(
        &mut self,
        nouvelles: Vec<crypto::sig::SigPublicKey>,
        maintenant_ms: u64,
    ) -> bool {
        match self.noeud.proposer_changement(nouvelles, maintenant_ms) {
            Some((_, actions)) => {
                self.engager(actions); // méthode existante qui exécute les Action
                true
            }
            None => false,
        }
    }
```

**Vérifier le nom exact** de la méthode qui exécute les `Vec<Action>` dans le runtime (chercher comment `tick`/`sceller` y injectent leurs actions) et l'appeler. Ne pas inventer : `grep -n "Action" crates/node/src/runtime.rs`.

- [ ] **Step 3 : Lancer le test en release**

Run: `cargo test -p node --release --test reconfiguration 2>&1 | tail -25`
Expected: PASS. En cas d'échec de propagation, augmenter le délai réel d'attente (comme vue_sockets : `Duration::from_secs(120)`).

- [ ] **Step 4 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test -p node --release --test reconfiguration
```

```bash
git add crates/node/tests/reconfiguration.rs crates/node/src/runtime.rs
git commit -m "$(cat <<'EOF'
test(J1-c): une reconfiguration se certifie par l'ancien quorum sur sockets

4 autorités, l'autorité 3 remplacée par une clé neuve ; l'ancien comité
certifie le bloc de changement, qui se propage et enregistre le pendant.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9 : Socket — synergie J1-b2 et redémarrage

**Files:**
- Modify: `crates/node/tests/reconfiguration.rs`

**Interfaces:**
- Consumes: le montage de Task 8, `Donnees` (persistance), `attendre_en_tiquant`.
- Produces: deux tests supplémentaires.

- [ ] **Step 1 : Test de redémarrage dans la fenêtre `[h+1, h+K)`**

Un nœud qui applique le bloc de changement, persiste son état, puis REDÉMARRE (recharge depuis `Donnees`) doit retrouver le pendant et calculer le même basculement. Ce test peut rester LOCAL (sans sockets) : il exerce `ProvedLedgerState::{save, load}` via `node::persistance`.

```rust
/// REDÉMARRAGE : un nœud qui a enregistré un changement en attente le retrouve après
/// rechargement — sinon il raterait le basculement et divergerait.
#[test]
#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]
fn le_pendant_survit_au_redemarrage() {
    let cles: Vec<SigKeypair> = (0..1).map(|_| SigKeypair::generate()).collect();
    let genese =
        Bloc::genese_avec_autorites(Vec::new(), vec![cles[0].public.clone()]).unwrap();
    let dir = repertoire("redemarrage");
    let neuve = SigKeypair::generate().public;
    // Amorcer, proposer un changement (n=1, auto-appliqué), sauvegarder.
    {
        let donnees = Donnees::ouvrir(&dir).unwrap();
        let etat = ProvedLedgerState::depuis_genese_depth(&genese, PROFONDEUR).unwrap();
        let mut noeud = Noeud::new(
            SigKeypair::from_bytes_secret(&cles[0].to_bytes_secret()).unwrap(),
            etat,
            [5u8; 32],
        );
        noeud.proposer_changement(vec![neuve.clone()], 0).expect("reconfig n=1");
        assert_eq!(noeud.etat.hauteur(), 1);
        // Sauvegarder l'état via le chemin de persistance du nœud.
        noeud.etat.save(&donnees.chemin_etat()).unwrap();
    }
    // Recharger et vérifier le pendant.
    {
        let etat = ProvedLedgerState::load(&Donnees::ouvrir(&dir).unwrap().chemin_etat()).unwrap();
        assert_eq!(etat.hauteur(), 1);
        assert_eq!(
            etat.producteur_attendu(1 + DELAI_CHANGEMENT_AUTORITES, 0).map(|k| k.to_bytes()),
            Some(neuve.to_bytes()),
            "après redémarrage, le producteur à h+K est la nouvelle autorité"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
```

**Vérifier les noms exacts** de la persistance : `grep -n "pub fn\|chemin\|etat" crates/node/src/persistance.rs`. Si `Donnees` n'expose pas `chemin_etat()`, utiliser l'API réelle de sauvegarde/chargement d'état du nœud (chercher comment `runtime`/`persistance` sauvent l'état — p. ex. `donnees.enregistrer_etat(&etat)` / `donnees.charger_etat()`). Ne pas inventer.

- [ ] **Step 2 : Test de synergie J1-b2 (nouvelle autorité absente à h+K, contournée par changement de vue)**

Ce test est le plus lourd (dérouler jusqu'à `h+K` avec preuves). Le CADRER : commenter clairement qu'il exerce la COMPOSITION des deux briques, et le garder à profondeur 4 avec genèse vide. Si le coût de dérouler 8 blocs prouvés sur sockets est prohibitif, réduire la portée : prouver la synergie au niveau LEDGER en installant un pendant à effet proche via `injecter_changement_pour_test`, puis vérifier que `producteur_attendu(effet, 1)` (vue 1) désigne l'autorité SUIVANTE de la nouvelle liste — c'est-à-dire que le changement de vue contourne un nouveau membre absent. Ajouter ce test au module de tests de `proved_state.rs` (pas dans le fichier sockets) s'il reste au niveau ledger :

```rust
    /// SYNERGIE J1-b2 × J1-c : si le producteur de (h+K, 0) — un nouveau membre — est
    /// absent, le changement de vue désigne (h+K, 1) = l'autorité SUIVANTE de la
    /// NOUVELLE liste. Les deux briques composent sans cas particulier.
    #[test]
    fn changement_de_vue_contourne_un_nouveau_membre_absent() {
        let (mut etat, _cles) = chaine_a(4);
        let nouvelle: Vec<_> = (0..4)
            .map(|_| crypto::sig::SigKeypair::generate().public)
            .collect();
        let effet = 1 + DELAI_CHANGEMENT_AUTORITES;
        etat.injecter_changement_pour_test(nouvelle.clone(), effet);
        // Producteur de (effet, 0) = nouvelle[(effet-1) mod 4] ; de (effet, 1) =
        // nouvelle[(effet) mod 4]. Le changement de vue passe bien au SUIVANT.
        let p0 = etat.producteur_attendu(effet, 0).unwrap().to_bytes();
        let p1 = etat.producteur_attendu(effet, 1).unwrap().to_bytes();
        assert_eq!(p0, nouvelle[((effet - 1) % 4) as usize].to_bytes());
        assert_eq!(p1, nouvelle[(effet % 4) as usize].to_bytes());
        assert_ne!(p0, p1, "la vue 1 contourne le producteur absent de la vue 0");
    }
```

Placer ce test dans `proved_state.rs` (ledger) et le committer avec ce fichier. Le test de redémarrage reste dans `reconfiguration.rs`.

- [ ] **Step 3 : Lancer les deux tests**

Run: `cargo test -p ledger --lib changement_de_vue_contourne 2>&1 | tail -8`
Run: `cargo test -p node --release --test reconfiguration le_pendant_survit 2>&1 | tail -15`
Expected: PASS pour les deux.

- [ ] **Step 4 : CI locale + commit**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test -p ledger --lib && \
cargo test -p node --release --test reconfiguration
```

```bash
git add crates/node/tests/reconfiguration.rs crates/ledger/src/proved_state.rs
git commit -m "$(cat <<'EOF'
test(J1-c): redémarrage retrouve le pendant, vue contourne un nouveau absent

Le changement en attente survit au rechargement d'état ; le changement de
vue de J1-b2 désigne l'autorité suivante de la NOUVELLE liste — les deux
briques composent.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10 : Docs TESTNET, suite complète verte, PR

**Files:**
- Modify: `docs/TESTNET.md`
- (aucune modification des 8 fichiers protégés)

**Interfaces:**
- Consumes: tout J1-c.
- Produces: documentation opérateur + PR ouverte (non fusionnée).

- [ ] **Step 1 : Documenter la reconfiguration dans `docs/TESTNET.md`**

Dans la section §1.2 (Consensus), remplacer/compléter la ligne « Fédéré, pas décentralisé. La liste des autorités … En changer = nouvelle genèse = nouvelle chaîne. » par la réalité J1-c :

```markdown
- **Fédéré, pas décentralisé.** La liste des autorités de scellement est gravée
  dans la genèse, mais elle est désormais **reconfigurable sur la même chaîne**
  (J1-c) : l'ancien comité certifie collectivement la nouvelle liste par son
  quorum, et le changement prend effet à `h + K` (K = 8 blocs). Échanger, ajouter
  ou retirer un membre ne refait plus la chaîne. **En revanche, l'ancien quorum
  décide du nouveau** — y compris se réduire ou se remplacer entièrement : votre
  place dépend du quorum, pas d'un droit acquis.
- ⚠️ **Réduire le comité à `n ≤ 3` sacrifie la tolérance aux fautes.** Le quorum
  vaut alors `n` (tous doivent voter) et le changement de vue ne peut plus
  contourner une absence. Table de liveness :

  | n | quorum | tolère f absent(s) |
  |---|---|---|
  | 1 | 1 | 0 |
  | 2 | 2 | 0 |
  | 3 | 3 | 0 |
  | 4 | 3 | 1 |
  | 7 | 5 | 2 |
  | 10 | 7 | 3 |
```

Dans §2.1 (Ce qui provoque un reset), la ligne « Changement de la liste d'autorités | elle est gravée dans l'identifiant de genèse » n'est plus vraie pour un changement CERTIFIÉ. La corriger :

```markdown
| Changement NON certifié de la liste d'autorités (hors quorum, ou liste vide) | il faut une nouvelle genèse ; un changement certifié par le quorum, lui, se fait sur la même chaîne (J1-c) |
```

- [ ] **Step 2 : Vérifier que les 8 fichiers protégés sont intacts**

Run: `git status --short`
Expected: parmi les fichiers non indexés doivent figurer, INCHANGÉS depuis le début, les 8 fichiers protégés. Vérifier qu'aucun n'apparaît comme modifié par ce travail :

Run: `git diff --stat -- AGENTS.md CLAUDE.md crates/node/examples/dimensionner-ouverture.rs docs/POST_QUANTIQUE.md docs/STARK_STATEMENT.md docs/THREAT_MODEL.md docs/obscura-overview.html`
Expected: AUCUNE ligne (ces fichiers ne sont pas touchés par J1-c). Si l'un apparaît, ANNULER la modification accidentelle (`git checkout -- <fichier>`).

- [ ] **Step 3 : Suite complète verte**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets -- -D warnings && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo test --all-features --release
```
Expected: TOUTE la suite (crypto/net/ledger/circuit/wallet/node) verte.

- [ ] **Step 4 : Commit docs**

```bash
git add docs/TESTNET.md
git commit -m "$(cat <<'EOF'
docs(J1-c): TESTNET reflète la reconfiguration d'autorités certifiée

La liste est reconfigurable sur la même chaîne ; l'ancien quorum décide du
nouveau ; réduire à n<=3 sacrifie la tolérance aux fautes (table de liveness).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5 : Pousser et ouvrir la PR (NE PAS FUSIONNER)**

```bash
git push -u origin feat/j1c-changement-autorites
```

```bash
gh pr create --base master --head feat/j1c-changement-autorites \
  --title "J1-c — Changement d'ensemble d'autorités sur la même chaîne" \
  --body "$(cat <<'EOF'
## J1-c — dernière brique de la porte J1

Permet à l'ensemble d'autorités d'évoluer **sur la même chaîne**, certifié par le
quorum de l'**ancienne** liste, effectif à `h + K` (K = 8). Échanger, ajouter ou
retirer un membre ne refait plus la genèse.

### Ce que ça change
- **Bloc `0x05`** : champ `changement_autorites: Option<Vec<SigPublicKey>>` dans
  l'identifiant (le certificat de l'ancien comité signe donc sur la nouvelle liste).
  Encodage `0 = absent`, liste vide interdite, doublons refusés au décodage.
- **`sceller_changement`** : bloc de gouvernance VIDE de transactions, budget liste
  comprise. **Faille latente fermée** : un doublon d'autorité en genèse votait deux
  fois — désormais refusé.
- **État `0x05`** : `changement_en_attente` persisté. Helper height-aware
  `autorites_a(hauteur)` : producteur et quorum dérivent de la liste active de la
  hauteur, sans muter `self.autorites` avant le succès. Commit (bascule +
  enregistrement) à la toute fin d'`appliquer_bloc` — un bloc refusé ne mute rien.
- **Gardes** : `ChangementAvecTransactions`, `ChangementSurChaineOuverte`,
  `ChangementDejaEnAttente` (un seul en vol, back-to-back autorisé),
  `ChangementHauteurOverflow` (`checked_add`), invariants au chargement d'état.
- **Nœud** : `proposer_changement` — un bloc de reconfiguration transite par le
  chemin propose/vote/certifie de J1-b2, sans nouveau message.

### Tests
- Ledger : enregistrement, bascule à `h+K`, quorum height-aware, toutes les gardes,
  atomicité (par mutation), back-to-back, persistance + invariants, synergie vue.
- Sockets : reconfiguration certifiée par l'ancien quorum et propagée ; redémarrage
  retrouve le pendant.

### Décisions
- Plancher `n ≤ 3` laissé en **limite documentée** (cohérent avec la genèse, qui
  accepte tout `n`), pas en refus. Table de liveness dans `docs/TESTNET.md`.
- `changement_autorites` est un champ SÉPARÉ de `autorites` (genèse seule) : la règle
  `AutoritesHorsGenese` reste inchangée.

Ferme la porte J1. Le consensus est complet pour l'état cible B — reconfigurable
sans refaire la chaîne.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**S'ARRÊTER ICI.** Ne pas fusionner. Rapporter à l'utilisateur l'URL de la PR et attendre sa décision.

---

## Notes transverses pour l'exécutant

- **Le champ `autorites` (genèse) et `changement_autorites` (reconfiguration) sont DISTINCTS.** La règle `AutoritesHorsGenese` (un bloc `h>0` portant `autorites`) reste inchangée. J1-c n'introduit RIEN sur `autorites` post-genèse — il ajoute un canal séparé.
- **Ne jamais muter `self.autorites` / `self.changement_en_attente` avant le succès complet d'`appliquer_bloc`.** C'est l'erreur exacte que la revue a fermée : l'instantané d'atomicité ne clone PAS ces champs, donc les muter tôt les laisserait basculés par un bloc refusé.
- **Ordre du commit : activer d'abord, annoncer ensuite.** C'est ce qui rend le back-to-back correct.
- **Height-aware par un seul helper (`autorites_a`).** Ne pas dupliquer la logique « nouvelle liste ssi effet == hauteur » ailleurs : producteur, quorum et validation en dérivent tous.
- **Quand un nom d'API du runtime/persistance est incertain, le VÉRIFIER par `grep` avant de l'appeler.** Ne jamais inventer une méthode ; réutiliser le chemin exact qu'empruntent `sceller`/`tick`/`save`.
