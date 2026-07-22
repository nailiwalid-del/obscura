# J1-b1 — Votes sur le fil et assemblage du certificat

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Faire circuler les votes pour qu'une chaîne à `n ≥ 4` autorités produise
à nouveau des blocs — la régression assumée de J1-a.

**Architecture:** Deux messages nouveaux. Le producteur du tour diffuse une
**proposition** (un bloc sans certificat) ; chaque autorité vérifie, **persiste
son vote**, puis l'envoie ; le producteur assemble `2f+1` votes en certificat et
rediffuse le bloc **certifié**, qui s'applique par le chemin normal. Aucun délai,
aucun changement de vue : c'est J1-b2.

**Tech Stack:** Rust 1.87, aucune dépendance nouvelle.

**Références :** ADR `2026-07-22-j1-consensus-adr.md`, points 1 à 5.

## Global Constraints

- **Code et commentaires en français.**
- **Aucune dépendance ajoutée.**
- **Le vote est PERSISTÉ avant d'être émis.** Jamais l'inverse. C'est la seule
  chose qui empêche un nœud redémarré de voter deux fois différemment à la même
  `(hauteur, vue)` — et donc la seule chose qui rende l'absence de réorganisation
  tenable.
- **Décodage borné avant allocation**, comme tout le protocole applicatif.
- **La CI se rejoue localement avec ses commandes exactes**, y compris
  `cargo clippy --workspace --all-targets --release -- -D warnings` (passe **par
  défaut**, celle qui garde la surface de consensus).
- **`git add` nomme les fichiers.** Jamais `-A` : l'arbre de travail peut contenir
  du travail en cours qui n'est pas le nôtre.

## File Structure

| Fichier | Rôle |
|---|---|
| `crates/node/src/message.rs` | `Vote`, `Message::{Proposition, Vote}`, tags 8 et 9 |
| `crates/node/src/votes.rs` | **nouveau** — registre monotone des votes émis |
| `crates/node/src/persistance.rs` | `votes.bin` : charger / enregistrer |
| `crates/node/src/orchestration.rs` | `sur_proposition`, `sur_vote`, `proposer` |
| `crates/node/tests/quorum_sockets.rs` | **nouveau** — 4 autorités sur vraies sockets |

**Hors périmètre, et c'est écrit dans le plan pour ne pas l'oublier :** délais,
changement de vue, embargo, détection d'équivocation. Après J1-b1, **une autorité
absente fige encore la chaîne** — la liveness reste ouverte jusqu'à J1-b2.

---

### Task 1: le type `Vote` et les deux messages

**Files:**
- Modify: `crates/node/src/message.rs`

**Interfaces:**
- Produces :
  ```rust
  pub struct Vote { pub id: [u8; 64], pub index: u16, pub signature: HybridSignature }
  Message::Proposition(Box<Bloc>)   // tag 8
  Message::Vote(Box<Vote>)          // tag 9
  ```

**Pourquoi le vote ne porte NI hauteur NI vue.** L'identifiant du bloc les engage
déjà — les deux entrent dans `corps_bytes`. Les répéter créerait un champ qui
peut MENTIR par rapport à l'`id`, donc une divergence à arbitrer, pour zéro
information nouvelle. Le vote ne dit que : « l'autorité `index` a signé ce
bloc-là ».

**Pourquoi l'index est porté.** Sans lui, le collecteur devrait essayer la
signature contre chacune des `n` autorités — jusqu'à 64 vérifications hybrides
pour attribuer UN vote. Avec l'index, c'en est une.

- [ ] **Step 1: Écrire les tests qui échouent**

```rust
    #[test]
    fn aller_retour_proposition_et_vote() {
        let genese = ledger::bloc::Bloc::genese();
        let bloc = ledger::bloc::Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        let m = Message::Proposition(Box::new(bloc));
        let relu = Message::from_bytes(&m.to_bytes()).expect("proposition décodable");
        assert!(matches!(relu, Message::Proposition(_)));

        let k = crypto::sig::SigKeypair::generate();
        let id = [7u8; 64];
        let v = Vote {
            id,
            index: 3,
            signature: k.sign(ledger::bloc::DOMAINE_VOTE, &id),
        };
        let m = Message::Vote(Box::new(v));
        match Message::from_bytes(&m.to_bytes()).expect("vote décodable") {
            Message::Vote(v) => {
                assert_eq!(v.id, id);
                assert_eq!(v.index, 3);
            }
            _ => panic!("Vote attendu"),
        }
    }

    /// Un vote tronqué, ou à signature hors bornes, ne panique jamais.
    #[test]
    fn votes_malformes_sans_panique() {
        assert!(Message::from_bytes(&[TAG_VOTE]).is_err());
        assert!(Message::from_bytes(&[TAG_VOTE; 3]).is_err());
        let mut b = vec![TAG_VOTE];
        b.extend_from_slice(&[0u8; 64]); // id
        b.extend_from_slice(&0u16.to_le_bytes()); // index
        b.extend_from_slice(&u32::MAX.to_le_bytes()); // longueur délirante
        assert!(Message::from_bytes(&b).is_err());
    }

    /// Une proposition PORTANT un certificat est refusée au décodage : une
    /// proposition est par définition ce qui n'est pas encore certifié, et
    /// accepter les deux formes donnerait deux encodages du même objet.
    #[test]
    fn proposition_certifiee_refusee() {
        let genese = ledger::bloc::Bloc::genese();
        let mut bloc = ledger::bloc::Bloc::sceller(&genese.id(), 1, Vec::new()).unwrap();
        bloc.signer_vote(0, &crypto::sig::SigKeypair::generate());
        let octets = Message::Proposition(Box::new(bloc)).to_bytes();
        assert!(matches!(
            Message::from_bytes(&octets),
            Err(MessageError::PropositionCertifiee)
        ));
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec**

Run: `cargo test -p node --lib message`
Expected: échec de compilation (`Vote`, `TAG_VOTE`, variantes inexistantes).

- [ ] **Step 3: Implémenter**

```rust
const TAG_PROPOSITION: u8 = 8;
const TAG_VOTE: u8 = 9;

/// Majorant du vote sur le fil : id + index + signature longueur-préfixée.
const TAILLE_VOTE_MAX: usize = 64 + 2 + 4 + ledger::bloc::TAILLE_SCELLEMENT_MAX;

/// Le VOTE d'une autorité pour un bloc donné (ADR J1).
///
/// Ne porte ni hauteur ni vue : l'identifiant les engage déjà (les deux entrent
/// dans le corps du bloc). Les répéter créerait un champ capable de MENTIR par
/// rapport à l'`id`, donc une divergence à arbitrer, pour zéro information.
pub struct Vote {
    /// Identifiant du bloc voté. C'est lui qui est signé.
    pub id: [u8; 64],
    /// Index de l'autorité dans la liste gravée en genèse.
    ///
    /// Porté pour que le collecteur n'ait qu'UNE vérification à faire : sans lui,
    /// il devrait essayer la signature contre chacune des `n` autorités.
    pub index: u16,
    pub signature: crypto::sig::HybridSignature,
}
```

Encodage : `TAG_VOTE ‖ id(64) ‖ index LE(2) ‖ len LE(4) ‖ signature`.
Décodage : longueur bornée par `TAILLE_SCELLEMENT_MAX` **avant** la lecture,
octets résiduels refusés.

`Message::Proposition` réutilise l'encodage de `Message::Bloc`, avec **un contrôle
supplémentaire au décodage** :

```rust
            TAG_PROPOSITION => {
                let bloc = ledger::bloc::Bloc::from_bytes(reste)
                    .map_err(MessageError::BlocInvalide)?;
                // Une proposition est par définition NON certifiée. Accepter les
                // deux formes donnerait deux encodages du même objet, et le
                // collecteur ne saurait pas s'il doit voter ou appliquer.
                if bloc.certificat.is_some() {
                    return Err(MessageError::PropositionCertifiee);
                }
                Ok(Message::Proposition(Box::new(bloc)))
            }
```

Ajouter `MessageError::PropositionCertifiee`, et **inclure les deux nouveaux tags
dans `version_inconnue()`** — un pair d'ancienne version qui les ignore ne doit
pas être pénalisé.

- [ ] **Step 4: Lancer, vérifier le succès** — `cargo test -p node --lib message`

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/message.rs
git commit -m "protocole(J1-b1): Vote, Proposition — deux messages, zéro champ redondant

Le vote ne porte ni hauteur ni vue : l'identifiant du bloc les engage déjà.
Les répéter créerait un champ capable de mentir par rapport à l'id, donc une
divergence à arbitrer, pour zéro information nouvelle.

L'index de l'autorité, lui, EST porté : sans lui le collecteur devrait
essayer la signature contre chacune des n autorités — jusqu'à 64
vérifications hybrides pour attribuer un seul vote.

Une proposition PORTANT un certificat est refusée au décodage : accepter les
deux formes donnerait deux encodages du même objet, et le receveur ne
saurait pas s'il doit voter ou appliquer."
```

---

### Task 2: le registre de votes, persisté et monotone

**Files:**
- Create: `crates/node/src/votes.rs`
- Modify: `crates/node/src/lib.rs`, `crates/node/src/persistance.rs`

**Interfaces:**
- Produces :
  ```rust
  pub struct RegistreVotes { hauteur: u64, vue: u32, id: [u8; 64] }
  impl RegistreVotes {
      pub fn neuf() -> Self
      pub fn peut_voter(&self, hauteur: u64, vue: u32, id: &[u8; 64]) -> bool
      pub fn enregistrer(&mut self, hauteur: u64, vue: u32, id: [u8; 64])
      pub fn to_bytes(&self) -> Vec<u8>
      pub fn from_bytes(b: &[u8]) -> Result<Self, VoteDecodeError>
  }
  ```

**La règle, et pourquoi elle tient en trois champs.** Un nœud vote si
`(hauteur, vue)` est **strictement supérieur** au dernier vote émis, ou si c'est
exactement le même couple **et le même bloc** (re-voter pour le même bloc est
idempotent, donc sans danger — et c'est nécessaire, un vote peut se perdre).

Le registre est donc **monotone** et tient en O(1) : pas d'historique à élaguer,
pas de fichier qui croît. Même forme qu'une frontier — on ne garde que ce qui
interdit de revenir en arrière.

⚠️ **C'est la règle de sûreté du protocole.** Sans elle, deux blocs différents
peuvent atteindre `2f+1` à la même hauteur, et la divergence est **définitive**
sur un ledger append-only.

- [ ] **Step 1: Écrire les tests qui échouent**

```rust
    #[test]
    fn un_seul_vote_par_hauteur_et_vue() {
        let mut r = RegistreVotes::neuf();
        assert!(r.peut_voter(1, 0, &[1u8; 64]));
        r.enregistrer(1, 0, [1u8; 64]);

        // Même (h, vue), MÊME bloc : re-voter est idempotent et sans danger.
        assert!(r.peut_voter(1, 0, &[1u8; 64]));
        // Même (h, vue), AUTRE bloc : c'est l'équivocation. Refusé.
        assert!(!r.peut_voter(1, 0, &[2u8; 64]));
        // Vue suivante : autorisé.
        assert!(r.peut_voter(1, 1, &[2u8; 64]));
        // Hauteur suivante : autorisé.
        assert!(r.peut_voter(2, 0, &[3u8; 64]));
        // RETOUR EN ARRIÈRE : refusé, même pour un bloc inconnu.
        r.enregistrer(2, 0, [3u8; 64]);
        assert!(!r.peut_voter(1, 5, &[9u8; 64]));
    }

    /// Le registre SURVIT au redémarrage — sans quoi un nœud relancé revote.
    #[test]
    fn le_registre_survit_a_laller_retour() {
        let mut r = RegistreVotes::neuf();
        r.enregistrer(7, 2, [4u8; 64]);
        let relu = RegistreVotes::from_bytes(&r.to_bytes()).expect("relisible");
        assert!(!relu.peut_voter(7, 2, &[5u8; 64]), "l'interdit doit survivre");
        assert!(relu.peut_voter(7, 3, &[5u8; 64]));
    }

    #[test]
    fn registre_malforme_refuse_sans_panique() {
        assert!(RegistreVotes::from_bytes(&[]).is_err());
        assert!(RegistreVotes::from_bytes(&[0u8; 10]).is_err());
    }
```

- [ ] **Step 2: Lancer, vérifier l'échec** — `cargo test -p node --lib votes`

- [ ] **Step 3: Implémenter** `votes.rs`, avec une version d'octet en tête
(`VERSION_VOTES = 0x01`) et le refus nommé des versions inconnues, comme partout
ailleurs dans le dépôt.

- [ ] **Step 4: Persistance**

Dans `persistance.rs`, sur le modèle exact de `charger_ou_creer_identite` :

```rust
    /// Charge le registre de votes, ou en crée un VIERGE.
    ///
    /// ⚠️ Un registre illisible n'est JAMAIS remplacé par un registre vierge : ce
    /// serait autoriser l'équivocation exactement quand on ne sait plus ce qu'on a
    /// promis. Échec franc, le nœud refuse de démarrer — même discipline que
    /// « un fichier de wallet illisible ne doit jamais devenir un wallet vide ».
    pub fn charger_ou_creer_votes(&self) -> Result<RegistreVotes, PersistanceError>

    /// Écrit le registre, ATOMIQUEMENT et avec `sync_all`.
    ///
    /// Appelé AVANT l'émission du vote. L'ordre est la garantie : si la machine
    /// tombe entre l'écriture et l'envoi, on a promis sans le dire — inoffensif.
    /// Dans l'autre ordre, on aurait dit sans l'avoir promis — et au redémarrage
    /// on pourrait promettre autre chose.
    pub fn enregistrer_votes(&self, r: &RegistreVotes) -> Result<(), PersistanceError>
```

- [ ] **Step 5: Commit**

```bash
git add crates/node/src/votes.rs crates/node/src/lib.rs crates/node/src/persistance.rs
git commit -m "consensus(J1-b1): registre de votes monotone et PERSISTÉ

La règle de sûreté du protocole : un nœud ne vote qu'une fois par
(hauteur, vue). Sans elle, deux blocs différents peuvent atteindre 2f+1 à la
même hauteur — et sur un ledger append-only, la divergence est DÉFINITIVE.

Persisté, parce qu'un registre en mémoire seule laisserait un nœud REDÉMARRÉ
voter une seconde fois pour un autre bloc. Écrit AVANT l'émission : si la
machine tombe entre les deux, on a promis sans le dire (inoffensif) plutôt
que dit sans avoir promis (dangereux).

Monotone, donc O(1) : trois champs, pas d'historique à élaguer. Re-voter
pour le MÊME bloc reste autorisé — c'est idempotent, et nécessaire puisqu'un
vote peut se perdre.

Un registre illisible n'est jamais remplacé par un registre vierge : ce
serait autoriser l'équivocation exactement quand on ne sait plus ce qu'on a
promis."
```

---

### Task 3: proposer, voter, assembler

**Files:**
- Modify: `crates/node/src/orchestration.rs`

**Interfaces:**
- Consumes : `Message::{Proposition, Vote}`, `RegistreVotes`.
- Produces : `Noeud::proposer()`, `sur_proposition`, `sur_vote`, et le champ
  `votes_recus: BTreeMap<[u8; 64], BTreeMap<u16, HybridSignature>>`.

**Le flux, en trois temps.**

1. `proposer()` remplace l'ancien `sceller()` sur une chaîne à autorités : le
   producteur du tour construit le bloc, le scelle, **vote pour lui-même**, et
   diffuse une `Proposition`. Il ne l'applique PAS — il n'a pas le quorum.
2. `sur_proposition` : vérifier que l'émetteur est le producteur légitime de
   `(hauteur, vue)`, que le bloc s'enchaîne, **puis** consulter le registre. Si
   le vote est permis : persister, puis répondre `Message::Vote`.
3. `sur_vote` : vérifier la signature contre `autorites[index]`, accumuler ; au
   quorum, assembler le certificat et diffuser le bloc **certifié**, qui
   s'applique alors par le chemin normal chez tout le monde.

⚠️ **Ordre de vérification dans `sur_proposition`** : les contrôles O(1)
(producteur légitime, chaînage, hauteur) précèdent la consultation du registre,
qui précède l'écriture disque. Vérifier les preuves STARK d'une proposition est
**hors de question** avant d'avoir voté — ce serait offrir `~4 ms × n_tx` à
quiconque envoie une proposition. Le vote n'engage que l'identifiant ; la validité
des transactions est vérifiée à l'application du bloc certifié, comme aujourd'hui.

> **Conséquence assumée, à écrire dans le code :** on vote pour un bloc dont on
> n'a pas vérifié les transactions. C'est correct — le certificat prouve l'accord
> sur *quel* bloc, pas sur sa validité, et un bloc invalide sera refusé par tous à
> l'application. Un producteur qui en propose un gaspille son tour et rien d'autre.

- [ ] **Step 1: Écrire les tests qui échouent**

```rust
    /// Un pair qui n'est PAS le producteur du tour : pas de vote.
    #[test]
    fn proposition_dun_imposteur_ne_recoit_pas_de_vote()

    /// Le producteur légitime reçoit notre vote, et le registre l'a mémorisé.
    #[test]
    fn proposition_legitime_recoit_un_vote()

    /// Deux propositions DIFFÉRENTES à la même (hauteur, vue) : la seconde ne
    /// reçoit PAS de vote. C'est la règle de sûreté, vue depuis l'orchestration.
    #[test]
    fn seconde_proposition_a_la_meme_hauteur_sans_vote()

    /// Le collecteur assemble au quorum et diffuse un bloc CERTIFIÉ.
    #[test]
    fn au_quorum_le_bloc_certifie_est_diffuse()

    /// Un vote dont la signature ne correspond pas à `autorites[index]` est
    /// ignoré ET pénalisé : c'est du travail de vérification imposé pour rien.
    #[test]
    fn vote_invalide_penalise()
```

- [ ] **Step 2: Lancer, vérifier l'échec**

- [ ] **Step 3: Implémenter**, en respectant l'ordre de coût ci-dessus.

- [ ] **Step 4: Lancer** — `cargo test -p node --release`

- [ ] **Step 5: Commit**

---

### Task 4: quatre autorités sur de vraies sockets

**Files:**
- Create: `crates/node/tests/quorum_sockets.rs`

**Pourquoi sur sockets et pas en orchestration pure.** Les tests de la tâche 3
prouvent la LOGIQUE. Celui-ci prouve que le protocole tient sur le vrai
transport : cadrage, chiffrement, threads de lecture et d'écriture découplés.
C'est la discipline du dépôt depuis `finalite.rs` — « un message qui voyage ne
prouve rien », ce sont les **racines identiques** qui prouvent.

- [ ] **Step 1: Écrire le test qui échoue**

Quatre nœuds sur des sockets réelles, genèse à quatre autorités (`f = 1`,
quorum 3). Le producteur du tour propose ; les trois autres votent ; le bloc
certifié se diffuse.

**Assertions** : les quatre nœuds finissent à la **même hauteur**, la **même
tête** et la **même racine** ; le bloc appliqué porte un certificat d'au moins
3 votants **distincts**.

- [ ] **Step 2–4:** échec, implémentation, succès.

- [ ] **Step 5: Commit**

---

### Task 5: le redémarrage ne fait pas revoter

**Files:**
- Modify: `crates/node/tests/chaos_producteur.rs`

**C'est le test qui justifie la persistance**, et il prolonge exactement le
scénario de chaos existant.

- [ ] **Step 1: Écrire le test qui échoue**

```rust
/// SÛRETÉ APRÈS REDÉMARRAGE : un nœud qui a voté, puis redémarre, ne vote pas
/// pour un AUTRE bloc à la même (hauteur, vue).
///
/// Sans registre persisté, ce test échoue — et l'échec réel serait une chaîne
/// divergente, définitive sur un ledger append-only.
#[test]
fn le_redemarrage_ne_fait_pas_revoter() {
    // 1. Le nœud vote pour le bloc A à (1, 0). Le registre est persisté.
    // 2. On le détruit et on le recharge depuis le MÊME répertoire.
    // 3. Une proposition pour un bloc B ≠ A à (1, 0) ne reçoit AUCUN vote.
    // 4. Une proposition pour A à (1, 0) reçoit encore un vote (idempotence).
}
```

- [ ] **Step 2: Vérifier que le test ÉCHOUE si l'on supprime `votes.bin`** entre
      l'arrêt et le redémarrage — c'est la mutation qui prouve que le test porte.

- [ ] **Step 3–4:** succès, puis suite complète.

- [ ] **Step 5: Commit**

---

## Critère de sortie de J1-b1

- Une chaîne à **4 autorités produit des blocs** sur de vraies sockets, et les
  quatre nœuds convergent vers la même racine.
- Un bloc appliqué porte `≥ 2f+1` votants distincts.
- Un nœud ne vote **jamais** deux fois différemment à la même `(hauteur, vue)`,
  **redémarrage compris** — vérifié par mutation.
- Une proposition certifiée est refusée au décodage.
- CI verte avec ses commandes exactes, passe **par défaut** comprise.

**Ce que J1-b1 ne fait PAS** : aucun délai, aucun changement de vue. **Une
autorité absente fige encore la chaîne** — la liveness reste ouverte jusqu'à
J1-b2, et le dire évite de croire la porte D close.
