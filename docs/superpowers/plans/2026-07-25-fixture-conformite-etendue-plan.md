# Plan — Fixture de conformité étendue

**Spec :** `docs/superpowers/specs/2026-07-25-fixture-conformite-etendue-design.md`
**Branche :** `atelier/testnet-local`
**Décomposition :** 2 tâches. Elles sont **séquentielles** (Task 2 documente ce que
Task 1 produit) — ne pas les paralléliser.

---

## Global Constraints

Contraintes liantes, valables pour toute tâche de ce plan.

- **Profondeur Merkle = CONSENSUS.** Utiliser `ProvedLedgerState::depuis_genese`
  (profondeur consensus 32) et `Wallet::depuis_secret(secret, CONSENSUS_DEPTH)`.
  **Ne JAMAIS** utiliser `depuis_genese_depth(…, 4)` ni `PROFONDEUR = 4` — c'est le
  raccourci de test de `quorum_sockets.rs`, inadmissible dans une fixture de
  conformité. `CONSENSUS_DEPTH` vient de `ledger::merkle::CONSENSUS_DEPTH` (= 32).
- **Valeurs EXACTES, jamais `>=`.** La fixture est figée : les assertions portent
  sur des égalités (`masque == 0x0000000000000007`, `nombre_de_votants() == 3`,
  `votants().collect::<Vec<_>>() == vec![0, 1, 2]`, `quorum_requis() == 3`).
- **Déterminisme par commit, pas par régénération.** Les octets sont figés une
  fois et le rejeu les VÉRIFIE ; il ne les régénère pas. Ne pas écrire de test qui
  appelle le générateur puis vérifie sa propre sortie.
- **Ne pas modifier** `crates/node/tests/conformite.rs` ni
  `docs/fixtures/conformite-v3/*.bin|.cle|attendu.txt`.
- **Aucun changement de format**, d'invariant, ni de code de production. Ce plan
  n'ajoute que des tests et de la documentation.
- **Commentaires et docs en français** (convention du dépôt).
- Le dépôt compile en `--release` pour les preuves STARK : les tests de rejeu
  portent `#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]`.

---

## Task 1 — Le test et les artefacts de la fixture

**Fichier à créer :** `crates/node/tests/conformite_etendue.rs`
**Artefacts à générer puis committer :** `docs/fixtures/conformite-etendue/`

### Fichiers d'artefacts attendus

```
docs/fixtures/conformite-etendue/
  autorite-0.cle  autorite-1.cle  autorite-2.cle  autorite-3.cle
  beneficiaire.wallet          # Wallet::to_bytes_secret(), état PRÉ-scan
  genese.bin                   # 4 autorités + 1 émission vers le payeur
  bloc-1.bin                   # 1 transaction confidentielle + certificat masque 0x07
  bloc-1-sous-quorum.bin       # MÊME bloc, certificat masque 0x03 (2 votes)
  attendu.txt
```

Le `README.md` de ce répertoire est **hors périmètre de Task 1** (il est écrit en
Task 2).

### `attendu.txt` — format et contenu

En-tête de convention obligatoire, puis les clés. `#` = commentaire.

```
# Identifiants et racines : HEX. Compteurs et montants : DÉCIMAL. Masque : HEX (u64).
genese_id=<hex>
racine_apres_genese=<hex>
bloc1_id=<hex>
racine_apres_bloc1=<hex>
quorum_requis=3
masque_certificat=0x0000000000000007
nombre_de_votants=3
solde_beneficiaire=300
```

Ne PAS ajouter de clé `votants=` : la liste `{0,1,2}` est la dérivation exacte du
masque et s'affirme en code.

### Fonctions du fichier de test

Helpers `racine_fixture()`, `lire(nom)`, `attendus()` **dupliqués localement**
depuis `conformite.rs` (adaptés au répertoire `conformite-etendue`) — ne pas
extraire de module partagé, ne pas modifier `conformite.rs`.

#### `generer_la_fixture_etendue` — `#[test] #[ignore]`

Lancée à la main :
`cargo test -p node --test conformite_etendue --release -- --ignored generer_la_fixture_etendue --nocapture`

1. 4 `SigKeypair::generate()` → écrire `autorite-{i}.cle` (`to_bytes_secret()`).
2. `payeur` et `beneficiaire` par `Wallet::depuis_secret(secret(graine),
   CONSENSUS_DEPTH)` (motif `secret(graine)` de `quorum_sockets.rs`).
3. **Écrire `beneficiaire.wallet` = `beneficiaire.to_bytes_secret()` ICI**, à
   l'état PRÉ-scan (aucune note) — c'est cet état que le tiers rechargera.
4. Genèse à 4 autorités avec une émission vers le payeur : reprendre le motif
   `genese_pour` de `crates/node/tests/quorum_sockets.rs` (valeur 1000,
   `ledger::proved_wallet::emission_vers`, `Bloc::genese_avec_autorites`) — mais à
   `CONSENSUS_DEPTH`. Écrire `genese.bin`.
5. `ProvedLedgerState::depuis_genese(&genese)`. Le payeur se synchronise sur la
   genèse (`wallet::synchro::MorceauHistorique::bloc_entier`, motif de
   `quorum_sockets.rs`), puis `payeur.construire(&beneficiaire.adresse(), 300, 0)`.
6. `Bloc::sceller(&genese.id(), 1, vec![tx])` ; `signer_scellement(&cles[0])` ;
   `signer_vote(i, &cles[i])` pour `i ∈ {0,1,2}`. Vérifier que le producteur
   attendu est bien l'autorité 0 via `producteur_attendu(1, 0)`. Écrire
   `bloc-1.bin`.
7. Reconstruire le MÊME bloc (mêmes scellement et transaction) mais avec
   `signer_vote` seulement pour `i ∈ {0,1}` → masque `0x03`. Écrire
   `bloc-1-sous-quorum.bin`.
8. Appliquer `bloc-1` pour relever `racine_apres_bloc1` ; synchroniser une copie du
   bénéficiaire sur genèse + bloc-1 pour relever le solde. Écrire `attendu.txt`.

Documenter en tête de fonction que les clés et le wallet publiés sont **jetables**.

#### `la_fixture_etendue_se_rejoue` — rejeu positif

Gardé par `#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]`.

1. `genese.bin` décode ; `genese.autorites.len() == 4` ;
   `genese.emissions.len() == 1` ; `hex(genese.id()) == attendu[genese_id]`.
2. `depuis_genese` → `hex(tree.root().to_bytes()) == attendu[racine_apres_genese]` ;
   `hex(etat.tete()) == attendu[genese_id]`.
3. **Cohérence clés ↔ genèse** : pour `i ∈ 0..4`, charger `autorite-{i}.cle`
   (`SigKeypair::from_bytes_secret`), dériver la publique, vérifier l'égalité avec
   `genese.autorites[i]`.
4. `bloc-1.bin` décode ; `bloc1.hauteur == 1` ; `bloc1.vue == 0` ;
   `bloc1.transactions.len() == 1` ; `bloc1.emissions.is_empty()` ;
   `bloc1.changement_autorites.is_none()` ;
   `hex(bloc1.id()) == attendu[bloc1_id]`.
5. `bloc1.verifier_scellement(producteur_attendu(1, 0))`.
6. `etat.quorum_requis() == 3` ; certificat présent ;
   `cert.masque == 0x0000000000000007` ;
   `cert.votants().collect::<Vec<_>>() == vec![0, 1, 2]` ;
   `cert.nombre_de_votants() == 3`.
7. `etat.appliquer_bloc(&bloc1)` réussit (vérifie la preuve STARK sur le chemin de
   consensus) ; `hex(etat.tete()) == attendu[bloc1_id]` ;
   `hex(etat.tree.root().to_bytes()) == attendu[racine_apres_bloc1]`.

#### `le_beneficiaire_recouvre_son_paiement` — recouvrement

Même garde `--release`.

1. `Wallet::from_bytes_secret(&lire("beneficiaire.wallet"))`.
2. Le synchroniser sur genèse (h=0) puis bloc-1 (h=1), **dans cet ordre**, via des
   `MorceauHistorique` construits depuis les `.bin` publiés (motif de
   `quorum_sockets.rs` pour la genèse ; les sorties du bloc 1 viennent de ses
   transactions).
3. `beneficiaire.solde() == attendu[solde_beneficiaire].parse::<u64>()` (= 300).

#### `un_quorum_de_deux_est_refuse` — négatif

Même garde `--release`.

1. État FRAIS depuis `genese.bin`.
2. `bloc-1-sous-quorum.bin` décode ; `hex(bloc.id()) == attendu[bloc1_id]` (même
   id que le bloc plein — le certificat n'entre pas dans l'`id`) ;
   `cert.masque == 0x03` ; `cert.nombre_de_votants() == 2`.
3. `etat.appliquer_bloc(&sous_quorum)` renvoie
   `Err(BlocRefus::QuorumInsuffisant { obtenu: 2, requis: 3 })` — vérifier la
   variante ET les deux champs (adapter au nom réel du type d'erreur, défini dans
   `crates/ledger/src/proved_state.rs`).

### Vérification exigée avant de rendre

```
cargo test -p node --test conformite_etendue --release
```
Les trois tests de rejeu passent. Reporter la sortie réelle.
Vérifier aussi que `cargo test -p node --test conformite` (v3) passe toujours.

### Critère de complétion

Le fichier de test existe, les artefacts sont générés ET committés, les trois
rejeux passent en `--release` depuis les seuls fichiers du répertoire de fixture.

---

## Task 2 — Documentation

Dépend de Task 1 (les commandes et le comportement doivent être ceux qui marchent).

1. **Créer `docs/fixtures/conformite-etendue/README.md`** — sur le modèle de
   `docs/fixtures/conformite-v3/README.md` : ce que la fixture prouve (quorum
   `n=4` à 3 votants exacts, transaction confidentielle à preuve STARK vérifiée,
   recouvrement du paiement par le bénéficiaire, refus à 2 votes), la commande de
   rejeu, le fait qu'elle est **ignorée en debug et exécutée en `--release`**, la
   convention de types d'`attendu.txt`, le caractère **jetable** des clés
   d'autorité ET du wallet bénéficiaire publié (il donne l'autorité de dépense sur
   des fonds sans aucune valeur, sur une chaîne jetable), et la relation avec v3 +
   le versioning de format (un bump de format casse les DEUX fixtures, qui sont
   re-datées, jamais écrasées).

2. **`docs/CONFORMITE.md` §2** — dire que `conformite-v3` reste le contrôle minimal
   (rapide, sans `--release`) et que `conformite-etendue` ferme les deux réserves.
   Remplacer la phrase « **Ne couvre aucune transaction ni preuve STARK**, et son
   quorum n'a qu'**un seul votant** » par un énoncé exact qui distingue les deux
   fixtures, avec la commande de rejeu de la nouvelle.

3. **`docs/CONFORMITE.md` §5 (« Ce qui n'est pas démontré »)** — la puce « La
   fixture de consensus ne couvre aucune transaction (§2), ni un quorum à
   plusieurs votants » est désormais **fausse** : la corriger ou la retirer. §5
   doit rester exact.

4. **`docs/fixtures/conformite-v3/README.md`** — ajouter un renvoi vers
   `conformite-etendue` pour la couverture profonde, en gardant v3 décrite comme le
   smoke-check minimal sans `--release`.

### Contraintes

- Ne pas toucher aux artefacts binaires de v3.
- Ne rien affirmer que Task 1 n'a pas réellement produit — vérifier les noms de
  fichiers et la commande de rejeu contre le dépôt.
- `THREAT_MODEL.md`, `ARCHITECTURE.md`, `PROTOCOL.md`, `CLAUDE.md`, `AGENTS.md`
  ne changent PAS.

### Critère de complétion

Les quatre points sont faits ; aucune affirmation de `CONFORMITE.md` §2 ou §5 n'est
contredite par le dépôt.
