# Design — Fixture de conformité étendue (quorum multi-votant + transaction STARK + recouvrement)

**Date :** 2026-07-25
**Statut :** design révisé après revue (10 points), prêt pour le plan d'implémentation.
**Objet :** ajouter un **artefact rejouable par un tiers** qui ferme les deux
réserves nommées par `docs/CONFORMITE.md` §2 **et** §5 — « aucune transaction ni
preuve STARK » et « quorum à un seul votant » — et qui démontre en outre le
**recouvrement d'un paiement confidentiel** par son destinataire, sans toucher au
format ni à la fixture `conformite-v3` existante.
**Portée :** ce document conçoit une fixture de test et ses mises à jour
documentaires. Il ne change **aucun** format de consensus, aucun invariant, aucune
règle. Il n'ajoute que de la **couverture de vérification tierce**.

---

## Contexte, vérifié dans le code (2026-07-25)

1. **La fixture de conformité est l'artefact déterministe rejouable.**
   `crates/node/tests/conformite.rs` + `docs/fixtures/conformite-v3/` : genèse +
   bloc-1 + hachages attendus, versionnés. Délibérément `n=1`, sans transaction ni
   STARK, pour rester petite, rapide, testable **sans `--release`**.

2. **Le consensus multi-votant AVEC transaction STARK est déjà testé — mais pas
   comme artefact rejouable.** `crates/node/tests/quorum_sockets.rs` prouve
   `n=4, f=1, quorum 3` avec une transaction confidentielle sur sockets vivantes,
   à clés **aléatoires** : il valide le comportement, ne produit aucun fichier
   qu'un tiers rejoue depuis `docs/`.

3. **La lacune est donc de porter le quorum multi-votant et la transaction
   confidentielle dans l'artefact statique** que lit un auditeur — pas de
   ré-implémenter un consensus déjà couvert.

### Faits d'API confirmés (déterminent le design)

- `CONSENSUS_DEPTH = 32` (`crates/ledger/src/merkle.rs:13`) ; `depuis_genese`
  amorce à cette profondeur (`MerkleFrontier::consensus()`). La fixture N'UTILISE
  PAS `depuis_genese_depth(…, 4)`, réservé aux tests rapides.
- `Bloc` expose publiquement `parent, hauteur, vue, transactions: Vec<ProvedTx>,
  emissions: Vec<Emission>, autorites: Vec<SigPublicKey>, changement_autorites:
  Option<…>, certificat: Option<Certificat>`.
- `Certificat` expose `pub masque: u64` ; `votants()` et `nombre_de_votants()` en
  dérivent. Le **certificat n'entre pas dans l'`id`** du bloc.
- `quorum_requis()` = `quorum_pour(n)` ; pour `n=4`, vaut `3` (`⌊2·4/3⌋+1`).
- `appliquer_bloc` refuse un quorum trop faible par
  `QuorumInsuffisant { obtenu, requis }`.
- **`Wallet::depuis_secret` tire la clé KEM de réception d'`OsRng`**
  (`crates/wallet/src/lib.rs:177`, `reception: KemKeypair::generate()`) :
  l'adresse n'est donc **pas** déterministe à partir du seul secret. Un tiers ne
  peut recouvrer un paiement que si le matériel wallet est publié.
- `Wallet::to_bytes_secret()` / `from_bytes_secret()` sérialisent le wallet en
  clair, clés comprises, **sans Protection** — ce qui permet de publier un wallet
  bénéficiaire jetable. `solde()`, `notes()`, `scanner()`, `synchroniser()`
  existent.

---

## Décision

**Ajouter une fixture `conformite-etendue`, à côté de `conformite-v3` (intacte),
qui démontre en un rejeu :**

1. une **genèse à 4 autorités** portant une émission confidentielle vers un
   wallet payeur ;
2. un **bloc-1 contenant une transaction confidentielle** (payeur → bénéficiaire,
   300 sur 1000, frais 0), dont la **preuve STARK est vérifiée** au rejeu, sur le
   chemin de consensus réel (`appliquer_bloc`) ;
3. ce bloc-1 **certifié par un quorum de 3 votants distincts** (indices 0, 1, 2 ;
   `masque = 0x0000000000000007`) ;
4. l'avancée de la racine d'état **exactement** comme publié ;
5. le **recouvrement du paiement** : le bénéficiaire, rechargé depuis son matériel
   wallet **jetable publié**, synchronise sur les blocs et retrouve `solde == 300`;
6. la **morsure de la frontière de quorum** : le même bloc réduit à 2 votes est
   **refusé** par `QuorumInsuffisant { obtenu: 2, requis: 3 }`.

La fixture est **ignorée en debug et exécutée en `--release`** (génération et
vérification de preuve STARK), via l'idiome déjà en place :
`#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]`.

### Pourquoi une nouvelle fixture plutôt que remplacer v3

| | `conformite-v3` | `conformite-etendue` |
|---|---|---|
| Rôle | smoke-check permanent | preuve profonde tierce |
| Autorités | 1 (`n=1`, quorum 1) | 4 (`n=4`, quorum 3) |
| Transaction | aucune | 1 transfert confidentiel + recouvrement |
| Preuve STARK | aucune | vérifiée au rejeu |
| Debug (`cargo test`) | s'exécute | **ignorée** |
| `--release` | s'exécute aussi | **requis** |

Remplacer v3 forcerait `--release` pour tout contrôle de conformité et perdrait le
smoke-check debug. Deux artefacts, deux rôles.

### Pourquoi `conformite-etendue` et non `conformite-v4`

Les numéros de version tracent les **bumps de format de bloc** (v1→v2 : `0x04` ;
v2→v3 : `0x05`), pas les ajouts de couverture. La fixture étendue est au **même
format `0x05`**. Si le format bumpe plus tard, **les deux** fixtures cassent
ensemble (par construction, comme v1/v2/v3) et sont re-datées, jamais écrasées — le
README le dira.

---

## Architecture

### Fichiers de la fixture

Nouveau répertoire `docs/fixtures/conformite-etendue/` :

```
docs/fixtures/conformite-etendue/
  autorite-0.cle … autorite-3.cle   # 4 clés d'autorité JETABLES, publiées
  beneficiaire.wallet               # matériel wallet JETABLE (to_bytes_secret), état PRÉ-scan
  genese.bin                        # 4 autorités + émission vers le payeur
  bloc-1.bin                        # transaction confidentielle + certificat 3 votants (masque 0x07)
  bloc-1-sous-quorum.bin            # MÊME bloc, certificat réduit à 2 votes (masque 0x03)
  attendu.txt                       # valeurs attendues (format ci-dessous)
  README.md                         # rôle, rejeu, --release, clés/wallet jetables, relation v3
```

Les clés d'autorité **et** le wallet bénéficiaire sont **jetables et publiés** :
ils n'existent que pour rendre l'artefact reproductible et rejouable, et ne servent
nulle part ailleurs. Le README le dira mot pour mot (le wallet publié donne
l'autorité de dépense sur des fonds sans aucune valeur, sur une chaîne jetable).

`bloc-1-sous-quorum.bin` partage le **même `bloc1_id`** que `bloc-1.bin` (le
certificat n'entre pas dans l'`id`) : le test négatif le vérifie, ce qui démontre
au passage cette propriété.

### `attendu.txt`

Format `clé=valeur`, `#` en commentaire (parseur de `conformite.rs`). **Convention
de type explicite**, écrite en tête du fichier :

```
# Identifiants et racines : HEX. Compteurs et montants : DÉCIMAL. Masque : HEX (u64).
genese_id=<hex, 32 o>
racine_apres_genese=<hex>
bloc1_id=<hex>
racine_apres_bloc1=<hex>
quorum_requis=3
masque_certificat=0x0000000000000007
nombre_de_votants=3
solde_beneficiaire=300
```

La liste `votants = {0,1,2}` n'est pas dupliquée dans `attendu.txt` (elle est
l'exacte dérivation de `masque_certificat`) : le test l'affirme directement en
code (`cert.votants().collect::<Vec<_>>() == vec![0, 1, 2]`).

### Fichiers de test

Nouveau `crates/node/tests/conformite_etendue.rs`, calqué sur `conformite.rs`.
Les helpers `attendus()`/`lire()`/`racine_fixture()` sont **dupliqués localement**
(adaptés au répertoire `conformite-etendue`), pas extraits dans un module partagé :
ils sont courts et `conformite.rs` reste auto-suffisant — cohérent avec le style du
dépôt. Fonctions :

- `la_fixture_etendue_se_rejoue` — le rejeu tiers (positif).
- `le_beneficiaire_recouvre_son_paiement` — le scan/solde.
- `un_quorum_de_deux_est_refuse` — le test négatif.
- `generer_la_fixture_etendue` (`#[ignore]`) — régénère les artefacts à la main.

Les trois premières portent
`#[cfg_attr(debug_assertions, ignore = "preuves gardées par --release")]`.

---

## Générateur (`generer_la_fixture_etendue`)

Assemble tout **sans sockets** (assemblage direct du certificat) :

1. Générer 4 clés `cles[0..4]` ; écrire `autorite-i.cle`
   (`SigKeypair::to_bytes_secret`).
2. Wallets payeur et bénéficiaire par `Wallet::depuis_secret(secret(graine),
   CONSENSUS_DEPTH)` — profondeur **consensus (32)**, pas 4.
3. **Écrire `beneficiaire.wallet` = `beneficiaire.to_bytes_secret()` dès ici**,
   à l'état PRÉ-scan (aucune note, arbre vide profondeur 32) : c'est cet état que
   le tiers rechargera pour scanner lui-même.
4. Genèse à 4 autorités portant une émission vers le payeur (motif `genese_pour`
   de `quorum_sockets.rs`) ; écrire `genese.bin`.
5. Amorcer l'état par `depuis_genese` (profondeur consensus) ; le payeur
   synchronise sur la genèse, puis `construire(&beneficiaire.adresse(), 300, 0)`
   → `tx`.
6. `Bloc::sceller(&genese.id(), 1, vec![tx])` ;
   `signer_scellement(&cles[0])` (producteur du tour = `autorites[0]`, à confirmer
   par `producteur_attendu(1, 0)`) ; `signer_vote(i, &cles[i])` pour
   `i ∈ {0,1,2}` → certificat `masque = 0x07`. Écrire `bloc-1.bin`.
7. Reconstruire un second bloc identique mais avec seulement
   `signer_vote(i, …)` pour `i ∈ {0,1}` → certificat `masque = 0x03`. Écrire
   `bloc-1-sous-quorum.bin`.
8. Appliquer `bloc-1` sur une copie ; relever les racines. Synchroniser une copie
   du bénéficiaire sur genèse + bloc-1 pour relever `solde_beneficiaire` (sanity).
   Écrire `attendu.txt`.

**Déterminisme par commit, pas par régénération.** Les octets sont figés une fois
et le rejeu les *vérifie* ; il ne les régénère pas. Signatures hedgées et tailles
de preuve STARK variables (« une taille de preuve se lit comme une bande ») ne
cassent donc rien : c'est le contrat déjà tenu par v3. Re-lancer le générateur
produit un artefact **différent mais valide** ; seuls les octets commités font foi.

---

## Ce que le rejeu affirme

### `la_fixture_etendue_se_rejoue` (positif)

Assertions **structurelles explicites** d'abord, puis **valeurs exactes** :

1. `genese.bin` décode ; `genese.autorites.len() == 4` ;
   `genese.emissions.len() == 1` ; `genese.id() == attendu[genese_id]`.
2. Amorçage par `depuis_genese` → `tree.root() == attendu[racine_apres_genese]` ;
   tête == genèse.
3. **Clés publiées ↔ genèse** : pour `i ∈ 0..4`, charger `autorite-i.cle`, dériver
   la clé publique, vérifier `== genese.autorites[i]`. L'artefact est ainsi
   auto-cohérent.
4. `bloc-1.bin` décode ; `bloc1.hauteur == 1` ; `bloc1.vue == 0` ;
   `bloc1.transactions.len() == 1` ; `bloc1.emissions.is_empty()` ;
   `bloc1.changement_autorites.is_none()` ; `bloc1.id() == attendu[bloc1_id]`.
5. Scellement vérifié contre `producteur_attendu(1, 0)`.
6. Quorum, valeurs **exactes** : `etat.quorum_requis() == 3` ; le certificat
   existe ; `cert.masque == 0x0000000000000007` ;
   `cert.votants().collect::<Vec<_>>() == vec![0, 1, 2]` ;
   `cert.nombre_de_votants() == 3`.
7. `etat.appliquer_bloc(&bloc1)` réussit — **ce qui vérifie la preuve STARK de la
   transaction sur le chemin de consensus** — et fait avancer tête + racine vers
   `bloc1_id` / `racine_apres_bloc1` publiés.

### `le_beneficiaire_recouvre_son_paiement` (recouvrement, point 4→b)

1. Charger le bénéficiaire par `Wallet::from_bytes_secret(lire("beneficiaire.wallet"))`
   — état pré-scan.
2. Le synchroniser sur genèse (h=0) puis bloc-1 (h=1), dans l'ordre, via
   `MorceauHistorique` construits à partir des `.bin` publiés.
3. Affirmer `beneficiaire.solde() == attendu[solde_beneficiaire]` (= 300).

Ce test est la démonstration bout-en-bout de la confidentialité : le **détenteur
de la clé** recouvre sa note ; le montant n'est visible que pour lui. Il assume,
et le README le dit, que publier le wallet revient à publier l'autorité de dépense
— acceptable sur une chaîne jetable sans valeur.

### `un_quorum_de_deux_est_refuse` (négatif, point 5)

1. Amorcer un état **frais** depuis `genese.bin`.
2. Décoder `bloc-1-sous-quorum.bin` ; vérifier `bloc.id() == attendu[bloc1_id]`
   (même id que le bloc plein — le certificat n'entre pas dans l'`id`) et
   `cert.masque == 0x03`.
3. `etat.appliquer_bloc(&sous_quorum)` renvoie
   `Err(QuorumInsuffisant { obtenu: 2, requis: 3 })`.

Ce test prouve que la fixture ne constate pas seulement un bloc accepté : elle
**mord** sur la frontière `2 < 3`.

### Décision : pas d'assertion interne sur nullifieur/commitment

Au-delà des assertions structurelles (point 3 de la revue), on n'ajoute pas
d'assertion sur le nullifieur dépensé ni le commitment du bénéficiaire :
l'avancée de `racine_apres_bloc1` (rejeu positif) et `solde == 300` (recouvrement)
sont déjà les conséquences falsifiables complètes. YAGNI.

---

## Documentation à mettre à jour

- **`docs/CONFORMITE.md` §2** — v3 reste le contrôle minimal ; `conformite-etendue`
  ferme les deux réserves (quorum `n=4` à 3 votants, transaction confidentielle à
  preuve STARK vérifiée) et démontre le recouvrement.
- **`docs/CONFORMITE.md` §5 (« Ce qui n'est pas démontré »)** — retirer / requalifier
  la ligne « La fixture de consensus ne couvre aucune transaction (§2), ni un
  quorum à plusieurs votants » : c'est désormais couvert par `conformite-etendue`.
  §5 doit rester exact, pas seulement §2. **(Point 7 de la revue.)**
- **`docs/fixtures/conformite-v3/README.md`** — ajouter un renvoi : « la couverture
  profonde (quorum multi-votant, transaction STARK, recouvrement) vit dans
  `conformite-etendue` ; cette fixture-ci reste le smoke-check minimal sans
  `--release`. » **(Point 8.)**
- **`docs/fixtures/conformite-etendue/README.md`** (nouveau) — rôle, commande de
  rejeu, `--release` requis, clés/wallet jetables, convention de types
  d'`attendu.txt`, relation avec v3 et le versioning de format.

**Hors périmètre, délibérément :** `THREAT_MODEL.md`, `ARCHITECTURE.md`,
`PROTOCOL.md` ne changent pas — aucun format, invariant ni menace n'est touché.
`CLAUDE.md`/`AGENTS.md` ne font pas autorité.

---

## Tests et CI

- Les rejeus **sont** les tests. Ignorés en debug, exécutés en `--release` ; le job
  de conformité CI (`cargo test --all-features --release`, `CONFORMITE.md` §3) les
  exerce déjà — **rien à ajouter au workflow**.
- Le chemin debug rapide reste inchangé : v3 continue sans `--release`.
- Le générateur (`#[ignore]`) n'est jamais lancé en CI ; son résultat est versionné.

**Critère de franchissement.** `cargo test -p node --test conformite_etendue
--release` passe : décodage de la genèse à 4 autorités et du bloc portant une
transaction confidentielle, cohérence clés↔genèse, certificat exact
(`masque 0x07`, votants {0,1,2}), vérification STARK via `appliquer_bloc`, racines
publiées retrouvées, `solde == 300` recouvré par le bénéficiaire, et refus
`QuorumInsuffisant` à 2 votes — le tout depuis les seuls fichiers de
`docs/fixtures/conformite-etendue/`.

---

## Ce que ce design ne fait pas

- Il **ne change aucun format** de bloc, de fil ou de preuve.
- Il **ne modifie pas** `conformite-v3` ni `conformite.rs`.
- Il **n'implémente pas** l'économie (coinbase, `R(h)`) — hors périmètre, porte A.
- Il **ne teste pas** partition ni changement de vue : `quorum_sockets.rs`,
  `partition.rs`, `vue_sockets.rs` couvrent déjà ces dynamiques. La fixture est un
  artefact **statique** de vérification tierce.
- Il **n'introduit aucun `--release` sur le chemin de conformité rapide** — v3 le
  préserve.
