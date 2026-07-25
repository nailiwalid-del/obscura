# Design — Fixture de conformité étendue (quorum multi-votant + transaction STARK)

**Date :** 2026-07-25
**Statut :** design approuvé, prêt pour le plan d'implémentation.
**Objet :** ajouter un **artefact rejouable par un tiers** qui ferme les deux
réserves nommées par `docs/CONFORMITE.md` §2 — « aucune transaction ni preuve
STARK » et « quorum à un seul votant » — sans toucher au format ni à la fixture
`conformite-v3` existante.
**Portée :** ce document conçoit une fixture de test et sa mise à jour
documentaire. Il ne change **aucun** format de consensus, aucun invariant, aucune
règle. Il n'ajoute que de la **couverture de vérification tierce**.

---

## Contexte, vérifié dans le code

Trois faits contraignent le design. Ils sont lus dans le dépôt au 2026-07-25.

1. **La fixture de conformité est l'artefact déterministe rejouable.**
   `crates/node/tests/conformite.rs` + `docs/fixtures/conformite-v3/` : genèse +
   bloc-1 + hachages attendus, versionnés. Elle est **délibérément** `n=1`, sans
   transaction ni STARK, pour rester petite, rapide et testable sans `--release`.
   Elle exerce décodage `0x05`, chaînage, élection de producteur, scellement,
   certificat de quorum (à un votant), avancée de la tête.

2. **Le consensus multi-votant AVEC transaction STARK est déjà testé — mais pas
   comme un artefact rejouable.** `crates/node/tests/quorum_sockets.rs` prouve
   `n=4, f=1, quorum 3` avec une vraie transaction confidentielle et convergence
   de tête/racine sur les quatre nœuds. C'est un test **dynamique**, à clés
   aléatoires, sur sockets vivantes : il valide le comportement, mais ne produit
   **aucun fichier qu'un tiers rejoue** depuis `docs/`.

3. **La lacune est donc précise :** porter le quorum multi-votant et la
   transaction confidentielle dans **l'artefact statique** que lit un auditeur —
   pas ré-implémenter un consensus déjà couvert.

**Conséquence de cadrage.** Ce qui manque n'est pas une capacité, c'est une
*preuve rejouable*. Le design se limite à assembler et figer cette preuve.

---

## Décision

**Ajouter une fixture `conformite-etendue`, à côté de `conformite-v3` (qui reste
intacte), qui démontre en une exécution rejouable :**

1. une **genèse à 4 autorités** portant une émission confidentielle vers un
   wallet payeur ;
2. un **bloc-1 contenant une transaction confidentielle** (payeur → bénéficiaire,
   300 sur 1000, frais 0), dont la **preuve STARK est vérifiée au rejeu** ;
3. ce bloc-1 **certifié par un quorum de ≥ 3 votants distincts** (`n=4, f=1`) ;
4. l'avancée de la racine d'état **exactement** comme publié.

La fixture est **gatée `--release`** (génération et vérification de preuve STARK),
via l'idiome déjà en place :
`#[cfg_attr(debug_assertions, ignore = "preuves gatées : --release")]`.

### Pourquoi une nouvelle fixture plutôt que remplacer v3

`conformite-v3` a une valeur propre : c'est le **contrôle minimal**, déterministe,
rapide, **sans `--release`**, qui exerce le squelette (décode/chaînage/scellement/
forme du certificat) en profil debug. La remplacer forcerait `--release` pour tout
contrôle de conformité et perdrait ce smoke-check. Deux artefacts, deux rôles :

| | `conformite-v3` | `conformite-etendue` |
|---|---|---|
| Rôle | smoke-check permanent | preuve profonde tierce |
| Autorités | 1 (`n=1`, quorum 1) | 4 (`n=4`, quorum 3) |
| Transaction | aucune | 1 transfert confidentiel |
| Preuve STARK | aucune | vérifiée au rejeu |
| `--release` | non requis | **requis** |

### Pourquoi `conformite-etendue` et non `conformite-v4`

Les numéros de version de fixture tracent les **bumps de format de bloc**
(v1→v2 : `0x04` ; v2→v3 : `0x05`), pas les ajouts de couverture. La fixture
étendue est au **même format `0x05`** que v3. La nommer « v4 » suggérerait à tort
un changement de format. Le README documentera la relation : si le format bumpe
plus tard, **les deux** fixtures cassent ensemble (par construction, comme v1/v2/v3)
et sont re-datées, jamais écrasées.

---

## Architecture

### Fichiers de la fixture

Nouveau répertoire `docs/fixtures/conformite-etendue/` :

```
docs/fixtures/conformite-etendue/
  autorite-0.cle … autorite-3.cle   # 4 clés d'autorité JETABLES, publiées
  genese.bin                        # 4 autorités + émission vers le payeur
  bloc-1.bin                        # transaction confidentielle + certificat 3 votants
  attendu.txt                       # valeurs attendues (voir plus bas)
  README.md                         # rôle, rejeu, --release, clés jetables, relation v3
```

Les clés d'autorité sont **jetables et publiées** avec la fixture, exactement
comme `autorite.cle` de v3 : elles n'existent que pour rendre genèse et bloc
reproductibles, et ne servent nulle part ailleurs. Le README le dira mot pour mot.

### `attendu.txt`

Format `clé=valeur_hex`, `#` en commentaire (même parseur que v3) :

```
genese_id=<hex>
racine_apres_genese=<hex>
bloc1_id=<hex>
racine_apres_bloc1=<hex>
quorum_requis=3
nombre_de_votants=<n ≥ 3>
```

### Fichier de test

Nouveau `crates/node/tests/conformite_etendue.rs`, calqué sur `conformite.rs`,
deux fonctions :

- **`la_fixture_etendue_se_rejoue`** — le rejeu tiers, gaté `--release`.
- **`generer_la_fixture_etendue`** (`#[ignore]`) — régénère les artefacts à la
  main, versionnés ensuite.

Les helpers `attendus()`/`lire()`/`racine_fixture()` sont **dupliqués localement**
dans le nouveau fichier (adaptés au répertoire `conformite-etendue`), pas extraits
dans un module partagé : ils sont courts, et `conformite.rs` reste ainsi
auto-suffisant et lisible d'un bloc — cohérent avec le style du dépôt (chaque test
porte sa propre plomberie).

---

## Générateur (`generer_la_fixture_etendue`)

Assemble tout **sans sockets** — contrairement à `quorum_sockets.rs`, qui fait
circuler les votes sur le réseau : pour un artefact statique, on assemble le
certificat directement.

1. Générer 4 clés d'autorité `cles[0..4]` ; les écrire (`autorite-i.cle`).
2. Dériver les wallets payeur et bénéficiaire de graines fixes (comme
   `secret(graine)` dans `quorum_sockets.rs`).
3. Genèse à 4 autorités portant une émission vers le payeur (motif `genese_pour`
   de `quorum_sockets.rs`) ; écrire `genese.bin`.
4. Amorcer l'état ; le payeur se synchronise sur la genèse
   (`MorceauHistorique::bloc_entier`) puis `construire(&bénéficiaire.adresse(),
   300, 0)` → `tx`.
5. `Bloc::sceller(&genese.id(), 1, vec![tx])`, `signer_scellement(&cles[0])`,
   puis `signer_vote(i, &cles[i])` pour `i ∈ {0, 1, 2}` → certificat à **3
   votants distincts** ; écrire `bloc-1.bin`.
6. Appliquer le bloc, relever les racines, écrire `attendu.txt`.

**Déterminisme par commit, pas par régénération.** Les octets sont figés une fois
et le rejeu les *vérifie* ; il ne les régénère pas. Les signatures hedgées et les
tailles de preuve STARK variables (le dépôt lit une taille de preuve « comme une
bande, jamais comme une égalité ») ne cassent donc rien : c'est le contrat déjà
tenu par v3. Re-lancer le générateur produit un artefact **différent mais valide**;
seuls les octets commités font foi.

> Note d'implémentation : le producteur du tour à hauteur 1, vue 0, est
> `autorites[(1 − 1 + 0) mod 4] = autorites[0]`. Le scellement doit donc être
> signé par `cles[0]`. À confirmer dans le plan via `producteur_attendu(1, 0)`.

---

## Ce que le rejeu affirme (`la_fixture_etendue_se_rejoue`)

Dans l'ordre, chaque assertion falsifiable :

1. `genese.bin` décode ; `genese.id()` == `attendu[genese_id]`.
2. Amorçage → `tree.root()` == `attendu[racine_apres_genese]` ; tête == genèse.
3. `bloc-1.bin` décode ; `bloc1.id()` == `attendu[bloc1_id]` ; `bloc1.vue == 0`.
4. Scellement vérifié contre `producteur_attendu(1, 0)`.
5. `etat.quorum_requis() == 3` ; le certificat existe et porte **≥ 3 votants
   distincts** (`nombre_de_votants() >= 3`, indices distincts) — repris de la
   discipline de `quorum_sockets.rs`.
6. `etat.appliquer_bloc(&bloc1)` réussit — **ce qui vérifie la preuve STARK de la
   transaction sur le chemin de consensus réel** — et fait avancer tête + racine
   vers `bloc1_id` / `racine_apres_bloc1` publiés.

Le point 6 est le cœur du gain : la vérification STARK **dans** le chemin de
consensus (`appliquer_bloc`), pas un appel isolé — donc ce qu'un nœud fait
vraiment. C'est ce que la fixture v3 ne couvrait pas.

### Décision : pas d'assertion supplémentaire sur le transfert

On n'ajoute **pas** d'assertion isolée sur le nullifieur dépensé ni sur le
commitment du bénéficiaire. Raison : l'avancée de `racine_apres_bloc1` (point 6)
est déjà la conséquence intégrale et falsifiable de l'application de la
transaction — un nullifieur non dépensé ou un commitment absent donnerait une
racine différente et ferait échouer le point 6. Ajouter des assertions internes
dupliquerait cette garantie en couplant le test à la structure interne de l'arbre.
YAGNI.

---

## Documentation à mettre à jour

- **`docs/CONFORMITE.md` §2** — aujourd'hui : « Ne couvre aucune transaction ni
  preuve STARK, et son quorum n'a qu'un seul votant ». Après : v3 reste le
  contrôle minimal ; **`conformite-etendue` ferme les deux réserves** (quorum
  `n=4` à 3 votants, transaction confidentielle dont la preuve STARK est vérifiée
  au rejeu). C'est la mise à jour qui porte la valeur pour la thèse « un tiers
  vérifie sans nous croire ».
- **`docs/fixtures/conformite-etendue/README.md`** — rôle, commande de rejeu,
  `--release` requis, clés jetables, relation avec v3 et le versioning de format.

**Hors périmètre, délibérément :** `THREAT_MODEL.md`, `ARCHITECTURE.md`,
`PROTOCOL.md` ne changent pas — aucun format, invariant ni menace n'est touché.
`CLAUDE.md`/`AGENTS.md` ne font pas autorité et n'ont pas à être modifiés.

---

## Tests et CI

- Le rejeu **est** le test. Il est gaté `--release` ; le job de conformité CI
  (`cargo test --all-features --release`, `CONFORMITE.md` §3) l'exerce déjà —
  **rien à ajouter au workflow**.
- Le chemin debug rapide reste inchangé : v3 continue de tourner sans `--release`.
- Le générateur (`#[ignore]`) n'est jamais lancé en CI ; son résultat est
  versionné.

**Critère de franchissement.** `cargo test -p node --test conformite_etendue
--release` passe ; il décode la genèse à 4 autorités et le bloc portant une
transaction confidentielle, vérifie un certificat de ≥ 3 votants distincts,
vérifie la preuve STARK via `appliquer_bloc`, et retrouve les racines publiées —
le tout à partir des seuls fichiers de `docs/fixtures/conformite-etendue/`.

---

## Ce que ce design ne fait pas

- Il **ne change aucun format** de bloc, de fil ou de preuve.
- Il **ne modifie pas** `conformite-v3` ni `conformite.rs`.
- Il **n'implémente pas** l'économie (coinbase, `R(h)`) — hors périmètre, derrière
  la porte A.
- Il **ne teste pas** de partition ni de changement de vue : `quorum_sockets.rs`,
  `partition.rs` et `vue_sockets.rs` couvrent déjà ces dynamiques. La fixture est
  un artefact **statique** de vérification tierce, pas un test de comportement
  réseau.
- Il **n'introduit aucun `--release` sur le chemin de conformité rapide** — v3 le
  préserve.
