# Vérification des revendications

`docs/STARK_STATEMENT.md` range ses revendications en trois registres :
**Prouvé**, **Supposé**, **Hors modèle**. C'est une bonne discipline, mais elle
reste une *affirmation sur ce que le code établit* tant qu'un auditeur ne peut
pas la rejouer.

Ce répertoire la rend exécutable pour le registre **Prouvé**.

```bash
./verification/verifier.sh            # structurel — quelques secondes
./verification/verifier.sh --complet  # rejoue en plus les tests nommés
```

Sortie 0 si tout tient, 1 sinon, avec la liste des revendications non tenues.

## Les deux modes

**Structurel** répond à : *les preuves annoncées existent-elles, aux valeurs
annoncées ?* Il vérifie que chaque constante vaut ce que la spec dit, que chaque
assertion de construction est présente, que chaque test nommé existe, et que la
spec dit bien ce que la carte prétend qu'elle dit. Aucune compilation.

**Complet** répond à : *passent-elles ?* Il lance `cargo test -p circuit --lib`
une seule fois et rattache chaque résultat à sa revendication.

Un test qui existe mais n'est pas exécuté par cargo est signalé `KO`, pas ignoré.
C'est le cas d'un `#[ignore]` oublié, qui laisserait une revendication sans
preuve tout en passant inaperçu.

### Pourquoi `--release` n'est pas une option

Le harnais lance `cargo test --release`, et ce n'est pas un choix de vitesse.

Les tests qui portent les revendications les plus lourdes — les trois forges D7,
les forges à reconstruction D8, le masquage sous formes variables, la disjonction
des ouvertures — sont marqués :

```rust
#[cfg_attr(debug_assertions, ignore = "monolithe gaté : --release")]
```

Ils sont donc **silencieusement sautés en debug**. Un auditeur qui lance le
`cargo test` évident voit une suite verte dans laquelle huit des dix-sept
revendications n'ont jamais été évaluées. Le harnais a été écrit en debug et a
signalé les huit, ce qui est précisément son travail.

Si vous ajoutez une revendication à la carte, vérifiez sous quel profil son test
tourne réellement.

## La carte

`revendications.psv` est l'artefact auditable. Il se lit et se recoupe avec la
spec **sans rien exécuter** :

```
id | revendication | genre | cible | attendu
```

| genre | signification |
|---|---|
| `const` | une constante doit valoir exactement `attendu` |
| `assert` | l'assertion `attendu` doit être présente dans `cible` |
| `test` | le test `cible` doit exister, et passer en mode `--complet` |
| `ancre` | `attendu` doit apparaître dans le doc `cible` |

Le genre `ancre` mérite un mot : il vérifie que la **spec** contient encore la
phrase que la carte lui attribue. Sans lui, une réécriture de `STARK_STATEMENT.md`
pourrait faire dériver la spec loin de ce que le harnais vérifie, sans que rien
ne proteste.

## Périmètre — ce que ceci ne fait pas

Le registre **Supposé** n'est pas vérifiable par exécution : ROM, vérifieur
honnête, indépendance des primitives. Ce sont des hypothèses, nommées et
réfutables dans la spec, et elles le restent. Le registre **Hors modèle** ne
l'est pas davantage.

Ce harnais ne remplace donc pas un audit. Il établit une chose plus étroite et
utile : **que le registre Prouvé n'est pas plus large qu'il n'a le droit de
l'être**, et qu'il tient à la date où on le lance.

Comme le rappelle `docs/BACKEND_PQ.md` : un re-test n'est valable qu'à sa date.

## Règle d'usage

Une revendication non tenue est un défaut de la spec **ou** du code. Corriger
l'un des deux. Retirer la ligne de la carte parce qu'elle échoue transforme le
harnais en décoration.
