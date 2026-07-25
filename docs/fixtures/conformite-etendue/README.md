# Fixture de conformité étendue

> **Pourquoi une fixture séparée, et pas une v4.** Les numéros de
> `conformite-v{1,2,3}` tracent les **bumps de format** de bloc (`0x04`, puis
> `0x05`) : chaque bump invalide la fixture précédente *par construction*, et la
> remplacer plutôt que l'écraser laisse le remplacement visible dans
> l'historique. Ici le format ne bouge pas — c'est la **couverture** qui
> s'étend : transaction confidentielle, quorum à plusieurs votants, refus sous
> quorum, recouvrement par le destinataire. Un « v4 » mentirait sur la nature
> du changement. Le jour où le format bumpera, les **deux** fixtures (v3 et
> celle-ci) tomberont ensemble, et seront re-datées ensemble — jamais
> écrasées.

Artefact rejouable qui rend vérifiable, **sans lire le code**, ce que
`docs/fixtures/conformite-v3/` laisse volontairement de côté : une
transaction confidentielle dont la preuve STARK est vérifiée sur le chemin de
consensus, un quorum à plusieurs votants distincts, le refus d'un bloc
sous-quorum, et le recouvrement d'un paiement par son destinataire.

## Rejouer

```bash
cargo test -p node --test conformite_etendue --release
```

Le `--release` est **requis**, pas optionnel : générer et vérifier une preuve
STARK est gaté sur `--release` dans tout le dépôt, et les trois tests de rejeu
sont marqués `#[cfg_attr(debug_assertions, ignore = "preuves gardées par
--release")]` — ils sont **ignorés en build de debug** et ne s'exécutent qu'en
`--release`. `conformite-v3` reste, elle, le contrôle qui s'exécute sans
`--release` (voir plus bas).

Vert = l'implémentation reproduit `attendu.txt`. Rouge = elle ne le reproduit
pas, et l'écart est nommé dans le message d'échec.

## Contenu

| Fichier | Quoi |
|---|---|
| `genese.bin` | bloc 0, **quatre** autorités gravées (`n = 4`, `f = 1`, quorum `⌊2n/3⌋+1 = 3`), une émission de monnaie chiffrée vers le payeur |
| `bloc-1.bin` | bloc de hauteur 1, **une transaction confidentielle** (300 sur 1000, frais 0), certificat masque `0x07` → autorités 0, 1 et 2, soit **trois votants distincts** |
| `bloc-1-sous-quorum.bin` | le **même** bloc (même identifiant, même parent, même transaction), certificat masque `0x03` → **deux** votants seulement |
| `beneficiaire.wallet` | le matériel du destinataire du paiement, à l'état **pré-scan** (aucune note, position de synchronisation à zéro) |
| `autorite-0.cle` … `autorite-3.cle` | les quatre clés d'autorité, **jetables**, publiées pour la reproductibilité |
| `attendu.txt` | identifiants, racines, masque et compteurs attendus |

⚠️ `autorite-{0,1,2,3}.cle` sont du matériel de clé **volontairement public**.
Elles n'existent que pour régénérer et vérifier cette fixture. Ne jamais s'en
servir sur une chaîne réelle.

⚠️ `beneficiaire.wallet` est du matériel de clé **volontairement public** au
même titre : il donne l'autorité de **dépense** sur les fonds qu'il détient
(300 unités reçues au bloc 1). C'est assumé et sans conséquence, parce que ces
fonds n'ont **aucune valeur** et vivent sur une chaîne **jetable** qui n'existe
que dans ce répertoire — la genèse et le bloc 1 publiés ici, rien d'autre. Ne
jamais reprendre ce motif (clé publiée + fonds réels) sur une chaîne où la
valeur compte.

## Convention de types d'`attendu.txt`

Déclarée en tête du fichier lui-même : identifiants et racines en
**hexadécimal**, compteurs et montants en **décimal**, masque de certificat en
**hexadécimal** au format `u64` (`0x` suivi de 16 chiffres, ex.
`0x0000000000000007`). Le hexadécimal pour identifiants et racines prolonge la
convention de v3 ; le décimal pour les compteurs et le masque en hexadécimal
sont propres à cette fixture, v3 n'ayant ni compteur ni certificat à plusieurs
votants à publier.

## Ce que la fixture couvre

- **Cohérence clés ↔ genèse** : les quatre clés publiées sont bien celles que
  la genèse grave, dans le même ordre — l'index d'un votant est une position
  dans cette liste.
- **Décodage et scellement** du bloc 1 : hauteur 1, vue 0, une transaction,
  aucune émission hors genèse, aucune reconfiguration, scellé par l'autorité
  du tour (`autorites[(1−1+0) mod 4]`, donc l'autorité 0).
- **Le certificat de quorum aux valeurs exactes** : masque `0x07`, trois
  votants distincts (autorités 0, 1, 2) sur un quorum requis de 3 — la
  démonstration qu'un quorum à plusieurs votants, et pas une auto-certification
  à un seul, est ce qui fait avancer la chaîne.
- **La preuve STARK de la transaction, vérifiée sur le chemin de consensus
  réel** : le rejeu positif fait passer le bloc par `appliquer_bloc`
  (`apply_proved_tx` → `verify_tx`), pas par un vérifieur de test isolé, à la
  profondeur consensus (`CONSENSUS_DEPTH = 32`).
- **Le refus d'un bloc sous-quorum** : `bloc-1-sous-quorum.bin` porte le même
  identifiant que `bloc-1.bin` (le certificat n'entre pas dans l'identifiant
  canonique) mais seulement deux votes ; l'état le refuse nommément
  (`BlocRefus::QuorumInsuffisant { obtenu: 2, requis: 3 }`) et n'avance pas
  d'un octet. Ce refus est démontrable ici depuis les seuls octets publiés,
  sans lire le code — le scénario lui-même (quorum insuffisant) est par
  ailleurs déjà couvert par un test unitaire de `ledger`.
- **Le recouvrement du paiement par son destinataire** : `beneficiaire.wallet`,
  rechargé depuis son état pré-scan puis synchronisé sur la genèse et le bloc
  1, retrouve et **déchiffre** son montant (300), avec une seule note à lui —
  l'autre sortie du bloc est la monnaie rendue au payeur, chiffrée vers une clé
  que le bénéficiaire n'a pas.

## Ce qu'elle ne couvre pas

Cette fixture ne prétend pas remplacer les tests unitaires de `ledger` ou de
`circuit` — voir `docs/CONFORMITE.md` §5 pour ce qui reste non démontré à
l'échelle du dépôt (audit externe, argument HVZK honnête-vérifieur, backend PQ,
etc.).

## Relation avec `conformite-v3` et versioning de format

`conformite-v3` et cette fixture coexistent et jouent des rôles différents :

- **`conformite-v3`** est le smoke-check **minimal** : genèse à une autorité,
  bloc vide, aucune preuve, exécutable **sans** `--release`. C'est le contrôle
  rapide.
- **`conformite-etendue`** (ce répertoire) est la preuve **profonde** :
  quorum à plusieurs votants, transaction confidentielle avec preuve STARK
  vérifiée, recouvrement par le destinataire, refus sous quorum. Elle exige
  `--release`.

Les deux fixtures encodent le **même format de bloc** (`VERSION_BLOC 0x05`).
Un futur bump de ce format invaliderait les deux fixtures **par construction**
— exactement comme le bump `0x04 → 0x05` a invalidé v2 avant que v3 ne soit
créée. La règle est la même pour les deux : une fixture invalidée par un bump
de format est **re-datée** dans un nouveau répertoire, jamais écrasée sur
place — le remplacement doit rester visible dans l'historique.

## Régénérer

```bash
cargo test -p node --test conformite_etendue --release -- --ignored \
    generer_la_fixture_etendue --nocapture
```

⚠️ Régénérer produit quatre **nouvelles** clés d'autorité et un **nouveau**
wallet bénéficiaire, donc une nouvelle genèse et de nouvelles valeurs
attendues : les signatures sont hedgées et une taille de preuve STARK varie,
donc relancer le générateur donne un artefact différent — valide, mais
différent. Seuls les octets déjà commités font foi pour le rejeu ; ne
régénérer que délibérément.
