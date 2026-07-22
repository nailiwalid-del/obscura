# Fixture de conformité v1

Artefact rejouable qui rend vérifiable, **sans lire le code**, que cette
implémentation produit les identifiants et les racines annoncés.

## Rejouer

```bash
cargo test -p node --test conformite
```

Vert = l'implémentation reproduit `attendu.txt`. Rouge = elle ne le reproduit
pas, et l'écart est nommé dans le message d'échec.

## Contenu

| Fichier | Quoi |
|---|---|
| `genese.bin` | bloc 0, une autorité de scellement gravée, aucune allocation |
| `bloc-1.bin` | bloc de hauteur 1, **vide**, scellé par cette autorité |
| `attendu.txt` | identifiants et racines attendus, en hexadécimal **non tronqué** |
| `autorite.cle` | clé d'autorité **jetable**, publiée pour la reproductibilité |

⚠️ `autorite.cle` est du matériel de clé **volontairement public**. Il n'existe
que pour régénérer la fixture. Ne jamais s'en servir sur une chaîne réelle.

## Ce que la fixture couvre

Décodage de bloc · identifiant de genèse (**autorités comprises** — deux listes
donnent deux chaînes) · amorçage d'état · chaînage parent → enfant · élection de
producteur · vérification de scellement · avancée de la tête.

Un détail qui est une assertion et non un hasard : `racine_apres_bloc1` est
**égale** à `racine_apres_genese`. Un bloc vide n'insère aucune sortie, donc
l'arbre ne bouge pas — alors que la **tête**, elle, avance. Le test vérifie les
deux, ce qui distingue « le bloc a été appliqué » de « le bloc a été ignoré ».

## Ce qu'elle NE couvre PAS

Aucune transaction, donc **aucune preuve STARK**, aucun nullifier, aucune
émission. C'est délibéré : un bloc vide reste déterministe, petit et rapide. Une
fixture avec transaction pèserait ~68 Kio et plusieurs secondes de preuve ; elle
viendra séparément, et s'appellera `conformite-v2`.

## Régénérer

```bash
cargo test -p node --test conformite -- --ignored generer_la_fixture --nocapture
```

⚠️ Régénérer produit une **nouvelle clé d'autorité**, donc une **nouvelle
genèse**, donc de **nouvelles valeurs attendues**. Ne le faire que
délibérément — une fixture qui change à chaque exécution ne prouve rien.
