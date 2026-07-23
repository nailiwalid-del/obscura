# Fixture de conformité v3

> **Pourquoi une v3.** `VERSION_BLOC 0x05` (J1-c : le changement d'ensemble
> d'autorités entre dans l'identifiant, via le champ `changement_autorites`)
> change l'identifiant de genèse. La fixture v2 est devenue invalide **par
> construction**, et son échec a été la **première** chose que le changement de
> format a produite — c'est exactement ce pour quoi elle existait. Une v3 datée
> plutôt qu'un écrasement : le remplacement reste visible dans l'historique.

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
| `genese.bin` | bloc 0 en **version `0x05`**, une autorité gravée, aucune allocation |
| `bloc-1.bin` | bloc de hauteur 1, **vide**, vue 0, scellé **et certifié** par cette autorité |
| `attendu.txt` | identifiants et racines attendus, en hexadécimal **non tronqué** |
| `autorite.cle` | clé d'autorité **jetable**, publiée pour la reproductibilité |

⚠️ `autorite.cle` est du matériel de clé **volontairement public**. Il n'existe
que pour régénérer la fixture. Ne jamais s'en servir sur une chaîne réelle.

## Ce que la fixture couvre

Décodage de bloc `0x05` · identifiant de genèse (**autorités comprises** — deux
listes donnent deux chaînes) · amorçage d'état · chaînage parent → enfant ·
élection de producteur · vérification de scellement · **certificat de quorum** ·
avancée de la tête.

Le bloc 1 porte un certificat, et c'est ce qui le rend applicable : à `n = 1`,
`f = 0` et le quorum vaut **1** — l'unique autorité se certifie elle-même. Le
test l'exige explicitement (`quorum_requis() == 1`, votant `[0]`) plutôt que de
le constater : sans certificat, le bloc serait refusé pour `QuorumInsuffisant`.

Un détail qui est une assertion et non un hasard : `racine_apres_bloc1` est
**égale** à `racine_apres_genese`. Un bloc vide n'insère aucune sortie, donc
l'arbre ne bouge pas — alors que la **tête**, elle, avance. Le test vérifie les
deux, ce qui distingue « le bloc a été appliqué » de « le bloc a été ignoré ».

## Ce qu'elle NE couvre PAS

Aucune transaction, donc **aucune preuve STARK**, aucun nullifier, aucune
émission. C'est délibéré : un bloc vide reste déterministe, petit et rapide.

**Aucun quorum PLURIEL** : à `n = 1`, le certificat ne contient qu'une signature,
donc la fixture n'exerce ni le masque à plusieurs bits, ni le comptage de votants
distincts, ni le refus à `2f` votes — tout cela vit dans les tests unitaires de
`ledger::proved_state`. Une fixture à plusieurs autorités suppose des votes qui
circulent, donc J1-b.

**Aucun changement d'ensemble d'autorités** : le bloc 1 a `changement_autorites
= None` — la fixture exerce le décodage du champ introduit en `0x05` et
l'identifiant qu'il fixe, pas l'activation à `h + k` elle-même, qui vit dans
les tests unitaires de `ledger::bloc` et `ledger::proved_state`.

## Régénérer

```bash
cargo test -p node --test conformite -- --ignored generer_la_fixture --nocapture
```

⚠️ Régénérer produit une **nouvelle clé d'autorité**, donc une **nouvelle
genèse**, donc de **nouvelles valeurs attendues**. Ne le faire que
délibérément — une fixture qui change à chaque exécution ne prouve rien.
