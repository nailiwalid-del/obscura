# Fixture de conformité v2

> **Pourquoi une v2.** `VERSION_BLOC 0x04` (ADR J1 : vue + certificat de quorum)
> change l'identifiant de genèse. La fixture v1 est devenue invalide **par
> construction**, et son échec a été la **première** chose que le changement de
> format a produite — c'est exactement ce pour quoi elle existait. Une v2 datée
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
| `genese.bin` | bloc 0 en **version `0x04`**, une autorité gravée, aucune allocation |
| `bloc-1.bin` | bloc de hauteur 1, **vide**, vue 0, scellé par cette autorité |
| `attendu.txt` | identifiants et racines attendus, en hexadécimal **non tronqué** |
| `autorite.cle` | clé d'autorité **jetable**, publiée pour la reproductibilité |

⚠️ `autorite.cle` est du matériel de clé **volontairement public**. Il n'existe
que pour régénérer la fixture. Ne jamais s'en servir sur une chaîne réelle.

## Ce que la fixture couvre

Décodage de bloc `0x04` · identifiant de genèse (**autorités comprises** — deux
listes donnent deux chaînes) · amorçage d'état · chaînage parent → enfant ·
élection de producteur · vérification de scellement · avancée de la tête.

Un détail qui est une assertion et non un hasard : `racine_apres_bloc1` est
**égale** à `racine_apres_genese`. Un bloc vide n'insère aucune sortie, donc
l'arbre ne bouge pas — alors que la **tête**, elle, avance. Le test vérifie les
deux, ce qui distingue « le bloc a été appliqué » de « le bloc a été ignoré ».

## Ce qu'elle NE couvre PAS

Aucune transaction, donc **aucune preuve STARK**, aucun nullifier, aucune
émission. C'est délibéré : un bloc vide reste déterministe, petit et rapide.

**Aucun certificat de quorum non plus** : la vérification du quorum est livrée
par J1-a, mais les votes ne circulent qu'à partir de J1-b. Une fixture avec
certificat viendra avec le protocole.

## Régénérer

```bash
cargo test -p node --test conformite -- --ignored generer_la_fixture --nocapture
```

⚠️ Régénérer produit une **nouvelle clé d'autorité**, donc une **nouvelle
genèse**, donc de **nouvelles valeurs attendues**. Ne le faire que
délibérément — une fixture qui change à chaque exécution ne prouve rien.
