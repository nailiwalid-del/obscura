# Testnet public Obscura — limites, reset, et réaction à la valeur

**À lire avant d'utiliser ce réseau.** Ce document doit être publié **avant**
l'ouverture, et il fait partie des critères de sortie du jalon.

> **Ce réseau est expérimental et sans valeur. Les jetons qu'il distribue n'en
> ont aucune, n'en auront aucune, et la chaîne sera remise à zéro.** Ce n'est pas
> une clause de style : c'est le mode de fonctionnement prévu, décrit en §2.

---

## 1. Limites connues

Aucune de ces limites n'est un bug. Elles sont toutes des conséquences assumées
de décisions écrites, et chacune renvoie à son document de référence.

### 1.1 Statut

- **Prototype non audité.** Aucun audit externe n'a eu lieu. L'argument de
  witness-hiding du circuit est **honnête-vérifieur** et non audité
  ([`STARK_STATEMENT.md`](STARK_STATEMENT.md)).
- **Conformité FIPS partielle et mesurée** : 4 opérations sur 6 ne sont pas
  couvertes par vecteurs officiels, faute d'API adéquate dans le backend
  ([`CONFORMITE.md`](CONFORMITE.md)).
- **Le backend post-quantique est marqué `unmaintained`** en amont — dette
  ouverte, datée et défendue ([`BACKEND_PQ.md`](BACKEND_PQ.md)).

### 1.2 Consensus

- **Fédéré, pas décentralisé.** La liste des autorités de scellement est gravée
  dans la genèse. En changer = nouvelle genèse = **nouvelle chaîne**.
- **Une autorité absente fige la chaîne jusqu'à son retour.** Les transactions
  s'accumulent en mempool, rien n'est perdu, mais **plus aucun bloc n'est
  produit** tant que l'autorité du tour ne revient pas. Il n'existe aucun
  certificat de saut : c'est un choix, et le fermer demande un changement de vue,
  donc un autre modèle de consensus.
- **Aucune réorganisation n'est possible.** L'état est append-only de bout en
  bout. Toute divergence est **définitive** : un nœud qui diverge ne se répare
  pas, il se réamorce.
- **Aucune résistance à la censure du producteur.** L'ordre des transactions dans
  un bloc est une convention de reproductibilité, pas une défense.

### 1.3 Confidentialité

- **La forme d'une transaction est publique** : le nombre d'entrées et de sorties
  (`m`/`n`) se lit sur le fil.
- **Les frais sont publics.** `fee` est un champ public et une entrée publique de
  la preuve. C'est pourquoi **seuls des frais nuls sont acceptés** sur ce testnet
  (`obscura-wallet envoyer --frais 0`, ou l'option omise) : les frais étant
  brûlés, en payer n'achète rien et marquerait durablement le payeur.
- **Le nœud qui vous sert l'historique apprend votre IP, la cadence de vos
  demandes et votre position de chaîne.** Il peut aussi **mentir par omission** :
  taire une sortie produit une chaîne parfaitement cohérente dont la racine est
  celle qu'il annonce.
  → **Utilisez `--temoin` avec un nœud d'un AUTRE opérateur.** C'est la seule
  défense, et elle ne vaut que si vous le choisissez indépendamment.
- **Pas de Tor ni d'I2P intégrés.** Votre adresse IP est visible de vos pairs.
- **Ne synchronisez pas et n'envoyez pas depuis la même adresse au même nœud** :
  l'enchaînement vous désigne comme émetteur. `obscura-wallet envoyer` propose
  `--noeud-synchro` distinct pour cette raison.

### 1.4 Exploitation

- **L'archiviste est le point de centralisation réel du réseau.** Tout wallet qui
  se synchronise en dépend, et son disque croît sans borne (≈1,4 Kio par sortie,
  jamais élagué).
- **La genèse n'est pas authentifiée par elle-même.** Rien dans le fichier
  n'atteste qui l'a écrite. → **Comparez l'identifiant complet imprimé au
  démarrage de votre nœud avec celui publié hors bande.** 32 octets, pas 8.
- **Le mempool n'est pas persisté** (sans gravité : les pairs réannoncent).
- **La clé d'identité d'un nœud n'est pas chiffrée au repos.**
- **L'arbre du wallet est en O(n)** : pas de client léger, la mémoire croît avec
  la chaîne.

Le modèle de menace complet est dans [`THREAT_MODEL.md`](THREAT_MODEL.md). Ce
document-ci n'en est qu'un résumé destiné aux utilisateurs.

---

## 2. Procédure de reset

**Une chaîne de testnet est consommable.** Ce n'est pas un aveu d'échec : c'est
le fonctionnement prévu, et il est écrit d'avance pour que personne n'ait à le
découvrir au moment des faits.

### 2.1 Ce qui provoque un reset

| Cause | Pourquoi elle impose une nouvelle chaîne |
|---|---|
| Changement de la liste d'autorités | elle est gravée dans l'identifiant de genèse |
| Arrivée du mécanisme économique | la coinbase change les règles d'émission |
| Changement de version de bloc ou d'algorithme | le format de fil devient incompatible |
| Divergence irrécupérable | l'état est append-only : rien ne se répare |
| Chaîne acquérant une valeur | voir §3 |

### 2.2 Ce qui se passe

1. **Annonce préalable** sur les canaux d'ouverture, avec la raison et la date.
2. **Publication de la nouvelle genèse** et de son **identifiant complet**
   (32 octets) hors bande.
3. **Arrêt des bootnodes de l'ancienne chaîne.** Ils ne servent pas les deux.
4. **Redémarrage** : chaque opérateur repart d'un répertoire de données **neuf**
   et de la nouvelle genèse.

### 2.3 Ce que vous devez savoir

- **Rien n'est préservé.** Aucun solde, aucune note, aucun historique ne
  traverse un reset. Les fonds n'ayant aucune valeur, il n'y a rien à
  dédommager.
- **Votre fichier de wallet reste lisible**, mais ses notes pointent vers une
  chaîne qui n'existe plus. Créez-en un neuf.
- **Ne réutilisez pas un répertoire `--donnees` d'une autre chaîne** : le nœud le
  refusera au démarrage en affichant les deux identifiants de genèse. C'est
  volontaire, et c'est ce qui empêche une divergence silencieuse.

---

## 3. Si la chaîne acquiert une valeur malgré nous

Un testnet sans valeur peut en acquérir une contre la volonté de ses auteurs, dès
que quelqu'un accepte d'échanger ses jetons contre quoi que ce soit. **Un
déclencheur sans geste n'est pas une défense** : voici le geste, écrit d'avance
pour qu'il ne soit pas décidé sous pression.

Escalade, du moins grave au plus grave :

1. **Constat public.** Rappel écrit que la chaîne est sans valeur et consommable,
   sur les mêmes canaux que l'annonce d'ouverture.
2. **Pause du faucet.** Il est le robinet ; le fermer coupe l'entrée de « stock »
   sans toucher au réseau.
3. **Reset annoncé** (§2). C'est l'usage prévu — et **le simple fait qu'il soit
   connu d'avance décourage la spéculation** : personne ne valorise ce qui sera
   remis à zéro.
4. **Fermeture.** Arrêt des bootnodes et de l'archiviste, dépôt archivé.

⚠️ **Cette escalade fait partie des limites publiées.** Un réseau dont on sait
qu'il peut être remis à zéro à tout moment n'acquiert pas de valeur par accident.

---

## 4. Signaler un problème

Vulnérabilité, divergence de chaîne, comportement inattendu d'un nœud : voir le
canal d'incident indiqué sur la page d'ouverture du testnet.

⚠️ **Ce projet n'a pas de programme de bug bounty** et ne promet aucun délai de
réponse. Les fonds n'ayant aucune valeur, aucun signalement ne porte sur un
préjudice financier.
