# Testnet Obscura — limites, reset, et réaction à la valeur

**À lire avant d'utiliser ce réseau.** Ce document doit être publié **avant**
l'ouverture, et il fait partie des critères de sortie du jalon.

> **Ce réseau est expérimental et sans valeur. Les jetons qu'il distribue n'en
> ont aucune, n'en auront aucune, et la chaîne sera remise à zéro.** Ce n'est pas
> une clause de style : c'est le mode de fonctionnement prévu, décrit en §2.

---

## 0. Ce réseau fonctionne SUR INVITATION

**Il n'existe aucun bootnode public, aucun faucet, aucun explorateur.** C'est une
décision, pas un manque de temps : héberger un archiviste engage un disque qui
croît sans borne et une disponibilité que ce projet ne promet pas.

Conséquences, toutes assumées :

- **Les participants sont les opérateurs.** Chacun fait tourner son propre nœud ;
  les adresses de pairs circulent directement entre participants.
- **Les fonds viennent des allocations de genèse**, pas d'un robinet. Pour
  rejoindre, un participant transmet son adresse `obs1…` (`obscura-wallet
  adresse`) et, s'il doit sceller, l'empreinte de son identité de nœud
  (`obscura-node --identite`). Elles sont gravées dans la genèse par
  `obscura-genese` — donc **rejoindre après le gel exige une nouvelle chaîne**.
- **`--temoin` n'a de valeur que si au moins deux participants archivent.** Sur
  une source unique, un nœud peut mentir par omission sans qu'aucun contrôle
  local ne le démente (§1.3). À une seule archive, la synchronisation est un
  point de confiance, et il faut le savoir.
- **Aucune disponibilité n'est promise.** Le réseau s'arrête quand ses
  participants s'arrêtent.

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
  dans la genèse, mais elle est désormais **reconfigurable sur la même chaîne**
  (J1-c) : l'ancien comité certifie collectivement la nouvelle liste par son
  quorum, et le changement prend effet à `h + K` (K = 8 blocs). Échanger, ajouter
  ou retirer un membre ne refait plus la chaîne. **En revanche, l'ancien quorum
  décide du nouveau** — y compris se réduire ou se remplacer entièrement : votre
  place dépend du quorum, pas d'un droit acquis.
- ⚠️ **Réduire le comité à `n ≤ 3` sacrifie la tolérance aux fautes.** Le quorum
  vaut alors `n` (tous doivent voter) et le changement de vue ne peut plus
  contourner une absence. Table de liveness :

  | n | quorum | tolère f absent(s) |
  |---|---|---|
  | 1 | 1 | 0 |
  | 2 | 2 | 0 |
  | 3 | 3 | 0 |
  | 4 | 3 | 1 |
  | 7 | 5 | 2 |
  | 10 | 7 | 3 |
- **Un bloc exige un quorum de `2f + 1` autorités** (`n = 3f + 1`) depuis le
  format `0x04`. C'est ce qui donne la **finalité** : un bloc certifié ne peut
  être contredit sans que `f + 1` participants signent deux blocs à la même
  hauteur — une faute prouvable. Une partition qui ne réunit pas le quorum
  **s'arrête** plutôt que de diverger.
- **Une autorité absente est CONTOURNÉE par changement de vue** (J1-b2) : passé
  un délai (à backoff exponentiel), les autres passent à la vue suivante et la
  chaîne continue avec le producteur suivant. La panne d'un participant ne fige
  donc plus la chaîne.
  ⚠️ **Limite restante — le split de votes.** Si un producteur était « à moitié
  joignable » au moment exact du basculement de vue, les votes peuvent se
  partitionner : un nœud vote pour le bloc de la vue `v`, un autre pour celui de
  la vue `v+1`. Aucun n'atteint alors le quorum, et comme un vote est
  **définitif à sa hauteur** (règle de sûreté), la hauteur peut **caler pour
  toujours** — recovery par nouvelle chaîne (§2). C'est rare (il faut un
  producteur partiellement joignable pile au basculement), c'est le prix assumé
  de « arrêt plutôt que divergence », et ce n'est **jamais silencieux** : le
  statut passe en préoccupant et le journal émet une `ERREUR` dédiée.
- **Aucune réorganisation n'est possible.** L'état est append-only de bout en
  bout. Toute divergence est **définitive** : un nœud qui diverge ne se répare
  pas, il se réamorce. Avec la finalité instantanée, cette limite devient une
  conséquence assumée du modèle plutôt qu'un manque : il n'y a rien à
  réorganiser.
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
  jamais élagué). Sur un réseau sur invitation, cela veut dire : **celui qui
  archive voit passer les demandes de tous les autres** (§1.3).
- **La genèse n'est pas authentifiée par elle-même.** Rien dans le fichier
  n'atteste qui l'a écrite.
  → **Vérification :** l'identifiant complet (32 octets) est publié dans le
  README du dépôt, et les releases sont **signées**. Comparez-le avec celui
  imprimé au démarrage de votre nœud. 32 octets, pas 8 — la forme courte est un
  diagnostic, pas une ancre.
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
| Changement NON certifié de la liste d'autorités (hors quorum, ou liste vide) | il faut une nouvelle genèse ; un changement certifié par le quorum, lui, se fait sur la même chaîne (J1-c) |
| Arrivée du mécanisme économique | la coinbase change les règles d'émission |
| Changement de version de bloc ou d'algorithme | le format de fil devient incompatible |
| Divergence irrécupérable | l'état est append-only : rien ne se répare |
| Chaîne acquérant une valeur | voir §3 |

### 2.2 Ce qui se passe

1. **Annonce préalable** sur les canaux d'ouverture, avec la raison et la date.
2. **Publication de la nouvelle genèse** et de son **identifiant complet**
   (32 octets) hors bande.
3. **Arrêt des nœuds de l'ancienne chaîne.** Un nœud ne sert pas les deux : son
   répertoire de données grave sa genèse et refuse l'autre.
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

### 2.4 Avant de graver la genèse (pré-requis bloquant)

**Pré-requis bloquant** avant toute exécution de `obscura-genese` en
production : rejouer et **consigner** le re-test de `docs/BACKEND_PQ.md`
(section « Re-test avant le gel de genèse ») — le gel rend le format wire
définitif, donc la décision « ne pas migrer le backend PQ » doit être
re-confirmée à cette date précise, pas héritée d'une lecture plus ancienne.

---

## 3. Si la chaîne acquiert une valeur malgré nous

Un testnet sans valeur peut en acquérir une contre la volonté de ses auteurs, dès
que quelqu'un accepte d'échanger ses jetons contre quoi que ce soit. **Un
déclencheur sans geste n'est pas une défense** : voici le geste, écrit d'avance
pour qu'il ne soit pas décidé sous pression.

Escalade, du moins grave au plus grave :

1. **Constat public.** Rappel écrit que la chaîne est sans valeur et consommable,
   sur les mêmes canaux que l'annonce d'ouverture.
2. **Arrêt des invitations.** Il n'y a pas de faucet à fermer : l'entrée de
   « stock » passe par les allocations de genèse. Cesser d'inviter tarit donc la
   source sans toucher au réseau existant.
3. **Reset annoncé** (§2). C'est l'usage prévu — et **le simple fait qu'il soit
   connu d'avance décourage la spéculation** : personne ne valorise ce qui sera
   remis à zéro.
4. **Fermeture.** Chaque participant arrête son nœud, dépôt archivé.

⚠️ **Cette escalade fait partie des limites publiées.** Un réseau dont on sait
qu'il peut être remis à zéro à tout moment n'acquiert pas de valeur par accident.

---

## 4. Signaler un problème

| Quoi | Où |
|---|---|
| **Vulnérabilité** | **GitHub Security Advisories** du dépôt — canal privé, qui permet une divulgation coordonnée |
| Divergence de chaîne, bug, comportement inattendu | **GitHub Issues**, en public |

Le choix du canal privé pour les vulnérabilités n'est pas une promesse de
confidentialité durable : c'est simplement ce qui laisse la possibilité d'un
correctif avant publication. Rien n'oblige personne à l'emprunter.

⚠️ **Ce projet n'a pas de programme de bug bounty** et ne promet **aucun délai de
réponse**. Les fonds n'ayant aucune valeur, aucun signalement ne porte sur un
préjudice financier.
