# Faire tourner un nœud Obscura

Guide d'exploitation. Il suppose que vous n'avez pas écrit le code.

> ⚠️ **Prototype non audité, sans valeur.** Ne pas exposer sur un réseau où
> quelque chose compte. Les limites connues sont en fin de document — les lire
> AVANT de démarrer, pas après un incident.

## Démarrer

```sh
obscura-node --ecoute 0.0.0.0:9333 --donnees /var/lib/obscura/donnees \
             --genese /var/lib/obscura/genese.bin
```

| Option | Rôle |
|---|---|
| `--ecoute <adr>` | adresse d'écoute (**obligatoire**) |
| `--pair <adr>` | pair à contacter au démarrage (répétable) |
| `--donnees <rép>` | identité + état + archive (défaut : `./donnees-obscura`) |
| `--genese <fichier>` | bloc 0 de la chaîne (défaut : genèse VIDE, testnet local) |
| `--sceller <ms>` | produire des blocs (défaut : **désactivé**) |
| `--archiver` | conserver l'historique des sorties (défaut : **désactivé**) |

Déploiement : [`deploiement/obscura-node.service`](../deploiement/obscura-node.service)
(systemd, durci) et [`deploiement/Dockerfile`](../deploiement/Dockerfile).

### Les deux options qui engagent

**`--genese` engage votre chaîne.** Deux nœuds amorcés sur des genèses
différentes se refusent *tous* leurs blocs. L'identifiant est imprimé au
démarrage **pour être comparé** entre opérateurs :

```
[    0.002s] INFO   genèse e0f5ec2116b2c60e (0 émissions) — tête courante e0f5ec2116b2c60e
```

Si le vôtre diffère de celui de vos pairs, arrêtez-vous là : rien d'autre ne
fonctionnera, et le symptôme (aucun bloc accepté) ne désigne pas la cause.

**`--archiver` engage votre disque.** ≈1,4 Kio par sortie, ≈1,4 Mio par bloc
plein, **jamais élagué**. Ce rôle est ce qui permet aux wallets de se
synchroniser — un nœud qui ne l'active pas reste parfaitement valide, il ne peut
simplement pas amorcer de wallet. **À activer dès l'amorçage** : rien ne sait
reconstruire un préfixe manquant, et activer trop tard est refusé plutôt que
servi de travers.

## Créer la genèse (une fois, avant tout le reste)

Rien ne peut démarrer sans elle, et **rien ne peut la remplacer après coup**.

### D'abord, chaque autorité publie sa clé

```sh
obscura-node --identite --donnees /var/lib/obscura
```

La commande imprime la clé publique du nœud sur **stdout** (≈3970 caractères
hexadécimaux, seuls, sans prose autour — elle se redirige vers un fichier), crée
l'identité si elle n'existe pas encore, et sort sans rien démarrer d'autre. C'est
l'ordre normal des choses : votre clé doit être connue **avant** que la genèse
n'existe.

Chacun envoie cette clé au fabricant de la genèse. **Personne n'envoie son
fichier `identite.cle`** — il contient le secret du nœud, et le perdre ou le
divulguer coûte le tour de scellement, définitivement (la liste des autorités
est gravée dans l'identifiant de la chaîne : elle ne se corrige pas).

### Ensuite, la genèse

```sh
# Chaîne fédérée : autorités + allocation initiale
obscura-genese --sortie genese.bin     --autorite-hex <clé publique de l'autorité A>     --autorite-hex <clé publique de l'autorité B>     --allocation obs1…:1000000
```

| Option | Rôle |
|---|---|
| `--sortie <fichier>` | fichier à écrire (**refuse d'écraser**) |
| `--autorite <identite.cle>` | autorité, lue depuis un fichier d'identité de nœud |
| `--autorite-hex <hex>` | autorité, depuis une clé publique — **la bonne voie pour une fédération** : chacun publie sa clé, personne ne transmet son fichier |
| `--allocation <adr>:<n>` | alloue `n` unités à une adresse `obs1…` |

L'outil **relit et réamorce** ce qu'il vient d'écrire avant de vous le rendre : un
artefact que son auteur ne sait pas relire ne doit jamais atteindre un opérateur.

Il imprime ensuite l'**identifiant court**. **Comparez-le entre opérateurs avant
de démarrer quoi que ce soit** — c'est le seul contrôle qui détecte une chaîne
divergente *avant* qu'elle ne diverge.

Sans `--autorite`, la chaîne est **ouverte** : n'importe quel nœud avec
`--sceller` produit des blocs. Testnet local uniquement.

### Combien d'autorités ? — le quorum décide, et il se paie en octets

Un bloc n'est valide que muni d'un **certificat de quorum** : `2f + 1` signatures
d'autorités distinctes, avec `n = 3f + 1`. Le nombre d'autorités gravées n'est
donc pas cosmétique — il fixe à la fois ce que la chaîne tolère et ce que chaque
bloc pèse.

| `n` autorités | pannes tolérées `f` | quorum `2f+1` | certificat | part du bloc |
|---|---|---|---|---|
| 1 à 3 | **0** | 1 | 3 374 o | 0,3 % |
| **4** | **1** | 3 | 10 122 o | **1,0 %** |
| 7 | 2 | 5 | 16 870 o | 1,6 % |
| 10 | 3 | 7 | 23 618 o | 2,3 % |
| 64 (max) | 21 | 43 | 145 082 o | **13,8 %** |

**Recommandation : `n = 4`.** C'est le premier point qui tolère réellement une
panne, pour 1 % du budget du bloc. À `n ≤ 3`, `f = 0` : la chaîne exige un quorum
qu'une seule autorité atteint, ce qui n'est pas une faiblesse du calcul — c'est ce
que « tolérer zéro faute » signifie.

⚠️ **Le certificat ne s'agrège pas et ne s'agrègera pas** : aucune signature
post-quantique ne l'offre. Son coût croît **linéairement** avec le comité, pour
toujours. À `n = 64` il vaut l'équivalent de deux transactions par bloc. Mesurez
avant de graver : `cargo run -p node --example dimensionner-quorum --release`.

✅ **Une chaîne à `n ≥ 4` produit des blocs.** Le protocole qui fait circuler les
votes (J1-b1) et le changement de vue (J1-b2) sont livrés : le producteur
rassemble les votes des autres, finalise dès `⌊2n/3⌋+1`, et une autorité absente
est contournée par changement de vue. Vous pouvez donc graver le comité dont vous
avez besoin (voir « `--sceller` ne produit aucun bloc » pour les autres causes).

⚠️ Le **nombre** d'allocations est public à jamais (les montants et les
bénéficiaires, non). Une allocation unique désigne son bénéficiaire par sa seule
position.

## Surveiller

Le nœud journalise sur **stderr**, avec l'uptime et un niveau. `systemd` et
Docker y ajoutent l'horodatage absolu (`journalctl -u obscura-node -f`,
`docker logs -tf obscura`).

```sh
OBSCURA_LOG=info    # erreur | avert | info | debug   (défaut : info)
```

Une valeur inconnue ne fait **pas** taire le nœud : il avertit et retombe sur
`info`.

### La ligne de statut, toutes les 30 s

C'est la seule chose qu'un nœud sain écrit en régime permanent :

```
[  300.001s] INFO   statut — hauteur 42 | pairs 5 | liens 3 | mempool 0 | désaccords 0
```

| Champ | Ce qu'il dit | Quand s'inquiéter |
|---|---|---|
| `hauteur` | dernier bloc appliqué | elle n'avance plus alors que le réseau produit |
| `pairs` | pairs connus (table anti-eclipse) | proche de 0 |
| `liens` | connexions **ouvertes** | **0 = le nœud est isolé** |
| `mempool` | transactions en attente | croît sans jamais retomber |
| `désaccords` | blocs refusés pour chaînage | **> 0 et qui augmente** |

La ligne passe en **`AVERT`** dès que `liens = 0` ou `désaccords > 0`. Ces deux
cas sont les **pannes silencieuses** du protocole : un nœud isolé ou décroché
continue de répondre normalement, en servant un historique plus court mais
parfaitement cohérent. Rien d'autre ne les rend visibles.

## Sauvegarder

Trois fichiers dans `--donnees` :

| Fichier | Contenu | Perte = |
|---|---|---|
| `identite.cle` | **clé privée du nœud, EN CLAIR** | le nœud change de pair aux yeux du réseau |
| `etat.bin` | état de consensus | resynchronisation depuis les pairs |
| `historique.bin` | archive des sorties (si `--archiver`) | irrécupérable sans re-synchroniser depuis zéro |

`identite.cle` est le seul qui ne se reconstruit pas. Sur Unix il est en `0600` ;
**il n'est pas chiffré** — sa protection est celle du système de fichiers.

Les écritures sont **atomiques** (`tmp` + `rename`) : un arrêt brutal laisse la
version précédente intacte, jamais un fichier à moitié écrit. Sauvegarder à
chaud est donc sûr. L'état est enregistré toutes les 30 s ; au pire, le nœud
repart de la sauvegarde précédente et rattrape auprès de ses pairs.

## Mettre à jour le logiciel

Un réseau vivant ne s'arrête pas pour être mis à jour : plusieurs versions du
nœud tournent forcément côte à côte le temps du déploiement. Faire évoluer le
logiciel sans le forker exige de savoir, AVANT de déployer, dans laquelle des
deux natures suivantes tombe le changement — les confondre EST un fork.

### (a) Changement compatible fil

N'affecte **ni le format de bloc ni les règles de validation** : journalisation,
CLI, une métrique, l'ajout d'un message applicatif qui ne change rien au
décodage de ceux qui existent déjà (un nouveau tag au-delà de `DERNIER_TAG`,
cf. `crates/node/src/message.rs`). Se déploie **nœud par nœud, dans n'importe
quel ordre** : c'est exactement le cas que couvre la tolérance de version
réactive du protocole (`MessageError::version_inconnue()`) — un tag ou une
version inconnus sont traités comme un message **du futur**, jamais comme une
faute, et n'entraînent donc **aucune sanction** ni bannissement. Un pair resté
en arrière continue de servir l'ancien format pendant que les autres migrent ;
rien n'oblige à mettre à jour tout le monde au même instant.

### (b) Rupture de consensus

Change une **règle de validation** ou le **format de bloc**. Deux exemples
tirés du dépôt, pour reconnaître le cas :

- **Un bump de `VERSION_BLOC`** (`crates/ledger/src/bloc.rs`) : le passage de
  `0x04` à `0x05` lors de J1-c (changement d'autorités certifié) en est
  l'exemple direct. La version périmée (`VERSION_BLOC_PERIMEE`) est **refusée
  par son nom** dès le décodage — elle ne cohabite jamais avec la version
  courante, il n'existe pas de fenêtre où les deux formats sont valides à la
  fois.
- **Tout changement touchant `crates/ledger/src/proved_state.rs`**
  (`appliquer_bloc` et les règles qu'il impose à un bloc pour l'accepter) est
  **suspect par défaut** : c'est la porte unique par laquelle un bloc devient
  ou non partie de l'état.

À l'inverse, un changement purement **local** à un nœud — le format d'une
ligne de statut, une option CLI qui ne touche à rien sur le fil — n'en est pas
une, même s'il modifie du code dans les mêmes crates.

### La règle du testnet fédéré : une rupture = une nouvelle chaîne

Périmètre B ne fait **pas** d'activation par hauteur (pas de hard-fork
coordonné) : c'est explicitement **hors périmètre**. La seule réponse à une
rupture de consensus est de **graver une nouvelle genèse** et d'y migrer — ce
qui est cohérent avec le reste du projet : une chaîne de testnet est déjà
`consommable` par conception (voir « Procédure de reset »,
[`docs/TESTNET.md`](TESTNET.md)), et les autorités comme les allocations sont
gravées dans l'identifiant de genèse — les changer EST déjà, structurellement,
changer de chaîne. Une rupture de règle de validation n'est qu'un cas de plus
qui appelle la même procédure, pas un cas à part.

En pratique : annoncez l'arrêt de l'ancienne chaîne, fabriquez la nouvelle
genèse (`obscura-genese`, voir « Créer la genèse » ci-dessus) avec le logiciel
mis à jour, et redémarrez tous les nœuds dessus. Ne déployez **jamais** une
rupture de consensus progressivement : tant qu'une partie du réseau valide
encore l'ancienne règle, les deux moitiés produisent des blocs que l'autre
refuse — un fork silencieux, indiscernable au démarrage d'une simple
désynchronisation (cf. « `désaccords` augmente » ci-dessous).

### Lien avec la négociation de version

La tolérance de version ci-dessus est **réactive** : elle empêche qu'un pair à
jour sanctionne un pair en retard, mais ne dit à personne QUI parle QUELLE
version. La négociation explicite (J3, `Message::Version`, cf.
`docs/PROTOCOL.md`) comble ce manque : chaque nœud **constate** la version de
ses pairs, ce qui permet de juger si un déploiement nœud par nœud est terminé
avant d'annoncer une rupture.

Deux choses à savoir en exploitation :

- **Seul le côté sortant annonce**, l'entrant répond. Un pair qui n'annonce
  rien est présumé parler la version de base : servi normalement, jamais
  sanctionné, jamais mis en attente. Un `obscura-wallet` n'annonce rien du tout
  — c'est un client, pas un pair.
- **Un refus de version se lit dans le journal** (`avert : lien fermé avec … —
  version de protocole annoncée …`). Il ne touche PAS le score : le pair revient
  dès qu'il est à jour. Si vos `liens` tombent après une mise à jour, cette ligne
  est ce qui le dit.

## Dépanner

**Le nœud démarre puis ne fait rien.** Regardez `liens`. À 0, aucun pair n'est
joignable : vérifiez `--pair`, le pare-feu, et que vos pairs tournent.

**`désaccords` augmente.** Le nœud reçoit des blocs qui ne s'enchaînent pas.
Deux causes : il a manqué une hauteur (il la redemande tout seul — le compteur
doit se stabiliser), ou il est sur une **autre chaîne** (comparez l'identifiant
de genèse). Le second cas ne se répare pas : l'état est *append-only*, il faut
repartir d'un répertoire de données vide, avec la bonne genèse.

**`--sceller` ne produit aucun bloc.** Trois causes, dans l'ordre où les écarter :

1. **Vous n'êtes pas autorité.** Le démarrage le dit :

```
[    0.002s] AVERT  --sceller sans être autorité : AUCUN bloc ne sera produit
```

2. **Ce n'est pas votre tour.** Sur une chaîne à autorités, seul le producteur de
   la hauteur scelle — attendez le tour suivant.
3. **Le quorum n'est pas réuni.** Sur une chaîne à `n ≥ 4`, le producteur doit
   rassembler `⌊2n/3⌋+1` votes avant de finaliser ; s'il manque des pairs joignables
   (voir `liens`) ou si trop d'autorités sont hors ligne, le bloc n'atteint pas le
   quorum et le changement de vue tourne sans avancer. Les votes circulent bien sur
   le fil (J1-b1) et le changement de vue est actif (J1-b2) : vérifiez la
   connectivité et que les autres autorités tournent.

**« ARCHIVE INUTILISABLE ».** Le nœud démarre en mode **dégradé, sans archive** :
il reste valide mais ne peut plus servir de wallet. **Aucun fichier n'est
tronqué ni effacé** — l'archive est laissée telle quelle pour examen.

**Le nœud refuse de démarrer.** C'est délibéré dans trois cas : genèse illisible,
identité corrompue, répertoire de données d'une **autre** chaîne. Aucun repli
n'est tenté : un nœud mal amorcé est indiscernable d'un nœud neuf en bonne santé.

## Limites connues

- **Une autorité absente est CONTOURNÉE par changement de vue** (J1-b2). Passé un
  délai (à backoff exponentiel), les autres passent à la vue suivante et le
  producteur suivant reprend la main : la panne d'un participant ne fige plus la
  chaîne. ⚠️ Limite restante : un producteur « à moitié en ligne » qui émet sans
  réunir le quorum peut retarder la finalité jusqu'au changement de vue.
- **Aucune réorganisation n'est possible.** Une divergence est définitive — et
  avec la finalité par quorum, c'est désormais une conséquence assumée du modèle
  plutôt qu'un manque : un bloc certifié n'a rien à réorganiser.
- **Le mempool n'est pas persisté** — sans gravité, les pairs réannoncent.
- **Le nœud qui sert l'historique apprend** l'IP, la cadence et la position des
  wallets. Il peut aussi **mentir par omission** (taire une sortie : la racine
  annoncée reste cohérente) ou **retenir sa tête** (se taire plus tôt qu'il ne
  devrait). Les deux sont fermés côté wallet par
  `obscura-wallet synchroniser --temoin <ip:port>`, qui corrobore chaque bloc
  auprès d'un **second nœud** — dites donc à vos utilisateurs qu'il existe, et
  **publiez l'adresse d'archivistes tenus par d'autres que vous** : deux nœuds
  du même opérateur n'en valent qu'un.
- **L'archiviste est le point de centralisation réel** du réseau.
- Pas de Tor/I2P intégré, pas de métriques Prometheus, pas de client léger.
