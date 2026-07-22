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
| `identite.bin` | **clé privée du nœud, EN CLAIR** | le nœud change de pair aux yeux du réseau |
| `etat.bin` | état de consensus | resynchronisation depuis les pairs |
| `historique.bin` | archive des sorties (si `--archiver`) | irrécupérable sans re-synchroniser depuis zéro |

`identite.bin` est le seul qui ne se reconstruit pas. Sur Unix il est en `0600` ;
**il n'est pas chiffré** — sa protection est celle du système de fichiers.

Les écritures sont **atomiques** (`tmp` + `rename`) : un arrêt brutal laisse la
version précédente intacte, jamais un fichier à moitié écrit. Sauvegarder à
chaud est donc sûr. L'état est enregistré toutes les 30 s ; au pire, le nœud
repart de la sauvegarde précédente et rattrape auprès de ses pairs.

## Dépanner

**Le nœud démarre puis ne fait rien.** Regardez `liens`. À 0, aucun pair n'est
joignable : vérifiez `--pair`, le pare-feu, et que vos pairs tournent.

**`désaccords` augmente.** Le nœud reçoit des blocs qui ne s'enchaînent pas.
Deux causes : il a manqué une hauteur (il la redemande tout seul — le compteur
doit se stabiliser), ou il est sur une **autre chaîne** (comparez l'identifiant
de genèse). Le second cas ne se répare pas : l'état est *append-only*, il faut
repartir d'un répertoire de données vide, avec la bonne genèse.

**`--sceller` ne produit aucun bloc.** Sur une chaîne à autorités, seul le
producteur du tour scelle. Le démarrage le dit :

```
[    0.002s] AVERT  --sceller sans être autorité : AUCUN bloc ne sera produit
```

**« ARCHIVE INUTILISABLE ».** Le nœud démarre en mode **dégradé, sans archive** :
il reste valide mais ne peut plus servir de wallet. **Aucun fichier n'est
tronqué ni effacé** — l'archive est laissée telle quelle pour examen.

**Le nœud refuse de démarrer.** C'est délibéré dans trois cas : genèse illisible,
identité corrompue, répertoire de données d'une **autre** chaîne. Aucun repli
n'est tenté : un nœud mal amorcé est indiscernable d'un nœud neuf en bonne santé.

## Limites connues

- **Une autorité absente FIGE la chaîne à son tour** (liveness, option A
  assumée). Les transactions attendent au mempool, rien n'est perdu.
- **Aucune réorganisation n'est possible.** Une divergence est définitive.
- **Le mempool n'est pas persisté** — sans gravité, les pairs réannoncent.
- **Le nœud qui sert l'historique apprend** l'IP, la cadence et la position des
  wallets, et peut **mentir par omission** : la racine annoncée reste cohérente.
  Une seule source de synchronisation est un point de confiance.
- **L'archiviste est le point de centralisation réel** du réseau.
- Pas de Tor/I2P intégré, pas de métriques Prometheus, pas de client léger.
