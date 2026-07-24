# Runbook d'ouverture du testnet Obscura

> Ce document SÉQUENCE des procédures écrites ailleurs. Il ne crée aucune
> règle : en cas de divergence avec une source renvoyée, c'est cette source qui
> fait autorité, et l'écart ici est un défaut de ce runbook à corriger. Chaque
> étape a une pré-condition, un critère de passage, et une branche **« si ça
> échoue »**. **Les étapes 2 à 4 sont IRRÉVERSIBLES pour la chaîne ouverte** : la
> chaîne est consommable (`docs/TESTNET.md` §2), mais refaire ces étapes ne la
> répare pas — cela produit une **nouvelle chaîne**, avec un nouvel identifiant de
> genèse.

---

## Traçabilité — tout se rattache à UN commit

Avant tout, choisir **un commit unique** (idéalement un **tag signé**, p. ex.
`testnet-0`) et n'exécuter TOUTE la suite qu'à partir de lui. La raison est
concrète : sinon le re-test PQ peut valider un état du code, et la release être
produite depuis un autre — l'ancre ne prouverait plus rien.

**Critère, à vérifier au début et à re-vérifier avant l'étape 4 :**

- `git status` est **propre** (aucune modification non commitée) ;
- le **SHA du commit** (et le nom du tag) est **noté** dans le journal (dernière
  section), et publié avec la release ;
- les binaires sont **construits depuis ce SHA exact** (`cargo build --release`
  sur l'arbre propre), et `Cargo.lock` est **commité** dans ce même état ;
- le re-test PQ (étape 1), la genèse (étape 2), `docs/GENESE.md`, les scripts
  `deploiement/*` et la release (étape 4) portent **tous** ce SHA.

Si un correctif s'avère nécessaire en cours de route : commiter, **repartir de
l'étape 0** avec le nouveau SHA. On ne mélange pas deux états du code.

---

## Points de centralisation assumés (à lire d'abord)

Le détail est dans `docs/TESTNET.md` §0 ; les points qui pèsent sur l'ordre des
étapes :

- **L'archiviste est un point de centralisation réel.** Sur une source unique, un
  nœud peut mentir par omission sans qu'aucun contrôle local ne le démente
  (`docs/TESTNET.md` §0, §1.3).
- **`--temoin` n'a de valeur qu'avec au moins deux archivistes INDÉPENDANTS**
  (deux opérateurs distincts). À une seule archive, la synchronisation est
  elle-même un point de confiance. C'est un **critère de passage** de l'étape 5,
  pas un simple conseil.
- **Ce qui est figé au gel, et ce qui ne l'est pas.** Les **allocations** et
  l'**ancre** de genèse sont définitives : obtenir des fonds après le gel exige
  une nouvelle chaîne. En revanche, la **liste des autorités est reconfigurable
  sur la même chaîne** — le quorum de l'ancienne liste certifie ajout, retrait ou
  remplacement (J1-c), et une autorité absente est contournée par changement de
  vue (J1-b2). Un opérateur peut donc rejoindre le COMITÉ plus tard ; il ne peut
  pas se faire allouer des fonds plus tard (`docs/TESTNET.md` §1.2).

---

## Étape 0 — Répétition générale (sur chaîne JETABLE)

**Pré-condition :** le commit de traçabilité est choisi et l'arbre est propre.

**But :** transformer ce runbook en procédure **éprouvée**, pas seulement correcte
sur le papier. Rien de ce qui est produit ici n'est publié ; tout est détruit à la
fin. On rejoue le jour J en miniature, sur un répertoire temporaire.

1. Générer les identités de **≥ 4 autorités** jetables (`obscura-node --identite
   --donnees repA … repD`) et une genèse jetable fédérée les gravant
   (`obscura-genese`), en notant l'identifiant **complet**.
2. Signer une **fausse release** (clé minisign jetable) via
   `deploiement/signer-release.sh`, puis la vérifier
   (`deploiement/verifier-release.sh`) — la vérification doit passer, et une
   altération d'un octet doit la faire échouer.
3. Démarrer les 4 autorités (`obscura-node --ecoute … --genese … --sceller …`),
   maillées, et **vérifier qu'elles impriment toutes le MÊME identifiant complet**.
4. Laisser **produire quelques blocs**, puis **couper une autorité** et vérifier
   que la chaîne **continue** (changement de vue, J1-b2) — pas de gel.
5. Lancer **deux archivistes indépendants** (`--archiver`) et tester
   `obscura-wallet synchroniser --temoin` contre l'un, l'autre comme témoin :
   la synchronisation aboutit et les racines corroborent.

**Critère de passage :** les points 3, 4 et 5 sont observés en vrai. Un runbook
non répété n'est pas prêt.

**Si ça échoue :** ne pas geler la vraie genèse. Un identifiant divergent au point
3, un gel au point 4, ou une synchro qui échoue au point 5 sont des **défauts à
corriger avant l'ouverture** — corriger, re-commiter, **recommencer l'étape 0** sous
le nouveau SHA.

---

## Étape 1 — Re-test de la dette PQ (BLOQUANT)

**Pré-condition :** étape 0 réussie, SHA de traçabilité fixé.

Rejouer et **CONSIGNER par écrit** les critères de la section « Re-test avant le
gel de genèse (gate de T5) » de `docs/BACKEND_PQ.md`. Le gel de l'étape 2 rend le
format de fil définitif : la décision « ne pas migrer le backend post-quantique »
doit être re-confirmée **à cette date et pour ce SHA**, pas héritée.

**Critère de passage :** une trace écrite du re-test existe (rattachée au SHA),
même si sa conclusion est « toujours non ».

**Si ça échoue** (un critère de déclenchement est devenu vrai — vraie
vulnérabilité, `ml-dsa` 1.0, etc.) : **ARRÊT COMPLET du runbook.** La migration du
backend précède toute ouverture ; graver le format de fil actuel deviendrait une
dette qu'on ne pourrait plus payer sans nouvelle chaîne.

---

## Étape 2 — Gel de la genèse (IRRÉVERSIBLE)

**Pré-condition :** étape 1 consignée. Autorités et allocations décidées et
distribuées hors bande (adresses `obs1…` via `obscura-wallet adresse`, empreintes
d'identité via `obscura-node --identite`).

```
obscura-genese --sortie genese.bin \
    --autorite-hex <hex-autorité-1> --autorite-hex <hex-autorité-2> … \
    --allocation obs1…:<montant> …
```

- `--autorite-hex` : grave la liste INITIALE d'autorités dans l'identifiant de la
  chaîne. Elle reste reconfigurable ensuite (J1-c). Sans aucune autorité, la chaîne
  est **OUVERTE** (n'importe quel nœud scelle) — vérifier que c'est le choix voulu.
- `--allocation <adr>:<n>` : répétable. Le **nombre** d'allocations est public à
  jamais ; une allocation unique désigne son bénéficiaire par sa seule position.

L'outil s'**auto-vérifie** (relecture après écriture) et imprime l'identifiant de
genèse **COMPLET (64 octets = 128 hex)**, plus une forme courte (8 octets) à seul
usage de repère visuel.

**Critère de passage :** l'identifiant complet (64 octets) est imprimé et
recueilli. C'est lui, pas la forme courte, qui sert d'ancre.

**Si ça échoue** (l'outil refuse d'écrire, ou n'arrive pas à relire ce qu'il a
écrit) : ne rien publier. Un artefact que son auteur ne sait pas relire ne doit
jamais atteindre un opérateur — diagnostiquer, puis reprendre depuis l'étape 0.

---

## Étape 3 — Publication de l'ancre (IRRÉVERSIBLE)

**Pré-condition :** identifiant complet (64 octets) de l'étape 2 en main.

Renseigner `docs/GENESE.md` avec cet identifiant (SHA de traçabilité inclus), puis
publier la **même valeur hors bande** (canal d'invitation, distinct du dépôt Git).
Le dépôt seul ne prouve pas qui a écrit la genèse ; c'est la confrontation des deux
canaux qui protège d'une genèse substituée. Gabarit et checklist : `docs/GENESE.md`.

**Critère de passage :** la valeur inscrite dans `docs/GENESE.md` et la valeur
publiée hors bande sont **identiques sur les 128 caractères**, et au moins un
opérateur tiers a confirmé la confrontation.

**Si ça échoue** (un opérateur voit un identifiant DIFFÉRENT du sien) :
**ouverture SUSPENDUE.** Deux genèses divergentes se refusent tous leurs blocs sans
que l'erreur en désigne la cause — remonter à la source de l'écart (quel SHA, quel
`genese.bin`) avant de reprendre. Ne jamais « choisir » une des deux valeurs.

---

## Étape 4 — Release signée (IRRÉVERSIBLE)

**Pré-condition :** genèse gelée (étape 2), ancre publiée (étape 3), **traçabilité
re-vérifiée** (arbre propre, binaires construits depuis le SHA noté). Binaires +
`genese.bin` + `Cargo.lock` réunis dans un répertoire d'artefacts.

Signer avec `deploiement/signer-release.sh <repertoire> <cle-privee>` : produit un
manifeste `checksums.txt` (un artefact = une ligne) signé par minisign
(`checksums.txt.minisig`). **La clé privée reste chez le signataire, jamais dans le
dépôt** ; publier l'empreinte de la clé publique hors bande.

Publier la release (artefacts + `checksums.txt` + `checksums.txt.minisig`) et
`deploiement/release.pub`.

**Vérification tierce, obligatoire :** `deploiement/verifier-release.sh <repertoire>
<cle-publique>`, exécutée par une partie **autre que le signataire**.

**Critère de passage :** `verifier-release.sh` rapporte une release vérifiée, chez
un tiers.

**Si ça échoue** (`verifier-release.sh` sort non nul) : **publication ANNULÉE.** Une
signature ou un checksum qui diverge signifie soit une clé mal appariée, soit un
artefact altéré — retirer la release, re-signer depuis le répertoire d'artefacts du
bon SHA, re-vérifier. Ne jamais publier une release qu'un tiers n'a pas vérifiée.

---

## Étape 5 — Séquence de démarrage « jour J » et gate des archivistes

**Pré-condition :** étapes 1 à 4 complètes. **Aucun nœud externe n'est encore
invité.**

Dans l'ordre, sans sauter d'étape :

1. Chaque autorité **vérifie la release** (`verifier-release.sh`) **et la genèse**
   (identifiant complet contre `docs/GENESE.md` ET contre la valeur hors bande).
2. **Démarrer les autorités** (`obscura-node --ecoute … --genese genese.bin
   --sceller …`), maillées entre elles.
3. **Vérifier que toutes impriment le MÊME identifiant complet** au démarrage. Un
   écart d'un seul caractère → arrêter (voir « si ça échoue »).
4. Contrôler la santé du réseau : `liens` attendus établis, `hauteur` qui
   **avance**, et **aucun désaccord** (pas de bloc concurrent, pas de hauteur
   calée — cf. la limite « split de votes » de `docs/TESTNET.md` §1.2).
5. **Attendre N blocs** (p. ex. `N ≥ 10`) produits proprement, y compris après une
   coupure volontaire d'une autorité (la chaîne doit continuer — J1-b2).
6. **Démarrer au moins DEUX archivistes de deux opérateurs distincts**
   (`--archiver`), synchronisables, et **publier leurs adresses aux participants**.
7. **Test wallet + témoin :** `obscura-wallet synchroniser --temoin` contre un
   archiviste, l'autre comme témoin ; la synchro aboutit et les racines corroborent.

**Critère de passage (GATE, tous requis) :** même identifiant complet partout (3) ;
santé verte (4) ; N blocs produits, coupure absorbée (5) ; **≥ 2 archivistes
indépendants en ligne, synchronisables, adresses publiées (6)** ; test témoin réussi
(7). Sans le point 6, `--temoin` est purement théorique et l'ouverture est
**retardée**, pas franchie.

**Si ça échoue :**
- identifiant divergent (3) → **ouverture suspendue**, comme étape 3 ;
- désaccord / hauteur calée (4-5) → diagnostiquer avant d'inviter quiconque ;
- moins de deux archivistes indépendants (6) → **ouverture RETARDÉE** jusqu'à en
  avoir deux ; ne pas annoncer un réseau où `--temoin` ne peut pas fonctionner.

---

## Étape 6 — Annonce

**Pré-condition :** le gate de l'étape 5 est franchi en entier.

Publier, sur le même canal que l'invitation :

- Les limites connues, **avant** l'ouverture (`docs/TESTNET.md` §1).
- Le caractère consommable et la procédure de reset (`docs/TESTNET.md` §2).
- La règle de réaction à la valeur (`docs/TESTNET.md` §3).
- Le rappel « sur invitation » (`docs/TESTNET.md` §0) : pas de bootnode public, pas
  de faucet, pas d'explorateur.
- Le **SHA/tag de traçabilité** et l'**empreinte de `release.pub`**.

**Critère de passage :** les points ci-dessus sont publiés **avant** que le premier
nœud externe ne rejoigne.

---

## Résumé des critères de passage

| Étape | Critère |
|---|---|
| Traçabilité | `git status` propre, SHA/tag noté, binaires construits depuis ce SHA |
| 0. Répétition générale | ≥ 4 autorités démarrées, coupure absorbée, synchro + témoin OK sur chaîne jetable |
| 1. Re-test PQ | Trace écrite du re-test (rattachée au SHA), même négative |
| 2. Gel de la genèse | Identifiant complet (64 o) imprimé et recueilli |
| 3. Publication de l'ancre | `docs/GENESE.md` = canal hors bande sur 128 hex, confirmé par un tiers |
| 4. Release signée | `verifier-release.sh` exécuté par un tiers, release vérifiée |
| 5. Démarrage jour J | Même id partout, santé verte, N blocs, **≥ 2 archivistes indépendants**, témoin OK |
| 6. Annonce | Limites, reset, réaction, SHA/empreinte publiés avant ouverture |

---

## Journal de signatures humaines

À remplir au fil de l'exécution — c'est ce qui rend l'ouverture **auditable après
coup**. Une ligne par étape franchie.

| Étape | Responsable | Vérificateur tiers | Horodatage (UTC) | Commande exécutée | Fichier de preuve | Résultat |
|---|---|---|---|---|---|---|
| Traçabilité | | | | `git rev-parse HEAD` | SHA noté | |
| 0. Répétition | | | | | log de répétition | |
| 1. Re-test PQ | | | | (re-test `BACKEND_PQ.md`) | trace écrite | |
| 2. Gel genèse | | | | `obscura-genese …` | `genese.bin` + id complet | |
| 3. Ancre | | | | (édition `GENESE.md` + hors bande) | `docs/GENESE.md` | |
| 4. Release | | (≠ signataire) | | `signer-release.sh` / `verifier-release.sh` | `checksums.txt.minisig` | |
| 5. Démarrage | | | | (séquence jour J) | logs des nœuds | |
| 6. Annonce | | | | (publication) | message d'annonce | |
