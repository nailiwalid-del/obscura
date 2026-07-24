# Runbook d'ouverture du testnet Obscura

> Ce document SÉQUENCE des procédures écrites ailleurs. Il ne crée aucune
> règle : en cas de divergence avec une source renvoyée, c'est cette source qui
> fait autorité, et l'écart ici est un défaut de ce runbook à corriger. Chaque
> étape a une pré-condition et un critère de vérification. **Les étapes 2 à 4
> sont IRRÉVERSIBLES pour la chaîne ouverte** : la chaîne elle-même est
> consommable (voir `docs/TESTNET.md` §2), mais refaire ces étapes ne la
> répare pas — cela produit une **nouvelle chaîne**, avec un nouvel identifiant
> de genèse.

---

## Points de centralisation assumés (à lire d'abord)

Le détail et les conséquences sont dans `docs/TESTNET.md` §0 ; les trois
points qui pèsent directement sur l'ordre des étapes ci-dessous :

- **L'archiviste est un point de centralisation réel.** Sur une source
  unique, un nœud peut mentir par omission sans qu'aucun contrôle local ne le
  démente (`docs/TESTNET.md` §0, §1.3).
- **`--temoin` n'a de valeur qu'avec au moins deux archivistes indépendants.**
  À une seule archive, la synchronisation est elle-même un point de confiance.
- **Rejoindre après le gel de la genèse exige une nouvelle chaîne.** Adresses
  et autorités sont gravées à l'étape 2 ; il n'y a pas d'ajout a posteriori
  sur la même chaîne (`docs/TESTNET.md` §0).

---

## Étape 1 — Re-test de la dette PQ (BLOQUANT)

**Pré-condition :** aucune. C'est le point d'entrée du runbook.

Rejouer et **CONSIGNER par écrit** les critères de la section
« Re-test avant le gel de genèse (gate de T5) » de `docs/BACKEND_PQ.md`. Le
gel de l'étape 2 rend le format de fil définitif : la décision « ne pas migrer
le backend post-quantique » doit être re-confirmée à cette date précise, pas
héritée d'une lecture plus ancienne.

**Critère de passage :** une trace écrite du re-test existe, même si sa
conclusion est « toujours non ». Ne pas passer à l'étape 2 sans cette trace,
quelle que soit l'urgence.

---

## Étape 2 — Gel de la genèse (IRRÉVERSIBLE)

**Pré-condition :** étape 1 consignée. Autorités et allocations décidées et
distribuées hors bande entre opérateurs (adresses `obs1…` via
`obscura-wallet adresse`, empreintes d'identité via `obscura-node --identite`).

Exécuter `obscura-genese` (voir `crates/node/src/bin/obscura-genese.rs`) :

```
obscura-genese --sortie genese.bin \
    --autorite-hex <hex-autorité-1> --autorite-hex <hex-autorité-2> … \
    --allocation obs1…:<montant> …
```

- `--autorite` / `--autorite-hex` : figent la liste des autorités de scellement
  dans l'identifiant de la chaîne. Sans aucune autorité, la chaîne est
  **OUVERTE** (n'importe quel nœud peut sceller) — vérifier que c'est le choix
  voulu avant d'exécuter.
- `--allocation <adr>:<n>` : répétable, alloue `<n>` unités à `obs1…`. Le
  nombre d'allocations est public à jamais ; une allocation unique désigne son
  bénéficiaire par sa seule position, même si montant et destinataire sont
  chiffrés.

L'outil s'**auto-vérifie** (relecture après écriture) et imprime l'identifiant
de genèse **COMPLET (64 octets)**, ainsi qu'une forme courte (8 octets) à seul
usage de comparaison visuelle rapide.

**Critère de passage :** l'identifiant complet (64 octets) est imprimé et
recueilli. C'est lui, pas la forme courte, qui sert d'ancre à l'étape 3.

---

## Étape 3 — Publication de l'ancre (IRRÉVERSIBLE)

**Pré-condition :** identifiant complet (64 octets) de l'étape 2 en main.

Renseigner `docs/GENESE.md` avec cet identifiant, puis publier la **même
valeur hors bande** (canal d'invitation, distinct du dépôt Git) : le dépôt
seul ne prouve pas qui a écrit la genèse, c'est la confrontation des deux
canaux qui protège contre une genèse substituée. Procédure complète, gabarit
et checklist de comparaison : voir `docs/GENESE.md`.

**Critère de passage :** la valeur inscrite dans `docs/GENESE.md` et la valeur
publiée hors bande sont identiques, et au moins un opérateur tiers a confirmé
la confrontation.

---

## Étape 4 — Release signée (IRRÉVERSIBLE)

**Pré-condition :** genèse gelée (étape 2) et ancre publiée (étape 3). Les
binaires à publier et le fichier de genèse sont réunis dans un répertoire
d'artefacts.

Signer avec `deploiement/signer-release.sh <repertoire> <cle-privee>` : produit
un manifeste `checksums.txt` (un artefact = une ligne) signé par minisign
(`checksums.txt.minisig`). La clé privée reste chez le signataire, jamais dans
le dépôt.

Publier la release (artefacts + `checksums.txt` + `checksums.txt.minisig`) et
`deploiement/release.pub` (clé publique minisign).

**Vérification tierce**, obligatoire avant toute annonce publique :
`deploiement/verifier-release.sh <repertoire> <cle-publique>` — sortie non
nulle si la signature ou un checksum diverge.

**Critère de passage :** `verifier-release.sh` exécuté par une tierce partie
(pas le signataire) et rapportant une release vérifiée.

---

## Étape 5 — Annonce

**Pré-condition :** étapes 1 à 4 complètes.

Publier, sur le même canal que l'invitation :

- Les limites connues, **avant** l'ouverture (`docs/TESTNET.md` §1 « Limites
  connues »).
- Le caractère consommable de la chaîne et la procédure de reset
  (`docs/TESTNET.md` §2 « Procédure de reset »).
- La règle de réaction si la chaîne acquiert une valeur malgré tout
  (`docs/TESTNET.md` §3 « Si la chaîne acquiert une valeur malgré nous »).
- Le rappel que le réseau fonctionne **sur invitation** (`docs/TESTNET.md` §0) :
  pas de bootnode public, pas de faucet, pas d'explorateur.

**Critère de passage :** les quatre points ci-dessus sont publiés avant que le
premier nœud externe ne rejoigne.

---

## Résumé des critères de passage

| Étape | Critère |
|---|---|
| 1. Re-test PQ | Trace écrite du re-test, même négative |
| 2. Gel de la genèse | Identifiant complet (64 o) imprimé et recueilli |
| 3. Publication de l'ancre | `docs/GENESE.md` et canal hors bande identiques |
| 4. Release signée | `verifier-release.sh` exécuté par un tiers, release vérifiée |
| 5. Annonce | Limites, reset et réaction à la valeur publiés avant ouverture |
