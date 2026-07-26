# Design — Le certificat de quorum doit entrer dans le budget du bloc

**Date :** 2026-07-26
**Statut :** design approuvé (décisions prises par l'auteur), prêt pour implémentation.
**Origine :** audit externe (ChatGPT Codex, passe `crates/ledger`), constat « Élevé »,
**re-vérifié et chiffré** dans le dépôt avant d'être retenu.
**Gravité :** panne de liveness définitive sur un registre append-only.
**Fenêtre :** à corriger **avant T5** — le refus au décodage change une règle de
consensus, ce qui est gratuit tant qu'aucune chaîne n'est ouverte et impossible après.

---

## Le défaut

`Noeud::sceller` borne le bloc par `MAX_OCTETS_BLOC` en réservant la place du
**scellement** (`bloc.rs:579` : `to_bytes().len() + TAILLE_SCELLEMENT_MAX`), et le
sélecteur de mempool s'arrête au même plafond (`orchestration.rs:653`). **Ni l'un ni
l'autre ne réserve la place du certificat de quorum.**

Or `poser_vote` (`bloc.rs:658`) ajoute les signatures **sans retester la taille**, et
le bloc certifié est appliqué localement **avant** d'être diffusé
(`orchestration.rs:878-884` — « on l'applique chez nous d'abord »). Si le message
dépasse le cadre, `net::frame::ecrire_cadre` le refuse (`frame.rs:33`).

**Résultat :** le producteur applique définitivement, sur un état append-only, un
bloc que **personne ne peut recevoir**. La chaîne est coupée sans réparation possible.

### Le chiffrage — la marge réelle est de 132 octets

```
CADRE_NET        = 1 048 576
MAX_OCTETS_BLOC  = CADRE_NET − SURCOUT(68) − MARGE_MESSAGE(64) = 1 048 444
marge disponible = 132 o
coût d'UN vote   = 4 (préfixe de longueur) + 3 374 (signature hybride) = 3 378 o
```

**Un seul vote suffit donc à faire déborder un bloc rempli jusqu'à sa borne.** Il ne
faut pas un comité large — c'est ce qui rend le défaut plus grave que l'audit ne le
disait.

| `n` | quorum | coût du certificat | effet sur un bloc plein |
|---|---|---|---|
| 4 | 3 | 10 142 o | déborde si l'écart laissé par la dernière transaction < ~10 Ko (≈1 bloc plein sur 10, granularité ~100 Ko/tx) |
| 16 | 11 | 37 166 o | déborde ~1 fois sur 3 |
| 64 | 43 | 145 262 o | **déborde toujours** (dépassement ≈ 141 Ko) |

### Pourquoi les gardes existantes ne l'ont pas vu

Deux raisons, toutes deux instructives et à consigner :

1. **Le test qui garde l'invariant mesure le mauvais objet.**
   `un_bloc_scelle_tient_toujours_dans_un_cadre_reseau`
   (`orchestration.rs:1711`) sérialise un bloc **scellé**. Ce qui part sur le fil
   après quorum est le bloc **certifié**. Le doc-comment du test énonce pourtant
   l'invariant juste — « tel qu'il partira sur le fil ».
2. **La règle générale du projet existait déjà, et n'a pas été appliquée ici.**
   `orchestration.rs:563` : *« toute borne vérifiée dans `from_bytes` doit l'être
   aussi dans le constructeur, sinon elle ne protège que l'entrant. »* La borne du
   certificat **est** dans `from_bytes` (`bloc.rs:910`, majorant
   `8 + MAX_AUTORITES × (4 + TAILLE_SCELLEMENT_MAX)`), **pas** dans le constructeur.
   C'est exactement la classe de défaut que la revue adversariale avait corrigée pour
   `MAX_TX_PAR_BLOC` — le même oubli, un cran plus loin.

---

## Décision

**Réserver le coût EXACT du quorum** dans le budget du bloc, et fermer la borne aux
deux extrémités (production locale et décodage).

Le coût exact plutôt qu'un majorant : réserver
`8 + MAX_AUTORITES × (4 + TAILLE_SCELLEMENT_MAX) = 262 408 o` amputerait **25 % de la
capacité du bloc en permanence, même à `n = 4`**, et invaliderait l'analyse de budget
d'ADR-002 (qui a mesuré l'ouverture d'émission à 2,02 % du bloc). Le coût exact
est sûr parce que **le quorum à la hauteur du scellement est connu** : un changement
d'autorités ne prend effet qu'à `h + K` (J1-c).

---

## Le correctif, en quatre volets

### Volet 1 — exposer la taille réelle d'une signature hybride

Il n'existe aujourd'hui **aucune constante** pour cette taille : elle est recalculée
à `crates/crypto/src/sig.rs:195` (`1 + ED25519_SIG_LEN + mldsa65::signature_bytes()`).

Exposer dans `crypto::sig` une constante (ou une fonction `const` si
`signature_bytes()` ne l'autorise pas) valant cette somme, et **l'utiliser à
`sig.rs:195`** pour que la valeur exposée et la valeur vérifiée ne puissent pas
diverger. Ajouter un test qui confronte la constante à la taille d'une signature
réellement produite.

### Volet 2 — une fonction de coût du certificat, dans `ledger::bloc`

À côté de `cout_transaction` (`bloc.rs:203`), ajouter :

```
cout_certificat(quorum: usize) -> usize   // 8 (masque) + quorum × (4 + taille_signature)
```

Le `8` et le `4` viennent de l'encodage canonique documenté à `bloc.rs:359`
(`masque LE (8) ‖ [len(sigᵢ) LE (4) ‖ sigᵢ]`) — les dériver de là, pas de littéraux
nus.

### Volet 3 — réserver, à la production

**Dans le sélecteur** (`orchestration.rs:642-660`) : initialiser l'accumulateur avec
`SURCOUT_BLOC_VIDE + cout_certificat(quorum)` au lieu de `SURCOUT_BLOC_VIDE` seul, où
`quorum = etat.quorum_a(hauteur + 1)`.

⚠️ **Cas à traiter explicitement :** une chaîne **sans autorités** (chaîne ouverte) n'a
pas de certificat. Le coût réservé doit alors être nul, pas `8`. Vérifier ce que
`quorum_a` rend dans ce cas et ne pas réserver à vide.

⚠️ **À vérifier au passage, sans élargir le périmètre :** `SURCOUT_BLOC_VIDE`
(`bloc.rs:178`) vaut `1 + TAILLE_ID + 8 + 4 + 4`. Le format `0x05` porte aussi `vue`,
`autorites` et `changement_autorites`. Si ce surcoût sous-estime l'en-tête réel, le
signaler dans le rapport — **ne pas le corriger dans ce cycle** sans le dire.

**Dans `sceller`/`sceller_changement`** (`bloc.rs:579`, `:623`) : la vérification doit
porter sur le bloc **tel qu'il partira certifié**. Ajouter le coût du certificat au
calcul, ce qui suppose de faire connaître le quorum à ces fonctions (paramètre
explicite plutôt qu'accès à l'état — `ledger::bloc` ne doit pas dépendre de
`ProvedLedgerState`).

### Volet 4 — refuser, au décodage et à l'application

- **`Bloc::from_bytes`** (`bloc.rs:773`) : refuser d'emblée si
  `b.len() > MAX_OCTETS_BLOC`, **avant** tout décodage de champ. La variante d'erreur
  existe déjà (`bloc.rs:292`, message « bloc de {octets} o : indiffusable ») —
  réutiliser celle-là, ne pas en créer une seconde.
- **`appliquer_bloc`** (`proved_state.rs:732`) : refuser un bloc hors borne **avant
  toute vérification coûteuse** (donc avant le quorum et avant les preuves STARK),
  conformément à l'ordre déjà documenté (bornes O(1) → chaînage → scellement →
  quorum → STARK).
  ⚠️ `appliquer_bloc` reçoit un `&Bloc`, pas des octets : mesurer exige une
  sérialisation. C'est O(taille), négligeable devant une vérification STARK, mais
  **dis-le dans le rapport** si tu vois un moyen de l'éviter.

---

## Tests rouges exigés (TDD — écrire l'échec d'abord)

L'ordre importe : **chaque test doit être vu ROUGE avant le correctif**, et sa sortie
d'échec consignée dans le rapport. Un test écrit après le correctif ne prouve rien.

1. **`un_bloc_CERTIFIE_tient_toujours_dans_un_cadre_reseau`** — le test central, à
   `n = 64` : remplir le mempool, sceller jusqu'à la borne, assembler un quorum de 43
   votes, puis affirmer
   `Message::Bloc(certifie).to_bytes().len() + crypto::aead::SURCOUT <= net::MAX_CADRE`.
   **Doit échouer aujourd'hui.**
2. **Le même à `n = 4`**, en construisant un bloc dont l'écart au plafond est
   inférieur au coût du certificat. Si le cas n'est pas atteignable avec les tailles
   de transaction réelles, **le dire** plutôt que de forcer le test.
3. **`from_bytes` refuse un bloc hors borne** — fabriquer des octets dépassant
   `MAX_OCTETS_BLOC` et exiger la variante d'erreur d'indiffusabilité.
4. **`appliquer_bloc` refuse avant le STARK** — montrer que le refus tombe sans
   qu'aucune preuve ne soit vérifiée.
5. **Non-régression de capacité** : à `n = 4`, un bloc doit encore contenir un nombre
   de transactions raisonnable (la réservation ne doit pas vider le bloc). Nommer le
   nombre obtenu avant/après dans le rapport.

Le test existant `un_bloc_scelle_tient_toujours_dans_un_cadre_reseau` **reste** — il
garde le scellement. Son doc-comment doit dire qu'il ne couvre PAS le certificat, et
renvoyer au nouveau test.

---

## Divergences documentaires à corriger dans le même cycle

Ces trois-là sont des affirmations fausses, indépendamment du correctif. Deux ont été
trouvées deux fois (audit interne **et** externe).

- **D1** — `docs/ARCHITECTURE.md:85-90` et `docs/THREAT_MODEL.md:259-262` affirment
  que `MAX_OCTETS_BLOC` est « vérifié au scellement ET au décodage ». C'était faux ;
  le volet 4 le rend vrai. **Mettre le texte en accord avec le code final**, et dire
  ce qui borne quoi (constructeur, décodeur, cadre réseau).
- **D2** — `docs/PROTOCOL.md:196-198` affirme qu'un bloc `0x03` **ou** `0x04` rend
  `VersionPerimee`. Le code ne nomme que `0x04` (`VERSION_BLOC_PERIMEE`, `bloc.rs:153`) ;
  `0x03` rend `VersionInconnue`. Corriger le document, ou nommer `0x03` dans le code —
  **choisir, et écrire pourquoi**. (Recommandation : corriger le document ; aucune
  chaîne n'a existé en `0x03`, et le décodeur n'a pas à connaître un format qui n'a
  jamais circulé.)
- **D3** — `docs/PROTOCOL.md:28-33, 61-62, 165-166` décrit la migration Rescue-Prime
  comme FUTURE (« migrera ») alors qu'elle est faite et constitue le chemin de
  consensus. Le modèle BLAKE3/`dual_hash`/`PRF_nk` décrit correspond au mode
  `dev-transparent` (hors consensus, feature OFF par défaut). Réécrire au passé et
  cantonner la description BLAKE3 à la section « mode transparent ». Le document se
  contredit déjà lui-même (`:453-456` marque ✅ la migration).

---

## Ce que ce cycle ne fait pas

- Il **ne change aucun format de fil** : les tailles réservées changent la capacité
  utile d'un bloc, pas son encodage. Aucun `VERSION_BLOC` nouveau.
- Il **n'implémente pas** l'économie (ADR-002 reste derrière la porte A).
- Il **ne rouvre pas** les deux autres points ouverts de l'audit interne (l'invariant
  `try_into` de `ARCHITECTURE.md:45-46`, et la re-vérification des benchmarks de
  preuve) — ils restent à arbitrer séparément.
- Il **ne corrige pas** `SURCOUT_BLOC_VIDE` s'il s'avère sous-estimé : le constat est
  demandé, la correction non (voir volet 3).

## Critère de franchissement

Les cinq tests passent, **le n°1 ayant été vu rouge avant le correctif** ; la suite
complète (`cargo test --workspace --release --all-features`) reste verte ; et
`ARCHITECTURE.md`, `THREAT_MODEL.md` et `PROTOCOL.md` ne portent plus d'affirmation
contredite par le code.
