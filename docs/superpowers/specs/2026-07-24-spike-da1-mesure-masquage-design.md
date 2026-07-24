# Spike D-A1 — mesure du masquage de l'ouverture d'émission

**Date :** 2026-07-24
**Nature :** spike de MESURE, jetable, **hors consensus**. Ne gèle rien, ne
change aucun comportement de production.
**Objet :** remplacer la **majoration ×3** du masquage de l'ouverture d'émission
(résidu 1 de l'ADR-002) par une **mesure réelle** de taille de preuve, aux
paramètres de dev ET de consensus.
**Autorité amont :** `2026-07-22-j2-economie-adr.md` (ADR-002, résidu 1) et
`2026-07-24-decisions-A-carte.md` (fiche D-A1). Cette spec ne rouvre ni l'un ni
l'autre ; elle exécute le « sans regret » qu'ils nomment.

---

## Contexte

L'ADR-002 a mesuré l'ouverture d'émission **validity-only** : **21 227 o
(2,02 % du bloc)** aux paramètres de consensus (test `sponge::tests::mesure_ouverture`).
Ce chiffre ne cache PAS son témoin. Une émission de production exige le
**masquage** (witness-hiding, équivalent 3z-b1), dont le surcoût reste **majoré
×3** faute de mesure — d'où la borne « émission < ~6,1 % du bloc », défendable
mais non vérifiée.

Le **spike de cadrage** (2026-07-24, inline dans le résidu 1) a établi, par
raisonnement, que le masquage `BLIND_ROWS = 56` **domine** la petite trace de
l'ouverture (là où il se noie dans le monolithe), et que la preuve masquée
atterrit vraisemblablement dans **~30–55 Kio** — fourchette non tranchée sans
mesure.

Ce spike-ci produit cette mesure.

## Ce que le spike fait, et ne fait pas

| Fait | Ne fait pas |
|---|---|
| Porte le masquage `BLIND_ROWS` sur la trace de l'ouverture (`SpongeAir`) | N'intègre rien au consensus ni au ledger |
| Mesure la **taille de preuve** masquée réelle (dev + consensus) | Ne prouve pas que le masquage est **sûr** (soundness adversariale) |
| Vérifie roundtrip + inertie de l'aléa (garde-fous de mesure) | Ne touche AUCUNE ligne du sponge de production |

⚠️ **La soundness du masquage reste hors périmètre** — elle appartient à la vraie
implémentation derrière la porte A, comme la fiche D-A1 l'écrit. Le spike mesure
une DIMENSION de trace, pas une garantie ; c'est pourquoi la taille de preuve
qu'il produit est représentative même sans audit de soundness.

## La technique, transposée du monolithe

Le masquage witness-hiding du monolithe (`crates/circuit/src/monolith/`) tient en
trois gestes, tous réutilisables :

1. **Dimension.** Longueur de trace `= (lignes_utiles + BLIND_ROWS).next_power_of_two()`.
   Pour l'ouverture P7 : lignes utiles `= 32` (4 blocs × `TRACE_LEN` 8) →
   `(32 + 56).next_power_of_two() = 128`. La trace **quadruple** ; c'est la source
   du surcoût que l'on mesure.
2. **Extinction.** Une colonne périodique `blind_off` vaut `1` ssi `r + 1 <
   lignes_utiles`, `0` ensuite. Les 12 contraintes de transition sont **multipliées**
   par elle → éteintes sur le saut vers l'aléa et sur toute la région de masquage
   (identique à `blind_off` du monolithe, `seg_air.rs:213`).
3. **Remplissage.** Les lignes de masquage sont bourrées d'aléa (`OsRng`).

**Largeur inchangée** (20 colonnes : 12 état + 8 inject). Le masquage ajoute des
**lignes**, pas des colonnes — la mesure de taille est donc représentative de ce
que coûterait une ouverture masquée réelle.

**Déplacement d'assertion.** Le `SpongeAir` actuel asserte le digest à `l − 1`
(fin de trace). Sous masquage, le digest est à la **dernière ligne UTILE**
(`lignes_utiles − 1`), pas à la fin de trace. `SpongeMasqueAir` doit connaître
`lignes_utiles` pour ancrer cette assertion et pour bâtir `blind_off`.

## Architecture (Option A — module isolé)

### `crates/circuit/src/sponge_masque.rs` (nouveau, `#[cfg(feature = "dev-circuits")]`)

Un fichier autonome, réutilisant les helpers déjà `pub(crate)` de `sponge.rs`
(`enforce_sponge_transition`, `sponge_rows`, `locate`, les constantes de layout).
Il ne modifie AUCUN fichier existant hors du `mod sponge_masque;` ajouté à `lib.rs`.

- **`const BLIND_ROWS_SPONGE: usize = 56`** — local au spike, avec l'assertion de
  cohérence `BLIND_ROWS_SPONGE >= REQUETES_CONSENSUS + 4` (comme le monolithe).
- **`fn build_masked_trace(preamble: &[BaseElement], rng: &mut impl Rng) ->
  (TraceTable, usize)`** — bâtit les lignes utiles via `sponge_rows` (réutilisé
  tel quel), rallonge à `(l_utile + BLIND_ROWS_SPONGE).next_power_of_two()`,
  remplit les lignes ≥ `l_utile` d'aléa. Retourne la trace et `l_utile`.
- **`struct SpongeMasqueAir`** — porte `pi`, `l_utile`, `l`. Reprend
  `SpongeAir` avec deux différences :
  - `evaluate_transition` multiplie chaque `result[i]` par la colonne périodique
    `blind_off` ;
  - `get_assertions` ancre le digest à `l_utile − 1` ;
  - `get_periodic_column_values` ajoute la colonne `blind_off` (longueur `l`).
  - Le degré déclaré des contraintes doit inclure le facteur `blind_off`. La
    valeur exacte se **calque sur le `degrees()` du monolithe** (qui multiplie
    déjà par `blind_off` et compile) plutôt que de se deviner ; le plan
    d'implémentation la fige, et l'ajuste si winterfell refuse le degré déclaré.
- **`fn prove_sponge_masque_avec(domain, payload, public_idx, options, rng) ->
  (Digest, ValidityProof)`** et **`fn verify_sponge_masque(...) -> bool`** —
  jumeaux masqués de `prove_sponge_avec`/`verify_sponge`.

### Test de mesure `mesure_ouverture_masquee`

`#[ignore]` (comme `mesure_ouverture`), imprime aux paramètres **dev** et
**consensus** :

```
cargo test -p circuit --all-features --release --lib mesure_ouverture_masquee -- --ignored --nocapture
```

Sortie attendue (forme) : `octets | Kio | gen ms | % d'un bloc`, avec en regard
le rappel de la mesure validity-only (21 227 o) pour lire directement le **facteur
de masquage** réel.

## Garde-fous du spike (tests non-`ignore`)

Ce sont des tests de VALIDITÉ DE LA MESURE, pas de soundness :

1. **`roundtrip_masque`** — la preuve masquée vérifie, et le digest reproduit
   `rescue::note_commitment(...)` hors-circuit. Sans lui, on mesurerait la taille
   d'un circuit cassé.
2. **`inertie_du_masquage`** — deux masquages avec aléa différent produisent deux
   preuves **toutes deux acceptées** (rien ne lit l'aléa). Jumeau de
   `inertie_du_blinding` du monolithe.
3. **`digest_altere_rejete_masque`** — un digest altéré est rejeté même sous
   masquage (la région utile contraint toujours).

## Ce qui reste explicitement derrière la porte A

- La **soundness adversariale** du masquage (liaisons forgées, aléa hostile qui
  tenterait de fausser le digest) — non auditée ici.
- L'**intégration consensus** (nouvel énoncé STARK, règle de bloc, `R(h)`) —
  interdite avant que B ait tourné (garde-fou de la carte des décisions A).

## Livrable documentaire

Une fois la mesure obtenue, mettre à jour **le résidu 1 de l'ADR-002** et la
**fiche D-A1 de la carte des décisions A** : remplacer « majoration ×3 / fourchette
~30–55 Kio » par le chiffre mesuré (lu comme une **bande**, jamais une égalité —
la taille de preuve STARK varie avec le témoin et l'aléa). Ne rien graver d'autre.

## Critère de succès

`mesure_ouverture_masquee` imprime une taille de preuve masquée aux paramètres de
consensus ; les trois garde-fous passent ; aucun fichier de production n'est
modifié (seul `lib.rs` gagne une ligne `mod sponge_masque;` gatée `dev-circuits`) ;
le résidu 1 de l'ADR-002 est mis à jour avec le chiffre mesuré.
