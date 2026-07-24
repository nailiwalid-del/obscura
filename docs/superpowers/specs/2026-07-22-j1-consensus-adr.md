# ADR-001 (J1) : modèle de consensus d'Obscura

**Statut :** **ACCEPTÉ** le 2026-07-22, avec la recommandation de calendrier
(J1 **avant** le gel de genèse de T5).
**Date :** 2026-07-22
**Décideur :** l'auteur du projet.
**Jalon :** J1 de `2026-07-22-portes-vers-le-mainnet-design.md`.
**Portée :** ce document tranche le MODÈLE. Il ne contient aucun code, et sa mise
en œuvre fera l'objet d'un plan séparé.

---

## Contexte

Obscura scelle aujourd'hui ses blocs par **tour de rôle sur une liste d'autorités
gravée en genèse** : `producteur_attendu(h) = autorites[(h−1) mod n]`
(`crates/ledger/src/proved_state.rs:484`). Trois propriétés du code existant
contraignent tout ce qui suit.

**1. Le ledger est append-only, sans réorganisation possible.**
`crates/ledger/src/bloc.rs:33` — « Aucune réorganisation n'est possible, par
construction ». Il n'existe aucun *fork choice*. L'état, l'historique des
sorties, la synchronisation du wallet et les ancres de preuve en dépendent tous.

**2. Le champ de scellement contient exactement UNE signature.**
`TAILLE_SCELLEMENT_MAX = 4100` octets pour une signature hybride de **3374**
octets. Un certificat de quorum n'y entre pas.

**3. Il n'existe pas d'agrégation de signatures post-quantique.**
C'est la contrainte la plus structurante, et elle découle directement de la thèse
du projet. L'astuce qui rend les BFT modernes bon marché — l'agrégation BLS,
utilisée par Ethereum — repose sur des **couplages sur courbes elliptiques**,
cassés par Shor. Adopter un consensus à quorum sous une thèse post-quantique
signifie donc porter les signatures **linéairement**, pour toujours.

### Ce que coûte un quorum, en octets réels

Mesuré par `cargo run -p node --example dimensionner-quorum --release`, sur un
budget de bloc de **1 048 444** octets :

| `n` | `f` | quorum `2f+1` | certificat | part du bloc |
|---|---|---|---|---|
| 4 | 1 | 3 | 10 122 o | **1,0 %** |
| 7 | 2 | 5 | 16 870 o | 1,6 % |
| 10 | 3 | 7 | 23 618 o | 2,3 % |
| 16 | 5 | 11 | 37 114 o | 3,5 % |
| 31 | 10 | 21 | 70 854 o | 6,8 % |
| 64 | 21 | 43 | 145 082 o | **13,8 %** |

À ~68 Kio la transaction, un bloc plein en contient ~15. Le certificat à `n = 64`
en consomme donc **l'équivalent de deux**. À `n ≤ 16`, le coût est négligeable.

### Le contexte d'exploitation, décidé le 2026-07-22

Le testnet fonctionne **sur invitation**, sans infrastructure publique
(`docs/TESTNET.md`). Les participants sont les opérateurs, en petit nombre. Cela
place le point de fonctionnement attendu à **`n` entre 4 et 10**, pas à 64.

---

## Décision

**Adopter un BFT à finalité instantanée, à comité borné, sans réorganisation —
et l'implémenter AVANT le gel de genèse de T5.**

Les sept points imposés par le jalon sont tranchés en fin de document.

Le second membre de la phrase est aussi important que le premier : voir
« Conséquence de calendrier ».

---

## Options considérées

### Option A — BFT à finalité instantanée (retenue)

Un bloc par hauteur, finalisé par un certificat de quorum **avant** d'être
étendu. Un protocole de vue avec délais permet de changer de producteur quand
celui du tour ne répond pas.

| Dimension | Évaluation |
|---|---|
| Complexité | **Élevée** — le changement de vue est là où les BFT ont historiquement leurs bugs |
| Coût en octets | 1 à 3,5 % du bloc à `n ≤ 16` ; 13,8 % à `n = 64` |
| Coût en vérification | ~43 vérifications ML-DSA par bloc au pire, ≈ une vérification STARK |
| Préserve l'acquis | **Oui, entièrement** — pas de réorg, donc ledger, historique, synchro et ancres intacts |

**Pour**
- **Ferme la liveness par construction.** Le changement de vue *est* le mécanisme
  qui empêche une autorité absente de figer la chaîne. C'est le défaut n°1 de la
  porte D, et **aucune autre option ne le ferme**.
- Rend l'absence de réorganisation **défendable plutôt que subie** : avec une
  finalité instantanée, il n'y a rien à réorganiser. La limite devient la thèse.
- Ouvre un chemin vers A sans redessiner le ledger : ouvrir l'appartenance
  devient une question d'**admission au comité**, pas de course au hachage.

**Contre**
- Exige un changement de format de bloc (voir « Conséquence de calendrier »).
- Le coût du certificat croît linéairement avec `n`, sans espoir d'agrégation
  tant que la cryptographie post-quantique n'en offre pas. **La taille du comité
  est donc bornée par le budget du bloc, définitivement.**
- C'est le plus gros chantier des trois.

### Option B — Nakamoto (chaîne la plus longue)

| Dimension | Évaluation |
|---|---|
| Complexité | **Très élevée** — exige un fork choice, donc des réorganisations |
| Coût en octets | faible (un en-tête) |
| Préserve l'acquis | **Non** |

**Pour** : anti-Sybil éprouvé, appartenance réellement ouverte, pas de liste.

**Contre, et c'est rédhibitoire** : le fork choice impose les réorganisations,
qui imposent de redessiner **l'état, l'historique des sorties, la
synchronisation du wallet et la sémantique des ancres**. C'est la seule option
qui détruise une part importante de ce qui est livré et testé. Elle réintroduit
en outre la maturité de coinbase, un champ qui n'a de sens qu'en présence
d'orphelins.

### Option C — Fédération à liste tournante

Le modèle actuel, augmenté d'une gouvernance qui fait évoluer la liste.

| Dimension | Évaluation |
|---|---|
| Complexité | **Faible** |
| Coût en octets | une signature, 3374 o |
| Préserve l'acquis | Oui |

**Pour** : de très loin le moins cher. **Et — point à ne pas escamoter — elle
suffit à l'état cible B**, dont la définition retenue est « consensus public
vérifiable, éventuellement fédéré ou expérimental ». B n'exige pas
l'appartenance ouverte.

**Contre** : elle **ne ferme pas la liveness**. Une autorité absente fige la
chaîne jusqu'à son retour, définitivement s'il ne revient pas. Elle ne prépare
rien de A : le jour où l'appartenance doit s'ouvrir, tout le travail de quorum
reste à faire, et il faudra alors changer le format — c'est-à-dire jeter la
chaîne à ce moment-là plutôt que maintenant.

---

## Analyse des arbitrages

**Le choix n'est pas entre A et C. Il est entre « faire A maintenant » et « faire
C puis A plus tard ».** B se contente de C ; la norme de conception est A. La
question est donc uniquement de calendrier — et le calendrier a un coût chiffrable.

**Ce qui départage : le format.** Un certificat de quorum n'entre pas dans
`TAILLE_SCELLEMENT_MAX`. L'adopter impose un `VERSION_BLOC 0x04`, donc un
identifiant de genèse différent, donc **une nouvelle chaîne**. Or le champ
`extension` **ne peut pas servir** de refuge : il est réservé à la coinbase et au
collecteur de frais, et lui donner un second usage rendrait sa sémantique
dépendante du contexte — exactement le genre de subtilité qui produit des bugs de
consensus.

**Le coût du report est donc un reset de chaîne, et il n'est pas symétrique.**
Sur un réseau **sur invitation**, la genèse grave les adresses `obs1…` de tous
les participants et les identités de leurs nœuds. Un reset ne coûte pas seulement
une annonce : il oblige **chaque participant à re-transmettre son adresse**, et
l'auteur à refabriquer la genèse. C'est supportable une fois ; ce serait
désagréable de le faire deux fois pour une raison connue d'avance.

**Le coût d'avancer, lui, est du temps d'ingénierie sur un chantier qui doit de
toute façon être fait sous la norme A.**

**Ce qui ne départage pas** : la taille du certificat. À `n ≤ 10` — le point de
fonctionnement réel d'un réseau sur invitation — elle plafonne à 2,3 % du bloc.
L'argument du coût en octets ne devient sérieux qu'au-delà de `n = 31`, et il
sera alors une **borne de conception**, pas une objection au modèle.

---

## Les sept points tranchés

1. **Quorum.** `2f + 1` signatures hybrides distinctes sur l'identifiant du bloc,
   avec un domaine de séparation propre au vote (distinct de
   `DOMAINE_SCELLEMENT`, pour qu'un scellement ne puisse jamais être rejoué comme
   un vote). Les votants sont désignés par un **masque de bits** sur la liste
   d'autorités — 8 octets pour 64, négligeable, et canonique.
2. **Tolérance.** `n = 3f + 1`, `f` explicitement dérivé de la liste gravée en
   genèse. `MAX_AUTORITES = 64` fixe `f ≤ 21`. **Point de fonctionnement
   recommandé : `n = 4` (`f = 1`) au lancement**, ce qui tolère la panne d'un
   participant sur quatre pour 1,0 % du bloc.
3. **Changement de vue.** Sur expiration d'un délai sans bloc à la hauteur
   attendue, la vue s'incrémente et le producteur devient
   `autorites[(h − 1 + vue) mod n]`. La vue **entre dans l'identifiant du bloc** :
   deux vues différentes produisent deux blocs différents, jamais deux encodages
   du même. Le certificat prouve l'accord sur `(hauteur, vue)`.
4. **Partitions et minorité.** Une partition qui ne réunit pas `2f + 1`
   **s'arrête** — elle ne produit rien, et ne peut donc pas diverger. C'est la
   propriété qui rend l'absence de réorganisation tenable : *on préfère
   l'arrêt à la divergence*, puisque la divergence est irréparable sur un ledger
   append-only. La minorité rattrape par le chemin normal
   (`Message::DemandeBloc`) au retour.
5. **Absence de réorganisation — défendue.** Un bloc finalisé par `2f + 1` ne
   peut pas être contredit sans que `f + 1` participants signent deux blocs à la
   même hauteur, ce qui est une faute **prouvable** (deux signatures, même
   hauteur, même vue). L'append-only cesse d'être une limitation subie : il
   devient la conséquence de la finalité. **C'est l'argument que le jalon
   exigeait.**
6. **Admission au comité.** Le mécanisme est spécifié, l'ouverture ne l'est pas :
   la liste reste **gravée en genèse pour B**. Pour A, l'admission se fera par
   caution (`stake`), ce qui suppose le mécanisme économique de J2 — donc
   l'ordre J1 → J2 → J3 de la carte est confirmé, et l'anti-Sybil reste derrière
   la porte A.

   > ⚠️ **SUPERSÉÉ par ADR-002 (J2) puis ADR-003 (D-A3, 2026-07-24).** Deux
   > affirmations de ce point sont caduques :
   > - « la liste reste gravée en genèse pour B » : **faux depuis J1-c** — la liste
   >   est reconfigurable sur la même chaîne, en B comme en A.
   > - « l'admission se fera par caution (`stake`), ce qui suppose J2 » : **rejeté.**
   >   ADR-002 a établi que J2 *rémunère* un comité sans en *ouvrir* l'appartenance ;
   >   ADR-003 a établi que le `stake` PUBLIC est incompatible avec la thèse
   >   (soldes attribuables) et l'a REJETÉ. L'admission se fait par **reconfiguration
   >   certifiée du quorum** (J1-c), pas par enjeu. Voir
   >   `2026-07-24-appartenance-anti-sybil-adr.md`.
7. **Mise à jour de la liste sans nouvelle genèse.** Prévoir dès `0x04` un
   **changement d'ensemble** : un bloc peut porter une nouvelle liste d'autorités,
   qui prend effet à `h + k` (`k` fixe, connu), et **doit être certifiée par le
   quorum de l'ANCIENNE liste**. Sans cela, changer un participant impose une
   nouvelle chaîne — ce qui est précisément la limite que ce jalon doit lever.
   ⚠️ La liste initiale reste dans l'identifiant de genèse : **deux listes
   initiales = deux chaînes**, invariant conservé.

---

## Conséquence de calendrier — la partie actionnable

La carte ordonnait `AUD → T5 → D → J1`. **Cet ordre fait jeter la chaîne de T5**,
puisque J1 impose `VERSION_BLOC 0x04`.

**Recommandation : exécuter J1 avant le gel de genèse de T5.** La rédaction de
cet ADR est faite ; ce qui reste est l'implémentation. T5 n'a pas encore gravé sa
genèse — le coût de la réorganisation du calendrier est donc **nul aujourd'hui**,
et il devient « chaque participant re-transmet son adresse » dès que la genèse
est gravée.

Si tu préfères ouvrir tout de suite, c'est légitime : la chaîne est consommable
et c'est écrit. Mais le reset devient alors **certain et daté**, plus une
possibilité — et `docs/TESTNET.md` devrait le dire à l'avance, sous peine de
transformer une décision assumée en surprise pour les participants.

---

## Conséquences

**Ce qui devient plus facile**
- La liveness cesse d'être une limite publiée : le réseau survit à `f` absents.
- L'absence de réorganisation devient un argument, pas un aveu.
- Changer un participant n'impose plus une nouvelle chaîne (point 7).
- Le chemin vers A est un changement de politique d'admission, pas de ledger.

**Ce qui devient plus difficile**
- Un chantier de protocole distribué, avec sa machine à états et ses délais —
  la partie du système où les tests déterministes sont le plus difficiles à
  écrire, et où le test de chaos existant (`chaos_producteur.rs`) devra être
  considérablement étendu.
- Le bloc grossit d'un certificat, définitivement.
- Le comité est **borné par le budget du bloc**, sans espoir d'agrégation.

**Ce qu'il faudra revisiter**
- La taille du comité si la signature hybride change de taille — donc à toute
  migration de backend PQ (`docs/BACKEND_PQ.md`). L'outil de mesure existe.
- `MAX_AUTORITES = 64` : à `n = 64` le certificat coûte 13,8 % du bloc. La borne
  devrait probablement descendre, ou être justifiée.
- Le jour où une agrégation post-quantique pratique existera, tout ce calcul
  change. Rien n'indique que ce soit proche.

---

## Actions

1. [x] **ADR accepté** (2026-07-22).
2. [x] **Ordre tranché : J1 AVANT le gel de genèse de T5.** Le réordonnancement
       ne coûte rien aujourd'hui — la genèse n'est pas gravée — et éviterait
       sinon de faire re-transmettre son adresse à chaque participant.
3. [ ] Écrire le plan d'implémentation (format `0x04` + certificat + vue +
       changement d'ensemble).
4. [ ] Étendre `chaos_producteur.rs` : `f` absents, partition, changement de vue.
5. [ ] Mettre à jour `docs/TESTNET.md` — la liveness cesserait d'être une limite.
