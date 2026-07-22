# Portes vers le mainnet — carte de décision

**Date :** 2026-07-22
**Objet :** les quatre portes que `2026-07-22-testnet-public-0-design.md` avait
écartées comme « non planifiables » — audits, consensus public défendable,
économie, durcissement.
**Statut :** carte d'arbitrage validée, **révision 3**.
**Révisions :** r1 initiale · r2 (B falsifiable, J2 démoté, T5 devient une porte)
· r3 (nommage ACVP non surpromis, fixture de conformité, gel suspensif corrigé et
réattribué à J1, règle de réaction à la valeur).
**Ce document ne contient aucun spec implémentable** ; chaque porte obtient
ensuite son propre cycle spec → plan.

---

## Décisions prises (utilisateur, ne pas remettre en cause)

1. **Destination : B comme état cible livrable, A comme norme de conception.**
   On construit sous le modèle d'adversaire d'un mainnet — quelqu'un qui a un
   motif de profit — parce que c'est le seul modèle qui rende le travail
   honnête. On ne livre que jusqu'à B, et on n'engage aucune dépense externe
   tant que B n'est pas atteint et stable.
2. **Posture publique : B. Norme interne : A.** Viser A en ingénierie ne coûte
   rien ; *l'annoncer* crée l'attente, l'exposition juridique, et contredit la
   règle déjà écrite (« aucune communication du type monnaie utilisable »).
3. **Ordonnancement : deux voies séparées par leur réversibilité**, et non une
   séquence unique. **T5 n'appartient à aucune des deux** : c'est un événement
   qui les traverse — il ne gèle rien de définitif (la chaîne est consommable)
   mais il engage une dépense et une audience.
4. **Branchement : ouvrir d'abord** (porte T5), les portes mainnet s'appliquent
   ensuite à un réseau vivant. Une chaîne de testnet est **consommable**.
5. **Ce document est une carte, pas un plan.** Le premier spec implémentable est
   celui de la porte **AUD**.

### B, en une phrase falsifiable

> **B = un réseau public expérimental, sans valeur, dont un tiers peut vérifier
> l'état à partir de la seule documentation, redéployable à volonté, et dont le
> consensus n'est PAS permissionless.**

Chaque terme est un critère, et chacun est réfutable :

| Terme | Réfuté par |
|---|---|
| *public* | une adresse de bootnode non publiée, une release non taguée |
| *sans valeur* | tout mécanisme d'échange, tout faucet devenu marché |
| *vérifiable par un tiers* | un tiers qui doit lire le code pour valider un bloc |
| *redéployable* | une remise à zéro qui exige autre chose qu'une nouvelle genèse et une annonce |
| *non permissionless* | un participant inconnu qui produit un bloc accepté |

⚠️ **Cette phrase existe pour empêcher un glissement.** Sans elle, B devient un
mini-mainnet par accumulation de petites décisions raisonnables, dont aucune
n'est le moment où l'on a changé d'avis.

### Ce que A et B exigent, et où ils divergent

| Porte | Commun à A et B | Ce que **A seul** ajoute |
|---|---|---|
| **Durcissement** | tout | **rien** |
| **Audits** | être auditable : spec gelée, vecteurs ACVP ciblés, fixture de conformité, surface réduite, bug bounty | passer commande (argent, calendrier subi) |
| **Économie** | le **mécanisme spécifié** : coinbase prouvée, collecteur de frais | son **implémentation** et la politique (courbe, halving, queue) |
| **Consensus** | **consensus public vérifiable, fédéré ou expérimental** : finalité défendue, partitions, mise à jour, négociation de version | **ouverture de l'appartenance + anti-Sybil économique réel** |

⚠️ **Correction de la révision 1.** La première version listait « élection
ouverte » comme commune à A et B, et « anti-Sybil à coût réel » comme propre à A.
C'était incohérent : **une élection ouverte sans coût anti-Sybil n'est pas
ouverte, elle est simplement non authentifiée.** Les deux vont ensemble ou pas
du tout, et ils vont ensemble derrière la porte A.

Trois lectures de ce tableau, et elles fondent tout le reste :

- Sur deux portes, **A et B ne divergent pas du tout**. « Être auditable » est un
  préfixe strict de « être audité » : aucun travail n'est perdu si la commande
  vient plus tard.
- La divergence porte sur l'**implémentation** de l'économie et sur
  l'**ouverture** du consensus — deux choses qui n'ont de sens qu'avec de la
  valeur en jeu.
- **Ce qui reste commun est le travail de spécification**, pas de code : décrire
  le mécanisme économique assez précisément pour valider que la réservation de
  format suffit, et défendre le modèle de consensus par écrit.

---

## Constats de vérification (2026-07-22, `HEAD = 46694b0`)

Trois écarts entre le code et ce que les documents annoncent. Tous vérifiés dans
les fichiers, pas déduits.

### Constat 1 — deux sources de vérité, toutes deux périmées

`CLAUDE.md:448` écrit encore : « les `SecretKey` pqcrypto (Kyber768/Dilithium3)
NE s'effacent PAS (limitation crate) — à fermer à la migration FIPS `0x02` ».
**Doublement faux** : la dette est fermée (repli T1.5, `Zeroizing<Vec<u8>>` +
reconstruction du type — `crates/crypto/src/kem.rs:50`,
`crates/crypto/src/sig.rs:49`), et les noms cités sont ceux du round-3,
abandonnés depuis T1.

Et il n'y a pas un document mais **deux** : `AGENTS.md` (345 l., version Codex)
et `CLAUDE.md` (457 l.), **divergents**. Deux sources de vérité qui dérivent
séparément valent moins que zéro.

### Constat 2 — aucun vecteur de conformité n'existe

Aucun fichier de `crates/` ne contient de vecteurs KAT/ACVP ;
`crates/crypto/tests/` n'existe pas. C'était un **critère de sortie de T1**
(§T1.6), dont le texte disait : « c'est la première chose qu'un auditeur
demandera ». **T1 a été déclaré terminé sans son critère de sortie le plus
important pour la suite.** Un critère non vérifié ne vaut pas mieux que pas de
critère.

⚠️ **Nommage.** Ce document ne dit jamais « vecteurs KAT » sans qualificatif, et
ne dira jamais « KAT FIPS complets ». Ce qui est réalisable avec le backend
actuel est un sous-ensemble — voir la stratégie en porte AUD. Le terme retenu
partout est **« vecteurs ACVP ciblés (`decap`/`sigVer`) »**. Une surpromesse dans
un titre est exactement ce qu'un auditeur relève en premier, et elle décrédibilise
le travail réel qui est dessous.

### Constat 3 — l'ancre de genèse est tronquée là où elle sert

`obscura-genese` imprime l'identifiant **complet** (32 o) *et* sa forme courte
(`crates/node/src/bin/obscura-genese.rs:242`). Mais `obscura-node` n'imprime que
**8 octets** au démarrage (`crates/node/src/bin/obscura-node.rs:289`) —
c'est-à-dire exactement au moment où un opérateur compare avec la valeur publiée
hors bande. 64 bits comme ancre d'authentification d'une chaîne publique, c'est
court.

✅ **Fermé le 2026-07-22 (`2e9e4df`).** L'identifiant est imprimé entier ; la tête
courante reste courte (diagnostic, pas ancre). Le correctif n'a pas attendu T5 :
une ligne sans risque n'a aucune raison d'être mise en file d'attente derrière une
porte.

À rapprocher de `docs/THREAT_MODEL.md:381` : « **Rien n'atteste QUI a écrit la
genèse. Le fichier n'est ni signé ni authentifié** ». Pour un testnet public,
c'est la porte T5 qui doit fermer ça.

---

## Partie I — La structure de la carte

### Ce qu'est une porte

Pas une tâche : une fiche à six entrées, toujours les mêmes.

1. **État vérifié** — ce que le code fait, avec fichier et ligne. Pas ce que la
   doc affirme (cf. constats ci-dessus).
2. **Ce qui manque** — l'écart énoncé comme un **défaut**, jamais comme une
   fonctionnalité. Un défaut se ferme ou s'inscrit dans les limites connues ; une
   fonctionnalité se reporte indéfiniment.
3. **Dépend de** — quelles portes précèdent.
4. **Gèle quoi** — format de fil, format de bloc, énoncé STARK, genèse.
5. **Critère de franchissement** — une phrase **falsifiable**.
6. **Coût, et qui le paie** — en particulier ce qui n'est pas du temps
   d'ingénierie.

### Les deux voies

```
VOIE SANS REGRET  ──────────────────────────────────────────►  (continue)
  AUD. Auditabilité · D. Durcissement
  ne gèle rien · ne dépend de rien · jamais jeté

T5. OUVERTURE  ──►  chaîne publique consommable

VOIE IRRÉVERSIBLE  ──►  J1 Modèle  ──►  J2 Mécanisme  ──►  J3 Consensus
                        (ADR)           (SPÉCIFIÉ)         (périmètre B)
  gèle des formats · strictement séquencée en interne
```

La voie sans regret n'a pas de fin : c'est un **régime de travail**, pas un
chantier. Elle **démarre immédiatement et tourne en parallèle de T5** — elle
n'attend rien, puisqu'elle ne dépend de rien.

**Pourquoi cette séparation plutôt qu'une séquence.** Auditabilité et
durcissement ne dépendent réellement de rien : les bloquer derrière une décision
de consensus qui peut prendre des mois est du gaspillage pur, et ce sont
justement les deux dont le résultat n'est jamais perdu.

---

## Partie II — Les fiches

### Porte AUD — Auditabilité *(première porte)*

**État vérifié.** `PROTOCOL.md` (235 l.), `THREAT_MODEL.md` (738 l.),
`STARK_STATEMENT.md` (695 l.) ; gating dev/consensus effectif ; double licence ;
dépôt public.

**Ce qui manque — trois défauts.**

**1. Les vecteurs ACVP ciblés `decap`/`sigVer` (constat 2).** Le moins cher et le
plus rentable. C'est ce qui distingue « on a changé d'import » de « on implémente
bien FIPS 203/204 » — **sur la partie qu'on peut effectivement démontrer**.

> **Stratégie — à écrire avant de commencer, parce que le backend la contraint.**
> Vérifié : `pqcrypto_mlkem::mlkem768::keypair()` ne prend **aucun argument** — il
> n'existe aucune injection de graine officielle. `keyGen`, `encap` et `sigGen` ne
> sont donc **pas** KAT-ables avec ce backend.
>
> Mais les deux opérations **déterministes** le sont : `decapsulate(ct, sk) → ss`
> et `verify(sig, msg, pk)`, les deux types se reconstruisant depuis des octets
> (le projet le fait déjà pour le zeroize). **Or ce sont exactement les chemins
> critiques du consensus** : un nœud vérifie des signatures et décapsule ; il ne
> rejoue jamais le keygen d'autrui.
>
> **Donc : vecteurs ACVP officiels complets sur `decap` et `sigVer` ; trou nommé
> et documenté sur `keyGen`/`encap`/`sigGen`, avec sa raison (backend sans
> injection d'aléa).** Ce trou devient un critère de re-test du backend PQ, à
> ajouter à ceux de `docs/BACKEND_PQ.md`.

**2. Il y a deux sources de vérité, et un auditeur ne lira ni l'une ni l'autre
(constat 1).** `CLAUDE.md` et `AGENTS.md` sont les documents les plus détaillés
du dépôt, ils divergent, et ils sont structurés comme des notes d'agent. Tant que
`docs/` en est un résumé, un audit porterait sur un texte incomplet. Il ne s'agit
pas d'écrire plus, mais de **déplacer l'autorité vers `docs/`** et de réduire
`CLAUDE.md`/`AGENTS.md` à des pointeurs.

**3. L'argument HVZK est honnête-vérifieur et non audité.** Seul morceau qui ne
peut pas être préparé seul : il exige un spécialiste circuit/AIR. Sous B, la
préparation consiste à rendre l'énoncé **attaquable** — hypothèses isolées, ce
qui est prouvé séparé de ce qui est supposé.

**Dépend de :** rien pour (1) et (2). Le bug bounty dépend d'une cible publique,
donc de T5.
**Gèle :** rien — mais **consomme** un gel, un audit portant sur une spec figée.
**Critère de franchissement :** les vecteurs ACVP ciblés `decap`/`sigVer` passent
en CI ; **la fixture de conformité existe et un tiers la rejoue** (voir
ci-dessous) ; `CLAUDE.md` et `AGENTS.md` ne contiennent plus aucune affirmation
normative.

> **La fixture de conformité — parce que « un tiers vérifie en n'ayant lu que
> `docs/` » est un bon critère mais intestable tel quel.** Il faut un artefact,
> versionné dans le dépôt :
>
> - la **genèse** de référence (octets) et son identifiant complet attendu ;
> - **un bloc scellé** appliqué dessus ;
> - la **racine d'état attendue** après application ;
> - **la commande** qui rejoue tout ça, et son résultat attendu.
>
> Le critère devient alors falsifiable en une exécution : la commande sort le bon
> identifiant et la bonne racine, ou elle ne les sort pas. C'est aussi ce qui
> rend le reste de `docs/` vérifiable — une spec dont on peut rejouer un exemple
> se corrige toute seule.
**Coût :** temps d'ingénierie seul. **Zéro dépense externe** — c'est la
définition d'« être auditable » plutôt qu'« être audité ».

### Porte T5 — Ouverture

**État vérifié.** L'outillage existe : `obscura-genese` (refuse d'écraser,
auto-vérifie, imprime l'identifiant complet), `obscura-node --identite`,
`--archiver`, témoin de synchronisation, `deploiement/{service,Dockerfile}`,
`docs/OPERATEUR.md`.

**Ce qui manque — la checklist d'ouverture, dont rien n'est fait :**

| # | Élément | Pourquoi il ne peut pas être omis |
|---|---|---|
| 1 | **Genèse signée ou hash officiel publié hors bande** | `THREAT_MODEL.md:381` — rien n'atteste qui a écrit la genèse |
| 2 | ~~**`obscura-node` imprime l'identifiant COMPLET**~~ ✅ `2e9e4df` | constat 3 — 64 bits là où l'opérateur compare |
| 3 | **Bootnodes**, majoritairement **sans** `--archiver` | le rôle bon marché, et celui qui sert l'anti-eclipse |
| 4 | **Release taguée + checksums + signature** | sans quoi le binaire n'est pas plus authentifié que la genèse |
| 5 | **Limites connues publiées AVANT l'ouverture** | y compris : la chaîne est consommable, elle sera refaite |
| 6 | **Procédure de reset écrite** | une remise à zéro non écrite d'avance sera vécue comme un échec |
| 7 | **Canal d'incident** | un réseau public sans adresse de signalement est une impasse |
| 8 | **Politique de frais du testnet** | voir ci-dessous — c'est le seul morceau d'économie qui appartient à B |
| 9 | **Règle de réaction si la valeur apparaît** | voir ci-dessous — un déclencheur sans geste n'est pas une défense |

> **Pourquoi la politique de frais est ici et pas dans J2.** `fee` est une
> **entrée publique du STARK** (`crates/circuit/src/monolith/seg_air.rs:1423`) et
> un champ public de `ProvedTx`. Si le wallet laisse l'utilisateur choisir ses
> frais, **le montant devient un discriminant public dès l'ouverture** — une
> empreinte, sur un projet dont toute la thèse est la confidentialité. Frais
> constants ⇒ pas d'empreinte. C'est une décision de T5, bon marché, et elle ne
> peut pas attendre J2.

> **La règle de réaction — parce qu'un déclencheur sans geste n'est pas une
> défense.** La partie III inscrit « toute valeur réelle » comme déclencheur du
> cadre légal. Ça ne suffit pas : le jour où des jetons de testnet s'échangent, il
> faut un geste **déjà écrit**, sinon la décision se prendra sous pression, mal et
> tard. Escalade, du moins grave au plus grave :
>
> 1. **Constat public.** Rappel écrit que la chaîne est sans valeur et
>    consommable, sur les mêmes canaux que l'annonce d'ouverture.
> 2. **Pause du faucet.** Il est le robinet ; le fermer coupe l'entrée de
>    « stock » sans toucher au réseau.
> 3. **Reset annoncé.** Nouvelle genèse, ancienne chaîne abandonnée. C'est
>    l'usage prévu (chaîne consommable) et **le simple fait qu'il soit connu
>    d'avance décourage la spéculation** — personne ne valorise ce qui sera remis
>    à zéro.
> 4. **Fermeture.** Arrêt des bootnodes et de l'archiviste, dépôt archivé.
>
> **Ce qui déclenche quoi doit être écrit avant l'ouverture, pas au moment des
> faits.** L'escalade elle-même fait partie des limites publiées : un réseau dont
> on sait qu'il sera remis à zéro n'acquiert pas de valeur par accident.

**Dépend de :** rien de bloquant. **Gèle :** la genèse de *cette* chaîne — pas
le projet, puisqu'elle est consommable.
**Critère de franchissement :** un tiers monte un nœud depuis la release
publiée, rejoint la chaîne, et **vérifie l'identifiant de genèse complet contre
la valeur publiée hors bande**.
**Coût :** infrastructure (VPS bootnodes + au moins un archiviste). Première
dépense externe réelle du projet. L'archiviste croît sans borne (≈1,4 Kio/sortie)
et **est le point de centralisation du réseau** — à nommer comme tel dans les
limites publiées.

⚠️ **Le prix assumé de T5 :** la genèse sera figée **avant** que l'économie soit
décidée. `extension` est réservée et entre dans l'`id`, donc le format ne sera
pas refondu — mais la chaîne, elle, sera refaite. C'est le fonctionnement normal
d'un testnet, **à condition que ce soit écrit d'avance et pas subi**.

### Porte D — Durcissement

**État vérifié.** Beaucoup est fait, et c'est solide : fuzzing des deux anneaux,
CI à six jobs sur deux plateformes, décodage borné avant allocation partout,
échéances de socket posées avant le handshake, étranglement indexé sur
`GroupeReseau`, atomicité d'`appliquer_bloc`, zeroize — clés PQ comprises.

**Ce qui manque — quatre défauts.**

1. **Une autorité absente fige la chaîne jusqu'à son retour** — et le
   comportement de gel puis de reprise n'est pas testé.

   ⚠️ **Correction de la révision 2**, qui écrivait « fige la chaîne
   **définitivement** ». C'est faux : `producteur_attendu(h) =
   autorites[(h−1) mod n]` (`crates/ledger/src/proved_state.rs:484`) est une
   fonction pure de la hauteur — personne d'autre ne peut produire `h`, mais
   l'autorité qui revient produit `h` et la chaîne repart. Le gel est
   **suspensif**, pas terminal.

   **Et le défaut ainsi corrigé n'appartient plus entièrement à D.** Il faut
   séparer deux propriétés que la révision 2 confondait :

   | Propriété | Porte |
   |---|---|
   | le réseau **s'arrête proprement et reprend proprement** — pas d'état corrompu, pas de scission, pas de bannissement de pairs, mempool préservé, wallets qui rattrapent | **D** |
   | le réseau **continue à produire malgré l'absence** | **J1** — c'est un changement de vue, rien d'autre |

   D livre donc un **test de chaos** (producteur absent, puis de retour) et
   l'inscription du gel suspensif dans les limites connues. **Fermer** le gel est
   le travail de J1.
2. **Le fuzzing ne peut pas atteindre la logique de validation.** Un fuzzer
   aléatoire ne produira jamais une preuve STARK valide : `ProvedTx::from_bytes`
   est fuzzé, mais tout ce qui est **derrière** le décodeur ne l'est pas. Il
   manque du fuzzing *structure-aware* — générer des transactions valides puis
   muter les champs sémantiques (ancre, nullifiers, forme `m`/`n`).
3. **La dette backend PQ n'a pas d'échéance portée par un jalon.** Voir
   partie III.
4. **Les canaux auxiliaires ne sont pas dans le modèle.** Sous une thèse
   post-quantique, le temps constant des opérations ML-KEM/ML-DSA est une
   question légitime, et `THREAT_MODEL.md` ne la traite pas. Ce n'est peut-être
   pas un chantier — mais l'absence doit être **décidée**, pas subie.

**Dépend de :** rien. **Gèle :** rien.
**Critère de franchissement :** le producteur est arrêté puis redémarré, et la
chaîne **reprend exactement où elle s'était arrêtée** — même hauteur suivante,
aucune transaction perdue du mempool, aucun pair banni pendant le gel, tout wallet
qui se resynchronise obtient la même racine qu'avant. (Le réseau **ne produit pas**
pendant l'absence : c'est attendu, c'est écrit dans les limites, et c'est J1 qui
le changera.) Le fuzzing sémantique tourne au budget nocturne sans crash ;
les quatre défauts sont soit fermés, soit inscrits dans les limites connues
**avec leur raison**.
**Coût :** temps d'ingénierie seul.

### Jalon J1 — Le modèle de consensus *(un ADR, pas du code)*

**Livrable : un ADR — décision d'architecture tranchée et défendue.** C'est le
jalon le moins coûteux en lignes et le plus coûteux en conséquences.

**État vérifié.** `crates/ledger/src/bloc.rs:33` — « Aucune réorganisation n'est
possible, par construction » ; aucun fork choice nulle part. Un producteur
légitime par hauteur, tour de rôle `autorites[(h−1) mod n]`.

**L'espace de choix, et son asymétrie.**

| | Préserve l'acquis ? | Anti-Sybil | Coût |
|---|---|---|---|
| **(i) BFT à finalité instantanée** | **oui, entièrement** | admission au comité (A) | protocole de vue, quorum, messages en O(n²) |
| **(ii) Nakamoto (chaîne la plus longue)** | **non** — exige un fork choice, donc des réorgs, donc la refonte du ledger, de l'historique, de la synchro wallet et des ancres | éprouvé | énorme, et il jette une part importante de ce qui est livré |
| **(iii) Fédération à liste tournante** | oui | faible | modeste |

**L'argument à ne pas manquer.** L'architecture actuelle — append-only, sans
réorg, un producteur légitime par hauteur — **est déjà un BFT dégénéré**.
L'évolution naturelle n'est donc pas Nakamoto mais un BFT dont l'appartenance
*pourra* s'ouvrir. Dans ce monde, « défendre un modèle sans réorg » n'est pas une
excuse : c'est la thèse.

Et surtout : **c'est ici, et nulle part ailleurs, que le gel suspensif se ferme.**
Un BFT a besoin d'un protocole de vue avec délais et changement de vue —
exactement le mécanisme qui fait qu'une autorité absente ne fige plus la chaîne.
D constate le gel et le rend propre ; **seul J1 le supprime.** Aucune des deux
autres options ne le fait : (ii) le remplace par une course, (iii) le conserve.

**L'ADR doit trancher, explicitement, sept points :** quorum ; hypothèse de
tolérance (`n = 3f+1` ou autre, avec `f` énoncé) ; changement de vue ; partitions
et comportement en minorité ; absence de réorg **défendue** et non subie ;
admission au comité (le mécanisme, même si l'ouverture reste derrière A) ; mise à
jour de la liste d'autorités sans nouvelle genèse.

**Dépend de :** rien. **Gèle :** l'architecture.
**Critère de franchissement :** un tiers hostile ne peut pas produire deux
chaînes valides divergentes de même hauteur sans violer une hypothèse **écrite** ;
et le réseau reprend après défaillance de `f` participants, avec `f` énoncé.
**Coût :** faible en lignes, élevé en lecture — le livrable est un argument.
Aucune dépense externe.

### Jalon J2 — Le mécanisme économique *(SPÉCIFIÉ, non implémenté)*

**Statut révisé.** La révision 1 plaçait l'implémentation en B. **C'était une
erreur, révélée en corrigeant le point précédent :** l'argument de la coinbase
est le budget de sécurité, qui est un argument **A**. Sous une fédération de
volontaires, personne n'a besoin d'être payé — et le coût de reporter est
**quasi nul**, puisque `extension` est déjà réservée et entre dans l'`id`.
C'était tout l'intérêt de la réserver.

**Livrable en B : l'ADR du mécanisme, assez précis pour valider que la
réservation de format suffit. L'implémentation du circuit part derrière A.**

**La question de liaison, qui reste.** Aujourd'hui la règle est
`hauteur > 0 ⇒ emissions.is_empty()`, contrôle O(1)
(`crates/ledger/src/proved_state.rs:592`), et `mint` est privée. **C'est la seule
chose qui empêche l'inflation.** Une coinbase relâche précisément cette règle.

Le montant **n'a pas besoin d'être secret** : s'il suit un calendrier public, il
est déjà dérivable de la hauteur, et le publier ne fuit rien. Ce qui doit rester
caché est le **bénéficiaire**, et le commitment s'en charge. Mais comme le
commitment cache la valeur, il faut prouver qu'il **ouvre sur exactement
`R(h)`**. La question n'est donc pas « preuve ou pas de preuve » mais **« quelle
taille de preuve d'ouverture »** — un circuit petit, sans commune mesure avec
celui d'une transaction.

Le design l'a anticipé : `Emission { commitment, enc_note }` est délibérément
sans `Option`, pour ne pas vider le witness-hiding « le jour d'une coinbase »
(`crates/ledger/src/bloc.rs:73`).

**Résiduel à écrire, pas à résoudre :** une note de coinbase a une valeur
publiquement connue, ce qui la marque au moment de sa dépense ultérieure. Zcash
et Monero vivent avec.

**Le destin des frais.** Aujourd'hui brûlés (`Σin = Σout + fee`, aucun
collecteur). L'ADR doit comparer au moins : **frais fixes**, **frais par
paliers**, **frais retardés ou groupés** — l'objectif étant de réduire le pouvoir
discriminant du champ public `fee`. La politique du testnet, elle, est tranchée
en T5.

**Dépend de :** J1 — *la maturité de coinbase n'existe qu'en présence de
réorgs*. Bitcoin impose 100 blocs de maturité uniquement parce qu'une récompense
sur un bloc orphelin doit pouvoir être défaite ; avec une finalité instantanée, le
champ disparaît. Spécifier l'économie avant le modèle, c'est risquer d'écrire une
règle qui n'a de sens que dans un monde qu'on n'a pas choisi.
**Gèle :** rien en B (l'ADR ne grave rien). En A : le contenu d'`extension`,
l'énoncé STARK, la règle d'émission.
**Critère de franchissement (B) :** l'ADR démontre que `extension` telle que
réservée suffit à porter le mécanisme décrit, sans nouveau `VERSION_BLOC`.
**Coût (B) :** rédaction. **Coût (A) :** le plus élevé du projet — nouvel énoncé
STARK, re-bench, re-audit de soundness, regel de format.

### Jalon J3 — Le consensus, périmètre B

**Statut révisé.** « Le réseau accepte un participant inconnu » était le critère
de la révision 1 : **c'est un critère A**, puisque l'ouverture de l'appartenance
et l'anti-Sybil partent ensemble derrière A. Ce qui reste en B est plus petit et
plus honnête.

**Périmètre B :** partitions et comportement en minorité ; procédure de mise à
jour ; **négociation de version de fil formalisée**.

**État vérifié.** `Message::version_inconnue()` distingue déjà « version future »
de « malformation » et ne sanctionne pas la première — suffisant pour ne pas
partitionner un testnet, insuffisant au-delà.

**Dépend de :** J1. **Gèle :** le format de fil.
**Critère de franchissement (B) :** le réseau survit à une partition et se met à
jour sans fork non intentionnel.
**Hors périmètre (A) :** admission ouverte, anti-Sybil, et son coût chiffré.
**Coût :** tests multi-nœuds ; c'est le jalon qui exige le plus d'exploitation
réelle.

---

## Partie III — Ce qui reste ouvert

### Décisions A, avec leurs critères de déclenchement

Sur le modèle de `docs/BACKEND_PQ.md` : une décision écrite « pas maintenant »,
accompagnée de ce qui la ferait rouvrir.

| Décision | Ne se pose qu'après | Critère de déclenchement |
|---|---|---|
| Implémentation de la coinbase | J2 (ADR) livré | quelqu'un propose d'attribuer une valeur |
| Courbe d'émission | coinbase implémentée | idem |
| Ouverture de l'appartenance + anti-Sybil | J1 et J3 livrés | idem |
| Achat des audits | AUD franchie **et** spec gelée | budget disponible **et** spec stable depuis ≥ 3 mois |
| Cadre légal | — | toute valeur réelle, tout échange, tout faucet devenant marché |

### Une échéance à accrocher, sinon elle se perd

**La dette backend PQ doit être re-testée avant le gel de genèse.**
`BACKEND_PQ.md` l'écrit ; aucun jalon ne la portait. Elle est accrochée à T5 :
**avant d'exécuter `obscura-genese` en production**, les critères de
`BACKEND_PQ.md` sont rejoués et le résultat écrit — **même si c'est « toujours
non »**. La stratégie ACVP ajoute un critère à cette liste : *un backend
permettant l'injection d'aléa officiel rendrait `keyGen`/`encap`/`sigGen`
vérifiables, et supprimerait le trou nommé en porte AUD*.

### Une omission nommée

La liste des quatre portes remplace « cadre légal » du document de juillet par
« durcissement ». Sous B, c'est défendable : sans valeur réelle, l'exposition est
faible. Mais **ce doit être une décision écrite, pas une disparition** — le
faucet est précisément l'endroit où un testnet sans valeur peut en acquérir une
contre la volonté de son auteur.

---

## Partie IV — Ce que la carte interdit

Quatre garde-fous, formulés comme des interdits parce que ce sont des erreurs
qu'on ne rattrape pas.

1. **Aucune communication laissant entendre un mainnet, une valeur ou une
   garantie.** A est une norme d'ingénierie interne ; B est la posture publique.
2. **Aucun champ `emissions` valable à toute hauteur.** Ce qui protégeait avant
   n'était pas une règle mais la **divergence** — un mineur clandestin obtenait
   une racine que personne n'avait. Une émission diffusée **et acceptée** est
   irréparable sur un ledger append-only. La coinbase passe par J2 ou ne passe
   pas.
3. **Aucun fork choice introduit sans l'ADR J1.** C'est la porte par laquelle la
   refonte du ledger entrerait sans que personne l'ait décidé.
4. **Aucun audit commandé avant spec gelée.** Un audit sur une spec mouvante est
   de l'argent brûlé, et il produit un rapport qui rassure à tort.

---

## Ordre recommandé

```
  1. AUD  ── ACVP ciblés (decap/sigVer) · FIXTURE de conformité
       │     · docs source normative · CLAUDE+AGENTS assainis
       │
  2. T5  ── genèse signée · bootnodes · release · limites · reset
       │     · incident · POLITIQUE DE FRAIS · RÈGLE DE RÉACTION
       │
  3. D   ── fuzzing sémantique · chaos arrêt/reprise du producteur · dette PQ
       │     (le gel suspensif est CONSTATÉ ici, fermé en J1)
       │
  4. J1  ── ADR : quorum, n=3f+1, changement de vue, partitions,
       │     non-réorg défendue, admission, mise à jour d'autorités
       │     └─ ferme le gel suspensif
       │
  5. J2  ── ADR du mécanisme (coinbase à montant public, bénéficiaire caché ;
       │     destin des frais).  IMPLÉMENTATION derrière A.
       │
  6. J3  ── partitions, mise à jour, négociation de version.  OUVERTURE
             derrière A.
  ═══════════════════════════════════════════════════════════════════
     ÉTAT B  ──►  [décision écrite]  ──►  A
```

AUD et D relèvent de la voie sans regret : ils tournent en continu et ne
s'arrêtent pas quand la porte suivante commence. L'ordre ci-dessus est celui des
*démarrages*, pas des fins.

---

## Ce que ce document ne fait pas

- Il **ne choisit pas** le modèle de consensus : c'est le livrable de J1.
- Il **ne dimensionne pas** la flotte ni le calendrier. Aucune date n'y figure,
  volontairement — les portes sont ordonnées, pas planifiées.
- Il **ne remplace pas** `2026-07-22-testnet-public-0-design.md`, qui reste la
  référence pour le contenu de T5–T7.
- Il **ne produit aucun code.** Chaque porte obtient son propre cycle
  spec → plan → implémentation.

## Suites immédiates

1. **Spec de la porte AUD**, dans cet ordre : vecteurs ACVP ciblés
   `decap`/`sigVer` ; **fixture de conformité** (genèse + bloc + racine attendue +
   commande) ; `docs/` promu source normative ; `CLAUDE.md` et `AGENTS.md` réduits
   à des pointeurs (constats 1 et 2).
2. ~~Correctif `obscura-node`~~ — fait (`2e9e4df`, constat 3).
