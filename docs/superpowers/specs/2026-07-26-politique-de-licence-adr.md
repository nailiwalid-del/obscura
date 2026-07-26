# ADR-004 : politique de licence et provenance des contributions

**Statut :** **ACCEPTÉ** le 2026-07-26 (proposé le même jour).
**Décideur :** l'auteur du projet.
**Ce qui a permis l'acceptation :** la décision ne dépend d'aucune mesure ni d'aucun
code de consensus. Elle tranche une POSITION, et la position retenue (statu quo de
licence + DCO) ne coûte presque rien à tenir tout en laissant sa porte de
renversement écrite.
**Origine :** fiche S4 de `2026-07-26-monetisation-carte.md`.
**Portée :** la licence du dépôt, le régime des contributions externes, et
l'instrument de provenance. **Ne touche ni le consensus, ni aucun format de fil** —
`docs/STABILITE.md` n'est pas affecté.

---

## Contexte

Quatre faits, relevés dans le dépôt le 2026-07-26, contraignent la décision.

**1. Le droit d'auteur est détenu à 100 % par un seul auteur.** `git shortlog`
donne 404 commits sous deux identités de la même personne, et aucun contributeur
externe. **Aucun accord de tiers n'est requis pour changer de licence** — ni CLA à
rétro-obtenir, ni consentement à collecter.

**2. Le dépôt est public depuis le 2026-07-14 sous `MIT OR Apache-2.0`**, avec 1
étoile et **0 fork** ; aucun crate n'est publié sur crates.io (`publish = false`
partout). L'instantané déjà diffusé reste disponible sous ces termes pour toujours —
cela est irréversible. Mais à 0 fork, la portée pratique de cette irréversibilité est
aujourd'hui **nulle**.

**3. Aucun dispositif de contribution n'existe** : ni `CONTRIBUTING.md`, ni gabarit
de PR, ni contrôle de provenance. Une première PR externe serait fusionnée sans
qu'aucune trace n'atteste que son auteur avait le droit de la soumettre.

**4. Un entrant permissif ne forclôt aucune option de licence.** MIT autorise la
sous-licence ; Apache-2.0 accorde les droits de reproduction, d'œuvre dérivée et de
distribution, et porte sa propre concession de brevet. Une contribution reçue sous
`MIT OR Apache-2.0` peut donc être incluse dans une offre commerciale ou une double
licence, sous réserve de préserver les mentions.

### Ce que cette décision corrige

La fiche S4 de la carte de monétisation écrivait que fusionner une PR externe sans
CLA rendrait « toute stratégie de licence future négociable avec un tiers ».
**La seconde moitié est fausse** : le fait 4 montre qu'un entrant permissif préserve
l'open core comme la double licence. La fiche est corrigée dans la carte, et le
présent ADR fait foi.

**Ce qui manque réellement n'est pas un droit, c'est une attestation.** Sans
instrument de provenance, rien ne certifie que le contributeur pouvait soumettre ce
qu'il soumet — et c'est précisément ce qu'interroge une revue de chaîne
d'approvisionnement logicielle, le même mécanisme qui fait remonter un `unmaintained`
en rouge chez un acheteur institutionnel.

---

## Décision

**1. Le dépôt reste sous `MIT OR Apache-2.0`.** Aucun changement de modèle de
licence n'est engagé.

**2. Entrant = sortant.** Toute contribution est reçue sous la double licence du
dépôt. **Pas de CLA, pas de cession de droits** : le contributeur conserve son droit
d'auteur.

**3. Le DCO 1.1 est obligatoire**, attesté par une ligne `Signed-off-by` sur chaque
commit, **vérifiée en CI** (job `dco`, commits de fusion exclus).

**4. Le raisonnement et les règles sont publiés** dans `CONTRIBUTING.md`, avec un
gabarit de PR qui interroge explicitement la surface de `docs/STABILITE.md`.

**Critère de renversement :** un acheteur ou un partenaire exigeant la faculté de
**re-licencier le projet en bloc** (ce que l'entrant permissif ne donne pas). Un CLA
serait alors ajouté — il ne vaudrait que pour les contributions **postérieures**, ce
qui est une raison de plus de ne pas le poser d'avance sans besoin.

---

## Options considérées

### (i) Ne rien faire — **REJETÉ**

Continuer sans `CONTRIBUTING.md` ni instrument de provenance.

**Contre :** laisse le trou de provenance ouvert au moment précis où le dépôt devient
visible, et le referme d'autant plus mal qu'il faudrait alors revenir vers des
contributeurs déjà partis. Le coût du dispositif est d'une après-midi ; l'inaction
n'économise rien de mesurable.

### (ii) DCO + entrant = sortant — **RETENU**

**Pour :** proportionné et standard (Linux, Git, la plupart de l'écosystème Rust) ;
aucune friction pour le contributeur — pas de document à signer, une option de
`git commit` ; vérifiable mécaniquement en CI ; ferme le trou de provenance sans rien
demander que le projet n'ait besoin.
**Contre, assumé :** ne donne pas la faculté de re-licencier en bloc. C'est
exactement le critère de renversement, et rien aujourd'hui ne l'exige.

### (iii) CLA — **DIFFÉRÉ**

**Pour :** faculté de re-licencier le projet entièrement, interlocuteur unique en
cas de litige, concession de brevet explicite.
**Contre :** friction réelle — beaucoup de contributeurs refusent de signer, et il
faut une mécanique de collecte et de conservation des signatures. Surtout, **le gain
principal ne sert aucun besoin actuel** : le fait 4 montre que les options de licence
sont déjà préservées. Poser un CLA d'avance, ce serait payer une friction certaine
pour un besoin hypothétique.
**Décision :** différé derrière le critère de renversement, sans chemin pré-choisi.

### (iv) Changer de modèle de licence maintenant (open core, AGPL + commercial) — **REJETÉ à ce stade**

**Contre :** prématuré. Il n'y a **aucun acheteur, aucun client, aucun fork
concurrent** — donc rien à protéger, et un signal public (« ce projet se ferme »)
payé au comptant contre un bénéfice nul. Le fait 1 garantit que cette option reste
ouverte à tout moment ; rien n'oblige à la prendre avant qu'elle serve.

---

## Conséquences

**Ce qui devient plus clair**
- Un contributeur sait sous quelle licence sa contribution est reçue, et ce qu'il
  atteste — écrit, pas implicite.
- Le trou de provenance est fermé, et sa fermeture est **mécaniquement vérifiée**
  plutôt que promise.
- `CONTRIBUTING.md` publie un fait jusqu'ici invisible de l'extérieur : toucher à la
  surface de `docs/STABILITE.md` remet à zéro une horloge de trois mois dont dépendent
  des décisions bien plus lourdes qu'une revue de code.

**Ce qui reste assumé**
- Pas de faculté de re-licence en bloc, par choix (option iii).
- L'instantané `MIT OR Apache-2.0` déjà publié est irrévocable. À 0 fork, sans portée
  pratique aujourd'hui ; cette portée croît avec chaque fork.

**Ce que ça n'empêche pas**
- Un modèle open core ou une double licence sur les crates **futurs** restent
  entièrement ouverts (fait 4), sans rien renégocier avec personne.

---

## Résidus, écrits et non résolus

1. **Le job `dco` n'a jamais tourné sur une vraie PR** — le dépôt n'en a reçu aucune.
   Il est écrit contre `github.event.pull_request`, donc silencieux sur les pushes
   `master` par construction. **À observer au premier passage réel** plutôt qu'à
   supposer correct.
2. **Le DCO n'est pas une vérification, c'est une attestation.** Il n'empêche pas un
   contributeur de mentir ; il déplace la responsabilité et laisse une trace. C'est sa
   fonction, et c'est aussi sa limite.
3. **La politique ne dit rien de la revue elle-même** — qui relit, selon quels
   critères, avec quel délai. Sans contributeur, la question est théorique ; elle se
   posera au premier.

---

## Actions

1. [x] **Accepter ou amender cet ADR.** — **ACCEPTÉ le 2026-07-26.**
2. [x] Écrire `CONTRIBUTING.md` (licence, DCO, surface de stabilité, conventions,
   commandes de vérification).
3. [x] Ajouter `.github/PULL_REQUEST_TEMPLATE.md`.
4. [x] Ajouter le job `dco` à `.github/workflows/ci.yml`.
5. [x] Corriger la fiche S4 de `2026-07-26-monetisation-carte.md`.
6. [ ] **Observer le job `dco` au premier passage sur une PR réelle** (résidu 1).
