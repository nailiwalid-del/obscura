# L'argument post-quantique d'Obscura — écrit et quantifié

**Statut :** T3 du plan Testnet 0. Document de RÉFÉRENCE, destiné à être lu par
un sceptique. Tout chiffre y est soit **mesuré** (avec la commande qui le
reproduit), soit **repris d'une norme** (avec sa référence), soit marqué comme
**non établi**. Aucun chiffre n'est estimé à la main.

> ⚠️ **Prototype non audité.** Ce document explique une conception, il ne certifie
> rien. Deux audits indépendants restent une porte du mainnet, pas une case cochée.

---

## 1. La thèse, et ce qu'elle ne dit pas

**La thèse :** Obscura est conçue pour que la confidentialité de ses transactions
survive à un ordinateur quantique cryptographiquement pertinent (CRQC).

**Ce que la thèse ne dit pas** — et qu'aucun document public ne doit laisser croire :

- qu'Obscura est plus petite, plus rapide ou plus mature que Zcash ou Monero
  (elle est **plus grosse** : ~68 Kio par transaction, cf. §6) ;
- qu'elle est auditée (elle ne l'est pas) ;
- que sa soundness est prouvée au niveau qu'on lui souhaite (cf. §5, le point le
  plus inconfortable de ce document) ;
- que le post-quantique la rend « sûre ». Il la rend **résistante à une classe de
  menace précise**, énumérée au §2.

## 2. La menace, précisément

| Algorithme quantique | Ce qu'il casse | Effet sur une monnaie |
|---|---|---|
| **Shor** | logarithme discret, factorisation | signatures et échanges de clés fondés sur les courbes elliptiques deviennent forgeables/déchiffrables |
| **Grover** | recherche non structurée | divise par 2 l'exposant de sécurité d'une préimage de hachage (2ⁿ → 2^(n/2)) |

### Le point qui commande tout : la rétroactivité

Un CRQC ne casse pas seulement les transactions **futures**. Une chaîne publique
est un enregistrement **permanent** : tout ce qui y est écrit aujourd'hui peut être
déchiffré le jour où la machine existe — c'est le modèle *harvest now, decrypt
later*. Pour une monnaie dont la confidentialité repose sur le logarithme discret,
l'arrivée d'un CRQC ne dégrade pas la vie privée à partir de ce jour : elle
**annule rétroactivement** celle de tout l'historique déjà publié.

C'est la raison d'être d'Obscura, et c'est une propriété **structurelle**, pas une
question d'implémentation : elle ne se corrige pas par une mise à jour, puisque les
données sont déjà publiées.

## 3. Inventaire des primitives — ce qui tient, et quand

Principe directeur du projet (décision utilisateur) : **chaque fonction combine
deux familles mathématiques indépendantes ; la sécurité tient si l'une des deux
tient.** L'hybride n'est donc pas une transition vers le post-quantique, c'est le
régime permanent.

| Fonction | Moitié classique | Moitié post-quantique | Si un CRQC arrive |
|---|---|---|---|
| Échange de clés | X25519 | **ML-KEM-768** (FIPS 203, catégorie NIST 3) | X25519 tombe (Shor) ; ML-KEM tient → **le secret tient** |
| Signature | Ed25519 | **ML-DSA-65** (FIPS 204, catégorie NIST 3) | Ed25519 tombe ; ML-DSA tient → **forger exige encore de casser ML-DSA** |
| Chiffrement | AES-256-GCM | XChaCha20-Poly1305 | ni l'un ni l'autre n'est cassé par Shor ; Grover ramène 256 bits de clé à ~2¹²⁸ |
| Hachage consensus | BLAKE3 ‖ SHA3-256, jamais tronqué | (les deux résistent) | une collision exige de casser **les deux** ; Grover s'applique aux préimages |
| Preuve | zk-STARK (hachage seul) | — | **aucune hypothèse de log discret**, cf. §4 |

**Version d'algorithme `0x02`** partout depuis la migration T1 ; le round-3
(`0x01`) n'est pas accepté « pour compatibilité » : il est **refusé par son nom**
(`CryptoError::AlgoPerime`). Aucun objet round-3 ne peut donc traverser un nœud à
jour — ce qui évite qu'un attaquant force une négociation vers le plus faible.

**Ce que l'hybride ne fait PAS :** il ne protège pas contre une faille
d'implémentation commune aux deux moitiés, ni contre la compromission du poste
(hors périmètre, cf. THREAT_MODEL). Et il coûte : deux fois les clés, deux fois les
signatures.

## 4. Pourquoi le choix des STARK est le cœur de l'argument

Une preuve à divulgation nulle est le composant le plus difficile à rendre
post-quantique, parce que la plupart des systèmes déployés (Groth16, PLONK,
Halo 2…) fondent leur sécurité sur des hypothèses de **logarithme discret** sur
courbes elliptiques ou sur des appariements. Un CRQC les casse.

Les **zk-STARK** ne reposent que sur la sécurité d'une **fonction de hachage** et
sur des arguments d'information. Conséquences, toutes vérifiables dans ce dépôt :

- **aucun setup de confiance** (rien à corrompre, rien à détruire cérémonieusement) ;
- **aucune hypothèse de log discret** — donc rien que Shor n'attaque directement ;
- le prix : des preuves **beaucoup plus grosses** (§6). C'est un arbitrage assumé,
  pas un défaut d'optimisation.

## 5. Le chiffre inconfortable : soundness conjecturée ≠ prouvée

Ces valeurs sont **annoncées par winterfell lui-même** sur une preuve réelle (forme
2/2, profondeur de consensus 32), pas estimées :

```
paramètres : 48 requêtes, blowup 16, grinding 0, extension quadratique
CONJECTURÉE (conjecture 1, eprint 2021/582) : 127 bits
PROUVÉE — décodage par liste : 78 à 82 bits selon la forme | unique : 43 bits
```

Reproduire : `cargo test -p circuit --release --lib securite_par_forme --
--ignored --nocapture`

**Comment le lire.** La sécurité *conjecturée* (127 bits) suppose vraie une
conjecture de la littérature FRI qui n'est pas démontrée. La sécurité *prouvée* est
ce qui tient **sans** cette conjecture. C'est la borne de **soundness** — la
difficulté de forger une preuve invalide, donc, dans le pire cas, de **créer de la
monnaie**.

**Elle dépend de la LONGUEUR DE TRACE, donc de la forme de la transaction :**

| forme | trace | prouvé (liste) |
|---|---|---|
| 1-in/1-out, 1-in/2-out | 1024 | 82 bits |
| 2-in/2-out (défaut) | 2048 | 80 bits |
| 4-in/4-out | 4096 | **78 bits** |

Le réseau ne vaut donc que ce que vaut sa **plus grande** transaction : le vérifieur
exige 78 bits prouvés (`SOUNDNESS_MINIMALE`) et refuse toute preuve en dessous.

**Ce que le durcissement du 2026-07-22 a changé.** Le circuit produisait ses preuves
avec 32 requêtes FRI — 62 bits prouvés — et, plus grave, le vérifieur n'exigeait
qu'un niveau *conjecturé* (95 bits) qui vaut 127 à 32 comme à 48 requêtes : il ne
distinguait donc **rien**. N'importe qui pouvait produire une preuve économique que
le réseau acceptait. Le verrou est désormais côté vérifieur (`MinProvenSecurity`).

**Ce qui reste ouvert.** Ces 78 bits vivent dans le régime de décodage par **liste**,
qui suppose la list-decodability. Le régime de décodage **unique**, qui ne suppose
rien, ne vaut que 43 bits ici ; l'amener à 87 demanderait 96 requêtes, soit ×1,8 sur
la taille de preuve (178 Kio par transaction). Arbitrage tranché en faveur de 48 :
le gain théorique ne valait pas un doublement du coût permanent du réseau.

> Ces chiffres sont indépendants du quantique : ils valent déjà contre un adversaire
> classique. Ils sont écrits ici parce qu'un document qui vante 127 bits sans nommer
> la conjecture mentirait par omission.

## 6. Le coût, mesuré

Preuves à la profondeur de consensus (32), par forme de transaction —
`cargo test -p circuit --release --lib mesure_formes -- --ignored --nocapture` :

| Forme | Taille de preuve | Vérification |
|---|---|---|
| 1-in/1-out | 78,3 Kio | 2,4 ms |
| 1-in/2-out | 78,1 Kio | 1,8 ms |
| **2-in/2-out** (défaut) | **98,0 Kio** | 4,6 ms |
| 4-in/4-out | 114,0 Kio | 11,3 ms |

Sur le fil, une `ProvedTx` 2/2 complète (preuve + enveloppe d'intention + enc_notes)
pèse **105 Kio** — c'est ce chiffre-là qui borne le nombre de transactions par bloc
(~9, contre ~15 avant le durcissement de soundness).

Une transaction Obscura pèse donc **environ 105 Kio**, contre un ordre de grandeur
de quelques Kio pour les monnaies privées à courbes elliptiques. **L'écart n'est
pas rattrapable par de l'optimisation : c'est le prix des STARK.** Un lecteur qui
n'accepte pas ce prix n'a pas besoin d'Obscura — et le document doit le lui dire.

> Les chiffres des autres projets ne sont volontairement pas tabulés ici : ils
> changent avec leurs versions et devraient être re-vérifiés à chaque publication.
> Ce qui ne change pas, et qui suffit à l'argument, est **structurel** : leurs
> constructions reposent sur le logarithme discret.

## 7. Ce que le post-quantique NE couvre PAS ici

Écrit franchement, parce que c'est ce qu'un auditeur cherchera en premier.

- **Le witness-hiding est argumenté en ROM, pas en QROM.** L'argument HVZK du
  monolithe (cf. STARK_STATEMENT) est fait dans le modèle de l'oracle aléatoire
  classique. Un adversaire quantique interroge l'oracle en superposition (QROM) —
  le passage n'est pas automatique et **n'a pas été fait**. C'est le principal
  angle mort spécifiquement quantique du projet.
- **L'anonymat ANO-CCA du KEM est reconduit, pas re-démontré** : les analyses
  publiées visent Kyber round-3, et FIPS 203 n'en est pas la copie (cf. PROTOCOL).
- **Grover contre les hachages** n'est pas quantifié finement ici : la sécurité de
  Rescue-Prime (le hachage *prouvé*, dans le circuit) face à un adversaire
  quantique n'a pas été analysée dans ce projet.
- **Les métadonnées réseau** ne sont pas un problème quantique : Dandelion++ et la
  diversité de pairs restent la seule défense, et le nœud servant l'historique
  apprend IP, cadence et position (cf. THREAT_MODEL).
- **Les canaux auxiliaires** des implémentations sont hors périmètre (prototype).
- **La gouvernance** : la chaîne est fédérée (autorités gravées en genèse), une
  autorité absente fige la chaîne à son tour. Rien de tout cela n'est quantique,
  et tout cela compte davantage pour un utilisateur réel, aujourd'hui.

## 8. Résumé pour un lecteur pressé

Obscura fait un pari étroit et vérifiable : **ne dépendre du logarithme discret
nulle part où la confidentialité en dépendrait de façon rétroactive.** Signatures
et KEM sont hybrides (une moitié FIPS), les preuves sont des STARK (hachage seul),
et le hachage de consensus combine deux familles.

Ce pari coûte cher (≈68 Kio par transaction) et laisse deux chantiers ouverts qui
ne sont pas des détails : la **soundness prouvée à 62 bits** (§5) et l'argument de
masquage **non porté en QROM** (§7). Les deux sont écrits ici plutôt que découverts
par un auditeur.
