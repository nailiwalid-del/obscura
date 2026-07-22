# Provenance des vecteurs de conformité

Source : dépôt NIST **ACVP-Server**, `gen-val/json-files/`, branche `master`,
récupéré le **2026-07-22**.

## Ce qui est couvert

| Primitive | Opération | Jeu ACVP | Fichier | Vecteurs |
|---|---|---|---|---|
| ML-KEM-768 (FIPS 203) | **décapsulation** | `ML-KEM-encapDecap-FIPS203` | `mlkem768-decap.txt` | **10 officiels** |
| ML-DSA-65 (FIPS 204) | **vérification** | `ML-DSA-sigVer-FIPS204` | `mldsa65-sigver.txt` | **1 officiel + 3 dérivés** |

Ce sont **exactement les deux opérations que le consensus exécute** : un nœud
vérifie des signatures et décapsule. Il ne rejoue jamais la génération de clés
d'autrui, ni l'encapsulation d'autrui, ni la signature d'autrui.

⚠️ **Ne jamais décrire ce répertoire comme des « KAT FIPS complets ».** Il
contient des **vecteurs ACVP ciblés**. La différence est exactement ce qu'un
auditeur vérifiera en premier.

## Groupes retenus et exclus

Comptés à la conversion, par `outils/convertir-acvp.py`.

| Jeu | Groupes retenus | Groupes exclus |
|---|---|---|
| ML-KEM-768 décapsulation | **1** | **14** |
| ML-DSA-65 vérification | **1** | **11** |

Les exclusions ne sont pas des omissions : chacune a une cause nommée ci-dessous.

## La variante ML-DSA, déterminée expérimentalement

FIPS 204 définit plusieurs interfaces de vérification, et le backend n'annonce
pas la sienne. Elle a été **mesurée**, pas supposée, en rejouant les deux
candidats sur les vecteurs officiels à contexte vide :

| Candidat | Résultat |
|---|---|
| `signatureInterface: internal` | le backend rejette **les 3 signatures attendues valides** |
| `signatureInterface: external`, `preHash: pure` | accord |

**Conclusion : PQClean implémente la variante externe PURE à contexte vide.**

⚠️ **Le piège que cette mesure a évité.** La variante `internal` affichait
*« 12/15 d'accord »* — un score entièrement produit par les cas **négatifs**, que
n'importe quelle fonction refusant tout obtiendrait. Sans cas négatifs
**étiquetés**, la conclusion aurait été exactement inverse. C'est la raison pour
laquelle `acvp_mldsa65.rs` porte trois tests de forme du jeu (présence
d'officiels, de négatifs, **et de positifs**) en plus du test de conformité.

## Pourquoi un seul vecteur ML-DSA officiel

L'API du backend ne prend pas de chaîne de contexte : elle préfixe la sienne,
vide. Or **un seul** test ACVP `ML-DSA-65` / `external` / `pure` a un contexte
vide ; les 14 autres en portent un non vide. Ils ne sont **pas faux** — ils sont
**invérifiables avec ce backend**.

Le jeu est donc complété par **3 cas négatifs dérivés** : mutation d'un bit du
vecteur officiel valide (premier octet de signature, dernier octet de signature,
dernier octet de message). Ils portent le préfixe `derive-`, ne sont jamais
comptés comme officiels, et un test dédié refuse un fichier qui n'aurait plus de
vecteur officiel.

## Ce qui n'est PAS couvert, et pourquoi

| Opération | Cause | Vérifié comment |
|---|---|---|
| `keyGen` (ML-KEM, ML-DSA) | `keypair()` ne prend **aucun argument** : pas d'injection de l'aléa officiel | lecture de l'API |
| `encap` (ML-KEM) | idem — aléa non injectable | lecture de l'API |
| `sigGen` (ML-DSA) | `detached_sign` est **hedgé**, pas déterministe | **mesuré** : les signatures produites diffèrent des vecteurs `sigGen` déterministes |
| ML-DSA à contexte non vide | l'API ne prend pas de contexte | lecture de l'API |
| ML-DSA `preHash` | non implémenté par PQClean | groupes exclus à la conversion |
| ML-KEM `keyFormat: seed` | exigerait une génération de clés depuis graine | groupes exclus à la conversion |

Le cas `sigGen` mérite d'être souligné : il a été **testé** avant d'être déclaré
hors couverture. Les vecteurs `ML-DSA-sigGen-FIPS204` du groupe déterministe ont
été rejoués, et `detached_sign` a produit des signatures différentes — le backend
utilise la variante randomisée. Ce n'est pas une supposition.

**Ces trous sont des critères de re-test du backend PQ** (voir
`docs/BACKEND_PQ.md`) : un backend exposant l'injection d'aléa, une signature
déterministe et une chaîne de contexte les refermerait presque tous. C'est une
raison positive d'en changer le jour venu, et elle est chiffrable — 4 opérations
sur 6 sont aujourd'hui hors de portée.

## Régénérer

```bash
python outils/convertir-acvp.py mlkem-decap  <prompt.json> <expectedResults.json>
python outils/convertir-acvp.py mldsa-sigver <prompt.json> <expectedResults.json>
```

Le convertisseur écrit ses comptes de groupes retenus/exclus sur **stderr** :
les reporter dans le tableau ci-dessus. Les en-têtes `#` des fichiers de vecteurs
sont ajoutés à la main et ne doivent pas être perdus.
