#!/usr/bin/env python3
"""Convertit les JSON ACVP du NIST en vecteurs texte pour crates/crypto/tests.

Usage :
    python outils/convertir-acvp.py mlkem-decap  <prompt.json> <expectedResults.json>
    python outils/convertir-acvp.py mldsa-sigver <prompt.json> <expectedResults.json>

Le résultat part sur stdout ; le rediriger vers le fichier de vecteurs.

POURQUOI un format texte plutôt que le JSON tel quel : le dépôt n'a pas de
dépendance JSON et n'en veut pas dans le consensus. La conversion a lieu UNE
FOIS, hors build, et le résultat est vendorisé.

# Les filtres, et pourquoi chacun existe

Ils ont TOUS été établis en inspectant les fichiers réels, pas en supposant.

- `parameterSet` : les jeux ACVP mélangent 512/768/1024 (ML-KEM) et 44/65/87
  (ML-DSA). Sans filtre, on empile des vecteurs d'un autre niveau de sécurité.
- `keyFormat == "expanded"` (ML-KEM) : les groupes `seed` donnent (z, d), pas la
  `dk` de 2400 o. Les reconstituer exigerait une génération de clés depuis graine,
  que le backend n'expose pas.
- `signatureInterface == "external"` et `preHash == "pure"` (ML-DSA) : PQClean
  implémente la variante PURE à contexte vide. Établi expérimentalement — voir
  `crates/crypto/tests/vecteurs/PROVENANCE.md`, qui donne le résultat chiffré.
- `context` vide (ML-DSA) : l'API du backend ne prend pas de chaîne de contexte
  et préfixe la sienne (vide). Un vecteur à contexte non vide est donc
  invérifiable, pas faux.

⚠️ `dk` (ML-KEM) et `pk` (ML-DSA) vivent au niveau du TEST, pas du groupe.
"""
import json
import sys

# Le jeu officiel ML-DSA-65 exploitable est minuscule (voir PROVENANCE.md). On y
# ajoute des cas négatifs DÉRIVÉS par mutation d'un vecteur valide officiel. Ils
# sont étiquetés comme tels et ne sont jamais présentés comme officiels.
MUTATIONS = [
    ("sig-premier-octet", "sig", 0),
    ("sig-dernier-octet", "sig", -1),
    ("msg-dernier-octet", "msg", -1),
]


def charger(prompt_path, results_path):
    with open(prompt_path, encoding="utf-8") as f:
        prompt = json.load(f)
    with open(results_path, encoding="utf-8") as f:
        results = json.load(f)
    # Les résultats attendus sont indexés par tcId, pas dans l'ordre du prompt.
    attendus = {}
    for groupe in results["testGroups"]:
        for t in groupe["tests"]:
            attendus[t["tcId"]] = t
    return prompt, attendus


def mlkem_decap(prompt, attendus):
    retenus = exclus = 0
    lignes = []
    for groupe in prompt["testGroups"]:
        if (
            groupe.get("parameterSet") != "ML-KEM-768"
            or groupe.get("function") != "decapsulation"
            or groupe.get("keyFormat") != "expanded"
        ):
            exclus += 1
            continue
        retenus += 1
        for t in groupe["tests"]:
            att = attendus.get(t["tcId"])
            if att is None or "k" not in att:
                continue
            lignes.append(f"{t['dk']}:{t['c']}:{att['k']}")
    print(
        f"# groupes retenus : {retenus} ; groupes exclus : {exclus} ; "
        f"vecteurs : {len(lignes)}",
        file=sys.stderr,
    )
    for l in lignes:
        print(l)


def _muter(hexstr, index):
    """Retourne un bit de l'octet `index` d'une chaîne hexadécimale."""
    b = bytearray.fromhex(hexstr)
    b[index] ^= 0x01
    return b.hex()


def mldsa_sigver(prompt, attendus):
    retenus = exclus = 0
    lignes = []
    valide_officiel = None
    for groupe in prompt["testGroups"]:
        if (
            groupe.get("parameterSet") != "ML-DSA-65"
            or groupe.get("signatureInterface") != "external"
            or groupe.get("preHash") != "pure"
        ):
            exclus += 1
            continue
        retenus += 1
        for t in groupe["tests"]:
            # Contexte non vide : invérifiable avec ce backend, pas faux.
            if t.get("context"):
                continue
            att = attendus.get(t["tcId"])
            if att is None or "testPassed" not in att:
                continue
            drapeau = "1" if att["testPassed"] else "0"
            lignes.append(f"officiel:{t['pk']}:{t['message']}:{t['signature']}:{drapeau}")
            if att["testPassed"] and valide_officiel is None:
                valide_officiel = t

    if valide_officiel is None:
        print("aucun vecteur valide officiel : mutations impossibles", file=sys.stderr)
    else:
        t = valide_officiel
        for nom, quoi, idx in MUTATIONS:
            pk, msg, sig = t["pk"], t["message"], t["signature"]
            if quoi == "sig":
                sig = _muter(sig, idx)
            else:
                msg = _muter(msg, idx)
            lignes.append(f"derive-{nom}:{pk}:{msg}:{sig}:0")

    print(
        f"# groupes retenus : {retenus} ; groupes exclus : {exclus} ; "
        f"vecteurs officiels : {sum(1 for l in lignes if l.startswith('officiel:'))} ; "
        f"cas dérivés : {sum(1 for l in lignes if l.startswith('derive-'))}",
        file=sys.stderr,
    )
    for l in lignes:
        print(l)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    quoi, prompt_path, results_path = sys.argv[1], sys.argv[2], sys.argv[3]
    prompt, attendus = charger(prompt_path, results_path)
    if quoi == "mlkem-decap":
        mlkem_decap(prompt, attendus)
    elif quoi == "mldsa-sigver":
        mldsa_sigver(prompt, attendus)
    else:
        print(f"inconnu : {quoi}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
