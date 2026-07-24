#!/usr/bin/env bash
# Vérifie une release Obscura : (1) signature minisign du manifeste, (2) chaque
# checksum. Sortie non nulle si l'un échoue. Usage : verifier-release.sh <repertoire> <cle-publique>
set -euo pipefail
rep="${1:?répertoire des artefacts requis}"
pub="${2:?clé publique minisign requise}"
# Résoudre la clé en chemin absolu AVANT de changer de répertoire : passée en
# relatif, elle ne se retrouverait plus une fois dans "$rep".
pub="$(cd "$(dirname "$pub")" && pwd)/$(basename "$pub")"
cd "$rep"
# 1) Signature du manifeste.
minisign -V -p "$pub" -m checksums.txt
# 2) Checksums (sha256sum -c échoue si un fichier diffère).
sha256sum -c checksums.txt
echo "Release vérifiée : manifeste signé et checksums conformes."
