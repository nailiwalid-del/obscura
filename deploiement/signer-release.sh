#!/usr/bin/env bash
# Signe une release Obscura : produit un manifeste de checksums SHA-256 (un
# artefact = une ligne) et le signe avec minisign. La clé privée est un secret
# d'opérateur — jamais dans le dépôt. Usage : signer-release.sh <repertoire> <cle-privee>
set -euo pipefail
rep="${1:?répertoire des artefacts requis}"
cle="${2:?clé privée minisign requise}"
# Résoudre la clé en chemin absolu AVANT de changer de répertoire : passée en
# relatif, elle ne se retrouverait plus une fois dans "$rep".
cle="$(cd "$(dirname "$cle")" && pwd)/$(basename "$cle")"
cd "$rep"
# Manifeste : checksums de tous les fichiers sauf le manifeste lui-même.
: > checksums.txt
for f in *; do
  [ "$f" = checksums.txt ] && continue
  [ "$f" = checksums.txt.minisig ] && continue
  sha256sum "$f" >> checksums.txt
done
# Signer le manifeste.
minisign -S -s "$cle" -m checksums.txt
echo "Release signée : $(wc -l < checksums.txt) artefact(s), manifeste checksums.txt.minisig"
