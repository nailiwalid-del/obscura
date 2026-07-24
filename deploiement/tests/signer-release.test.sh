#!/usr/bin/env bash
# Test de bout en bout de la signature de release, avec une clé JETABLE.
set -euo pipefail
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# Répertoire d'artefacts factices.
mkdir artefacts
printf 'binaire factice obscura-node\n' > artefacts/obscura-node
printf 'genese factice\n' > artefacts/genese.bin

# Clé jetable minisign (sans mot de passe).
minisign -G -p rel.pub -s rel.key -W

# Signer.
bash "$OLDPWD/deploiement/signer-release.sh" artefacts rel.key
test -f artefacts/checksums.txt
test -f artefacts/checksums.txt.minisig

# Vérifier : doit PASSER.
bash "$OLDPWD/deploiement/verifier-release.sh" artefacts rel.pub

# Altérer un artefact d'un octet : la vérification doit ÉCHOUER.
printf 'X' >> artefacts/obscura-node
if bash "$OLDPWD/deploiement/verifier-release.sh" artefacts rel.pub 2>/dev/null; then
  echo "ECHEC : altération NON détectée"; exit 1
fi
echo "TEST OK : altération détectée, release saine vérifiée"
