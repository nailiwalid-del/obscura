# 99-reset — arrête les nœuds et efface tout l'état de travail.
#
# À lancer entre deux runs, ou pour tout nettoyer. Rien de précieux n'est effacé :
# wallets jetables, genèse et données sont tous reproductibles par les scripts.
. "$PSScriptRoot\lib.ps1"

Etape 'Reset — arrêt des nœuds et nettoyage'

Arreter-Noeuds

if (Test-Path $Travail) {
    Remove-Item -Recurse -Force $Travail
    Write-Host 'travail\ effacé (wallets, genèse, données de nœuds, journaux).'
} else {
    Write-Host 'rien à nettoyer.'
}
