# 00-tout — enchaîne les 6 étapes de l'atelier d'un coup.
#
# Les nœuds restent debout à la fin (99-reset.ps1 pour tout arrêter et nettoyer).
. "$PSScriptRoot\lib.ps1"

Etape 'Atelier Obscura — run complet (create → genèse → nœuds → sync → payer → resync)'
Assurer-Build

& "$PSScriptRoot\01-wallets.ps1"
& "$PSScriptRoot\02-genese.ps1"
& "$PSScriptRoot\03-noeuds.ps1"
& "$PSScriptRoot\04-synchroniser.ps1"
& "$PSScriptRoot\05-payer.ps1"
& "$PSScriptRoot\06-resync.ps1"

Write-Host "`n✅ Atelier terminé." -ForegroundColor Green
Write-Host '   Les nœuds A et B tournent encore. 99-reset.ps1 pour tout arrêter et nettoyer.'
