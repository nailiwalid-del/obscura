# Étape 6 — resynchronisation : la monnaie rendue revient à Alice, Bob reçoit son paiement.
. "$PSScriptRoot\lib.ps1"

Etape 'Étape 6 — resync : monnaie rendue à Alice, paiement reçu par Bob'

Write-Host '--- Alice (la monnaie rendue revient) ---'
Wallet synchroniser --fichier (Join-Path $Travail 'alice.wallet') --noeud $NoeudA --temoin $NoeudB

Write-Host "`n--- Bob (le paiement reçu apparaît) ---"
Wallet synchroniser --fichier (Join-Path $Travail 'bob.wallet') --noeud $NoeudA --temoin $NoeudB

Write-Host "`n--- Bilan (la masse se conserve : 999 700 + 300 = 1 000 000) ---"
Wallet solde --fichier (Join-Path $Travail 'alice.wallet') | Select-String 'solde connu'
Wallet solde --fichier (Join-Path $Travail 'bob.wallet')   | Select-String 'solde connu'
