# Étape 1 — deux wallets : Alice paie, Bob reçoit.
. "$PSScriptRoot\lib.ps1"
Assurer-Build
Assurer-Travail

Etape 'Étape 1 — deux wallets (Alice paie, Bob reçoit)'

foreach ($w in 'alice', 'bob') {
    $f = Join-Path $Travail "$w.wallet"
    if (Test-Path $f) { Write-Host "$w.wallet existe déjà (ok)"; continue }
    # `creer` refuse d'écraser ; il imprime l'adresse + des avertissements qu'on
    # tait ici (on ré-affiche les adresses proprement juste après).
    Wallet creer --fichier $f | Out-Null
    Write-Host "$w.wallet créé"
}

Write-Host "`nAdresses (à communiquer hors chaîne au payeur) :"
Write-Host "  Alice : $(Wallet adresse --fichier (Join-Path $Travail 'alice.wallet'))"
Write-Host "  Bob   : $(Wallet adresse --fichier (Join-Path $Travail 'bob.wallet'))"
