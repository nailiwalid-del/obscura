# Étape 4 — Alice synchronise via A, chaque bloc corroboré par le témoin B.
. "$PSScriptRoot\lib.ps1"

Etape 'Étape 4 — Alice synchronise (via A, corroborée par le témoin B)'

# --temoin B : un SECOND nœud redemande la même hauteur et compare la racine de fin
# de bloc. Sans lui, A pourrait taire un paiement en servant un historique
# parfaitement cohérent. Ici A et B ont amorcé la MÊME genèse : la corroboration
# passe, et Alice découvre son allocation.
Wallet synchroniser --fichier (Join-Path $Travail 'alice.wallet') --noeud $NoeudA --temoin $NoeudB

Write-Host "`nSolde d'Alice :"
Wallet solde --fichier (Join-Path $Travail 'alice.wallet')
