# Étape 5 — Alice paie 300 à Bob avec une preuve STARK (via A, synchro préalable via B).
. "$PSScriptRoot\lib.ps1"

Etape 'Étape 5 — Alice paie 300 à Bob (preuve STARK)'

$bob = Wallet adresse --fichier (Join-Path $Travail 'bob.wallet')

# --noeud A : soumission de la transaction.
# --noeud-synchro B : la synchro préalable passe par un nœud DIFFÉRENT, pour ne pas
#   révéler à A « je viens de télécharger l'historique PUIS j'émets » (ce qui
#   désignerait Alice comme émettrice).
# --frais 0 : seul 0 est accepté sur ce testnet (fee est public et brûlé).
# La preuve prend quelques secondes ; la monnaie rendue (999 700) part vers Alice,
# chiffrée pour elle — elle ne reviendra au solde qu'après scellement (étape 6).
Wallet envoyer --fichier (Join-Path $Travail 'alice.wallet') `
    --a $bob --montant 300 --frais 0 `
    --noeud $NoeudA --noeud-synchro $NoeudB

Write-Host "`nEn attente du scellement du bloc 1 par A…"
if (Attendre-Log 'A' 'scellé à la hauteur 1' 30) {
    Write-Host 'bloc 1 scellé et diffusé au témoin B.'
} else {
    Write-Host "⚠️  bloc pas encore scellé — l'étape 6 le trouvera au besoin."
}
