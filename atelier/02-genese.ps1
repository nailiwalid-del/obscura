# Étape 2 — genèse : alloue 1 000 000 unités à Alice, chaîne OUVERTE (sans autorité).
. "$PSScriptRoot\lib.ps1"
Assurer-Travail

Etape 'Étape 2 — genèse (1 000 000 → Alice, chaîne ouverte)'

$genese = Join-Path $Travail 'genese.bin'
if (Test-Path $genese) {
    Write-Host "genese.bin existe déjà — 99-reset.ps1 pour repartir d'une chaîne neuve."
    return
}

# L'adresse d'Alice est le bénéficiaire de l'allocation. La chaîne est OUVERTE
# (aucun --autorite) : tout nœud lancé avec --sceller peut produire des blocs.
# Ordre convenu, pas défendu — testnet local uniquement.
$alice = Wallet adresse --fichier (Join-Path $Travail 'alice.wallet')
Genese --sortie $genese --allocation "${alice}:1000000"
