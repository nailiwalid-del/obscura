# lib.ps1 — fonctions partagées de l'atelier Obscura.
#
# Chargé par chaque script d'étape via `. "$PSScriptRoot\lib.ps1"`. Ne fait rien
# tout seul : il ne définit que des chemins et des fonctions.

$ErrorActionPreference = 'Stop'
# Un binaire qui sort en erreur (exit != 0) doit FAIRE ÉCHOUER le script, pas
# passer inaperçu — c'est ce qui distingue un atelier d'une suite de commandes qui
# « ont l'air » de marcher.
$PSNativeCommandUseErrorActionPreference = $true

# atelier/ est le dossier de ce script ; le dépôt est son parent.
$Repo    = Split-Path $PSScriptRoot -Parent
$Bin     = Join-Path $Repo 'target\release'
$Travail = Join-Path $PSScriptRoot 'travail'

# ⚠️ Wallet EN CLAIR : atelier jetable, chaîne sans valeur. JAMAIS pour un wallet
# réel — utilisez alors OBSCURA_WALLET_PHRASE (cf. README).
$env:OBSCURA_WALLET_SANS_CHIFFREMENT = '1'

# Les deux nœuds de l'atelier.
$NoeudA = '127.0.0.1:9333'   # scelle + archive (le producteur)
$NoeudB = '127.0.0.1:9334'   # archive + témoin, relié à A par --pair

function Etape($titre) { Write-Host "`n=== $titre ===" -ForegroundColor Cyan }

# Chemin d'un binaire release, avec un message utile s'il manque.
function Exe($nom) {
    $p = Join-Path $Bin "$nom.exe"
    if (-not (Test-Path $p)) {
        throw "binaire absent : $p`n   Lance d'abord :  cargo build --release"
    }
    $p
}

# Raccourcis : forwardent leurs arguments au binaire (@args = splat automatique).
function Wallet { & (Exe 'obscura-wallet') @args }
function Genese { & (Exe 'obscura-genese') @args }

function Assurer-Travail {
    if (-not (Test-Path $Travail)) { New-Item -ItemType Directory -Path $Travail | Out-Null }
}

# Compile en release si un binaire manque (la preuve STARK est gatée en release).
function Assurer-Build {
    foreach ($n in 'obscura-wallet','obscura-genese','obscura-node') {
        if (-not (Test-Path (Join-Path $Bin "$n.exe"))) {
            Write-Host 'build release manquant — compilation (plusieurs minutes la 1re fois)…' -ForegroundColor Yellow
            Push-Location $Repo
            try { cargo build --release --bin obscura-wallet --bin obscura-genese --bin obscura-node }
            finally { Pop-Location }
            return
        }
    }
}

# Démarre un nœud en arrière-plan, journaux redirigés, PID mémorisé pour 99-reset.
function Demarrer-Noeud($nom, $ecoute, [string[]]$extra) {
    Assurer-Travail
    $log     = Join-Path $Travail "$nom.log"
    $err     = Join-Path $Travail "$nom.err.log"
    $donnees = Join-Path $Travail "donnees-$nom"
    $genese  = Join-Path $Travail 'genese.bin'
    $nodeArgs = @('--ecoute', $ecoute, '--genese', $genese, '--archiver', '--donnees', $donnees) + $extra
    $p = Start-Process -FilePath (Exe 'obscura-node') -ArgumentList $nodeArgs -PassThru `
            -RedirectStandardOutput $log -RedirectStandardError $err -WindowStyle Hidden
    $p.Id | Set-Content (Join-Path $Travail "$nom.pid")
    Write-Host "nœud $nom démarré (PID $($p.Id)) — journal : travail\$nom.err.log"
    $p
}

# Attend qu'une ligne correspondant à $motif apparaisse dans les journaux du nœud.
# Le journal peut sortir sur stdout ou stderr : on regarde les deux.
function Attendre-Log($nom, $motif, $secondes = 30) {
    $fichiers = @((Join-Path $Travail "$nom.log"), (Join-Path $Travail "$nom.err.log"))
    $t = [Diagnostics.Stopwatch]::StartNew()
    while ($t.Elapsed.TotalSeconds -lt $secondes) {
        foreach ($f in $fichiers) {
            if ((Test-Path $f) -and (Select-String -Path $f -Pattern $motif -Quiet)) { return $true }
        }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

# Affiche le journal d'un nœud (stderr d'abord : c'est là que va le journal).
function Journal-Noeud($nom) {
    foreach ($f in @((Join-Path $Travail "$nom.err.log"), (Join-Path $Travail "$nom.log"))) {
        if ((Test-Path $f) -and (Get-Item $f).Length -gt 0) { Get-Content $f }
    }
}

# Arrête les nœuds : par PID mémorisé, puis filet de sécurité par port.
function Arreter-Noeuds {
    if (Test-Path $Travail) {
        foreach ($pf in Get-ChildItem -Path $Travail -Filter '*.pid' -ErrorAction SilentlyContinue) {
            $id = Get-Content $pf.FullName
            try { Stop-Process -Id $id -Force -ErrorAction Stop; Write-Host "nœud arrêté (PID $id)" }
            catch { }
            Remove-Item $pf.FullName -Force
        }
    }
    foreach ($port in 9333, 9334) {
        $c = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        foreach ($id in ($c.OwningProcess | Select-Object -Unique)) {
            try { Stop-Process -Id $id -Force -ErrorAction Stop; Write-Host "listener $port arrêté (PID $id)" }
            catch { }
        }
    }
}
