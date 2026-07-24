# repetition-generale.ps1 — ÉTAPE 0 du runbook d'ouverture (docs/OUVERTURE.md).
#
# Répétition générale sur chaîne JETABLE, à 4 AUTORITÉS, avec test de COUPURE
# (liveness J1-b2). C'est ce que l'atelier local à 2 nœuds NE teste pas : à n=4,
# couper une autorité doit être absorbé par changement de vue, la chaîne continue.
#
# Sur une chaîne À AUTORITÉS, chaque producteur scelle un bloc de battement (même
# vide) à son tour : la HAUTEUR avance toute seule dès que le quorum finalise. La
# liveness se lit donc directement sur la hauteur scellée qui MONTE — inutile de
# fabriquer des paiements (l'inclusion de transaction, elle, est couverte par
# l'atelier). Une hauteur qui CALE (split de votes) est un échec FRANC, journalisé.
#
# Rien de ce qui est produit ici n'est publié ; tout est jetable (dossier
# atelier/repetition/, ports 9340-9343, distincts de l'atelier). `-Nettoyer` efface.
#
# Critères observés (runbook étape 0) :
#   3. les 4 autorités impriment le MÊME identifiant complet (128 hex) ;
#   4. la hauteur avance (4 debout), puis une autorité coupée → elle CONTINUE ;
#   5. synchro témoin corroborée sur la chaîne résultante.

param([switch]$Nettoyer)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$Repo = Split-Path $PSScriptRoot -Parent
$Bin  = Join-Path $Repo 'target\release'
$Rep  = Join-Path $PSScriptRoot 'repetition'
$env:OBSCURA_WALLET_SANS_CHIFFREMENT = '1'   # chaîne jetable, wallets en clair

$Ports  = 9340, 9341, 9342, 9343
$Compte = $Ports.Count
$script:echecs = 0

function Exe($nom) {
    $p = Join-Path $Bin "$nom.exe"
    if (-not (Test-Path $p)) { throw "binaire absent : $p`n   cargo build --release" }
    $p
}
function Node   { & (Exe 'obscura-node')   @args }
function Wallet { & (Exe 'obscura-wallet') @args }
function Genese { & (Exe 'obscura-genese') @args }

function Titre($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function OK($t) { Write-Host "  [OK] $t" -ForegroundColor Green }
function KO($t) { Write-Host "  [KO] $t" -ForegroundColor Red; $script:echecs++ }

function Ecoute($i) { "127.0.0.1:$($Ports[$i])" }
function Dossier($i) { Join-Path $Rep "n$i" }
function ErrLog($i) { Join-Path $Rep "n$i.err.log" }

# Arrête tout nœud encore debout sur nos ports (filet de sécurité entre deux runs).
function Arreter-Tout {
    foreach ($port in $Ports) {
        $c = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        foreach ($id in ($c.OwningProcess | Select-Object -Unique)) {
            try { Stop-Process -Id $id -Force -ErrorAction Stop } catch {}
        }
    }
    if (Test-Path $Rep) {
        foreach ($pf in Get-ChildItem -Path $Rep -Filter '*.pid' -ErrorAction SilentlyContinue) {
            try { Stop-Process -Id (Get-Content $pf.FullName) -Force -ErrorAction Stop } catch {}
        }
    }
}

function Attendre-Log($i, $motif, $secondes = 30) {
    $f = ErrLog $i
    $t = [Diagnostics.Stopwatch]::StartNew()
    while ($t.Elapsed.TotalSeconds -lt $secondes) {
        if ((Test-Path $f) -and (Select-String -Path $f -Pattern $motif -Quiet)) { return $true }
        Start-Sleep -Milliseconds 300
    }
    return $false
}

# Identifiant de genèse (128 hex) qu'un nœud a imprimé au démarrage.
function Genese-Id($i) {
    $f = ErrLog $i
    if (-not (Test-Path $f)) { return $null }
    $m = Select-String -Path $f -Pattern '([0-9a-f]{128})' | Select-Object -First 1
    if ($m) { $m.Matches[0].Groups[1].Value } else { $null }
}

# Plus haute hauteur SCELLÉE observée parmi les nœuds vivants (= tête finalisée + 1).
# Sur une chaîne saine elle MONTE ; une chaîne calée la fige.
function Hauteur-Max($vivants) {
    $max = -1
    foreach ($i in $vivants) {
        $f = ErrLog $i
        if (-not (Test-Path $f)) { continue }
        foreach ($m in Select-String -Path $f -Pattern 'hauteur (\d+) \(\d+ transactions\)') {
            $h = [int]$m.Matches[0].Groups[1].Value
            if ($h -gt $max) { $max = $h }
        }
    }
    $max
}

# Une hauteur CALÉE (split de votes) est un échec de consensus FRANC.
function Calage-Detecte($vivants) {
    foreach ($i in $vivants) {
        $f = ErrLog $i
        if ((Test-Path $f) -and (Select-String -Path $f -Pattern 'CAL.E' -Quiet)) { return $true }
    }
    return $false
}

# Attend que la hauteur scellée atteigne $cible. Échoue vite sur calage.
function Attendre-Hauteur($cible, $vivants, $secondes = 90) {
    $t = [Diagnostics.Stopwatch]::StartNew()
    while ($t.Elapsed.TotalSeconds -lt $secondes) {
        if (Calage-Detecte $vivants) { return 'calage' }
        if ((Hauteur-Max $vivants) -ge $cible) { return 'ok' }
        Start-Sleep -Milliseconds 500
    }
    return 'timeout'
}

# Démarre l'autorité i : scelle, archive, maillée aux autorités DÉJÀ démarrées
# (0..i-1). Un lien porte les messages dans LES DEUX SENS (l'atelier montre A→B sur
# un lien ouvert par B) : pairer chaque nœud aux précédents suffit donc à une maille
# complète, tout en ne connectant QUE des pairs déjà à l'écoute — sinon `connecter`
# bloque ~20 s sur un timeout et le démarrage simultané se verrouille.
function Demarrer($i) {
    $extra = @('--sceller', '2000')
    for ($j = 0; $j -lt $i; $j++) { $extra += '--pair'; $extra += (Ecoute $j) }
    $nodeArgs = @('--ecoute', (Ecoute $i), '--genese', (Join-Path $Rep 'genese.bin'),
                  '--archiver', '--donnees', (Dossier $i)) + $extra
    $p = Start-Process -FilePath (Exe 'obscura-node') -ArgumentList $nodeArgs -PassThru `
            -RedirectStandardOutput (Join-Path $Rep "n$i.log") `
            -RedirectStandardError (ErrLog $i) -WindowStyle Hidden
    $p.Id | Set-Content (Join-Path $Rep "n$i.pid")
    $p
}

# ============================================================================
Titre 'Répétition générale — étape 0 du runbook (chaîne jetable, 4 autorités)'

foreach ($binNom in 'obscura-wallet', 'obscura-genese', 'obscura-node') {
    if (-not (Test-Path (Join-Path $Bin "$binNom.exe"))) {
        Write-Host 'build release manquant — compilation…' -ForegroundColor Yellow
        Push-Location $Repo
        try { cargo build --release --bin obscura-wallet --bin obscura-genese --bin obscura-node }
        finally { Pop-Location }
        break
    }
}

Arreter-Tout
if (Test-Path $Rep) { Remove-Item $Rep -Recurse -Force }
if ($Nettoyer) { Write-Host 'nettoyage demandé — sortie.'; return }
New-Item -ItemType Directory -Path $Rep | Out-Null

try {
    # --- Identités des 4 autorités (clé publique hex sur stdout). ---
    Titre 'Identités des 4 autorités'
    $hex = @()
    for ($i = 0; $i -lt $Compte; $i++) {
        $out = & (Exe 'obscura-node') --identite --donnees (Dossier $i) 2>$null
        $h = ($out | Select-Object -Last 1).Trim()
        if ($h -notmatch '^[0-9a-f]+$') { KO "identité $i illisible : '$h'"; return }
        $hex += $h
        Write-Host "  autorité $i : $($h.Substring(0,16))…"
    }

    # --- Wallets + genèse fédérée. ---
    Wallet creer --fichier (Join-Path $Rep 'alice.wallet') | Out-Null
    $alice = Wallet adresse --fichier (Join-Path $Rep 'alice.wallet')
    Titre 'Genèse fédérée (4 autorités + allocation à Alice)'
    $autoArgs = @()
    foreach ($h in $hex) { $autoArgs += '--autorite-hex'; $autoArgs += $h }
    Genese --sortie (Join-Path $Rep 'genese.bin') @autoArgs --allocation "${alice}:1000000"

    # --- Démarrage des 4 autorités, maille complète. ---
    Titre 'Démarrage des 4 autorités (maille complète)'
    for ($i = 0; $i -lt $Compte; $i++) {
        Demarrer $i | Out-Null
        if (-not (Attendre-Log $i 'coute sur' 30)) { KO "autorité $i n'écoute pas"; return }
        Write-Host "  autorité $i démarrée (port $($Ports[$i]))"
    }

    # --- Critère 3 : même identifiant complet partout. ---
    Titre 'Critère 3 — identifiant de genèse identique sur les 4'
    Start-Sleep -Seconds 2
    $ids = 0..($Compte - 1) | ForEach-Object { Genese-Id $_ }
    $ref = $ids[0]
    if ($ref -and ($ids | Where-Object { $_ -eq $ref }).Count -eq $Compte) {
        OK "128 hex identiques : $($ref.Substring(0,16))…"
    } else {
        KO 'identifiants divergents entre autorités'
        for ($i = 0; $i -lt $Compte; $i++) { Write-Host "    n$i : $($ids[$i])" }
    }

    # --- Critère 4a : la hauteur avance, 4 debout. ---
    Titre 'Critère 4a — la hauteur avance (4 autorités debout)'
    $vivants = 0..($Compte - 1)
    switch (Attendre-Hauteur 3 $vivants 90) {
        'ok'      { OK "hauteur scellée atteint 3 (finalisation par quorum de 3/4)" }
        'calage'  { KO 'hauteur CALÉE avant la coupure (split de votes)' }
        'timeout' { KO "hauteur bloquée à $(Hauteur-Max $vivants) (jamais 3) — pas de finalisation" }
    }
    $avantCoupure = Hauteur-Max $vivants

    # --- Critère 4b : COUPER l'autorité 3 (productrice de h=4) → la chaîne continue. ---
    Titre 'Critère 4b — coupure de l''autorité 3 → liveness (changement de vue)'
    Write-Host '  producteur(h) = autorites[(h-1+vue) mod 4] ; on coupe l''autorité 3.'
    Write-Host '  Le quorum tombe à 3 voix disponibles pour 3 requises : la chaîne DOIT continuer.'
    try { Stop-Process -Id (Get-Content (Join-Path $Rep 'n3.pid')) -Force -ErrorAction Stop; OK 'autorité 3 coupée' }
    catch { KO 'coupure de l''autorité 3 impossible' }
    Remove-Item (Join-Path $Rep 'n3.pid') -ErrorAction SilentlyContinue
    $vivants = 0, 1, 2
    $cible = [Math]::Max(6, $avantCoupure + 3)
    switch (Attendre-Hauteur $cible $vivants 120) {
        'ok'      { OK "hauteur repart et dépasse $cible SANS l'autorité 3 (liveness J1-b2)" }
        'calage'  { KO 'hauteur CALÉE après la coupure — la chaîne ne survit pas à -1 autorité' }
        'timeout' { KO "hauteur figée à $(Hauteur-Max $vivants) après coupure (cible $cible)" }
    }

    # --- Critère 5 : synchro témoin corroborée sur la chaîne résultante. ---
    Titre 'Critère 5 — synchro Alice corroborée par témoin (2 archivistes restants)'
    try {
        Wallet synchroniser --fichier (Join-Path $Rep 'alice.wallet') --noeud (Ecoute 0) --temoin (Ecoute 1) | Out-Null
        OK 'synchro via n0, corroborée par le témoin n1'
    } catch { KO "synchro témoin échouée : $_" }
}
finally {
    Arreter-Tout   # jamais de nœud orphelin, même en cas d'échec
}

# --- Bilan. ---
Titre 'Bilan de la répétition'
if ($script:echecs -eq 0) {
    Write-Host "`n  ✅ RÉPÉTITION RÉUSSIE — étape 0 franchie (chaîne jetable détruite)." -ForegroundColor Green
    Write-Host '     Critères 3, 4 (dont coupure/liveness) et 5 observés en vrai.'
} else {
    Write-Host "`n  ❌ $($script:echecs) critère(s) en échec — NE PAS geler la vraie genèse." -ForegroundColor Red
    Write-Host '     Journaux : atelier/repetition/nX.err.log — diagnostiquer, corriger, recommencer.'
}
Write-Host "`n  './repetition-generale.ps1 -Nettoyer' pour effacer atelier/repetition/."
