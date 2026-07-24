# Étape 3 — deux nœuds : A scelle + archive, B archive + sert de témoin.
. "$PSScriptRoot\lib.ps1"

Etape 'Étape 3 — deux nœuds (A scelle+archive, B archive+témoin)'

# Au cas où un run précédent aurait laissé des nœuds debout (ports occupés).
Arreter-Noeuds

# A : le producteur. --sceller 3000 = tente de sceller toutes les 3 s (mais un nœud
# ne scelle pas de bloc VIDE : la hauteur ne bougera qu'après le paiement).
Demarrer-Noeud 'A' $NoeudA @('--sceller', '3000') | Out-Null
if (-not (Attendre-Log 'A' 'écoute sur' 30)) { throw "nœud A n'écoute pas — voir travail\A.err.log" }

# B : archiviste témoin, relié à A par --pair. Il reçoit les blocs scellés par
# diffusion et sert de second avis (--temoin) contre une omission de A.
Demarrer-Noeud 'B' $NoeudB @('--pair', $NoeudA) | Out-Null
if (-not (Attendre-Log 'B' 'écoute sur' 30)) { throw "nœud B n'écoute pas — voir travail\B.err.log" }
if (-not (Attendre-Log 'B' 'connecté à' 15)) { Write-Host "⚠️  B n'a pas confirmé sa connexion à A." }

Write-Host "`nA et B debout, même genèse. B est relié à A (il recevra les blocs scellés)."
Write-Host "Genèse (doit être IDENTIQUE sur les deux) :"
Journal-Noeud 'A' | Select-String 'genèse ' | ForEach-Object { "  A : $_" }
Journal-Noeud 'B' | Select-String 'genèse ' | ForEach-Object { "  B : $_" }
