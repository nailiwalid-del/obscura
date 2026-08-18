#!/usr/bin/env bash
# Vérifie le registre PROUVÉ de docs/STARK_STATEMENT.md.
#
#   ./verification/verifier.sh            structurel seul, quelques secondes
#   ./verification/verifier.sh --complet  rejoue en plus les tests nommés
#
# Le mode structurel répond à « les preuves annoncées existent-elles, aux
# valeurs annoncées ? ». Le mode complet répond à « passent-elles ? ».
# Sortie 0 si tout tient, 1 sinon.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

CARTE="verification/revendications.psv"
COMPLET=0
[ "${1:-}" = "--complet" ] && COMPLET=1

if [ ! -f "$CARTE" ]; then echo "carte absente : $CARTE" >&2; exit 2; fi

if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; B=$'\033[1m'; Z=$'\033[0m'
else G=""; R=""; D=""; B=""; Z=""; fi

ok=0; ko=0; skip=0
declare -a ECHECS=()

# --- mode complet : une seule passe cargo, on parse ensuite ------------------
RESULTATS=""
if [ "$COMPLET" -eq 1 ]; then
  echo "${D}cargo test -p circuit --lib --release  (plusieurs minutes)${Z}"
  RESULTATS=$(cargo test -p circuit --lib --release 2>&1)
fi

verdict_test() {   # $1 = nom du test
  if [ "$COMPLET" -eq 0 ]; then echo "SKIP"; return; fi
  if grep -qE "^test .*[:]$1 [.][.][.] ok" <<<"$RESULTATS"; then
    echo "OK"
  elif grep -qE "\b$1\b.*(FAILED|panicked)" <<<"$RESULTATS"; then
    echo "KO"
  else
    echo "ABSENT"
  fi
}

ligne() { printf '  %-6s %-52s %s\n' "$1" "$2" "$3"; }

courant=""
while IFS='|' read -r id revend genre cible attendu; do
  case "$id" in ''|'#'*) continue;; esac

  if [ "$id" != "$courant" ]; then
    courant="$id"
    printf '\n%s%s  %s%s\n' "$B" "$id" "$revend" "$Z"
  fi

  statut="KO"; detail=""
  case "$genre" in
    const|assert|ancre)
      if [ ! -f "$cible" ]; then
        statut="KO"; detail="fichier absent"
      elif grep -qF -- "$attendu" "$cible"; then
        statut="OK"; detail="$cible"
      else
        statut="KO"; detail="absent de $cible"
      fi
      etiq="$attendu"
      ;;
    test)
      if ! grep -rqn --include=*.rs -E "fn +$cible *\(" crates/; then
        statut="KO"; detail="test introuvable dans crates/"
      else
        v=$(verdict_test "$cible")
        case "$v" in
          OK)     statut="OK";   detail="passe" ;;
          KO)     statut="KO";   detail="ÉCHOUE" ;;
          ABSENT) statut="KO";   detail="non exécuté par cargo" ;;
          SKIP)   statut="SKIP"; detail="existe (--complet pour l'exécuter)" ;;
        esac
      fi
      etiq="$cible"
      ;;
    *) statut="KO"; detail="genre inconnu : $genre"; etiq="$cible" ;;
  esac

  case "$statut" in
    OK)   ok=$((ok+1));   ligne "${G}OK${Z}"   "$etiq" "${D}$detail${Z}" ;;
    SKIP) skip=$((skip+1)); ligne "${D}--${Z}" "$etiq" "${D}$detail${Z}" ;;
    KO)   ko=$((ko+1));   ligne "${R}KO${Z}"   "$etiq" "${R}$detail${Z}"
          ECHECS+=("$id / $etiq : $detail") ;;
  esac
done < "$CARTE"

printf '\n%s\n' "────────────────────────────────────────────────────────────────"
if [ "$COMPLET" -eq 0 ]; then
  printf '%d vérifiées, %d non tenues, %d tests non exécutés.\n' "$ok" "$ko" "$skip"
  printf '%sRelancer avec --complet pour rejouer les tests.%s\n' "$D" "$Z"
else
  printf '%d vérifiées, %d non tenues.\n' "$ok" "$ko"
fi

if [ "$ko" -gt 0 ]; then
  printf '\n%sRevendications non tenues :%s\n' "$R" "$Z"
  for e in "${ECHECS[@]}"; do printf '  - %s\n' "$e"; done
  printf '\nUne revendication non tenue est un défaut de la spec OU du code.\n'
  printf 'Corriger l%sun des deux ; ne pas retirer la ligne de la carte.\n' "'"
  exit 1
fi
printf '\nLe registre PROUVÉ de docs/STARK_STATEMENT.md est tenu.\n'
