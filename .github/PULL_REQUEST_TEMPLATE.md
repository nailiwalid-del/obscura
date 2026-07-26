<!--
Merci pour la contribution. Ce gabarit est court exprès : il ne demande que ce
qui ne se lit pas dans le diff. Détail des règles : CONTRIBUTING.md
-->

## Ce que ça change, et pourquoi

<!-- Deux ou trois phrases. Le « pourquoi » est ce que le diff ne dit pas. -->

## Surface de stabilité

Cette PR touche-t-elle l'un des points de `docs/STABILITE.md` (`VERSION_BLOC` ou
un format de fil, l'énoncé STARK, le backend PQ, le mécanisme économique, les
formats wallet/nœud, un invariant de consensus) ?

- [ ] **Non** — aucun de ces points.
- [ ] **Oui**, et le sujet a été discuté en amont (issue ou ADR) : <!-- lien -->

> Un « oui » non annoncé remet à zéro une horloge de trois mois dont dépendent
> des décisions bien plus lourdes qu'une revue de code. Ce n'est pas une
> interdiction — c'est un préalable.

## Vérifications

- [ ] Tous les commits sont signés (`git commit -s`) — le job `dco` le vérifie.
- [ ] `cargo fmt --all --check` passe.
- [ ] `cargo clippy --workspace --all-targets --release -- -D warnings` passe,
      **et** la même commande avec `--all-features`.
- [ ] `cargo test --workspace --release --all-features` passe.
- [ ] Les tests couvrent le changement (unitaires dans le module ; bout en bout
      dans `crates/ledger/tests/` si le comportement traverse les crates).
- [ ] `docs/` est à jour si le comportement documenté change — `docs/` fait
      autorité, une divergence est un défaut.
- [ ] Tout nouveau hash ou PRF est séparé par domaine et non tronqué.
