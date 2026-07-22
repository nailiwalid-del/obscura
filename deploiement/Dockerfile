# Image d'un nœud Obscura (prototype, non audité).
#
#   docker build -f deploiement/Dockerfile -t obscura-node .
#   docker run -d --name obscura -p 9333:9333 \
#       -v obscura-donnees:/donnees \
#       obscura-node --ecoute 0.0.0.0:9333 --donnees /donnees
#
#   docker logs -tf obscura      # -t : horodatage absolu, ajouté par Docker
#
# Construction en DEUX étapes : l'image finale ne contient ni la chaîne de
# compilation Rust, ni les sources, ni le cache de build — seulement le binaire.

FROM rust:1.87-bookworm AS constructeur
WORKDIR /source

# Les dépendances d'abord, pour que le cache de couches survive à un changement
# de code : `cargo fetch` ne re-télécharge pas tant que les manifestes n'ont pas
# bougé. Les manifestes des huit crates sont nécessaires à la résolution.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
# `--locked` : la construction ÉCHOUE si Cargo.lock ne suffit pas, au lieu de
# résoudre silencieusement d'autres versions que celles testées. Sur un projet
# cryptographique, une dépendance qui glisse sans qu'on le sache est inacceptable.
RUN cargo build --release --locked --bin obscura-node

# Image d'exécution minimale. `bookworm-slim` et non `scratch` : le binaire est
# lié dynamiquement à la libc et les crates pqcrypto embarquent du C.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur NON privilégié. Le fichier d'identité contient du matériel de clé
# en clair : le protéger par les permissions est le seul mécanisme disponible.
RUN useradd --system --uid 10001 --home /donnees --shell /usr/sbin/nologin obscura \
    && install -o obscura -g obscura -d /donnees
COPY --from=constructeur /source/target/release/obscura-node /usr/local/bin/obscura-node

USER obscura
WORKDIR /donnees
VOLUME ["/donnees"]
EXPOSE 9333

# Niveau de journal : erreur | avert | info | debug.
ENV OBSCURA_LOG=info

ENTRYPOINT ["/usr/local/bin/obscura-node"]
# Sans argument, le nœud affiche son aide et sort — plutôt que de démarrer sur
# une configuration devinée. La genèse et l'écoute sont des décisions
# d'opérateur, jamais des valeurs par défaut.
CMD ["--help"]
