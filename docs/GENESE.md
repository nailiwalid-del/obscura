# Ancre de genèse du testnet Obscura

> Ce fichier publie l'identifiant de la genèse de la chaîne courante. C'est
> l'ancre hors bande vis-à-vis du réseau P2P : `THREAT_MODEL.md` rappelle que
> rien dans le protocole n'atteste QUI a écrit la genèse — cette publication,
> plus la release signée, y supplée.

## Chaîne courante

- **Identifiant complet (64 o, hex)** : `<À RENSEIGNER AU GEL — sortie de obscura-genese>`
- **Genèse signée** : voir la release (`deploiement/verifier-release.sh`).
- **Valeur hors bande** : la même chaîne hex est publiée sur le canal d'invitation.

> ⚠️ **64 octets, soit 128 caractères hexadécimaux** — pas 32. L'identifiant est le
> `dual_hash` (BLAKE3‖SHA3-256, `DUAL_DIGEST_LEN = 64`), jamais tronqué. La forme
> **courte** imprimée à côté (8 o = 16 hex) est un diagnostic de commodité, **pas**
> l'ancre : comparez la valeur COMPLÈTE.

## Comment un opérateur vérifie

Au démarrage, `obscura-node --genese genese.bin` imprime l'identifiant COMPLET
(les 128 caractères hex). Le confronter (1) à la valeur ci-dessus ET (2) à la valeur
reçue hors bande. Un écart, **fût-ce d'un seul caractère** = ne pas rejoindre.
