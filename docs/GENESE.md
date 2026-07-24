# Ancre de genèse du testnet Obscura

> Ce fichier publie l'identifiant de la genèse de la chaîne courante. C'est
> l'ancre hors bande vis-à-vis du réseau P2P : `THREAT_MODEL.md` rappelle que
> rien dans le protocole n'atteste QUI a écrit la genèse — cette publication,
> plus la release signée, y supplée.

## Chaîne courante

- **Identifiant complet (32 o, hex)** : `<À RENSEIGNER AU GEL — sortie de obscura-genese>`
- **Genèse signée** : voir la release (`deploiement/verifier-release.sh`).
- **Valeur hors bande** : la même chaîne hex est publiée sur le canal d'invitation.

## Comment un opérateur vérifie

Au démarrage, `obscura-node --genese genese.bin` imprime l'identifiant COMPLET.
Le confronter (1) à la valeur ci-dessus ET (2) à la valeur reçue hors bande. Un
écart = ne pas rejoindre.
