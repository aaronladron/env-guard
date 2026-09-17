# Politique de sécurité

## Signaler une vulnérabilité

Utilisez les
[avis de sécurité privés GitHub](https://github.com/aaronladron/env-guard/security/advisories/new)
pour signaler une vulnérabilité. N’ouvrez pas d’issue publique avant qu’un
correctif ou une mesure de réduction du risque soit disponible.

Ne transmettez jamais un secret réel dans le rapport. Révoquez immédiatement
tout credential exposé et remplacez sa valeur par une chaîne masquée ou un
exemple synthétique.

## Informations utiles

Un rapport exploitable contient idéalement :

- la version ou le commit concerné ;
- le système d’exploitation et l’architecture ;
- les conditions nécessaires pour reproduire le problème ;
- son impact attendu ;
- un exemple minimal sans donnée sensible ;
- toute proposition de correction ou de réduction du risque.

## Traitement du rapport

Le rapport sera d’abord confirmé et son impact évalué. Les échanges et travaux
préparatoires resteront privés tant qu’une publication pourrait exposer les
utilisateurs. Après correction, une note de sécurité pourra décrire les versions
concernées, la mise à jour recommandée et les crédits souhaités par l’auteur du
signalement.

Les faux positifs et demandes de nouvelles règles qui n’exposent pas de faiblesse
du logiciel peuvent être proposés dans une issue publique, toujours avec des
valeurs synthétiques.
