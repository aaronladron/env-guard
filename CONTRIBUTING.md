# Contribuer à env-guard

Les corrections ciblées, nouvelles règles et améliorations de documentation sont
bienvenues. Une pull request doit rester limitée à un problème clairement décrit.

## Préparer le projet

Go 1.27 ou une version ultérieure est requis.

```sh
git clone https://github.com/aaronladron/env-guard.git
cd env-guard
go mod download
go test ./...
go vet ./...
```

Avant d’ouvrir une pull request :

```sh
make check
make test-race
```

Ajoutez un test qui démontre le comportement corrigé lorsque la modification
touche la détection, Git, les hooks, la configuration ou les formats de sortie.
N’ajoutez jamais de credential réel dans un test, une fixture, un commit ou une
discussion.

## Ajouter une règle

Les règles intégrées se trouvent dans `internal/scanner/patterns.go`.

1. choisissez un identifiant stable et descriptif ;
2. documentez le format à partir d’une source officielle du fournisseur ;
3. choisissez la sévérité selon l’impact de la valeur ;
4. capturez uniquement la partie secrète lorsque la règle contient du contexte ;
5. ajoutez des cas positifs, des limites de longueur et des non-correspondances ;
6. construisez les exemples au moment du test avec des caractères répétés ;
7. vérifiez que la valeur n’apparaît jamais dans un `Finding` ou une sortie.

Une règle générique doit justifier son contexte et ses filtres. Évitez d’ajouter
une expression très large qui déplacerait le coût vers les utilisateurs sous la
forme de faux positifs.

## Style

- utilisez `gofmt` ;
- gardez les erreurs compréhensibles et sans contenu potentiellement sensible ;
- commentez les contrats et décisions non évidentes ;
- préférez une fonction simple à une abstraction sans usage concret ;
- conservez le cœur du scanner indépendant du système d’exploitation.

Les commits et descriptions de pull request doivent expliquer le comportement
final et les vérifications réellement exécutées.
