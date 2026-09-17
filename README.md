# env-guard

Un outil CLI écrit en Go pour détecter les secrets potentiellement exposés dans
un projet avant leur commit dans Git.

**État du développement : étape 2.** Le CLI minimal et le moteur de détection
sont disponibles. Aucune règle de détection réelle n’est encore fournie et le
moteur n’est pas encore raccordé à la commande `scan`. Cette version ne peut pas
servir de contrôle de sécurité.

## Compiler et exécuter

Go 1.27 ou une version ultérieure est requis. Le projet utilise uniquement la
bibliothèque standard, sans dépendance Go externe.

```sh
go build -o bin/env-guard ./cmd/env-guard
./bin/env-guard --help
./bin/env-guard scan
```

Sous Windows, utiliser `-o bin/env-guard.exe`, puis exécuter ce fichier.

Pour l’instant, `scan` écrit ce message sur la sortie d’erreur et retourne le code 3 :

```text
Error: scanning is not implemented yet; no files were scanned.
```

Ce comportement évite de signaler un contrôle réussi alors que le scanner complet
n’existe pas encore. `scan --help` affiche l’aide et retourne 0. Les commandes,
options et arguments non pris en charge sont rejetés, notamment `--staged`.

## Architecture

```text
cmd/env-guard/main.go           Point d’entrée et code de sortie du processus
internal/cli/                  Arguments, aide et sorties du CLI
internal/scanner/
  scanner.go                   Lecture bornée du flux et annulation
  detector.go                  Validation et exécution des règles injectées
  finding.go                   Résultats localisés et niveaux de sévérité
  detector_test.go             Règles, masquage et scans concurrents
  scanner_test.go              Lecture, limites et erreurs
```

Le point d’entrée délègue au CLI, dont les sorties sont injectées pour permettre
les tests sans quitter le processus. Le moteur reçoit un `io.Reader` : il est
indépendant du système de fichiers, de Git et du système d’exploitation. Les
règles sont fournies séparément au constructeur ; aucune règle fournisseur n’est
codée dans le moteur. Le parcours des fichiers viendra dans une étape suivante.

## Moteur de détection

`scanner.NewDetector([]scanner.Rule{...})` valide les règles et compile leurs
expressions régulières une seule fois. Chaque règle possède :

- un identifiant unique, un type, un message descriptif et une sévérité ;
- un motif appliqué ligne par ligne ;
- un indice de capture désignant le secret (`0` pour la correspondance entière).

Les sévérités disponibles sont `LOW`, `MEDIUM` et `HIGH`. Le constructeur refuse
une liste vide, les métadonnées manquantes, les identifiants dupliqués, les motifs
invalides, les motifs correspondant à une entrée vide et les indices de capture
hors limites. Les captures absentes ou vides ne produisent pas de détection.

`detector.Scan(ctx, fichier, lecteur)` renvoie des `Finding` contenant le type,
la sévérité, le fichier, le numéro de ligne à partir de 1, l’identifiant de règle,
le message et une valeur masquée. Le fichier est un libellé fourni par l’appelant :
le moteur ne l’ouvre pas lui-même et ne ferme pas le lecteur fourni.

La valeur détectée est entièrement remplacée par `[REDACTED]`, même pour un secret
court. Le résultat ne conserve ni le secret ni sa ligne source. Les métadonnées
des règles doivent être des descriptions statiques, sans credentials ; elles et
le nom du fichier ne sont pas masqués. Les erreurs de validation n’affichent pas
le motif invalide, et les erreurs du lecteur sont remplacées par `ErrRead` pour
éviter d’exposer du texte source dans les diagnostics.

L’ordre des résultats est déterministe : ligne, ordre des règles, puis position
des correspondances pour chaque règle. Deux règles peuvent signaler le même
emplacement. Un détecteur peut être réutilisé simultanément avec des lecteurs
indépendants.

### Limites actuelles

- Les règles sont évaluées sur une ligne à la fois, sans détection multiligne.
- Les fins de ligne LF et CRLF sont prises en charge, y compris sans saut de ligne final.
- Une ligne est limitée à 1 Mio, hors fin de ligne. Le dépassement retourne
  `ErrLineTooLong`, sans ignorer silencieusement la ligne.
- Une erreur ou une annulation ne renvoie aucun résultat partiel. Une analyse sans
  correspondance renvoie une liste vide, sans erreur.
- L’annulation est contrôlée entre les lectures et les lignes. Elle ne peut pas
  interrompre un lecteur déjà bloqué ou une expression régulière en cours.
- La lecture est progressive, mais les résultats sont conservés en mémoire : leur
  volume dépend du nombre de correspondances.
- Les règles réelles, la réduction des faux positifs, les exclusions, les fichiers
  binaires et le parcours des répertoires ne sont pas encore implémentés.

## Codes de sortie actuels du CLI

| Code | Signification |
| --- | --- |
| 0 | Aide affichée avec succès |
| 2 | Commande ou arguments invalides |
| 3 | Scan indisponible ou erreur d’écriture de la sortie |

Le code 1 sera introduit lors du raccordement de la détection au CLI. Aucun scan
réussi n’est possible depuis la ligne de commande à ce stade.

## Développement et tests

```sh
go test ./...
go vet ./...
go fmt ./...
```

Les tests du moteur utilisent des règles et des valeurs explicitement synthétiques,
sans credentials réels. Ils vérifient les captures, les sévérités, les numéros de
ligne, le masquage, la stabilité des règles, les analyses concurrentes, les limites
de taille, les erreurs de lecture et l’annulation.

Le détecteur de courses peut également être utilisé avec une chaîne C compatible :

```sh
go test -race ./...
```

Les étapes suivantes ajouteront les premières règles réelles, les exclusions et
les faux positifs, Git staged, le hook pre-commit, JSON et la configuration, puis
la CI, les releases et la documentation complète.
