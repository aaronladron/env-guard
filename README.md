# env-guard

Un outil CLI écrit en Go pour détecter les secrets potentiellement exposés dans
un projet avant leur commit dans Git.

**État du développement : étape 8.** La commande `scan` parcourt le dossier
courant ou uniquement le contenu staged dans Git. `init` gère le hook pre-commit.
La configuration YAML et les sorties humaine et JSON sont disponibles. GitHub
Actions vérifie le projet et GoReleaser construit les releases multiplateformes.

## Compiler et exécuter

Go 1.27 ou une version ultérieure est requis. La seule dépendance externe est
`go.yaml.in/yaml/v3`, utilisée pour parser YAML strictement et correctement.

```sh
go build -o bin/env-guard ./cmd/env-guard
./bin/env-guard --help
./bin/env-guard scan
```

Sous Windows, utiliser `-o bin/env-guard.exe`, puis exécuter ce fichier.

Exclure un nom dans toute l’arborescence ou un chemin relatif :

```sh
env-guard scan --exclude generated --exclude 'fixtures/*.txt'
```

L’option peut être répétée et accepte aussi la forme `--exclude=generated`.
Les commandes, options et arguments non pris en charge sont rejetés.
`--exclude` peut être combiné avec `--staged`.

Analyser uniquement ce qui sera inclus dans le prochain commit :

```sh
env-guard scan --staged
```

Ce mode lit les blobs présents dans l’index Git. Une modification non staged du
même fichier ne change donc pas le résultat. Les fichiers non suivis et les
suppressions staged ne sont pas analysés.

Produire une sortie JSON :

```sh
env-guard scan --json
env-guard scan --staged --json
```

## Hook pre-commit

Installer le hook dans le dépôt courant :

```sh
env-guard init
```

L’installation est idempotente. Le hook lance `env-guard scan --staged` et bloque
le commit si des secrets potentiels sont détectés, si le scan échoue ou si le
binaire `env-guard` n’est pas disponible dans le `PATH` du processus Git.

Un hook existant n’est jamais écrasé. La commande s’arrête et propose de le
conserver explicitement :

```sh
env-guard init --wrap
```

L’ancien hook est déplacé vers `pre-commit.env-guard-backup`. Le nouveau hook
l’exécute en premier et ne lance env-guard que s’il réussit. Le type de l’ancien
hook n’a pas d’importance : son shebang d’origine reste utilisé.

Retirer env-guard :

```sh
env-guard init --remove
```

Un hook installé seul est supprimé. Un hook enveloppé est remplacé par sa
sauvegarde, avec son contenu et ses permissions d’origine. La commande respecte
également `core.hooksPath` lorsque cette option Git est configurée.

## Architecture

```text
cmd/env-guard/main.go           Point d’entrée et code de sortie du processus
internal/cli/                  Arguments, aide et sorties du CLI
internal/config/               Chargement strict de .env-guard.yaml
internal/git/                  Lecture sûre des fichiers présents dans l’index
internal/hook/                 Installation et retrait du hook pre-commit
internal/output/               Sorties humaine et JSON
internal/scanner/
  scanner.go                   Lecture bornée du flux et annulation
  files.go                     Parcours, exclusions et fichiers binaires
  detector.go                  Validation et exécution des règles injectées
  filter.go                    Placeholders, documentation et entropie
  finding.go                   Résultats localisés et niveaux de sévérité
  patterns.go                  Catalogue des premières règles
  patterns_test.go             Formats reconnus et fixtures
  detector_test.go             Règles, masquage et scans concurrents
  scanner_test.go              Lecture, limites et erreurs
```

Le point d’entrée délègue au CLI, dont les sorties sont injectées pour permettre
les tests sans quitter le processus. Le moteur reçoit un `io.Reader` : il est
indépendant du système de fichiers, de Git et du système d’exploitation. Les
règles sont fournies séparément au constructeur ; le catalogue fournisseur reste
séparé de la lecture, du parcours et de la détection.

`ScanFS` travaille avec un `fs.FS`, ce qui garde le parcours testable et portable.
Le CLI ouvre le dossier courant avec `os.OpenRoot` et ne suit pas les liens
symboliques rencontrés pendant le parcours.

Le mode staged appelle l’exécutable Git local avec des arguments séparés, puis
résout les objets de l’index par leur identifiant. Les noms sont lus avec un
séparateur nul : les espaces, tabulations et sauts de ligne dans un chemin ne
modifient pas le découpage. Les messages d’erreur de Git ne sont pas recopiés
dans la sortie afin d’éviter d’y propager du contenu sensible.

## Configuration

env-guard charge automatiquement `.env-guard.yaml` depuis le dossier courant.
L’absence du fichier utilise les valeurs par défaut. Les champs inconnus, les
règles inexistantes et les documents YAML multiples font échouer le scan.

```yaml
exclude:
  - generated
  - "fixtures/*.txt"

ignore_rules:
  - stripe-test-key

allowlist:
  - path: config/example.txt
    line: 12
    rule: aws-access-key-id

severity: medium
output: human
```

- `exclude` complète les exclusions par défaut et celles données avec
  `--exclude` ;
- `ignore_rules` désactive des identifiants du catalogue existant ;
- `allowlist` ignore une seule combinaison exacte de chemin, ligne et règle ;
- `severity` accepte `low`, `medium` ou `high` et vaut `low` par défaut ;
- `output` accepte `human` ou `json` et vaut `human` par défaut.

`--json` force JSON même si la configuration demande la sortie humaine. Une
configuration ne peut pas réactiver une sortie humaine demandée explicitement en
JSON. Le fichier est limité à 1 Mio et ses erreurs restent volontairement
génériques pour ne pas recopier une valeur sensible dans le terminal.

## Format JSON

Le format porte un numéro de version et utilise toujours un tableau pour
`findings`, y compris lorsqu’il est vide :

```json
{
  "version": 1,
  "files_scanned": 2,
  "skipped_entries": 1,
  "findings": [
    {
      "type": "AWS access key ID",
      "severity": "HIGH",
      "file": "config.txt",
      "line": 4,
      "rule": "aws-access-key-id",
      "message": "Potential AWS access key ID detected",
      "value": "[REDACTED]"
    }
  ]
}
```

La sortie JSON se termine par un saut de ligne. Son code de sortie reste 0, 1,
2 ou 3 selon le résultat du scan ; le JSON n’est donc pas une indication de
succès à lui seul.

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
- Un fichier texte est limité à 10 Mio. Une ligne reste limitée à 1 Mio.
- Les fichiers contenant des octets de contrôle binaires ou du texte UTF-8
  invalide sont ignorés.
- `.git`, `node_modules`, `vendor` et les fichiers `.gitignore` sont ignorés par
  défaut, quel que soit leur niveau dans l’arborescence.
- Les liens symboliques et les autres entrées non régulières sont ignorés.
- Une erreur de lecture invalide le rapport complet ; aucun résultat partiel
  n’est présenté comme un scan réussi.
- Le mode staged prend les fichiers ajoutés, copiés, modifiés ou renommés. Les
  suppressions, liens symboliques et sous-modules sont ignorés.
- Git doit être installé et le dossier courant doit appartenir à un dépôt Git.
  Un blob staged dépassant 10 Mio fait échouer le scan avant son chargement.

## Premières règles

Le catalogue s’utilise avec `scanner.NewDetector(scanner.DefaultRules())`.
`DefaultRules` renvoie une nouvelle liste à chaque appel : sa modification ne
change pas les détecteurs existants ou les futurs appels.

| Identifiant | Format recherché | Sévérité |
| --- | --- | --- |
| `aws-access-key-id` | `AKIA` ou `ASIA`, suivis de 16 caractères alphanumériques majuscules | HIGH |
| `github-classic-token` | `ghp_`, `gho_` ou `ghu_`, suivis de 36 caractères alphanumériques | HIGH |
| `stripe-live-key` | `sk_live_` ou `rk_live_`, suivis d’au moins 24 caractères alphanumériques | HIGH |
| `stripe-test-key` | `sk_test_` ou `rk_test_`, suivis d’au moins 24 caractères alphanumériques | MEDIUM |
| `private-key-header` | En-tête PEM privé, RSA, EC, DSA, OpenSSH ou PKCS#8 chiffré | HIGH |
| `generic-token` | Affectation explicite d’une clé API, d’un token, secret ou credential | MEDIUM |
| `config-password` | Affectation explicite d’un mot de passe | MEDIUM |

Ces règles signalent des formats plausibles. Elles ne vérifient ni l’existence,
ni la validité, ni les permissions d’un credential, et n’effectuent aucun appel
réseau. Les longueurs sont des choix de détection, pas une garantie que tous les
formats actuels ou futurs des fournisseurs seront reconnus.

Un identifiant AWS seul ne suffit pas à s’authentifier ; il reste un indice de
credentials potentiellement présents à proximité. Les clés Stripe publiques
(`pk_`) ne sont pas signalées par ce catalogue. Les clés secrètes de test sont
signalées avec une sévérité inférieure : elles ne sont pas des clés publiques.
Un en-tête de clé privée déclenche une détection même si le corps est absent ou
invalide ; le moteur ne valide pas de bloc cryptographique.

Les tokens GitHub à permissions fines (`github_pat_`), les tokens d’installation
(`ghs_`) et de rafraîchissement (`ghr_`), les anciens tokens sans préfixe, les clés
OpenAI et les secrets JWT ne possèdent pas encore de règle fournisseur dédiée.
Ils peuvent seulement être signalés par une affectation générique. La présence
d’un fichier `.env` ne produit pas, à elle seule, de détection.

Les règles génériques exigent un contexte d’affectation. Elles écartent les
placeholders usuels, les références à des variables d’environnement et les
valeurs répétitives. Les tokens génériques doivent aussi atteindre une entropie
de Shannon minimale. Ces règles génériques sont désactivées dans les fichiers de
documentation (`.md`, `.rst`, `.adoc`, README, LICENSE et CHANGELOG).

Une règle fournisseur reste active dans la documentation et prend la priorité sur
une règle générique pour la même valeur. Cela évite un doublon sans masquer une
clé reconnaissable. L’allowlist peut cibler exactement un chemin, une ligne et
une règle depuis `.env-guard.yaml`.

Références des préfixes : [AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html),
[formats GitHub](https://github.blog/engineering/behind-githubs-new-authentication-token-formats/)
et [clés Stripe](https://docs.stripe.com/keys).

## Codes de sortie actuels du CLI

| Code | Signification |
| --- | --- |
| 0 | Aucun secret détecté, ou aide affichée avec succès |
| 1 | Un ou plusieurs secrets potentiels détectés |
| 2 | Commande ou arguments invalides |
| 3 | Erreur de lecture, de scan ou d’écriture de la sortie |

La sortie humaine affiche uniquement `[REDACTED]` à la place de la valeur trouvée.

## Développement et tests

```sh
go test ./...
go vet ./...
go fmt ./...
```

Les tests du moteur utilisent des règles et des valeurs explicitement synthétiques,
sans credentials réels. Les fixtures de `tests/fixtures` sont des gabarits ; les
valeurs au format fournisseur sont construites uniquement en mémoire pendant les
tests. Aucun compte ni service externe n’est utilisé. Ils vérifient les captures, les sévérités, les numéros de
ligne, le masquage, la stabilité des règles, les analyses concurrentes, les limites
de taille, les erreurs de lecture, l’annulation, les exclusions, les fichiers
binaires, les placeholders, l’entropie, l’allowlist et les codes de sortie.

Le détecteur de courses peut également être utilisé avec une chaîne C compatible :

```sh
go test -race ./...
```

La dernière étape complétera la documentation du projet et les fichiers destinés
aux contributeurs et au signalement de vulnérabilités.

## Intégration continue

`.github/workflows/ci.yml` s’exécute sur chaque pull request et chaque push vers
`main`. Un job Linux vérifie les modules, le formatage, `go vet` et les tests avec
le détecteur de courses. Une matrice exécute les tests et compile le CLI sur
Linux, macOS et Windows.

Les commandes locales équivalentes sont regroupées dans le `Makefile` :

```sh
make check
make test-race
make build
```

## Releases

Un tag Git commençant par `v` déclenche `.github/workflows/release.yml`.
GoReleaser v2.18.1 crée une release GitHub avec les archives suivantes :

- macOS amd64 et arm64 ;
- Linux amd64 et arm64 ;
- Windows amd64.

Les archives Unix utilisent `tar.gz` et Windows utilise `zip`. Un fichier
`checksums.txt` contient les sommes SHA-256. Le workflow récupère tout
l’historique Git pour générer le changelog et possède uniquement la permission
`contents: write` nécessaire à la publication.

Tester la configuration sans publier :

```sh
goreleaser check
goreleaser release --snapshot --clean
```
