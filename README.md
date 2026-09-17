# env-guard

[![CI](https://github.com/aaronladron/env-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/aaronladron/env-guard/actions/workflows/ci.yml)
[![Release](https://github.com/aaronladron/env-guard/actions/workflows/release.yml/badge.svg)](https://github.com/aaronladron/env-guard/actions/workflows/release.yml)
[![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`env-guard` détecte les secrets et credentials potentiellement exposés dans un
projet avant leur commit dans Git. Il fonctionne localement, sans base de
données, compte utilisateur, API externe ou service cloud.

```console
$ env-guard scan
env-guard

142 files scanned

2 potential secrets detected

HIGH  AWS access key ID
    config/aws.go:24
    Value: [REDACTED]

HIGH  GitHub token
    scripts/release.sh:12
    Value: [REDACTED]
```

Les valeurs trouvées ne sont jamais affichées intégralement ni conservées dans
les résultats.

## Fonctionnalités

- analyse récursive du dossier courant ;
- analyse du contenu exact de l’index avec `scan --staged` ;
- règles AWS, GitHub, Stripe, clés privées et affectations génériques ;
- filtrage des placeholders, de la documentation et des valeurs peu entropiques ;
- exclusions, allowlist exacte et seuil de sévérité configurables ;
- fichiers binaires et liens symboliques ignorés ;
- hook pre-commit idempotent et réversible ;
- sorties humaine et JSON versionnée ;
- codes de sortie adaptés aux scripts et à la CI ;
- binaires macOS, Linux et Windows produits avec GoReleaser.

## Installation

### Releases

Télécharger l’archive correspondant à votre plateforme depuis la page
[Releases](https://github.com/aaronladron/env-guard/releases), vérifier sa somme
SHA-256 avec `checksums.txt`, puis placer le binaire dans votre `PATH`.

Les plateformes publiées sont :

| Système | Architectures |
| --- | --- |
| macOS | amd64, arm64 |
| Linux | amd64, arm64 |
| Windows | amd64 |

### Avec Go

Go 1.27 ou une version ultérieure est requis :

```sh
go install github.com/aaronladron/env-guard/cmd/env-guard@latest
```

### Depuis les sources

```sh
git clone https://github.com/aaronladron/env-guard.git
cd env-guard
make build
./bin/env-guard --help
```

La seule dépendance directe est
[`go.yaml.in/yaml/v3`](https://pkg.go.dev/go.yaml.in/yaml/v3), utilisée pour
charger la configuration YAML avec une validation stricte.

## Démarrage rapide

Analyser tout le projet :

```sh
env-guard scan
```

Analyser uniquement les fichiers staged :

```sh
env-guard scan --staged
```

Installer le hook pre-commit :

```sh
env-guard init
```

Le hook exécute `env-guard scan --staged` avant chaque commit. Un secret potentiel
ou une erreur de scan bloque le commit.

## Commandes

| Commande | Description |
| --- | --- |
| `env-guard --help` | Affiche l’aide générale |
| `env-guard scan` | Analyse le dossier courant |
| `env-guard scan --staged` | Analyse les blobs présents dans l’index Git |
| `env-guard scan --json` | Produit le format JSON versionné |
| `env-guard scan --exclude MOTIF` | Ajoute une exclusion ; option répétable |
| `env-guard init` | Installe le hook pre-commit |
| `env-guard init --wrap` | Préserve et enveloppe un hook existant |
| `env-guard init --remove` | Retire env-guard et restaure l’ancien hook |

`--staged`, `--json` et `--exclude` peuvent être combinés.

### Hook existant

`env-guard init` n’écrase jamais un hook existant. Il s’arrête et indique la
commande sûre à utiliser :

```sh
env-guard init --wrap
```

Le hook actuel est déplacé vers `pre-commit.env-guard-backup`. Le wrapper
l’exécute en premier, puis lance env-guard uniquement s’il réussit.
`env-guard init --remove` restaure son contenu et ses permissions. La commande
respecte également `core.hooksPath`.

## Configuration

env-guard charge `.env-guard.yaml` depuis le dossier courant. Tous les champs
sont optionnels :

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

| Champ | Valeurs | Par défaut |
| --- | --- | --- |
| `exclude` | Noms ou chemins relatifs avec jokers simples | Liste vide |
| `ignore_rules` | Identifiants de règles existants | Liste vide |
| `allowlist` | Combinaisons exactes `path`, `line`, `rule` | Liste vide |
| `severity` | `low`, `medium`, `high` | `low` |
| `output` | `human`, `json` | `human` |

Les exclusions du fichier complètent celles données avec `--exclude`. Le drapeau
`--json` prend la priorité sur `output: human`.

Le chargeur refuse les champs inconnus, les règles inexistantes, les documents
YAML multiples et les configurations de plus de 1 Mio. Ses erreurs ne recopient
pas le contenu du fichier.

### Exclusions par défaut

Les noms suivants sont ignorés à tous les niveaux de l’arborescence :

```text
.git
node_modules
vendor
.gitignore
```

Les fichiers contenant des octets binaires, le texte UTF-8 invalide et les liens
symboliques sont également ignorés. Un fichier texte est limité à 10 Mio et une
ligne à 1 Mio. Une erreur de lecture invalide le scan complet.

## Règles de détection

| Identifiant | Détection | Sévérité |
| --- | --- | --- |
| `aws-access-key-id` | Identifiants AWS commençant par `AKIA` ou `ASIA` | HIGH |
| `github-classic-token` | Tokens GitHub `ghp_`, `gho_` ou `ghu_` | HIGH |
| `stripe-live-key` | Clés Stripe secrètes ou restreintes de production | HIGH |
| `stripe-test-key` | Clés Stripe secrètes ou restreintes de test | MEDIUM |
| `private-key-header` | En-têtes de clés privées PEM, OpenSSH et apparentés | HIGH |
| `generic-token` | Affectations explicites de clés API, tokens ou secrets | MEDIUM |
| `config-password` | Affectations explicites de mots de passe | MEDIUM |

Les règles fournisseurs recherchent un format plausible ; elles ne vérifient pas
la validité d’un credential auprès du fournisseur. Les règles génériques exigent
un contexte d’affectation et filtrent notamment :

- `YOUR_API_KEY_HERE`, `example-api-key`, `test-token` et `changeme` ;
- les références telles que `${API_KEY}` ou `process.env.API_TOKEN` ;
- les chaînes répétitives comme `xxxxxxxx` ;
- les tokens génériques dont l’entropie est insuffisante ;
- les affectations génériques dans README, Markdown, reStructuredText et AsciiDoc.

Une règle fournisseur reste active dans la documentation et prend la priorité
sur une règle générique pour éviter les doublons.

### Limites

Aucun scanner de secrets ne peut garantir l’absence de credentials. env-guard
peut produire des faux positifs ou manquer :

- un format fournisseur nouveau ou non couvert ;
- un secret découpé sur plusieurs lignes ;
- une valeur encodée, chiffrée ou construite dynamiquement ;
- un token générique sans contexte d’affectation reconnaissable.

Traitez chaque résultat comme un signal à vérifier. Si un secret réel a été
commité, révoquez-le et remplacez-le ; supprimer le texte de l’historique ne rend
pas le credential inoffensif.

## Format JSON

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

`version` vaut actuellement `1`. `findings` est toujours un tableau, même sans
résultat. La sortie se termine par un saut de ligne et ne contient jamais la
valeur détectée.

## Codes de sortie

| Code | Signification |
| --- | --- |
| `0` | Aucun secret détecté, ou aide affichée avec succès |
| `1` | Un ou plusieurs secrets potentiels détectés |
| `2` | Commande ou arguments invalides |
| `3` | Erreur de configuration, de lecture, de scan ou de sortie |

## GitHub Actions

Exemple d’utilisation dans un autre dépôt :

```yaml
- name: Installer Go
  uses: actions/setup-go@v7
  with:
    go-version: "1.27"

- name: Installer env-guard
  run: go install github.com/aaronladron/env-guard/cmd/env-guard@latest

- name: Rechercher les secrets
  run: "$(go env GOPATH)/bin/env-guard" scan
```

Le projet lui-même utilise :

- `ci.yml` pour les modules, le formatage, `go vet`, les tests avec détection de
  courses et les compilations Linux/macOS/Windows ;
- `release.yml` pour publier les cinq archives multiplateformes avec GoReleaser
  lors de la création d’un tag `v*`.

## Architecture

```text
cmd/env-guard/       point d’entrée du binaire
internal/cli/        commandes, arguments et codes de sortie
internal/config/     configuration YAML stricte
internal/git/        lecture des blobs staged et chemin des hooks
internal/hook/       installation et restauration du hook pre-commit
internal/output/     sorties humaine et JSON
internal/scanner/    parcours, règles, filtres et résultats
tests/fixtures/      gabarits de tests sans credentials réels
```

Le moteur accepte un `io.Reader`, un `fs.FS` ou une collection de fichiers en
mémoire. Il ne dépend ni de Git ni du système d’exploitation. Les règles, le
parcours, les filtres et la présentation restent séparés.

## Développement

```sh
git clone https://github.com/aaronladron/env-guard.git
cd env-guard
go mod download
make check
make build
```

Commandes disponibles :

```sh
make test
make test-race
make vet
make fmt
make fmt-check
make mod-verify
```

Valider une release sans la publier :

```sh
goreleaser check
goreleaser release --snapshot --clean
```

## Tests

La suite utilise uniquement le paquet standard `testing` :

```sh
go test ./...
go test -race ./...
go vet ./...
```

Les fixtures sont des gabarits. Les chaînes qui ressemblent à des formats
fournisseurs sont construites en mémoire avec des caractères répétés et ne
proviennent d’aucun compte réel.

## Contribuer

Consultez [CONTRIBUTING.md](CONTRIBUTING.md) pour préparer une modification,
ajouter une règle et exécuter les contrôles attendus.

## Sécurité

Consultez [SECURITY.md](SECURITY.md) pour signaler une vulnérabilité de manière
privée. Ne publiez jamais de secret, token ou credential dans une issue.

## Licence

Distribué sous licence MIT. Voir [LICENSE](LICENSE).
