# Fixtures

Ces fichiers ne contiennent aucun credential réel.

Les marqueurs `{{AWS_ACCESS_KEY}}`, `{{GITHUB_TOKEN}}`, `{{STRIPE_LIVE_KEY}}` et
`{{STRIPE_TEST_KEY}}` sont remplacés en mémoire par les tests. Les valeurs sont
construites à partir de caractères répétés et ne proviennent d’aucun compte.
Le fichier PEM contient uniquement un en-tête reconnaissable et un corps invalide.

Les fichiers de configuration positifs sont donc des gabarits : les analyser
directement, sans substitution, ne reproduit pas les détections des tests.
