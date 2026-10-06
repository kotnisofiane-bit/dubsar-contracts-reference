# OC-BRIDGE-01 — contrat de frontière v1

Bibliothèque ESM `@dubsar/contracts` : handler/factory embeddable autour d’OC-KERNEL-01, plus un harness stdio JSON-lines de **laboratoire uniquement**.

Cette frontière n’ajoute aucune sémantique de vérité, aucun workflow, aucune action métier et aucune autorité parallèle. Elle expose exactement deux opérations :

* `observe` → port kernel `ingestObservation`
* `get_context_view` → port kernel `readView`

## Hors profil

My Work, Hermes, Platform, Core, HTTP, TCP, Unix daemon, MCP, cron, worker, systemd, service déployé, auth Core/SSO, connecteur réel.

`SimulatedAuthority` n’est admise que dans le harness lab explicitement marqué `--lab`. Elle n’est pas un fallback du bridge de production.

## Autorité

La requête cliente ne peut ni fournir ni remplacer :

* `trust`
* `tenant_id`
* `environment_id`
* `principal_id`
* grants / permissions
* DSN / credentials / authority

La confiance est injectée par l’hôte via `resolveTrust`. Le kernel continue d’utiliser `authority.authorize` / `revalidate`. Absence de trust host, absence d’authority, authority indisponible ou refus : fail-closed.

## Envelope requête v1

Champs racine **exactement** : `contract`, `version`, `request_id`, `operation`, `payload`. Tout autre champ racine est rejeté avant le kernel.

```json
{
  "contract": "dubsar.operational-context.bridge-request/1",
  "version": 1,
  "request_id": "req-01",
  "operation": "observe",
  "payload": {}
}
```

| Champ | Règle |
| --- | --- |
| `contract` | `dubsar.operational-context.bridge-request/1` |
| `version` | entier `1` uniquement |
| `request_id` | `^[A-Za-z0-9._:~-]{1,128}$` |
| `operation` | `observe` \| `get_context_view` |
| `payload` | objet ; pour `observe` : observation kernel ; pour `get_context_view` : view-request kernel |

Les clés d’autorité (`trust`, `tenant_id`, `environment_id`, `principal_id`, `grants`, `permissions`, `dsn`, `credentials`, `authority`, …) sont refusées à la racine **et** à la racine du payload (`OC_INJECTION_REFUSED`). `tenant_id` / `environment_id` restent licites **à l’intérieur** du sujet d’observation (identité de ressource kernel) ; le kernel applique `assertSameScope`.

## Envelope réponse v1

Une requête produit au plus une réponse corrélée au même `request_id`. Pas de stack, DSN, chemin hôte, secret ni objet authority.

Succès (résultat kernel admissible, y compris `duplicate_identical` / `integrity_conflict` / `rejected` d’`ingestObservation`) :

```json
{
  "contract": "dubsar.operational-context.bridge-response/1",
  "version": 1,
  "request_id": "req-01",
  "ok": true,
  "result": {
    "contract": "dubsar.operational-context.ingest-result/1",
    "outcome": "applied"
  }
}
```

Échec borné (protocole, trust host, `readView` qui lève, borne de réponse) :

```json
{
  "contract": "dubsar.operational-context.bridge-response/1",
  "version": 1,
  "request_id": "req-01",
  "ok": false,
  "error": {
    "code": "OC_UNAUTHORIZED",
    "message": "authorization denied"
  }
}
```

`error` contient uniquement `code` et `message`. Le `message` est **allowlisté et déterministe par code `OC_*`** : le texte d’exception (stack, DSN, chemin hôte) n’est jamais recopié. Un `request_id` illisible est renvoyé vide.

## Délégation kernel

| Opération | Port | Conservation |
| --- | --- | --- |
| `observe` | `ingestObservation` | validation, scopes, idempotence, `duplicate_identical`, `integrity_conflict`, bornes, provenance. Correction / rétractation hors surface. |
| `get_context_view` | `readView` | reçus `complete_in_authorized_selection` \| `partial` \| `unavailable`, `relation_depth`, sélection autorisée. Supports non autorisés absents, sans compteur caché. |

Le bridge n’interprète pas le contenu métier et ne transforme pas une erreur en succès. Une valeur retournée par le kernel est `result`. Une exception kernel devient `error` avec un code `OC_*` admis, sinon `OC_UNAVAILABLE`.

## Bornes transport

| Masse | Valeur | Couche compétente |
| --- | --- | --- |
| Observation UTF-8 | ≤ 64 KiB | kernel |
| Ressources / appel | ≤ 20 | kernel / schéma |
| Profondeur de relation | ≤ 1 | kernel / schéma |
| Envelope requête UTF-8 | ≤ 256 KiB | protocole / harness |
| Envelope réponse UTF-8 | ≤ 256 KiB | protocole ; jamais troncature présentée comme complète |
| `request_id` | 1–128 | protocole |

## Transport

* Composant stable : `createOperationalContextBridge({ kernel, resolveTrust })`.
* Harness : `node tools/operational-context/bridge-stdio-lab.mjs --lab`. Sans `--lab` : refus de démarrer (exit 2). JSON-lines stdin/stdout. Trust hôte : `OC_HOST_TRUST_JSON`. Grants lab : `OC_LAB_GRANTS_JSON`. DSN : uniquement `DUBSAR_TEST_POSTGRES_URL`.
* Aucun serveur HTTP, port TCP, socket Unix, MCP, cron, worker ou service.

## Preuve B05

Setup borné (migration + graine). Processus producteur A distinct → `observe` `applied`. A s’arrête. Processus lecteur B distinct → `get_context_view` voit la donnée persistée. PIDs distincts, aucun état JS partagé. Redémarrage de B conserve la lecture.
