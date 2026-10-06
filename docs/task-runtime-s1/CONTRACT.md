# Task Runtime S1 — contrat du probe Gateway

Statut : **CONTRACT_ONLY_NOT_RUNTIME_QUALIFIED**.

Ce lot définit un contrat et sa conformité locale. Il ne livre ni émetteur Core,
ni admission v2, ni médiateur, ni configuration réseau, ni client Gateway.
Les fichiers existants S0/v1, exact-action v2 et Broker restent inchangés.
Le namespace S1 est chargé explicitement ; il n'entre pas dans le catalogue v1
ou dans les scripts/CI existants.

## Frontières et profil fermé

Core / Human Gates restent l'autorité métier. Le futur Task Manager devra
vérifier la signature et les bindings, consommer la lease une seule fois, puis
créer le sandbox. OpenSandbox conserve le lifecycle, gVisor l'isolation et le
Broker l'autorité des effets externes. Le probe a `effect: none` au sens du
contrat Broker ; l'inférence Gateway demeure une capacité d'egress limitée.
Aucune route d'action Broker n'est autorisée par ce profil.

`dubsar.gateway.probe.v1` fixe :

| Paramètre | Valeur |
| --- | --- |
| Destination | service `dubsar.gateway`, HTTPS, peer `dubsar.gateway.s1` |
| Opération | `POST /v1/chat/completions` |
| Profil / contexte / modèle Gateway | `dubsar.s1.synthetic.v1` / `ctx-s1-synthetic` / `dubsar-s1-synthetic` |
| Corps | JSON canonique exact de `contracts/task-runtime-s1/synthetic-request.json` ; 179 octets UTF-8 |
| Tentatives / retry | 1 / interdit |
| Redirect / CONNECT / streaming / tools | interdits |
| Fenêtre / timeout requête | 30 s / 2 000 ms |
| Taille requête / réponse | au plus 4 096 / 16 384 octets |
| Génération | au plus 128 tokens |
| Authentification | credential éphémère détenu hors workload |
| Révocation | session liée à l'autorité Core |

La destination est une identité de service, pas une URL à saisir. Le futur
adaptateur de confiance devra résoudre cette identité vers son endpoint Gateway,
vérifier son peer TLS et inclure cette résolution/configuration dans le pin
`enforcer_digest`. La résolution DNS seule ne constitue pas une preuve d'identité.
Aucun endpoint concret ni mécanisme d'enforcement n'est qualifié dans ce lot.

`createS1ClosedProfile()` reçoit uniquement trois paramètres de configuration de
confiance : `runtime_lock`, `input_digest`, `enforcer_digest`. Cette fonction
n'est pas une API de demandeur. Core et Task Manager doivent posséder leur
profil local approuvé et comparer les digests ; accepter un profil fourni par
le workload annulerait cette garantie. Les limites, routes, contexte, commandes,
outputs et identité sont fixés par le catalogue et les schémas.

Le runtime lock réutilise son format et son digest v1. Le profil S1 conserve les
valeurs d'isolation du socle S0 : rootfs readonly, mounts tmpfs bornés, uid/gid
65532, capabilities fermées, ressources fixes et cinq opérations lifecycle.
La commande réservée est `python3 /workspace/run_gateway_probe.py`, avec pour
seul output `/workspace/out/result.json`. Le programme, son bundle et son image
S1 ne sont pas livrés ici. Les pins du vecteur sont synthétiques ; ils ne
démontrent aucune image exécutable S1.

Le futur médiateur devra reconstruire la requête exacte, imposer tous les budgets
et injecter son credential éphémère côté Gateway. Le plafond de génération doit
être configuré/enforcé dans ce chemin de confiance ; le JSON du workload ne
fournit aucun paramètre de budget libre. Son credential devra expirer au plus
tard à la fin de la fenêtre et être révocable sans nouveau droit métier.
Le format ne définit ni service de credentials ni capacité d'écriture externe.

## Lease et enveloppe signée

La Task Lease a `schema: dubsar.task-lease.v2`, `contract_version: 2.0.0`.
Les bindings v1 sont conservés : autorité `DUBSAR_CORE`, audience
`dubsar-task-manager`, identité du Task Manager, task/action/mission/tenant,
evidence, nonce et replay key à usage unique. Le bloc task inclut la policy S1
et le pin du médiateur ; son profile digest couvre également ces valeurs.

Les timestamps sont des UTC canoniques avec millisecondes `.000Z`, alignés sur
la seconde. `issued_at <= not_before < expires_at`, validité depuis
`not_before` au plus 300 s, et écart émission/not-before au plus 5 s.
Le TTL doit tenir dans la validité ; les invariants d'isolation sont vérifiés
par réutilisation des validateurs v1 sur une projection interne de validation.
Cette projection n'est ni une lease exécutable ni un chemin d'admission.
`assertS1LeaseBinding()` impose en plus le profil local complet et ses digests.

Format compact : `base64url(header).base64url(payload).base64url(signature)`.
Header et payload sont sérialisés avec la canonicalisation existante : tri
récursif des clés, ordre des arrays conservé, entiers sûrs seulement, UTF-8.
Base64url sans padding, représentation canonique, taille totale maximale
32 768 caractères, signature Ed25519 de 64 octets sur les deux premiers
segments séparés par un point ASCII.

Header fermé : `alg: EdDSA`, `kid: core-key_...`,
`typ: DUBSAR-TASK-LEASE+JSON`, **`v: 2`**.
Payload fermé, mêmes huit clés que v1 : `exp`, `iat`, `issuer`, `lease`,
`lease_digest`, `nbf`, `policy_digest`, `schema`. L'issuer reste
`dubsar-governance-core`, le schema devient `dubsar.signed-task-lease.v2`.
Les dates numériques sont des secondes et doivent correspondre à la lease.

**`policy_digest` reste le digest de la décision Core**, indépendant du digest
de policy réseau. Le parseur S1 vérifie le format et les bindings internes ;
il ne vérifie pas la signature, la confiance du `kid`, l'horloge d'admission,
les identités attendues ni l'anti-rejeu. Ces responsabilités restent à implémenter
dans les adaptateurs Core / Task Manager existants. Aucun signer de production
ni replay store S1 n'est ajouté. Le test cryptographique utilise uniquement la
clé publique du vecteur ; aucune clé privée n'est enregistrée.

## Digests et receipt

Les digests S1 sont `sha256(UTF8(domain) || 0x00 || UTF8(canonical_json))` :

| Objet | Domain separator |
| --- | --- |
| Requête synthétique exacte | `dubsar.s1.gateway-request.v1` |
| Policy demandée / effective | `dubsar.s1.egress-policy.v1` |
| Profil fermé | `dubsar.task-profile.v2` |
| Lease | `dubsar.contract.task-lease.v2` |
| Receipt | `dubsar.s1.egress-receipt.v1` |

Les octets transmis pour la requête doivent être exactement son JSON canonique,
sans retour à la ligne. Le response digest est le SHA-256 des octets de réponse
observés, sans domaine ; ces octets ne figurent jamais dans le receipt.
Les goldens de `fixtures/task-runtime-s1/hash-vectors.json` ont été calculés
indépendamment avec la bibliothèque standard Python sur les fixtures fixes.

Le receipt `dubsar.s1.egress-receipt.v1` est fermé et corrélé à la lease, à la
décision Core, au profil, au runtime lock, au sandbox et à la session. Il contient :

- `requested_policy` et son digest, liés à la lease ;
- `effective_policy` et son digest, distincts, ou `null` si non établis ;
- destination/route fermées, fenêtre autorisée et révocation ;
- `recorded_at`, timestamp du constat ou de l'enregistrement du résultat ;
- durée, tentative, transmission, compteurs bornés, digests et résultat ;
- observations déclarées, leur statut structurel et un statut de preuve distinct.

Pour ce premier profil, une policy effective différente de la policy demandée
est refusée, y compris une modification de budget. La fenêtre expire exactement
à `min(lease.expires_at, sandbox_created_at + TTL, window.not_before + 30 s)`.
`window.not_before` remplace le champ du draft `activated_at` : il décrit le
début de la fenêtre autorisée, sans affirmer qu'une activation réelle a eu lieu.
L'échéance ne dépend jamais de `recorded_at`. Pour toute tentative, le début
doit rester dans cette fenêtre, la fin au plus tard à l'échéance, la durée au
plus 2 s, et l'enregistrement postérieur ou égal à la fin.

Un `DENIED` est un constat sans opération : `started_at`, `finished_at` et
`duration_ms` valent `null`, tentatives/transmission/octets sont nuls,
`generation_tokens`, response digest et référence Gateway sont `null`.
Son `recorded_at` peut être après expiration, y compris celle de la lease,
ou avant le début de la fenêtre si une révocation a déjà été constatée.
Cela ne réactive aucune capacité. Le constat doit rester postérieur ou égal
à la création du sandbox. Une révocation peut précéder le début de la fenêtre ;
elle doit être entre émission de la lease et échéance et ne pas être future
au constat. Le refus reste représentable si la révocation précède la création.
Aucune tentative ne peut commencer à ou après cette révocation.

Cette correction concerne le draft receipt local non publié. Lease, profil,
policy, enveloppe et leurs digests ne changent pas ; le digest du receipt change.

Le receipt distingue trois informations, sans transformer une déclaration en
preuve : `declared_observations` contient les références fournies,
`observations_status` indique `NONE` ou `STRUCTURALLY_VALID`, et
`proof_acquired` est **toujours `false` dans ce lot**. `policy_applied` reste
également `false`. Le validateur contrôle la cohérence du statut structurel ;
ce statut n'authentifie ni l'artefact ni son producteur.

Trois niveaux décrivent les données admissibles :

| Niveau | Portée et contraintes |
| --- | --- |
| `MODEL_ONLY` | Projection de contrat, résultat `SIMULATED`, déclarations vides et statut `NONE` ; aucun forward ni référence Gateway réelle. |
| `DECLARED_ONLY` | Quatre références déclarées, structurées et corrélées ; statut `STRUCTURALLY_VALID`, preuve non acquise ; résultat `SIMULATED` ou refus sans effet `DENIED`. |
| `NOT_PROVEN` | Policy effective et digest `null`, déclarations vides et statut `NONE` ; résultat `DENIED`, aucune opération. |

Les quatre références concernent le readback médiateur, le readback de frontière
réseau hôte, l'identité Gateway et les probes de contournement. Chaque déclaration
doit avoir le type et la source déclarative attendus, un digest d'évidence,
les mêmes lease/policy digests, sandbox/session et un timestamp entre création
et début de la tentative modélisée, ou au plus tard au constat pour `DENIED`.
Même si toutes ces vérifications passent, la preuve reste non acquise. Un digest
de contenu synthétique correctement formé est une donnée de modèle valide.

Tout claim `proof_acquired: true` est refusé par
`S1_ENFORCEMENT_PROOF_UNAVAILABLE`, même avec quatre références valides.
Un claim `policy_applied: true` est refusé par `S1_ENFORCEMENT_NOT_PROVEN`.
L'ancien niveau `RUNTIME_OBSERVED` est refusé, sans fallback implicite. Aucun
paramètre de contexte fourni par l'appelant ne permet de contourner ce refus.
Une vérification de confiance nécessitera un lot ultérieur : retrouver les
artefacts, authentifier les producteurs et vérifier la configuration et les
probes. Aucun vérificateur, signer ou producteur de confiance n'est ajouté ici.

Les outcomes de runtime `SUCCEEDED`, `FAILED`, `INDETERMINATE` et les forwards
réels ne peuvent pas être validés tant que cette vérification est indisponible.
Ils restent réservés dans le schéma, sans chemin positif dans le validateur.
Les budgets et restrictions temporelles des tentatives ne sont pas relâchés.
Le receipt ne contient aucune
credential, aucun token d'authentification, secret, header ou contenu brut de
requête/réponse ; tout champ supplémentaire est refusé.

## Conformité et validation locale

`valid-vector.json` contient profil, lease, enveloppe Ed25519 vérifiable avec clé
publique et receipt de simulation, ainsi que trois exemples supplémentaires :
déclarations synthétiques non probantes, refus après expiration et refus après
révocation pré-activation. Les goldens des quatre receipts sont calculés
indépendamment, sans recalculer les digests de lease/profil/policy/requête.
`alterations.json` décrit 24 remplacements
d'une seule valeur existante, sans recalculer d'autres champs. Chaque test vérifie
qu'il n'y a qu'un changement et contrôle le code exact de refus. Les cas incluent
destination, route, request digest, budgets, durée, versions, policy effective,
preuve d'enforcement, statut structurel, cinq protocoles interdits et séparation
du digest Core. Les régressions supplémentaires vérifient les deux refus hors
fenêtre, leurs compteurs nuls et le maintien des refus de tentative/forward.

Commande ciblée S1 :

```sh
node --test --test-isolation=none tests/task-runtime-s1/contracts.test.mjs
```

Non-régression ciblée du socle :

```sh
node --test --test-isolation=none tests/task-lease.test.mjs tests/contracts.test.mjs tests/exact-action.test.mjs tests/broker-boundary.test.mjs
```

Ces tests n'utilisent ni réseau, runtime, Gateway, PostgreSQL réel ni CI.
Les quatre suites historiques couvrent S0/v1, les goldens exact-action v2 et
la frontière Broker. Aucun script package, workflow ou dépendance n'est modifié.

Avant un lot d'émission/admission v2, faire une revue readonly du contrat et
des vecteurs. L'admission, l'enforcement, l'expiration/révocation effective,
la configuration du Gateway et les credentials éphémères restent à qualifier
séparément. S0 reste strictement `egress_none` ; aucune bascule implicite vers S1.
