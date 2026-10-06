# OC-KERNEL-01 — contrat de noyau v0

Bibliothèque ESM `@dubsar/contracts` : observations autorisées, journal PostgreSQL `dubsar_context`, associations explicites, qualification déterministe, vues bornées.

## Bornes V0

| Limite | Valeur |
| --- | --- |
| Observation sérialisée UTF-8 | ≤ 64 KiB |
| Ressources par appel | ≤ 20 |
| Profondeur de relation | ≤ 1 |
| Observations/supports examinés | ≤ 200 |
| Réponse UTF-8 | ≤ 256 KiB |
| Instruction SQL | ≤ 5 s |

Entrée excessive : refus avant écriture. Sélection limitée : reçu `partial` ou refus, jamais troncature silencieuse présentée comme complète.

## Ports

`registerResource`, `resolveResource`, `ingestObservation`, `correctObservation`, `retractObservation`, `proposeAssociation`, `admitAssociation`, `revokeAssociation`, `admitMapping`, `revokeMapping`, `admitRule`, `revokeRule`, `qualify`, `readView`, `rebuildDerivatives`.

Le contexte de confiance (`tenant_id`, `environment_id`, `principal_id`) vient de l’hôte. Le port d’autorisation est obligatoire. Aucun allow de secours.

## Journal

Mesure ≠ livraison. Même `delivery_id` + même contenu : `duplicate_identical` sans rafraîchir. Même identité + contenu différent : `integrity_conflict`. Correction/rétractation additives, liées à l’antécédent, habilitées. Le rôle SQL `dubsar_context_runtime` ne peut ni réécrire ni supprimer une observation admise.

## Associations

`related_to` et `same_resource` : candidat, admis, révoqué, version attendue. Seul `same_resource` admis compare des références sources distinctes. Pas de fusion d’historiques, pas de transitivité, pas de matching flou. Clés de paires canoniques (objets triés), pas une concaténation de séparateurs. Une révocation invalide **toutes** les propriétés réellement concernées aux deux extrémités (pas de `LIMIT 1`) et conserve l’historique du lien.

## Qualification

Dimensions distinctes : admissibilité, fraîcheur, couverture, comparabilité, accord/conflit, limites. Pas de score de vérité, pas de dernier message gagnant. Reproductible à observations + versions + règle + instant fixés. Une version de mapping ou de règle lie un contenu : rejeu identique admis ; contenu différent → conflit d’intégrité. La révocation change le statut, pas la définition versionnée.

## Vues

Reçus : `complete_in_authorized_selection` | `partial` | `unavailable`. Jamais exhaustive d’entreprise. Propriétés et supports dérivés uniquement des observations autorisées. Supports non autorisés absents de la vue, sans compteur caché ni nom de propriété interdit. La réserve générique vient du périmètre, pas de l’existence d’un objet interdit. Revalidation immédiate avant restitution de chaque ressource, support et relation rendus.

## Reconstruction

`rebuildDerivatives` exige `rebuild` et ne rend qu’un reçu (compteurs/statut). Le contenu se lit ensuite par `qualify` / `readView` avec `read` courant.

## Hors profil (différé)

Hermes/My Work/LLM, notifications, outbox distribuée, UI/MCP, T05, T07, T13, T15, T18, T22.
