import { canonicalBytes } from '../canonical-json.mjs'
import { artifactError } from '../artifacts/contracts.mjs'

// Exact identity mapping is selected by the service, never derived from prefixes.
export class ExactArtifactReader {
  #store
  constructor({ store, exactContext }) {
    store.assertExactContext(exactContext)
    this.#store = store
  }
  async read(ref) {
    const { reference, bytes } = await this.#store.read(ref)
    if (reference.media_type !== 'application/json') throw artifactError('ARTIFACT_MEDIA_TYPE_INVALID')
    let value
    try {
      value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
      if (!canonicalBytes(value).equals(bytes)) throw new Error('not canonical')
    } catch { throw artifactError('ARTIFACT_JSON_INVALID') }
    return value
  }
}
