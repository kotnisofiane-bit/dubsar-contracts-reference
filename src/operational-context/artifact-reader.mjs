/** Declared simulated ArtifactStore reader. Never copies heavy content. */
export class SimulatedArtifactStoreReader {
  constructor() {
    this.simulated = true
    this.kind = 'simulated-artifact-store-reader'
  }

  async resolve(reference) {
    return {
      simulated: true,
      kind: 'reference_only',
      available: false,
      reference: reference === undefined ? null : { digest: reference.digest ?? null, kind: 'artifact_ref' },
    }
  }
}
