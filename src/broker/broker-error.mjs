export class BrokerRejection extends Error {
  constructor(code) {
    super(code)
    this.name = 'BrokerRejection'
    this.code = code
  }
}

export function reject(code) {
  throw new BrokerRejection(code)
}
