export class TaskManagerRejection extends Error {
  constructor(code) {
    super(code)
    this.name = 'TaskManagerRejection'
    this.code = code
  }
}

export function reject(code) {
  throw new TaskManagerRejection(code)
}
