import fs from 'node:fs'

const definitionUrl = new URL('../contracts/v1/execution-state-machine.json', import.meta.url)
export const STATE_MACHINE = Object.freeze(JSON.parse(fs.readFileSync(definitionUrl, 'utf8')))
export const ACTION_STATES = Object.freeze([...STATE_MACHINE.states])

const stateSet = new Set(ACTION_STATES)
const transitionSet = new Set(
  STATE_MACHINE.allowed_transitions.map(({ from, to }) => `${from}->${to}`),
)

export function isActionState(value) {
  return typeof value === 'string' && stateSet.has(value)
}

export function isTransitionAllowed(from, to) {
  return transitionSet.has(`${from}->${to}`)
}

export function assertTransitionAllowed(from, to) {
  if (!isActionState(from) || !isActionState(to) || !isTransitionAllowed(from, to)) {
    throw new Error(`undeclared action transition: ${String(from)} -> ${String(to)}`)
  }
}

export function allowedTransitionCount() {
  return transitionSet.size
}
