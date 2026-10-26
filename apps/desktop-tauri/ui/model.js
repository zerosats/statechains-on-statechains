// Wallet UI state. The runtime and the blinded worker remain the authority for
// every action; this only tracks what the screens show.

export function initialModel() {
  return {
    snapshot: null,
    busy: false,
    error: null,
    progress: '',
    // False until the first wallet snapshot.
    loaded: false,
    // Payment review and the running step of a long action.
    preview: null,
    stage: null,
    errorCode: null,
  };
}

const EVENT_FIELDS = ['progress', 'preview', 'stage'];

/** Applies one runtime event. A reply decides its action's outcome. */
export function applyEvent(model, event, isReply) {
  if (event.snapshot) { model.snapshot = event.snapshot; model.loaded = true; }
  // A background step (an automatic claim) ends with its snapshot.
  if (event.snapshot && !event.stage && !model.busy) model.stage = null;
  for (const field of EVENT_FIELDS) if (event[field] !== undefined && event[field] !== null) model[field] = event[field];
  // An older background error must not turn a committed send into an apparent failure.
  if (isReply) { model.error = event.error ?? null; model.errorCode = event.errorCode ?? null; }
  else if (event.error) { model.error = event.error; model.errorCode = event.errorCode ?? null; }
}

export function applyShellError(model, message) {
  model.error = message;
  model.busy = false;
  model.progress = '';
}

export function beginAction(model, action) {
  model.busy = true;
  model.error = null;
  model.errorCode = null;
  model.progress = action === 'refresh' ? '' : 'Working…';
}

export function endAction(model) {
  model.busy = false;
  model.progress = '';
  model.stage = null;
}

export const sats = amount => Number(amount ?? 0).toLocaleString();
