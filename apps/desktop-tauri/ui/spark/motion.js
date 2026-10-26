// Screen motion for a UI that replaces its DOM on each render. A bill or card
// with the same `data-shared` key on both screens flies to its new place; the
// rest of the old screen fades out over the new one. Every copy is inert and
// decorative, so wallet actions always use the live view.
const COLORS = ['--paper', '--ink', '--muted', '--line', '--fill', '--field', '--field-line', '--button-line', '--accent', '--danger', '--bill-shadow', '--control', '--quiet', '--on-accent', '--danger-line'];
const EASING = 'cubic-bezier(0.22, 1, 0.36, 1)';
const FLIGHT = 520, FADE = 220;

const stageOf = root => root.querySelector('.z-stage');
const sharedIn = node => new Map([...(node?.querySelectorAll('[data-shared]') ?? [])].map(item => [item.dataset.shared, item]));

/** Untransformed frame of a piece placed in the stage, in viewport coordinates. */
function geometry(node, stageRect) {
  return {
    left: stageRect.left + node.offsetLeft, top: stageRect.top + node.offsetTop,
    width: node.offsetWidth, height: node.offsetHeight, rotate: getComputedStyle(node).rotate,
    under: node.classList.contains('under'),
  };
}

function decorative(copy) {
  copy.removeAttribute('id');
  copy.querySelectorAll('[id]').forEach(el => el.removeAttribute('id'));
  copy.inert = true;
  copy.setAttribute('aria-hidden', 'true');
  return copy;
}

export function createWalletMotion(root) {
  let previous, active;

  function clear() {
    if (!active) return;
    clearTimeout(active.timer);
    for (const animation of active.animations) animation.cancel();
    active.fade?.cancel();
    active.layer?.remove();
    for (const flight of active.flights) flight.remove();
    for (const node of root.querySelectorAll('[data-shared]')) node.style.removeProperty('visibility');
    active = null;
  }

  /** Before a render: remember the old screen if this render changes screens. */
  function capture(next) {
    const old = previous;
    previous = next;
    if (!old || old.screen === next.screen) return null;
    clear();
    const stage = stageOf(root);
    if (!stage || matchMedia('(prefers-reduced-motion: reduce)').matches || typeof root.animate !== 'function') return null;
    const stageRect = stage.getBoundingClientRect(), theme = getComputedStyle(document.body);
    const from = new Map([...sharedIn(stage)].map(([key, node]) => [key, geometry(node, stageRect)]));
    const layer = decorative(stage.cloneNode(true));
    layer.classList.add('z-motion-layer');
    for (const color of COLORS) layer.style.setProperty(color, theme.getPropertyValue(color));
    layer.style.setProperty('color', theme.color);
    layer.style.setProperty('left', `${stageRect.left}px`);
    layer.style.setProperty('top', `${stageRect.top}px`);
    return { from, layer };
  }

  function start({ from, layer }) {
    const stage = stageOf(root);
    if (!stage) return;
    const stageRect = stage.getBoundingClientRect(), animations = [], flights = [], keys = [];
    const oldShared = sharedIn(layer);
    for (const [key, node] of sharedIn(stage)) {
      const start = from.get(key);
      if (!start) continue;
      const end = geometry(node, stageRect);
      oldShared.get(key)?.remove();
      const flight = decorative(node.cloneNode(true));
      flight.classList.add('z-flight');
      if (!start.under || !end.under) flight.classList.remove('under');
      flight.style.setProperty('z-index', String(30 + Number(node.style.getPropertyValue('--z') || 0)));
      document.body.append(flight);
      const frame = g => ({ left: `${g.left}px`, top: `${g.top}px`, width: `${g.width}px`, height: `${g.height}px`, rotate: g.rotate });
      animations.push(flight.animate([frame(start), frame(end)], { duration: FLIGHT, easing: EASING, fill: 'forwards' }));
      flights.push(flight);
      keys.push(key);
    }
    document.body.append(layer);
    animations.push(layer.animate([{ opacity: 1 }, { opacity: 0 }], { duration: FADE, easing: 'ease-out', fill: 'forwards' }));
    const duration = flights.length ? FLIGHT : FADE + 80;
    active = { animations, flights, keys, layer, duration, started: performance.now(), timer: setTimeout(clear, duration + 32) };
  }

  /** After a render: start the change, or keep a running one on the replaced DOM. */
  function play(change) {
    if (change) start(change);
    if (!active) return;
    const elapsed = performance.now() - active.started;
    if (elapsed >= active.duration) { clear(); return; }
    const stage = stageOf(root);
    if (stage && stage !== active.stage) {
      active.stage = stage;
      active.fade?.cancel();
      active.fade = stage.animate([{ opacity: 0, translate: '0 6px' }, { opacity: 1, translate: '0 0' }],
        { duration: FADE + 80, delay: 60, easing: EASING, fill: 'backwards' });
      // Typing or a progress step can replace the screen mid-change; continue from the same time.
      active.fade.currentTime = elapsed;
    }
    for (const key of active.keys) stage?.querySelector(`[data-shared="${CSS.escape(key)}"]`)?.style.setProperty('visibility', 'hidden');
  }

  return { capture, play };
}
