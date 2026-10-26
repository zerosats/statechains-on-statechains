// Shared visual components. Text is always assigned as text, never parsed as markup.

export function h(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (name === 'class') element.className = value;
    else if (name === 'text') element.textContent = value;
    else if (name === 'key') element.dataset.key = value;
    // The webview CSP forbids style attributes; CSSOM properties remain allowed.
    else if (name === 'style') for (const [property, setting] of Object.entries(value)) element.style.setProperty(property, setting);
    else if (name.startsWith('on')) element.addEventListener(name.slice(2).toLowerCase(), value);
    else if (name in element && name !== 'list') element[name] = value;
    else element.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined && child !== false) element.append(child);
  return element;
}

const SVG = 'http://www.w3.org/2000/svg';
// [viewBox size, stroke width, ...paths]
const ICONS = {
  activity: [16, 1.5, 'M13.5 8a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0', 'M8 4.5V8l2.5 1.5'],
  back: [24, 1.7, 'M19 12H5m6-6-6 6 6 6'],
  forward: [24, 1.5, 'M5 12h14M13 6l6 6-6 6'],
  check: [24, 1.7, 'm5 12 4 4 10-10'],
  plus: [24, 1.7, 'M12 5v14M5 12h14'],
  pending: [24, 1.7, 'M20 12a8 8 0 1 1-8-8m0-2v4m0-2h4'],
  refresh: [24, 1.7, 'M20 7v5h-5M4 17v-5h5M6.1 7a7 7 0 0 1 11.6-1L20 9M4 15l2.3 3A7 7 0 0 0 17.9 17'],
  search: [24, 1.5, 'M17 10.5a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0', 'M15.5 15.5 21 21'],
  sent: [24, 1.7, 'M7 17 17 7M7 7h10v10'],
  received: [24, 1.7, 'M7 7l10 10M7 17h10V7'],
};

export function icon(name, size = 16) {
  const [box, stroke, ...paths] = ICONS[name];
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', `0 0 ${box} ${box}`);
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('stroke-width', stroke);
  svg.classList.add('icon');
  for (const d of paths) {
    const path = document.createElementNS(SVG, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}
