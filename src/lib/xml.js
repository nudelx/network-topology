/**
 * Minimal XML parser — just enough for nmap's `-oX` output, so the project
 * stays dependency-free. Handles elements, attributes, self-closing tags,
 * comments, declarations and doctypes. Text nodes are kept only when
 * non-whitespace, which nmap never relies on anyway.
 */

const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
};

function decode(str) {
  if (!str.includes('&')) return str;
  return str.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X'
        ? parseInt(body.slice(2), 16)
        : parseInt(body.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    return ENTITIES[body] ?? whole;
  });
}

function parseAttrs(raw) {
  const attrs = {};
  const re = /([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(raw)) !== null) {
    attrs[m[1]] = decode(m[3] !== undefined ? m[3] : m[4] ?? '');
  }
  return attrs;
}

function node(name, attrs) {
  return { name, attrs, children: [], text: '' };
}

/** Parse an XML string into a tree of { name, attrs, children, text }. */
export function parseXml(xml) {
  const root = node('#document', {});
  const stack = [root];
  let i = 0;

  while (i < xml.length) {
    const lt = xml.indexOf('<', i);
    if (lt === -1) break;

    if (lt > i) {
      const text = xml.slice(i, lt).trim();
      if (text) stack[stack.length - 1].text += decode(text);
    }

    if (xml.startsWith('<!--', lt)) {
      const end = xml.indexOf('-->', lt);
      i = end === -1 ? xml.length : end + 3;
      continue;
    }
    if (xml.startsWith('<![CDATA[', lt)) {
      const end = xml.indexOf(']]>', lt);
      const body = xml.slice(lt + 9, end === -1 ? xml.length : end);
      stack[stack.length - 1].text += body;
      i = end === -1 ? xml.length : end + 3;
      continue;
    }
    if (xml.startsWith('<?', lt) || xml.startsWith('<!', lt)) {
      const end = xml.indexOf('>', lt);
      i = end === -1 ? xml.length : end + 1;
      continue;
    }

    const gt = xml.indexOf('>', lt);
    if (gt === -1) break;
    let inner = xml.slice(lt + 1, gt);
    i = gt + 1;

    if (inner[0] === '/') {
      const name = inner.slice(1).trim();
      for (let s = stack.length - 1; s > 0; s--) {
        if (stack[s].name === name) {
          stack.length = s;
          break;
        }
      }
      continue;
    }

    const selfClosing = inner.endsWith('/');
    if (selfClosing) inner = inner.slice(0, -1);

    const space = inner.search(/\s/);
    const name = space === -1 ? inner : inner.slice(0, space);
    const attrs = space === -1 ? {} : parseAttrs(inner.slice(space + 1));
    const el = node(name, attrs);
    stack[stack.length - 1].children.push(el);
    if (!selfClosing) stack.push(el);
  }

  return root;
}

/** Direct children matching `name`. */
export function kids(el, name) {
  if (!el) return [];
  return el.children.filter((c) => c.name === name);
}

/** First direct child matching `name`, or undefined. */
export function kid(el, name) {
  return el?.children.find((c) => c.name === name);
}

/** Depth-first search for all descendants matching `name`. */
export function find(el, name, out = []) {
  if (!el) return out;
  for (const c of el.children) {
    if (c.name === name) out.push(c);
    find(c, name, out);
  }
  return out;
}
