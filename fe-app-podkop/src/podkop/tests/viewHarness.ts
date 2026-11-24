import { readFileSync } from 'fs';
import { join } from 'path';
import * as constants from '../../constants';
import * as validators from '../../validators';
import * as devices from '../devices';
import * as sources from '../sources';

// A hand-written view of the page (luci-app-podkop/.../view/podkop/*.js) run as LuCI runs it:
// its text is the body of a function that gets the modules it requires. LuCI itself is faked as
// far as the views use it while their options are made and their methods are called: form's
// options and sections, uci, the elements of E() and the document. The bundle (main) is the
// sources of fe-app-podkop/src, with what a test puts over it.

const VIEWS = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'luci-app-podkop',
  'htdocs',
  'luci-static',
  'resources',
  'view',
  'podkop',
);

type Fn = (...args: unknown[]) => unknown;

// an element of E(): its attributes and children, and click() a test can watch; querySelector
// takes selectors of tags, .classes and [attributes], with descendant and > combinators
export class FakeNode {
  tag: string;
  attrs: Record<string, unknown>;
  children: (FakeNode | string)[] = [];
  parentNode: FakeNode | null = null;
  title?: string;
  scrollIntoView?: Fn;
  click: Fn = () => undefined;

  constructor(
    tag: string,
    attrs?: Record<string, unknown>,
    children?: unknown,
  ) {
    this.tag = tag;
    this.attrs = { ...(attrs ?? {}) };
    const list = Array.isArray(children)
      ? children
      : children == null
        ? []
        : [children];
    list.forEach((child) => this.appendChild(child));
  }

  appendChild<T>(child: T): T {
    if (child instanceof FakeNode) {
      child.parentNode = this;
      this.children.push(child);
    } else if (child != null) {
      this.children.push(String(child));
    }
    return child;
  }

  replaceChildren(...children: unknown[]) {
    this.children = [];
    children.forEach((child) => this.appendChild(child));
  }

  remove() {
    if (this.parentNode) {
      this.parentNode.children = this.parentNode.children.filter(
        (child) => child !== this,
      );
      this.parentNode = null;
    }
  }

  getAttribute(name: string): string | null {
    return name in this.attrs ? String(this.attrs[name]) : null;
  }

  get elements(): FakeNode[] {
    return this.children.filter(
      (child): child is FakeNode => child instanceof FakeNode,
    );
  }

  get previousElementSibling(): FakeNode | null {
    const siblings = this.parentNode ? this.parentNode.elements : [];
    const index = siblings.indexOf(this);
    return index > 0 ? siblings[index - 1] : null;
  }

  get textContent(): string {
    return this.children
      .map((child) => (child instanceof FakeNode ? child.textContent : child))
      .join('');
  }

  set textContent(text: string) {
    this.replaceChildren(text);
  }

  matches(compound: string): boolean {
    const parts = compound.match(/[a-z]+|\.[\w-]+|\[[^\]]+\]/g) ?? [];
    return parts.every((part) => {
      if (part.startsWith('.'))
        return String(this.attrs.class ?? '')
          .split(/\s+/)
          .includes(part.slice(1));
      if (part.startsWith('[')) {
        const [name, value] = part.slice(1, -1).split('=');
        if (value === undefined) return name in this.attrs;
        return this.getAttribute(name) === value.replace(/^"|"$/g, '');
      }
      return this.tag === part;
    });
  }

  get descendants(): FakeNode[] {
    return this.elements.flatMap((child) => [child, ...child.descendants]);
  }

  querySelectorAll(selector: string): FakeNode[] {
    const steps = selector
      .trim()
      .split(/\s*(>)\s*|\s+/)
      .filter(Boolean);
    let found: FakeNode[] = [this];
    let child = false;
    steps.forEach((step) => {
      if (step === '>') {
        child = true;
        return;
      }
      found = found
        .flatMap((node) => (child ? node.elements : node.descendants))
        .filter((node) => node.matches(step));
      child = false;
    });
    return found.filter((node) => node !== this);
  }

  querySelector(selector: string): FakeNode | null {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  closest(selector: string): FakeNode | null {
    if (this.matches(selector)) return this;
    return this.parentNode ? this.parentNode.closest(selector) : null;
  }
}

// the settings: sections by name, each with its type and options
export type Settings = Record<string, Record<string, unknown>>;

export class FakeUci {
  values: Settings;
  records: unknown[] = [];
  state = { changes: {}, creates: {} };

  constructor(values: Settings) {
    this.values = values;
  }

  get(_config: string, section: string, option?: string) {
    const found = this.values[section];
    if (option !== undefined) return found?.[option];
    return found && { '.name': section, ...found };
  }

  sections(_config: string, type?: string) {
    return Object.keys(this.values)
      .filter((name) => !type || this.values[name]['.type'] === type)
      .map((name) => ({ '.name': name, ...this.values[name] }));
  }

  set(_config: string, section: string, option: string, value: unknown) {
    this.values[section] = { ...this.values[section], [option]: value };
  }

  unset(_config: string, section: string, option: string) {
    delete this.values[section]?.[option];
  }

  // the records of rpcd's uci changes for the config podkop
  changes() {
    return Promise.resolve({ podkop: this.records });
  }
}

// an option of a form: what the views set on it, and the base methods of LuCI they call (load
// reads the settings, cfgvalue keeps what load gave, formvalue is what the window holds)
export class FakeOption {
  [key: string]: unknown;
  section: FakeSection;
  map: FakeMap;
  option: string;
  data: Record<string, unknown> = {};
  window: Record<string, unknown> = {};
  subsection?: FakeSection;

  constructor(section: FakeSection, option: string, title?: unknown) {
    this.section = section;
    this.map = section.map;
    this.option = option;
    if (typeof title === 'function')
      this.subsection = new FakeSection(this.map);
  }

  // what the option depends on, each alone enough, as LuCI keeps it
  depends(field: string | Record<string, unknown>, value?: unknown) {
    ((this.deps ??= []) as unknown[]).push(
      typeof field === 'string' ? { [field]: value } : field,
    );
  }

  // a choice, as LuCI keeps it
  value(key: unknown, label?: unknown) {
    ((this.keylist ??= []) as unknown[]).push(String(key));
    ((this.vallist ??= []) as unknown[]).push(label ?? key);
  }

  load(section_id: string) {
    return this.map.data.get(this.map.config, section_id, this.option);
  }

  cfgvalue(section_id: string, ...set: unknown[]) {
    if (set.length) this.data[section_id] = set[0];
    return this.data[section_id];
  }

  formvalue(section_id: string) {
    return section_id in this.window ? this.window[section_id] : null;
  }

  isValid() {
    return true;
  }

  getValidationError() {
    return '';
  }

  render(): unknown {
    return Promise.resolve(null);
  }

  parse(): unknown {
    return Promise.resolve();
  }

  checkDepends() {}

  handleModalSave(): unknown {
    return Promise.resolve();
  }

  // a method the view set on the option, called with it as this
  call(name: string, ...args: unknown[]): unknown {
    return (this[name] as Fn).apply(this, args);
  }
}

export class FakeMap {
  [key: string]: unknown;
  config = 'podkop';
  data: FakeUci;
  parent: unknown = null;
  sections: FakeSection[] = [];
  elements: Record<string, FakeNode> = {};

  constructor(data: FakeUci) {
    this.data = data;
  }

  lookupOption(name: string, section_id: string) {
    for (const section of this.sections) {
      const found = section.find(name);
      if (found) return [found, section_id];
    }
    return null;
  }

  findElement(_attribute: string, value: string) {
    return this.elements[value] ?? null;
  }
}

export class FakeSection {
  [key: string]: unknown;
  map: FakeMap;
  children: FakeOption[] = [];

  constructor(map: FakeMap) {
    this.map = map;
    map.sections.push(this);
  }

  tab() {}

  option(cls: new (...args: unknown[]) => FakeOption, ...args: unknown[]) {
    const created = new cls(this, ...args);
    this.children.push(created);
    return created;
  }

  taboption(
    tab: string,
    cls: new (...args: unknown[]) => FakeOption,
    ...args: unknown[]
  ) {
    const created = this.option(cls, ...args);
    created.tab = tab;
    return created;
  }

  find(name: string): FakeOption | undefined {
    return this.children.find((child) => child.option === name);
  }

  lookup(name: string): FakeOption {
    const found = this.find(name);
    if (!found) throw new Error(`no option ${name}`);
    return found;
  }

  cfgvalue(section_id: string, option: string) {
    return this.lookup(option).cfgvalue(section_id);
  }

  formvalue(section_id: string, option: string) {
    return this.lookup(option).formvalue(section_id);
  }

  load(_section_id: string): unknown {
    return Promise.resolve();
  }

  // the load of a section of LuCI: each option's load kept as its cfgvalue
  loadOptions(section_id: string) {
    return Promise.all(
      this.children.map((child) =>
        Promise.resolve(child.load(section_id)).then((value) =>
          child.cfgvalue(section_id, value),
        ),
      ),
    );
  }
}

// the classes of form: one each, as LuCI has, made when first named
function fakeForm() {
  const classes: Record<string, typeof FakeOption> = {};
  return new Proxy(classes, {
    get(target, name: string) {
      target[name] ??= class extends FakeOption {};
      return target[name];
    },
  });
}

// the L of luci.js as far as the views use it
export function toArray(value: unknown): unknown[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'object') return [value];
  const text = String(value).trim();
  return text === '' ? [] : text.split(/\s+/);
}

export interface View {
  exports: Record<string, Fn>;
  form: Record<string, typeof FakeOption>;
  uci: FakeUci;
  map: FakeMap;
  section: FakeSection;
  ui: { addNotification: Fn };
  elements: Record<string, FakeNode>;
}

// loadView runs the view of this name with the settings, and the bundle with main over it
export function loadView(
  name: string,
  settings: Settings,
  main: Record<string, unknown> = {},
): View {
  const text = readFileSync(join(VIEWS, name), 'utf8');
  const form = fakeForm();
  const uci = new FakeUci(settings);
  const map = new FakeMap(uci);
  const section = new FakeSection(map);
  const ui = { addNotification: () => undefined };
  const elements: Record<string, FakeNode> = {};
  const bundle = new Proxy(
    { ...constants, ...validators, ...devices, ...sources, ...main },
    {
      get(target: Record<string, unknown>, key: string) {
        if (!(key in target)) throw new Error(`main.${key} is not faked`);
        return target[key];
      },
    },
  );
  const modules: Record<string, unknown> = {
    form,
    baseclass: { extend: (members: unknown) => members },
    uci,
    ui,
    widgets: { DeviceSelect: form.DeviceSelect },
    main: bundle,
    devices: { forRole: () => undefined },
    network: {},
    E: (tag: string, attrs?: Record<string, unknown>, children?: unknown) =>
      new FakeNode(tag, attrs, children),
    _: (text: string) => text,
    L: {
      toArray,
      resolveDefault: (promise: unknown, fallback: unknown) =>
        Promise.resolve(promise).catch(() => fallback),
    },
    document: {
      documentElement: { lang: 'en' },
      getElementById: (id: string) => elements[id] ?? null,
      hidden: false,
    },
  };
  const run = new Function(...Object.keys(modules), text);
  const exports = run(...Object.values(modules)) as Record<string, Fn>;
  return { exports, form, uci, map, section, ui, elements };
}
