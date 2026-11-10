const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(`${__dirname}/login-focus.js`, 'utf8');

function fixture({ path = '/login', type = 'password', autocomplete = 'current-password' } = {}) {
  class HTMLFormElement {}
  class HTMLInputElement {}
  const form = new HTMLFormElement();
  let blurs = 0;
  const input = Object.assign(new HTMLInputElement(), {
    form, type, autocomplete,
    blur() { blurs++; },
  });
  Object.defineProperty(input, 'value', {
    get() { throw new Error('Must not read credentials'); },
  });
  let submit;
  const document = {
    activeElement: input,
    addEventListener(name, handler, capture) {
      assert.equal(name, 'submit');
      assert.equal(capture, true); // Must run before React disables the fields.
      submit = handler;
    },
  };
  vm.runInNewContext(source, {
    document, window: { location: { pathname: path } }, HTMLFormElement, HTMLInputElement,
  });
  return { form, input, document, submit, blurs: () => blurs };
}

test('login releases password focus synchronously without reading credentials or cancelling submission', () => {
  const f = fixture();
  f.submit({ target: f.form, preventDefault() { assert.fail('Must preserve login'); } });
  assert.equal(f.blurs(), 1);
});

for (const [name, options] of [
  ['chat page', { path: '/' }],
  ['username field', { type: 'text' }],
  ['new password field', { autocomplete: 'new-password' }],
]) {
  test(`does not disturb ${name}`, () => {
    const f = fixture(options);
    f.submit({ target: f.form });
    assert.equal(f.blurs(), 0);
  });
}

test('does not blur a password belonging to another form', () => {
  const f = fixture();
  f.submit({ target: {} });
  assert.equal(f.blurs(), 0);
});

test('submission from a button with no focused input is safe', () => {
  const f = fixture();
  f.document.activeElement = null;
  f.submit({ target: f.form });
  assert.equal(f.blurs(), 0);
});
