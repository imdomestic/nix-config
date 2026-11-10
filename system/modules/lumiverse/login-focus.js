// Release macOS Secure Input before React disables/unmounts the login fields.
// See docs/incidents.md#lumiverse-secure-input.
document.addEventListener('submit', (event) => {
  const form = event.target;
  const active = document.activeElement;
  if (
    window.location.pathname !== '/login' ||
    !(form instanceof HTMLFormElement) ||
    !(active instanceof HTMLInputElement) ||
    active.form !== form ||
    active.type !== 'password' ||
    active.autocomplete !== 'current-password'
  ) return;

  active.blur();
}, true);
