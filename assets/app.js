const menuButton = document.querySelector('[data-menu-toggle]');
const nav = document.querySelector('[data-nav]');

if (menuButton && nav) {
  menuButton.addEventListener('click', () => nav.classList.toggle('open'));
}

function scorePassword(value) {
  return [
    value.length >= 8,
    /[A-Z]/.test(value),
    /[a-z]/.test(value),
    /\d/.test(value),
    /[!@#$%^&*(),.?":{}|<>]/.test(value),
  ].filter(Boolean).length;
}

document.querySelectorAll('[data-password]').forEach((input) => {
  const meter = input.closest('form')?.querySelector('[data-strength]');
  if (!meter) return;
  input.addEventListener('input', () => {
    meter.value = scorePassword(input.value);
  });
});

document.querySelectorAll('[data-file-input]').forEach((input) => {
  const list = input.closest('.file-field')?.querySelector('[data-file-list]');
  if (!list) return;

  input.addEventListener('change', () => {
    list.innerHTML = '';
    Array.from(input.files || []).forEach((file) => {
      const item = document.createElement('li');
      item.textContent = file.name;
      list.appendChild(item);
    });
  });
});

const encryptForm = document.querySelector('[data-encrypt-form]');

if (encryptForm) {
  const recoveryPanel = encryptForm.querySelector('[data-recovery-panel]');
  const modeValue = encryptForm.querySelector('[data-mode-value]');
  const choices = encryptForm.querySelectorAll('[data-mode-choice]');
  const submitButtons = encryptForm.querySelectorAll('[data-submit-mode]');

  const setMode = (mode) => {
    if (modeValue) modeValue.value = mode;
    choices.forEach((choice) => {
      const active = choice.dataset.modeChoice === mode;
      choice.classList.toggle('is-active', active);
      choice.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    submitButtons.forEach((button) => {
      button.disabled = button.dataset.submitMode !== mode;
    });
    if (recoveryPanel) {
      recoveryPanel.hidden = mode !== 'recovery';
    }
  };

  choices.forEach((choice) => {
    choice.addEventListener('click', () => setMode(choice.dataset.modeChoice));
  });

  setMode(modeValue?.value || 'regular');
}
