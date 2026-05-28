document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('#upload-form');
  if (!form) return;

  const errorBox = document.querySelector('[data-error-placeholder]');
  const buttons = Array.from(form.querySelectorAll('[data-submit-mode]'));

  function setError(message) {
    if (!errorBox) return;
    errorBox.textContent = message || '';
    errorBox.hidden = !message;
  }

  function setLoading(isLoading, activeButton) {
    buttons.forEach((button) => {
      const label = button.querySelector('.button-label');
      const spinner = button.querySelector('.button-spinner');
      button.disabled = isLoading;
      if (spinner) spinner.hidden = !(isLoading && button === activeButton);
      if (label) label.hidden = isLoading && button === activeButton;
    });
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const submitter = event.submitter || buttons[0];
    const formData = new FormData(form);
    if (submitter?.dataset.submitMode) {
      formData.set('mode', submitter.dataset.submitMode);
    }

    setError('');
    setLoading(true, submitter);

    try {
      const authHeaders = window.LockItPDFAuth?.attachAuthHeaders
        ? window.LockItPDFAuth.attachAuthHeaders()
        : {};

      const response = await window.LockItPDFApi.apiFetch('/api/upload', {
        method: 'POST',
        credentials: 'include',
        headers: authHeaders,
        body: formData,
      });

      const data = await response.json();
      if (!response.ok || !data.ok) {
        throw new Error(data.error || 'Upload failed.');
      }

      if (data.download_url) {
        window.location.href = new URL(data.download_url, response.url).toString();
        return;
      }

      setError('Upload finished, but no download URL was returned.');
    } catch (error) {
      setError(error.message || 'Upload failed.');
    } finally {
      setLoading(false, submitter);
    }
  });
});
