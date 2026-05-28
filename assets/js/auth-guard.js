document.addEventListener('DOMContentLoaded', async () => {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const publicPages = new Set(['login.html', 'signup.html', 'support.html']);
  if (publicPages.has(currentPage)) return;

  try {
    const response = await window.LockItPDFApi.apiFetch('/api/me', {
      credentials: 'include',
      headers: window.LockItPDFAuth?.attachAuthHeaders ? window.LockItPDFAuth.attachAuthHeaders() : {},
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || 'Login required.');
    }
  } catch (error) {
    window.location.href = `login.html?next=${encodeURIComponent(currentPage)}`;
  }
});
