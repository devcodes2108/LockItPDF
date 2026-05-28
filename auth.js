(function () {
  function attachAuthHeaders(headers = {}) {
    // Sessions are stored in HttpOnly cookies; JavaScript should not read tokens.
    return { ...headers };
  }

  async function login(username, password) {
    const response = await window.LockItPDFApi.apiFetch('/api/login', {
      method: 'POST',
      credentials: 'include',
      headers: attachAuthHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || 'Login failed.');
    }

    return data;
  }

  async function signup(data) {
    const response = await window.LockItPDFApi.apiFetch('/api/signup', {
      method: 'POST',
      credentials: 'include',
      headers: attachAuthHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(data),
    });

    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(result.error || 'Signup failed.');
    }

    return result;
  }

  async function exampleUsage() {
    const me = await window.LockItPDFApi.apiFetch('/api/me', {
      credentials: 'include',
      headers: attachAuthHeaders(),
    });
    return me.json();
  }

  window.LockItPDFAuth = {
    login,
    signup,
    attachAuthHeaders,
    exampleUsage,
  };
})();
