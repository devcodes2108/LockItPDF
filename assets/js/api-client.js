(function () {
  const explicitBase = window.localStorage.getItem('LOCKITPDF_API_BASE');
  const currentHost = window.location.hostname || '127.0.0.1';
  const localApiBases = [
    `http://${currentHost}:8000`,
    'http://127.0.0.1:8000',
    'http://localhost:8000',
  ].filter((base, index, bases) => base !== window.location.origin && bases.indexOf(base) === index);
  const fallbackBase = localApiBases[0] || 'http://127.0.0.1:8000';

  function sameOriginUrl(path) {
    return path;
  }

  function shouldTryFallback() {
    return window.location.protocol === 'file:' || localApiBases.length > 0;
  }

  function looksLikeApiResponse(response) {
    const contentType = response.headers.get('content-type') || '';
    return contentType.includes('application/json');
  }

  function jsonError(message, status = 502) {
    return new Response(JSON.stringify({ ok: false, error: message }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  function htmlApiError(baseLabel, response) {
    const status = response.status && response.status >= 400 ? response.status : 502;
    return jsonError(`${baseLabel} returned HTML instead of JSON. Start the Flask server with start-dev.bat, then open http://127.0.0.1:8000/.`, status);
  }

  async function tryLocalApiBases(path, requestOptions) {
    let lastResponse = null;
    let lastError = null;

    for (const base of localApiBases) {
      try {
        const response = await fetch(`${base}${path}`, requestOptions);
        if (looksLikeApiResponse(response)) {
          return response;
        }
        lastResponse = response;
      } catch (error) {
        lastError = error;
      }
    }

    if (lastResponse) {
      return htmlApiError('The local LockItPDF API', lastResponse);
    }

    const triedBases = localApiBases.join(', ') || 'http://127.0.0.1:8000';
    throw new Error(`Cannot reach the LockItPDF API. Start the Flask server with start-dev.bat, then open http://127.0.0.1:8000/. Tried: ${triedBases}.`);
  }

  async function apiFetch(path, options = {}) {
    const requestOptions = {
      credentials: 'include',
      ...options,
    };

    if (explicitBase) {
      try {
        const response = await fetch(`${explicitBase}${path}`, requestOptions);
        return looksLikeApiResponse(response) ? response : htmlApiError(`The LockItPDF API at ${explicitBase}`, response);
      } catch (error) {
        throw new Error(`Cannot reach the LockItPDF API at ${explicitBase}. Start the Flask server and then refresh this page.`);
      }
    }

    try {
      const response = await fetch(sameOriginUrl(path), requestOptions);
      if (shouldTryFallback() && ([404, 405, 501].includes(response.status) || !looksLikeApiResponse(response))) {
        return await tryLocalApiBases(path, requestOptions);
      }
      return looksLikeApiResponse(response) ? response : htmlApiError('The current server', response);
    } catch (error) {
      if (!shouldTryFallback()) {
        throw error;
      }
      return await tryLocalApiBases(path, requestOptions);
    }
  }

  async function health() {
    const response = await apiFetch('/api/health');
    return response.ok;
  }

  window.LockItPDFApi = {
    apiFetch,
    health,
    fallbackBase,
  };
})();
