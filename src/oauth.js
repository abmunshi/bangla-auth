// Step 1: Generate OAuth 2.0 Authorization URL
import { generateCodeVerifier, generateCodeChallenge } from "./utils/pkce.js";

/**
 * Generate the OAuth 2.0 authorization URL
 * @param {Object} options
 * @param {string} options.authorizationEndpoint
 * @param {string} options.clientId
 * @param {string} options.redirectUri
 * @param {string[]} options.scopes
 * @param {string} [options.state]
 * @returns {Object} { url, codeVerifier }
 */
function getAuthorizationUrl({
  authorizationEndpoint,
  clientId,
  redirectUri,
  scopes = [],
  state = "",
}) {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(" "),
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });
  return {
    url: `${authorizationEndpoint}?${params.toString()}`,
    codeVerifier,
  };
}

async function exchangeCodeForToken({
  tokenEndpoint,
  clientId,
  redirectUri,
  code,
  codeVerifier,
}) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: codeVerifier,
  });

  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.statusText}`);
  }
  return response.json();
}

module.exports = {
  getAuthorizationUrl,
  exchangeCodeForToken,
};
