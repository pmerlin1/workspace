/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { google, Auth } from 'googleapis';
import crypto from 'node:crypto';
import * as http from 'node:http';
import * as net from 'node:net';
import * as url from 'node:url';
import { logToFile } from '../utils/logger';
import open from '../utils/open-wrapper';
import { shouldLaunchBrowser } from '../utils/secure-browser-launcher';
import { OAuthCredentialStorage } from './token-storage/oauth-credential-storage';
import { loadConfig } from '../utils/config';

const config = loadConfig();
const CLIENT_ID = config.clientId;
const CLIENT_SECRET = config.clientSecret;
const CLOUD_FUNCTION_URL = config.cloudFunctionUrl;
const TOKEN_EXPIRY_BUFFER_MS = 5 * 60 * 1000; // 5 minutes

/**
 * An Authentication URL for updating the credentials of a Oauth2Client
 * as well as a promise that will resolve when the credentials have
 * been refreshed (or which throws error when refreshing credentials failed).
 */
interface OauthWebLogin {
  authUrl: string;
  loginCompletePromise: Promise<void>;
}

export class AuthManager {
  private client: Auth.OAuth2Client | null = null;
  private scopes: string[];
  private onStatusUpdate: ((message: string) => void) | null = null;

  constructor(scopes: string[]) {
    this.scopes = scopes;
  }

  public setOnStatusUpdate(callback: (message: string) => void) {
    this.onStatusUpdate = callback;
  }

  private isTokenExpiringSoon(credentials: Auth.Credentials): boolean {
    return !!(
      credentials.expiry_date &&
      credentials.expiry_date < Date.now() + TOKEN_EXPIRY_BUFFER_MS
    );
  }

  private async loadCachedCredentials(
    client: Auth.OAuth2Client,
  ): Promise<boolean> {
    const credentials = await OAuthCredentialStorage.loadCredentials();

    if (credentials) {
      // Check if saved token has required scopes
      const savedScopes = new Set(credentials.scope?.split(' ') ?? []);
      logToFile(`Cached token has scopes: ${[...savedScopes].join(', ')}`);
      logToFile(`Required scopes: ${this.scopes.join(', ')}`);

      const missingScopes = this.scopes.filter(
        (scope) => !savedScopes.has(scope),
      );

      if (missingScopes.length > 0) {
        logToFile(
          `Token cache missing required scopes: ${missingScopes.join(', ')}`,
        );
        logToFile('Removing cached token to force re-authentication...');
        await OAuthCredentialStorage.clearCredentials();
        return false;
      } else {
        client.setCredentials(credentials);
        return true;
      }
    }

    return false;
  }

  public async getAuthenticatedClient(): Promise<Auth.OAuth2Client> {
    logToFile('getAuthenticatedClient called');

    // Check if we have a cached client with valid credentials
    if (
      this.client &&
      this.client.credentials &&
      this.client.credentials.refresh_token
    ) {
      logToFile('Returning existing cached client with valid credentials');
      logToFile(
        `Access token exists: ${!!this.client.credentials.access_token}`,
      );
      logToFile(`Expiry date: ${this.client.credentials.expiry_date}`);
      logToFile(`Current time: ${Date.now()}`);

      const isExpired = this.isTokenExpiringSoon(this.client.credentials);
      logToFile(`Token expired: ${isExpired}`);

      // Proactively refresh if expired
      if (isExpired) {
        logToFile('Token is expired, refreshing proactively...');
        try {
          await this.refreshToken();
          logToFile('Token refreshed successfully');
        } catch (error) {
          logToFile(`Failed to refresh token: ${error}`);
          // Clear the client and fall through to re-authenticate
          this.client = null;
          await OAuthCredentialStorage.clearCredentials();
        }
      }

      // Return the client (either still valid or just refreshed)
      if (this.client) {
        return this.client;
      }
    }

    const options: Auth.OAuth2ClientOptions = {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    };
    const oAuth2Client = new google.auth.OAuth2(options);

    oAuth2Client.on('tokens', async (tokens) => {
      logToFile('Tokens refreshed event received');
      if (tokens.refresh_token) {
        logToFile('New refresh token received in event');
      }

      try {
        // Create a copy to preserve refresh_token from storage
        const current = (await OAuthCredentialStorage.loadCredentials()) || {};
        const merged = {
          ...tokens,
          refresh_token: tokens.refresh_token || current.refresh_token,
        };
        await OAuthCredentialStorage.saveCredentials(merged);
        logToFile('Credentials saved after refresh');
      } catch (e) {
        logToFile(`Error saving refreshed credentials: ${e}`);
      }
    });

    logToFile('No valid cached client, checking for saved credentials...');
    if (await this.loadCachedCredentials(oAuth2Client)) {
      logToFile('Loaded saved credentials, caching and returning client');
      this.client = oAuth2Client;

      // Check if the loaded token is expired and refresh proactively
      const isExpired = this.isTokenExpiringSoon(this.client.credentials);
      logToFile(`Token expired: ${isExpired}`);

      if (isExpired) {
        logToFile('Loaded token is expired, refreshing proactively...');
        try {
          await this.refreshToken();
          logToFile('Token refreshed successfully after loading from storage');
        } catch (error) {
          logToFile(`Failed to refresh loaded token: ${error}`);
          // Clear the client and fall through to re-authenticate
          this.client = null;
          await OAuthCredentialStorage.clearCredentials();
        }
      }

      // Return the client if refresh succeeded or token was still valid
      if (this.client) {
        return this.client;
      }
    }

    // Fail fast for the cloud-function flow in headless environments instead
    // of hanging. Installed-app mode can still print a URL and receive the
    // localhost callback after the user opens it manually.
    if (!shouldLaunchBrowser() && config.authMode !== 'installed-app') {
      throw new Error(
        'No browser available for authentication. ' +
          'Please run: node dist/headless-login.js\n' +
          '(from the workspace-server directory)\n' +
          'After authenticating, retry your request.',
      );
    }

    const webLogin = await this.authWithWeb(oAuth2Client);
    if (!shouldLaunchBrowser()) {
      // Headless / WSL: return the URL synchronously via a thrown error so it
      // appears in the tool result. The localhost callback server stays
      // listening; once the user opens the URL and grants access, credentials
      // are saved by the callback handler. The next tool call will pick up the
      // saved credentials from disk.
      webLogin.loginCompletePromise
        .then(async () => {
          await OAuthCredentialStorage.saveCredentials(
            oAuth2Client.credentials,
          );
          this.client = oAuth2Client;
          logToFile('Headless auth complete; credentials saved.');
        })
        .catch((e) => logToFile(`Headless auth failed: ${e}`));

      throw new Error(
        'Authentication required. Open this URL in any browser to grant ' +
          'access, then retry your request:\n\n' +
          webLogin.authUrl,
      );
    }

    await open(webLogin.authUrl);
    const msg = 'Waiting for authentication... Check your browser.';
    logToFile(msg);
    if (this.onStatusUpdate) {
      this.onStatusUpdate(msg);
    }

    // Add timeout to prevent infinite waiting when browser tab gets stuck
    const authTimeout = 5 * 60 * 1000; // 5 minutes timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(
          new Error(
            'User is not authenticated. Authentication timed out after 5 minutes. The user did not complete the login process in the browser. ' +
              'Please ask the user to check their browser and try again.',
          ),
        );
      }, authTimeout);
    });
    await Promise.race([webLogin.loginCompletePromise, timeoutPromise]);

    await OAuthCredentialStorage.saveCredentials(oAuth2Client.credentials);
    this.client = oAuth2Client;
    return this.client;
  }

  public async clearAuth(): Promise<void> {
    logToFile('Clearing authentication...');
    this.client = null;
    await OAuthCredentialStorage.clearCredentials();
    logToFile('Authentication cleared.');
  }

  public async refreshToken(): Promise<void> {
    logToFile('Manual token refresh triggered');
    if (!this.client) {
      logToFile('No client available to refresh, checking cached credentials');
      const cachedCredentials = await OAuthCredentialStorage.loadCredentials();
      if (!cachedCredentials?.refresh_token) {
        throw new Error(
          'No refresh token available. Authenticate first by calling a Google Workspace tool and completing OAuth.',
        );
      }

      this.client = new google.auth.OAuth2({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      });
      this.client.setCredentials(cachedCredentials);
    }
    try {
      const currentCredentials = { ...this.client.credentials };

      if (!currentCredentials.refresh_token) {
        throw new Error('No refresh token available');
      }

      let newTokens: Auth.Credentials;
      if (config.authMode === 'installed-app') {
        logToFile('Refreshing token directly for installed-app OAuth mode...');
        const refreshed = await this.client.refreshAccessToken();
        newTokens = refreshed.credentials;
      } else {
        logToFile('Calling cloud function to refresh token...');

        // Call the cloud function refresh endpoint.
        // The cloud function has the client secret needed for token refresh.
        const response = await fetch(`${CLOUD_FUNCTION_URL}/refreshToken`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            refresh_token: currentCredentials.refresh_token,
          }),
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(
            `Token refresh failed: ${response.status} ${errorText}`,
          );
        }

        newTokens = await response.json();
      }

      // Merge new tokens with existing credentials, preserving refresh_token
      // Note: Google does NOT return a new refresh_token on refresh
      const mergedCredentials = {
        ...newTokens,
        refresh_token: currentCredentials.refresh_token, // Always preserve original
      };

      this.client.setCredentials(mergedCredentials);
      await OAuthCredentialStorage.saveCredentials(mergedCredentials);
      logToFile('Token refreshed and saved successfully');
    } catch (error) {
      logToFile(`Error during token refresh: ${error}`);
      throw error;
    }
  }

  private async getAvailablePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      let port = 0;
      try {
        const portStr = process.env['OAUTH_CALLBACK_PORT'];
        if (portStr) {
          port = parseInt(portStr, 10);
          if (isNaN(port) || port <= 0 || port > 65535) {
            return reject(
              new Error(`Invalid value for OAUTH_CALLBACK_PORT: "${portStr}"`),
            );
          }
          return resolve(port);
        }
        const server = net.createServer();
        server.listen(0, () => {
          const address = server.address()! as net.AddressInfo;
          port = address.port;
        });
        server.on('listening', () => {
          server.close();
          server.unref();
        });
        server.on('error', (e) => reject(e));
        server.on('close', () => resolve(port));
      } catch (e) {
        reject(e);
      }
    });
  }

  private async authWithWeb(client: Auth.OAuth2Client): Promise<OauthWebLogin> {
    logToFile(
      `Requesting authentication with scopes: ${this.scopes.join(', ')}`,
    );

    const port = await this.getAvailablePort();
    const host = process.env['OAUTH_CALLBACK_HOST'] || 'localhost';

    const localRedirectUri = `http://${host}:${port}/oauth2callback`;

    const isGuiAvailable = shouldLaunchBrowser();

    // SECURITY: Generate a random token for CSRF protection.
    const csrfToken = crypto.randomBytes(32).toString('hex');

    const statePayload = {
      uri: isGuiAvailable ? localRedirectUri : undefined,
      manual: !isGuiAvailable,
      csrf: csrfToken,
    };
    const state =
      config.authMode === 'installed-app'
        ? csrfToken
        : Buffer.from(JSON.stringify(statePayload)).toString('base64');

    const redirectUri =
      config.authMode === 'installed-app'
        ? localRedirectUri
        : CLOUD_FUNCTION_URL;

    const authUrl = client.generateAuthUrl({
      redirect_uri: redirectUri,
      access_type: 'offline',
      scope: this.scopes,
      state: state, // Pass our JSON payload in the state
      prompt: 'consent', // Make sure we get a refresh token
    });

    const loginCompletePromise = new Promise<void>((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        try {
          // Use startsWith for more robust path checking.
          if (!req.url || !req.url.startsWith('/oauth2callback')) {
            res.end();
            reject(
              new Error(
                'OAuth callback not received. Unexpected request: ' + req.url,
              ),
            );
            return;
          }

          const qs = new url.URL(req.url, `http://${host}:${port}`)
            .searchParams;

          // SECURITY: Validate the state parameter to prevent CSRF attacks.
          const returnedState = qs.get('state');
          if (returnedState !== csrfToken) {
            res.end('State mismatch. Possible CSRF attack.');
            reject(new Error('OAuth state mismatch. Possible CSRF attack.'));
            return;
          }

          if (qs.get('error')) {
            const errorCode = qs.get('error');
            const errorDescription =
              qs.get('error_description') || 'No additional details provided';
            res.end();
            reject(
              new Error(
                `Google OAuth error: ${errorCode}. ${errorDescription}`,
              ),
            );
            return;
          }

          const code = qs.get('code');

          if (config.authMode === 'installed-app' && code) {
            const { tokens } = await client.getToken({
              code,
              redirect_uri: localRedirectUri,
            });
            client.setCredentials(tokens);
            res.end('Authentication successful! Please return to the console.');
            resolve();
            return;
          }

          const access_token = qs.get('access_token');
          const refresh_token = qs.get('refresh_token');
          const scope = qs.get('scope');
          const token_type = qs.get('token_type');
          const expiry_date_str = qs.get('expiry_date');

          if (access_token && expiry_date_str) {
            const tokens: Auth.Credentials = {
              access_token: access_token,
              refresh_token: refresh_token || null,
              scope: scope || undefined,
              token_type: (token_type as 'Bearer') || undefined,
              expiry_date: parseInt(expiry_date_str, 10),
            };
            client.setCredentials(tokens);
            res.end('Authentication successful! Please return to the console.');
            resolve();
          } else {
            reject(
              new Error(
                'Authentication failed: Did not receive tokens from callback.',
              ),
            );
          }
        } catch (e) {
          reject(e);
        } finally {
          server.close();
        }
      });

      server.listen(port, host, () => {
        // Server started successfully
      });

      server.on('error', (err) => {
        reject(new Error(`OAuth callback server error: ${err}`));
      });
    });

    return {
      authUrl,
      loginCompletePromise,
    };
  }
}
