/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { logToFile } from './logger';

export interface WorkspaceConfig {
  clientId: string;
  clientSecret?: string;
  authUri: string;
  tokenUri: string;
  cloudFunctionUrl: string;
  authMode: 'cloud-function' | 'installed-app';
}

const DEFAULT_CONFIG: WorkspaceConfig = {
  clientId:
    '338689075775-o75k922vn5fdl18qergr96rp8g63e4d7.apps.googleusercontent.com',
  authUri: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUri: 'https://oauth2.googleapis.com/token',
  cloudFunctionUrl: 'https://google-workspace-extension.geminicli.com',
  authMode: 'cloud-function',
};

/**
 * Loads the configuration from environment variables, falling back to the
 * default cloud-function OAuth flow used by the Gemini extension.
 */
export function loadConfig(): WorkspaceConfig {
  const clientSecret = process.env['WORKSPACE_CLIENT_SECRET'];
  const config: WorkspaceConfig = {
    clientId: process.env['WORKSPACE_CLIENT_ID'] || DEFAULT_CONFIG.clientId,
    clientSecret,
    authUri: process.env['WORKSPACE_AUTH_URI'] || DEFAULT_CONFIG.authUri,
    tokenUri: process.env['WORKSPACE_TOKEN_URI'] || DEFAULT_CONFIG.tokenUri,
    cloudFunctionUrl:
      process.env['WORKSPACE_CLOUD_FUNCTION_URL'] ||
      DEFAULT_CONFIG.cloudFunctionUrl,
    authMode:
      process.env['WORKSPACE_AUTH_MODE'] === 'installed-app' || clientSecret
        ? 'installed-app'
        : DEFAULT_CONFIG.authMode,
  };

  const maskedClientId =
    config.clientId.length > 2
      ? `...${config.clientId.slice(-2)}`
      : config.clientId;
  logToFile(
    `Loaded config: clientId=${maskedClientId}, authMode=${config.authMode}, cloudFunctionUrl=${config.cloudFunctionUrl}`,
  );
  return config;
}
