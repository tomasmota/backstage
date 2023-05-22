/*
 * Copyright 2020 The Backstage Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import express, { CookieOptions } from 'express';
import crypto from 'crypto';
import { URL } from 'url';
import {
  BackstageIdentityResponse,
  BackstageSignInResult,
} from '@backstage/plugin-auth-node';
import {
  AuthProviderRouteHandlers,
  AuthProviderConfig,
  CookieConfigurer,
} from '../../providers/types';
import {
  AuthenticationError,
  InputError,
  isError,
  NotAllowedError,
} from '@backstage/errors';
import { defaultCookieConfigurer, readState, verifyNonce } from './helpers';
import {
  postMessageResponse,
  ensuresXRequestedWith,
  WebMessageResponse,
} from '../flow';
import {
  OAuthHandlers,
  OAuthStartRequest,
  OAuthRefreshRequest,
  OAuthState,
  OAuthLogoutRequest,
} from './types';
import { prepareBackstageIdentityResponse } from '../../providers/prepareBackstageIdentityResponse';
import {
  OAuthAuthenticationResult,
  OAuthAuthenticator,
  ProfileTransform,
} from '@backstage/plugin-auth-backend/src/providers/google/new-provider';
import { Config } from '@backstage/config';
import {
  AuthResolverContext,
  OAuthResponse,
  SignInResolver,
} from '@backstage/plugin-auth-backend';

export const THOUSAND_DAYS_MS = 1000 * 24 * 60 * 60 * 1000;
export const TEN_MINUTES_MS = 600 * 1000;

export interface OAuthHandlersOptions<TProfile> {
  authenticator: OAuthAuthenticator<unknown, TProfile>;
  appUrl: string;
  baseUrl: string;
  isOriginAllowed: (origin: string) => boolean;
  callbackUrl: string;
  providerId: string;
  config: Config;
  resolverContext: AuthResolverContext;
  profileTransform: ProfileTransform<TProfile>;
  signInResolver?: SignInResolver<OAuthAuthenticationResult<TProfile>>;
}

class OAuthCookieManager {
  private readonly cookieConfigurer: CookieConfigurer;
  private readonly defaultAppOrigin: string;

  constructor(
    private readonly options: {
      providerId: string;
      appUrl: string;
      baseUrl: string;
      callbackUrl: string;
      cookieConfigurer: CookieConfigurer;
    },
  ) {
    this.cookieConfigurer = options.cookieConfigurer ?? defaultCookieConfigurer;
    this.defaultAppOrigin = new URL(options.appUrl).origin;
  }

  getConfig(origin: string, pathSuffix: string = '') {
    const cookieConfig = this.cookieConfigurer({
      providerId: this.options.providerId,
      baseUrl: this.options.baseUrl,
      callbackUrl: this.options.callbackUrl,
      appOrigin: origin,
    });
    return {
      httpOnly: true,
      sameSite: 'lax',
      ...cookieConfig,
      path: cookieConfig.path + pathSuffix,
    };
  }

  setNonce(res: express.Response) {}

  setRefreshToken(res: express.Response) {}

  setGrantedScopes(res: express.Response) {}

  getNonce(req: express.Request) {}

  getRefreshToken(req: express.Request) {}

  getGrantedScopes(req: express.Request) {}
}

export function createOAuthHandlers<TProfile>(
  options: OAuthHandlersOptions<TProfile>,
): AuthProviderRouteHandlers {
  const {
    authenticator,
    config,
    baseUrl,
    appUrl,
    providerId,
    isOriginAllowed,
    resolverContext,
    profileTransform,
    signInResolver,
  } = options;

  const defaultAppOrigin = new URL(appUrl).origin;
  const callbackUrl =
    config.getOptionalString('callbackUrl') ??
    `${baseUrl}/${providerId}/handler/frame`;

  const authenticatorCtx = authenticator.initialize({ config, callbackUrl });

  return {
    async start(
      this: never,
      req: express.Request,
      res: express.Response,
    ): Promise<void> {
      // retrieve scopes from request
      const scope = req.query.scope?.toString() ?? '';
      const env = req.query.env?.toString();
      const origin = req.query.origin?.toString();
      const redirectUrl = req.query.redirectUrl?.toString();
      const flow = req.query.flow?.toString();

      if (!env) {
        throw new InputError('No env provided in request query parameters');
      }

      const nonce = crypto.randomBytes(16).toString('base64');
      // set a nonce cookie before redirecting to oauth provider
      res.cookie(`${providerId}-nonce`, nonce, {
        maxAge: TEN_MINUTES_MS,
        ...getCookieConfig(origin ?? defaultAppOrigin, '/handler'),
      });

      const state: OAuthState = { nonce, env, origin, redirectUrl, flow };

      // If scopes are persisted then we pass them through the state so that we
      // can set the cookie on successful auth
      if (authenticator.shouldPersistScopes) {
        state.scope = scope;
      }

      const { url, status } = await options.authenticator.start(
        { req, scope, state },
        authenticatorCtx,
      );

      res.statusCode = status || 302;
      res.setHeader('Location', url);
      res.setHeader('Content-Length', '0');
      res.end();
    },

    async frameHandler(
      this: never,
      req: express.Request,
      res: express.Response,
    ): Promise<void> {
      let appOrigin = defaultAppOrigin;

      try {
        const state: OAuthState = readState(req.query.state?.toString() ?? '');

        if (state.origin) {
          try {
            appOrigin = new URL(state.origin).origin;
          } catch {
            throw new NotAllowedError('App origin is invalid, failed to parse');
          }
          if (!isOriginAllowed(appOrigin)) {
            throw new NotAllowedError(`Origin '${appOrigin}' is not allowed`);
          }
        }

        // verify nonce cookie and state cookie on callback
        verifyNonce(req, providerId);

        const result = await authenticator.authenticate(
          { req },
          authenticatorCtx,
        );
        const { profile } = await profileTransform(result, resolverContext);

        const response: OAuthResponse = {
          profile,
          providerInfo: {
            idToken: result.session.idToken,
            accessToken: result.session.accessToken,
            scope: result.session.scope,
            expiresInSeconds: result.session.expiresInSeconds,
          },
        };

        if (signInResolver) {
          const identity = await signInResolver(
            { profile, result },
            resolverContext,
          );
          response.backstageIdentity =
            prepareBackstageIdentityResponse(identity);
        }

        const cookieConfig = getCookieConfig(appOrigin);

        // Store the scope that we have been granted for this session. This is useful if
        // the provider does not return granted scopes on refresh or if they are normalized.
        if (authenticator.shouldPersistScopes && state.scope) {
          res.cookie(`${providerId}-granted-scope`, state.scope, {
            maxAge: THOUSAND_DAYS_MS,
            ...cookieConfig,
          });
          result.session.scope = state.scope;
        }

        if (result.session.refreshToken) {
          // set new refresh token
          res.cookie(
            `${providerId}-refresh-token`,
            result.session.refreshToken,
            {
              maxAge: THOUSAND_DAYS_MS,
              ...cookieConfig,
            },
          );
        }

        // When using the redirect flow we rely on refresh token we just
        // acquired to get a new session once we're back in the app.
        if (state.flow === 'redirect') {
          if (!state.redirectUrl) {
            throw new InputError(
              'No redirectUrl provided in request query parameters',
            );
          }
          res.redirect(state.redirectUrl);
        }
        // post message back to popup if successful
        return postMessageResponse(res, appOrigin, {
          type: 'authorization_response',
          response,
        });
      } catch (error) {
        const { name, message } = isError(error)
          ? error
          : new Error('Encountered invalid error'); // Being a bit safe and not forwarding the bad value
        // post error message back to popup if failure
        return postMessageResponse(res, appOrigin, {
          type: 'authorization_response',
          error: { name, message },
        });
      }
    },

    async logout(
      this: never,
      req: express.Request,
      res: express.Response,
    ): Promise<void> {
      if (!ensuresXRequestedWith(req)) {
        throw new AuthenticationError('Invalid X-Requested-With header');
      }

      if (authenticator.logout) {
        const refreshToken = this.getRefreshTokenFromCookie(req);
        const revokeRequest: OAuthLogoutRequest = Object.assign(req, {
          refreshToken,
        });
        await this.handlers.logout(revokeRequest);
      }

      // remove refresh token cookie if it is set
      const origin = req.get('origin');
      const cookieConfig = this.getCookieConfig(origin);
      this.removeRefreshTokenCookie(res, cookieConfig);

      res.status(200).end();
    },

    async refresh(
      this: never,
      req: express.Request,
      res: express.Response,
    ): Promise<void> {
      if (!ensuresXRequestedWith(req)) {
        throw new AuthenticationError('Invalid X-Requested-With header');
      }

      if (!this.handlers.refresh) {
        throw new InputError(
          `Refresh token is not supported for provider ${this.options.providerId}`,
        );
      }

      try {
        const refreshToken = this.getRefreshTokenFromCookie(req);

        // throw error if refresh token is missing in the request
        if (!refreshToken) {
          throw new InputError('Missing session cookie');
        }

        let scope = req.query.scope?.toString() ?? '';
        if (this.options.persistScopes) {
          scope = this.getGrantedScopeFromCookie(req);
        }
        const forwardReq = Object.assign(req, { scope, refreshToken });

        // get new access_token
        const { response, refreshToken: newRefreshToken } =
          await this.handlers.refresh(forwardReq as OAuthRefreshRequest);

        const backstageIdentity = await this.populateIdentity(
          response.backstageIdentity,
        );

        if (newRefreshToken && newRefreshToken !== refreshToken) {
          const origin = req.get('origin');
          const cookieConfig = this.getCookieConfig(origin);
          this.setRefreshTokenCookie(res, newRefreshToken, cookieConfig);
        }

        res.status(200).json({ ...response, backstageIdentity });
      } catch (error) {
        throw new AuthenticationError('Refresh failed', error);
      }
    },
  };
}

/** @public */
export type OAuthAdapterOptions = {
  providerId: string;
  persistScopes?: boolean;
  appOrigin: string;
  baseUrl: string;
  cookieConfigurer: CookieConfigurer;
  isOriginAllowed: (origin: string) => boolean;
  callbackUrl: string;
};

/** @public */
export class OAuthAdapter implements AuthProviderRouteHandlers {
  static fromConfig(
    config: AuthProviderConfig,
    handlers: OAuthHandlers,
    options: Pick<
      OAuthAdapterOptions,
      'providerId' | 'persistScopes' | 'callbackUrl'
    >,
  ): OAuthAdapter {
    const { appUrl, baseUrl, isOriginAllowed } = config;
    const { origin: appOrigin } = new URL(appUrl);

    const cookieConfigurer = config.cookieConfigurer ?? defaultCookieConfigurer;

    return new OAuthAdapter(handlers, {
      ...options,
      appOrigin,
      baseUrl,
      cookieConfigurer,
      isOriginAllowed,
    });
  }

  private readonly baseCookieOptions: CookieOptions;

  constructor(
    private readonly handlers: OAuthHandlers,
    private readonly options: OAuthAdapterOptions,
  ) {
    this.baseCookieOptions = {
      httpOnly: true,
      sameSite: 'lax',
    };
  }

  async start(req: express.Request, res: express.Response): Promise<void> {
    // retrieve scopes from request
    const scope = req.query.scope?.toString() ?? '';
    const env = req.query.env?.toString();
    const origin = req.query.origin?.toString();
    const redirectUrl = req.query.redirectUrl?.toString();
    const flow = req.query.flow?.toString();

    if (!env) {
      throw new InputError('No env provided in request query parameters');
    }

    const cookieConfig = this.getCookieConfig(origin);

    const nonce = crypto.randomBytes(16).toString('base64');
    // set a nonce cookie before redirecting to oauth provider
    this.setNonceCookie(res, nonce, cookieConfig);

    const state: OAuthState = { nonce, env, origin, redirectUrl, flow };

    // If scopes are persisted then we pass them through the state so that we
    // can set the cookie on successful auth
    if (this.options.persistScopes) {
      state.scope = scope;
    }
    const forwardReq = Object.assign(req, { scope, state });

    const { url, status } = await this.handlers.start(
      forwardReq as OAuthStartRequest,
    );

    res.statusCode = status || 302;
    res.setHeader('Location', url);
    res.setHeader('Content-Length', '0');
    res.end();
  }

  async frameHandler(
    req: express.Request,
    res: express.Response,
  ): Promise<void> {
    let appOrigin = this.options.appOrigin;

    try {
      const state: OAuthState = readState(req.query.state?.toString() ?? '');

      if (state.origin) {
        try {
          appOrigin = new URL(state.origin).origin;
        } catch {
          throw new NotAllowedError('App origin is invalid, failed to parse');
        }
        if (!this.options.isOriginAllowed(appOrigin)) {
          throw new NotAllowedError(`Origin '${appOrigin}' is not allowed`);
        }
      }

      // verify nonce cookie and state cookie on callback
      verifyNonce(req, this.options.providerId);

      const { response, refreshToken } = await this.handlers.handler(req);

      const cookieConfig = this.getCookieConfig(appOrigin);

      // Store the scope that we have been granted for this session. This is useful if
      // the provider does not return granted scopes on refresh or if they are normalized.
      if (this.options.persistScopes && state.scope) {
        this.setGrantedScopeCookie(res, state.scope, cookieConfig);
        response.providerInfo.scope = state.scope;
      }

      if (refreshToken) {
        // set new refresh token
        this.setRefreshTokenCookie(res, refreshToken, cookieConfig);
      }

      const identity = await this.populateIdentity(response.backstageIdentity);

      const responseObj: WebMessageResponse = {
        type: 'authorization_response',
        response: { ...response, backstageIdentity: identity },
      };

      if (state.flow === 'redirect') {
        if (!state.redirectUrl) {
          throw new InputError(
            'No redirectUrl provided in request query parameters',
          );
        }
        res.redirect(state.redirectUrl);
      }
      // post message back to popup if successful
      return postMessageResponse(res, appOrigin, responseObj);
    } catch (error) {
      const { name, message } = isError(error)
        ? error
        : new Error('Encountered invalid error'); // Being a bit safe and not forwarding the bad value
      // post error message back to popup if failure
      return postMessageResponse(res, appOrigin, {
        type: 'authorization_response',
        error: { name, message },
      });
    }
  }

  async logout(req: express.Request, res: express.Response): Promise<void> {
    if (!ensuresXRequestedWith(req)) {
      throw new AuthenticationError('Invalid X-Requested-With header');
    }

    if (this.handlers.logout) {
      const refreshToken = this.getRefreshTokenFromCookie(req);
      const revokeRequest: OAuthLogoutRequest = Object.assign(req, {
        refreshToken,
      });
      await this.handlers.logout(revokeRequest);
    }

    // remove refresh token cookie if it is set
    const origin = req.get('origin');
    const cookieConfig = this.getCookieConfig(origin);
    this.removeRefreshTokenCookie(res, cookieConfig);

    res.status(200).end();
  }

  async refresh(req: express.Request, res: express.Response): Promise<void> {
    if (!ensuresXRequestedWith(req)) {
      throw new AuthenticationError('Invalid X-Requested-With header');
    }

    if (!this.handlers.refresh) {
      throw new InputError(
        `Refresh token is not supported for provider ${this.options.providerId}`,
      );
    }

    try {
      const refreshToken = this.getRefreshTokenFromCookie(req);

      // throw error if refresh token is missing in the request
      if (!refreshToken) {
        throw new InputError('Missing session cookie');
      }

      let scope = req.query.scope?.toString() ?? '';
      if (this.options.persistScopes) {
        scope = this.getGrantedScopeFromCookie(req);
      }
      const forwardReq = Object.assign(req, { scope, refreshToken });

      // get new access_token
      const { response, refreshToken: newRefreshToken } =
        await this.handlers.refresh(forwardReq as OAuthRefreshRequest);

      const backstageIdentity = await this.populateIdentity(
        response.backstageIdentity,
      );

      if (newRefreshToken && newRefreshToken !== refreshToken) {
        const origin = req.get('origin');
        const cookieConfig = this.getCookieConfig(origin);
        this.setRefreshTokenCookie(res, newRefreshToken, cookieConfig);
      }

      res.status(200).json({ ...response, backstageIdentity });
    } catch (error) {
      throw new AuthenticationError('Refresh failed', error);
    }
  }

  /**
   * If the response from the OAuth provider includes a Backstage identity, we
   * make sure it's populated with all the information we can derive from the user ID.
   */
  private async populateIdentity(
    identity?: BackstageSignInResult,
  ): Promise<BackstageIdentityResponse | undefined> {
    if (!identity) {
      return undefined;
    }
    if (!identity.token) {
      throw new InputError(`Identity response must return a token`);
    }

    return prepareBackstageIdentityResponse(identity);
  }

  private setNonceCookie = (
    res: express.Response,
    nonce: string,
    cookieConfig: ReturnType<CookieConfigurer>,
  ) => {
    res.cookie(`${this.options.providerId}-nonce`, nonce, {
      maxAge: TEN_MINUTES_MS,
      ...this.baseCookieOptions,
      ...cookieConfig,
      path: `${cookieConfig.path}/handler`,
    });
  };

  private setGrantedScopeCookie = (
    res: express.Response,
    scope: string,
    cookieConfig: ReturnType<CookieConfigurer>,
  ) => {
    res.cookie(`${this.options.providerId}-granted-scope`, scope, {
      maxAge: THOUSAND_DAYS_MS,
      ...this.baseCookieOptions,
      ...cookieConfig,
    });
  };

  private getRefreshTokenFromCookie = (req: express.Request) => {
    return req.cookies[`${this.options.providerId}-refresh-token`];
  };

  private getGrantedScopeFromCookie = (req: express.Request) => {
    return req.cookies[`${this.options.providerId}-granted-scope`];
  };

  private setRefreshTokenCookie = (
    res: express.Response,
    refreshToken: string,
    cookieConfig: ReturnType<CookieConfigurer>,
  ) => {
    res.cookie(`${this.options.providerId}-refresh-token`, refreshToken, {
      maxAge: THOUSAND_DAYS_MS,
      ...this.baseCookieOptions,
      ...cookieConfig,
    });
  };

  private removeRefreshTokenCookie = (
    res: express.Response,
    cookieConfig: ReturnType<CookieConfigurer>,
  ) => {
    res.cookie(`${this.options.providerId}-refresh-token`, '', {
      maxAge: 0,
      ...this.baseCookieOptions,
      ...cookieConfig,
    });
  };

  private getCookieConfig = (origin?: string) => {
    return this.options.cookieConfigurer({
      providerId: this.options.providerId,
      baseUrl: this.options.baseUrl,
      callbackUrl: this.options.callbackUrl,
      appOrigin: origin ?? this.options.appOrigin,
    });
  };
}
