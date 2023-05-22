/*
 * Copyright 2021 The Backstage Authors
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

import express from 'express';
import { TokenPayload } from 'google-auth-library';
import { createAuthProviderIntegration } from '../createAuthProviderIntegration';
import { prepareBackstageIdentityResponse } from '../prepareBackstageIdentityResponse';
import {
  AuthHandler,
  AuthProviderConfig,
  AuthProviderRouteHandlers,
  AuthResolverContext,
  SignInInfo,
  SignInResolver,
} from '../types';
import {
  createTokenValidator,
  defaultAuthHandler,
  parseRequestToken,
} from './helpers';
import { GcpIapResponse, GcpIapResult, DEFAULT_IAP_JWT_HEADER } from './types';
import { OAuthResult } from '../../lib/oauth';
import { Config } from '@backstage/config';

export class GcpIapProvider implements AuthProviderRouteHandlers {
  private readonly authHandler: AuthHandler<GcpIapResult>;
  private readonly signInResolver: SignInResolver<GcpIapResult>;
  private readonly tokenValidator: (token: string) => Promise<TokenPayload>;
  private readonly resolverContext: AuthResolverContext;
  private readonly jwtHeader: string;

  constructor(options: {
    authHandler: AuthHandler<GcpIapResult>;
    signInResolver: SignInResolver<GcpIapResult>;
    tokenValidator: (token: string) => Promise<TokenPayload>;
    resolverContext: AuthResolverContext;
    jwtHeader?: string;
  }) {
    this.authHandler = options.authHandler;
    this.signInResolver = options.signInResolver;
    this.tokenValidator = options.tokenValidator;
    this.resolverContext = options.resolverContext;
    this.jwtHeader = options?.jwtHeader || DEFAULT_IAP_JWT_HEADER;
  }

  async start() {}

  async frameHandler() {}

  async refresh(req: express.Request, res: express.Response): Promise<void> {
    const result = await parseRequestToken(
      req.header(this.jwtHeader),
      this.tokenValidator,
    );

    const { profile } = await this.authHandler(result, this.resolverContext);

    const backstageIdentity = await this.signInResolver(
      { profile, result },
      this.resolverContext,
    );

    const response: GcpIapResponse = {
      providerInfo: { iapToken: result.iapToken },
      profile,
      backstageIdentity: prepareBackstageIdentityResponse(backstageIdentity),
    };

    res.json(response);
  }
}

export const authModuleGcpIapProvider = createAuthProviderModule<GcpIapResult>({
  defaultId: 'gcp-iap',
  handlers: createProxyAuthHandlers({
    async refresh(req, ctx) {
      const result = await parseRequestToken(
        req.header(this.jwtHeader),
        this.tokenValidator,
      );

      return { result };
    },
  }),
});

export interface ProxyAuthenticator<TContext, TResult> {
  initialize(ctx: {
    providerId: string;
    globalConfig: AuthProviderConfig;
    config: Config;
  }): Promise<TContext>;
  authenticate(
    options: { req: express.Request },
    ctx: TContext,
  ): Promise<{ result: TResult }>;
}

export function createProxyAuthenticator<TContext, TResult>(
  authenticator: ProxyAuthenticator<TContext, TResult>,
): ProxyAuthenticator<TContext, TResult> {
  return authenticator;
}

export const gcpIapAuthenticator = createProxyAuthenticator({
  async initialize({ config }) {
    const audience = config.getString('audience');
    const jwtHeader =
      config.getOptionalString('jwtHeader') ?? DEFAULT_IAP_JWT_HEADER;

    const tokenValidator = createTokenValidator(audience);

    return { jwtHeader, tokenValidator };
  },
  async authenticate({ req }, { jwtHeader, tokenValidator }) {
    const result = await parseRequestToken(
      req.header(jwtHeader),
      tokenValidator,
    );

    return { result };
  },
});

export const authModuleGcpIapProvider = createBackendModule({
  defaultId: 'gcp-iap',
  handlers: createProxyAuthHandlers({
    async refresh(req) {
      const result = await parseRequestToken(
        req.header(this.jwtHeader),
        this.tokenValidator,
      );

      return { result };
    },
  }),
});

export const authModuleGoogleProvider = createBackendModule(
  (options?: { providerId?: string }) => {
    const providerId = options?.providerId ?? 'gcp-iap';
    return {
      pluginId: 'auth',
      moduleId: `provider-${providerId}`,
      register(reg) {
        reg.registerInit({
          deps: {
            logger: coreServices.logger,
            providers: authProvidersExtensionPoint,
          },
          async init({ logger, providers }) {
            providers.registerProvider({
              providerId,
              factory: createProxyAuthProviderFactory({
                logger,
                authenticator: gcpIapAuthenticator,
              }),
            });
          },
        });
      },
    };
  },
);

/**
 * Auth provider integration for Google Identity-Aware Proxy auth
 *
 * @public
 */
export const gcpIap = createAuthProviderIntegration({
  create(options: {
    /**
     * The profile transformation function used to verify and convert the auth
     * response into the profile that will be presented to the user. The default
     * implementation just provides the authenticated email that the IAP
     * presented.
     */
    authHandler?: AuthHandler<GcpIapResult>;

    /**
     * Configures sign-in for this provider.
     */
    signIn: {
      /**
       * Maps an auth result to a Backstage identity for the user.
       */
      resolver: SignInResolver<GcpIapResult>;
    };
  }) {
    return ({ config, resolverContext }) => {
      const audience = config.getString('audience');
      const jwtHeader = config.getOptionalString('jwtHeader');

      const authHandler = options.authHandler ?? defaultAuthHandler;
      const signInResolver = options.signIn.resolver;
      const tokenValidator = createTokenValidator(audience);

      return new GcpIapProvider({
        authHandler,
        signInResolver,
        tokenValidator,
        resolverContext,
        jwtHeader,
      });
    };
  },
});
