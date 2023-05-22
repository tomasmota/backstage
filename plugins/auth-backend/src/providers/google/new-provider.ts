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

import express from 'express';
import passport from 'passport';
import { OAuth2Client } from 'google-auth-library';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import {
  encodeState,
  OAuthAdapter,
  OAuthEnvironmentHandler,
  OAuthHandlers,
  OAuthProviderOptions,
  OAuthRefreshRequest,
  OAuthResponse,
  OAuthResult,
  OAuthStartRequest,
  OAuthLogoutRequest,
} from '../../lib/oauth';
import {
  executeFetchUserProfileStrategy,
  executeFrameHandlerStrategy,
  executeRedirectStrategy,
  executeRefreshTokenStrategy,
  makeProfileInfo,
  PassportDoneCallback,
} from '../../lib/passport';
import {
  AuthHandler,
  AuthProviderConfig,
  AuthProviderFactory,
  AuthResolverContext,
  OAuthStartResponse,
  ProfileInfo,
  SignInResolver,
} from '../types';
import { createAuthProviderIntegration } from '../createAuthProviderIntegration';
import {
  commonByEmailLocalPartResolver,
  commonByEmailResolver,
} from '../resolvers';
import { Config } from '@backstage/config';
import {
  LoggerService,
  coreServices,
  createBackendModule,
  createExtensionPoint,
} from '@backstage/backend-plugin-api';
import { PassportProfile } from '../../lib/passport/types';

type PrivateInfo = {
  refreshToken: string;
};

type Options = OAuthProviderOptions & {
  signInResolver?: SignInResolver<OAuthResult>;
  authHandler: AuthHandler<OAuthResult>;
  resolverContext: AuthResolverContext;
};

export class GoogleAuthProvider implements OAuthHandlers {
  private readonly strategy: GoogleStrategy;
  private readonly signInResolver?: SignInResolver<OAuthResult>;
  private readonly authHandler: AuthHandler<OAuthResult>;
  private readonly resolverContext: AuthResolverContext;

  constructor(options: Options) {
    this.authHandler = options.authHandler;
    this.signInResolver = options.signInResolver;
    this.resolverContext = options.resolverContext;
    this.strategy = new GoogleStrategy(
      {
        clientID: options.clientId,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackUrl,
        passReqToCallback: false,
      },
      (
        accessToken: any,
        refreshToken: any,
        params: any,
        fullProfile: passport.Profile,
        done: PassportDoneCallback<OAuthResult, PrivateInfo>,
      ) => {
        done(
          undefined,
          {
            fullProfile,
            params,
            accessToken,
            refreshToken,
          },
          {
            refreshToken,
          },
        );
      },
    );
  }

  async start(req: OAuthStartRequest): Promise<OAuthStartResponse> {
    return await executeRedirectStrategy(req, this.strategy, {
      accessType: 'offline',
      prompt: 'consent',
      scope: req.scope,
      state: encodeState(req.state),
    });
  }

  async handler(req: express.Request) {
    const { result, privateInfo } = await executeFrameHandlerStrategy<
      OAuthResult,
      PrivateInfo
    >(req, this.strategy);

    return {
      response: await this.handleResult(result),
      refreshToken: privateInfo.refreshToken,
    };
  }

  async logout(req: OAuthLogoutRequest) {
    const oauthClient = new OAuth2Client();
    await oauthClient.revokeToken(req.refreshToken);
  }

  async refresh(req: OAuthRefreshRequest) {
    const { accessToken, refreshToken, params } =
      await executeRefreshTokenStrategy(
        this.strategy,
        req.refreshToken,
        req.scope,
      );
    const fullProfile = await executeFetchUserProfileStrategy(
      this.strategy,
      accessToken,
    );

    return {
      response: await this.handleResult({
        fullProfile,
        params,
        accessToken,
      }),
      refreshToken,
    };
  }

  private async handleResult(result: OAuthResult) {
    const { profile } = await this.authHandler(result, this.resolverContext);

    const response: OAuthResponse = {
      providerInfo: {
        idToken: result.params.id_token,
        accessToken: result.accessToken,
        scope: result.params.scope,
        expiresInSeconds: result.params.expires_in,
      },
      profile,
    };

    if (this.signInResolver) {
      response.backstageIdentity = await this.signInResolver(
        {
          result,
          profile,
        },
        this.resolverContext,
      );
    }

    return response;
  }
}

export interface AuthProviderRegistrationOptions {
  providerId: string;
  factory: AuthProviderFactory;
}

export interface AuthProvidersExtensionPoint {
  registerProvider(options: AuthProviderRegistrationOptions): void;
}

export const authProvidersExtensionPoint =
  createExtensionPoint<AuthProvidersExtensionPoint>({
    id: 'auth.providers',
  });

export function createOAuthProviderFactory<TProfile>(options: {
  authenticator: OAuthAuthenticator<unknown, TProfile>;
  profileTransform?: ProfileTransform<TProfile>;
  signInResolver?: SignInResolver<OAuthAuthenticationResult<TProfile>>;
  availableSignInResolvers?: Record<
    string,
    SignInResolver<OAuthAuthenticationResult<TProfile>>
  >;
}): AuthProviderFactory {
  return ctx => {
    return OAuthEnvironmentHandler.mapConfig(ctx.config, envConfig => {
      const authenticator = options.authenticator;

      const callbackUrl =
        envConfig.getOptionalString('callbackUrl') ??
        `${ctx.globalConfig.baseUrl}/${ctx.providerId}/handler/frame`;

      const authenticatorCtx = authenticator.initialize({
        callbackUrl,
        config: envConfig,
      });

      const profileTransform =
        options.profileTransform ?? authenticator.defaultProfileTransform;

      const signInResolver =
        options.signInResolver ??
        readDeclarativeSignInResolver(envConfig, {
          availableResolvers: options.availableSignInResolvers,
        });

      return OAuthAdapter.fromConfig(
        ctx.globalConfig,
        {
          start(req) {
            return authenticator.start({ req }, authenticatorCtx);
          },
          async handler(req) {
            const result = await authenticator.authenticate(
              { req },
              authenticatorCtx,
            );
            const { profile } = await profileTransform(
              result,
              ctx.resolverContext,
            );
            return {
              response: {
                profile,
                backstageIdentity:
                  signInResolver &&
                  (await signInResolver(
                    { profile, result },
                    ctx.resolverContext,
                  )),
                providerInfo: {
                  scope: result.session.scope,
                  idToken: result.session.idToken,
                  accessToken: result.session.accessToken,
                  expiresInSeconds: result.session.expiresInSeconds,
                },
              },
            };
          },
          async refresh(req) {
            const result = await authenticator.refresh(
              { req },
              authenticatorCtx,
            );
            const { profile } = await profileTransform(
              result,
              ctx.resolverContext,
            );
            return {
              response: {
                profile,
                backstageIdentity:
                  signInResolver &&
                  (await signInResolver(
                    { profile, result },
                    ctx.resolverContext,
                  )),
                providerInfo: {
                  scope: result.session.scope,
                  idToken: result.session.idToken,
                  accessToken: result.session.accessToken,
                  expiresInSeconds: result.session.expiresInSeconds,
                },
              },
            };
          },
          logout(req) {
            return authenticator.logout({ req }, authenticatorCtx);
          },
        },
        {
          callbackUrl,
          providerId: ctx.providerId,
          persistScopes: authenticator.persistScopes,
        },
      );
    });
  };
}

export interface OAuthSession {
  accessToken: string;
  tokenType: string;
  idToken?: string;
  scope: string;
  expiresInSeconds: number;
  refreshToken?: string;
}

export interface OAuthAuthenticatorStartInput {
  scope: string;
  state: string;
  req: express.Request;
}

export interface OAuthAuthenticatorAuthenticateInput {
  req: express.Request;
}

export interface OAuthAuthenticatorRefreshInput {
  scope: string;
  refreshToken: string;
  req: express.Request;
}

export interface OAuthAuthenticatorLogoutInput {
  accessToken?: string;
  refreshToken?: string;
  req: express.Request;
}

export interface OAuthAuthenticationResult<TProfile> {
  fullProfile: TProfile;
  session: OAuthSession;
}

export interface OAuthAuthenticator<TContext, TProfile> {
  defaultProfileTransform: ProfileTransform<TProfile>;
  shouldPersistScopes?: boolean;
  initialize(ctx: { callbackUrl: string; config: Config }): TContext;
  start(
    input: OAuthAuthenticatorStartInput,
    ctx: TContext,
  ): Promise<{ url: string; status?: number }>;
  authenticate(
    input: OAuthAuthenticatorAuthenticateInput,
    ctx: TContext,
  ): Promise<OAuthAuthenticationResult<TProfile>>;
  refresh(
    input: OAuthAuthenticatorRefreshInput,
    ctx: TContext,
  ): Promise<OAuthAuthenticationResult<TProfile>>;
  logout?(input: OAuthAuthenticatorLogoutInput, ctx: TContext): Promise<void>;
}

export type ProfileTransform<TProfile> = (
  result: OAuthAuthenticationResult<TProfile>,
  context: AuthResolverContext,
) => Promise<{ profile: ProfileInfo }>;

export function createOAuthAuthenticator<TContext, TProfile>(
  authenticator: OAuthAuthenticator<TContext, TProfile>,
): OAuthAuthenticator<TContext, TProfile> {
  return authenticator;
}

/** @public */
export class PassportAuthenticatorHelper {
  static from(strategy: passport.Strategy) {
    return new PassportAuthenticatorHelper(strategy);
  }

  readonly #strategy: passport.Strategy;

  private constructor(strategy: passport.Strategy) {
    this.#strategy = strategy;
  }

  async start(
    input: OAuthAuthenticatorStartInput,
    options: Record<string, string>,
  ): Promise<{ url: string; status?: number }> {
    return executeRedirectStrategy(input.req, this.#strategy, {
      scope: input.scope,
      state: input.state,
      ...options,
    });
  }

  async authenticate(
    input: OAuthAuthenticatorAuthenticateInput,
  ): Promise<OAuthAuthenticationResult<PassportProfile>> {
    const { result, privateInfo } = await executeFrameHandlerStrategy<
      OAuthResult,
      { refreshToken?: string }
    >(input.req, this.#strategy);

    return {
      fullProfile: result.fullProfile as PassportProfile,
      session: {
        accessToken: result.accessToken,
        tokenType: result.params.token_type ?? 'bearer',
        scope: result.params.scope,
        expiresInSeconds: result.params.expires_in,
        idToken: result.params.id_token,
        refreshToken: privateInfo.refreshToken,
      },
    };
  }

  async refresh(
    input: OAuthAuthenticatorRefreshInput,
  ): Promise<OAuthAuthenticationResult<PassportProfile>> {
    const result = await executeRefreshTokenStrategy(
      this.#strategy,
      input.refreshToken,
      input.scope,
    );
    const fullProfile = await this.fetchProfile(result.accessToken);
    return {
      fullProfile,
      session: {
        accessToken: result.accessToken,
        tokenType: result.params.token_type ?? 'bearer',
        scope: result.params.scope,
        expiresInSeconds: result.params.expires_in,
        idToken: result.params.id_token,
        refreshToken: result.refreshToken,
      },
    };
  }

  async fetchProfile(accessToken: string): Promise<PassportProfile> {
    const profile = await executeFetchUserProfileStrategy(
      this.#strategy,
      accessToken,
    );
    return profile;
  }
}

const defaultPassportProfileTransform: ProfileTransform<
  PassportProfile
> = async input => ({
  profile: makeProfileInfo(input.fullProfile, input.session.idToken),
});

export const googleAuthenticator = createOAuthAuthenticator({
  defaultProfileTransform: defaultPassportProfileTransform,
  initialize({ callbackUrl, config }) {
    const clientId = config.getString('clientId');
    const clientSecret = config.getString('clientSecret');

    return PassportAuthenticatorHelper.from(
      new GoogleStrategy(
        {
          clientID: clientId,
          clientSecret: clientSecret,
          callbackURL: callbackUrl,
          passReqToCallback: false,
        },
        (
          accessToken: any,
          refreshToken: any,
          params: any,
          fullProfile: passport.Profile,
          done: PassportDoneCallback<OAuthResult, PrivateInfo>,
        ) => {
          done(
            undefined,
            {
              fullProfile,
              params,
              accessToken,
              refreshToken,
            },
            {
              refreshToken,
            },
          );
        },
      ),
    );
  },

  async start(input, helper) {
    return helper.start(input, {
      accessType: 'offline',
      prompt: 'consent',
    });
  },

  async authenticate(input, helper) {
    return helper.authenticate(input);
  },

  async refresh(input, helper) {
    return helper.refresh(input);
  },

  async logout(input) {
    if (input.refreshToken) {
      const oauthClient = new OAuth2Client();
      await oauthClient.revokeToken(input.refreshToken);
    }
  },
});

function adaptLegacyAuthHandler(
  authHandler?: AuthHandler<OAuthResult>,
): ProfileTransform<PassportProfile> | undefined {
  return (
    authHandler &&
    (async (result, ctx) =>
      authHandler(
        {
          fullProfile: result.fullProfile,
          accessToken: result.session.accessToken,
          params: {
            scope: result.session.scope,
            id_token: result.session.idToken,
            token_type: result.session.tokenType,
            expires_in: result.session.expiresInSeconds,
          },
        },
        ctx,
      ))
  );
}

function adaptLegacySignInResolver(
  signInResolver?: SignInResolver<OAuthResult>,
): SignInResolver<OAuthAuthenticationResult<PassportProfile>> | undefined {
  return (
    signInResolver &&
    (async (input, ctx) =>
      signInResolver(
        {
          profile: input.profile,
          result: {
            fullProfile: input.result.fullProfile,
            accessToken: input.result.session.accessToken,
            refreshToken: input.result.session.refreshToken,
            params: {
              scope: input.result.session.scope,
              id_token: input.result.session.idToken,
              token_type: input.result.session.tokenType,
              expires_in: input.result.session.expiresInSeconds,
            },
          },
        },
        ctx,
      ))
  );
}

function adaptSignInResolversToLegacy(
  resolvers: Record<
    string,
    SignInResolver<OAuthAuthenticationResult<PassportProfile>>
  >,
): Record<string, () => SignInResolver<OAuthResult>> {
  return Object.fromEntries(
    Object.entries(resolvers).map(([name, resolver]) => [
      name,
      () => async (input, ctx) =>
        resolver(
          {
            profile: input.profile,
            result: {
              fullProfile: input.result.fullProfile,
              session: {
                accessToken: input.result.accessToken,
                expiresInSeconds: input.result.params.expires_in,
                scope: input.result.params.scope,
                idToken: input.result.params.id_token,
                tokenType: input.result.params.token_type ?? 'bearer',
                refreshToken: input.result.refreshToken,
              },
            },
          },
          ctx,
        ),
    ]),
  );
}

const resolvers: Record<
  string,
  SignInResolver<OAuthAuthenticationResult<PassportProfile>>
> = {
  /**
   * Looks up the user by matching their email local part to the entity name.
   */
  emailLocalPartMatchingUserEntityName: commonByEmailLocalPartResolver,
  /**
   * Looks up the user by matching their email to the entity email.
   */
  emailMatchingUserEntityProfileEmail: commonByEmailResolver,
  /**
   * Looks up the user by matching their email to the `google.com/email` annotation.
   */
  emailMatchingUserEntityAnnotation: async (info, ctx) => {
    const { profile } = info;

    if (!profile.email) {
      throw new Error('Google profile contained no email');
    }

    return ctx.signInWithCatalogUser({
      annotations: {
        'google.com/email': profile.email,
      },
    });
  },
};

export const authModuleGoogleProvider = createBackendModule(
  (options?: { providerId?: string }) => {
    const providerId = options?.providerId ?? 'google';
    return {
      pluginId: 'auth',
      moduleId: `provider-${providerId}`,
      register(reg) {
        reg.registerInit({
          deps: {
            providers: authProvidersExtensionPoint,
          },
          async init({ providers }) {
            providers.registerProvider({
              providerId,
              factory: createOAuthProviderFactory({
                authenticator: googleAuthenticator,
                availableSignInResolvers: resolvers,
              }),
            });
          },
        });
      },
    };
  },
);

/**
 * Auth provider integration for Google auth
 *
 * @public
 */
export const google = createAuthProviderIntegration({
  create(options?: {
    /**
     * The profile transformation function used to verify and convert the auth response
     * into the profile that will be presented to the user.
     */
    authHandler?: AuthHandler<OAuthResult>;

    /**
     * Configure sign-in for this provider, without it the provider can not be used to sign users in.
     */
    signIn?: {
      /**
       * Maps an auth result to a Backstage identity for the user.
       */
      resolver: SignInResolver<OAuthResult>;
    };
  }) {
    return createOAuthProviderFactory({
      authenticator: googleAuthenticator,
      profileTransform: adaptLegacyAuthHandler(options?.authHandler),
      signInResolver: adaptLegacySignInResolver(options?.signIn?.resolver),
    });
  },
  resolvers: adaptSignInResolversToLegacy(resolvers),
});
