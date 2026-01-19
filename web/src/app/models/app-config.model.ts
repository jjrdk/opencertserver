export interface OidcConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  scope: string;
  responseType: string;
  requireHttps: boolean;
}

export interface ApiConfig {
  baseUrl: string;
}

export interface AppConfig {
  oidc: OidcConfig;
  api: ApiConfig;
}
