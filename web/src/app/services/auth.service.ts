import { Injectable } from '@angular/core';
import { AuthConfig, OAuthService } from 'angular-oauth2-oidc';
import { ConfigService } from './config.service';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private isAuthenticatedSubject = new BehaviorSubject<boolean>(false);
  public isAuthenticated$: Observable<boolean> = this.isAuthenticatedSubject.asObservable();

  constructor(
    private oauthService: OAuthService,
    private configService: ConfigService,
    private router: Router
  ) {}

  async initializeAuth(): Promise<void> {
    const config = this.configService.getConfig();
    
    const authConfig: AuthConfig = {
      issuer: config.oidc.issuer,
      clientId: config.oidc.clientId,
      redirectUri: config.oidc.redirectUri,
      postLogoutRedirectUri: config.oidc.postLogoutRedirectUri,
      scope: config.oidc.scope,
      responseType: config.oidc.responseType,
      requireHttps: config.oidc.requireHttps,
      showDebugInformation: true
    };

    this.oauthService.configure(authConfig);
    this.oauthService.setupAutomaticSilentRefresh();

    try {
      await this.oauthService.loadDiscoveryDocumentAndTryLogin();
      
      if (this.oauthService.hasValidAccessToken()) {
        this.isAuthenticatedSubject.next(true);
      } else {
        this.isAuthenticatedSubject.next(false);
      }
    } catch (error) {
      console.error('Error during authentication initialization:', error);
      this.isAuthenticatedSubject.next(false);
    }
  }

  login(): void {
    this.oauthService.initCodeFlow();
  }

  logout(): void {
    this.oauthService.logOut();
    this.isAuthenticatedSubject.next(false);
    this.router.navigate(['/login']);
  }

  isAuthenticated(): boolean {
    return this.oauthService.hasValidAccessToken();
  }

  getAccessToken(): string {
    return this.oauthService.getAccessToken();
  }

  getUserProfile(): any {
    const claims = this.oauthService.getIdentityClaims();
    return claims;
  }
}
