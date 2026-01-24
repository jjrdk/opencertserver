import { ApplicationConfig, APP_INITIALIZER } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideAnimations } from '@angular/platform-browser/animations';
import { provideHttpClient } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';
import { importProvidersFrom } from '@angular/core';

import { routes } from './app.routes';
import { ConfigService } from './services/config.service';
import { AuthService } from './services/auth.service';

function initializeApp(
  configService: ConfigService,
  authService: AuthService
) {
  return async () => {
    try {
      await configService.loadConfig();
      await authService.initializeAuth();
    } catch (error) {
      console.error('App initialization error:', error);
      // Continue loading the app even if auth initialization fails
    }
  };
}

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideAnimations(),
    provideHttpClient(),
    importProvidersFrom(OAuthModule.forRoot()),
    {
      provide: APP_INITIALIZER,
      useFactory: initializeApp,
      deps: [ConfigService, AuthService],
      multi: true
    }
  ]
};
