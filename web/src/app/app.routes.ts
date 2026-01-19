import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login/login.component';
import { HomeComponent } from './pages/home/home.component';
import { CertificatesComponent } from './pages/certificates/certificates.component';
import { RevokeComponent } from './pages/revoke/revoke.component';
import { CaCertificatesComponent } from './pages/ca-certificates/ca-certificates.component';
import { CertificatePolicyComponent } from './pages/certificate-policy/certificate-policy.component';
import { CertificationPracticeStatementComponent } from './pages/certification-practice-statement/certification-practice-statement.component';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'certificates', component: CertificatesComponent, canActivate: [authGuard] },
  { path: 'ca-certificates', component: CaCertificatesComponent, canActivate: [authGuard] },
  { path: 'revoke', component: RevokeComponent, canActivate: [authGuard] },
  { path: 'certificate-policy', component: CertificatePolicyComponent },
  { path: 'certification-practice-statement', component: CertificationPracticeStatementComponent },
  { path: '**', redirectTo: '/' }
];
