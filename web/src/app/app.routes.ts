import { Routes } from '@angular/router';
import { LoginComponent } from './pages/login/login.component';
import { HomeComponent } from './pages/home/home.component';
import { CertificatesComponent } from './pages/certificates/certificates.component';
import { RevokeComponent } from './pages/revoke/revoke.component';
import { CaCertificatesComponent } from './pages/ca-certificates/ca-certificates.component';
import { CertificatePolicyComponent } from './pages/certificate-policy/certificate-policy.component';
import { CertificationPracticeStatementComponent } from './pages/certification-practice-statement/certification-practice-statement.component';
import { authGuard } from './guards/auth.guard';
import { CsrAttributesComponent } from './pages/csr-attributes/csr-attributes.component';
import { EnrollComponent } from './pages/enroll/enroll.component';
import { ServerKeygenComponent } from './pages/server-keygen/server-keygen.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'certificates', component: CertificatesComponent },
  { path: 'ca-certificates', component: CaCertificatesComponent },
  { path: 'revoke', component: RevokeComponent, canActivate: [authGuard] },
  { path: 'certificate-policy', component: CertificatePolicyComponent },
  { path: 'certification-practice-statement', component: CertificationPracticeStatementComponent },
  { path: 'csr-attributes', component: CsrAttributesComponent, canActivate: [authGuard] },
  { path: 'enroll', component: EnrollComponent, canActivate: [authGuard] },
  { path: 'server-keygen', component: ServerKeygenComponent, canActivate: [authGuard] },
  { path: '**', redirectTo: '/' }
];
