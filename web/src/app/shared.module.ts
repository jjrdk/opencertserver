import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { JsonPipe } from '@angular/common';

// Material imports
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatPaginatorModule } from '@angular/material/paginator';
import { MatSortModule } from '@angular/material/sort';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatRadioModule } from '@angular/material/radio';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatDividerModule } from '@angular/material/divider';
import { MatExpansionModule } from '@angular/material/expansion';

// Components
import { HeaderComponent } from './components/header/header.component';
import { LoginComponent } from './pages/login/login.component';
import { HomeComponent } from './pages/home/home.component';
import { CertificatesComponent } from './pages/certificates/certificates.component';
import { RevokeComponent } from './pages/revoke/revoke.component';
import { CaCertificatesComponent } from './pages/ca-certificates/ca-certificates.component';
import { CertificatePolicyComponent } from './pages/certificate-policy/certificate-policy.component';
import { CertificationPracticeStatementComponent } from './pages/certification-practice-statement/certification-practice-statement.component';
import { CsrAttributesComponent } from './pages/csr-attributes/csr-attributes.component';
import { EnrollComponent } from './pages/enroll/enroll.component';
import { ServerKeygenComponent } from './pages/server-keygen/server-keygen.component';

@NgModule({
  declarations: [
    LoginComponent,
    CertificatesComponent,
    RevokeComponent,
    CaCertificatesComponent,
    CertificatePolicyComponent,
    CertificationPracticeStatementComponent,
    CsrAttributesComponent,
    EnrollComponent,
    ServerKeygenComponent
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    FormsModule,
    RouterModule,
    MatToolbarModule,
    MatButtonModule,
    MatIconModule,
    MatMenuModule,
    MatCardModule,
    MatTableModule,
    MatPaginatorModule,
    MatSortModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatProgressSpinnerModule,
    MatDividerModule,
    MatExpansionModule,
    MatRadioModule,
    MatProgressBarModule,
    JsonPipe
  ],
  exports: [
    LoginComponent,
    CertificatesComponent,
    RevokeComponent,
    CaCertificatesComponent,
    CertificatePolicyComponent,
    CertificationPracticeStatementComponent,
    CsrAttributesComponent,
    EnrollComponent,
    ServerKeygenComponent
  ]
})
export class SharedModule { }
