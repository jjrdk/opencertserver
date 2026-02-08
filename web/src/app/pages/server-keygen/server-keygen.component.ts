  import { Component } from '@angular/core';
  import { ServerKeygenService } from '../../services/server-keygen.service';

  @Component({
    selector: 'app-server-keygen',
    templateUrl: './server-keygen.component.html',
    styleUrls: ['./server-keygen.component.scss'],
    standalone: false
})
  export class ServerKeygenComponent {
    dn = {
      cn: '',
      o: '',
      ou: '',
      c: '',
      st: '',
      l: ''
    };
    keyType: 'RSA' | 'EC' = 'RSA';
    certificate?: string;
    privateKey?: string;
    error?: string;
    loading = false;

    constructor(private serverKeygenService: ServerKeygenService) {}

    saveCertificate() {
      if (!this.certificate) return;
      const blob = new Blob([this.certificate], { type: 'application/x-pem-file' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'certificate.pem';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }, 0);
    }

    savePrivateKey() {
      if (!this.privateKey) return;
      const blob = new Blob([this.privateKey], { type: 'application/x-pem-file' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'privatekey.pem';
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }, 0);
    }

    onSubmit(form: any) {
      this.error = undefined;
      this.certificate = undefined;
      this.privateKey = undefined;
      this.loading = true;
      const request = {
        dn: this.dn,
        keyType: this.keyType
      };
      this.serverKeygenService.serverKeygen(request).subscribe({
        next: async (blob) => {
          // Assume response is multipart: first part is cert, second is private key (PEM or PKCS8)
          const text = await blob.text();
          // Try to split PEM blocks
          const certMatch = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
          const keyMatch = text.match(/-----BEGIN (?:PRIVATE|ENCRYPTED PRIVATE) KEY-----[\s\S]+?-----END (?:PRIVATE|ENCRYPTED PRIVATE) KEY-----/);
          this.certificate = certMatch ? certMatch[0] : undefined;
          this.privateKey = keyMatch ? keyMatch[0] : undefined;
          if (!this.certificate || !this.privateKey) {
            this.error = 'Could not parse certificate or private key from response.';
          }
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Server keygen failed.';
          this.loading = false;
        }
      });
    }
  }
