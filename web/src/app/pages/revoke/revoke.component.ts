import { Component } from '@angular/core';
import { RevocationService } from '../../services/revocation.service';
import { RevocationReason } from '../../models/revocation.model';

@Component({
    selector: 'app-revoke',
    templateUrl: './revoke.component.html',
    styleUrls: ['./revoke.component.scss'],
    standalone: false
})
export class RevokeComponent {
  serialNumber: string = '';
  revocationReason: RevocationReason = RevocationReason.Unspecified;
  privateKeyPem: string = '';
  uploadedFileName: string = '';
  loading: boolean = false;
  error: string | null = null;
  success: boolean = false;

  constructor(private revocationService: RevocationService) {}

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      const file = input.files[0];
      this.uploadedFileName = file.name;
      
      const reader = new FileReader();
      reader.onload = (e) => {
        this.privateKeyPem = e.target?.result as string;
      };
      reader.readAsText(file);
    }
  }

  async onSubmit(): Promise<void> {
    this.error = null;
    this.success = false;
    this.loading = true;

    try {
      // Import the private key
      const privateKey = await this.revocationService.importPrivateKey(this.privateKeyPem);

      // Sign the revocation request
      const signature = await this.revocationService.signRevocationRequest(
        this.serialNumber,
        this.revocationReason,
        privateKey
      );

      // Submit the revocation request
      await this.revocationService.revokeCertificate(
        this.serialNumber,
        this.revocationReason,
        signature
      ).toPromise();

      this.success = true;
      this.serialNumber = '';
      this.revocationReason = RevocationReason.Unspecified;
      this.privateKeyPem = '';
      this.uploadedFileName = '';
    } catch (err: any) {
      console.error('Error revoking certificate:', err);
      
      if (err.status === 401) {
        this.error = 'Unauthorized: Invalid signature or authentication failed.';
      } else if (err.status === 404) {
        this.error = 'Certificate not found with the specified serial number.';
      } else if (err.status === 400) {
        this.error = 'Bad request: Please check the serial number and reason.';
      } else if (err.message?.includes('importKey')) {
        this.error = 'Invalid private key format. Please provide a valid PEM-encoded private key.';
      } else {
        this.error = 'Failed to revoke certificate. Please try again.';
      }
    } finally {
      this.loading = false;
    }
  }

  onReset(): void {
    this.serialNumber = '';
    this.revocationReason = RevocationReason.Unspecified;
    this.privateKeyPem = '';
    this.uploadedFileName = '';
    this.error = null;
    this.success = false;
  }
}
