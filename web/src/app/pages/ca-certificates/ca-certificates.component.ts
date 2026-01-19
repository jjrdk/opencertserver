import { Component, OnInit } from '@angular/core';
import { CaCertificateService } from '../../services/ca-certificate.service';
import { CaCertificate } from '../../models/ca-certificate.model';

@Component({
  selector: 'app-ca-certificates',
  templateUrl: './ca-certificates.component.html',
  styleUrls: ['./ca-certificates.component.scss']
})
export class CaCertificatesComponent implements OnInit {
  certificates: CaCertificate[] = [];
  loading: boolean = true;
  error: string | null = null;

  constructor(private caCertService: CaCertificateService) {}

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.loading = true;
    this.error = null;

    this.caCertService.getCaCertificates().subscribe({
      next: (certs) => {
        this.certificates = certs;
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading CA certificates:', err);
        this.error = 'Failed to load CA certificates. Please try again later.';
        this.loading = false;
      }
    });
  }

  refresh(): void {
    this.loadCertificates();
  }

  downloadCertificate(certificate: CaCertificate, index: number): void {
    this.caCertService.downloadCertificate(certificate, `ca-certificate-${index + 1}.pem`);
  }

  downloadAll(): void {
    this.caCertService.downloadAllCertificates(this.certificates);
  }

  copyToClipboard(text: string): void {
    navigator.clipboard.writeText(text).then(
      () => {
        // Could show a snackbar notification here
        console.log('Certificate copied to clipboard');
      },
      (err) => {
        console.error('Failed to copy certificate:', err);
      }
    );
  }
}
