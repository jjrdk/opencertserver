import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ConfigService } from './config.service';
import { AuthService } from './auth.service';
import { CaCertificate } from '../models/ca-certificate.model';

@Injectable({
  providedIn: 'root'
})
export class CaCertificateService {
  private baseUrl: string;

  constructor(
    private http: HttpClient,
    private configService: ConfigService,
    private authService: AuthService
  ) {
    this.baseUrl = this.configService.getConfig().api.baseUrl;
  }

  private getHeaders(): HttpHeaders | undefined {
    if (this.authService.isAuthenticated && this.authService.isAuthenticated()) {
      const token = this.authService.getAccessToken();
      return new HttpHeaders({
        'Authorization': `Bearer ${token}`
      });
    }
    return undefined;
  }

  /**
   * Fetch CA certificates from the EST endpoint
   * Returns PEM-encoded certificates
   */
  getCaCertificates(): Observable<CaCertificate[]> {
    const url = `${this.baseUrl}/.well-known/est/cacerts`;
    const headers = this.getHeaders();
    const options: any = { responseType: 'arraybuffer' };
    if (headers) {
      options.headers = headers;
    }
    return this.http.get(url, options).pipe(
      map((data: ArrayBuffer | string) => {
        let pemData: string;
        if (typeof data === 'string') {
          pemData = data;
        } else {
          // Convert ArrayBuffer to string (assume UTF-8 PEM)
          pemData = new TextDecoder('utf-8').decode(data);
        }
        return this.parsePemCertificates(pemData);
      })
    );
  }

  /**
   * Parse PEM-encoded certificates and extract certificate information
   */
  private parsePemCertificates(pemData: string): CaCertificate[] {
    const certificates: CaCertificate[] = [];
    const certPattern = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
    const matches = pemData.match(certPattern);

    if (!matches) {
      return certificates;
    }

    matches.forEach((pem, index) => {
      try {
        const certInfo = this.parseCertificateInfo(pem);
        certificates.push({
          ...certInfo,
          pem: pem.trim()
        });
      } catch (error) {
        console.error(`Failed to parse certificate ${index}:`, error);
      }
    });

    return certificates;
  }

  /**
   * Parse certificate information from PEM
   * Note: This is a basic parser. For production, consider using a library like node-forge
   */
  private parseCertificateInfo(pem: string): Omit<CaCertificate, 'pem'> {
    // Extract base64 content
    const base64 = pem
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replace(/\s/g, '');

    // Decode base64 to binary
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    // Basic DER parsing to extract common fields
    // This is simplified - in production use a proper ASN.1 parser
    const certData = this.extractCertificateData(bytes);

    return {
      subject: certData.subject || 'Unknown',
      issuer: certData.issuer || 'Unknown',
      notBefore: certData.notBefore || new Date().toISOString(),
      notAfter: certData.notAfter || new Date().toISOString(),
      serialNumber: certData.serialNumber || 'Unknown',
      thumbprint: certData.thumbprint || 'Unknown'
    };
  }

  /**
   * Basic certificate data extraction
   * For production, use a proper X.509 parsing library
   */
  private extractCertificateData(bytes: Uint8Array): any {
    // This is a placeholder implementation
    // In a real application, use a library like node-forge or @peculiar/x509
    
    // For now, return placeholder data
    // The actual parsing would require proper ASN.1/DER decoding
    return {
      subject: this.extractDNField(bytes, 'CN'),
      issuer: this.extractDNField(bytes, 'CN'),
      serialNumber: this.bytesToHex(bytes.slice(0, 20)),
      notBefore: new Date().toISOString(),
      notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      thumbprint: this.bytesToHex(bytes.slice(0, 20))
    };
  }

  private extractDNField(bytes: Uint8Array, field: string): string {
    // Simplified DN extraction - in production use proper ASN.1 parser
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const cnMatch = text.match(/CN=([^,\n]+)/);
    return cnMatch ? cnMatch[1].trim() : 'CA Certificate';
  }

  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':')
      .toUpperCase();
  }

  /**
   * Download a certificate as a file
   */
  downloadCertificate(certificate: CaCertificate, filename?: string): void {
    const blob = new Blob([certificate.pem], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename || `ca-cert-${certificate.serialNumber}.pem`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }

  /**
   * Download all certificates as a bundle
   */
  downloadAllCertificates(certificates: CaCertificate[]): void {
    const allPems = certificates.map(cert => cert.pem).join('\n\n');
    const blob = new Blob([allPems], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'ca-certificates-bundle.pem';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }
}
