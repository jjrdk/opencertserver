import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ConfigService } from './config.service';
import { AuthService } from './auth.service';
import { RevocationReason } from '../models/revocation.model';

@Injectable({
  providedIn: 'root'
})
export class RevocationService {
  private baseUrl: string;

  constructor(
    private http: HttpClient,
    private configService: ConfigService,
    private authService: AuthService
  ) {
    this.baseUrl = this.configService.getConfig().api.baseUrl;
  }

  private getHeaders(): HttpHeaders {
    const token = this.authService.getAccessToken();
    return new HttpHeaders({
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    });
  }

  /**
   * Sign the revocation request data
   * @param serialNumber The certificate serial number
   * @param reason The revocation reason
   * @param privateKey The private key for signing (PEM format)
   * @returns Base64-encoded signature
   */
  async signRevocationRequest(
    serialNumber: string,
    reason: RevocationReason,
    privateKey: CryptoKey
  ): Promise<string> {
    const encoder = new TextEncoder();
    const reasonString = RevocationReason[reason];
    const data = encoder.encode(serialNumber + reasonString);

    const signature = await crypto.subtle.sign(
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: 'SHA-256' }
      },
      privateKey,
      data
    );

    return this.arrayBufferToBase64(signature);
  }

  /**
   * Revoke a certificate
   * @param serialNumber The certificate serial number
   * @param reason The revocation reason
   * @param signature The base64-encoded signature
   * @returns Observable that completes when revocation is successful
   */
  revokeCertificate(
    serialNumber: string,
    reason: RevocationReason,
    signature: string
  ): Observable<void> {
    const reasonString = RevocationReason[reason];
    const url = `${this.baseUrl}/ca/revoke?sn=${encodeURIComponent(serialNumber)}&reason=${encodeURIComponent(reasonString)}&signature=${encodeURIComponent(signature)}`;

    return this.http.delete<void>(url, {
      headers: this.getHeaders()
    });
  }

  /**
   * Import a private key from PEM format
   * @param pemKey The PEM-formatted private key
   * @returns CryptoKey for signing
   */
  async importPrivateKey(pemKey: string): Promise<CryptoKey> {
    // Remove PEM header/footer and whitespace
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = pemKey
      .replace(pemHeader, '')
      .replace(pemFooter, '')
      .replace(/\s/g, '');

    // Decode base64
    const binaryDer = this.base64ToArrayBuffer(pemContents);

    // Import the key
    return await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
