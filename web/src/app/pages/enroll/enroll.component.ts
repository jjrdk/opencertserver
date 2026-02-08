import { Component } from '@angular/core';
import { EnrollService } from '../../services/enroll.service';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

@Component({
    selector: 'app-enroll',
    templateUrl: './enroll.component.html',
    styleUrls: ['./enroll.component.scss'],
    standalone: false
})
export class EnrollComponent {
  dn = {
    cn: '',
    o: '',
    ou: '',
    c: '',
    st: '',
    l: ''
  };
  keyType: 'RSA' | 'EC' = 'RSA';
  privateKey?: CryptoKey;
  publicKey?: CryptoKey;
  certificate?: string;
  error?: string;
  loading = false;

  constructor(private enrollService: EnrollService) {}

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

  async onSubmit(form: any) {
    this.error = undefined;
    this.certificate = undefined;
    this.loading = true;
    try {
      await this.generateKeyPair();
      const csr = await this.createCsr();
      this.enrollService.enroll(csr).subscribe({
        next: async (blob) => {
          this.certificate = await blob.text();
          this.loading = false;
        },
        error: (err) => {
          this.error = 'Enrollment failed.';
          this.loading = false;
        }
      });
    } catch (e) {
      this.error = (e as Error).message;
      this.loading = false;
    }
  }

  async generateKeyPair() {
    if (this.keyType === 'RSA') {
      const keyPair = await window.crypto.subtle.generateKey({
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      }, true, ['sign', 'verify']);
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    } else {
      const keyPair = await window.crypto.subtle.generateKey({
        name: 'ECDSA',
        namedCurve: 'P-256'
      }, true, ['sign', 'verify']);
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;
    }
  }

  async createCsr(): Promise<ArrayBuffer> {
    // Prepare subject string
    const dnParts = [];
    if (this.dn.cn) dnParts.push(`CN=${this.dn.cn}`);
    if (this.dn.o) dnParts.push(`O=${this.dn.o}`);
    if (this.dn.ou) dnParts.push(`OU=${this.dn.ou}`);
    if (this.dn.c) dnParts.push(`C=${this.dn.c}`);
    if (this.dn.st) dnParts.push(`ST=${this.dn.st}`);
    if (this.dn.l) dnParts.push(`L=${this.dn.l}`);
    const subject = dnParts.join(',');

    // PKIjs expects a crypto engine
    pkijs.setEngine('webcrypto', window.crypto, window.crypto.subtle);

    // Build subject as pkijs RelativeDistinguishedNames
    // OIDs for DN fields
    const oidMap: Record<string, string> = {
      CN: '2.5.4.3',
      O: '2.5.4.10',
      OU: '2.5.4.11',
      C: '2.5.4.6',
      ST: '2.5.4.8',
      L: '2.5.4.7'
    };
    const rdn = new pkijs.RelativeDistinguishedNames({
      typesAndValues: dnParts.map(part => {
        const [type, value] = part.split('=');
        return new pkijs.AttributeTypeAndValue({
          type: oidMap[type] || type,
          value: new asn1js.PrintableString({ value })
        });
      })
    });

    // Build CSR
    const csr = new pkijs.CertificationRequest();
    csr.subject = rdn;
    await csr.subjectPublicKeyInfo.importKey(this.publicKey!);
    await csr.sign(this.privateKey!, 'SHA-256');
    return csr.toSchema().toBER(false);
  }
}
