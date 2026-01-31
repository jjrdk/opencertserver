import { Component, OnInit } from '@angular/core';
import { CsrAttributesService } from '../../services/csr-attributes.service';
import * as asn1js from 'asn1js';

@Component({
  selector: 'app-csr-attributes',
  templateUrl: './csr-attributes.component.html',
  styleUrls: ['./csr-attributes.component.scss']
})
export class CsrAttributesComponent implements OnInit {
  derData?: ArrayBuffer;
  decoded?: any;
  error?: string;
  loading = false;

  constructor(private csrAttributesService: CsrAttributesService) { }

  ngOnInit(): void {
    this.fetchCsrAttributes();
  }

  fetchCsrAttributes() {
    this.loading = true;
    this.csrAttributesService.getCsrAttributes().subscribe({
      next: (data) => {
        this.derData = data;
        this.decodeDer(data);
        this.loading = false;
      },
      error: (err) => {
        this.error = 'Failed to fetch CSR attributes.';
        this.loading = false;
      }
    });
  }

  decodeDer(der: ArrayBuffer) {
    try {
      const asn1 = asn1js.fromBER(der);
      if (asn1.offset === -1) {
        this.error = 'Failed to decode DER.';
        return;
      }
      this.decoded = this.parseCsrTemplate(asn1.result);
    } catch (e) {
      this.error = 'Error decoding DER: ' + (e as Error).message;
    }
  }

  // Parse the ASN.1 structure to a user-friendly object
  parseCsrTemplate(asn1: any): any {
    // This is a simplified parser for demonstration. Real parsing should match the CSR template structure.
    if (!asn1.valueBlock || !asn1.valueBlock.value) return null;
    const seq = asn1.valueBlock.value;
    const version = seq[0]?.valueBlock?.valueDec;
    // Subject and SubjectPublicKeyInfo are optional, so check existence
    const subject = seq[1] ? this.parseSubject(seq[1]) : undefined;
    const subjectPkInfo = seq[2] ? this.parseSubjectPkInfo(seq[2]) : undefined;
    return { version, subject, subjectPkInfo };
  }

  parseSubject(subjectAsn1: any): any {
    // This is a placeholder. Real implementation should parse the NameTemplate structure.
    return { raw: subjectAsn1.toString() };
  }

  parseSubjectPkInfo(pkInfoAsn1: any): any {
    // This is a placeholder. Real implementation should parse the SubjectPublicKeyInfoTemplate structure.
    return { raw: pkInfoAsn1.toString() };
  }
}
