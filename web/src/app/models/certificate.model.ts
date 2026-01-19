export interface Certificate {
  id: string;
  serialNumber: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  status: 'Valid' | 'Expired' | 'Revoked';
  thumbprint: string;
}
