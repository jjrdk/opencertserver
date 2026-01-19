export interface CaCertificate {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  serialNumber: string;
  thumbprint: string;
  pem: string;
}
