# OpenCertServer Certification Practice Statement

## 1. Introduction

This Certification Practice Statement (CPS) describes the operational practices and procedures followed by the
OpenCertServer Certificate Authority (CA) in the issuance, management, and revocation of digital certificates.
OpenCertServer is a non-commercial, open source CA that issues certificates using the Enrollment Over Secure Transport (
EST, RFC 7030) and Automated Certificate Management Environment (ACME, RFC 8555) protocols. This CPS is intended for use
in community, educational, research, and development environments, and is not suitable for commercial or high-assurance
applications. No legal liability is assumed by the CA, its operators, or contributors.

## 2. CA Environment and Governance

OpenCertServer is operated by a community of volunteers and project maintainers. All operations, policies, and
procedures are developed and maintained transparently, with public documentation and open discussion. The CA does not
operate as a legal entity and does not provide any warranties or guarantees regarding its services or certificates.

## 3. Certificate Application and Issuance

Certificate requests may be submitted via the EST or ACME protocols, or through a web interface. Applicants must provide
accurate information and demonstrate control over the identifiers for which certificates are requested. For ACME, domain
validation is performed as specified in RFC 8555. For EST, identity validation may include email, account, or device
verification. The CA may approve or reject requests at its discretion.

## 4. Certificate Profiles and Usage

Certificates issued by OpenCertServer conform to the X.509 v3 standard. Key usage and extended key usage extensions are
set according to the intended purpose. ACME-issued certificates are restricted to server authentication. All
certificates are for non-commercial use only. Subscribers and relying parties are responsible for ensuring that
certificates are used only for their intended, permitted purposes.

## 5. Key Management

CA private keys are generated and stored securely, with access limited to trusted project maintainers. Subscriber
private keys are generated and protected by the subscriber. The CA does not retain or manage subscriber private keys.
Key lifetimes and cryptographic parameters follow current best practices.

## 6. Certificate Revocation

Certificates may be revoked if the private key is compromised, the certificate is no longer needed, or at the request of
the subscriber. Revocation requests must be authenticated. Revocation status is published via Certificate Revocation
Lists (CRLs) and/or Online Certificate Status Protocol (OCSP) responses.

## 7. Security Controls

The CA employs reasonable technical and procedural controls to protect its systems and private keys. These include
access controls, secure storage, regular updates, and monitoring. The CA encourages community review and reporting of
security issues.

## 8. Audits and Assessments

No formal third-party audits are performed. The CA relies on transparency, public documentation, and community oversight
to ensure compliance with its policies and practices.

## 9. Privacy and Data Protection

The CA collects minimal personal data necessary for certificate issuance and management. Personal data is handled in
accordance with applicable privacy laws and is not shared with third parties except as required for CA operations.
Subscribers are encouraged to use pseudonymous identifiers where appropriate.

## 10. Legal Matters and Disclaimers

OpenCertServer, its operators, and contributors assume no legal liability or responsibility for any damages, losses, or
claims arising from the use or reliance on its certificates or services. All services and documentation are provided "as
is" without warranties of any kind. Use of OpenCertServer certificates is entirely at the user's own risk. Users and
relying parties are solely responsible for determining the suitability of the CA for their needs and for complying with
applicable laws and regulations.

## 11. Amendments and Contact

This CPS may be amended by the project maintainers through public discussion and version control. For questions,
suggestions, or incident reports, please refer to the project repository.

---

This Certification Practice Statement is intended for non-commercial, community, and development use only. No legal
liability is assumed by the CA, its operators, or contributors.
