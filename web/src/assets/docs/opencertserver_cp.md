# OpenCertServer Certificate Policy Document

## 1. Introduction

### 1.1 Overview

This Certificate Policy (CP) establishes the principles and requirements for the operation of the OpenCertServer
Certificate Authority (CA). OpenCertServer is a non-commercial, open source CA designed to issue and manage digital
certificates in accordance with the Enrollment Over Secure Transport (EST, RFC 7030) and Automated Certificate
Management Environment (ACME, RFC 8555) protocols. The policy is intended to support secure communications,
authentication, and encryption for community, educational, research, and development environments. It is not intended
for commercial or high-assurance production use. The policy aims to foster trust, transparency, and responsible use
within the OpenCertServer community.

### 1.2 Document Name and Identification

This document is titled "OpenCertServer Certificate Policy" and is identified as version 1.0, dated January 17, 2026.
The policy is maintained as part of the OpenCertServer project documentation and is subject to version control and
public review. All changes to this document are tracked and made available to the community.

### 1.3 PKI Participants

The OpenCertServer Public Key Infrastructure (PKI) involves several types of participants:

- The **Certification Authority (CA)** is responsible for issuing, managing, and revoking certificates. The CA operates
  transparently and is governed by the OpenCertServer project maintainers.
- The **Registration Authority (RA)** may be operated by the CA or delegated to trusted community members. The RA is
  responsible for validating the identity of certificate applicants and approving or rejecting certificate requests.
- **Subscribers** are individuals, devices, or entities that request and use certificates issued by the CA. Subscribers
  are expected to use certificates responsibly and in accordance with this policy.
- **Relying Parties** are users, systems, or applications that rely on the validity of certificates issued by the CA.
  Relying parties are encouraged to review this policy and understand its limitations before trusting certificates.

### 1.4 Certificate Usage

Certificates issued by OpenCertServer are intended for non-commercial purposes such as secure communication,
authentication, encryption, and code signing within community, educational, or research settings. Use of certificates
for commercial, unlawful, or malicious activities is strictly prohibited. The CA does not guarantee suitability for any
specific purpose and does not support use in critical infrastructure or high-risk environments. Relying parties should
assess the appropriateness of using OpenCertServer certificates for their intended application.

Certificates issued via the ACME protocol are restricted to server authentication only. These certificates must not be
used for client authentication, code signing, or any other purpose. The CA enforces this restriction through certificate
profiles and key usage extensions, and subscribers are responsible for ensuring compliance with this limitation.

### 1.5 Policy Administration

The OpenCertServer Certificate Policy is administered by the OpenCertServer project maintainers. The policy is developed
and maintained in an open, collaborative manner, with proposed changes discussed publicly and documented in the project
repository. Community feedback is encouraged. The contact point for policy matters is the project repository or
designated email address. All policy changes are versioned and include a changelog for transparency.

## 2. Identification and Authentication

### 2.1 Naming

Certificate subjects are identified by Distinguished Names (DNs) that must be unique within the CA's namespace. The CA
supports the use of pseudonymous names to protect user privacy, provided that such names do not conflict with the
uniqueness requirement. The CA may reject names that are misleading, offensive, or otherwise inappropriate. Subscribers
are responsible for ensuring the accuracy and appropriateness of their requested subject names.

### 2.2 Initial Identity Validation

The CA and/or RA must validate the identity of all certificate applicants before certificate issuance. For individuals,
this typically involves verification of an email address or a community account associated with the OpenCertServer
project. For devices or services, proof of control over the identifier (such as a DNS name or IP address) is required,
which may be demonstrated through DNS-based validation, file-based challenges, or other secure methods. The CA may
require additional information or documentation at its discretion to ensure the legitimacy of requests.

### 2.3 Authentication of Re-key and Revocation Requests

Requests for certificate re-key (renewal) or revocation must be authenticated to prevent unauthorized actions. Re-key
requests may be authenticated using the same process as initial enrollment or by demonstrating possession of the
existing private key. Revocation requests must be accompanied by proof of identity or proof of possession of the private
key corresponding to the certificate. The CA may require additional verification if there is doubt about the legitimacy
of a request.

## 3. Certificate Life-Cycle Operational Requirements

### 3.1 Certificate Application

Certificate applications are submitted via the EST protocol, the ACME protocol, or through a web interface provided by
the CA. Applicants must provide all required information, including the subject DN, a valid public key, and the intended
usage of the certificate. The CA may request additional information to support the validation process. All applications
are subject to review and may be approved or rejected at the discretion of the CA or RA.

### 3.2 Certificate Issuance

Certificates are issued only after successful validation of the applicant's identity and the information provided in the
application. The CA may use automated or manual approval processes depending on the risk profile and the nature of the
request. For ACME protocol requests, the CA performs domain validation as specified in RFC 8555 to confirm the
applicant's control over the requested domain name. Issued certificates are signed by the CA and made available to the
subscriber through secure channels. The CA maintains records of all issued certificates for audit and transparency
purposes.

### 3.3 Certificate Acceptance

Upon issuance, certificates are published to a public repository and/or delivered directly to the subscriber. By
accepting and using the certificate, the subscriber agrees to abide by the terms of this policy and to use the
certificate only for its intended, permitted purposes. Subscribers are responsible for verifying the accuracy of the
certificate and reporting any errors or concerns to the CA promptly.

### 3.4 Certificate Renewal, Re-key, and Update

Certificates may be renewed or re-keyed prior to expiration, subject to successful re-validation of the subscriber's
identity and continued compliance with this policy. The renewal process generally mirrors the initial application
process, with the option to authenticate using the existing private key. Updates to certificate information may require
a new application and validation.

### 3.5 Certificate Revocation and Suspension

Subscribers or authorized parties may request revocation of a certificate if the private key is compromised, the
subscriber's affiliation changes, the certificate is no longer needed, or for other valid reasons. Revocation requests
must be authenticated as described above. The CA will process revocation requests promptly and publish the status of
revoked certificates via Certificate Revocation Lists (CRLs) and/or Online Certificate Status Protocol (OCSP) responses.
The CA does not support certificate suspension; revoked certificates cannot be reinstated.

### 3.6 End of Subscription

A subscription ends when a certificate expires or is revoked. Upon termination, the subscriber has no further rights or
obligations under this policy, except for any continuing responsibilities related to the protection of private keys and
the reporting of security incidents.

## 4. Facility, Management, and Operational Controls

### 4.1 Physical Controls

The CA's private keys and critical systems should be protected by reasonable physical security measures appropriate to
the non-commercial, open source context. This may include secure storage, restricted access, and environmental controls.
While the CA does not operate in a dedicated secure facility, project maintainers are expected to take all reasonable
steps to prevent unauthorized access to sensitive materials.

### 4.2 Procedural Controls

Procedures for key management, certificate issuance, and other critical operations are documented and reviewed by the
project maintainers. Access to sensitive operations is limited to trusted individuals who have demonstrated commitment
to the project's security and integrity. All significant actions are logged and subject to community oversight.

### 4.3 Personnel Controls

Individuals with administrative or RA responsibilities are selected from trusted community members based on their
experience, reputation, and commitment to the project's values. There are no formal background checks, but the community
is encouraged to report concerns about personnel to the project maintainers. Training and awareness resources are
provided as needed to support secure operations.

## 5. Technical Security Controls

### 5.1 Key Pair Generation and Installation

CA key pairs are generated in secure environments using strong cryptographic algorithms and key sizes consistent with
current best practices. Subscriber key pairs may be generated by the subscriber or, if necessary, by the CA and
delivered securely. The CA does not retain copies of subscriber private keys. All key generation processes are
documented and reviewed for security. For ACME protocol certificates, subscribers are responsible for generating and
protecting their private keys in accordance with ACME client best practices.

### 5.2 Private Key Protection and Cryptographic Module Engineering Controls

The CA's private keys are protected by strong passphrases and, where feasible, stored in hardware security modules (
HSMs) or equivalent secure storage. Access to private keys is restricted to authorized personnel. Backup copies are
encrypted and stored securely. The CA periodically reviews its key protection measures to ensure ongoing security.

### 5.3 Other Aspects of Key Pair Management

Key lifetimes, sizes, and usage parameters are set in accordance with industry standards and reviewed periodically. The
CA maintains records of key generation and destruction events. Compromised or obsolete keys are securely destroyed to
prevent misuse.

### 5.4 Activation Data

Activation data such as passphrases or PINs used to protect private keys must be chosen to be strong and kept
confidential. Activation data should not be shared or transmitted insecurely. The CA provides guidance to subscribers on
the creation and protection of activation data.

### 5.5 Computer Security Controls

Systems used to operate the CA are kept up to date with security patches and are monitored for signs of compromise.
Access controls, firewalls, and anti-malware tools are employed as appropriate. The CA maintains an incident response
plan to address security events.

### 5.6 Life Cycle Technical Controls

All software and hardware used by the CA are maintained and updated regularly to address vulnerabilities and improve
security. The CA uses open source tools and encourages community review of its technical controls. Decommissioned
equipment is securely wiped or destroyed.

## 6. Certificate, CRL, and OCSP Profiles

### 6.1 Certificate Profile

Certificates issued by the CA conform to the X.509 version 3 standard. Key usage and extended key usage extensions are
set to reflect the intended purpose of the certificate, such as server authentication, client authentication, or code
signing. Subject Alternative Name (SAN) extensions are supported to allow for multiple identifiers. The CA publishes its
certificate profiles and encourages community feedback on their suitability.

Certificates issued via the ACME protocol include key usage and extended key usage extensions that restrict their use to
server authentication only. These certificates are not valid for client authentication, code signing, or other purposes,
and relying parties should enforce these restrictions.

### 6.2 CRL and OCSP Profile

The CA publishes Certificate Revocation Lists (CRLs) at regular intervals and supports the Online Certificate Status
Protocol (OCSP) if implemented. CRLs and OCSP responses conform to relevant standards and are made available to relying
parties through public repositories or online services. The CA documents the frequency and method of status information
publication.

## 7. Compliance Audit and Other Assessments

The CA does not require formal third-party audits, but encourages community review and transparency in all operations.
All significant actions, incidents, and policy changes are documented and made available for public scrutiny. The CA
welcomes independent assessments and reports of non-compliance or security concerns, which are addressed openly and
collaboratively.

## 8. Other Legal and Policy Matters

### 8.1 Fees

OpenCertServer does not charge any fees for certificate issuance, management, or related services. The project is
operated on a volunteer basis and is funded through community contributions and sponsorships, if any.

### 8.2 Financial Responsibility

The CA and its operators assume no financial liability for any damages or losses resulting from the use or misuse of
certificates. Users and relying parties accept all risks associated with the use of OpenCertServer certificates.

### 8.3 Confidentiality of Business Information

All operations, documentation, and source code are open and transparent. The CA does not maintain confidential business
information. Any sensitive information, such as private keys or activation data, is protected as described in this
policy.

### 8.4 Privacy of Personal Information

The CA collects minimal personal data necessary for certificate issuance and management. Personal information is handled
in accordance with applicable privacy laws and is not shared with third parties except as required for the operation of
the CA. Subscribers are encouraged to use pseudonymous identifiers where appropriate to protect their privacy.

### 8.5 Intellectual Property Rights

All software, documentation, and related materials are provided under the open source license specified by the
OpenCertServer project. Users are free to use, modify, and redistribute these materials in accordance with the license
terms.

### 8.6 Representations and Warranties

The CA provides all services, software, and documentation "as is" without any warranties, express or implied. No
guarantee is made regarding the availability, security, or fitness for a particular purpose of certificates or related
services.

### 8.7 Disclaimers of Liability

To the maximum extent permitted by law, the CA and its contributors disclaim all liability for any damages, losses, or
claims arising from the use or reliance on OpenCertServer certificates or services. Users and relying parties are solely
responsible for assessing the suitability of the CA for their needs.

### 8.8 Dispute Resolution Provisions

Disputes related to the operation of the CA or the interpretation of this policy are resolved through community
discussion and consensus. If necessary, project maintainers may make final decisions. The CA encourages open and
respectful communication in resolving disagreements.

### 8.9 Governing Law

This policy is not governed by any specific jurisdiction, but is instead guided by the principles of open source
collaboration and community governance. Users are responsible for complying with applicable laws in their own
jurisdictions.

---

This Certificate Policy is intended for non-commercial, community, and development use only. For questions or
suggestions, please refer to the project repository.
