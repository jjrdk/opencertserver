# Data Use and Privacy

This page explains how OpenCertServer handles certificate data and login information.

## Certificate Data Processing

- When you create or request certificates, the server stores the certificate data required to issue and manage the certificate (for example: subject fields, public keys, validity periods and revocation status).
- Certificate signing requests (CSRs) and issued certificates are stored to allow certificate lifecycle operations such as renewal and revocation.
- Revocation and audit information is retained to support the integrity of the certificate system and to allow administrators to respond to security incidents.
- Stored certificate data is only used for certificate management and operational purposes related to providing the CA functionality.

## Login Data

- Login credentials and authentication-related metadata (such as session identifiers and timestamps) are stored to enable access control and to provide a secure administrative experience.
- Login data **is not used** for commercial purposes, profiling, or analytics.
- Authentication logs are retained only for operational, debugging, and security incident investigation purposes.

## No Commercial Use or Analytics

We do not use login information for any commercial purposes, advertising, or analytics. The data collected for authentication and certificate management is used solely to operate and secure the OpenCertServer application.

## Questions

If you have questions about how your data is handled, contact the project maintainers or check the repository for more details.
