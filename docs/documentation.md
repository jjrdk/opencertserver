# OpenCertServer Documentation

## Endpoints

OpenCertServer provides a variety of endpoints for managing certificates, including Certificate Authority (CA)
operations, enrollment processes, and ACME protocol support.

Below is a detailed description of each endpoint.

### Certificate Authority (CA) Endpoints

- **GET /ca/crl**
    - Description: Retrieve the current Certificate Revocation List (CRL).
    - Response: Returns the CRL in PEM format.
- **POST /ca/revoke**
    - Description: Revoke a certificate.
    - Request Query Parameters:
        - `sn` (base64 string, required): The serial number of the certificate to be revoked.
        - `reason` (string, required): The reason for revocation (e.g., "keyCompromise", "cessationOfOperation").
        - `signature` (base64 string, required): A digital signature to authenticate the revocation request. The
          signature must be from the private key corresponding to the certificate being revoked.
    - Response: Status code `200` as confirmation of revocation.
- **GET /ca/inventory**
    - Description: Retrieve the inventory of issued certificates.
    - Response: Returns a JSON array of issued certificates with their details.
- **GET /ca/certificate**
    - Description: Retrieve a specific issued certificate.
    - Request Query Parameters:
        - `id` (hex-string, optional) (multiple allowed): The serial number of the certificate to retrieve.
        - `thumbprint` (string, optional) (multiple allowed): The thumbprint of the certificate to retrieve.
    - Response: Returns the requested certificate(s) in PEM format.

### Enrollment Endpoints

- **POST /.well-known/est/simpleenroll**
    - Description: Enroll for a new certificate.
    - Request Body: A PKCS#10 Certificate Signing Request (CSR) in PEM format.
    - Request Headers:
        - `Content-Type`: `application/pkcs10`
        - `Accept`: `application/pkcs7-mime`
    - Response: Returns the issued certificate in PKCS#7 format.
    - Notes: The request must be authenticated using an OIDC token.
    - Additional Information: For more details on the enrollment process, refer to
      the [EST Protocol Documentation](https://tools.ietf.org/html/rfc7030).
- **POST /.well-known/est/simplereenroll**
    - Description: Re-enroll for a new certificate using an existing certificate.
    - Response: Returns the issued certificate in PKCS#7 format.
    - Notes: The request must be authenticated using the certificate to re-enroll.
    - Additional Information: For more details on the re-enrollment process, refer to
      the [EST Protocol Documentation](https://tools.ietf.org/html/rfc7030).
    - Requirements: The existing certificate used for authentication must be valid and not revoked.
- **GET /.well-known/est/cacerts**
    - Description: Retrieve the CA certificates.
    - Response: Returns the CA certificates in PEM format.
    - Additional Information: For more details on the CA certificates retrieval process, refer to
      the [EST Protocol Documentation](https://tools.ietf.org/html/rfc7030).
    - Notes: This endpoint does not require authentication.
- **GET /.well-known/est/serverkeygen**
    - Description: Generate a key pair on the server and enroll for a certificate.
    - Response: Returns the issued certificate in PKCS#7 format with the generated along with the generated private key
      in PEM format.
    - Notes: The request must be authenticated using an OIDC token.
    - Additional Information: For more details on the server key generation process, refer to
      the [EST Protocol Documentation](https://tools.ietf.org/html/rfc7030).
- **GET /.well-known/est/csrattrs**
    - Description: Retrieve the CSR attributes.
    - Response: Returns a PKCS#10 CSR attributes structure in DER format.
    - Additional Information: The CSR attributes help clients understand what attributes are required for enrollment.
      For more details on the CSR attributes retrieval process, refer to
      the [EST Protocol Documentation](https://tools.ietf.org/html/rfc7030).
    - Notes: The request must be authenticated using an OIDC token. The CSR attributes may vary based on the client's
      authentication context.

### ACME Endpoints

- **POST /acme/new-order**
    - Description: Create a new ACME order for certificate issuance.
    - Request Body: A JSON object containing the order details.
    - Response: Returns a JSON object with the order status and details.
    - Additional Information: For more details on the ACME order process, refer to
      the [ACME Protocol Documentation](https://tools.ietf.org/html/rfc8555).
- **POST /acme/finalize/{orderId}**
    - Description: Finalize an ACME order by submitting a CSR.
    - Path Parameters:
        - `orderId` (string, required): The ID of the order to finalize.
    - Request Body: A PKCS#10 Certificate Signing Request (CSR) in PEM format.
    - Response: Returns the issued certificate in PEM format.
    - Additional Information: For more details on the ACME order finalization process, refer to
      the [ACME Protocol Documentation](https://tools.ietf.org/html/rfc8555).
- **GET /acme/certificate/{orderId}**
    - Description: Retrieve the issued certificate for a completed ACME order.
    - Path Parameters:
        - `orderId` (string, required): The ID of the order for which to retrieve the certificate.
    - Response: Returns the issued certificate in PEM format.
    - Additional Information: For more details on the ACME certificate retrieval process, refer to
      the [ACME Protocol Documentation](https://tools.ietf.org/html/rfc8555).
    - Notes: The order must be in a completed state to retrieve the certificate.

## Authentication

OpenCertServer supports multiple authentication methods for securing its endpoints:

- **OIDC Tokens**
    - Used for authenticating enrollment requests.
    - Tokens must be included in the `Authorization` header as a Bearer token.
    - Example: `Authorization: Bearer <token>`
- **Client Certificates**
    - Used for authenticating re-enrollment requests.
    - The client must present a valid certificate during the TLS handshake.

## Storage Backends

OpenCertServer defines interfaces for various storage backends to manage certificates, keys, and related data.

No backend implementations are provided by default; users must implement these interfaces according to their storage
solutions.
