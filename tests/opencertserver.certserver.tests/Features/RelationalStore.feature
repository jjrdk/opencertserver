Feature: Relational store service integration
    The application services must use PostgreSQL- and MSSQL-backed ACME and CA stores across service-provider reloads.

    Scenario Outline: ACME issuance and CA revocation survive a relational provider reload
        Given a relational test server using the <Database> provider
        When an ACME client registers an account and places an order
        And the relational service provider is rebuilt
        Then the ACME request resolves the same account and order
        When the CA service revokes the issued certificate
        Then the CRL contains the revoked certificate

        Examples:
          | Database   |
          | PostgreSQL |
          | MSSQL      |
