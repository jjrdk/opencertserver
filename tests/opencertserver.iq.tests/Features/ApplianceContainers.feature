@iq @blackbox @appliance
Feature: Chiseled appliance containers are hardened and serve their role
  Each appliance role (Unified, CA, RA) ships as a chiseled Ubuntu 24.04 image that
  bundles a self-contained server on the runtime-deps glibc base. These scenarios boot
  one image per role and assert the hardened posture that a deployment depends on:
  an unprivileged process, TLS 1.3 only, no Server header, a healthy endpoint, and a
  role-appropriate surface. A final scenario proves the HTTPS-only startup guard that
  a hardened appliance enforces.

  Rule: The Unified role serves every protocol and is hardened
  Scenario: The Unified appliance is unprivileged, TLS-1.3-only and healthy
    Given the "Unified" appliance is deployed as a chiseled Ubuntu 24.04 image
    Then the image and the running process run as the unprivileged user "1654"
    And a "TLS 1.3" handshake completes
    And a "TLS 1.2" handshake is rejected
    And the server omits the "Server" response header
    And the health endpoint reports a healthy server
    And the Unified role exposes the EST, ACME, CA and SCEP endpoints
    And the Unified role hides the RA endpoints

  Rule: The CA role serves only the CA responder
  Scenario: The CA appliance is hardened and CA-only
    Given the "Ca" appliance is deployed as a chiseled Ubuntu 24.04 image
    Then the image and the running process run as the unprivileged user "1654"
    And a "TLS 1.3" handshake completes
    And a "TLS 1.2" handshake is rejected
    And the server omits the "Server" response header
    And the health endpoint reports a healthy server
    And the CA role exposes the CA responder
    And the CA role hides the EST, ACME and SCEP endpoints

  Rule: The RA role serves only the RA responder
  Scenario: The RA appliance is hardened and RA-only
    Given the "Ra" appliance is deployed as a chiseled Ubuntu 24.04 image
    Then the image and the running process run as the unprivileged user "1654"
    And a "TLS 1.3" handshake completes
    And a "TLS 1.2" handshake is rejected
    And the server omits the "Server" response header
    And the health endpoint reports a healthy server
    And the RA role exposes the RA endpoints
    And the RA role hides the EST, ACME, CA and SCEP endpoints

  Rule: A hardened appliance is HTTPS-only
  Scenario: A hardened appliance refuses a plain-HTTP listener
    Given a hardened appliance is started with a plain-HTTP Kestrel endpoint
    Then the appliance refuses to start because a hardened appliance permits only HTTPS listeners
