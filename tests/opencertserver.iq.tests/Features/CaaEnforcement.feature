@iq @blackbox @linux-client @hardened
Feature: CAA enforcement (RFC 8659 / RFC 8657) is observable through the ACME path
  CAA decides which CA may issue for a domain. On a hardened install CAA is enforced
  *fail-closed*: an order is refused when the domain's applicable CAA issue records do
  not authorize this CA. An absent CAA RRset does not restrict issuance (RFC 8659).
  These scenarios observe that decision the way a Linux client would - by watching
  the outcome of a real issuance attempt (or `acme.sh` run), not by reaching into the
  CAA validator directly.

  They complement the CAA conformance suite; the new assertion is the *end-to-end
  outcome a Linux client sees*: an issuance attempt is blocked by, or accepted by, CAA.

  Rule: CAA enforcement is fail-closed by default
  Scenario: An issuance attempt is refused when CAA does not include this CA
    Given a hardened OpenCertServer has CAA enforcement enabled with "AcmeServer:CAAIdentities" set
    And the domain "unprotected.example.com" has no CAA RRset that names this CA
    When the Linux client attempts to issue "unprotected.example.com" via "acme.sh"
    Then the order fails
    And the failure is a CAA error ("caa" type in the ACME challenge problem)

  Scenario: An issuance attempt succeeds when CAA includes this CA
    Given a hardened OpenCertServer has CAA enforcement enabled
    And the domain "protected.example.com" has a CAA RRset that names this CA
    When the Linux client attempts to issue "protected.example.com" via "acme.sh"
    Then the order succeeds and the issued certificate chains to the CA

  Rule: The opt-out is explicit and observable
  @caa-disabled
  Scenario: With DisableCaaChecks, a CAA-less domain is still issued
    Given a hardened OpenCertServer with "AcmeServer:DisableCaaChecks" set to true
    And the domain "lab.example.com" has no CAA RRset
    When the Linux client attempts to issue "lab.example.com" via "acme.sh"
    Then the order succeeds
