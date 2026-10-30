@profile-bound-renewal
Feature: Re-enrollment is bound to the issuing profile
    A shared CA key does not authorize a holder to move between certificate profiles.

    Scenario Outline: Stored certificates can only renew within their resolved issuing profile
        Given EST profiles sharing one issuer with "<permissions>" permissions
        When a certificate from "<source>" with "present" issuance records is renewed through "<target>" using "<transport>"
        Then profile-bound renewal is "<outcome>"

        Examples:
          | permissions | source     | target     | transport | outcome  |
          | different   | vpn-user   | vpn-server | EST       | refused  |
          | different   | vpn-server | vpn-user   | EST       | refused  |
          | different   | vpn-user   | default    | EST       | refused  |
          | different   | vpn-user   | vpn-user   | EST       | accepted |
          | different   | vpn-server | default    | EST       | accepted |
          | identical   | vpn-user   | vpn-server | EST       | refused  |
          | different   | vpn-user   | vpn-server | CA        | refused  |
          | different   | vpn-user   | default    | CA        | refused  |
          | different   | vpn-server | default    | CA        | accepted |
          | different   | default    | vpn-server | EST       | accepted |
          | different   | default    | vpn-server | CA        | accepted |

    Scenario Outline: Missing issuance provenance cannot authorize renewal
        Given EST profiles sharing one issuer with "different" permissions
        When a certificate from "<source>" with "missing" issuance records is renewed through "<target>" using "<transport>"
        Then profile-bound renewal is "refused"

        Examples:
          | source     | target     | transport |
          | vpn-user   | vpn-server | EST       |
          | vpn-user   | vpn-user   | EST       |
          | vpn-server | default    | EST       |
          | vpn-user   | vpn-user   | CA        |

    Scenario: Revocation still prevents renewal within a profile
        Given EST profiles sharing one issuer with "different" permissions
        When a certificate from "vpn-user" with "revoked" issuance records is renewed through "vpn-user" using "EST"
        Then profile-bound renewal is "revoked"

    Scenario Outline: An imported certificate without a profile cannot renew
        Given EST profiles sharing one issuer with "different" permissions
        When a certificate from "vpn-user" with "imported" issuance records is renewed through "vpn-user" using "<transport>"
        Then profile-bound renewal is "refused"

        Examples:
          | transport |
          | EST       |
          | CA        |

    Scenario Outline: A serial number cannot substitute for exact certificate provenance
        Given EST profiles sharing one issuer with "different" permissions
        When a certificate from "vpn-user" with "collision" issuance records is renewed through "vpn-user" using "<transport>"
        Then profile-bound renewal is "refused"

        Examples:
          | transport |
          | EST       |
          | CA        |

    Scenario Outline: Existing custom stores keep issuance but fail closed on renewal
        Given EST profiles sharing one issuer with "legacy store" permissions
        When a certificate from "vpn-user" with "present" issuance records is renewed through "vpn-user" using "<transport>"
        Then profile-bound renewal is "refused"

        Examples:
          | transport |
          | EST       |
          | CA        |
