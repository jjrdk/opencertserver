Feature: Batched Intune certificate inventory

    Scenario: A report page loads trusted certificates without per-certificate reads
        Given an Intune report inventory with multiple trusted and untrusted profiles
        When the Intune inventory report is requested
        Then the report includes only trusted devices with bounded store reads
