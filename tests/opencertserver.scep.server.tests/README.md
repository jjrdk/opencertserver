# SCEP Server tests


## Storage backends

Every scenario is a Scenario Outline that starts with
`Given the certificate server storage is "<Storage>"` and runs against `in-memory`,
`postgresql` and `mssql`. The relational backends start Testcontainers databases
(`tests/Shared/RelationalTestDatabase.cs`), so Docker must be running.
