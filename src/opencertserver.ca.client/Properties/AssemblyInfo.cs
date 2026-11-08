using System.Runtime.CompilerServices;

// The CA-client "trusted connection" pinning is exercised by the certserver test suite, which
// verifies that a server certificate not chaining to a pinned anchor is rejected.
[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]
