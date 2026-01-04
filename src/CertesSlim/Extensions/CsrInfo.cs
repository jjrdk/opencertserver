namespace CertesSlim.Extensions;

/// <summary>
/// Represents common information for CSR.
/// </summary>
public class CsrInfo
{
    private readonly Dictionary<string, string> _data = new();

    /// <summary>
    /// Gets or sets the two-letter ISO abbreviation for your country.
    /// </summary>
    /// <value>
    /// The two-letter ISO abbreviation for your country.
    /// </value>
    public string? CountryName
    {
        get => _data.GetValueOrDefault("C");
        set => _data["C"] = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the state or province where your organization is located. Can not be abbreviated.
    /// </summary>
    /// <value>
    /// The state or province where your organization is located. Can not be abbreviated.
    /// </value>
    public string? State
    {
        get => _data.GetValueOrDefault("ST");
        set => _data["ST"] = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the city where your organization is located.
    /// </summary>
    /// <value>
    /// The city where your organization is located.
    /// </value>
    public string? Locality
    {
        get => _data.GetValueOrDefault("L");
        set => _data["L"] = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the exact legal name of your organization. Do not abbreviate.
    /// </summary>
    /// <value>
    /// The exact legal name of your organization. Do not abbreviate.
    /// </value>
    public string? Organization
    {
        get => _data.GetValueOrDefault("O");
        set => _data["O"] = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the optional organizational information.
    /// </summary>
    /// <value>
    /// The optional organizational information.
    /// </value>
    public string? OrganizationUnit
    {
        get => _data.GetValueOrDefault("OU");
        set => _data["OU"] = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the common name for the CSR.
    /// If not set, the first identifier of the ACME order will be chosen as common name.
    /// </summary>
    /// <value>
    /// The common name for the CSR.
    /// </value>
    public string? CommonName
    {
        get => _data.GetValueOrDefault("CN");
        set => _data["CN"] = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets all the fields with value.
    /// </summary>
    /// <value>
    /// All fields.
    /// </value>
    internal IEnumerable<(string name, string value)> Fields
    {
        get => _data.Select(p => (p.Key, p.Value));
    }
}
