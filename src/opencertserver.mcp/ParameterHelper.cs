namespace OpenCertServer.Mcp;

using System.Text.Json;

/// <summary>
/// Helper methods for extracting and converting parameters from JsonElement objects.
/// </summary>
internal static class ParameterHelper
{
    /// <summary>
    /// Safely extracts an integer parameter from a dictionary that may contain JsonElement values.
    /// </summary>
    public static int GetInt32(object? value, int defaultValue = 0)
    {
        if (value == null) return defaultValue;

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var intValue))
                return intValue;
            if (element.ValueKind == JsonValueKind.String && int.TryParse(element.GetString(), out var parsedValue))
                return parsedValue;
        }
        else if (value is int i)
        {
            return i;
        }
        else if (value is string s && int.TryParse(s, out var parsedValue))
        {
            return parsedValue;
        }

        try
        {
            return Convert.ToInt32(value);
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Safely extracts a boolean parameter from a dictionary that may contain JsonElement values.
    /// </summary>
    public static bool GetBoolean(object? value, bool defaultValue = false)
    {
        if (value == null) return defaultValue;

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.True) return true;
            if (element.ValueKind == JsonValueKind.False) return false;
            if (element.ValueKind == JsonValueKind.String && bool.TryParse(element.GetString(), out var parsedValue))
                return parsedValue;
        }
        else if (value is bool b)
        {
            return b;
        }
        else if (value is string s && bool.TryParse(s, out var parsedValue))
        {
            return parsedValue;
        }

        try
        {
            return Convert.ToBoolean(value);
        }
        catch
        {
            return defaultValue;
        }
    }

    /// <summary>
    /// Safely extracts a string array parameter from a dictionary that may contain JsonElement values.
    /// </summary>
    public static string[]? GetStringArray(object? value)
    {
        if (value == null) return null;

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                var list = new List<string>();
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                        list.Add(item.GetString()!);
                }
                return list.ToArray();
            }
            if (element.ValueKind == JsonValueKind.String)
            {
                // Fallback: treat as comma-separated string
                return element.GetString()?.Split(',', StringSplitOptions.TrimEntries);
            }
        }
        else if (value is string[] arr)
        {
            return arr;
        }
        else if (value is IEnumerable<string> enumerable)
        {
            return enumerable.ToArray();
        }
        else if (value is string s)
        {
            return s.Split(',', StringSplitOptions.TrimEntries);
        }

        return null;
    }

    /// <summary>
    /// Safely extracts an object array parameter from a dictionary that may contain JsonElement values.
    /// </summary>
    public static IEnumerable<object>? GetObjectArray(object? value)
    {
        if (value == null) return null;

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                var list = new List<object>();
                foreach (var item in element.EnumerateArray())
                {
                    list.Add(item);
                }
                return list;
            }
        }
        else if (value is IEnumerable<object> enumerable)
        {
            return enumerable;
        }

        return null;
    }

    /// <summary>
    /// Validates that a string is a valid hexadecimal string.
    /// </summary>
    public static bool IsValidHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        
        foreach (var c in value)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }

    /// <summary>
    /// Safely converts a hex string to bytes, with validation.
    /// </summary>
    public static byte[]? HexToBytes(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return null;
        if (!IsValidHex(hex)) return null;

        try
        {
            // Pad with leading zero if odd length
            var normalized = hex.Length % 2 == 0 ? hex : "0" + hex;
            return Convert.FromHexString(normalized);
        }
        catch
        {
            return null;
        }
    }
}
