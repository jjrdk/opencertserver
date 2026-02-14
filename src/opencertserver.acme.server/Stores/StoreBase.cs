using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Server.Stores;

using System.Text;
using System.Text.RegularExpressions;
using Abstractions.Model;
using Configuration;
using Microsoft.Extensions.Options;

public partial class StoreBase
{
    protected IOptions<FileStoreOptions> Options { get; }

    protected StoreBase(IOptions<FileStoreOptions> options)
    {
        Options = options;
    }

    protected static async Task<T?> LoadFromPath<T>(string filePath, CancellationToken cancellationToken)
        where T : class
    {
        if (!File.Exists(filePath))
        {
            return null;
        }

        await using var fileStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return await LoadFromStream<T>(fileStream, cancellationToken);
    }

    protected static async Task<T?> LoadFromStream<T>(FileStream fileStream, CancellationToken cancellationToken)
        where T : class
    {
        if (fileStream.Length == 0)
        {
            return null;
        }

        fileStream.Seek(0, SeekOrigin.Begin);

        var utf8Bytes = new byte[fileStream.Length];
        _ = await fileStream.ReadAsync(utf8Bytes, cancellationToken);
        var result =
            JsonSerializer.Deserialize<T>(utf8Bytes.AsSpan(),
                (JsonTypeInfo<T>)AcmeSerializerContext.Default.GetTypeInfo(typeof(T))!);

        return result;
    }

    protected static async Task ReplaceFileStreamContent<T>(
        FileStream fileStream,
        T content,
        CancellationToken cancellationToken)
    {
        if (fileStream.Length > 0)
        {
            fileStream.SetLength(0);
        }

        var utf8Bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(content,
            (JsonTypeInfo<T>)AcmeSerializerContext.Default.GetTypeInfo(typeof(T))!));
        await fileStream.WriteAsync(utf8Bytes, cancellationToken);
    }

    protected static void HandleVersioning(IVersioned? existingContent, IVersioned newContent)
    {
        if (existingContent != null && existingContent.Version != newContent.Version)
        {
            throw new ConcurrencyException();
        }

        newContent.Version = DateTime.UtcNow.Ticks;
    }

    [GeneratedRegex(@"[\w\d_-]+", RegexOptions.Compiled)]
    protected static partial Regex IdentifierRegex();
}
