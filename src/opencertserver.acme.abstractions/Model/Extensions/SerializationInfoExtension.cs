namespace OpenCertServer.Acme.Abstractions.Model.Extensions;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

public static class SerializationInfoExtension
{
    extension(SerializationInfo info)
    {
        public string GetRequiredString(string name)
        {
            if (info is null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var value = info.GetString(name);
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException($"Could not deserialize required value '{name}'");
            }

            return value;
        }

        [return: NotNull]
        public T GetRequiredValue<T>(string name)
        {
            if (info is null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var value = info.GetValue(name, typeof(T));
            if(value is null)
            {
                throw new InvalidOperationException($"Could not deserialize required value '{name}'");
            }

            return (T)value;
        }

        public T? GetValue<T>(string name)
        {
            ArgumentNullException.ThrowIfNull(info);

            return (T?)info.GetValue(name, typeof(T));
        }

        public T? TryGetValue<T>(string name)
        {
            ArgumentNullException.ThrowIfNull(info);

            try
            {
                return (T?)info.GetValue(name, typeof(T));
            }
            catch (SerializationException)
            {
                return default;
            }
        }
    }
}
