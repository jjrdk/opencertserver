namespace OpenCertServer.Acme.Abstractions.Model
{
    using System;
    using System.Linq;
    using System.Runtime.Serialization;
    using Exceptions;
    using Extensions;

    [Serializable]
    public sealed class Identifier : ISerializable
    {
        private static readonly string[] SupportedTypes = { "dns" };

        private string _type = null!;
        private string _value = null!;

        public Identifier(string type, string value)
        {
            Type = type;
            Value = value;
        }

        public string Type
        {
            get { return _type; }
            set
            {
                var normalizedType = value.Trim().ToLowerInvariant();
                if (!SupportedTypes.Contains(normalizedType))
                {
                    throw new MalformedRequestException($"Unsupported identifier type: {normalizedType}");
                }

                _type = normalizedType;
            }
        }

        public string Value
        {
            get { return _value; }
            set { _value = value.Trim().ToLowerInvariant(); }
        }

        public bool IsWildcard
        {
            get { return Value.StartsWith("*", StringComparison.InvariantCulture); }
        }


        // --- Serialization Methods --- //

        private Identifier(SerializationInfo info, StreamingContext streamingContext)
        {
            if (info is null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            Type = info.GetRequiredString(nameof(Type));
            Value = info.GetRequiredString(nameof(Value));
        }

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info is null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            info.AddValue("SerializationVersion", 1);

            info.AddValue(nameof(Type), Type);
            info.AddValue(nameof(Value), Value);
        }
    }
}
