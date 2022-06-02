﻿namespace OpenCertServer.Acme.Server.RequestServices
{
    using System;
    using System.Text.Json;
    using Abstractions.HttpModel.Requests;
    using Abstractions.Model.Exceptions;
    using Abstractions.RequestServices;
    using Microsoft.IdentityModel.Tokens;

    public class DefaultRequestProvider : IAcmeRequestProvider
    {
        private AcmeRawPostRequest? _request;
        private AcmeHeader? _header;

        private Type? _payloadType;
        private object? _payload;

        
        public void Initialize(AcmeRawPostRequest rawPostRequest)
        {
            _request = rawPostRequest ?? throw new ArgumentNullException(nameof(rawPostRequest));
            _header = ReadHeader(_request);
        }

        public AcmeHeader GetHeader()
        {
            if (_request is null || _header is null)
            {
                throw new NotInitializedException();
            }

            if (string.IsNullOrEmpty(_header.Kid))
            {
                _header.Jwk!.SecurityKey.Kid = _header.Jwk?.KeyHash;
            }
            return _header;
        }

        public T? GetPayload<T>()
        {
            if (_request is null)
            {
                throw new NotInitializedException();
            }

            if (_payload != null)
            {
                if (_payloadType != typeof(T))
                {
                    throw new InvalidOperationException("Cannot change types during request");
                }

                return (T)_payload;
            }

            _payloadType = typeof(T);
            
            var payload = ReadPayload<T>(_request);
            _payload = payload;

            return payload;
        }

        public AcmeRawPostRequest GetRequest()
        {
            if (_request is null)
            {
                throw new NotInitializedException();
            }

            return _request;
        }


        private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };

        private static AcmeHeader? ReadHeader(AcmeRawPostRequest rawRequest)
        {
            if (rawRequest is null)
            {
                throw new ArgumentNullException(nameof(rawRequest));
            }

            var headerJson = Base64UrlEncoder.Decode(rawRequest.Header);
            var header = JsonSerializer.Deserialize<AcmeHeader>(headerJson, _jsonOptions);

            return header;
        }

        private static TPayload? ReadPayload<TPayload>(AcmeRawPostRequest rawRequest)
        {
            if (rawRequest is null)
            {
                throw new ArgumentNullException(nameof(rawRequest));
            }

            var payloadJson = Base64UrlEncoder.Decode(rawRequest.Payload);
            var payload = JsonSerializer.Deserialize<TPayload>(payloadJson, _jsonOptions);

            return payload;
        }
    }
}
