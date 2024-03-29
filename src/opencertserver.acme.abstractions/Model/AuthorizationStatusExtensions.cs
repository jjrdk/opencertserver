﻿namespace OpenCertServer.Acme.Abstractions.Model;

using System.Linq;

public static class AuthorizationStatusExtensions
{
    private static readonly AuthorizationStatus[] _invalidStatus =
    [
        AuthorizationStatus.Invalid,
        AuthorizationStatus.Deactivated,
        AuthorizationStatus.Expired,
        AuthorizationStatus.Revoked
    ];

    public static bool IsInvalid(this AuthorizationStatus status)
    {
        return _invalidStatus.Contains(status);
    }
}