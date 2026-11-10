//namespace OpenCertServer.Data.MsSql;
//
//using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
//
///// <summary>
///// Normalizes SQL Server <c>datetime2</c> reads to <see cref="DateTimeKind.Utc"/>.
///// <c>datetime2</c> carries no <see cref="DateTime.Kind"/>, so reads come back as
///// <see cref="DateTimeKind.Unspecified"/>; this converter forces UTC on the way back.
///// It is a parameterless <see cref="ValueConverter{TModel,TProvider}"/> so EF Core can
///// serialize it into the model snapshot and migrations stay consistent.
///// </summary>
//public sealed class UtcDateTimeConverter : ValueConverter<DateTime, DateTime>
//{
//    /// <summary>Initializes a new instance of the <see cref="UtcDateTimeConverter"/> class.</summary>
//    public UtcDateTimeConverter()
//        : base(
//            // modelToProvider: stored as-is.
//            value => value,
//            // providerToModel: datetime2 has no Kind, so read it back as UTC.
//            value => DateTime.SpecifyKind(value, DateTimeKind.Utc))
//    {
//    }
//}
