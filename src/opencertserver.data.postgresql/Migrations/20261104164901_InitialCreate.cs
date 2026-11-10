using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OpenCertServer.Data.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Accounts",
                columns: table => new
                {
                    AccountId = table.Column<string>(type: "text", nullable: false),
                    JwkThumbprint = table.Column<string>(type: "text", nullable: false),
                    ExternalAccountId = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<string>(type: "text", nullable: false),
                    Payload = table.Column<string>(type: "text", nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Accounts", x => x.AccountId);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    SerialNumber = table.Column<string>(type: "text", nullable: false),
                    ProfileName = table.Column<string>(type: "text", nullable: true),
                    DistinguishedName = table.Column<string>(type: "text", nullable: false),
                    Issuer = table.Column<string>(type: "text", nullable: true),
                    NotBefore = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Thumbprint = table.Column<string>(type: "text", nullable: false),
                    PublicKeyPem = table.Column<string>(type: "text", nullable: false),
                    RevocationReason = table.Column<int>(type: "integer", nullable: true),
                    RevocationDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.SerialNumber);
                });

            migrationBuilder.CreateTable(
                name: "ExternalAccountKeys",
                columns: table => new
                {
                    KeyId = table.Column<string>(type: "text", nullable: false),
                    MacKey = table.Column<string>(type: "text", nullable: false),
                    MacAlgorithm = table.Column<string>(type: "text", nullable: false),
                    IsUsed = table.Column<bool>(type: "boolean", nullable: false),
                    BoundAccountId = table.Column<string>(type: "text", nullable: true),
                    BoundAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalAccountKeys", x => x.KeyId);
                });

            migrationBuilder.CreateTable(
                name: "Nonces",
                columns: table => new
                {
                    Token = table.Column<string>(type: "text", nullable: false),
                    Created = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Nonces", x => x.Token);
                });

            migrationBuilder.CreateTable(
                name: "Orders",
                columns: table => new
                {
                    OrderId = table.Column<string>(type: "text", nullable: false),
                    AccountId = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<string>(type: "text", nullable: false),
                    HasProcessingChallenge = table.Column<bool>(type: "boolean", nullable: false),
                    Payload = table.Column<string>(type: "text", nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Orders", x => x.OrderId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_ExternalAccountId",
                table: "Accounts",
                column: "ExternalAccountId");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_JwkThumbprint",
                table: "Accounts",
                column: "JwkThumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_RevocationReason",
                table: "Certificates",
                column: "RevocationReason");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_Thumbprint",
                table: "Certificates",
                column: "Thumbprint");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalAccountKeys_BoundAccountId",
                table: "ExternalAccountKeys",
                column: "BoundAccountId");

            migrationBuilder.CreateIndex(
                name: "IX_Orders_AccountId",
                table: "Orders",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_Orders_HasProcessingChallenge",
                table: "Orders",
                column: "HasProcessingChallenge");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Accounts");

            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "ExternalAccountKeys");

            migrationBuilder.DropTable(
                name: "Nonces");

            migrationBuilder.DropTable(
                name: "Orders");
        }
    }
}
