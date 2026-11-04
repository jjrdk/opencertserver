using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OpenCertServer.Data.MsSql.Migrations
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
                    AccountId = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    JwkThumbprint = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    ExternalAccountId = table.Column<string>(type: "nvarchar(450)", nullable: true, collation: "Latin1_General_100_BIN2"),
                    Status = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    Payload = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
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
                    SerialNumber = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    ProfileName = table.Column<string>(type: "nvarchar(max)", nullable: true, collation: "Latin1_General_100_BIN2"),
                    DistinguishedName = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    Issuer = table.Column<string>(type: "nvarchar(max)", nullable: true, collation: "Latin1_General_100_BIN2"),
                    NotBefore = table.Column<DateTimeOffset>(type: "datetime2", nullable: false),
                    NotAfter = table.Column<DateTimeOffset>(type: "datetime2", nullable: false),
                    Thumbprint = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    PublicKeyPem = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    RevocationReason = table.Column<int>(type: "int", nullable: true),
                    RevocationDate = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.SerialNumber);
                });

            migrationBuilder.CreateTable(
                name: "ExternalAccountKeys",
                columns: table => new
                {
                    KeyId = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    MacKey = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    MacAlgorithm = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    IsUsed = table.Column<bool>(type: "bit", nullable: false),
                    BoundAccountId = table.Column<string>(type: "nvarchar(450)", nullable: true, collation: "Latin1_General_100_BIN2"),
                    BoundAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
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
                    Token = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    Created = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Nonces", x => x.Token);
                });

            migrationBuilder.CreateTable(
                name: "Orders",
                columns: table => new
                {
                    OrderId = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    AccountId = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    Status = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    HasProcessingChallenge = table.Column<bool>(type: "bit", nullable: false),
                    Payload = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2"),
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
