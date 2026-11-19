using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OpenCertServer.Data.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddCaProfileStore : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CaProfiles",
                columns: table => new
                {
                    Name = table.Column<string>(type: "text", nullable: false),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false),
                    Payload = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CaProfiles", x => x.Name);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CaProfiles_IsDefault",
                table: "CaProfiles",
                column: "IsDefault");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CaProfiles");
        }
    }
}
