using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OpenCertServer.Data.MsSql.Migrations
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
                    Name = table.Column<string>(type: "nvarchar(450)", nullable: false, collation: "Latin1_General_100_BIN2"),
                    IsDefault = table.Column<bool>(type: "bit", nullable: false),
                    Payload = table.Column<string>(type: "nvarchar(max)", nullable: false, collation: "Latin1_General_100_BIN2")
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
