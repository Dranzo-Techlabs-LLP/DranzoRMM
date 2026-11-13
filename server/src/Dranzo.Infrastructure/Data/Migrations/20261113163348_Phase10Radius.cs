using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dranzo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class Phase10Radius : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "NetworkCertificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    PartnerId = table.Column<Guid>(type: "uuid", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    DeviceId = table.Column<Guid>(type: "uuid", nullable: false),
                    SerialHex = table.Column<string>(type: "text", nullable: false),
                    Thumbprint = table.Column<string>(type: "text", nullable: false),
                    IssuedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RevokedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    InstalledAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkCertificates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RadiusConfigs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    PartnerId = table.Column<Guid>(type: "uuid", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientsCidr = table.Column<string>(type: "text", nullable: false),
                    OfficeSsid = table.Column<string>(type: "text", nullable: false),
                    SharedSecretProtected = table.Column<string>(type: "text", nullable: false),
                    CrlNumber = table.Column<long>(type: "bigint", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RadiusConfigs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkCertificates_SerialHex",
                table: "NetworkCertificates",
                column: "SerialHex",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RadiusConfigs_OrganizationId",
                table: "RadiusConfigs",
                column: "OrganizationId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NetworkCertificates");

            migrationBuilder.DropTable(
                name: "RadiusConfigs");
        }
    }
}
