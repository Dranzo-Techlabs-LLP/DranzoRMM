using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dranzo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class Phase10Network : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DefaultGateway",
                table: "Devices",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string[]>(
                name: "MacAddresses",
                table: "Devices",
                type: "text[]",
                nullable: false,
                defaultValue: Array.Empty<string>());

            migrationBuilder.AddColumn<string>(
                name: "WifiSsid",
                table: "Devices",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "NetworkDevices",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    PartnerId = table.Column<Guid>(type: "uuid", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    SiteId = table.Column<Guid>(type: "uuid", nullable: false),
                    Mac = table.Column<string>(type: "text", nullable: false),
                    Ip = table.Column<string>(type: "text", nullable: false),
                    Hostname = table.Column<string>(type: "text", nullable: true),
                    Vendor = table.Column<string>(type: "text", nullable: true),
                    Randomized = table.Column<bool>(type: "boolean", nullable: false),
                    IsGateway = table.Column<bool>(type: "boolean", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    SeenByDeviceId = table.Column<Guid>(type: "uuid", nullable: true),
                    ManagedDeviceId = table.Column<Guid>(type: "uuid", nullable: true),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Note = table.Column<string>(type: "text", nullable: true),
                    StatusChangedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    StatusChangedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_NetworkDevices", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Devices_MacAddresses",
                table: "Devices",
                column: "MacAddresses")
                .Annotation("Npgsql:IndexMethod", "gin");

            migrationBuilder.CreateIndex(
                name: "IX_NetworkDevices_OrganizationId_Status",
                table: "NetworkDevices",
                columns: new[] { "OrganizationId", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_NetworkDevices_SiteId_Mac",
                table: "NetworkDevices",
                columns: new[] { "SiteId", "Mac" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "NetworkDevices");

            migrationBuilder.DropIndex(
                name: "IX_Devices_MacAddresses",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "DefaultGateway",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "MacAddresses",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "WifiSsid",
                table: "Devices");
        }
    }
}
