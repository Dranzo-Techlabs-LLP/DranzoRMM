using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dranzo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class SecurityReviewFixes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PatchCatalog_PartnerId_Source_UpdateId",
                table: "PatchCatalog");

            migrationBuilder.AddColumn<Guid>(
                name: "OrganizationId",
                table: "PatchCatalog",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            // Backfill: existing partner-wide entries take the organization of a device that uses them. Entries used by
            // several organizations are split on the next scan (agents re-report their pending updates).
            migrationBuilder.Sql("""
                UPDATE "PatchCatalog" c SET "OrganizationId" = s."OrganizationId"
                FROM (SELECT DISTINCT ON ("CatalogEntryId") "CatalogEntryId", "OrganizationId" FROM "DevicePatchStates" ORDER BY "CatalogEntryId") s
                WHERE s."CatalogEntryId" = c."Id";
                DELETE FROM "PatchCatalog" WHERE "OrganizationId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.CreateIndex(
                name: "IX_PatchCatalog_PartnerId_OrganizationId_Source_UpdateId",
                table: "PatchCatalog",
                columns: new[] { "PartnerId", "OrganizationId", "Source", "UpdateId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PatchCatalog_PartnerId_OrganizationId_Source_UpdateId",
                table: "PatchCatalog");

            migrationBuilder.DropColumn(
                name: "OrganizationId",
                table: "PatchCatalog");

            migrationBuilder.CreateIndex(
                name: "IX_PatchCatalog_PartnerId_Source_UpdateId",
                table: "PatchCatalog",
                columns: new[] { "PartnerId", "Source", "UpdateId" },
                unique: true);
        }
    }
}
