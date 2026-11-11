using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dranzo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class Phase6Remote : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "InputSeq",
                table: "RemoteSessions",
                newName: "BytesOut");

            migrationBuilder.AddColumn<long>(
                name: "BytesIn",
                table: "RemoteSessions",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "InputSha256",
                table: "RemoteSessions",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "MeshGroupId",
                table: "Organizations",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "MeshUser",
                table: "Organizations",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BytesIn",
                table: "RemoteSessions");

            migrationBuilder.DropColumn(
                name: "InputSha256",
                table: "RemoteSessions");

            migrationBuilder.DropColumn(
                name: "MeshGroupId",
                table: "Organizations");

            migrationBuilder.DropColumn(
                name: "MeshUser",
                table: "Organizations");

            migrationBuilder.RenameColumn(
                name: "BytesOut",
                table: "RemoteSessions",
                newName: "InputSeq");
        }
    }
}
