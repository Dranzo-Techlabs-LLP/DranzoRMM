using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dranzo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class Phase10Isolation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "IsolatedAt",
                table: "Devices",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IsolatedBy",
                table: "Devices",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IsolationReason",
                table: "Devices",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsolatedAt",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "IsolatedBy",
                table: "Devices");

            migrationBuilder.DropColumn(
                name: "IsolationReason",
                table: "Devices");
        }
    }
}
