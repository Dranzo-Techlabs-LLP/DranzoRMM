using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dranzo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AuditImmutability : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // The audit log is append-only: the database itself refuses UPDATE, DELETE and TRUNCATE.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION dranzo_audit_immutable() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'AuditEvents is append-only';
                END;
                $$ LANGUAGE plpgsql;
                CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON "AuditEvents"
                    FOR EACH ROW EXECUTE FUNCTION dranzo_audit_immutable();
                CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON "AuditEvents"
                    FOR EACH STATEMENT EXECUTE FUNCTION dranzo_audit_immutable();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS audit_events_no_truncate ON "AuditEvents";
                DROP TRIGGER IF EXISTS audit_events_immutable ON "AuditEvents";
                DROP FUNCTION IF EXISTS dranzo_audit_immutable();
                """);
        }
    }
}
