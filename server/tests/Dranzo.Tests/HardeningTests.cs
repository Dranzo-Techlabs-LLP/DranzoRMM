using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dranzo.Tests;

[Collection("server")]
public class HardeningTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    [Fact]
    public async Task Temporary_password_blocks_everything_until_changed_and_admin_can_reset_and_unlock()
    {
        var admin = await fx.AdminAsync();
        var email = $"temp-{Guid.NewGuid():N}@t.test";
        var created = await admin.PostJsonAsync("/api/v1/users", new { email, displayName = "Temp", password = "Temp-Strong-Pass-5501" });
        var userId = created.GetProperty("id").GetGuid();
        var roles = await admin.GetJsonAsync("/api/v1/roles");
        await admin.StepUpAsync();
        await admin.PostJsonAsync("/api/v1/role-assignments", new { userId, roleId = roles.EnumerateArray().First(r => r.GetProperty("name").GetString() == BuiltInRoles.ReadOnly).GetProperty("id").GetGuid(), scopeType = "Partner" });
        var user = fx.NewClient();
        await user.LoginAsync(email, "Temp-Strong-Pass-5501");
        // Enforced by the server, not just hidden by the UI.
        var blocked = await user.GetAsync("/api/v1/devices");
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Contains("password_change_required", await blocked.Content.ReadAsStringAsync());
        Assert.True((await user.GetJsonAsync("/api/v1/auth/me")).GetProperty("user").GetProperty("mustChangePassword").GetBoolean());
        Assert.Equal(HttpStatusCode.NoContent, (await user.PostAsync("/api/v1/auth/password", new { currentPassword = "Temp-Strong-Pass-5501", newPassword = "Brand-New-Pass-9911" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/api/v1/devices")).StatusCode);

        // Admin reset: sessions end, a temporary password applies again.
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/v1/users/{userId}/reset-password", new { password = "short" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/users/{userId}/reset-password", new { password = "Reset-Strong-Pass-3300" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.GetAsync("/api/v1/auth/me")).StatusCode);
        await user.LoginAsync(email, "Reset-Strong-Pass-3300");
        Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync("/api/v1/devices")).StatusCode);

        // Lock the account with bad passwords, then unlock it.
        var attacker = fx.NewClient();
        for (var i = 0; i < 5; i++)
        {
            await attacker.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong-wrong-wrong" });
        }
        Assert.Equal((HttpStatusCode)423, (await attacker.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Reset-Strong-Pass-3300" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/users/{userId}/unlock")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await attacker.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Reset-Strong-Pass-3300" })).StatusCode);
    }

    [Fact]
    public async Task Recovery_codes_are_long_and_regenerating_them_needs_step_up()
    {
        var user = await fx.CreateUserAsync($"rc-{Guid.NewGuid():N}@t.test", BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        Assert.All(user.RecoveryCodes!, c => Assert.Equal(23, c.Length)); // 80 bits as xxxxx-xxxxx-xxxxx-xxxxx
        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        var fresh = fx.NewClient();
        Assert.Contains("step_up_required", await (await user.PostAsync("/api/v1/auth/recovery-codes")).Content.ReadAsStringAsync());
        await user.StepUpAsync();
        var codes = (await user.PostJsonAsync("/api/v1/auth/recovery-codes", new { })).GetProperty("recoveryCodes");
        Assert.Equal(10, codes.GetArrayLength());
        Assert.DoesNotContain(user.RecoveryCodes![0], codes.EnumerateArray().Select(c => c.GetString()));
        Assert.NotEmpty((await user.GetJsonAsync("/api/v1/auth/time-zones")).EnumerateArray());
    }

    [Fact]
    public async Task Secrets_in_the_database_cannot_be_read_without_the_key_store()
    {
        var user = await fx.CreateUserAsync($"sp-{Guid.NewGuid():N}@t.test", BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var stored = await fx.DbAsync(db => db.Users.IgnoreQueryFilters().Where(u => u.Id == user.UserId).Select(u => u.TotpSecretProtected).FirstAsync());
        Assert.StartsWith("v1.", stored);
        var real = fx.Service<SecretProtector>();
        Assert.NotNull(real.Unprotect("totp-secret", stored));
        Assert.Null(real.Unprotect("notification-channel", stored)); // bound to its purpose
        // A different key store (an attacker with only the database) gets nothing.
        var other = new SecretProtector(new FileKeyStore(Path.Combine(fx.TempDir, "other-keys-" + U)), allowCreate: true);
        Assert.Null(other.Unprotect("totp-secret", stored));
        Assert.Null(real.Unprotect("totp-secret", stored![..^4] + "AAAA"));
        Assert.Null(real.UnprotectTimed("x", real.ProtectTimed("x", "v", DateTimeOffset.UtcNow.AddSeconds(-1)), DateTimeOffset.UtcNow));
        Assert.Equal("v", real.UnprotectTimed("x", real.ProtectTimed("x", "v", DateTimeOffset.UtcNow.AddMinutes(1)), DateTimeOffset.UtcNow));
        // No data-protection key table exists any more.
        Assert.Equal(0, await fx.DbAsync(async db => (await db.Database.SqlQueryRaw<int>("SELECT count(*)::int AS \"Value\" FROM information_schema.tables WHERE table_name = 'DataProtectionKeys'").ToListAsync())[0]));
    }

    [Fact]
    public void Missing_keys_stop_startup_when_creation_is_not_allowed()
    {
        var empty = new FileKeyStore(Path.Combine(fx.TempDir, "empty-keys-" + U));
        Assert.Contains("AllowCreate", Assert.Throws<InvalidOperationException>(() => new CertificateAuthority(empty, ["localhost"], allowCreate: false)).Message);
        Assert.Throws<InvalidOperationException>(() => new Ed25519CommandSigner(empty, allowCreate: false));
        Assert.Throws<InvalidOperationException>(() => new SecretProtector(empty, allowCreate: false));
        Assert.Null(empty.Get("device-ca-key")); // nothing was minted
    }

    [Fact]
    public async Task Nightly_verifier_reports_a_broken_audit_chain()
    {
        var partnerId = Guid.NewGuid();
        await fx.DbAsync(async db =>
        {
            db.Partners.Add(new Partner { Id = partnerId, Name = "Verify " + U, CreatedAt = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync();
        });
        async Task<int> RunAsync()
        {
            await using var scope = fx.App.Services.CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            return await AuditVerifier.RunAsync(scope.ServiceProvider, NullLogger.Instance, default);
        }
        await using (var scope = fx.App.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            var audit = scope.ServiceProvider.GetRequiredService<Dranzo.Infrastructure.Audit.IAuditLog>();
            for (var i = 0; i < 3; i++)
            {
                await audit.WriteAsync(partnerId, new Dranzo.Infrastructure.Audit.AuditEntry("test.event", Detail: new { i }));
            }
        }
        Assert.Equal(0, await RunAsync());
        await fx.DbAsync(async db =>
        {
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AuditEvents\" DISABLE TRIGGER audit_events_immutable");
            await db.AuditEvents.Where(a => a.PartnerId == partnerId && a.Sequence == 2).ExecuteUpdateAsync(s => s.SetProperty(a => a.Result, "tampered"));
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AuditEvents\" ENABLE TRIGGER audit_events_immutable");
        });
        Assert.Equal(1, await RunAsync());
        Assert.True(await fx.DbAsync(db => db.AuditEvents.AnyAsync(a => a.PartnerId == partnerId && a.Action == "audit.integrity_failed")));
    }

    [Fact]
    public async Task Installers_attached_to_a_release_can_be_downloaded_by_enrollment_managers()
    {
        var admin = await fx.AdminAsync();
        await admin.StepUpAsync();
        var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(1_100_000);
        async Task<Guid> Upload() => (await (await admin.SendAsync(HttpMethod.Put, "/api/v1/releases/upload?fileName=x", new ByteArrayContent(bytes))).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("blobId").GetGuid();
        var version = $"8.{Random.Shared.Next(1, 9999)}.0";
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/releases", new { version, binaries = new[] { new { os = "linux", arch = "amd64", blobId = await Upload(), kind = "msi" } } })).StatusCode);
        await admin.PostJsonAsync("/api/v1/releases", new { version, binaries = new object[] { new { os = "linux", arch = "amd64", blobId = await Upload() }, new { os = "linux", arch = "amd64", blobId = await Upload(), kind = "deb" } } });
        var org = await fx.SeedOrgAsync("Inst " + U);
        var tech = await fx.CreateUserAsync($"inst-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, org.OrgId);
        var list = await tech.GetJsonAsync("/api/v1/agent/installers");
        var deb = list.GetProperty("installers").EnumerateArray().Single(i => i.GetProperty("kind").GetString() == "deb");
        Assert.EndsWith($"{version}-linux-amd64.deb", deb.GetProperty("fileName").GetString());
        var file = await tech.GetAsync(deb.GetProperty("url").GetString()!);
        Assert.Equal(bytes, await file.Content.ReadAsByteArrayAsync());
        Assert.Equal("attachment", file.Content.Headers.ContentDisposition!.DispositionType);
        // The plain agent program is offered too, for manual installs.
        var plain = list.GetProperty("installers").EnumerateArray().Single(i => i.GetProperty("kind").GetString() == "binary");
        Assert.Matches(@"^dranzo-agent-[0-9.]+-linux-amd64$", plain.GetProperty("fileName").GetString());
        Assert.Equal(HttpStatusCode.OK, (await tech.GetAsync(plain.GetProperty("url").GetString()!)).StatusCode);
        Assert.Contains(await tech.GetJsonAsync("/api/v1/enrollment-tokens/targets") is var t ? t.GetProperty("sites").EnumerateArray().Select(s => s.GetProperty("id").GetGuid()) : [], id => id == org.SiteId);
    }
}
