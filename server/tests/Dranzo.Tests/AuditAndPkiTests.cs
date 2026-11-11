using System.Text.Json;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Dranzo.Tests;

[Collection("server")]
public class AuditTests(ServerFixture fx)
{
    private async Task<Guid> NewPartnerWithEventsAsync(int events)
    {
        var partnerId = Guid.NewGuid();
        await fx.DbAsync(async db =>
        {
            db.Partners.Add(new Partner { Id = partnerId, Name = "Audit " + partnerId.ToString("N")[..6], CreatedAt = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync();
        });
        await Task.WhenAll(Enumerable.Range(0, events).Select(async i =>
        {
            await using var scope = fx.App.Services.CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await scope.ServiceProvider.GetRequiredService<IAuditLog>().WriteAsync(partnerId, new AuditEntry("test.event", Detail: new { i, text = "détail \"quoted\"" }));
        }));
        return partnerId;
    }

    [Fact]
    public async Task Concurrent_writes_form_one_valid_chain()
    {
        var partnerId = await NewPartnerWithEventsAsync(40);
        var result = await fx.DbAsync(db => AuditLog.VerifyAsync(db, partnerId, default));
        Assert.True(result.Ok, result.Problem);
        Assert.Equal(40, result.Count);
        var sequences = await fx.DbAsync(db => db.AuditEvents.Where(a => a.PartnerId == partnerId).OrderBy(a => a.Sequence).Select(a => a.Sequence).ToListAsync());
        Assert.Equal(Enumerable.Range(1, 40).Select(i => (long)i), sequences);
    }

    [Fact]
    public async Task Database_refuses_update_and_delete_of_audit_rows()
    {
        var partnerId = await NewPartnerWithEventsAsync(2);
        var update = await Assert.ThrowsAsync<PostgresException>(() => fx.DbAsync(db => db.AuditEvents.Where(a => a.PartnerId == partnerId).ExecuteUpdateAsync(s => s.SetProperty(a => a.Result, "edited"))));
        Assert.Contains("append-only", update.MessageText);
        var delete = await Assert.ThrowsAsync<PostgresException>(() => fx.DbAsync(db => db.AuditEvents.Where(a => a.PartnerId == partnerId).ExecuteDeleteAsync()));
        Assert.Contains("append-only", delete.MessageText);
    }

    [Theory]
    [InlineData("edit")]
    [InlineData("delete")]
    public async Task Tampering_behind_the_trigger_is_detected_by_the_hash_chain(string kind)
    {
        var partnerId = await NewPartnerWithEventsAsync(5);
        await fx.DbAsync(async db =>
        {
            // Simulates a database superuser bypassing the trigger.
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AuditEvents\" DISABLE TRIGGER audit_events_immutable");
            try
            {
                if (kind == "edit")
                {
                    await db.AuditEvents.Where(a => a.PartnerId == partnerId && a.Sequence == 3).ExecuteUpdateAsync(s => s.SetProperty(a => a.ActorName, "someone else"));
                }
                else
                {
                    await db.AuditEvents.Where(a => a.PartnerId == partnerId && a.Sequence == 3).ExecuteDeleteAsync();
                }
            }
            finally
            {
                await db.Database.ExecuteSqlRawAsync("ALTER TABLE \"AuditEvents\" ENABLE TRIGGER audit_events_immutable");
            }
        });
        var result = await fx.DbAsync(db => AuditLog.VerifyAsync(db, partnerId, default));
        Assert.False(result.Ok);
        Assert.Equal(3, result.FirstBadSequence);
    }

    [Fact]
    public async Task Admin_actions_and_logins_are_audited_and_the_live_chain_verifies()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Audited " + Guid.NewGuid().ToString("N")[..6]);
        var items = (await admin.GetJsonAsync($"/api/v1/audit?organizationId={org.OrgId}&pageSize=100")).GetProperty("items");
        var actions = items.EnumerateArray().Select(e => e.GetProperty("action").GetString()).ToList();
        Assert.Contains("organization.create", actions);
        Assert.Contains("site.create", actions);
        Assert.Contains("enrollment_token.create", actions);
        Assert.All(items.EnumerateArray(), e => Assert.Equal(ServerFixture.AdminEmail, e.GetProperty("actorName").GetString()));
        Assert.All(items.EnumerateArray(), e => Assert.False(string.IsNullOrEmpty(e.GetProperty("ip").GetString())));
        var logins = (await admin.GetJsonAsync("/api/v1/audit?action=auth.login&pageSize=5")).GetProperty("total").GetInt32();
        Assert.True(logins > 0);
        var verify = await admin.GetJsonAsync("/api/v1/audit/verify");
        Assert.True(verify.GetProperty("ok").GetBoolean(), verify.ToString());
        // Secrets never reach the audit log.
        var all = await (await admin.GetAsync("/api/v1/audit/export.csv")).Content.ReadAsStringAsync();
        Assert.DoesNotContain(org.Token, all);
        Assert.DoesNotContain(ServerFixture.AdminPassword, all);
    }
}

public class SigningTests
{
    private sealed class MemoryKeyStore : IKeyStore
    {
        private readonly Dictionary<string, byte[]> _d = [];

        public byte[]? Get(string name) => _d.GetValueOrDefault(name);

        public void Put(string name, byte[] value) => _d[name] = value;
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static string VectorPath()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !Directory.Exists(Path.Combine(dir, "agent")))
        {
            dir = Path.GetDirectoryName(dir);
        }
        return Path.Combine(dir!, "agent", "internal", "protocol", "testdata", "vectors.json");
    }

    [Fact]
    public void Signature_covers_type_and_payload()
    {
        var signer = new Ed25519CommandSigner(new MemoryKeyStore());
        var payload = "{\"a\":1}"u8.ToArray();
        var sig = signer.Sign("job.dispatch", payload);
        Assert.True(Ed25519CommandSigner.Verify(signer.PublicKey, "job.dispatch", payload, sig));
        Assert.False(Ed25519CommandSigner.Verify(signer.PublicKey, "update.available", payload, sig));
        Assert.False(Ed25519CommandSigner.Verify(signer.PublicKey, "job.dispatch", "{\"a\":2}"u8.ToArray(), sig));
        var other = new Ed25519CommandSigner(new MemoryKeyStore());
        Assert.False(Ed25519CommandSigner.Verify(other.PublicKey, "job.dispatch", payload, sig));
    }

    [Fact]
    public void Key_is_persisted_and_reused()
    {
        var store = new MemoryKeyStore();
        var a = new Ed25519CommandSigner(store);
        var b = new Ed25519CommandSigner(store);
        Assert.Equal(a.KeyId, b.KeyId);
        Assert.Equal(a.PublicKey, b.PublicKey);
    }

    [Fact]
    public void File_keystore_rejects_path_tricks_and_restricts_permissions()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dz-ks-" + Guid.NewGuid().ToString("N"));
        var store = new FileKeyStore(dir);
        store.Put("k1", [1, 2, 3]);
        Assert.Equal([1, 2, 3], store.Get("k1"));
        Assert.Throws<ArgumentException>(() => store.Put("../evil", [1]));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(dir, "k1.key")));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(dir));
        }
        Directory.Delete(dir, true);
    }

    /// <summary>
    /// Interop vectors consumed by the Go agent's verifier tests. Regenerate with DRANZO_WRITE_VECTORS=1.
    /// The key below is a fixed, public test value and signs nothing outside this file.
    /// </summary>
    [Fact]
    public void Interop_vectors_for_the_go_agent_are_valid()
    {
        var path = VectorPath();
        var store = new MemoryKeyStore();
        store.Put("command-signing-key", [.. Enumerable.Range(1, 32).Select(i => (byte)i)]);
        var signer = new Ed25519CommandSigner(store);
        var now = new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);
        var deviceId = Guid.Parse("11111111-2222-3333-4444-555555555555");

        if (Environment.GetEnvironmentVariable("DRANZO_WRITE_VECTORS") == "1")
        {
            JsonElement Env(string json) => JsonDocument.Parse(json).RootElement.Clone();
            var fields = new Dictionary<string, object?> { ["jobRunId"] = Guid.NewGuid().ToString("D"), ["kind"] = "script", ["timeoutSeconds"] = 60, ["maxOutputBytes"] = 1048576, ["spec"] = new { language = "sh", body = "echo hi", args = Array.Empty<string>(), env = new { }, runAs = "system", requireSignedPowerShell = false } };
            var ok = new EnvelopeFactory(signer, new FixedClock(now));
            var cases = new List<object>
            {
                new { name = "valid job.dispatch", envelope = Env(ok.Signed("job.dispatch", deviceId, fields)), expect = "ok" },
                new { name = "wrong device", envelope = Env(ok.Signed("job.dispatch", Guid.NewGuid(), fields)), expect = "wrong_device" },
                new { name = "expired", envelope = Env(new EnvelopeFactory(signer, new FixedClock(now.AddHours(-1))).Signed("job.dispatch", deviceId, fields)), expect = "expired" },
                new { name = "not yet valid", envelope = Env(new EnvelopeFactory(signer, new FixedClock(now.AddHours(1))).Signed("job.dispatch", deviceId, fields)), expect = "not_yet_valid" },
                new { name = "validity too long", envelope = Env(ok.Signed("job.dispatch", deviceId, fields, validity: TimeSpan.FromHours(2))), expect = "validity_too_long" },
                new { name = "unsigned", envelope = Env(ok.Plain("job.dispatch", fields)), expect = "unsigned" },
            };
            var tampered = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(ok.Signed("job.dispatch", deviceId, fields))!;
            var other = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(ok.Signed("job.dispatch", deviceId, fields))!;
            cases.Add(new { name = "payload swapped under another signature", envelope = new Dictionary<string, JsonElement>(tampered) { ["signedPayload"] = other["signedPayload"] }, expect = "bad_signature" });
            cases.Add(new { name = "type changed after signing", envelope = new Dictionary<string, JsonElement>(tampered) { ["type"] = Env("\"update.available\"") }, expect = "bad_signature" });
            cases.Add(new { name = "unknown key id", envelope = new Dictionary<string, JsonElement>(tampered) { ["keyId"] = Env("\"cmd-0000000000000000\"") }, expect = "unknown_key" });
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(new { publicKey = Convert.ToBase64String(signer.PublicKey), kid = signer.KeyId, deviceId = deviceId.ToString("D"), now = now.ToString("yyyy-MM-ddTHH:mm:ssZ"), cases }, new JsonSerializerOptions { WriteIndented = true }));
        }

        Assert.True(File.Exists(path), "vectors.json missing: run the test once with DRANZO_WRITE_VECTORS=1");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal(Convert.ToBase64String(signer.PublicKey), doc.RootElement.GetProperty("publicKey").GetString());
        var seen = 0;
        foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            var env = c.GetProperty("envelope");
            var expect = c.GetProperty("expect").GetString();
            if (!env.TryGetProperty("signedPayload", out var sp))
            {
                Assert.Equal("unsigned", expect);
                continue;
            }
            var valid = Ed25519CommandSigner.Verify(signer.PublicKey, env.GetProperty("type").GetString()!, Convert.FromBase64String(sp.GetString()!), Convert.FromBase64String(env.GetProperty("signature").GetString()!));
            Assert.Equal(expect != "bad_signature", valid);
            seen++;
        }
        Assert.True(seen >= 7);
    }
}
