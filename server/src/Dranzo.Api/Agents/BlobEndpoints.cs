using System.Security.Cryptography;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Storage;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Agents;

public sealed record StoredBlob(Guid Id, string Sha256, long SizeBytes);

/// <summary>Streams uploads into object storage while hashing and enforcing a size cap.</summary>
public sealed class BlobService(DranzoDbContext db, IObjectStore store, TimeProvider clock)
{
    public async Task<StoredBlob?> SaveAsync(Guid partnerId, Stream content, string fileName, string purpose, long maxBytes, TimeSpan? expiresAfter, CancellationToken ct)
    {
        var id = Guid.NewGuid();
        var tmp = Path.Combine(Path.GetTempPath(), "dz-upload-" + id.ToString("N"));
        try
        {
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long total = 0;
            await using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous))
            {
                var buffer = new byte[81920];
                int read;
                while ((read = await content.ReadAsync(buffer, ct)) > 0)
                {
                    total += read;
                    if (total > maxBytes)
                    {
                        return null;
                    }
                    sha.AppendData(buffer, 0, read);
                    await fs.WriteAsync(buffer.AsMemory(0, read), ct);
                }
            }
            if (total == 0)
            {
                return null;
            }
            var key = $"{partnerId:N}/{purpose}/{id:N}";
            await using (var fs = File.OpenRead(tmp))
            {
                await store.PutAsync(key, fs, ct);
            }
            var hash = Convert.ToHexStringLower(sha.GetHashAndReset());
            var now = clock.GetUtcNow();
            db.Blobs.Add(new Blob
            {
                Id = id, PartnerId = partnerId, StorageKey = key, FileName = SafeFileName(fileName), SizeBytes = total, Sha256 = hash, Purpose = purpose,
                CreatedAt = now, ExpiresAt = expiresAfter is null ? null : now.Add(expiresAfter.Value),
            });
            await db.SaveChangesAsync(ct);
            return new StoredBlob(id, hash, total);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    /// <summary>Keeps a plain file name: no directories, no control characters, bounded length.</summary>
    public static string SafeFileName(string? name)
    {
        var n = Path.GetFileName((name ?? "").Replace('\\', '/'));
        n = new string([.. n.Where(c => !char.IsControl(c) && c is not ('"' or '<' or '>' or '|' or ':' or '*' or '?'))]).Trim().TrimStart('.');
        if (n.Length > 128)
        {
            n = n[^128..];
        }
        return n.Length == 0 ? "file" : n;
    }
}

/// <summary>Agent-side blob transfer over mTLS (docs/PROTOCOL.md section 8).</summary>
public static class BlobEndpoints
{
    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/agent/v1").AgentListener();

        g.MapGet("/blobs/{blobId:guid}", async Task<IResult> (Guid blobId, HttpContext http, DranzoDbContext db, TenantContext tenant, IObjectStore store, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.SetSystem();
            var device = await AgentGateway.AuthenticateDeviceAsync(http, db, clock, tracking: false, ct);
            if (device is null)
            {
                return Results.StatusCode(403);
            }
            var now = clock.GetUtcNow();
            // Only blobs referenced by a command recently dispatched to this very device.
            var granted = await db.BlobGrants.AnyAsync(x => x.BlobId == blobId && x.DeviceId == device.Id && x.ExpiresAt > now, ct);
            var blob = granted ? await db.Blobs.AsNoTracking().FirstOrDefaultAsync(b => b.Id == blobId && b.PartnerId == device.PartnerId, ct) : null;
            if (blob is null)
            {
                return Results.NotFound();
            }
            var stream = await store.OpenReadAsync(blob.StorageKey, ct);
            http.Response.ContentLength = blob.SizeBytes;
            http.Response.Headers["X-Content-Sha256"] = blob.Sha256;
            return Results.Stream(stream, "application/octet-stream");
        });

        g.MapPut("/uploads/{uploadId:guid}", async Task<IResult> (Guid uploadId, HttpContext http, DranzoDbContext db, TenantContext tenant, BlobService blobs, IOptions<DranzoOptions> options, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.SetSystem();
            var device = await AgentGateway.AuthenticateDeviceAsync(http, db, clock, tracking: false, ct);
            if (device is null)
            {
                return Results.StatusCode(403);
            }
            var now = clock.GetUtcNow();
            var ticket = await db.UploadTickets.FirstOrDefaultAsync(t => t.Id == uploadId && t.DeviceId == device.Id && t.UsedAt == null && t.ExpiresAt > now, ct);
            if (ticket is null)
            {
                return Results.NotFound();
            }
            var max = Math.Min(ticket.MaxBytes, options.Value.Storage.MaxFileTransferBytes);
            http.Features.Get<IHttpMaxRequestBodySizeFeature>()!.MaxRequestBodySize = max + 1;
            if (http.Request.ContentLength > max)
            {
                return Results.StatusCode(413);
            }
            // Claim the ticket first so it can be used exactly once even under concurrent uploads.
            if (await db.UploadTickets.Where(t => t.Id == uploadId && t.UsedAt == null).ExecuteUpdateAsync(s => s.SetProperty(t => t.UsedAt, now), ct) != 1)
            {
                return Results.NotFound();
            }
            var stored = await blobs.SaveAsync(device.PartnerId, http.Request.Body, "upload", "file-transfer", max, TimeSpan.FromHours(1), ct);
            if (stored is null)
            {
                return Results.StatusCode(413);
            }
            await db.UploadTickets.Where(t => t.Id == uploadId).ExecuteUpdateAsync(s => s.SetProperty(t => t.BlobId, stored.Id), ct);
            return Results.Ok(new { sizeBytes = stored.SizeBytes, sha256 = stored.Sha256 });
        });
    }
}
