using Amazon.S3;
using Amazon.S3.Model;
using Azure.Identity;
using Azure.Storage.Blobs;

namespace Dranzo.Infrastructure.Storage;

/// <summary>Opaque blob storage for packages, agent builds and transferred files. Keys are server-generated.</summary>
public interface IObjectStore
{
    Task PutAsync(string key, Stream content, CancellationToken ct);
    Task<Stream> OpenReadAsync(string key, CancellationToken ct);
    Task DeleteAsync(string key, CancellationToken ct);
}

public sealed class FileObjectStore : IObjectStore
{
    private readonly string _root;

    public FileObjectStore(string root)
    {
        _root = Path.GetFullPath(root);
        Directory.CreateDirectory(_root);
    }

    private string PathFor(string key)
    {
        if (key.Length is 0 or > 200 || key.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '/' or '.')) || key.Contains("..", StringComparison.Ordinal) || key.StartsWith('/'))
        {
            throw new ArgumentException("Invalid storage key.", nameof(key));
        }
        var full = Path.GetFullPath(Path.Combine(_root, key));
        if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException("Invalid storage key.", nameof(key));
        }
        return full;
    }

    public async Task PutAsync(string key, Stream content, CancellationToken ct)
    {
        var path = PathFor(key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        await using (var fs = File.Create(tmp))
        {
            await content.CopyToAsync(fs, ct);
        }
        File.Move(tmp, path, overwrite: true);
    }

    public Task<Stream> OpenReadAsync(string key, CancellationToken ct) =>
        Task.FromResult<Stream>(new FileStream(PathFor(key), FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true));

    public Task DeleteAsync(string key, CancellationToken ct)
    {
        File.Delete(PathFor(key));
        return Task.CompletedTask;
    }
}

/// <summary>S3-compatible storage (MinIO in local development).</summary>
public sealed class S3ObjectStore(IAmazonS3 s3, string bucket) : IObjectStore
{
    private bool _bucketChecked;

    private async Task EnsureBucketAsync(CancellationToken ct)
    {
        if (_bucketChecked)
        {
            return;
        }
        try
        {
            await s3.PutBucketAsync(new PutBucketRequest { BucketName = bucket }, ct);
        }
        catch (AmazonS3Exception ex) when (ex.ErrorCode is "BucketAlreadyOwnedByYou" or "BucketAlreadyExists")
        {
        }
        _bucketChecked = true;
    }

    public async Task PutAsync(string key, Stream content, CancellationToken ct)
    {
        await EnsureBucketAsync(ct);
        // Buffer to a temp file: S3 needs a seekable stream with a known length.
        var tmp = Path.GetTempFileName();
        try
        {
            await using (var fs = File.Create(tmp))
            {
                await content.CopyToAsync(fs, ct);
            }
            await s3.PutObjectAsync(new PutObjectRequest { BucketName = bucket, Key = key, FilePath = tmp }, ct);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    public async Task<Stream> OpenReadAsync(string key, CancellationToken ct)
    {
        var response = await s3.GetObjectAsync(bucket, key, ct);
        return response.ResponseStream;
    }

    public Task DeleteAsync(string key, CancellationToken ct) => s3.DeleteObjectAsync(bucket, key, ct);
}

/// <summary>Azure Blob Storage (production). Uses a connection string if given, else managed identity.</summary>
public sealed class AzureObjectStore : IObjectStore
{
    private readonly BlobContainerClient _container;
    private bool _checked;

    public AzureObjectStore(string? connectionString, Uri? accountUri, string container)
    {
        _container = connectionString is not null
            ? new BlobContainerClient(connectionString, container)
            : new BlobContainerClient(new Uri(accountUri!, container), new DefaultAzureCredential());
    }

    private async Task EnsureAsync(CancellationToken ct)
    {
        if (!_checked)
        {
            await _container.CreateIfNotExistsAsync(cancellationToken: ct);
            _checked = true;
        }
    }

    public async Task PutAsync(string key, Stream content, CancellationToken ct)
    {
        await EnsureAsync(ct);
        await _container.GetBlobClient(key).UploadAsync(content, overwrite: true, ct);
    }

    public async Task<Stream> OpenReadAsync(string key, CancellationToken ct) =>
        await _container.GetBlobClient(key).OpenReadAsync(cancellationToken: ct);

    public Task DeleteAsync(string key, CancellationToken ct) => _container.GetBlobClient(key).DeleteIfExistsAsync(cancellationToken: ct);
}
