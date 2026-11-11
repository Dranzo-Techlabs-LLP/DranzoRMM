namespace Dranzo.Tests.Infra;

/// <summary>All integration tests share one running server and run sequentially (they share the test clock).</summary>
[CollectionDefinition("server")]
public sealed class ServerCollection : ICollectionFixture<ServerFixture>;
