using Dranzo.Api;

var app = DranzoApp.Build(args);
await DranzoApp.InitializeAsync(app);
await app.RunAsync();
