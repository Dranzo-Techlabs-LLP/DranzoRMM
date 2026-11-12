# DranzoRMM server (API + agent gateway). Build context: the server/ directory.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props DranzoRMM.sln ./
COPY src/Dranzo.Domain/Dranzo.Domain.csproj src/Dranzo.Domain/packages.lock.json src/Dranzo.Domain/
COPY src/Dranzo.Infrastructure/Dranzo.Infrastructure.csproj src/Dranzo.Infrastructure/packages.lock.json src/Dranzo.Infrastructure/
COPY src/Dranzo.Api/Dranzo.Api.csproj src/Dranzo.Api/packages.lock.json src/Dranzo.Api/
RUN dotnet restore src/Dranzo.Api/Dranzo.Api.csproj --locked-mode
COPY src/ src/
RUN dotnet publish src/Dranzo.Api/Dranzo.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:11.0
WORKDIR /app
COPY --from=build /app .
# Key store, object storage (file mode) and exported trust anchors live on volumes owned by the non-root app user.
RUN mkdir -p /data/keys /data/storage /data/trust && chown -R $APP_UID:0 /data
USER $APP_UID
ENV Dranzo__KeyStore__Directory=/data/keys \
    Dranzo__Storage__Directory=/data/storage \
    DOTNET_gcServer=0
EXPOSE 8080 8443
ENTRYPOINT ["dotnet", "Dranzo.Api.dll"]
