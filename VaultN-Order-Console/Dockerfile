FROM mcr.microsoft.com/dotnet/runtime:8.0 AS base
USER $APP_UID
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["VaultN-Order-Console/VaultN-Order-Console.csproj", "VaultN-Order-Console/"]
RUN dotnet restore "VaultN-Order-Console/VaultN-Order-Console.csproj"
COPY . .
WORKDIR "/src/VaultN-Order-Console"
RUN dotnet build "VaultN-Order-Console.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "VaultN-Order-Console.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "VaultN-Order-Console.dll"]
