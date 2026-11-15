# Multi-stage build for EnterpriseScalpel
# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder

WORKDIR /src

# Copy project files
COPY ["EnterpriseScalpel.csproj", "."]
COPY "Logging/" "Logging/"
COPY "Models/" "Models/"
COPY "Services/" "Services/"
COPY "wwwroot/" "wwwroot/"
COPY "Program.cs" "."
COPY "scalpel.config.json" "."

# Restore and build
RUN dotnet restore "EnterpriseScalpel.csproj"
RUN dotnet build "EnterpriseScalpel.csproj" --configuration Release --no-restore
RUN dotnet publish "EnterpriseScalpel.csproj" --configuration Release --no-build --output /app/publish

# Stage 2: Runtime (ASP.NET runtime only - no SDK/compilers in the shipped image)
FROM mcr.microsoft.com/dotnet/aspnet:8.0

# Install git and wget (required for the application and health check)
RUN apt-get update && apt-get install -y --no-install-recommends git wget ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy published files from builder
COPY --from=builder /app/publish .

# Output and sample-repository cache directories, owned by the non-root user
RUN mkdir -p /app/scalpel-reports /app/sample-repos && chown -R $APP_UID /app/scalpel-reports /app/sample-repos

# Containers must listen on all interfaces; the app defaults to loopback otherwise.
# PORT defaults to 5000 here; platforms such as Render override it.
ENV SCALPEL_HOST=0.0.0.0 \
    PORT=5000

EXPOSE 5000

# Health check follows $PORT so it keeps working when the platform changes the port
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 -O /dev/null "http://localhost:${PORT}/api/health" || exit 1

# Run as the image's built-in non-root user
USER $APP_UID

# Run the application
ENTRYPOINT ["dotnet", "/app/EnterpriseScalpel.dll"]
CMD ["serve"]
