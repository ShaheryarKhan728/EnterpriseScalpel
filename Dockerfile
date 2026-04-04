# Multi-stage build for EnterpriseScalpel
# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine AS builder

WORKDIR /src

# Copy project files
COPY ["EnterpriseScalpel.csproj", "."]
COPY "Logging/" "Logging/"
COPY "Models/" "Models/"
COPY "Services/" "Services/"
COPY "wwwroot/" "wwwroot/"
COPY "Program.cs" "."
COPY "scalpel.config.json" "."
COPY "pm-integration.config.json" "."

# Restore and build
RUN dotnet restore "EnterpriseScalpel.csproj"
RUN dotnet build "EnterpriseScalpel.csproj" --configuration Release --no-restore
RUN dotnet publish "EnterpriseScalpel.csproj" --configuration Release --no-build --output /app/publish

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/runtime:8.0-alpine

# Install git (required for the application to work)
RUN apk add --no-cache git

WORKDIR /app

# Copy published files from builder
COPY --from=builder /app/publish .

# Create scalpel-reports directory for output
RUN mkdir -p /app/scalpel-reports

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5000/api/health || exit 1

# Run the application
ENTRYPOINT ["dotnet", "EnterpriseScalpel.dll"]
CMD ["serve"]
