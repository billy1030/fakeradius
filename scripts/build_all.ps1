# Build script for FakeRADIUS
$platforms = @(
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe" },
    @{ OS = "windows"; Arch = "arm64"; Ext = ".exe" },
    @{ OS = "linux";   Arch = "amd64"; Ext = "" },
    @{ OS = "linux";   Arch = "arm64"; Ext = "" },
    @{ OS = "darwin";  Arch = "amd64"; Ext = "" },
    @{ OS = "darwin";  Arch = "arm64"; Ext = "" }
)

foreach ($p in $platforms) {
    $os = $p.OS
    $arch = $p.Arch
    $ext = $p.Ext
    
    $outDir = "dist/multi/$os-$arch"
    if (!(Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    
    Write-Host "Building for $os-$arch..."
    
    $env:GOOS = $os
    $env:GOARCH = $arch
    
    go build -o "$outDir/fakeradius-server$ext" ./cmd/server
    go build -o "$outDir/radius-cli$ext" ./cmd/cli
}

# Reset env
$env:GOOS = ""
$env:GOARCH = ""

Write-Host "Build complete. Binaries are in dist/multi/"
