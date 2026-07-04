# Build des images Docker pour les fonctions OpenFaaS
# Equivalent de faas-cli build, mais compatible Windows

$ErrorActionPreference = "Stop"

$FUNCTIONS_DIR = $PSScriptRoot
$TEMPLATE_DIR  = Join-Path $FUNCTIONS_DIR "template\python3-http"
$FUNCTION_DIR  = Join-Path $TEMPLATE_DIR "function"

$functions = @(
    @{ name = "create-account";   image = "dockerazariel/create-account:latest"   },
    @{ name = "generate-password"; image = "dockerazariel/generate-password:latest" },
    @{ name = "generate-2fa";     image = "dockerazariel/generate-2fa:latest"      }
)

foreach ($fn in $functions) {
    Write-Host ""
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "  Building $($fn.name)..." -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan

    $src = Join-Path $FUNCTIONS_DIR $fn.name

    # Vider le dossier function/ du template
    Get-ChildItem $FUNCTION_DIR | Remove-Item -Recurse -Force

    # Copier les fichiers de la fonction dans template/function/
    Copy-Item -Path "$src\*" -Destination $FUNCTION_DIR -Recurse

    # Build l'image Docker depuis le dossier template
    docker build -t $fn.image $TEMPLATE_DIR
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ECHEC du build pour $($fn.name)" -ForegroundColor Red
        exit 1
    }

    Write-Host "OK : $($fn.image)" -ForegroundColor Green
}

Write-Host ""
Write-Host "==============================" -ForegroundColor Green
Write-Host "  Toutes les images buildees !" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green
Write-Host ""
Write-Host "Prochaine etape :" -ForegroundColor Yellow
Write-Host "  minikube image load dockerazariel/create-account:latest"
Write-Host "  minikube image load dockerazariel/generate-password:latest"
Write-Host "  minikube image load dockerazariel/generate-2fa:latest"
Write-Host "  faas-cli deploy -f stack.yaml --gateway http://127.0.0.1:8888"
