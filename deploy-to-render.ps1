<#
Simple helper to commit and push current changes, then remind to trigger Render deploy.
Usage: Run at repo root in PowerShell:
.
    .\deploy-to-render.ps1 -Message "Prepare render deploy"

This script requires `git` configured and a remote named `origin`.
#>

param(
    [string]$Message = "chore: prepare render deploy"
)

Write-Host "Checking for git..."
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "git not found in PATH. Install Git and try again."
    exit 1
}

Push-Location (Get-Location)

try {
    $branch = git rev-parse --abbrev-ref HEAD 2>$null
    if (-not $branch) { throw "Could not determine current branch." }
    Write-Host "On branch: $branch"

    Write-Host "Staging changes..."
    git add -A

    Write-Host "Committing..."
    git commit -m "$Message" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "No changes to commit or commit failed. Continuing to push."
    }

    Write-Host "Pushing to origin/$branch..."
    git push origin $branch

    Write-Host "Done. Now go to the Render dashboard and ensure the service is linked to this repo and redeploy if needed."
    Write-Host "Also verify the environment variable HIBP_API_KEY is set in the service settings."
} catch {
    Write-Error "Error: $($_.Exception.Message)"
} finally {
    Pop-Location
}
