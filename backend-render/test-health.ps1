param(
    [string]$BaseUrl = "http://localhost:3000"
)

Write-Host "Testing health endpoints at $BaseUrl"

try {
    Write-Host "GET /"
    $root = Invoke-RestMethod -Uri "$BaseUrl/" -Method GET -ErrorAction Stop
    $root | ConvertTo-Json -Depth 5 | Write-Host

    Write-Host "GET /api/stats"
    $stats = Invoke-RestMethod -Uri "$BaseUrl/api/stats" -Method GET -ErrorAction Stop
    $stats | ConvertTo-Json -Depth 5 | Write-Host

    Write-Host "Done."
} catch {
    Write-Host "Request failed: $($_.Exception.Message)"
}
