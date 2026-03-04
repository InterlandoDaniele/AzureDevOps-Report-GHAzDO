$ErrorActionPreference = "Stop"

$useServicePrincipal = $false
$authHeader = $null
$SP_CLIENT_ID = $env:ClientId
$SP_CLIENT_SECRET = $env:ClientSecret
$SP_TENANT_ID = $env:TenantId

# Helper HTTP con retry e optionale ritorno della response completa
function Invoke-ApiWithRetry {
    param(
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$Url,
        $Headers = $null,
        $Body = $null,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 30,
        [switch]$ReturnResponse
    )
    $delay = 2
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            if ($ReturnResponse) {
                return Invoke-WebRequest -Method $Method -Uri $Url -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
            } else {
                return Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers -Body $Body -TimeoutSec $TimeoutSec -ErrorAction Stop
            }
        } catch {
            $status = $null
            try { if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = $_.Exception.Response.StatusCode.value__ } } catch {}
            if ($status -eq 429 -and $i -lt $MaxRetries) {
                Start-Sleep -Seconds $delay
                $delay = [math]::Min($delay * 2, 60)
                continue
            }
            throw $_
        }
    }
}

if ($SP_CLIENT_ID -and $SP_CLIENT_SECRET -and $SP_TENANT_ID) {
    Write-Host "Service Principal variables rilevate - autenticazione Entra ID (Bearer token)"

    $tokenUrl = "https://login.microsoftonline.com/$SP_TENANT_ID/oauth2/v2.0/token"

    $body = @{
        client_id     = $SP_CLIENT_ID
        scope         = "499b84ac-1321-427f-aa17-267ca6975798/.default"
        client_secret = $SP_CLIENT_SECRET
        grant_type    = "client_credentials"
    }

    try {
        Write-Host "Richiesta token a: $tokenUrl"
        $formBody = ($body.GetEnumerator() | ForEach-Object { [uri]::EscapeDataString($_.Key) + '=' + [uri]::EscapeDataString($_.Value) }) -join '&'
        $tokenResponse = Invoke-ApiWithRetry -Method Post -Url $tokenUrl -Body $formBody -Headers @{ 'Content-Type' = 'application/x-www-form-urlencoded' }

        $accessToken = $tokenResponse.access_token
        if ($accessToken) { Write-Host "TOKEN OTTENUTO CON SUCCESSO (mascherato)" }

        $authHeader = @{
            Authorization  = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }

        $useServicePrincipal = $true
    }
    catch {
        Write-Warning "Errore ottenimento token Entra ID: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try { $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream()); $errorBody = $reader.ReadToEnd(); Write-Host "=== DETTAGLIO ERRORE ENTRA ID ==="; Write-Host $errorBody; Write-Host "=== FINE DETTAGLIO ==="; $reader.Close() } catch {}
        }
        # Resetta il flag: il fallback a SYSTEM_ACCESSTOKEN gestira' l'autenticazione
        $useServicePrincipal = $false
    }
}

# Fallback al vecchio metodo se SP non configurato o fallito
if (-not $useServicePrincipal) {
    Write-Warning "Service Principal non configurato o errore - fallback a System.AccessToken"
    $patToken = $env:SYSTEM_ACCESSTOKEN
    if (-not $patToken) { Write-Error "SYSTEM_ACCESSTOKEN non impostato o vuoto. Abilitare 'Allow scripts to access OAuth token' in pipeline."; exit 1 }
    $authHeader = @{
        Authorization  = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$patToken"))
        "Content-Type" = "application/json"
    }
}

# Header PAT separato per le API Git standard (repo listing, ecc.)
# Il SP Bearer token funziona solo per Advanced Security; per le API Git si usa sempre il PAT.
$_pat = $env:SYSTEM_ACCESSTOKEN
if ($_pat) {
    $patHeader = @{
        Authorization  = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$_pat"))
        "Content-Type" = "application/json"
    }
    Write-Host "PAT header costruito per API Git standard"
} else {
    $patHeader = $authHeader
    Write-Host "SYSTEM_ACCESSTOKEN non disponibile, uso authHeader per API Git"
}

$rawUri = $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI
Write-Host "Raw SYSTEM_TEAMFOUNDATIONCOLLECTIONURI: $rawUri"

if ($rawUri -match "^https://dev\.azure\.com/([^/]+)") {
    $orgShortName = $matches[1]
} elseif ($rawUri -match "^https://([^.]+)\.visualstudio\.com") {
    $orgShortName = $matches[1]
} else {
    Write-Host "ERRORE: Impossibile estrarre l'organizzazione da: $rawUri"
    exit 1
}
Write-Host "orgShortName estratto: $orgShortName"

$projName         = $env:SYSTEM_TEAMPROJECT
$apiVersion       = "7.2-preview.1"
$maxAlertsPerRepo = 1000

$encodedProjName = [uri]::EscapeDataString($projName)

$isLegacyTenant = $rawUri -match "\.visualstudio\.com"
# Con Service Principal (Bearer token) si deve usare dev.azure.com anche per tenant legacy.
# Il dominio visualstudio.com funziona solo con autenticazione Basic/PAT.
if ($useServicePrincipal) {
    $repoApiUrl = "https://dev.azure.com/$orgShortName/$encodedProjName/_apis/git/repositories?api-version=$apiVersion"
    Write-Host "Autenticazione SP: usando dominio dev.azure.com"
} elseif ($isLegacyTenant) {
    $repoApiUrl = "https://$orgShortName.visualstudio.com/$encodedProjName/_apis/git/repositories?api-version=$apiVersion"
    Write-Host "Tenant legacy rilevato, usando dominio: $orgShortName.visualstudio.com"
} else {
    $repoApiUrl = "https://dev.azure.com/$orgShortName/$encodedProjName/_apis/git/repositories?api-version=$apiVersion"
    Write-Host "Tenant moderno rilevato, usando dominio: dev.azure.com"
}
Write-Host "URL lista repositories: $repoApiUrl"

try {
    $repoResp      = Invoke-ApiWithRetry -Method Get -Url $repoApiUrl -Headers $patHeader -ReturnResponse
    $__raw = $repoResp.Content; if ($__raw -is [byte[]]) { $contentString = [System.Text.Encoding]::UTF8.GetString($__raw).TrimStart([char]0xFEFF) } else { $contentString = ([string]$__raw).TrimStart([char]0xFEFF) }
    Write-Host "Response ricevuta. Parsing JSON..."
    $reposJson = $contentString | ConvertFrom-Json
    Write-Host "Lista repositories ottenuta (trovati $($reposJson.count))"
} catch {
    Write-Host "Errore lista repositories: $($_.Exception.Message)"
    if ($_.Exception.Response) {
        try { $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream()); Write-Host "Response Body: $($reader.ReadToEnd())"; $reader.Close() } catch {}
    }
    exit 1
}

# RILEVA AUTOMATICAMENTE TUTTI I REPO CHECKOUTATI
$checkoutRepos = @()
$envVars = Get-ChildItem Env: | Where-Object { $_.Name -match '^BUILD_REPOSITORY_(.+)_NAME$' -and $_.Name -ne 'BUILD_REPOSITORY_NAME' }

foreach ($var in $envVars) {
    $alias    = $var.Name -replace '^BUILD_REPOSITORY_(.+)_NAME$', '$1'
    $repoName = $var.Value
    Write-Host "Trovato repo checkoutato: $repoName (alias: $alias)"

    $repoObj = $reposJson.value | Where-Object { $_.name -eq $repoName }
    if ($repoObj) {
        $repoId = $repoObj.id

        $repoBranchVar = "BUILD_REPOSITORY_${alias}_SOURCEBRANCH"
        $repoBranch = if (Test-Path Env:$repoBranchVar) { (Get-Item Env:$repoBranchVar).Value } else { $env:BUILD_SOURCEBRANCH }

        $checkoutRepos += @{
            Name   = $repoName
            Id     = $repoId
            Branch = $repoBranch
        }
    } else {
        Write-Warning "Repo $repoName non trovato in lista API - salto"
    }
}

if ($checkoutRepos.Count -eq 0) {
    Write-Host "Nessun repo checkoutato rilevato: fallback a repo della pipeline"
    $repoName = $env:BUILD_REPOSITORY_NAME
    $repoObj  = $reposJson.value | Where-Object { $_.name -eq $repoName }
    if ($repoObj) {
        $repoId = $repoObj.id
        $checkoutRepos += @{
            Name   = $repoName
            Id     = $repoId
            Branch = $env:BUILD_SOURCEBRANCH
        }
    } else {
        Write-Host "Nessun repo trovato: errore"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# DEFINIZIONI FUNZIONI HELPER
# ---------------------------------------------------------------------------

function Extract-Properties {
    param($object, $prefix = "")
    $properties = @{}
    if ($object -is [PSCustomObject]) {
        foreach ($prop in $object.PSObject.Properties) {
            $key = if ($prefix) { "$prefix.$($prop.Name)" } else { $prop.Name }
            if ($prop.Value -is [Array] -and $prop.Value.Count -gt 0) {
                for ($i = 0; $i -lt $prop.Value.Count; $i++) {
                    $properties += Extract-Properties -object $prop.Value[$i] -prefix "$key[$i]"
                }
            } elseif ($prop.Value -is [PSCustomObject]) {
                $properties += Extract-Properties -object $prop.Value -prefix $key
            } else {
                $properties[$key] = $prop.Value
            }
        }
    }
    return $properties
}

function Get-CveDetails {
    param($cveId)
    $nvdApiUrl  = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cveId"
    $maxRetries = 3
    $retryDelay = 15
    for ($retry = 1; $retry -le $maxRetries; $retry++) {
        try {
            Write-Host "Richiedendo dati per CVE: $cveId (tentativo $retry)"
            $response = Invoke-RestMethod -Uri $nvdApiUrl -Method Get -ErrorAction Stop -TimeoutSec 30
            Start-Sleep -Seconds 6
            $cveData = $response.vulnerabilities[0].cve
            if ($cveData) {
                $metrics = $null
                $version = "N/A"
                if ($cveData.metrics.cvssMetricV40)     { $metrics = $cveData.metrics.cvssMetricV40[0];  $version = "4.0" }
                elseif ($cveData.metrics.cvssMetricV31) { $metrics = $cveData.metrics.cvssMetricV31[0];  $version = "3.1" }
                elseif ($cveData.metrics.cvssMetricV30) { $metrics = $cveData.metrics.cvssMetricV30[0];  $version = "3.0" }
                $cvssScore  = if ($metrics) { $metrics.cvssData.baseScore } else { "N/A" }
                $severity   = if ($metrics -and $metrics.cvssData.PSObject.Properties.Name -contains "baseSeverity") { $metrics.cvssData.baseSeverity } else { "N/A" }
                $vector     = if ($metrics) { $metrics.cvssData.vectorString } else { "N/A" }
                $patchAvailable = $false
                $exploitPublic  = $false
                if ($cveData.references) {
                    foreach ($ref in $cveData.references) {
                        if ("Patch" -in $ref.tags -or "Vendor Advisory" -in $ref.tags) { $patchAvailable = $true }
                        $url = $ref.url.ToLower()
                        if ($url -match "exploit|exploit-db|packetstorm|metasploit|github.com") { $exploitPublic = $true }
                    }
                }
                return [PSCustomObject]@{
                    CVEId          = $cveId
                    CVSSScore      = $cvssScore
                    CVSSVersion    = $version
                    Severity       = $severity
                    Vector         = $vector
                    PatchAvailable = $patchAvailable
                    ExploitPublic  = $exploitPublic
                }
            }
            Write-Host "Nessun dato trovato per CVE: $cveId"
            return [PSCustomObject]@{ CVEId=$cveId; CVSSScore="N/A"; CVSSVersion="N/A"; Severity="N/A"; Vector="N/A"; PatchAvailable=$false; ExploitPublic=$false }
        } catch {
            Write-Host "Errore durante la richiesta per CVE: $cveId - $_"
            try { $status = if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $_.Exception.Response.StatusCode.value__ } else { $null } } catch { $status = $null }
            if ($retry -lt $maxRetries -and $status -eq 429) {
                Write-Host "Rate limit rilevato, ritento tra $retryDelay secondi (tentativo $retry/$maxRetries)"
                Start-Sleep -Seconds $retryDelay
            } else {
                return [PSCustomObject]@{ CVEId=$cveId; CVSSScore="N/A"; CVSSVersion="N/A"; Severity="N/A"; Vector="N/A"; PatchAvailable=$false; ExploitPublic=$false }
            }
        }
    }
    return [PSCustomObject]@{ CVEId=$cveId; CVSSScore="N/A"; CVSSVersion="N/A"; Severity="N/A"; Vector="N/A"; PatchAvailable=$false; ExploitPublic=$false }
}

function Load-EpssData {
    $epssUrl = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    $tmpFile = Join-Path $env:TEMP "epss_$([Guid]::NewGuid()).csv.gz"
    try {
        Invoke-WebRequest -Uri $epssUrl -OutFile $tmpFile -ErrorAction Stop
        $stream = New-Object IO.Compression.GzipStream([IO.File]::OpenRead($tmpFile), [IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object IO.StreamReader($stream)
        $data   = @{}
        $header = $reader.ReadLine()
        while (-not $reader.EndOfStream) {
            $line  = $reader.ReadLine()
            $parts = $line -split ","
            if ($parts.Length -ge 3) { $data[$parts[0]] = @{ "EPSS" = $parts[1]; "Percentile" = $parts[2] } }
        }
        $reader.Close()
        $stream.Close()
        return $data
    } catch {
        Write-Host "Errore in Load-EpssData: $_"
        return @{}
    } finally {
        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
    }
}

function Load-CisaKev {
    $url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try {
        $resp          = Invoke-ApiWithRetry -Method Get -Url $url -TimeoutSec 20 -ReturnResponse
        $__raw = $resp.Content; if ($__raw -is [byte[]]) { $contentString = [System.Text.Encoding]::UTF8.GetString($__raw).TrimStart([char]0xFEFF) } else { $contentString = ([string]$__raw).TrimStart([char]0xFEFF) }
        return ($contentString | ConvertFrom-Json).vulnerabilities.cveID
    } catch {
        Write-Host "Errore in Load-CisaKev: $_"
        return @()
    }
}

# ---------------------------------------------------------------------------
# FUNZIONI DI QUERY ALERT — definite PRIMA del loop sui repository
# ---------------------------------------------------------------------------

function Get-SecurityAlerts {
    $advsecDomain  = if ($useServicePrincipal -or -not $isLegacyTenant) { "advsec.dev.azure.com/$orgShortName" } else { "$orgShortName.advsec.visualstudio.com" }
    $encodedBranch = [uri]::EscapeDataString($buildBranch)
    $alertsUrls = @(
        "https://$advsecDomain/$encodedProjName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion`&criteria.alertType=1`&criteria.alertState=active`&criteria.ref=$encodedBranch`&top=$maxAlertsPerRepo",
        "https://$advsecDomain/$encodedProjName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion`&criteria.alertType=code`&criteria.alertState=active`&criteria.ref=$encodedBranch`&top=$maxAlertsPerRepo"
    )
    if ($env:BUILD_DEFINITIONNAME) {
        $encodedPipelineName = [uri]::EscapeDataString($env:BUILD_DEFINITIONNAME)
        $alertsUrls = $alertsUrls | ForEach-Object { $_ + "`&criteria.pipelineName=$encodedPipelineName" }
    }
    $allAlerts = @()
    $alertIds  = @{}
    foreach ($alertsUrl in $alertsUrls) {
        $nextLink = $null
        do {
            $currentUrl = if ($nextLink) { $nextLink } else { $alertsUrl }
            Write-Host "Chiamata API per alert di sicurezza: $currentUrl"
            try {
                $apiResponse   = Invoke-ApiWithRetry -Method Get -Url $currentUrl -Headers $authHeader -ReturnResponse
                $__raw = $apiResponse.Content; if ($__raw -is [byte[]]) { $contentString = [System.Text.Encoding]::UTF8.GetString($__raw).TrimStart([char]0xFEFF) } else { $contentString = ([string]$__raw).TrimStart([char]0xFEFF) }
                $json          = $contentString | ConvertFrom-Json
                if ($json.value.Count -eq $maxAlertsPerRepo) { Write-Host "Limite $maxAlertsPerRepo alert raggiunto per $alertsUrl" }
                if ($json.PSObject.Properties.Name -contains "value" -and $json.value) {
                    foreach ($alert in $json.value) {
                        if ($alert.gitRef -ne $buildBranch) { Write-Host "Ignorato alert con gitRef $($alert.gitRef), atteso $buildBranch"; continue }
                        $alertId = if ($alert.PSObject.Properties.Name -contains "alertId") { $alert.alertId } else { "N/A" }
                        if ($alertIds.ContainsKey($alertId)) { Write-Host "Alert $alertId duplicato, ignorato"; continue }
                        $alertIds[$alertId] = $true
                        $alertProps = Extract-Properties -object $alert
                        $alertType  = if ($alert.PSObject.Properties.Name -contains "alertType") { $alert.alertType } else { "N/A" }
                        $cveId = ($alertProps.Keys | Where-Object { $_ -like "*cveId" } | ForEach-Object { $alertProps[$_] } | Where-Object { $_ }) | Select-Object -First 1
                        if ($cveId) {
                            $cveDetails = Get-CveDetails -cveId $cveId
                            $epssInfo   = if ($epssData.ContainsKey($cveId)) { $epssData[$cveId] } else { @{ "EPSS" = "N/A"; "Percentile" = "N/A" } }
                            $isKev      = if ($cisaKev -contains $cveId) { "Yes" } else { "No" }
                            $priority   = if ($isKev -eq "Yes" -or $cveDetails.ExploitPublic) { "CRITICA" }
                                          elseif (($cveDetails.CVSSScore -ne "N/A" -and [double]$cveDetails.CVSSScore -ge 8) -or
                                                  ($epssInfo.EPSS -ne "N/A" -and [double]$epssInfo.EPSS -ge 0.5)) { "ALTA" }
                                          elseif (($cveDetails.CVSSScore -ne "N/A" -and [double]$cveDetails.CVSSScore -ge 6) -or
                                                  ($epssInfo.EPSS -ne "N/A" -and [double]$epssInfo.EPSS -ge 0.2)) { "MEDIA" }
                                          else { "BASSA" }
                        } else {
                            $cveId      = "N/A"
                            $cveDetails = [PSCustomObject]@{ CVSSScore="N/A"; CVSSVersion="N/A"; Severity="N/A"; Vector="N/A"; PatchAvailable=$false; ExploitPublic=$false }
                            $epssInfo   = @{ "EPSS" = "N/A"; "Percentile" = "N/A" }
                            $isKev      = "N/A"
                            $priority   = "N/A"
                        }
                        $locationFiles = @()
                        $locationLines = @()
                        foreach ($location in $alert.physicalLocations) {
                            if ($location.filePath -and $location.region.lineStart) {
                                $locationFiles += $location.filePath
                                $locationLines += $location.region.lineStart
                            }
                        }
                        $locationFile = if ($locationFiles) { $locationFiles -join "; " } else { "N/A" }
                        $locationLine = if ($locationLines) { $locationLines -join "; " } else { "N/A" }
                        $description  = if ($alert.tools -and $alert.tools[0].rules -and $alert.tools[0].rules[0].description) { $alert.tools[0].rules[0].description } else { if ($alert.title) { $alert.title } else { "N/A" } }
                        $state        = if ($alert.PSObject.Properties.Name -contains "state") { $alert.state } else { "N/A" }
                        $linkItem     = "https://dev.azure.com/$orgShortName/$projName/_git/$repoId/alerts/$alertId"
                        $alertObj     = $alert
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedCVEId"          -Value $cveId
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedCVSSScore"      -Value $cveDetails.CVSSScore
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedCVSSVersion"    -Value $cveDetails.CVSSVersion
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedSeverity"       -Value $cveDetails.Severity
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedAlertSeverity"  -Value $alert.severity
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedVector"         -Value $cveDetails.Vector
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedEPSS"           -Value $epssInfo.EPSS
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedEPSSPercentile" -Value $epssInfo.Percentile
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedCISA_KEV"       -Value $isKev
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedPatchAvailable" -Value $cveDetails.PatchAvailable
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedExploitPublic"  -Value $cveDetails.ExploitPublic
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedPriority"       -Value $priority
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationFile"   -Value $locationFile
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationLine"   -Value $locationLine
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationFiles"  -Value $locationFiles
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationLines"  -Value $locationLines
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedDescription"    -Value $description
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedState"          -Value $state
                        $alertObj | Add-Member -MemberType NoteProperty -Name "EnhancedLinkItem"       -Value $linkItem
                        $alertObj | Add-Member -MemberType NoteProperty -Name "NomeRepo"               -Value $repoName
                        $allAlerts += $alertObj
                        Write-Host "Alert aggiunto: ID=$alertId, Type=$alertType, CVE=$cveId"
                    }
                }
                $nextLink = if ($json.PSObject.Properties.Name -contains "@odata.nextLink") { $json."@odata.nextLink" } else { $null }
                Write-Host "NextLink: $nextLink"
            } catch {
                Write-Host "Errore in Get-SecurityAlerts: $_"
                try { $status = if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $_.Exception.Response.StatusCode.value__ } else { $null } } catch { $status = $null }
                if ($status -eq 429) { Write-Host "Rate limit, retry in 5s..."; Start-Sleep -Seconds 5; continue }
                elseif ($status -eq 401 -or $status -eq 403) {
                    Write-Warning "Accesso negato (HTTP $status) agli alert di sicurezza per repo $repoId. Il Service Principal deve essere aggiunto come membro del progetto con permesso 'Advanced Security: Read alerts'. Repo saltato."
                    return @()
                }
                elseif ($status -eq 404) {
                    Write-Warning "Progetto o repo non trovato (HTTP 404) per repo $repoId. Il Service Principal potrebbe non avere accesso al progetto Azure DevOps. Repo saltato."
                    return @()
                }
                else { throw $_ }
            }
        } while ($nextLink)
    }
    Write-Host "Totale alert di sicurezza raccolti: $($allAlerts.Count)"
    return $allAlerts
}

function Get-SecretAlerts {
    $advsecDomain = if ($useServicePrincipal -or -not $isLegacyTenant) { "advsec.dev.azure.com/$orgShortName" } else { "$orgShortName.advsec.visualstudio.com" }
    $alertsUrls = @(
        "https://$advsecDomain/$encodedProjName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion`&criteria.alertType=secret`&criteria.alertState=active`&top=$maxAlertsPerRepo",
        "https://$advsecDomain/$encodedProjName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion`&criteria.alertType=secret`&criteria.confidenceLevels=other`&criteria.alertState=active`&top=$maxAlertsPerRepo"
    )
    $secretAlerts = @()
    $alertIds     = @{}
    foreach ($alertsUrl in $alertsUrls) {
        $tokenFilter = ""
        $oldToken    = ""
        do {
            $currentUrl = if ($tokenFilter) { "$alertsUrl`&continuationToken=$tokenFilter" } else { $alertsUrl }
            Write-Host "Chiamata API per segreti: $currentUrl"
            try {
                $apiResponse   = Invoke-ApiWithRetry -Method Get -Url $currentUrl -Headers $authHeader -ReturnResponse
                $__raw = $apiResponse.Content; if ($__raw -is [byte[]]) { $contentString = [System.Text.Encoding]::UTF8.GetString($__raw).TrimStart([char]0xFEFF) } else { $contentString = ([string]$__raw).TrimStart([char]0xFEFF) }
                $json          = $contentString | ConvertFrom-Json
                $secretCount   = ($json.value | Where-Object { $_.alertType -eq 'secret' }).Count
                Write-Host "Numero di segreti trovati nell'API: $secretCount"
                Write-Host "Secret Alerts Response: $($json.value | Where-Object { $_.alertType -eq 'secret' } | ConvertTo-Json -Depth 5)"
                $highConfidenceCount = ($json.value | Where-Object { $_.alertType -eq 'secret' -and $_.confidence -eq 'high' }).Count
                Write-Host "Segreti con confidence=high trovati: $highConfidenceCount"
                if ($json.PSObject.Properties.Name -contains "value" -and $json.value) {
                    foreach ($alert in $json.value) {
                        Write-Host "Elaborazione alert: ID=$($alert.alertId), Type=$($alert.alertType), GitRef=$($alert.gitRef), State=$($alert.state)"
                        if ($alert.alertType -ne "secret") { continue }
                        $alertId = if ($alert.PSObject.Properties.Name -contains "alertId") { $alert.alertId } else { "N/A" }
                        if ($alertIds.ContainsKey($alertId)) { Write-Host "Alert $alertId duplicato, ignorato"; continue }
                        $alertIds[$alertId] = $true
                        $secretType    = if ($alert.PSObject.Properties.Name -contains "title") { $alert.title } else { "N/A" }
                        $locationFiles = @()
                        $locationLines = @()
                        foreach ($location in $alert.physicalLocations) {
                            if ($location.filePath -and $location.region.lineStart) {
                                $locationFiles += $location.filePath
                                $locationLines += $location.region.lineStart
                            }
                        }
                        $locationFile    = if ($locationFiles) { $locationFiles -join "; " } else { "N/A" }
                        $locationLine    = if ($locationLines) { $locationLines -join "; " } else { "N/A" }
                        $description     = if ($alert.tools[0].rules[0].description) { $alert.tools[0].rules[0].description } else { if ($alert.title) { $alert.title } else { "N/A" } }
                        $state           = if ($alert.PSObject.Properties.Name -contains "state")           { $alert.state }           else { "N/A" }
                        $confidence      = if ($alert.PSObject.Properties.Name -contains "confidence")      { $alert.confidence }      else { "N/A" }
                        $severity        = if ($alert.PSObject.Properties.Name -contains "severity")        { $alert.severity }        else { "N/A" }
                        $firstSeenDate   = if ($alert.PSObject.Properties.Name -contains "firstSeenDate")   { $alert.firstSeenDate }   else { "N/A" }
                        $lastSeenDate    = if ($alert.PSObject.Properties.Name -contains "lastSeenDate")    { $alert.lastSeenDate }    else { "N/A" }
                        $introducedDate  = if ($alert.PSObject.Properties.Name -contains "introducedDate")  { $alert.introducedDate }  else { "N/A" }
                        $dismissalType   = if ($alert.dismissal -and $alert.dismissal.PSObject.Properties.Name -contains "dismissalType") { $alert.dismissal.dismissalType } else { "N/A" }
                        $dismissalUser   = if ($alert.dismissal -and $alert.dismissal.stateChangedByIdentity) { $alert.dismissal.stateChangedByIdentity.displayName } else { "N/A" }
                        $dismissalComment= if ($alert.dismissal -and $alert.dismissal.PSObject.Properties.Name -contains "message")      { $alert.dismissal.message }      else { "N/A" }
                        $dismissalDate   = if ($alert.dismissal -and $alert.dismissal.PSObject.Properties.Name -contains "requestedOn")  { $alert.dismissal.requestedOn }  else { "N/A" }
                        $linkItem        = "https://dev.azure.com/$orgShortName/$projName/_git/$repoId/alerts/$alertId"
                        $gitRef          = if ($alert.PSObject.Properties.Name -contains "gitRef") { $alert.gitRef } else { "N/A" }
                        $secretObj       = $alert
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedSecretType"       -Value $secretType
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationFile"     -Value $locationFile
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationLine"     -Value $locationLine
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationFiles"    -Value $locationFiles
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedLocationLines"    -Value $locationLines
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedDescription"      -Value $description
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedState"            -Value $state
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedConfidence"       -Value $confidence
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedSeverity"         -Value $severity
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedFirstSeenDate"    -Value $firstSeenDate
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedLastSeenDate"     -Value $lastSeenDate
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedIntroducedDate"   -Value $introducedDate
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedDismissalType"    -Value $dismissalType
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedDismissalUser"    -Value $dismissalUser
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedDismissalComment" -Value $dismissalComment
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedDismissalDate"    -Value $dismissalDate
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedLinkItem"         -Value $linkItem
                        $secretObj | Add-Member -MemberType NoteProperty -Name "EnhancedGitRef"           -Value $gitRef
                        $secretObj | Add-Member -MemberType NoteProperty -Name "NomeRepo"                 -Value $repoName
                        $secretAlerts += $secretObj
                        Write-Host "Segreto aggiunto: ID=$alertId, SecretType=$secretType, Confidence=$confidence"
                    }
                }
                $continuationToken = $apiResponse.Headers["x-ms-continuationtoken"]
                if ($continuationToken -and $continuationToken -ne $oldToken) { $tokenFilter = $continuationToken; $oldToken = $continuationToken } else { $tokenFilter = "" }
            } catch {
                Write-Host "Errore nella chiamata API: $_"
                try { $status = if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $_.Exception.Response.StatusCode.value__ } else { $null } } catch { $status = $null }
                if ($status -eq 429) { Write-Host "Rate limit, retry in 5s..."; Start-Sleep -Seconds 5; continue }
                elseif ($status -eq 401 -or $status -eq 403) {
                    Write-Warning "Accesso negato (HTTP $status) agli alert secrets per repo $repoId. Il Service Principal deve essere aggiunto come membro del progetto con permesso 'Advanced Security: Read alerts'. Repo saltato."
                    return @()
                }
                elseif ($status -eq 404) {
                    Write-Warning "Progetto o repo non trovato (HTTP 404) per repo $repoId. Il Service Principal potrebbe non avere accesso al progetto Azure DevOps. Repo saltato."
                    return @()
                }
                else { throw $_ }
            }
        } while ($tokenFilter)
    }
    Write-Host "Totale segreti raccolti: $($secretAlerts.Count)"
    return $secretAlerts
}

# ---------------------------------------------------------------------------
# LOOP ESECUZIONE PER OGNI REPOSITORY
# ---------------------------------------------------------------------------

$timeStamp = Get-Date -Format "yyyyMMdd_HHmmss"

foreach ($repo in $checkoutRepos) {
    $repoName    = $repo.Name
    $repoId      = $repo.Id
    $buildBranch = $repo.Branch

    Write-Host "===== INIZIO ANALISI per repo: $repoName (ID: $repoId, branch: $buildBranch) ====="

    $outputDir = "AdvancedSecurityReport_${repoName}_$timeStamp"
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

    $epssData = Load-EpssData
    $cisaKev  = Load-CisaKev

    $securityAlerts = Get-SecurityAlerts
    $secretAlerts   = Get-SecretAlerts

    # ---------------------------------------------------------------------------
    # ESECUZIONE PRINCIPALE
    # ---------------------------------------------------------------------------

    if (-not $securityAlerts -or $securityAlerts.Count -eq 0) {
        $dummySecurity = [PSCustomObject]@{
            alertId = "N/A"; severity = "N/A"; title = "N/A"; tools = @(); dismissal = $null; repositoryId = $null
            projectId = "00000000-0000-0000-0000-000000000000"; repositoryUrl = "N/A"; gitRef = "N/A"; alertType = "N/A"
            firstSeenDate = "N/A"; lastSeenDate = "N/A"; fixedDate = "N/A"; introducedDate = "N/A"; state = "N/A"
            physicalLocations = @(); logicalLocations = @(); hasTrustedSourceOrigin = $false
            EnhancedCVEId = "N/A"; EnhancedCVSSScore = "N/A"; EnhancedCVSSVersion = "N/A"; EnhancedSeverity = "N/A"
            EnhancedAlertSeverity = "N/A"; EnhancedVector = "N/A"; EnhancedEPSS = "N/A"; EnhancedEPSSPercentile = "N/A"
            EnhancedCISA_KEV = "N/A"; EnhancedPatchAvailable = $false; EnhancedExploitPublic = $false
            EnhancedPriority = "N/A"; EnhancedLocationFile = "N/A"; EnhancedLocationLine = "N/A"
            EnhancedLocationFiles = @(); EnhancedLocationLines = @(); EnhancedDescription = "N/A"
            EnhancedState = "N/A"; EnhancedLinkItem = "N/A"; NomeRepo = $repoName
        }
        $securityAlerts += $dummySecurity
    }

    if (-not $secretAlerts -or $secretAlerts.Count -eq 0) {
        $dummySecret = [PSCustomObject]@{
            alertId = "N/A"; alertType = "secret"; title = "N/A"; physicalLocations = @(); tools = @()
            state = "N/A"; confidence = "N/A"; severity = "N/A"; firstSeenDate = "N/A"; lastSeenDate = "N/A"
            introducedDate = "N/A"; dismissal = $null; repositoryUrl = "N/A"; gitRef = "N/A"
            EnhancedSecretType = "N/A"; EnhancedLocationFile = "N/A"; EnhancedLocationLine = "N/A"
            EnhancedLocationFiles = @(); EnhancedLocationLines = @(); EnhancedDescription = "N/A"
            EnhancedState = "N/A"; EnhancedConfidence = "N/A"; EnhancedSeverity = "N/A"
            EnhancedFirstSeenDate = "N/A"; EnhancedLastSeenDate = "N/A"; EnhancedIntroducedDate = "N/A"
            EnhancedDismissalType = "N/A"; EnhancedDismissalUser = "N/A"; EnhancedDismissalComment = "N/A"
            EnhancedDismissalDate = "N/A"; EnhancedLinkItem = "N/A"; EnhancedGitRef = "N/A"; NomeRepo = $repoName
        }
        $secretAlerts += $dummySecret
    }

    # ---------------------------------------------------------------------------
    # EXPORT CSV
    # ---------------------------------------------------------------------------

    $detailedCsv     = Join-Path $outputDir "AdvancedSecurityReport_Detailed_${timeStamp}.csv"
    $flattenedAlerts = $securityAlerts | ForEach-Object {
        $props = Extract-Properties -object $_
        $enhancedObj = [PSCustomObject]@{
            AlertId               = $_.alertId
            EnhancedCVEId         = $_.EnhancedCVEId
            EnhancedCVSSScore     = $_.EnhancedCVSSScore
            EnhancedCVSSVersion   = $_.EnhancedCVSSVersion
            EnhancedSeverity      = $_.EnhancedSeverity
            EnhancedAlertSeverity = $_.EnhancedAlertSeverity
            EnhancedVector        = $_.EnhancedVector
            EnhancedEPSS          = $_.EnhancedEPSS
            EnhancedEPSSPercentile= $_.EnhancedEPSSPercentile
            EnhancedCISA_KEV      = $_.EnhancedCISA_KEV
            EnhancedPatchAvailable= $_.EnhancedPatchAvailable
            EnhancedExploitPublic = $_.EnhancedExploitPublic
            EnhancedPriority      = $_.EnhancedPriority
            GitRef                = $_.gitRef
            FirstSeenDate         = $_.firstSeenDate
            AlertType             = $_.alertType
            EnhancedLocationFile  = $_.EnhancedLocationFile
            EnhancedLocationLine  = $_.EnhancedLocationLine
            EnhancedDescription   = $_.EnhancedDescription
            EnhancedState         = $_.state
            EnhancedLinkItem      = $_.EnhancedLinkItem
            NomeRepo              = $repoName
        }
        foreach ($k in $props.Keys) {
            if ($enhancedObj.PSObject.Properties.Name -notcontains $k) {
                $enhancedObj | Add-Member -MemberType NoteProperty -Name $k -Value $props[$k]
            }
        }
        $enhancedObj
    }
    $flattenedAlerts | Export-Csv -Path $detailedCsv -NoTypeInformation -Encoding UTF8

    $aggCve = $securityAlerts | Where-Object { $_.EnhancedCVEId -ne "N/A" } | Group-Object EnhancedCVEId | ForEach-Object {
        $alertIds = $_.Group | ForEach-Object { $_.alertId } | Where-Object { $_ -ne $null -and $_ -ne "" }
        [PSCustomObject]@{
            CVEId                 = $_.Name
            AlertIDs              = ($alertIds -join "; ")
            AlertIdsArray         = $alertIds
            EnhancedCVSSScore     = ($_.Group | Select-Object -First 1).EnhancedCVSSScore
            EnhancedCVSSVersion   = ($_.Group | Select-Object -First 1).EnhancedCVSSVersion
            EnhancedSeverity      = ($_.Group | Select-Object -First 1).EnhancedSeverity
            EnhancedAlertSeverity = ($_.Group | Select-Object -First 1).EnhancedAlertSeverity
            EnhancedVector        = ($_.Group | Select-Object -First 1).EnhancedVector
            EnhancedEPSS          = ($_.Group | Select-Object -First 1).EnhancedEPSS
            EnhancedEPSSPercentile= ($_.Group | Select-Object -First 1).EnhancedEPSSPercentile
            EnhancedCISA_KEV      = ($_.Group | Select-Object -First 1).EnhancedCISA_KEV
            EnhancedPatchAvailable= ($_.Group | Select-Object -First 1).EnhancedPatchAvailable
            EnhancedExploitPublic = ($_.Group | Select-Object -First 1).EnhancedExploitPublic
            EnhancedPriority      = ($_.Group | Select-Object -First 1).EnhancedPriority
            CountAlerts           = $_.Group.Count
            NomeRepo              = $repoName
        }
    }
    $aggregatedCsv = Join-Path $outputDir "AdvancedSecurityReport_Aggregated_${timeStamp}.csv"
    $aggCve | Export-Csv -Path $aggregatedCsv -NoTypeInformation -Encoding UTF8

    $secretsCsv       = Join-Path $outputDir "AdvancedSecurityReport_Secrets_${timeStamp}.csv"
    $flattenedSecrets = $secretAlerts | ForEach-Object {
        $props = Extract-Properties -object $_
        $enhancedObj = [PSCustomObject]@{
            AlertId                 = $_.alertId
            AlertType               = $_.alertType
            EnhancedSecretType      = $_.EnhancedSecretType
            EnhancedLocationFile    = $_.EnhancedLocationFile
            EnhancedLocationLine    = $_.EnhancedLocationLine
            EnhancedDescription     = $_.EnhancedDescription
            EnhancedState           = $_.EnhancedState
            EnhancedConfidence      = $_.EnhancedConfidence
            EnhancedSeverity        = $_.EnhancedSeverity
            EnhancedFirstSeenDate   = $_.EnhancedFirstSeenDate
            EnhancedLastSeenDate    = $_.EnhancedLastSeenDate
            EnhancedIntroducedDate  = $_.EnhancedIntroducedDate
            EnhancedDismissalType   = $_.EnhancedDismissalType
            EnhancedDismissalUser   = $_.EnhancedDismissalUser
            EnhancedDismissalComment= $_.EnhancedDismissalComment
            EnhancedDismissalDate   = $_.EnhancedDismissalDate
            EnhancedLinkItem        = $_.EnhancedLinkItem
            EnhancedGitRef          = $_.EnhancedGitRef
            NomeRepo                = $repoName
        }
        foreach ($k in $props.Keys) {
            if ($enhancedObj.PSObject.Properties.Name -notcontains $k) {
                $enhancedObj | Add-Member -MemberType NoteProperty -Name $k -Value $props[$k]
            }
        }
        $enhancedObj
    }
    $flattenedSecrets | Export-Csv -Path $secretsCsv -NoTypeInformation -Encoding UTF8

    # ---------------------------------------------------------------------------
    # EXPORT JSON
    # ---------------------------------------------------------------------------

    $detailedJson   = Join-Path $outputDir "AdvancedSecurityReport_Detailed_${timeStamp}.json"
    $aggregatedJson = Join-Path $outputDir "AdvancedSecurityReport_Aggregated_${timeStamp}.json"
    $secretsJson    = Join-Path $outputDir "AdvancedSecurityReport_Secrets_${timeStamp}.json"

    $securityAlerts | ConvertTo-Json -Depth 10 | Out-File -FilePath $detailedJson   -Encoding UTF8
    $aggCve         | ConvertTo-Json -Depth 10 | Out-File -FilePath $aggregatedJson -Encoding UTF8
    $secretAlerts   | ConvertTo-Json -Depth 10 | Out-File -FilePath $secretsJson    -Encoding UTF8

    $detailedCsvFull    = (Resolve-Path $detailedCsv).Path
    $aggregatedCsvFull  = (Resolve-Path $aggregatedCsv).Path
    $secretsCsvFull     = (Resolve-Path $secretsCsv).Path
    $detailedJsonFull   = (Resolve-Path $detailedJson).Path
    $aggregatedJsonFull = (Resolve-Path $aggregatedJson).Path
    $secretsJsonFull    = (Resolve-Path $secretsJson).Path

    Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_Detailed_${repoName};]$detailedCsvFull"
    Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_Aggregated_${repoName};]$aggregatedCsvFull"
    Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_Secrets_${repoName};]$secretsCsvFull"
    Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_DetailedJson_${repoName};]$detailedJsonFull"
    Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_AggregatedJson_${repoName};]$aggregatedJsonFull"
    Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_SecretsJson_${repoName};]$secretsJsonFull"
}
