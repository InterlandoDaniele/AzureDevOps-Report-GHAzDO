#Task da inserire nella pipeline per richiamare lo script#


#$ErrorActionPreference = "Stop"
#$scriptUrl = ""
#$authHeader = @{Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($env:SYSTEM_ACCESSTOKEN)"))}
#$tempScriptPath = "$(System.DefaultWorkingDirectory)/....."
#Write-Host "Downloading script from $scriptUrl"
#Invoke-WebRequest -Uri $scriptUrl -Headers $authHeader -OutFile $tempScriptPath -UseBasicParsing
#Write-Host "Executing script: $tempScriptPath"
#& $tempScriptPath

$ErrorActionPreference = "Stop"
Write-Host "Raw SYSTEM_TEAMFOUNDATIONCOLLECTIONURI: $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"
$orgName = $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI -replace "^https://dev\.azure\.com/", "" -replace "/$", ""
$orgName = $orgName -replace "^https://", "" -replace "//", "/"
if ($orgName -notmatch "\.visualstudio\.com") {
    $orgName = "$orgName.visualstudio.com"
}
$projName = $env:SYSTEM_TEAMPROJECT
$repoName = $env:BUILD_REPOSITORY_NAME
$patToken = $env:SYSTEM_ACCESSTOKEN
$apiVersion = "7.2-preview.1"
$maxAlertsPerRepo = 500
$buildBranch = $env:BUILD_SOURCEBRANCH
if (-not $orgName -or -not $projName -or -not $repoName -or -not $patToken -or -not $buildBranch) { 
    $patTokenStatus = if ($patToken) { "Present" } else { "Missing" }
    Write-Host "Variabili d'ambiente mancanti: orgName=$orgName, projName=$projName, repoName=$repoName, patToken=[$patTokenStatus], buildBranch=$buildBranch"; 
    exit 1 
}
$authHeader = @{Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$patToken"));"Content-Type" = "application/json"}
Write-Host "orgName: $orgName"
Write-Host "projName: $projName"
$repoApiUrl = "https://$orgName/$projName/_apis/git/repositories?api-version=$apiVersion"
Write-Host "URL generato: $repoApiUrl"  # Debug per verificare l'URL
Write-Host "AuthHeader generato: $($authHeader.Authorization)"  # Debug per verificare l'header
Write-Host "PAT length: $($patToken.Length)"  # Debug per verificare la lunghezza del token
$systemAccessTokenStatus = if ($env:SYSTEM_ACCESSTOKEN) { "Yes" } else { "No" }
Write-Host "Environment SYSTEM_ACCESSTOKEN available: $systemAccessTokenStatus"  # Debug per verificare la variabile
# Verifica esplicita del token
if ([string]::IsNullOrEmpty($patToken) -or $patToken.Length -lt 10) {
    Write-Host "Errore: Il token PAT sembra non valido o troppo corto. Lunghezza: $($patToken.Length)"
    exit 1
}
try {
    $repoData = Invoke-WebRequest -Uri $repoApiUrl -Headers $authHeader -Method Get -UseBasicParsing -ErrorAction Stop
    if ($repoData.StatusCode -ne 200) { Write-Host "Errore repository: $($repoData.StatusCode) $($repoData.StatusDescription)"; exit 1 }
} catch {
    Write-Host "Errore dettagliato: $($_.Exception.Message)"
    Write-Host "Response: $($_.Exception.Response.StatusCode) $($_.Exception.Response.StatusDescription)"
    if ($_.Exception.Response) {
        $responseStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseBody = $reader.ReadToEnd()
        Write-Host "Response Body: $responseBody"
        $reader.Close()
    }
    exit 1
}
$repoId = (($repoData.Content | ConvertFrom-Json).value | Where-Object { $_.name -eq $repoName }).id
if (-not $repoId) { Write-Host "Repository non trovato: $repoName"; exit 1 }
$timeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "AdvancedSecurityReport_${repoName}_$timeStamp"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

function Extract-Properties {
    param($object, $prefix = "")
    $properties = @{}
    if ($object -is [PSCustomObject]) {
        foreach ($prop in $object.PSObject.Properties) {
            $key = if ($prefix) { "$prefix.$($prop.Name)" } else { $prop.Name }
            if ($prop.Value -is [Array] -and $prop.Value.Count -gt 0) {
                for ($i = 0; $i -lt $prop.Value.Count; $i++) { $properties += Extract-Properties -object $prop.Value[$i] -prefix "$key[$i]" }
            } elseif ($prop.Value -is [PSCustomObject]) { $properties += Extract-Properties -object $prop.Value -prefix $key }
            else { $properties[$key] = $prop.Value }
        }
    }
    return $properties
}

function Get-CveDetails {
    param($cveId)
    $nvdApiUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cveId"
    $maxRetries = 3
    $retryDelay = 15  # Secondi tra ritentativi (per rispettare il rate limit)
    for ($retry = 1; $retry -le $maxRetries; $retry++) {
        try {
            Write-Host "Richiedendo dati per CVE: $cveId (tentativo $retry)"
            $response = Invoke-RestMethod -Uri $nvdApiUrl -Method Get -ErrorAction Stop -TimeoutSec 30
            Start-Sleep -Seconds 6  # Pausa standard tra chiamate
            $cveData = $response.vulnerabilities[0].cve
            if ($cveData) {
                $metrics = $null
                $version = "N/A"
                if ($cveData.metrics.cvssMetricV40) { $metrics = $cveData.metrics.cvssMetricV40[0]; $version = "4.0" }
                elseif ($cveData.metrics.cvssMetricV31) { $metrics = $cveData.metrics.cvssMetricV31[0]; $version = "3.1" }
                elseif ($cveData.metrics.cvssMetricV30) { $metrics = $cveData.metrics.cvssMetricV30[0]; $version = "3.0" }
                $cvssScore = if ($metrics) { $metrics.cvssData.baseScore } else { "N/A" }
                $severity = if ($metrics -and $metrics.cvssData.PSObject.Properties.Name -contains "baseSeverity") { $metrics.cvssData.baseSeverity } else { "N/A" }
                $vector = if ($metrics) { $metrics.cvssData.vectorString } else { "N/A" }
                $patchAvailable = $false
                $exploitPublic = $false
                if ($cveData.references) {
                    foreach ($ref in $cveData.references) {
                        if ("Patch" -in $ref.tags -or "Vendor Advisory" -in $ref.tags) { $patchAvailable = $true }
                        $url = $ref.url.ToLower()
                        if ($url -match "exploit|exploit-db|packetstorm|metasploit|github.com") { $exploitPublic = $true }
                    }
                }
                return [PSCustomObject]@{
                    CVEId = $cveId
                    CVSSScore = $cvssScore
                    CVSSVersion = $version
                    Severity = $severity
                    Vector = $vector
                    PatchAvailable = $patchAvailable
                    ExploitPublic = $exploitPublic
                }
            }
            Write-Host "Nessun dato trovato per CVE: $cveId"
            return [PSCustomObject]@{
                CVEId = $cveId
                CVSSScore = "N/A"
                CVSSVersion = "N/A"
                Severity = "N/A"
                Vector = "N/A"
                PatchAvailable = $false
                ExploitPublic = $false
            }
        } catch {
            Write-Host "Errore durante la richiesta per CVE: $cveId - $_"
            if ($retry -lt $maxRetries -and $_.Exception.Response.StatusCode.value__ -eq 429) {
                Write-Host "Rate limit rilevato, ritento tra $retryDelay secondi (tentativo $retry/$maxRetries)"
                Start-Sleep -Seconds $retryDelay
            } else {
                return [PSCustomObject]@{
                    CVEId = $cveId
                    CVSSScore = "N/A"
                    CVSSVersion = "N/A"
                    Severity = "N/A"
                    Vector = "N/A"
                    PatchAvailable = $false
                    ExploitPublic = $false
                }
            }
        }
    }
    return [PSCustomObject]@{
        CVEId = $cveId
        CVSSScore = "N/A"
        CVSSVersion = "N/A"
        Severity = "N/A"
        Vector = "N/A"
        PatchAvailable = $false
        ExploitPublic = $false
    }
}

function Load-EpssData {
    $epssUrl = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    $tmpFile = Join-Path $env:TEMP "epss_$([Guid]::NewGuid()).csv.gz"
    try {
        Invoke-WebRequest -Uri $epssUrl -OutFile $tmpFile -UseBasicParsing
        $stream = New-Object IO.Compression.GzipStream([IO.File]::OpenRead($tmpFile), [IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object IO.StreamReader($stream)
        $data = @{}
        $header = $reader.ReadLine()
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $parts = $line -split ","
            if ($parts.Length -ge 3) { $data[$parts[0]] = @{"EPSS" = $parts[1]; "Percentile" = $parts[2]} }
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
        $json = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 20 -UseBasicParsing
        return ($json.Content | ConvertFrom-Json).vulnerabilities.cveID
    } catch {
        Write-Host "Errore in Load-CisaKev: $_"
        return @()
    }
}

function Get-SecurityAlerts {
    $alertsUrls = @(
        "https://OrganizzazioneXXX.advsec.visualstudio.com/$projName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion&criteria.alertType=1&criteria.alertState=active&criteria.ref=$buildBranch&top=$maxAlertsPerRepo",
        "https://OrganizzazioneXXX.advsec.visualstudio.com/$projName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion&criteria.alertType=code&criteria.alertState=active&criteria.ref=$buildBranch&top=$maxAlertsPerRepo"
    )
    if ($env:BUILD_DEFINITIONNAME) {
        $encodedPipelineName = [System.Web.HttpUtility]::UrlEncode($env:BUILD_DEFINITIONNAME)
        $alertsUrls = $alertsUrls | ForEach-Object { $_ + "&criteria.pipelineName=$encodedPipelineName" }
    }
    $allAlerts = @(); $alertIds = @{}
    foreach ($alertsUrl in $alertsUrls) {
        $nextLink = $null
        do {
            $currentUrl = if ($nextLink) { $nextLink } else { $alertsUrl }
            Write-Host "Chiamata API per alert di sicurezza: $currentUrl"
            try {
                $apiResponse = Invoke-WebRequest -Uri $currentUrl -Headers $authHeader -Method Get -UseBasicParsing
                $json = $apiResponse.Content | ConvertFrom-Json
                if ($json.value.Count -eq $maxAlertsPerRepo) { Write-Host "Limite $maxAlertsPerRepo alert raggiunto per $alertsUrl" }
                if ($json.PSObject.Properties.Name -contains "value" -and $json.value) {
                    foreach ($alert in $json.value) {
                        if ($alert.gitRef -ne $buildBranch) { Write-Host "Ignorato alert con gitRef $($alert.gitRef), atteso $buildBranch"; continue }
                        $alertId = if ($alert.PSObject.Properties.Name -contains "alertId") { $alert.alertId } else { "N/A" }
                        if ($alertIds.ContainsKey($alertId)) { Write-Host "Alert $alertId duplicato, ignorato"; continue }
                        $alertIds[$alertId] = $true
                        $alertProps = Extract-Properties -object $alert
                        $alertType = if ($alert.PSObject.Properties.Name -contains "alertType") { $alert.alertType } else { "N/A" }
                        $cveId = ($alertProps.Keys | Where-Object { $_ -like "*cveId" } | ForEach-Object { $alertProps[$_] } | Where-Object { $_ }) | Select-Object -First 1
                        if ($cveId) {
                            $cveDetails = Get-CveDetails -cveId $cveId
                            $epssInfo = if ($epssData.ContainsKey($cveId)) { $epssData[$cveId] } else { @{"EPSS" = "N/A"; "Percentile" = "N/A"} }
                            $isKev = if ($cisaKev -contains $cveId) { "Yes" } else { "No" }
                            $priority = if ($isKev -eq "Yes" -or $cveDetails.ExploitPublic) { "CRITICA" }
                                       elseif (($cveDetails.CVSSScore -ne "N/A" -and [double]$cveDetails.CVSSScore -ge 8) -or 
                                               ($epssInfo.EPSS -ne "N/A" -and [double]$epssInfo.EPSS -ge 0.5)) { "ALTA" }
                                       elseif (($cveDetails.CVSSScore -ne "N/A" -and [double]$cveDetails.CVSSScore -ge 6) -or 
                                               ($epssInfo.EPSS -ne "N/A" -and [double]$epssInfo.EPSS -ge 0.2)) { "MEDIA" }
                                       else { "BASSA" }
                        } else {
                            $cveId = "N/A"
                            $cveDetails = [PSCustomObject]@{CVSSScore = "N/A"; CVSSVersion = "N/A"; Severity = "N/A"; Vector = "N/A"; PatchAvailable = $false; ExploitPublic = $false}
                            $epssInfo = @{"EPSS" = "N/A"; "Percentile" = "N/A"}
                            $isKev = "N/A"
                            $priority = "N/A"
                        }
                        # Mappatura corretta per LocationFile e LocationLine
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
                        # Mappatura corretta per Description con fallback
                        $description = if ($alert.tools -and $alert.tools[0].rules -and $alert.tools[0].rules[0].description) { $alert.tools[0].rules[0].description } else { if ($alert.title) { $alert.title } else { "N/A" } }
                        $state = if ($alert.PSObject.Properties.Name -contains "state") { $alert.state } else { "N/A" }
                        $linkItem = "https://dev.azure.com/$orgName/$projName/_git/$repoId/alerts/$alertId"
                        $alertObj = [PSCustomObject]@{
                            AlertId = $alertId
                            CVEId = $cveId
                            CVSSScore = $cveDetails.CVSSScore
                            CVSSVersion = $cveDetails.CVSSVersion
                            Severity = $cveDetails.Severity  # Severity dal CVE (NVD)
                            AlertSeverity = if ($alert.PSObject.Properties.Name -contains "severity") { $alert.severity } else { "N/A" }  # Severity nativa dell'alert
                            Vector = $cveDetails.Vector
                            EPSS = $epssInfo.EPSS
                            EPSSPercentile = $epssInfo.Percentile
                            CISA_KEV = $isKev
                            PatchAvailable = $cveDetails.PatchAvailable
                            ExploitPublic = $cveDetails.ExploitPublic
                            Priority = $priority
                            GitRef = $alert.gitRef
                            FirstSeenDate = if ($alert.PSObject.Properties.Name -contains "firstSeenDate") { $alert.firstSeenDate } else { "N/A" }
                            AlertType = $alertType
                            LocationFile = $locationFile
                            LocationLine = $locationLine
                            Description = $description
                            State = $state
                            LinkItem = $linkItem
                        }
                        foreach ($k in $alertProps.Keys) {
                            if ($alertObj.PSObject.Properties.Name -notcontains $k) { $alertObj | Add-Member -MemberType NoteProperty -Name $k -Value $alertProps[$k] }
                        }
                        $allAlerts += $alertObj
                        Write-Host "Alert aggiunto: ID=$alertId, Type=$alertType, CVE=$cveId"
                    }
                }
                $nextLink = if ($json.PSObject.Properties.Name -contains "@odata.nextLink") { $json."@odata.nextLink" } else { $null }
                Write-Host "NextLink: $nextLink"
            } catch {
                Write-Host "Errore in Get-SecurityAlerts: $_"
                if ($_.Exception.Response.StatusCode -eq 429) { Write-Host "Rate limit, retry in 5s..."; Start-Sleep -Seconds 5; continue }
                else { throw $_ }
            }
        } while ($nextLink)
    }
    Write-Host "Totale alert di sicurezza raccolti: $($allAlerts.Count)"
    return $allAlerts
}

function Get-SecretAlerts {
    $orgShortName = "OrganizzazioneXXX"
    $alertsUrls = @(
        "https://advsec.dev.azure.com/$orgShortName/$projName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion&criteria.alertType=secret&criteria.alertState=active&top=$maxAlertsPerRepo",
        "https://advsec.dev.azure.com/$orgShortName/$projName/_apis/alert/repositories/$repoId/alerts?api-version=$apiVersion&criteria.alertType=secret&criteria.confidenceLevels=other&criteria.alertState=active&top=$maxAlertsPerRepo"
    )
    $secretAlerts = @()
    $alertIds = @{}
    foreach ($alertsUrl in $alertsUrls) {
        $tokenFilter = ""
        $oldToken = ""
        do {
            $currentUrl = if ($tokenFilter) { "$alertsUrl&continuationToken=$tokenFilter" } else { $alertsUrl }
            Write-Host "Chiamata API per segreti: $currentUrl"
            try {
                $apiResponse = Invoke-WebRequest -Uri $currentUrl -Headers $authHeader -Method Get -UseBasicParsing
                $json = $apiResponse.Content | ConvertFrom-Json
                $secretCount = ($json.value | Where-Object { $_.alertType -eq 'secret' }).Count
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
                        $alertProps = Extract-Properties -object $alert

                        # Mappatura corretta basata sulla struttura JSON
                        $secretType = if ($alert.PSObject.Properties.Name -contains "title") { $alert.title } else { "N/A" }
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
                        $description = if ($alert.tools[0].rules[0].description) { $alert.tools[0].rules[0].description } else { if ($alert.title) { $alert.title } else { "N/A" } }
                        $state = if ($alert.PSObject.Properties.Name -contains "state") { $alert.state } else { "N/A" }
                        $confidence = if ($alert.PSObject.Properties.Name -contains "confidence") { $alert.confidence } else { "N/A" }
                        $severity = if ($alert.PSObject.Properties.Name -contains "severity") { $alert.severity } else { "N/A" }
                        $firstSeenDate = if ($alert.PSObject.Properties.Name -contains "firstSeenDate") { $alert.firstSeenDate } else { "N/A" }
                        $lastSeenDate = if ($alert.PSObject.Properties.Name -contains "lastSeenDate") { $alert.lastSeenDate } else { "N/A" }
                        $introducedDate = if ($alert.PSObject.Properties.Name -contains "introducedDate") { $alert.introducedDate } else { "N/A" }
                        $dismissalType = if ($alert.dismissal -and $alert.dismissal.PSObject.Properties.Name -contains "dismissalType") { $alert.dismissal.dismissalType } else { "N/A" }
                        $dismissalUser = if ($alert.dismissal -and $alert.dismissal.stateChangedByIdentity) { $alert.dismissal.stateChangedByIdentity.displayName } else { "N/A" }
                        $dismissalComment = if ($alert.dismissal -and $alert.dismissal.PSObject.Properties.Name -contains "message") { $alert.dismissal.message } else { "N/A" }
                        $dismissalDate = if ($alert.dismissal -and $alert.dismissal.PSObject.Properties.Name -contains "requestedOn") { $alert.dismissal.requestedOn } else { "N/A" }
                        $linkItem = "https://dev.azure.com/$orgName/$projName/_git/$repoId/alerts/$alertId"
                        $gitRef = if ($alert.PSObject.Properties.Name -contains "gitRef") { $alert.gitRef } else { "N/A" }

                        $secretAlerts += [PSCustomObject]@{
                            AlertId = $alertId
                            AlertType = "secret"
                            SecretType = $secretType
                            LocationFile = $locationFile
                            LocationLine = $locationLine
                            Description = $description
                            State = $state
                            Confidence = $confidence
                            Severity = $severity
                            FirstSeenDate = $firstSeenDate
                            LastSeenDate = $lastSeenDate
                            IntroducedDate = $introducedDate
                            DismissalType = $dismissalType
                            DismissalUser = $dismissalUser
                            DismissalComment = $dismissalComment
                            DismissalDate = $dismissalDate
                            LinkItem = $linkItem
                            GitRef = $gitRef
                        }
                        Write-Host "Segreto aggiunto: ID=$alertId, SecretType=$secretType, Confidence=$confidence"
                    }
                }
                $continuationToken = $apiResponse.Headers["x-ms-continuationtoken"]
                if ($continuationToken -and $continuationToken -ne $oldToken) { $tokenFilter = $continuationToken; $oldToken = $continuationToken } else { $tokenFilter = "" }
            } catch {
                Write-Host "Errore nella chiamata API: $_"
                if ($_.Exception.Response.StatusCode -eq 429) { Write-Host "Rate limit, retry in 5s..."; Start-Sleep -Seconds 5; continue }
                else { throw $_ }
            }
        } while ($tokenFilter)
    }
    Write-Host "Totale segreti raccolti: $($secretAlerts.Count)"
    return $secretAlerts
}

$epssData = Load-EpssData
$cisaKev = Load-CisaKev
$securityAlerts = Get-SecurityAlerts
$secretAlerts = Get-SecretAlerts
if (-not $securityAlerts -or $securityAlerts.Count -eq 0) {
    $securityAlerts += [PSCustomObject]@{
        AlertId = "N/A"; CVEId = "N/A"; CVSSScore = "N/A"; CVSSVersion = "N/A"; Severity = "N/A"; AlertSeverity = "N/A"; Vector = "N/A"; EPSS = "N/A"; EPSSPercentile = "N/A"; CISA_KEV = "N/A"; PatchAvailable = $false; ExploitPublic = $false; Priority = "N/A"; GitRef = "N/A"; FirstSeenDate = "N/A"; AlertType = "N/A"; LocationFile = "N/A"; LocationLine = "N/A"; Description = "N/A"; State = "N/A"; LinkItem = "N/A"
    }
}
if (-not $secretAlerts -or $secretAlerts.Count -eq 0) {
    $secretAlerts += [PSCustomObject]@{
        AlertId = "N/A"; AlertType = "secret"; SecretType = "N/A"; LocationFile = "N/A"; LocationLine = "N/A"; Description = "N/A"; State = "N/A"; Confidence = "N/A"; Severity = "N/A"; FirstSeenDate = "N/A"; LastSeenDate = "N/A"; IntroducedDate = "N/A"; DismissalType = "N/A"; DismissalUser = "N/A"; DismissalComment = "N/A"; DismissalDate = "N/A"; LinkItem = "N/A"; GitRef = "N/A"
    }
}
$detailedCsv = Join-Path $outputDir "AdvancedSecurityReport_Detailed_${timeStamp}.csv"
$securityAlerts | Export-Csv -Path $detailedCsv -NoTypeInformation -Encoding UTF8
$aggCve = $securityAlerts | Where-Object { $_.CVEId -ne "N/A" } | Group-Object CVEId | ForEach-Object {
    $alertIds = $_.Group | ForEach-Object { $_.AlertId } | Where-Object { $_ -ne $null -and $_ -ne "" }
    [PSCustomObject]@{
        CVEId = $_.Name
        AlertIDs = ($alertIds -join "; ")
        CVSSScore = ($_.Group | Select-Object -First 1).CVSSScore
        CVSSVersion = ($_.Group | Select-Object -First 1).CVSSVersion
        Severity = ($_.Group | Select-Object -First 1).Severity
        AlertSeverity = ($_.Group | Select-Object -First 1).AlertSeverity
        Vector = ($_.Group | Select-Object -First 1).Vector
        EPSS = ($_.Group | Select-Object -First 1).EPSS
        EPSSPercentile = ($_.Group | Select-Object -First 1).EPSSPercentile
        CISA_KEV = ($_.Group | Select-Object -First 1).CISA_KEV
        PatchAvailable = ($_.Group | Select-Object -First 1).PatchAvailable
        ExploitPublic = ($_.Group | Select-Object -First 1).ExploitPublic
        Priority = ($_.Group | Select-Object -First 1).Priority
        CountAlerts = $_.Group.Count
    }
}
$aggregatedCsv = Join-Path $outputDir "AdvancedSecurityReport_Aggregated_${timeStamp}.csv"
$aggCve | Export-Csv -Path $aggregatedCsv -NoTypeInformation -Encoding UTF8
$secretsCsv = Join-Path $outputDir "AdvancedSecurityReport_Secrets_${timeStamp}.csv"
$secretAlerts | Select-Object AlertId, AlertType, SecretType, LocationFile, LocationLine, Description, State, Confidence, Severity, FirstSeenDate, LastSeenDate, IntroducedDate, DismissalType, DismissalUser, DismissalComment, DismissalDate, LinkItem, GitRef | Export-Csv -Path $secretsCsv -NoTypeInformation -Encoding UTF8
$detailedCsvFull = (Resolve-Path $detailedCsv).Path
$aggregatedCsvFull = (Resolve-Path $aggregatedCsv).Path
$secretsCsvFull = (Resolve-Path $secretsCsv).Path
Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_Detailed;]$detailedCsvFull"
Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_Aggregated;]$aggregatedCsvFull"
Write-Host "##vso[artifact.upload artifactname=AdvancedSecurityReport_Secrets;]$secretsCsvFull"
Write-Host "Report generati e pubblicati."
