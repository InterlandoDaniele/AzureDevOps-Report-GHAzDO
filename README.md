## Panoramica
Lo script PowerShell `export_report_GHAzDO.ps1` è uno strumento progettato per recuperare e analizzare gli alert di sicurezza da un repository Azure DevOps, inclusi vulnerabilità delle dipendenze, problemi di code scanning e fughe di segreti. Genera report dettagliati e aggregati in formato CSV, che possono essere pubblicati come artefatti in una pipeline Azure DevOps. Lo script si integra con l'API di Advanced Security di Azure DevOps e arricchisce i dati con informazioni da fonti esterne come NVD, EPSS e CISA KEV.

## Funzionalità
- Recupera alert di sicurezza per dipendenze, code scanning e segreti.
- Genera tre report CSV:
  - `AdvancedSecurityReport_Detailed_*.csv`: Dettagli di ogni alert individuale.
  - `AdvancedSecurityReport_Aggregated_*.csv`: Sommario aggregato dei CVE.
  - `AdvancedSecurityReport_Secrets_*.csv`: Elenco degli alert relativi ai segreti.
- Arricchisce i dati CVE con CVSS, EPSS, e stato CISA KEV.
- Supporta il filtraggio per branch e nome della pipeline.
- Pubblica i report come artefatti Azure DevOps.

## Requisiti
- **PowerShell**: Versione 5.1 o superiore.
- **Azure DevOps**: Accesso a un repository con Advanced Security abilitato.
- **Variabili d'ambiente** (da impostare nella pipeline Azure DevOps):
  - `$env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI`: URL dell'organizzazione Azure DevOps.
  - `$env:SYSTEM_TEAMPROJECT`: Nome del progetto.
  - `$env:BUILD_REPOSITORY_NAME`: Nome del repository.
  - `$env:SYSTEM_ACCESSTOKEN`: Token di accesso personale (PAT) con permessi adeguati.
  - `$env:BUILD_SOURCEBRANCH`: Nome del branch (es. `refs/heads/main`).
  - `$env:BUILD_DEFINITIONNAME`: Nome opzionale della pipeline per il filtraggio.
- **Accesso a Internet**: Necessario per le chiamate API a NVD, EPSS e CISA KEV.

2. Salva lo script come `export_report_GHAzDO.ps1` nella directory principale del repository.
3. Assicurati che il repository sia accessibile tramite un URL raw (es. da Azure DevOps, se lo script è ospitato lì).

## Utilizzo
### Configurazione della Pipeline
Aggiungi il seguente task PowerShell alla tua pipeline Azure DevOps per eseguire lo script:

```
- task: PowerShell@2
  inputs:
 targetType: 'inline'
 script: |
   $ErrorActionPreference = "Stop"
   $scriptUrl = "https://dev.azure.com/{organizzazione}/{progetto}/_apis/git/repositories/items?path=/path/export_report_GHAzDO.ps1&versionDescriptor.version=main&api-version=7.1"
   $authHeader = @{Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($env:SYSTEM_ACCESSTOKEN)"))}
   $tempScriptPath = "$(System.DefaultWorkingDirectory)/export_report_GHAzDO.ps1"
   Write-Host "Downloading script from $scriptUrl"
   Invoke-WebRequest -Uri $scriptUrl -Headers $authHeader -OutFile $tempScriptPath -UseBasicParsing
   Write-Host "Executing script: $tempScriptPath"
   & $tempScriptPath
  env:
 SYSTEM_TEAMFOUNDATIONCOLLECTIONURI: $(System.TeamFoundationCollectionUri)
 SYSTEM_TEAMPROJECT: $(System.TeamProject)
 BUILD_REPOSITORY_NAME: $(Build.Repository.Name)
 SYSTEM_ACCESSTOKEN: $(System.AccessToken)
 BUILD_SOURCEBRANCH: $(Build.SourceBranch)
 BUILD_DEFINITIONNAME: $(Build.DefinitionName)
```
##Abilita l'opzione "Allow scripts to access the OAuth token" nel job della pipeline.

##File Generati

- AdvancedSecurityReport_Detailed_<timestamp>.csv: Contiene dettagli come AlertId, CVEId, CVSSScore, ecc. (senza AlertType, LocationFile, LocationLine, Description).
- AdvancedSecurityReport_Aggregated_<timestamp>.csv: Riassume i CVE con CVEId, CountAlerts, ecc.
- AdvancedSecurityReport_Secrets_<timestamp>.csv: Elenca gli alert segreti con AlertId, SecretType, LocationFile, ecc.

##Note

- Filtri: Il filtraggio per criteria.ref=$buildBranch e criteria.pipelineName può essere regolato.
- Limiti: $maxAlertsPerRepo è impostato a 500; aumentalo se necessario.
- Debug: I messaggi Write-Host forniscono informazioni sui progressi; controlla i log per diagnosticare problemi.
- Personalizzazione: Modifica lo script per adattarlo a repository o pipeline specifiche.





