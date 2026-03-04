# Export Azure DevOps Advanced Security Alerts  
**Report di vulnerabilità dipendenze e secret scanning**

Script PowerShell progettato per pipeline Azure DevOps che estrae, arricchisce e pubblica report di **Advanced Security** (ex GitHub Advanced Security su Azure DevOps).

Supporta sia **Service Principal** (Entra ID / Microsoft Entra ID) che autenticazione classica tramite `SYSTEM_ACCESSTOKEN`( solamente per invoke tramite Repository)

Data ultima revisione script / guida: **marzo 2026**

## Funzionalità principali

- Riconoscimento automatico dei repository checkoutati (supporto multi-repo)
- Autenticazione preferenziale con **Service Principal** (variabili di ambiente)
- Fallback su `SYSTEM_ACCESSTOKEN` se SP non disponibile / fallito
- Recupero alert attivi di tipo:
  - **code** → vulnerabilità in dipendenze (con CVE)
  - **secret** → credenziali / token / chiavi nel codice
- Arricchimento CVE con dati esterni:
  - CVSS v3.1 / v4.0 + severity (da NVD)
  - **EPSS** score & percentile (Exploit Prediction Scoring System)
  - Presenza in **CISA KEV** (Known Exploited Vulnerabilities)
  - Calcolo priorità semplificata: **CRITICA / ALTA / MEDIA / BASSA**
- Output per ogni repository analizzato:
  - CSV dettagliato (tutti i campi arricchiti)
  - CSV aggregato per CVE (raggruppamento)
  - CSV solo secret scanning
  - Versioni JSON equivalenti
- Pubblicazione automatica come **artifact** di pipeline

## Prerequisiti

| Requisito                                  | Dove configurare                               | Livello     | Note obbligatorie                                                                 |
|--------------------------------------------|------------------------------------------------|-------------|-----------------------------------------------------------------------------------|
| Advanced Security abilitato                | Project Settings → Repos → Advanced Security   | Progetto    | Senza questo non ci sono alert                                                    |
| Service Principal (consigliato)            | Variable group / pipeline variables            | Pipeline    | `ClientId`, `ClientSecret`, `TenantId`                                            |
| Key Vault con i segreti SP                 | Service connections → Azure Key Vault          | Organizzazione / Progetto | Collegare il KV al pipeline                                         |
| Permessi al Service Principal              | Project Settings → Permissions                 | Progetto    | **Advanced Security: Read alerts** + membership progetto                          |
| Allow scripts to access OAuth Token        | Agent Job → checkbox                           | Job         | Necessario solo se si usa fallback `SYSTEM_ACCESSTOKEN`                          |

## Metodo consigliato di esecuzione (2025–2026)

Utilizzare un task **PowerShell@2** inline che scarica lo script da un repository centrale:

```yaml
- task: PowerShell@2
  displayName: '📊 Export Advanced Security Report'
  env:
    ClientId:     $(SP-CLIENT-ID)
    ClientSecret: $(SP-CLIENT-SECRET)
    TenantId:     $(SP-TENANT-ID)
  inputs:
    targetType: 'inline'
    script: |
        $ErrorActionPreference = "Stop"
        $scriptUrl = "https://dev.azure.com/{Organizzation}/{Project}/_apis/git/repositories/{Repository}/items?path=../../script.ps1&versionDescriptor.version=main&api-version=7.1"
        $authHeader = @{Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($env:SYSTEM_ACCESSTOKEN)"))}
        $tempScriptPath = "$(System.DefaultWorkingDirectory)/script.ps1"
        Write-Host "Downloading script from $scriptUrl"
        Invoke-WebRequest -Uri $scriptUrl -Headers $authHeader -OutFile $tempScriptPath -UseBasicParsing
        Write-Host "Executing script: $tempScriptPath"
        & $tempScriptPath
