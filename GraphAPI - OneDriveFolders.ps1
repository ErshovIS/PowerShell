function Write-CMLog {
    Param (
        [Parameter(Mandatory = $true, HelpMessage = "Message to write in Log file")]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory = $true, HelpMessage = "Entry severity. 1 - Info, 2 - Warning, 3 - Error")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("1", "2", "3")]
        [string]$Severity,
        [Parameter(Mandatory = $false, HelpMessage = "Log file name (DriverManagement.log default")]
        [ValidateNotNullOrEmpty()]
        [string]$LogFileName = "OneDrive.log"
    )
    if (-not(Test-Path -Path 'variable:global:TimezoneBias')) {
        [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
        if ($TimezoneBias -match "^-") {
            $TimezoneBias = $TimezoneBias.Replace('-', '+')
        }
        else {
            $TimezoneBias = '-' + $TimezoneBias
        }
    }
    $EntryTime = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)
    $EntryDate = Get-Date -Format "MM-dd-yyyy"
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

    $LogFilePath = Join-Path $LogDirectory -ChildPath $LogFileName

    $LogMessage = "<![LOG[$($Message)]LOG]!><time=""$($EntryTime)"" date=""$($EntryDate)"" component=""OneDrive Azure Export"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"       
    Out-File -InputObject $LogMessage -Append -NoClobber -Encoding UTF8 -FilePath $LogFilePath
}

function Invoke-GraphWebRequest{
    param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$URL
    )
    try{
        $result = Invoke-WebRequest -Headers $headers -Uri "$URL"
            if ($result) {
                if ($result.Content) { ($result.Content | ConvertFrom-Json) }
             else {
                return $result
            }
        }
        else {
            return
        }
    }
    catch {
        Write-CMLog -LogFileName $logFileName -Message "Fialed to retriev URL" -Severity 3
        return
    }
}

function getChildren{
    param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$URL,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$parentFolder
    )
    $currentURL = "$URL/children"
    $childrenItems = @()
    do {
        Write-CMLog -LogFileName $logFilename -Message "Quering current url $($currentURL)" -Severity 1
        $childrenResult = Invoke-GraphWebRequest -URL $currentURL -ErrorAction Stop       
        $currentURL = $childrenResult.'@odata.nextLink'
        #write-host "next url - "$URL
        $childrenItems += $childrenResult
    } while ($currentURL)
    $output = @()

    foreach ($folder in $childrenItems.value | Where-Object {$_.Folder}){ 
        Write-CMLog -LogFileName $logFilename -Message "Processing $($folder.Name) with ID:$($folder.id) and URL: https://graph.microsoft.com/v1.0/users/$($user.id)/drive/items/$($folder.id)" -Severity 1
        $currentFolder = Join-Path $parentFolder -ChildPath $folder.Name
        IF (-not (Test-Path $currentFolder)){
            New-Item -Path $currentFolder -ItemType Directory -Force
            Write-CMLog -LogFileName $logFilename -Message "Creating folder $($currentFolder)" -Severity 1
        }    
        $output += (processFolder -folder $folder.id -parentFolder $currentFolder)                     
    }

    foreach ($file in $childrenItems.value | Where-Object {$_.File}){
        $DownloadStartTime = Get-Date
        Write-CMLog -LogFileName $logFilename -Message "Downloading file $($File.name) to $($parentFolder)\$($File.name) Size: $([math]::Round($File.Size/1024/1024,2))MB" -Severity 1
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Headers $headers -Uri $File.'@microsoft.graph.downloadUrl' -Method Get -OutFile "$($parentFolder)\$($File.name)"
        $DownloadEndTime = Get-Date
        $Duration = $DownloadEndTime - $DownloadStartTime
        Write-CMLog -LogFileName $logFilename -Message "Download complete in $($Duration.Hours) hours $($Duration.minutes) minutes $($Duration.Seconds) seconds" -Severity 1
    }
    return $childrenItems
}

function processFolder {
    param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$folderID,
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$parentFolder
    )
    $URL = "https://graph.microsoft.com/v1.0/users/$($user.id)/drive/items/$($folderid)"
    $folderItems = getChildren -URL $url -parentFolder $parentFolder
}
 
$tenantID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$appID = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$client_secret = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

$LogDirectory = "C:\temp\"
$logFilename = "OneDrive_export.log"
$BackupFolderRoot = "C:\temp\"

$tokenBody = @{ 
    Grant_Type    = "client_credentials" 
    Scope         = "https://graph.microsoft.com/.default" 
    Client_Id     = $appID 
    Client_Secret = $client_Secret 
}  

Write-CMLog -LogFileName $logFilename -Message "Authorizing on tenant $($tenantID)..." -Severity 1
$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenantid/oauth2/v2.0/token" -Method POST -Body $tokenBody 
 
$headers = @{
    "Authorization" = "Bearer $($tokenResponse.access_token)"
    "Content-type"  = "application/json"
}

$OneDriveUsers = @()

# Get more users
#$URL = "https://graph.microsoft.com/v1.0/users/?$`select=displayName,mail,userPrincipalName,id,userType&`$top=999&`$filter=userType eq 'Member'"
#$URL = "https://graph.microsoft.com/v1.0/users/?$`select=displayName,mail,userPrincipalName,id,userType&`$filter=userType eq 'Member'"

# Test User
$URL = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq 'test_user@testDomain.ru'"
 
Write-CMLog -LogFileName $logFilename -Message "Requesting users using the following URL: $($url)" -Severity 1

do {
    $AllUsersResult = Invoke-GraphWebRequest -URL $URL -ErrorAction Stop
    $URL = $AllUsersResult.'@odata.nextLink'
    #If we are getting multiple pages, best add some delay to avoid throttling
    Start-Sleep -Milliseconds 500
    $OneDriveUsers += $AllUsersResult.Value
} while ($URL)

foreach ($user in $OneDriveUsers){
    Write-CMLog -LogFileName $logFilename -Message "Processing user $($user.displayName)..." -Severity 1
    # getting current user OneDrive Folder content
    $URL = "https://graph.microsoft.com/v1.0/users/$($user.id)/drive/root"
    $UserDrive = Invoke-GraphWebRequest -URL $URL -ErrorAction Stop
    IF (!$UserDrive -or $UserDrive.folder.childCount -eq 0){
        Write-CMLog -LogFileName $logFilename -Message "User $($user.displayName) ($($user.userPrincipalName)) does not have any content" -Severity 2
        continue
    }
    $BackupFolderCurrentUserRoot = Join-Path $BackupFolderRoot -ChildPath $user.userPrincipalName
    IF (-not (Test-Path $BackupFolderCurrentUserRoot)){
        New-Item -Path $BackupFolderCurrentUserRoot -ItemType Directory -Force | Out-Null
        Write-CMLog -LogFileName $logFilename -Message "Creating root folder $($BackupFolderCurrentUserRoot)" -Severity 1
    }
    $output = getChildren -URL $URL -parentFolder $BackupFolderCurrentUserRoot   
}