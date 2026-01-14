#VARIABLES IN REGION 2 - CUSTOMIZE AS NEEDED

#region 1. Self-Elevation
# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Relaunch script with elevation
    $scriptPath = $MyInvocation.MyCommand.Definition
    $scriptDir = Split-Path -Parent $scriptPath
    $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`""
    
    # Start elevated PowerShell window
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -WorkingDirectory $scriptDir
    
    exit
}

# If elevated, hide THIS console window
Add-Type -Name Window -Namespace Console -MemberDefinition @"
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
"@

$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)  # Hide elevated console only
#endregion


#region 2. Global Variables
#INSERT YOUR OWN CA/COMPANY DETAILS HERE
$yourCA = "MyCA.Mydomain.com\My Subordinate Certification Authority"
$yourDomainSuffix = "mydomain.com"
# -------------------------
# Input Fields
# -------------------------
$labels = @("Common Name", "SANs", "Point of Contact Email", "Organizational Unit", "Organization", "Locality", "State", "Country")
$defaults = @{
    "Common Name" = "ServerName"
    "Organizational Unit" = "IT Services"
    "Organization" = "My Organization"
    "Locality" = "City"
    "State" = "State"
    "Country" = "US"
}
$textboxes = @{}


# Tracks the most recently installed certificate's thumbprint (set during Retrieve-Certificate)
$script:LastInstalledThumbprint = $null

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptDir
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
#endregion

#region 3. Utility Functions
function Validate-CN($cn) {
    return $cn -match '^[a-zA-Z0-9.\-]+$'
}

function Get-CATemplates {
    $caConfig = $yourCA
    $certutilCmd = "certutil -catemplates -config `"$caConfig`""
    $templateOutput = & cmd /c $certutilCmd
    $templates = @()
    foreach ($line in $templateOutput) {
        if ($line -match "^([^:]+):\s+(.*)$") {
            $templateName = $matches[1].Trim()
            $access = $matches[2].Trim()
            if ($access -match "Access is denied") {
                $templates += "$templateName (Access Denied)"
            } else {
                $templates += $templateName
            }
        }
    }
    return $templates
}

#DER PEM Helpers for RSA key export

function Get-DerLengthBytes {
    param([int]$len)
    if ($len -lt 128) { return [byte[]]$len }
    $bytes = New-Object System.Collections.Generic.List[byte]
    while ($len -gt 0) { $bytes.Insert(0, $len -band 0xff); $len = $len -shr 8 }
    ,(0x80 -bor $bytes.Count) + $bytes.ToArray()
}

function Add-DerInteger {
    param([System.Collections.Generic.List[byte]]$list, [byte[]]$valueBytes)
    if (-not $valueBytes) { $valueBytes = [byte[]]@(0x00) }
    while ($valueBytes.Length -gt 1 -and $valueBytes[0] -eq 0x00 -and ($valueBytes[1] -band 0x80) -eq 0) {
        $valueBytes = $valueBytes[1..($valueBytes.Length-1)]
    }
    if (($valueBytes[0] -band 0x80) -ne 0) { $valueBytes = ,0x00 + $valueBytes }
    $lenBytes = Get-DerLengthBytes $valueBytes.Length
    $list.Add(0x02)                                           # INTEGER
    foreach ($b in $lenBytes)  { $list.Add($b) }
    foreach ($b in $valueBytes) { $list.Add($b) }
}

function Write-Pkcs1PemFromRSAParameters {
    param([System.Security.Cryptography.RSAParameters]$Params, [string]$OutPath)
    $body = New-Object System.Collections.Generic.List[byte]
    Add-DerInteger $body ([byte[]]@(0x00))                    # version = 0
    Add-DerInteger $body $Params.Modulus
    Add-DerInteger $body $Params.Exponent
    Add-DerInteger $body $Params.D
    Add-DerInteger $body $Params.P
    Add-DerInteger $body $Params.Q
    Add-DerInteger $body $Params.DP
    Add-DerInteger $body $Params.DQ
    Add-DerInteger $body $Params.InverseQ

    $bodyBytes = $body.ToArray()
    $lenBytes  = Get-DerLengthBytes $bodyBytes.Length

    $seq = New-Object System.Collections.Generic.List[byte]
    $seq.Add(0x30)                                            # SEQUENCE
    foreach ($b in $lenBytes)  { $seq.Add($b) }
    foreach ($b in $bodyBytes) { $seq.Add($b) }

    $der     = $seq.ToArray()
    $b64     = [System.Convert]::ToBase64String($der)
    $wrapped = ($b64.ToCharArray() -split "(.{1,64})" | Where-Object { $_ -ne "" }) -join "`r`n"
    $pem     = "-----BEGIN RSA PRIVATE KEY-----`r`n$wrapped`r`n-----END RSA PRIVATE KEY-----`r`n"
    $pem | Out-File -FilePath $OutPath -Encoding ascii -Force
}



#endregion

#region RSAT Check
$rsatInstalled = (Get-WindowsCapability -Online | Where-Object { $_.Name -eq 'Rsat.CertificateServices.Tools~~~~0.0.1.0' }).State
#endregion

#region 4. GUI Setup
$form = New-Object System.Windows.Forms.Form
$form.Text = "Certificate Request Generator"
$form.Size = [System.Drawing.Size]::new(700, 1100)
$form.StartPosition = "CenterScreen"

# Layout variables
$baseY = 10
$spacing = 30
$nextY = $baseY


#Build the first three sections/labels here:

# -------------------------
# Visual Separator: Header + Line
# -------------------------

# Header text
$requiredHeader = New-Object System.Windows.Forms.Label
$requiredHeader.Text = "YOUR CA: $yourCA" 
$requiredHeader.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$requiredHeader.Location = [System.Drawing.Point]::new(10, $nextY)
$requiredHeader.Size = [System.Drawing.Size]::new(695, 25)
$form.Controls.Add($requiredHeader)
$nextY += 30

# Horizontal line
$separator = New-Object System.Windows.Forms.Label
$separator.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
$separator.AutoSize = $false
$separator.Location = [System.Drawing.Point]::new(10, $nextY)
$separator.Size = [System.Drawing.Size]::new(660, 2)  # Thin horizontal line
$form.Controls.Add($separator)

$nextY += 20  # Add space after the line

foreach ($labelText in $labels[0..2]) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $labelText
    $label.Location = [System.Drawing.Point]::new(10, $nextY)
    $label.Size = [System.Drawing.Size]::new(250, 20)
    $form.Controls.Add($label)

    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = [System.Drawing.Point]::new(270, $nextY)
    $textbox.Size = [System.Drawing.Size]::new(400, 20)
    $form.Controls.Add($textbox)

    $textboxes[$labelText] = $textbox
    if ($defaults.ContainsKey($labelText)) {
        $textbox.Text = $defaults[$labelText]
    }

    $nextY += $spacing
}
    $emllabel = New-Object System.Windows.Forms.Label
    $emllabel.Text = "Note: We will add . and @ $yourDomainSuffix to values entered above. To keep the base name as well, check box below."
    $emllabel.Location = [System.Drawing.Point]::new(10, $nextY)
    $emllabel.Size = [System.Drawing.Size]::new(695, 20)
    $form.Controls.Add($emllabel)

    $nextY += $spacing

#Inserting the buttons for easy TAB access:
# -------------------------
# Buttons Row
# -------------------------
$submitButton = New-Object System.Windows.Forms.Button
$submitButton.Text = "Generate Request"
$submitButton.Location = [System.Drawing.Point]::new(10, $nextY)
$submitButton.Size = [System.Drawing.Size]::new(100, 35)
$form.Controls.Add($submitButton)

$retrieveButton = New-Object System.Windows.Forms.Button
$retrieveButton.Text = "Retrieve and Install"
$retrieveButton.Location = [System.Drawing.Point]::new(120, $nextY)
$retrieveButton.Size = [System.Drawing.Size]::new(100, 35)
$form.Controls.Add($retrieveButton)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Export PFX"
$exportButton.Location = [System.Drawing.Point]::new(230, $nextY)
$exportButton.Size = [System.Drawing.Size]::new(100, 35)
$form.Controls.Add($exportButton)

#NewButtons
$exportCerButton = New-Object System.Windows.Forms.Button
$exportCerButton.Text = "Export CER"
$exportCerButton.Location = [System.Drawing.Point]::new(340, $nextY)   # shift cleanup to the right
$exportCerButton.Size = [System.Drawing.Size]::new(100, 35)
$form.Controls.Add($exportCerButton)

$exportKeyButton = New-Object System.Windows.Forms.Button
$exportKeyButton.Text = "Export Key"
$exportKeyButton.Location = [System.Drawing.Point]::new(450, $nextY)
$exportKeyButton.Size = [System.Drawing.Size]::new(100, 35)
$form.Controls.Add($exportKeyButton)


#EndNew
$cleanupButton = New-Object System.Windows.Forms.Button
$cleanupButton.Text = "Delete .req, .rsp .inf RetrievedCert_*.Cer"
$cleanupButton.Location = [System.Drawing.Point]::new(560, $nextY)
$cleanupButton.Size = [System.Drawing.Size]::new(100, 35)
$form.Controls.Add($cleanupButton)

$nextY += 50

# Quit Button
$quitButton = New-Object System.Windows.Forms.Button
$quitButton.Text = "Click Here or ESC to exit"
$quitButton.Location = [System.Drawing.Point]::new(450, ($nextY + 10))  # Position below other buttons
$quitButton.Size = [System.Drawing.Size]::new(150, 35)
$form.Controls.Add($quitButton)

# Quit Button Event
$quitButton.Add_Click({
    [System.Environment]::Exit(0)
})


# -------------------------
# Request ID Section
# -------------------------
$requestIdLabel = New-Object System.Windows.Forms.Label
$requestIdLabel.Text = "Request ID:"
$requestIdLabel.Location = [System.Drawing.Point]::new(10, $nextY)
$requestIdLabel.Size = [System.Drawing.Size]::new(100, 20)
$form.Controls.Add($requestIdLabel)

$requestIdBox = New-Object System.Windows.Forms.TextBox
$requestIdBox.Location = [System.Drawing.Point]::new(120, $nextY)
$requestIdBox.Size = [System.Drawing.Size]::new(150, 20)
$form.Controls.Add($requestIdBox)

$approveButton = New-Object System.Windows.Forms.Button
$approveButton.Text = "Approve Request"
$approveButton.Location = [System.Drawing.Point]::new(280, $nextY)
$approveButton.Size = [System.Drawing.Size]::new(150, 25)
$form.Controls.Add($approveButton)

$nextY += 30

# -------------------------
# Note
# -------------------------
$exportNote = New-Object System.Windows.Forms.Label
$exportNote.Text = "Note: Export uses the latest installed certificate matching the Common Name."
$exportNote.Location = [System.Drawing.Point]::new(10, $nextY)
$exportNote.Size = [System.Drawing.Size]::new(610, 20)
$form.Controls.Add($exportNote)

$nextY += 30


#Now insert the rest of the fields in the lables form - these won't change much over time:

# -------------------------
# Visual Separator: Header + Line
# -------------------------

# Header text
$optionalHeader = New-Object System.Windows.Forms.Label
$optionalHeader.Text = "Advanced Options (Optional)"
$optionalHeader.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$optionalHeader.Location = [System.Drawing.Point]::new(10, $nextY)
$optionalHeader.Size = [System.Drawing.Size]::new(400, 25)
$form.Controls.Add($optionalHeader)

$nextY += 30

# Horizontal line
$separator = New-Object System.Windows.Forms.Label
$separator.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
$separator.AutoSize = $false
$separator.Location = [System.Drawing.Point]::new(10, $nextY)
$separator.Size = [System.Drawing.Size]::new(660, 2)  # Thin horizontal line
$form.Controls.Add($separator)

$nextY += 20  # Add space after the line


foreach ($labelText in $labels[3..($labels.Count-1)]) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $labelText
    $label.Location = [System.Drawing.Point]::new(10, $nextY)
    $label.Size = [System.Drawing.Size]::new(250, 20)
    $form.Controls.Add($label)

    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = [System.Drawing.Point]::new(270, $nextY)
    $textbox.Size = [System.Drawing.Size]::new(400, 20)
    $form.Controls.Add($textbox)

    $textboxes[$labelText] = $textbox
    if ($defaults.ContainsKey($labelText)) {
        $textbox.Text = $defaults[$labelText]
    }

    $nextY += $spacing
}




# -------------------------
# Template Dropdown
# -------------------------
$templateLabel = New-Object System.Windows.Forms.Label
$templateLabel.Text = "Certificate Template"
$templateLabel.Location = [System.Drawing.Point]::new(10, $nextY)
$templateLabel.Size = [System.Drawing.Size]::new(250, 20)
$form.Controls.Add($templateLabel)

$templateDropdown = New-Object System.Windows.Forms.ComboBox
$templateDropdown.Location = [System.Drawing.Point]::new(270, $nextY)
$templateDropdown.Size = [System.Drawing.Size]::new(400, 25)
$templateDropdown.DropDownStyle = "DropDownList"
$templateDropdown.Items.AddRange((Get-CATemplates))
$templateDropdown.SelectedIndex = 0
$form.Controls.Add($templateDropdown)

$nextY += 40


# -------------------------
# Visual Separator: Header + Line
# -------------------------

# Header text
$thirdHeader = New-Object System.Windows.Forms.Label
$thirdHeader.BackColor = [System.Drawing.Color]::LightGray
$thirdHeader.Text = "UNCHECK THE BOX BELOW TO SKIP SUBMISSION TO CA"
$thirdHeader.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$thirdHeader.Location = [System.Drawing.Point]::new(10, $nextY)
$thirdHeader.Size = [System.Drawing.Size]::new(660, 18)
$form.Controls.Add($thirdHeader)

$nextY += 25

# Horizontal line
$separator = New-Object System.Windows.Forms.Label
$separator.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
$separator.AutoSize = $false
$separator.Location = [System.Drawing.Point]::new(10, $nextY)
$separator.Size = [System.Drawing.Size]::new(660, 2)  # Thin horizontal line
$form.Controls.Add($separator)

$nextY += 10  # Add space after the line

# -------------------------
# Checkbox
# -------------------------
$submitCheckbox = New-Object System.Windows.Forms.CheckBox
$submitCheckbox.Text = "Submit to CA after generating .req"
$submitCheckbox.Location = [System.Drawing.Point]::new(10, $nextY)
$submitCheckbox.Size = [System.Drawing.Size]::new(350, 25)
$submitCheckbox.Checked = $true   # ✅ Checked by default
$form.Controls.Add($submitCheckbox)

$nextY += 20

$includeOriginalCheckbox = New-Object System.Windows.Forms.CheckBox
$includeOriginalCheckbox.Text = "Include original names in SAN list (without domain suffix)"
$includeOriginalCheckbox.Location = [System.Drawing.Point]::new(10, $nextY)
$includeOriginalCheckbox.Size = [System.Drawing.Size]::new(350, 25)
$form.Controls.Add($includeOriginalCheckbox)

$nextY += 40

# Button to install RSAT tools (hidden by default)
$installRsatButton = New-Object System.Windows.Forms.Button
$installRsatButton.Text = "Install RSAT Tools"
$installRsatButton.Location = [System.Drawing.Point]::new(450, ($nextY - 50))  # Adjust position as needed
$installRsatButton.Size = [System.Drawing.Size]::new(180, 35)
$installRsatButton.Visible = $false
$form.Controls.Add($installRsatButton)

# Event handler for RSAT install
$installRsatButton.Add_Click({
    try {
        Update-Status "Installing RSAT tools... This may take a few minutes."
        Start-Process powershell -ArgumentList 'Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0' -Verb RunAs
        Update-Status "RSAT installation started. Please wait for completion."
    } catch {
        Update-Status "Failed to start RSAT installation: $_" $true
    }
})


# -------------------------
# Status Box
# -------------------------
$statusBox = New-Object System.Windows.Forms.RichTextBox
$statusBox.Location = [System.Drawing.Point]::new(10, $nextY)
$statusBox.Size = [System.Drawing.Size]::new(650, 350)
$statusBox.ReadOnly = $true
$statusBox.ScrollBars = "Vertical"
$form.Controls.Add($statusBox)

#endregion

#region 5. Status Updates
function Update-Status($message, $isError=$false) {
    $statusBox.SelectionStart = $statusBox.Text.Length
    $statusBox.SelectionLength = 0
    $statusBox.SelectionColor = if ($isError) { [System.Drawing.Color]::Red } else { [System.Drawing.Color]::Black }
    $statusBox.AppendText("$message`r`n")
    $statusBox.ScrollToCaret()
}
#endregion

#region 6. Certificate Request Generationm
function Generate-ReqFile($fields, $template, $submitToCA) {
    $domainSuffix = "." + $yourDomainSuffix
    $cn = $fields["Common Name"]
    if ([string]::IsNullOrWhiteSpace($cn)) {
        Update-Status "ERROR: Common Name is required." $true .\Certificate-SelectAdvanced.txt
        return
    }
    if (-not $cn.EndsWith($domainSuffix)) { $cn += $domainSuffix }

    $ou = $fields["Organizational Unit"]
    $o = $fields["Organization"]
    $l = $fields["Locality"]
    $s = $fields["State"]
    $c = $fields["Country"]
    $emailInput = $fields["Point of Contact Email"]
    $email = $emailInput.Trim()
    if ($email -and -not ($email -match "@")) { $email += "@" + $yourDomainSuffix }

    $sansInput = $fields["SANs"]
    $sansList = @($cn)
    if ($sansInput -and $sansInput.Trim()) {
        $additionalSANs = $sansInput -split ","
        foreach ($san in $additionalSANs) {
            $sanTrimmed = $san.Trim()
            if (-not $sanTrimmed.EndsWith($domainSuffix)) { $sanTrimmed += $domainSuffix }
            $sansList += $sanTrimmed
        # If checkbox is checked, also add original name
        if ($includeOriginalCheckbox.Checked) {
            $sansList += $san.Trim()
        }
    }
} 
# If checkbox is checked, also add original CN
if ($includeOriginalCheckbox.Checked) {
    $sansList += $fields["Common Name"]
}

    $sanFormatted = ($sansList | ForEach-Object { "dns=$_"} ) -join "&"
    $sanSection = @"
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "$sanFormatted"
"@

    $baseName = $cn -replace '[^a-zA-Z0-9.\-]', '_'
    $infPath = Join-Path $scriptDir "$baseName.inf"
    $reqPath = Join-Path $scriptDir "$baseName.req"

    # Check if .req file exists
    if (Test-Path $reqPath) {
        Update-Status "WARNING: Existing request file will be overwritten." $true
    }

    $infContent = @"
[Version]
Signature="$Windows NT$"
[NewRequest]
Subject = "CN=$cn, OU=$ou, O=$o, L=$l, S=$s, C=$c, E=$email"
KeySpec = 1
KeyLength = 4096
Exportable = TRUE
MachineKeySet = TRUE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = CMC
KeyUsage = 0xa0
$sanSection
[RequestAttributes]
CertificateTemplate = $template
"@
    $infContent | Out-File -FilePath $infPath -Encoding ascii
    certreq -new -f $infPath $reqPath
    Update-Status "Certificate request saved to: $reqPath"

    if ($submitToCA) {
        $caConfig = $yourCA
        $submitResult = certreq -submit -config "$caConfig" $reqPath
        Update-Status "CA submission result: $submitResult"
        $requestId = ($submitResult | Select-String 'RequestId:\s*(\d+)').Matches.Groups[1].Value
        if ($requestId) {
            Update-Status "Request submitted successfully. Request ID: $requestId"
            Add-Content -Path (Join-Path $scriptDir "RequestLog.txt") -Value "$requestId,$cn,$template"
        }
        if ($requestId) {
    $requestIdBox.Text = $requestId
}
    }    
}
#endregion

#region 7. Retrieve and Export Certificate


function Retrieve-Certificate($CAConfig, $RequestID) {
    $certPath = Join-Path $scriptDir "RetrievedCert_$RequestID.cer"
    Update-Status "Attempting to retrieve certificate for Request ID: $RequestID"

    # Snapshot pre-install thumbprints
    $preThumbprints = @(Get-ChildItem Cert:\LocalMachine\My | Select-Object -ExpandProperty Thumbprint)

    $output = certreq -retrieve -f -config "$CAConfig" $RequestID $certPath 2>&1
    if (-not (Test-Path $certPath)) {
        Update-Status "ERROR: Certificate file not created. Output:`n$output" $true
        return $false
    }

    $acceptOutput = certreq -accept -f -machine $certPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        Update-Status "Certificate retrieved and installed successfully."

        # Diff post-install to find the new thumbprint
        $postThumbprints = @(Get-ChildItem Cert:\LocalMachine\My | Select-Object -ExpandProperty Thumbprint)
        $newThumb = ($postThumbprints | Where-Object { $_ -notin $preThumbprints } | Select-Object -First 1)

        if ($newThumb) {
            $script:LastInstalledThumbprint = $newThumb
            Update-Status "Newly installed certificate thumbprint: $newThumb"

            # OPTIONAL: append thumbprint to RequestLog.txt for this RequestID
            $logFile = Join-Path $scriptDir "RequestLog.txt"
            if (Test-Path $logFile) {
                $lines = Get-Content $logFile
                $updated = $false
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match "^\s*$RequestID,") {
                        if ($lines[$i] -notmatch ",[0-9A-F]{40}$") {
                            $lines[$i] = $lines[$i] + "," + $newThumb
                            $updated = $true
                        }
                        break
                    }
                }
                if ($updated) { $lines | Set-Content $logFile }
            }
        } else {
            Update-Status "WARNING: Could not determine new thumbprint (CN collision or pre-existing match)." $true
        }
        return $true
    } else {
        Update-Status "ERROR during accept:`n$acceptOutput" $true
        return $false
    }
}


function Export-Pfx($CN, $RequestID) {
    # Sanitize CN for filename
    $safeCN = ($CN -replace '[^a-zA-Z0-9.\-]', '_')

    # Build filename: CN + optional RequestID
    $fileName = if ($RequestID -and $RequestID.Trim()) {
        "$safeCN-$RequestID.pfx"
    } else {
        "$safeCN-unknownReqID.pfx"
    }

    $pfxPath = Join-Path $scriptDir $fileName
    Update-Status "Preparing to export certificate to $pfxPath"

    # GUI password prompt
    $passwordForm = New-Object System.Windows.Forms.Form
    $passwordForm.Text = "Enter PFX Password"
    $passwordForm.Size = [System.Drawing.Size]::new(400,150)
    $passwordForm.StartPosition = "CenterScreen"

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "Password:"
    $label.Location = [System.Drawing.Point]::new(20,30)
    $label.Size = [System.Drawing.Size]::new(80,20)
    $passwordForm.Controls.Add($label)

    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = [System.Drawing.Point]::new(110,30)
    $textbox.Size = [System.Drawing.Size]::new(250,25)
    $textbox.UseSystemPasswordChar = $true
    $passwordForm.Controls.Add($textbox)

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Location = [System.Drawing.Point]::new(150,70)
    $okButton.Add_Click({ $passwordForm.DialogResult = [System.Windows.Forms.DialogResult]::OK })
    $passwordForm.Controls.Add($okButton)
    
    # Enable Enter key to trigger OK
    $passwordForm.AcceptButton = $okButton

    # Cancel Button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = [System.Drawing.Point]::new(230,70)
    $cancelButton.Add_Click({ $passwordForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel })
    $passwordForm.Controls.Add($cancelButton)

    # Allow for ESC key to cancel
    $passwordForm.KeyPreview = $true
    $passwordForm.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            $passwordForm.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $passwordForm.Close()
        }
    })



if ($passwordForm.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    if ([string]::IsNullOrWhiteSpace($textbox.Text)) {
    Update-Status "Password entry canceled. Blank password not allowed" $true
    return
    } else {
        $password = ConvertTo-SecureString $textbox.Text -AsPlainText -Force
    }
} else {
    Update-Status "Password entry canceled." $true
    return
}
    

    # Find matching certificates
    $certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$CN*" }
    if (-not $certs) {
        Update-Status "ERROR: No certificate found matching CN '$CN' in LocalMachine\My store." $true
        return
    }

    # Show what we found
    Update-Status "Found $($certs.Count) certificate(s) matching CN '$CN':"
    foreach ($c in $certs) {
        Update-Status "Subject: $($c.Subject) | Thumbprint: $($c.Thumbprint) | Exportable: $($c.PrivateKey.CspKeyContainerInfo.Exportable)"
    }

    # Use first match for export
    $cert = $certs[0]
    Update-Status "Using certificate with Thumbprint: $($cert.Thumbprint) for export."

    try {
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password -Force
        Update-Status "PFX exported successfully to $pfxPath"
    }
    catch {
        Update-Status "ERROR during PFX export: $($_.Exception.Message)" $true
    }
}



function Export-Cer {
    param(
        [Parameter(Mandatory=$true)] [string] $CN,
        [Parameter(Mandatory=$false)] [string] $RequestID
    )
    $safeCN = ($CN -replace '[^a-zA-Z0-9.\-]', '_')
    $cerName = if ($RequestID -and $RequestID.Trim()) { "Cer_${safeCN}-${RequestID}.cer" } else { "Cer_${safeCN}-unknownReqID.cer" }
    $cerPath = Join-Path $scriptDir $cerName

    # Prefer last installed thumbprint; fall back to CN match
    $cert = $null
    if ($script:LastInstalledThumbprint) {
        $cert = Get-ChildItem "Cert:\LocalMachine\My\$script:LastInstalledThumbprint" -ErrorAction SilentlyContinue
    }
    if (-not $cert) {
        $matches = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$CN*" }
        if (-not $matches -or $matches.Count -eq 0) {
            Update-Status "ERROR: No certificate found matching CN '$CN' in LocalMachine\My store." $true
            return
        }
        # pick newest as a stable heuristic
        $cert = ($matches | Sort-Object NotBefore -Descending | Select-Object -First 1)
    }

    Update-Status "Exporting CER for Subject: $($cert.Subject) | Thumbprint: $($cert.Thumbprint)"
    try {
        Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
        Update-Status "CER exported successfully to $cerPath"
    } catch {
        Update-Status "ERROR during CER export: $($_.Exception.Message)" $true
    }
}






function Export-PrivateKey {
    param(
        [Parameter(Mandatory=$true)] [string] $CN,
        [Parameter(Mandatory=$false)] [string] $RequestID
    )

    # Prefer the cert we just accepted via thumbprint
    $cert = $null
    if ($script:LastInstalledThumbprint) {
        $cert = Get-ChildItem "Cert:\LocalMachine\My\$script:LastInstalledThumbprint" -ErrorAction SilentlyContinue
        if ($cert) { Update-Status "Using last installed cert thumbprint: $($script:LastInstalledThumbprint)" }
    }
    if (-not $cert) {
        # Fallback: CN match (newest)
        $matches = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CN=$CN*" -or $_.Subject -like "*$CN*" }
        if (-not $matches -or $matches.Count -eq 0) {
            Update-Status "ERROR: No certificate found matching CN '$CN' in LocalMachine\My." $true
            return
        }
        $cert = ($matches | Sort-Object NotBefore -Descending | Select-Object -First 1)
        Update-Status "Selected by CN. Subject: $($cert.Subject) | Thumbprint: $($cert.Thumbprint)"
    }

    if (-not $cert.HasPrivateKey) {
        Update-Status "ERROR: The selected certificate does not have a linked private key." $true
        return
    }

    # File naming
    $safeCN  = ($CN -replace '[^a-zA-Z0-9.\-]', '_')
    $label   = if ($RequestID -and $RequestID.Trim()) { "${safeCN}-${RequestID}" } else { "${safeCN}-unknownReqID" }
    $pkcs8Path = Join-Path $scriptDir ("PrivateKey_{0}.pem" -f $label)
    $pkcs1Path = Join-Path $scriptDir ("PrivateKey_{0}.key" -f $label)

    # Try CNG path you used (PKCS#8 PEM)
    try {
        $rsaCng = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($rsaCng -and ($rsaCng.PSObject.Properties.Name -contains 'Key') -and $rsaCng.Key) {
            # Export as PKCS#8 blob
            $bytes = $rsaCng.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            $b64   = [System.Convert]::ToBase64String($bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
            $pem   = @"
-----BEGIN PRIVATE KEY-----
$b64
-----END PRIVATE KEY-----
"@
            $pem | Out-File -FilePath $pkcs8Path -Encoding ascii -Force
            Update-Status "Private key exported (PKCS#8, CNG) to $pkcs8Path"
            return
        }
    } catch {
        Update-Status "INFO: CNG PKCS#8 export not available, trying RSA CSP fallback (PKCS#1)." # not an error; we'll fall back
    }

    # Fallback: CSP RSA (PKCS#1 via RSAParameters)
    try {
        # Get RSA handle via PrivateKey or RSACertificateExtensions
        $rsa = $null
        try { $rsa = $cert.PrivateKey } catch { $rsa = $null }
        if (-not $rsa -or -not ($rsa -is [System.Security.Cryptography.RSA])) {
            try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert) } catch { $rsa = $null }
        }
        if (-not $rsa -or -not ($rsa -is [System.Security.Cryptography.RSA])) {
            Update-Status "ERROR: Could not obtain an RSA private key handle for fallback export." $true
            return
        }

        # Ensure exportable for CSP
        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $csp = [System.Security.Cryptography.RSACryptoServiceProvider]$rsa
            if (-not $csp.CspKeyContainerInfo.Exportable) {
                Update-Status "ERROR: Private key marked non-exportable by provider (CSP). Ensure the new cert was created with Exportable=TRUE and you're targeting it by thumbprint." $true
                return
            }
        }

        $params = $rsa.ExportParameters($true)
        Write-Pkcs1PemFromRSAParameters -Params $params -OutPath $pkcs1Path
        Update-Status "Private key exported (PKCS#1, CSP) to $pkcs1Path"
    } catch {
        Update-Status "ERROR exporting private key: $($_.Exception.Message)" $true
    }
}



#endregion

#region 8. Event Handlers
$cleanupButton.Add_Click({
    Get-ChildItem -Path $scriptDir -Filter *.req | Remove-Item -Force
    Get-ChildItem -Path $scriptDir -Filter *.inf | Remove-Item -Force
    Get-ChildItem -Path $scriptDir -Filter *.rsp | Remove-Item -Force
    Get-ChildItem -Path $scriptDir -Filter RetrievedCert_*.cer | Remove-Item -Force
    Update-Status "WARNING: All .req, .rsp and .inf files have been deleted as well as RetrievedCert_*.Cer." $true
})

$submitButton.Add_Click({
    $fields = @{}
    foreach ($label in $labels) { $fields[$label] = $textboxes[$label].Text }
    $cn = $fields["Common Name"]
    if (-not $cn -or -not (Validate-CN $cn)) {
        Update-Status "ERROR: Common Name is required and must be valid." $true
        return
    }
    $template = $templateDropdown.SelectedItem
    if ($template -match "Access Denied") {
        Update-Status "ERROR: Selected template is not accessible." $true
        return
    }
    $submitToCA = $submitCheckbox.Checked
    Generate-ReqFile $fields $template $submitToCA
})

$retrieveButton.Add_Click({
    $requestId = $requestIdBox.Text.Trim()
    if (-not $requestId) {
        Update-Status "ERROR: Request ID is required." $true
        return
    }
    $caConfig = $yourCA
    if (Retrieve-Certificate $caConfig $requestId) {
        Update-Status "You can now export the certificate to PFX using the Export button."
    }
})


$exportButton.Add_Click({
    $cn = $textboxes["Common Name"].Text
    $requestId = $requestIdBox.Text.Trim()  # Always read current value from the box

    if (-not $cn) {
        Update-Status "ERROR: Common Name is required for export." $true
        return
    }

    if ([string]::IsNullOrWhiteSpace($requestId)) {
        Update-Status "WARNING: Request ID is blank. Export will use 'unknownReqID' in filename." $true
    } else {
        Update-Status "Exporting certificate for CN '$cn' with Request ID '$requestId'..."
    }

    Export-Pfx $cn $requestId
})


$exportCerButton.Add_Click({
    $cn = $textboxes["Common Name"].Text
    $requestId = $requestIdBox.Text.Trim()

    if (-not $cn) {
        Update-Status "ERROR: Common Name is required for CER export." $true
        return
    }
    if ([string]::IsNullOrWhiteSpace($requestId)) {
        Update-Status "WARNING: Request ID is blank. CER will use 'unknownReqID' in filename." $true
    } else {
        Update-Status "Exporting CER for CN '$cn' with Request ID '$requestId'..."
    }
    Export-Cer -CN $cn -RequestID $requestId
})

$exportKeyButton.Add_Click({
    $cn = $textboxes["Common Name"].Text
    $requestId = $requestIdBox.Text.Trim()

    if (-not $cn) {
        Update-Status "ERROR: Common Name is required for Private Key export." $true
        return
    }
    if ([string]::IsNullOrWhiteSpace($requestId)) {
        Update-Status "WARNING: Request ID is blank. Key export will use 'unknownReqID' in filename." $true
    } else {
        Update-Status "Exporting Private Key for CN '$cn' with Request ID '$requestId'..."
    }

    # Default PKCS#1; change to 'PKCS8' if desired or add a small dropdown/toggle
    Export-PrivateKey -CN $cn -RequestID $requestId -Format 'PKCS1'
})

$exportKeyButton.Add_Click({
    $cn = $textboxes["Common Name"].Text
    $requestId = $requestIdBox.Text.Trim()

    if (-not $cn) {
        Update-Status "ERROR: Common Name is required for Private Key export." $true
        return
    }
    if ([string]::IsNullOrWhiteSpace($requestId)) {
        Update-Status "WARNING: Request ID is blank. Key export will use 'unknownReqID' in filename." $true
    } else {
        Update-Status "Exporting Private Key for CN '$cn' with Request ID '$requestId'..."
    }
    Export-PrivateKey -CN $cn -RequestID $requestId
})


$approveButton.Add_Click({
    $requestId = $requestIdBox.Text.Trim()
    if (-not $requestId) {
        Update-Status "ERROR: Request ID is required to approve." $true
        return
    }
    if ($rsatInstalled -eq 'Installed') {
        Update-Status "RSAT tools detected. Approving request $requestId..."
        $caConfig = $yourCA
        $approveResult = certutil -config "$caConfig" -resubmit $requestId
        Update-Status "Approve result:`n$approveResult"
    } else {
        Update-Status "RSAT tools NOT installed. Please run this command to install:" $true
        Update-Status 'Add-WindowsCapability -Online -Name Rsat.CertificateServices.Tools~~~~0.0.1.0'
    }
})



# Handle Escape key to close the app
$form.KeyPreview = $true
$form.Add_KeyDown({
    if ($_.KeyCode -eq 'Escape') {
        [System.Environment]::Exit(0)
    }
})

# Ensure app exits when form closes
$form.Add_FormClosing({
    [System.Environment]::Exit(0)
})



$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
#endregion
