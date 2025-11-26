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
##############################################
$yourCA = "yourCA.yourdomain.com\Your Certification Authority"
$yourDomainSuffix = "yourdomain.com"
# -------------------------
# Input Fields
# -------------------------
$labels = @("Common Name", "SANs", "Point of Contact Email", "Organizational Unit", "Organization", "Locality", "State", "Country")
$defaults = @{
    "Common Name" = "ServerName"
    "Organizational Unit" = "IT Services"
    "Organization" = "Organization"
    "Locality" = "City"
    "State" = "State"
    "Country" = "US"
}
$textboxes = @{}

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
$submitButton.Size = [System.Drawing.Size]::new(150, 35)
$form.Controls.Add($submitButton)

$retrieveButton = New-Object System.Windows.Forms.Button
$retrieveButton.Text = "Retrieve and Install"
$retrieveButton.Location = [System.Drawing.Point]::new(170, $nextY)
$retrieveButton.Size = [System.Drawing.Size]::new(150, 35)
$form.Controls.Add($retrieveButton)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Export PFX"
$exportButton.Location = [System.Drawing.Point]::new(330, $nextY)
$exportButton.Size = [System.Drawing.Size]::new(150, 35)
$form.Controls.Add($exportButton)

$cleanupButton = New-Object System.Windows.Forms.Button
$cleanupButton.Text = "Delete .req, .rsp .inf RetrievedCert_*.Cer"
$cleanupButton.Location = [System.Drawing.Point]::new(490, $nextY)
$cleanupButton.Size = [System.Drawing.Size]::new(180, 35)
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
    $output = certreq -retrieve -f -config "$CAConfig" $RequestID $certPath 2>&1
    if (-not (Test-Path $certPath)) {
        Update-Status "ERROR: Certificate file not created. Output:`n$output" $true
        return $false
    }
    $acceptOutput = certreq -accept -f -machine $certPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        Update-Status "Certificate retrieved and installed successfully."
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


