Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security

function Create-SecureKey {
    param (
        [string]$password,
        [byte[]]$salt
    )
    
    $iterations = 600000
    $deriveBytes = New-Object Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $iterations)
    $encryptionKey = $deriveBytes.GetBytes(32)
    $hmacKey = $deriveBytes.GetBytes(32)
    return @($encryptionKey, $hmacKey)
}

function Test-PasswordStrength {
    param (
        [string]$password
    )
    
    if ($password.Length -lt 16) { return $false }
    if ($password -notmatch "[A-Z]") { return $false }
    if ($password -notmatch "[a-z]") { return $false }
    if ($password -notmatch "[0-9]") { return $false }
    if ($password -notmatch "[^A-Za-z0-9]") { return $false }
    
    return $true
}

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Secure File Encryption/Decryption Tool (AES-256)"
$form.Size = New-Object System.Drawing.Size(620, 450)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Create tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(585, 390)

# Create Encryption tab
$encryptionTab = New-Object System.Windows.Forms.TabPage
$encryptionTab.Text = "Encryption"
$tabControl.Controls.Add($encryptionTab)

# Create Decryption tab
$decryptionTab = New-Object System.Windows.Forms.TabPage
$decryptionTab.Text = "Decryption"
$tabControl.Controls.Add($decryptionTab)

# Encryption Tab Controls
$encSecurityNote = New-Object System.Windows.Forms.Label
$encSecurityNote.Location = New-Object System.Drawing.Point(10, 10)
$encSecurityNote.Size = New-Object System.Drawing.Size(540, 40)
$encSecurityNote.Text = "This tool uses AES-256 with HMAC-SHA512 authentication and secure key derivation."
$encSecurityNote.Font = New-Object System.Drawing.Font("Arial", 9)

$encSelectButton = New-Object System.Windows.Forms.Button
$encSelectButton.Location = New-Object System.Drawing.Point(10, 60)
$encSelectButton.Size = New-Object System.Drawing.Size(120, 30)
$encSelectButton.Text = "Select File"

$encFilePathBox = New-Object System.Windows.Forms.TextBox
$encFilePathBox.Location = New-Object System.Drawing.Point(140, 60)
$encFilePathBox.Size = New-Object System.Drawing.Size(410, 30)
$encFilePathBox.ReadOnly = $true

$encPasswordLabel = New-Object System.Windows.Forms.Label
$encPasswordLabel.Location = New-Object System.Drawing.Point(10, 110)
$encPasswordLabel.Size = New-Object System.Drawing.Size(120, 20)
$encPasswordLabel.Text = "Password:"

$encPasswordBox = New-Object System.Windows.Forms.TextBox
$encPasswordBox.Location = New-Object System.Drawing.Point(140, 110)
$encPasswordBox.Size = New-Object System.Drawing.Size(410, 30)
$encPasswordBox.PasswordChar = "*"

$encConfirmLabel = New-Object System.Windows.Forms.Label
$encConfirmLabel.Location = New-Object System.Drawing.Point(10, 150)
$encConfirmLabel.Size = New-Object System.Drawing.Size(120, 20)
$encConfirmLabel.Text = "Confirm Password:"

$encConfirmBox = New-Object System.Windows.Forms.TextBox
$encConfirmBox.Location = New-Object System.Drawing.Point(140, 150)
$encConfirmBox.Size = New-Object System.Drawing.Size(410, 30)
$encConfirmBox.PasswordChar = "*"

$encRequirementsLabel = New-Object System.Windows.Forms.Label
$encRequirementsLabel.Location = New-Object System.Drawing.Point(140, 190)
$encRequirementsLabel.Size = New-Object System.Drawing.Size(410, 30)
$encRequirementsLabel.Text = "Password must be at least 16 characters with uppercase, lowercase, numbers, and symbols"
$encRequirementsLabel.Font = New-Object System.Drawing.Font("Arial", 8)

$encryptButton = New-Object System.Windows.Forms.Button
$encryptButton.Location = New-Object System.Drawing.Point(190, 230)
$encryptButton.Size = New-Object System.Drawing.Size(200, 40)
$encryptButton.Text = "Encrypt File"
$encryptButton.Enabled = $false

$encStatusBox = New-Object System.Windows.Forms.TextBox
$encStatusBox.Location = New-Object System.Drawing.Point(10, 280)
$encStatusBox.Size = New-Object System.Drawing.Size(540, 60)
$encStatusBox.Multiline = $true
$encStatusBox.ScrollBars = "Vertical"
$encStatusBox.ReadOnly = $true

# Add controls to Encryption tab
$encryptionTab.Controls.Add($encSecurityNote)
$encryptionTab.Controls.Add($encSelectButton)
$encryptionTab.Controls.Add($encFilePathBox)
$encryptionTab.Controls.Add($encPasswordLabel)
$encryptionTab.Controls.Add($encPasswordBox)
$encryptionTab.Controls.Add($encConfirmLabel)
$encryptionTab.Controls.Add($encConfirmBox)
$encryptionTab.Controls.Add($encRequirementsLabel)
$encryptionTab.Controls.Add($encryptButton)
$encryptionTab.Controls.Add($encStatusBox)

# Decryption Tab Controls
$decSecurityNote = New-Object System.Windows.Forms.Label
$decSecurityNote.Location = New-Object System.Drawing.Point(10, 10)
$decSecurityNote.Size = New-Object System.Drawing.Size(540, 40)
$decSecurityNote.Text = "This tool decrypts files encrypted with the corresponding encryption tool."
$decSecurityNote.Font = New-Object System.Drawing.Font("Arial", 9)

$decSelectButton = New-Object System.Windows.Forms.Button
$decSelectButton.Location = New-Object System.Drawing.Point(10, 60)
$decSelectButton.Size = New-Object System.Drawing.Size(120, 30)
$decSelectButton.Text = "Select File"

$decFilePathBox = New-Object System.Windows.Forms.TextBox
$decFilePathBox.Location = New-Object System.Drawing.Point(140, 60)
$decFilePathBox.Size = New-Object System.Drawing.Size(410, 30)
$decFilePathBox.ReadOnly = $true

$decPasswordLabel = New-Object System.Windows.Forms.Label
$decPasswordLabel.Location = New-Object System.Drawing.Point(10, 110)
$decPasswordLabel.Size = New-Object System.Drawing.Size(120, 20)
$decPasswordLabel.Text = "Password:"

$decPasswordBox = New-Object System.Windows.Forms.TextBox
$decPasswordBox.Location = New-Object System.Drawing.Point(140, 110)
$decPasswordBox.Size = New-Object System.Drawing.Size(410, 30)
$decPasswordBox.PasswordChar = "*"

$decryptButton = New-Object System.Windows.Forms.Button
$decryptButton.Location = New-Object System.Drawing.Point(190, 170)
$decryptButton.Size = New-Object System.Drawing.Size(200, 40)
$decryptButton.Text = "Decrypt File"
$decryptButton.Enabled = $false

$decStatusBox = New-Object System.Windows.Forms.TextBox
$decStatusBox.Location = New-Object System.Drawing.Point(10, 230)
$decStatusBox.Size = New-Object System.Drawing.Size(540, 110)
$decStatusBox.Multiline = $true
$decStatusBox.ScrollBars = "Vertical"
$decStatusBox.ReadOnly = $true

# Add controls to Decryption tab
$decryptionTab.Controls.Add($decSecurityNote)
$decryptionTab.Controls.Add($decSelectButton)
$decryptionTab.Controls.Add($decFilePathBox)
$decryptionTab.Controls.Add($decPasswordLabel)
$decryptionTab.Controls.Add($decPasswordBox)
$decryptionTab.Controls.Add($decryptButton)
$decryptionTab.Controls.Add($decStatusBox)

# Encryption: Select File button click event
$encSelectButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "All files (*.*)|*.*"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $encFilePathBox.Text = $openFileDialog.FileName
        $encryptButton.Enabled = $true
    }
})

# Decryption: Select File button click event
$decSelectButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Encrypted files (*.encrypted)|*.encrypted|All files (*.*)|*.*"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $decFilePathBox.Text = $openFileDialog.FileName
        $decryptButton.Enabled = $true
    }
})

# Encrypt button click event
$encryptButton.Add_Click({
    if (-not (Test-PasswordStrength $encPasswordBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Password must be at least 16 characters and include uppercase, lowercase, numbers, and symbols",
            "Invalid Password",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    if ($encPasswordBox.Text -ne $encConfirmBox.Text) {
        [System.Windows.Forms.MessageBox]::Show(
            "Passwords do not match!",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    try {
        $filePath = $encFilePathBox.Text
        $password = $encPasswordBox.Text
        
        $salt = New-Object byte[] 32
        $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($salt)
        
        $keys = Create-SecureKey -password $password -salt $salt
        $encryptionKey = $keys[0]
        $hmacKey = $keys[1]
        
        $iv = New-Object byte[] 16
        $rng.GetBytes($iv)
        
        $encryptedPath = $filePath + ".encrypted"
        
        $plaintext = [System.IO.File]::ReadAllBytes($filePath)
        
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.Key = $encryptionKey
        $aes.IV = $iv
        
        $encryptor = $aes.CreateEncryptor()
        $ciphertext = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
        
        $hmacAlg = New-Object System.Security.Cryptography.HMACSHA512
        $hmacAlg.Key = $hmacKey
        $hmacData = $salt + $iv + $ciphertext
        $hmacValue = $hmacAlg.ComputeHash($hmacData)
        
        $fileStream = [System.IO.File]::Create($encryptedPath)
        $fileStream.Write($salt, 0, $salt.Length)
        $fileStream.Write($iv, 0, $iv.Length)
        $fileStream.Write($hmacValue, 0, $hmacValue.Length)
        $fileStream.Write($ciphertext, 0, $ciphertext.Length)
        $fileStream.Close()
        
        $encStatusBox.AppendText("File encrypted successfully!`r`nSaved as: $encryptedPath`r`n")
    }
    catch {
        $encStatusBox.AppendText("An error occurred during encryption: $_`r`n")
    }
    finally {
        if ($aes) { $aes.Dispose() }
        if ($hmacAlg) { $hmacAlg.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }
    }
})

# Decrypt button click event
$decryptButton.Add_Click({
    if ([string]::IsNullOrWhiteSpace($decPasswordBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please enter the password.",
            "Missing Password",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    try {
        $filePath = $decFilePathBox.Text
        $password = $decPasswordBox.Text
        
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        
        $salt = $fileBytes[0..31]
        $iv = $fileBytes[32..47]
        $storedHmac = $fileBytes[48..111]
        $ciphertext = $fileBytes[112..($fileBytes.Length-1)]
        
        $keys = Create-SecureKey -password $password -salt $salt
        $encryptionKey = $keys[0]
        $hmacKey = $keys[1]
        
        $hmacAlg = New-Object System.Security.Cryptography.HMACSHA512
        $hmacAlg.Key = $hmacKey
        $hmacData = $salt + $iv + $ciphertext
        $calculatedHmac = $hmacAlg.ComputeHash($hmacData)
        
        $hmacValid = $true
        if ($calculatedHmac.Length -eq $storedHmac.Length) {
            for ($i = 0; $i -lt $calculatedHmac.Length; $i++) {
                if ($calculatedHmac[$i] -ne $storedHmac[$i]) {
                    $hmacValid = $false
                    break
                }
            }
        } else {
            $hmacValid = $false
        }
        
        if (-not $hmacValid) {
            throw "Authentication failed! The file may be corrupted or tampered with."
        }
        
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.Key = $encryptionKey
        $aes.IV = $iv
        
        $decryptor = $aes.CreateDecryptor()
        $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        
        $directory = [System.IO.Path]::GetDirectoryName($filePath)
        $originalFileName = [System.IO.Path]::GetFileName($filePath) -replace '\.encrypted$', ''
        $decryptedFileName = "decrypted_" + $originalFileName
        $decryptedPath = [System.IO.Path]::Combine($directory, $decryptedFileName)
        
        $counter = 1
        while (Test-Path $decryptedPath) {
            $decryptedFileName = "decrypted_${counter}_" + $originalFileName
            $decryptedPath = [System.IO.Path]::Combine($directory, $decryptedFileName)
            $counter++
        }
        
        [System.IO.File]::WriteAllBytes($decryptedPath, $plaintext)
        
        $decStatusBox.AppendText("File decrypted successfully!`r`nSaved as: $decryptedPath`r`n")
    }
    catch {
        $decStatusBox.AppendText("An error occurred during decryption: $_`r`n")
    }
    finally {
        if ($aes) { $aes.Dispose() }
        if ($hmacAlg) { $hmacAlg.Dispose() }
        if ($decryptor) { $decryptor.Dispose() }
    }
})

# Add tab control to form
$form.Controls.Add($tabControl)

# Show the form
$form.ShowDialog()