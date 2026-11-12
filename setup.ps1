# sanity check if certificate already generated
$caCertPath = Join-Path $PSScriptRoot "ca.crt"
$caKeyPath = Join-Path $PSScriptRoot "ca.key"

if (Test-Path $caCertPath) {
    Write-Host "Certificate already generated at $caCertPath. Delete or rename this file before generating a new certificate."
    exit 1
}

if (Test-Path $caKeyPath) {
    Write-Host "Key already generated at $caKeyPath. Delete or rename this file before generating a new certificate."
    exit 1
}

# create key
openssl ecparam -name prime256v1 -genkey -noout -out $caKeyPath

# create cert
$uuid = [guid]::NewGuid().ToString()
openssl req -x509 -new -nodes `
  -subj "/CN=$uuid" `
  -addext 'basicConstraints=critical,CA:TRUE' `
  -addext 'keyUsage=critical,keyCertSign,cRLSign' `
  -addext 'subjectKeyIdentifier=hash' `
  -key $caKeyPath `
  -sha256 `
  -days 3650 `
  -out $caCertPath
