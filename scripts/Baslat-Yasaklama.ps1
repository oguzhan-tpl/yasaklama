$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $ProjectRoot

# DNS port 53 and HTTP portal port 80 require an elevated process on Windows.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $escapedPath = '"' + $PSCommandPath.Replace('"', '\"') + '"'
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -File $escapedPath"
    exit
}

Write-Host ""
Write-Host " YASAKLAMA | Okul agi engelleme servisi" -ForegroundColor Cyan
Write-Host " --------------------------------------"
Write-Host "Bu bilgisayarda DNS filtresi, yonetim paneli ve HTTP engel sayfasi acilacak."
Write-Host "Yonetici izni Windows tarafindan onaylanir; guvenlik onlemleri atlanmaz."
Write-Host ""

$ipConfig = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | Sort-Object InterfaceMetric | Select-Object -First 1
if (-not $ipConfig) { throw "Etkin ag arabirimi bulunamadi. Once okul agina baglanin." }
$serverIP = [string]$ipConfig.IPv4Address[0].IPAddress
if ([string]::IsNullOrWhiteSpace($serverIP) -or $serverIP.StartsWith("169.254.") -or $serverIP.StartsWith("127.")) {
    throw "Gecerli yerel IPv4 adresi bulunamadi."
}
Write-Host "Sunucu LAN IP: $serverIP" -ForegroundColor Green
if ($ipConfig.NetIPv4Interface.Dhcp -eq "Enabled") {
    Write-Host "NOT: IP DHCP ile alinmis gorunuyor. Router'da bu bilgisayar icin DHCP rezervasyonu yapin; IP degismemeli." -ForegroundColor Yellow
}
Write-Host ""

$python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $pyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if (-not $pyLauncher) { throw "Python 3.11+ bulunamadi. Python kurun ve 'py -3 --version' komutunu dogrulayin." }
    & $pyLauncher.Source -3 -m venv (Join-Path $ProjectRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Sanal Python ortami olusturulamadi." }
    if (-not (Test-Path $python)) { throw ".venv Python dosyasi olusturulamadi." }
}
& $python -m pip install --disable-pip-version-check -r (Join-Path $ProjectRoot "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Python paketleri kurulurken hata olustu." }

$configFile = Join-Path $ProjectRoot "data\config.json"
if (-not (Test-Path $configFile)) {
    Write-Host "Ilk kullanim: yonetici parolasini olusturun." -ForegroundColor Cyan
    & $python (Join-Path $ProjectRoot "controller.py") --init-admin
    if ($LASTEXITCODE -ne 0) { throw "Ilk yonetici kurulumu basarisiz." }
}

$certFile = Join-Path $ProjectRoot "data\server-cert.pem"
$keyFile = Join-Path $ProjectRoot "data\server-key.pem"
if (-not (Test-Path $certFile) -or -not (Test-Path $keyFile)) {
    & $python (Join-Path $ProjectRoot "scripts\create_lan_cert.py") --ip $serverIP --output-dir (Join-Path $ProjectRoot "data")
    if ($LASTEXITCODE -ne 0) { throw "HTTPS sertifikasi olusturulamadi." }
}

$occupiedDns = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)
$occupiedDnsTcp = @(Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue)
if ($occupiedDns.Count -gt 0 -or $occupiedDnsTcp.Count -gt 0) {
    $pids = (@($occupiedDns + $occupiedDnsTcp) | Select-Object -ExpandProperty OwningProcess -Unique) -join ", "
    throw "Port 53 baska bir program tarafindan kullaniliyor (PID: $pids). Once DNS portunu kullanan servisi yetkili yoneticiyle inceleyin."
}
$occupiedHttp = @(Get-NetTCPConnection -State Listen -LocalPort 80 -ErrorAction SilentlyContinue)
if ($occupiedHttp.Count -gt 0) {
    $pids = ($occupiedHttp | Select-Object -ExpandProperty OwningProcess -Unique) -join ", "
    throw "TCP 80 baska bir program tarafindan kullaniliyor (PID: $pids). IIS veya baska web sunucusunu kontrol edin."
}
$occupiedPanel = @(Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue)
if ($occupiedPanel.Count -gt 0) {
    $pids = ($occupiedPanel | Select-Object -ExpandProperty OwningProcess -Unique) -join ", "
    throw "TCP 8765 baska bir program tarafindan kullaniliyor (PID: $pids)."
}

$firewallRules = @(
    @{ Name = "Yasaklama DNS UDP 53"; Protocol = "UDP"; Port = "53" },
    @{ Name = "Yasaklama DNS TCP 53"; Protocol = "TCP"; Port = "53" },
    @{ Name = "Yasaklama HTTP Block Portal 80"; Protocol = "TCP"; Port = "80" },
    @{ Name = "Yasaklama Admin HTTPS 8765"; Protocol = "TCP"; Port = "8765" }
)
foreach ($rule in $firewallRules) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol $rule.Protocol -LocalPort $rule.Port -Profile Any -RemoteAddress LocalSubnet -Description "Yasaklama authorized school LAN service" | Out-Null
    }
}

Write-Host ""
Write-Host "Bir defalik ag ayari:" -ForegroundColor Yellow
Write-Host ("Router/DHCP yonetim ekraninda istemcilerin DNS adresini {0} yapin." -f $serverIP)
Write-Host "Bu ayar yapilmadan diger bilgisayarlarin DNS sorgulari bu bilgisayara gelmez."
Write-Host ("Yonetim paneli: https://{0}:8765" -f $serverIP)
Write-Host ("HTTP engel sayfasi: http://{0}" -f $serverIP)
Write-Host "Kural eklemek/kaldirmak icin panelden site baglantisini yapistirman yeterli."
Write-Host ""
Write-Host "TLS notu: yerel sertifika ilk baglantida tarayici uyarisi verir. Kurumsal kullanimda okulun guvenilir sertifikasini kullanin." -ForegroundColor Yellow
Write-Host "HTTPS engelli sitelerde ozel HTML sayfasi degil TLS/sertifika engeli gorulebilir; DNS tek basina HTTPS icerigini degistiremez." -ForegroundColor Yellow
Write-Host ""
Write-Host "Servis baslatiliyor. Durdurmak icin Ctrl+C." -ForegroundColor Green

& $python (Join-Path $ProjectRoot "controller.py") --web-host 0.0.0.0 --web-port 8765 --ssl-certfile $certFile --ssl-keyfile $keyFile --dns-host 0.0.0.0 --dns-port 53 --upstream 1.1.1.1 --block-ip $serverIP --block-page-host 0.0.0.0 --block-page-port 80
if ($LASTEXITCODE -ne 0) { Write-Host "Servis kapandi veya hata olustu (kod $LASTEXITCODE)." -ForegroundColor Red }
