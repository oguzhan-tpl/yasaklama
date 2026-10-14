$ErrorActionPreference = "Continue"
Write-Host ""
Write-Host "YASAKLAMA - Salt okunur ağ ön kontrolü" -ForegroundColor Cyan
Write-Host "Bu betik IP/DNS ayarlarını, DNS bölgelerini veya güvenlik duvarını DEĞİŞTİRMEZ."
Write-Host ""

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os) {
    Write-Host ("İşletim sistemi: {0}" -f $os.Caption)
    Write-Host ("Sürüm: {0}" -f $os.Version)
}
Write-Host ""

$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
if ($dnsService) {
    Write-Host ("Windows DNS hizmeti: {0}" -f $dnsService.Status)
} else {
    Write-Host "Windows DNS hizmeti: bulunamadı" -ForegroundColor Yellow
}
if (Get-Module -ListAvailable -Name DnsServer) {
    Write-Host "DnsServer PowerShell modülü: kurulu"
} else {
    Write-Host "DnsServer PowerShell modülü: bulunamadı" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Bu sunucunun etkin ağ arabirimleri:"
$ipConfigs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue |
    Where-Object { $_.IPv4Address } )
if ($ipConfigs.Count -eq 0) {
    Write-Host "IPv4 arabirimi bulunamadı." -ForegroundColor Yellow
} else {
    foreach ($cfg in $ipConfigs) {
        $addresses = @($cfg.IPv4Address | ForEach-Object { $_.IPAddress }) -join ", "
        $dnsServers = @()
        if ($cfg.DNSServer -and $cfg.DNSServer.ServerAddresses) {
            $dnsServers = @($cfg.DNSServer.ServerAddresses)
        }
        Write-Host ("- {0}: IPv4={1}; DNS={2}" -f $cfg.InterfaceAlias, $addresses, ($dnsServers -join ", "))
    }
}

Write-Host ""
Write-Host "Yerel 53 numaralı port dinleyicileri:"
$udp = @(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue)
$tcp = @(Get-NetTCPConnection -State Listen -LocalPort 53 -ErrorAction SilentlyContinue)
if (($udp.Count + $tcp.Count) -eq 0) {
    Write-Host "UDP/TCP 53 dinleyicisi bulunamadı."
} else {
    foreach ($row in $udp) {
        $proc = Get-Process -Id $row.OwningProcess -ErrorAction SilentlyContinue
        Write-Host ("- UDP 53, adres={0}, PID={1}, süreç={2}" -f $row.LocalAddress, $row.OwningProcess, $proc.ProcessName)
    }
    foreach ($row in $tcp) {
        $proc = Get-Process -Id $row.OwningProcess -ErrorAction SilentlyContinue
        Write-Host ("- TCP 53, adres={0}, PID={1}, süreç={2}" -f $row.LocalAddress, $row.OwningProcess, $proc.ProcessName)
    }
}

Write-Host ""
Write-Host "ÖNEMLİ:"
Write-Host "Bu çıktı yalnızca sunucunun yerel durumunu gösterir; okul istemcilerinin gerçekten hangi DNS sunucusunu kullandığını tek başına kanıtlamaz."
Write-Host "İstemcilerin mevcut DNS adresi bu Windows DNS sunucusunun IP adresi değilse, istemci/DHCP ayarı veya mevcut ağ geçidi değiştirilmeden bu sunucudaki DNS kuralı tüm istemcilere uygulanamaz."
Write-Host "Hiçbir ayar değiştirilmedi." -ForegroundColor Green
Write-Host ""
