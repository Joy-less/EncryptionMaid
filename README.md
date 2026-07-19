# EncryptionMaid

[![NuGet](https://img.shields.io/nuget/v/EncryptionMaid.svg)](https://www.nuget.org/packages/EncryptionMaid)

Super simple encryption in C#.

## Usage

### AesGcmMaid

[AES-GCM](https://medium.com/@pravallikayakkala123/understanding-aes-encryption-and-aes-gcm-mode-an-in-depth-exploration-using-java-e03be85a3faa) ensures confidentiality and authenticity:
- A randomly-generated nonce ensures identical inputs produce different outputs.
- An authentication tag ensures the encrypted data was not tampered with.

```cs
using EncryptionMaid;

string Input = "my data to encrypt";
string Password = "my super secret password";

byte[] EncryptedBytes = AesGcmMaid.EncryptStringWithPassword(Input, Password, 600_000);

string DecryptedInput = AesGcmMaid.DecryptStringWithPassword(EncryptedBytes, Password, 600_000);
```

> [!WARNING]
> As of .NET 10.0, AES-GCM is not supported on browser platforms.

## Disclaimer

This implementation has been tested but not audited, so use at your own risk.