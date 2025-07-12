# EncryptionMaid

Super simple encryption in C#.

## Usage

### AesGcmMaid (recommended)

[AES-GCM](https://medium.com/@pravallikayakkala123/understanding-aes-encryption-and-aes-gcm-mode-an-in-depth-exploration-using-java-e03be85a3faa) ensures confidentiality and authenticity:
- A randomly-generated nonce ensures identical inputs produce different outputs.
- An authentication tag ensures the encrypted data was not tampered with.

```cs
using EncryptionMaid;

string Input = "my data to encrypt";
string Password = "my super secret password";

byte[] EncryptedBytes = AesGcmMaid.Encrypt(Input, Password);

string DecryptedInput = AesGcmMaid.Decrypt(EncryptedBytes, Password);
```

### AesCbcMaid

[AES-CBC](https://www.studysmarter.co.uk/explanations/computer-science/cybersecurity-in-computer-science/cbc-mode) ensures confidentiality but not authenticity:
- A randomly-generated initialization vector (IV) ensures identical inputs produce different outputs.
- It does not ensure the encryption data was not tampered with. A separate [hash message authentication code (HMAC)](https://medium.com/@short_sparrow/how-hmac-works-step-by-step-explanation-with-examples-f4aff5efb40e) would be required.

```cs
using EncryptionMaid;

string Input = "my data to encrypt";
string Password = "my super secret password";

byte[] EncryptedBytes = AesCbcMaid.Encrypt(Input, Password);

string DecryptedInput = AesCbcMaid.Decrypt(EncryptedBytes, Password);
```

### AesCbcHmacMaid

[AES-CBC](https://www.studysmarter.co.uk/explanations/computer-science/cybersecurity-in-computer-science/cbc-mode) with [HMAC](https://security.stackexchange.com/a/63134) ensures confidentiality and authenticity:
- A randomly-generated initialization vector (IV) ensures identical inputs produce different outputs.
- A hash message authentication code (HMAC) ensures the encrypted data was not tampered with.

```cs
using EncryptionMaid;

string Input = "my data to encrypt";
string Password = "my super secret password";

byte[] EncryptedBytes = AesCbcHmacMaid.Encrypt(Input, Password);

string DecryptedInput = AesCbcHmacMaid.Decrypt(EncryptedBytes, Password);
```

## Disclaimer

This implementation has not been audited, so it should not be used for high-stakes encryption.