using System.Text;
using System.Security.Cryptography;

namespace EncryptionMaid;

/// <summary>
/// A simple symmetric encryption implementation using AES-CBC.
/// <list type="bullet">
///   <item>Encrypting the same input twice results in different outputs using a randomly-generated IV.</item>
///   <item>Decryption does not verify whether the encrypted data was tampered with.</item>
/// </list>
/// Generally prefer <see cref="AesGcmMaid"/> if supported.
/// </summary>
public static class AesCbcMaid {
    /// <summary>
    /// The size in bytes of the initialization vector (salt) used to ensure identical inputs result in different outputs.
    /// The recommended size is 128 bits (16 bytes).
    /// </summary>
    private const int IVSize = 16;
    /// <summary>
    /// The size in bytes of the key when generating a key from a password.
    /// </summary>
    private const int DerivedKeySize = 32;
    /// <summary>
    /// The size in bytes of the salt used when generating a key from a password.
    /// </summary>
    private const int DerivedSaltSize = 16;
    /// <summary>
    /// The maximum number of bytes to dynamically allocate on the stack.
    /// </summary>
    private const int StackAllocMaxSize = 256;

    /// <summary>
    /// Converts the plain bytes to encrypted bytes using the given key.
    /// </summary>
    /// <param name="PlainBytes">
    /// The plain bytes to encrypt.
    /// </param>
    /// <param name="Key">
    /// The encryption key. Must be a supported length (16, 24, or 32 bytes).
    /// </param>
    /// <returns>
    /// The encrypted bytes in the format: <c>iv(16) + ciphertext</c>.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Encrypt(scoped ReadOnlySpan<byte> PlainBytes, scoped ReadOnlySpan<byte> Key) {
        Span<byte> IV = stackalloc byte[IVSize];
        RandomNumberGenerator.Fill(IV);

        using Aes Aes = Aes.Create();
        Aes.Key = Key.ToArray();

        int CipherBytesLength = Aes.GetCiphertextLengthCbc(PlainBytes.Length);
        Span<byte> CipherBytes = CipherBytesLength <= StackAllocMaxSize
            ? stackalloc byte[CipherBytesLength]
            : new byte[CipherBytesLength];
        Aes.EncryptCbc(PlainBytes, IV, CipherBytes);

        byte[] EncryptedBytes = [.. IV, .. CipherBytes];
        return EncryptedBytes;
    }
    /// <summary>
    /// Converts the plain bytes to encrypted bytes using the given password.
    /// </summary>
    /// <remarks>
    /// The password is converted to bytes using UTF-8.<br/>
    /// The key is derived from the password using PBKDF2 with SHA-256.
    /// </remarks>
    /// <param name="PlainBytes">
    /// The plain bytes to encrypt.
    /// </param>
    /// <param name="Password">
    /// The password used to create the encryption key.
    /// </param>
    /// <param name="Iterations">
    /// The number of iterations for deriving the key using PBKDF2 with SHA-256.
    /// <list type="bullet">
    ///   <item>Microsoft recommends at least <c>100_000</c> (<see href="https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5387">link</see>).</item>
    ///   <item>OWASP recommends <c>600_000</c> (<see href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">link</see>).</item>
    /// </list>
    /// </param>
    /// <returns>
    /// The encrypted bytes in the format: <c>salt(16) + iv(16) + ciphertext</c>.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] EncryptWithPassword(scoped ReadOnlySpan<byte> PlainBytes, scoped ReadOnlySpan<char> Password, int Iterations) {
        int PasswordBytesCount = Encoding.UTF8.GetByteCount(Password);
        Span<byte> PasswordBytes = PasswordBytesCount <= StackAllocMaxSize
            ? stackalloc byte[PasswordBytesCount]
            : new byte[PasswordBytesCount];
        Encoding.UTF8.GetBytes(Password, PasswordBytes);

        Span<byte> Salt = stackalloc byte[16];
        RandomNumberGenerator.Fill(Salt);

        byte[] Key = Rfc2898DeriveBytes.Pbkdf2(PasswordBytes, Salt, Iterations, HashAlgorithmName.SHA256, outputLength: DerivedKeySize);

        byte[] EncryptedBytesNoSalt = Encrypt(PlainBytes, Key);

        byte[] EncryptedBytes = [.. Salt, .. EncryptedBytesNoSalt];
        return EncryptedBytes;
    }
    /// <summary>
    /// Converts the plain text to encrypted bytes using the given password.
    /// </summary>
    /// <remarks>
    /// The plain text and password are converted to bytes using UTF-8.<br/>
    /// The key is derived from the password using PBKDF2 with SHA-256.
    /// </remarks>
    /// <param name="PlainText">
    /// The plain text to encrypt.
    /// </param>
    /// <param name="Password">
    /// The password used to create the encryption key.
    /// </param>
    /// <param name="Iterations">
    /// The number of iterations for deriving the key using PBKDF2 with SHA-256.
    /// <list type="bullet">
    ///   <item>Microsoft recommends at least <c>100_000</c> (<see href="https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5387">link</see>).</item>
    ///   <item>OWASP recommends <c>600_000</c> (<see href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">link</see>).</item>
    /// </list>
    /// </param>
    /// <returns>
    /// The encrypted bytes in the format: <c>salt(16) + iv(16) + ciphertext</c>.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] EncryptStringWithPassword(string PlainText, scoped ReadOnlySpan<char> Password, int Iterations) {
        byte[] PlainBytes = Encoding.UTF8.GetBytes(PlainText);

        byte[] EncryptedBytes = EncryptWithPassword(PlainBytes, Password, Iterations);
        return EncryptedBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain bytes using the given key.<br/>
    /// Accepts encrypted bytes in the format: <c>iv(16) + ciphertext</c>.
    /// </summary>
    /// <param name="EncryptedBytes">
    /// The encrypted bytes to decrypt.
    /// </param>
    /// <param name="Key">
    /// The encryption key. Must be a supported length (16, 24, 32).
    /// </param>
    /// <returns>
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, scoped ReadOnlySpan<byte> Key) {
        ReadOnlySpan<byte> IV = EncryptedBytes[..IVSize];
        ReadOnlySpan<byte> CipherBytes = EncryptedBytes[IVSize..];

        using Aes Aes = Aes.Create();
        Aes.Key = Key.ToArray();

        byte[] PlainBytes = Aes.DecryptCbc(CipherBytes, IV);
        return PlainBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain bytes using the given password.<br/>
    /// Accepts encrypted bytes in the format: <c>salt(16) + iv(16) + ciphertext</c>.
    /// </summary>
    /// <remarks>
    /// The password is converted to bytes using UTF-8.<br/>
    /// The key is derived from the password using PBKDF2 with SHA-256.
    /// </remarks>
    /// <param name="EncryptedBytes">
    /// The encrypted bytes to decrypt and authenticate.
    /// </param>
    /// <param name="Password">
    /// The password used to create the encryption key.
    /// </param>
    /// <param name="Iterations">
    /// The number of iterations for deriving the key using PBKDF2 with SHA-256.
    /// <list type="bullet">
    ///   <item>Microsoft recommends at least <c>100_000</c> (<see href="https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5387">link</see>).</item>
    ///   <item>OWASP recommends <c>600_000</c> (<see href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">link</see>).</item>
    /// </list>
    /// </param>
    /// <returns>
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] DecryptWithPassword(scoped ReadOnlySpan<byte> EncryptedBytes, scoped ReadOnlySpan<char> Password, int Iterations) {
        int PasswordBytesCount = Encoding.UTF8.GetByteCount(Password);
        Span<byte> PasswordBytes = PasswordBytesCount <= StackAllocMaxSize
            ? stackalloc byte[PasswordBytesCount]
            : new byte[PasswordBytesCount];
        Encoding.UTF8.GetBytes(Password, PasswordBytes);

        ReadOnlySpan<byte> Salt = EncryptedBytes[..DerivedSaltSize];

        byte[] Key = Rfc2898DeriveBytes.Pbkdf2(PasswordBytes, Salt, Iterations, HashAlgorithmName.SHA256, outputLength: DerivedKeySize);

        byte[] PlainBytes = Decrypt(EncryptedBytes[DerivedSaltSize..], Key);
        return PlainBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain text using the given password.<br/>
    /// Accepts encrypted bytes in the format: <c>salt(16) + iv(16) + ciphertext</c>.
    /// </summary>
    /// <remarks>
    /// The plain bytes and password are converted to bytes using UTF-8.<br/>
    /// The key is derived from the password using PBKDF2 with SHA-256.
    /// </remarks>
    /// <param name="EncryptedBytes">
    /// The encrypted bytes to decrypt and authenticate.
    /// </param>
    /// <param name="Password">
    /// The password used to create the encryption key.
    /// </param>
    /// <param name="Iterations">
    /// The number of iterations for deriving the key using PBKDF2 with SHA-256.
    /// <list type="bullet">
    ///   <item>Microsoft recommends at least <c>100_000</c> (<see href="https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5387">link</see>).</item>
    ///   <item>OWASP recommends <c>600_000</c> (<see href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2">link</see>).</item>
    /// </list>
    /// </param>
    /// <returns>
    /// The decrypted text.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static string DecryptStringWithPassword(scoped ReadOnlySpan<byte> EncryptedBytes, scoped ReadOnlySpan<char> Password, int Iterations) {
        byte[] PlainBytes = DecryptWithPassword(EncryptedBytes, Password, Iterations);

        string PlainText = Encoding.UTF8.GetString(PlainBytes);
        return PlainText;
    }
}