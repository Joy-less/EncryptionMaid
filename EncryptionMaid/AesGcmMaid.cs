using System.Text;
using System.Security.Cryptography;

namespace EncryptionMaid;

/// <summary>
/// A simple symmetric encryption implementation using AES-GCM.
/// <list type="bullet">
///   <item>Encrypting the same input twice results in different outputs using a randomly-generated nonce.</item>
///   <item>Decryption verifies whether the encrypted data was tampered with using a tag.</item>
///   <item>Supported platforms: <see href="https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#authenticated-encryption">Documentation</see></item>
/// </list>
/// </summary>
public static class AesGcmMaid {
    /// <summary>
    /// The size in bytes of the nonce (salt) used to ensure identical inputs result in different outputs.
    /// The recommended size is 96 bits (12 bytes).
    /// </summary>
    private const int NonceSize = 12;
    /// <summary>
    /// The size in bytes of the tag (authentication code) used to verify the encrypted data wasn't tampered with.
    /// The recommended size is 16 bytes (128 bits).
    /// </summary>
    private const int TagSize = 16;
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
    /// Returns whether <see cref="AesGcm"/> is supported on the current platform.
    /// </summary>
    public static bool IsSupported => AesGcm.IsSupported;

    /// <summary>
    /// Converts the plain bytes to encrypted bytes using the given key.
    /// </summary>
    /// <param name="PlainBytes">
    /// The plain bytes to encrypt and authenticate.
    /// </param>
    /// <param name="Key">
    /// The encryption key. Must be a supported length (16, 24, or 32 bytes).
    /// </param>
    /// <param name="Metadata">
    /// Optional metadata that should be authenticated but not encrypted or included in the result.
    /// </param>
    /// <returns>
    /// The encrypted bytes in the format: <c>nonce(12) + ciphertext + tag(16)</c>.
    /// </returns>
    /// <exception cref="PlatformNotSupportedException"/>
    /// <exception cref="CryptographicException"/>
    public static byte[] Encrypt(scoped ReadOnlySpan<byte> PlainBytes, scoped ReadOnlySpan<byte> Key, scoped ReadOnlySpan<byte> Metadata = default) {
        Span<byte> Nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(Nonce);

        Span<byte> CipherBytes = PlainBytes.Length <= StackAllocMaxSize
            ? stackalloc byte[PlainBytes.Length]
            : new byte[PlainBytes.Length];

        Span<byte> Tag = stackalloc byte[TagSize];

        using AesGcm AesGcm = new(Key, TagSize);
        AesGcm.Encrypt(Nonce, PlainBytes, CipherBytes, Tag, Metadata);

        byte[] EncryptedBytes = [.. Nonce, .. CipherBytes, .. Tag];
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
    /// The plain text to encrypt and authenticate.
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
    /// The encrypted bytes in the format: <c>salt(16) + nonce(12) + ciphertext + tag(16)</c>.
    /// </returns>
    /// <exception cref="PlatformNotSupportedException"/>
    /// <exception cref="CryptographicException"/>
    public static byte[] EncryptWithPassword(string PlainText, string Password, int Iterations) {
        byte[] PlainBytes = Encoding.UTF8.GetBytes(PlainText);
        byte[] PasswordBytes = Encoding.UTF8.GetBytes(Password);

        Span<byte> Salt = stackalloc byte[16];
        RandomNumberGenerator.Fill(Salt);

        byte[] Key = Rfc2898DeriveBytes.Pbkdf2(PasswordBytes, Salt, Iterations, HashAlgorithmName.SHA256, outputLength: DerivedKeySize);

        byte[] EncryptedBytesNoSalt = Encrypt(PlainBytes, Key);

        byte[] EncryptedBytes = [.. Salt, .. EncryptedBytesNoSalt];
        return EncryptedBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain bytes using the given key.<br/>
    /// Accepts encrypted bytes in the format: <c>nonce(12) + ciphertext + tag(16)</c>.
    /// </summary>
    /// <param name="EncryptedBytes">
    /// The encrypted bytes to decrypt and authenticate.
    /// </param>
    /// <param name="Key">
    /// The encryption key. Must be a supported length (16, 24, 32).
    /// </param>
    /// <param name="Metadata">
    /// Optional metadata that should be authenticated but not encrypted or included in the result.
    /// </param>
    /// <returns>
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="PlatformNotSupportedException"/>
    /// <exception cref="CryptographicException"/>
    /// <exception cref="AuthenticationTagMismatchException"/>
    public static byte[] Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, scoped ReadOnlySpan<byte> Key, scoped ReadOnlySpan<byte> Metadata = default) {
        ReadOnlySpan<byte> Nonce = EncryptedBytes[..NonceSize];
        ReadOnlySpan<byte> Tag = EncryptedBytes[^TagSize..];
        ReadOnlySpan<byte> CipherBytes = EncryptedBytes[NonceSize..^TagSize];

        byte[] PlainBytes = new byte[CipherBytes.Length];

        using AesGcm AesGcm = new(Key, TagSize);
        AesGcm.Decrypt(Nonce, CipherBytes, Tag, PlainBytes, Metadata);

        return PlainBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain text using the given password.<br/>
    /// Accepts encrypted bytes in the format: <c>salt(16) + nonce(12) + ciphertext + tag(16)</c>.
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
    /// <exception cref="PlatformNotSupportedException"/>
    /// <exception cref="CryptographicException"/>
    /// <exception cref="AuthenticationTagMismatchException"/>
    public static string DecryptWithPassword(scoped ReadOnlySpan<byte> EncryptedBytes, string Password, int Iterations) {
        byte[] PasswordBytes = Encoding.UTF8.GetBytes(Password);

        ReadOnlySpan<byte> Salt = EncryptedBytes[..DerivedSaltSize];

        byte[] Key = Rfc2898DeriveBytes.Pbkdf2(PasswordBytes, Salt, Iterations, HashAlgorithmName.SHA256, outputLength: DerivedKeySize);

        byte[] PlainBytes = Decrypt(EncryptedBytes[DerivedSaltSize..], Key);

        string PlainText = Encoding.UTF8.GetString(PlainBytes);
        return PlainText;
    }
}