using System.Text;
using System.Security.Cryptography;

namespace EncryptionMaid;

/// <summary>
/// A simple symmetric encryption implementation using AES-CBC with HMAC.
/// <list type="bullet">
///   <item>Encrypting the same input twice results in different outputs using a randomly-generated IV.</item>
///   <item>Decryption verifies whether the encrypted data was tampered with using a HMAC.</item>
/// </list>
/// Generally prefer <see cref="AesGcmMaid"/> if supported.
/// </summary>
public static class AesCbcHmacMaid {
    /// <summary>
    /// The size in bytes of the initialization vector (salt) used to ensure identical inputs result in different outputs.
    /// The recommended size is 128 bits (16 bytes).
    /// </summary>
    private const int IVSize = 16;
    /// <summary>
    /// The maximum number of bytes to dynamically allocate on the stack.
    /// </summary>
    private const int StackAllocMaxSize = 32;
    /// <summary>
    /// The size in bytes of the derived encryption key.
    /// Must be 256 bits (32 bytes) to use HMACSHA256.
    /// </summary>
    private const int AesKeySize = 32;
    /// <summary>
    /// The size in bytes of the salt for the derived encryption key.
    /// </summary>
    private const int AesKeySaltSize = 16;
    /// <summary>
    /// The size in bytes of the hash-based message authentication code used to verify the encrypted data wasn't tampered with.
    /// Must be 256 bits (32 bytes) to use HMACSHA256.
    /// </summary>
    private const int HmacSize = 32;
    /// <summary>
    /// The size in bytes of the encryption key for the hash-based message authentication code.
    /// Must be 256 bits (32 bytes) to use HMACSHA256.
    /// </summary>
    private const int HmacKeySize = 32;
    /// <summary>
    /// The size in bytes of the salt for the encryption key for the hash-based message authentication code.
    /// </summary>
    private const int HmacKeySaltSize = 16;

    /// <summary>
    /// Converts the plain bytes to encrypted bytes using the given key.
    /// </summary>
    /// <param name="PlainBytes">
    /// The plain bytes to encrypt.
    /// </param>
    /// <param name="Key">
    /// The encryption key.
    /// </param>
    /// <returns>
    /// The encrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Encrypt(scoped ReadOnlySpan<byte> PlainBytes, scoped ReadOnlySpan<byte> Key) {
        Span<byte> IV = stackalloc byte[IVSize];
        RandomNumberGenerator.Fill(IV);

        Span<byte> AesKeySalt = stackalloc byte[HmacKeySaltSize];
        RandomNumberGenerator.Fill(AesKeySalt);

        Span<byte> AesKey = stackalloc byte[HmacKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Key, AesKey, AesKeySalt, default);

        using Aes Aes = Aes.Create();
        Aes.Key = AesKey.ToArray();

        int CipherBytesLength = Aes.GetCiphertextLengthCbc(PlainBytes.Length);
        Span<byte> CipherBytes = CipherBytesLength <= StackAllocMaxSize
            ? stackalloc byte[CipherBytesLength]
            : new byte[CipherBytesLength];
        int CipherBytesWritten = Aes.EncryptCbc(PlainBytes, IV, CipherBytes);
        CipherBytes = CipherBytes[..CipherBytesWritten];

        Span<byte> HmacKeySalt = stackalloc byte[HmacKeySaltSize];
        RandomNumberGenerator.Fill(HmacKeySalt);

        Span<byte> HmacKey = stackalloc byte[HmacKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Key, HmacKey, HmacKeySalt, default);

        byte[] HmacInput = [.. AesKeySalt, .. IV, .. CipherBytes];

        Span<byte> HmacBytes = stackalloc byte[HmacSize];
        int HmacBytesWritten = HMACSHA256.HashData(HmacKey, HmacInput, HmacBytes);
        HmacBytes = HmacBytes[..HmacBytesWritten];

        byte[] EncryptedBytes = [.. AesKeySalt, .. IV, .. CipherBytes, .. HmacKeySalt, .. HmacBytes];
        return EncryptedBytes;
    }
    /// <summary>
    /// Converts the plain text to encrypted bytes using the given password.
    /// </summary>
    /// <remarks>
    /// Should only be used for trivial scenarios such as encrypted save files.
    /// </remarks>
    /// <param name="PlainText">
    /// The plain text to encrypt.
    /// </param>
    /// <param name="Password">
    /// The password used to create the encryption key.
    /// </param>
    /// <returns>
    /// The encrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Encrypt(string PlainText, string Password) {
        byte[] PlainBytes = Encoding.UTF8.GetBytes(PlainText);
        byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes(Password));
        byte[] EncryptedBytes = Encrypt(PlainBytes, Key);
        return EncryptedBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain bytes using the given key.
    /// </summary>
    /// <param name="EncryptedBytes">
    /// The encrypted bytes to decrypt.
    /// </param>
    /// <param name="Key">
    /// The encryption key.
    /// </param>
    /// <returns>
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, scoped ReadOnlySpan<byte> Key) {
        ReadOnlySpan<byte> AesKeySalt = EncryptedBytes[..AesKeySaltSize];
        ReadOnlySpan<byte> IV = EncryptedBytes[AesKeySaltSize..(AesKeySaltSize + IVSize)];
        ReadOnlySpan<byte> CipherBytes = EncryptedBytes[(AesKeySaltSize + IVSize)..^(HmacKeySaltSize + HmacSize)];
        ReadOnlySpan<byte> HmacKeySalt = EncryptedBytes[^(HmacKeySaltSize + HmacSize)..^HmacSize];
        ReadOnlySpan<byte> HmacBytes = EncryptedBytes[^HmacSize..];

        Span<byte> HmacKey = stackalloc byte[HmacKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Key, HmacKey, HmacKeySalt, default);

        byte[] HmacInput = [.. AesKeySalt, .. IV, .. CipherBytes];

        Span<byte> TestHmacBytes = stackalloc byte[HmacSize];
        int TestHmacBytesWritten = HMACSHA256.HashData(HmacKey, HmacInput, TestHmacBytes);
        TestHmacBytes = TestHmacBytes[..TestHmacBytesWritten];

        if (!CryptographicOperations.FixedTimeEquals(HmacBytes, TestHmacBytes)) {
            throw new AuthenticationTagMismatchException();
        }

        Span<byte> AesKey = stackalloc byte[HmacKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Key, AesKey, AesKeySalt, default);

        using Aes Aes = Aes.Create();
        Aes.Key = AesKey.ToArray();

        byte[] PlainBytes = Aes.DecryptCbc(CipherBytes, IV);

        return PlainBytes;
    }
    /// <summary>
    /// Converts the encrypted bytes to plain text using the given password.
    /// </summary>
    /// <remarks>
    /// Should only be used for trivial scenarios such as encrypted save files.
    /// </remarks>
    /// <param name="EncryptedBytes">
    /// The encrypted bytes to decrypt and authenticate.
    /// </param>
    /// <param name="Password">
    /// The password used to create the encryption key.
    /// </param>
    /// <returns>
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static string Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, string Password) {
        byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes(Password));
        byte[] PlainBytes = Decrypt(EncryptedBytes, Key);
        string PlainText = Encoding.UTF8.GetString(PlainBytes);
        return PlainText;
    }
}