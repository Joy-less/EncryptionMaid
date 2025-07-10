using System.Security.Cryptography;
using System.Text;

namespace EncryptionMaid;

/// <summary>
/// A simple symmetric encryption implementation using AES-CBC with HMAC.
/// <list type="bullet">
///   <item>Encrypting the same input twice results in different outputs using a randomly-generated IV.</item>
///   <item>Decryption verifies whether the encrypted data was tampered with using a HMAC (SHA-256).</item>
/// </list>
/// </summary>
public static class AesCbcHmacMaid {
    /// <summary>
    /// The size in bytes of the initialization vector (salt) used to ensure identical inputs result in different outputs.
    /// The recommended size is 128 bits (16 bytes).
    /// </summary>
    private const int IVSize = 16;
    /// <summary>
    /// The size in bytes of the hash-based message authentication code used to verify the encrypted data wasn't tampered with.
    /// The recommended size is 256 bits (32 bytes).
    /// </summary>
    private const int HmacSize = 32;
    /// <summary>
    /// The size in bytes of the encryption key for the hash-based message authentication code.
    /// </summary>
    private const int HmacKeySize = 32;
    /// <summary>
    /// The size in bytes of the salt for the encryption key for the hash-based message authentication code.
    /// </summary>
    private const int HmacKeySaltSize = 16;
    /// <summary>
    /// The maximum number of bytes to dynamically allocate on the stack.
    /// </summary>
    private const int StackallocMaxSize = 128;

    public static byte[] Encrypt(scoped ReadOnlySpan<byte> PlainBytes, byte[] Key, scoped ReadOnlySpan<byte> Metadata = default) {
        Span<byte> IV = stackalloc byte[IVSize];
        RandomNumberGenerator.Fill(IV);

        using Aes Aes = Aes.Create();
        Aes.Key = Key;

        int CipherBytesLength = Aes.GetCiphertextLengthCbc(PlainBytes.Length);
        Span<byte> CipherBytes = CipherBytesLength <= StackallocMaxSize
            ? stackalloc byte[CipherBytesLength]
            : new byte[CipherBytesLength];
        int CipherBytesWritten = Aes.EncryptCbc(PlainBytes, IV, CipherBytes);
        CipherBytes = CipherBytes[..CipherBytesWritten];

        Span<byte> HmacSalt = stackalloc byte[HmacKeySaltSize];
        RandomNumberGenerator.Fill(HmacSalt);

        Span<byte> HmacKey = stackalloc byte[HmacKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Key, HmacKey, HmacSalt, default);

        byte[] HmacInput = [.. IV, .. CipherBytes, .. Metadata];
        Span<byte> HmacBytes = stackalloc byte[HmacSize];
        int HmacBytesWritten = HMACSHA256.HashData(HmacKey, HmacInput, HmacBytes);
        HmacBytes = HmacBytes[..HmacBytesWritten];

        return [.. IV, .. CipherBytes, .. HmacSalt, .. HmacBytes];
    }
    public static byte[] Encrypt(string PlainText, string Password) {
        byte[] PlainBytes = Encoding.UTF8.GetBytes(PlainText);
        byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes(Password));
        byte[] EncryptedBytes = Encrypt(PlainBytes, Key);
        return EncryptedBytes;
    }
    public static byte[] Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, byte[] Key, scoped ReadOnlySpan<byte> Metadata = default) {
        ReadOnlySpan<byte> IV = EncryptedBytes[..IVSize];
        ReadOnlySpan<byte> Hmac = EncryptedBytes[^HmacSize..];
        ReadOnlySpan<byte> HmacSalt = EncryptedBytes[^(HmacKeySaltSize + HmacSize)..^HmacKeySaltSize];
        ReadOnlySpan<byte> CipherBytes = EncryptedBytes[IVSize..^(HmacKeySaltSize + HmacSize)];

        using Aes Aes = Aes.Create();
        Aes.Key = Key;

        byte[] PlainBytes = Aes.DecryptCbc(CipherBytes, IV);

        Span<byte> HmacKey = stackalloc byte[HmacKeySize];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Key, HmacKey, HmacSalt, default);

        byte[] HmacInput = [.. IV, .. CipherBytes, .. Metadata];
        Span<byte> HmacBytes = stackalloc byte[HmacSize];
        int HmacBytesWritten = HMACSHA256.HashData(HmacKey, HmacInput, HmacBytes);
        HmacBytes = HmacBytes[..HmacBytesWritten];

        if (!CryptographicOperations.FixedTimeEquals(Hmac, HmacBytes)) {
            throw new AuthenticationTagMismatchException("HMAC not equal");
        }

        return PlainBytes;
    }
    public static string Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, string Password) {
        byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes(Password));
        byte[] PlainBytes = Decrypt(EncryptedBytes, Key);
        string PlainText = Encoding.UTF8.GetString(PlainBytes);
        return PlainText;
    }
}