using System.Security.Cryptography;
using System.Text;

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
    /// The maximum number of bytes to dynamically allocate on the stack.
    /// </summary>
    private const int StackallocMaxSize = 128;

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
    /// The encrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Encrypt(scoped ReadOnlySpan<byte> PlainBytes, byte[] Key) {
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

        return [.. IV, .. CipherBytes];
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
    /// The encryption key. Must be a supported length (16, 24, 32).
    /// </param>
    /// <returns>
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="CryptographicException"/>
    public static byte[] Decrypt(scoped ReadOnlySpan<byte> EncryptedBytes, byte[] Key) {
        ReadOnlySpan<byte> IV = EncryptedBytes[..IVSize];
        ReadOnlySpan<byte> CipherBytes = EncryptedBytes[IVSize..];

        using Aes Aes = Aes.Create();
        Aes.Key = Key;

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