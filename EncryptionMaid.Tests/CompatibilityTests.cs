using System.Text;

namespace EncryptionMaid.Tests;

public class CompatibilityTests {
    [Theory]
    [InlineData("Hello, world!", "password123")]
    [InlineData("Play Konekomi Castle", "super password 321")]
    public void GcmFromEncryptionMaidToAesBridgeTest(string Input, string Password) {
        byte[] EncryptedBytes = AesGcmMaid.EncryptStringWithPassword(Input, Password, 100_000);

        string DecryptedBytes = Encoding.UTF8.GetString(AesBridge.Gcm.DecryptBin(EncryptedBytes, Password));

        DecryptedBytes.ShouldBe(Input);
    }
    [Theory]
    [InlineData("Hello, world!", "password123")]
    [InlineData("Play Konekomi Castle", "super password 321")]
    public void GcmFromAesBridgeToEncryptionMaidTest(string Input, string Password) {
        byte[] EncryptedBytes = AesBridge.Gcm.EncryptBin(Input, Password);

        string DecryptedBytes = AesGcmMaid.DecryptStringWithPassword(EncryptedBytes, Password, 100_000);

        DecryptedBytes.ShouldBe(Input);
    }
    [Theory]
    [InlineData(new byte[] { 50, 100, 150 }, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })]
    public void GcmFromEncryptionMaidToLibSodiumCoreTest(byte[] Input, byte[] Key) {
        byte[] EncryptedBytes = AesGcmMaid.Encrypt(Input, Key);
        byte[] Cipher = EncryptedBytes[12..];
        byte[] Nonce = EncryptedBytes[..12];

        byte[] DecryptedBytes = Sodium.SecretAeadAes.Decrypt(Cipher, Nonce, Key);

        DecryptedBytes.ShouldBe(Input);
    }
    [Theory]
    [InlineData(new byte[] { 50, 100, 150 }, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })]
    public void GcmFromLibSodiumCoreToEncryptionMaidTest(byte[] Input, byte[] Key) {
        byte[] Nonce = Sodium.SecretAeadAes.GenerateNonce();
        byte[] Cipher = Sodium.SecretAeadAes.Encrypt(Input, Nonce, Key);
        byte[] EncryptedBytes = [.. Nonce, .. Cipher];

        byte[] DecryptedBytes = AesGcmMaid.Decrypt(EncryptedBytes, Key);

        DecryptedBytes.ShouldBe(Input);
    }
}