namespace EncryptionMaid.Tests;

public class AesGcmMaidTests {
    [Theory]
    [InlineData("Hello, world!", "password123")]
    [InlineData("Play Konekomi Castle", "super password 321")]
    public void EncryptDecryptPasswordTest(string Input, string Password) {
        byte[] EncryptedBytes = AesGcmMaid.Encrypt(Input, Password);
        string DecryptedInput = AesGcmMaid.Decrypt(EncryptedBytes, Password);
        DecryptedInput.ShouldBe(Input);
    }
    [Theory]
    [InlineData(new byte[] { 50, 100, 150 }, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })]
    public void EncryptDecryptKeyTest(byte[] Input, byte[] Key) {
        byte[] EncryptedBytes = AesGcmMaid.Encrypt(Input, Key);
        EncryptedBytes.ShouldNotBe(Input);
        byte[] DecryptedInput = AesGcmMaid.Decrypt(EncryptedBytes, Key);
        DecryptedInput.ShouldBe(Input);
    }
}