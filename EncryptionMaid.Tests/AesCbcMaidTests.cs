namespace EncryptionMaid.Tests;

public class AesCbcMaidTests {
    [Theory]
    [InlineData("Hello, world!", "password123")]
    [InlineData("Play Konekomi Castle", "super password 321")]
    public void EncryptDecryptPasswordTest(string Input, string Password) {
        byte[] EncryptedBytes = AesCbcMaid.EncryptStringWithPassword(Input, Password, 600_000);
        string DecryptedInput = AesCbcMaid.DecryptStringWithPassword(EncryptedBytes, Password, 600_000);
        DecryptedInput.ShouldBe(Input);
    }
    [Theory]
    [InlineData(new byte[] { 50, 100, 150 }, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })]
    public void EncryptDecryptKeyTest(byte[] Input, byte[] Key) {
        byte[] EncryptedBytes = AesCbcMaid.Encrypt(Input, Key);
        EncryptedBytes.ShouldNotBe(Input);
        byte[] DecryptedInput = AesCbcMaid.Decrypt(EncryptedBytes, Key);
        DecryptedInput.ShouldBe(Input);
    }
    [Theory]
    [InlineData("Hello, world!", "password123")]
    public void EncryptIVTest(string Input, string Password) {
        byte[] EncryptedBytes1 = AesCbcMaid.EncryptStringWithPassword(Input, Password, 600_000);
        byte[] EncryptedBytes2 = AesCbcMaid.EncryptStringWithPassword(Input, Password, 600_000);
        EncryptedBytes1.ShouldNotBe(EncryptedBytes2);
    }
}