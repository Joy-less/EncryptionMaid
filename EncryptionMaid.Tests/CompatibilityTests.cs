using System.Text;

namespace EncryptionMaid.Tests;

public class CompatibilityTests {
    [Theory]
    [InlineData("Hello, world!", "password123")]
    [InlineData("Play Konekomi Castle", "super password 321")]
    public void GcmFromEncryptionMaidToAesBridgeTest(string Input, string Password) {
        byte[] EncryptedBytesEncryptionMaid = AesGcmMaid.EncryptWithPassword(Input, Password, 100_000);

        string DecryptedBytes = Encoding.UTF8.GetString(AesBridge.Gcm.DecryptBin(EncryptedBytesEncryptionMaid, Password));

        DecryptedBytes.ShouldBe(Input);
    }
    [Theory]
    [InlineData("Hello, world!", "password123")]
    [InlineData("Play Konekomi Castle", "super password 321")]
    public void GcmFromAesBridgeToEncryptionMaidTest(string Input, string Password) {
        byte[] EncryptedBytesEncryptionMaid = AesBridge.Gcm.EncryptBin(Input, Password);

        string DecryptedBytes = AesGcmMaid.DecryptWithPassword(EncryptedBytesEncryptionMaid, Password, 100_000);

        DecryptedBytes.ShouldBe(Input);
    }
}