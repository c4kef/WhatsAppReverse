using System.Net;
using System.Security.Cryptography;
using System.Text;

const string gpia = "avjP%2FQUGnYecO%2FL8QgdFHELcqF37qLtG4qX%2FfM8HO%2F7uFih%2BVZSYCxLhMVz5hma7Y1naO0cu23jcANMTsBfHs4tvbhbtXsTPI1TwdYbPlW8bZl2B4JY3qsn9%2BR1XQXClx%2BmDKPwMLx%2BsSK38owdq0kErtm%2F0MvDUKRx6cB8vTm4XNyGXMlBw8%2FYhHcb1%2FdEU42i8L6qaNFIs%2FuGWlippQOlWoxeIZn3mTd3oh83KI9y8%2BlAmmDgYP4jYGyo0tKGstMYoLaB%2FMdL1ArWJDX4XHjTV8%2FVenrpoccSyk7z%2F3u%2Bi0niR%2FqUzjqH9JDsiXwhWYMl3ZjxphC%2FMc0%2BQ1jjDDkP2XnRECQeAKaSWalpEyXHilJsRo33JNsUdnSK7j%2BavYVt8pgqymJF2V9Taa8Y5Fg%3D%3D";
const string gi = "3AfPZcOdBUTTcGjf%2B1Bp6A9Se5wmW3XfyC88cS80rOgysRFbQmSxL5iBpcEKai4q8A1VPkmp9MC0BwHFH1YtFa2nRiA1wRxh1Ng%2F6l77GPCC%2FvkN43QLdFt%2F%2B19ZfLhYd90PntZZdnw8mFBPVbbIplpcWLHYLxJqogp%2B0fPF9YwNXvevrBbqmERN5HSCkF2EEq3ajF1ItxbhnqPmRSeuofpM%2FQfWhkEqeXf5gjtJr55bWLUL%2F6RQ1iNjYCetaNJEsFGGkAp1Q8gI1xRerVSGtwDnvfWu62ordrr9jzf3acjkuWml4YE6Iia6G4rwBSHX%2F3rIJhebfxPbjGKx0cx2YyVNsecPJB444HrvJvzQWENMPJaNDiw4Dy0IdOsPGMQ4WkQAfN%2FMkLMBVoVHisIrUohr68z%2Bk36GI%2Fkama7JMu0KyRvVhzhWroC0pg8iEE95";
const string gg = "j8h7Olu%2Bg2Ii02f6GKFzlclg%2BOX0X2O1VM%2FZ5JDcwyU%3D";
const string accessSessionId = "4ka-cKVOTPuetZMebd5OAQ";

const string authkey = "Z86JF01hXLweT90THURDt7ChGDbKTvzFI6CXNsKHcBQ";

Console.WriteLine("Decrypted gpia: " + DecryptPlayIntegrityField(gpia, authkey));
Console.WriteLine("Decrypted gi: " + DecryptPlayIntegrityField(gi, authkey));
Console.WriteLine("Decrypted gg: " + DecryptPlayIntegrityField(gg, authkey));
Console.WriteLine("Decrypted access_session_id: " + new Guid(Convert.FromBase64String(ConvertToBase64FromBase64Url(accessSessionId))));

return;

string DecryptPlayIntegrityField(string encryptedData, string privateKey)
{
    privateKey = ConvertToBase64FromBase64Url(privateKey);
    var key = SHA256.HashData(Encoding.UTF8.GetBytes(privateKey));
    var combined = Convert.FromBase64String(WebUtility.UrlDecode(encryptedData));

    var iv = new byte[16];
    Buffer.BlockCopy(combined, 0, iv, 0, iv.Length);

    var encrypted = new byte[combined.Length - iv.Length];
    Buffer.BlockCopy(combined, iv.Length, encrypted, 0, encrypted.Length);

    using var aesAlg = Aes.Create();
    aesAlg.Key = key;
    aesAlg.IV = iv;
    aesAlg.Mode = CipherMode.CBC;
    aesAlg.Padding = PaddingMode.PKCS7;

    var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
    using var msDecrypt = new MemoryStream(encrypted);
    using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
    using var srDecrypt = new StreamReader(csDecrypt);
    return srDecrypt.ReadToEnd();
}

string ConvertToBase64FromBase64Url(string base64Url)
{
    var base64 = base64Url.Replace('-', '+').Replace('_', '/');
    switch (base64.Length % 4)
    {
        case 2:
            base64 += "==";
            break;
        case 3:
            base64 += "=";
            break;
    }

    return base64;
}