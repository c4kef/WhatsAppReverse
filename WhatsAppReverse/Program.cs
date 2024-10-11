using System.Net;
using System.Security.Cryptography;
using System.Text;

//Все поля содержат имена эквивалентные друг другу в оригинале.
//С заполнением проблем не должно быть будут проблемы
var gpia =
    "Rhujt5MA4nGkt0xtxzhCTWQPsFFNtsj0%2BP8nBKXni0mCPJQaJiQAotxQeEMfMtrXAbgv4cVO2aurlG0szASRrTlPBdjknnSfFTQ2uC1fdDeL1gYlfLKIhEV6iQ8w6oOKuMgPoKGFizUqPJ7GUV51Klunl9ryA1gTJOwTTm5Ip1GPqSTJpgWlMD0acgVjFRHpi3qfYnVtipROQQijGtYfN0kFS5EmIpku7BQv0fy1q%2BFj2z3x5USI40jYvVhZiEfXHTcPoP8pjTjIPf1XTFjCJk6nAnOCilmG960g2PZaBMzeaHX59oNiZe2qkFQOA0wyYfwszC%2B77Ufd2zFdOSqjkeLAttB2qiAay3zn9Tf6vWjGOCW7eFhfPhgKnYvnzW9QkO8kwcYDITJIDLfl8PFhKg%3D%3D";

var gi = "n08si9IU9K9HrxHKG2%2Bly3wG%2BYsmaVnnH9vy46k9N2O7%2FbaaCG1YruhiD%2FiGh1wOr%2BvupF2mdL9NwWK2jASciT4%2F5E7LRBNo4GhXukZ2iI6fK9YPjldrxyoeSYSqrkec7OopF%2B1JqDmhSLmaaQHPCJGQ0khpZ5i0qdQR798pFw4cqS6WbWIgUbaUek3kzKzCkyqytPQQ7wra0nVTsmOqgYw3Joh0egdvpBErCQvlK%2Fj1KxCjmw4nfClcMfyl2fRuTzWeDYR1vq5KKygOfWJvtcHv4%2FGs1HKR%2BeeY5d1q7w8v6k6IzIrtNkvYlbllLxs%2B9f99MRgldxcDYifG%2FezzwoVGn%2FmvDpa2EtaQFliAzoCLCt2F8gq%2FTZ3PRRdSJsCcEW1wsQmIiea8%2BQYwDZON1zIgTWf1USrSJlb9y%2BaexYfZK1PoSyVFJuK48lmf4kWe1R4utord0WxmgaPbGJPzGuhhaLU5xXqoTtdHe4DoIpKuxp2%2FS3mcpulnMuvvUajf";
var gg =
    "d6OnAFt6DoD326uICfPyn6R1R711O9RzSL59RFzse%2Bs%3D";

var authkey = "f03RwqZBVEuMSH-hYjuWKnqm-ZA9HT2s3swGy-FrWl4";

Console.WriteLine("Decrypted gpia: " + DecryptPlayIntegrityField(gpia, authkey));
Console.WriteLine("Decrypted gi: " + DecryptPlayIntegrityField(gi, authkey));
Console.WriteLine("Decrypted gg: " + DecryptPlayIntegrityField(gg, authkey));
Console.WriteLine("Decrypted test: " + DecryptPlayIntegrityField("0gwCfcxLVlcWwFqhAZei9HqgV1jk3KUVxhTgF%2Fp1uW4%3D", authkey));
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