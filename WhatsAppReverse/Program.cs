using System.Net;
using System.Security.Cryptography;
using System.Text;

//Все поля содержат имена эквивалентные друг другу в оригинале.
//С заполнением проблем не должно быть будут проблемы
var gpia =
    "ZF9gwtwNX1xZ0%2F83H%2BSC5%2Boaiclwhx3MaDZau69FnI8v9N%2F2BqwW9pJbiyjySf6KgtMYoReObaw%2FCLckM7et0i5GDi5XFMIQGKzlBdBfS2OB1PRlvYqtgGksGE2tUP3e4d%2B3s6WoMy5P44wsb68oiCd558M41%2BcPXMNobl3YtwYCy%2FIeHU%2FTxhaDzX80k9Ac2Rgsb0zE5iokPhwCEWgmRSOojHf0cWd4qfzIe5kVL%2FK%2F%2BGFcj8BfLUJb0KFCScA1F8CmI7Tnnqn%2BTCSK4n6M3WIFtXI%2B1pSsztyJSvCgjqsfph0QDBD%2FJ1vETNGFr2Lv4%2FlueuDDWRqyts8M6EG%2FPp4HyC23S4N97cvXRr%2BoMuI4CHMohypeNW7nQivdLEVgSVFW2WqtXv9nCw4m7h0hG6Hjco9XPtnHqD4HEMTw1Gyxowx6Q4lbVYzY3VNskx26MH8GCOpmAJ0NO7hWEsllb0VwuiM00ABk9n9W%2Fdjiflvmd3erMKK%2B%2F1me0YBxYqHiOIIKNViUCGTL8%2BPB7L%2Fe0%2BQkcRSPgka7iljFhfPq0cQuRKk9gGHK%2Bj47lnTLZFKs5WiEFAznFoTPhVyFcC4HVCMcc4mdC4IoWC9nfK7uwvZ3FYFTLVNvy3LTceah2TACEyUAfZcRM2nsGe6kjzTIsMR%2FlCbTLgRPcfebCcbTbGiNH3MdxxH7msRemCaldrVAIsJTl34yXxQFeFZRplC9sLOiD6SciuesmlQf%2BA1OjzMQG1x0n1XNtQ84MYgSz8MOa%2FPhd%2BfDf9N5a%2B88nvab7lFShkcGK%2FISLOAelci%2Fbl3DWbv5%2FoURTLQ8BFoo9YXv6QgiQsTKfSVDXvrzj62Z2%2FEW4o5pnTD4oRx13OsLKnP6pbQq4AVbcyQeRFXq8AMGcmif4UgeqgF1VjLGLfYz7ynQ5dncxGvu4ayoR1%2BfrFI%2FI%2FjW3pT1hCmpJ9u%2F67%2FxM0WX%2BanFkqc8b0wxqWCE6qQjAqBgvmBiPRixrG5sKTXBeCB6lj%2BxwT5kveUbAu9mwYjIm2TSsfPMHrJO%2B1d435Pj%2BJv16ysCmT20ghd2ogJ5ambSr%2FGtdJ68eEXxzb4J0r%2B97lwtXMUtjAZ1OLQm2mMgjFo1QWlG9QyfzsIKDLXSXw7Uuv6jyjVZPd0cac6HUd2YTtZga9hmHPeITc9Y8etHuN20GWGDtxnaodUO0hQe6YzBNzPbT1VL99TcrcurkB8I1LWCk00Zp2mGPRnR%2FDfdd8N9Z%2ByV2WI16%2FqrkPBQRziCjGI6P3CxTxQjz%2FTOG EF15cfav9Rlm8WG15U9r18oswpHC%2FRAmRs6qIWKhtrxkUeN9vqVH1ScJF22ufnucMW6Z2aey8LNIP85qnKrL6EbcTdLxKRgh%2Fq3Am80dhL8UUuBBNIDe4mSOTBHPqeuOwkXp%2Fi6mo%2F93hQcaFgVWaM5iUuJ%2FRhFYL2mipQzYuoU0jKh9rkZdK4DFLIMnJws4kyyw31knU3CZXGQUzZWRwBAqYxfbhb%2FckdcrvV2sOoGG%2Fr44vKNbRxGfU%2BLyMLCC1qbO7KgYJ9LUEvboqBoAwBGsrquf9Wj58k8C0RJlZo0dp0duevTx47su5LTXzwL%2BWdUtpN8g99bCnTJFePrOM4E%2F2tECPGkXx55xI7V49MlkNxnoqLhAX1I8pRPw54h6Mh3MNiK5pyw14WRJD67zP7Mw0tYd2n9%2BFC7dgZSd%2FTwZK2I7zOb1Ll6 IQz5pNMxNdTvIwF3UEV7rAtuRU%2F7L7qphmE9wrgdV4vW%2Bgd3qhtq0h5G56K9Nu1QDrA0AAItHcs10MCifHMirWiCbXdF4oK1%2BBg%2Fh%2F03IHsP3lmC4JGcBJakf7dPD%2Fmzbg2W9OrKwTrhbtibp9KzCpseLWMI3qW5DxSjEkOJTrlNjN7Ai9%2Fx2CUCyp9ijpOI4Bjlsq%2F1Llp8G1kuZAqJ3ERaRqevChO7T0QPKqH7M9gGXZxJKu1GQMqomzqupVlzlwltyqZAnXFJxEosntnaxM48g%2FU%2Fc5Q4mTbUakEL8Qbx9eQyQ7r%2Fu0pi%2BSc%2B6k54afdstPbD7wr5lyAQzwrB7v4ZEzsIPoBuMcswRc0Ib9A3V6ycRuGvC8ceeMTYyROgaPIxpT9Ptj423WhOat0Bp676FZU7t1K9DcKeo45jf6ncOBz%2BshRfVwmcFUv3cuCkolKh66Z1NYQzBF0wp1u3ZtQ%2BTGeAhmtC0gKpaCcijEE%2BKikPmYMgaFqxWOePSlpYLJef3ZwYzzZpPp9UDOXU0bwEHGrRFA%3D%3D";
var gi = 
    "%2BFn7oYWNA7ALGBrywEwmWjdVpbjRD7XtdkvQgfyWBj2SJfIy7Ox1ncF5sz%2BakarO5aCFqU2x1f6VhuHle5gLQiP8dtOjgHgOLpTDrEioiz6O%2FoZyO4tFsfBK%2BAg%2Bjz%2FaD8KfnxHwH6mHsAj8L%2ByKL2651hnJEZRZ4huAICM67bnHsAKzQbI64YvhVaTjngJH4E7DXlSrkkRPvY8aJe67Osp9ZEhMHiorqQvXKQK9PCyEgujFMP7AuN9c6d5mG2x9QLzJAoWHcvNVzXHtdPJn3zH50%2FCZDbsnrTc2%2FtteEUz%2B4G8UH63Dt8CF6wqOP89zCO%2FR%2BJ4qV56GV7ughRXhmK39a8il3svkNFpkOAFJPYw%3D";

var gg = 
    "tbNf3VSGB6VwAUgHU0Qxv2r%2FPV3hgkzXRxtYF8mpMh3ZNx6jCLKjfvxnBgs9VZQwzlFBdfywIBJbalFHFBd2TaFPv%2B1jT5kme8RHO36EyH4AdxgINqZZvjFwf6vldE0e4XZaX%2Fb5kngnJFqAI6MQHlPkgwqM7zE8MitiIaJPdee0bhgGFu1ZMtMhh3VFPlwjj6jmOLFqUa01qTLHK8JiFGvVeqijd8ba8cvmiD5gvSi%2FFxF8GJnTS2ZNLMxvZO3LRori2cVykq04TB4lz8y0DM8b4XnOfz%2B%2Fr3zRj3DjKypfldKKvLdWTXh4aExqU9nNB%2FgfYI0ZvBKYQ2pk%2FHx0vIrK32jScfEFKhESi4Rv%2FBvqMpaMwYtVJBRw69XUdarI53vHE1%2B4Fg7c5P%2FC61liwTfpUax36%2FOB9HDeetejgyNDa%2BSOaujDBHR6NEpCzOyiAifkttnqCIoRPpa4SiA8GlE5%2F7GEyQ7%2Fjymzh3Ei2oiHEgA1STeuuoB4iffJ5cqisWUgN2yGVAZ2tHU1tPpjHRAy2KffD9nxqjLYdO4rGMn4Y8JfE7qY0fjDg%2BsBNJz%2B3avU05DX9Pqy4SYt7V11X5CuMfxMmJnKXbGtWd8SydBpfCrKaFSIOxaAvR1Sn3nNBY26X83WNTcBOBNZzZwlyhCmAumYnMTGNLAFqlKGx0ZAiTT1InvBmpreidlRfiw%2BMeQ5HOjXxCxES%2BCh%2B11OfFseMeGnYOBfBeHMByz2c8%2FGoSHU337Oct2wkolmu8fTzWYu3fe%2F8zi4Tz8n7xRQ0I8r%2Bj%2BTvzDRqSqG4fMI6lbZNtvEGWGoR4qPMmBw66ZPWXpeS%2BVIeKPp%2FqLn%2Bqoqmwsqu4aZBbcKZH5Yoj%2BAGLU%3D";

var authkey = "EKps5Bz_lWJNDN00tBZw7AqrM_CybHqiizLbPLQPQyY";

Console.WriteLine("Decrypted gpia: " + DecryptPlayIntegrityField(gpia, authkey));
//Console.WriteLine("Decrypted gi: " + DecryptPlayIntegrityField(gi, authkey));
//Console.WriteLine("Decrypted gg: " + DecryptPlayIntegrityField(gg, authkey));
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