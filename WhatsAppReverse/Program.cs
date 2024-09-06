using System.Net;
using System.Security.Cryptography;
using System.Text;

//Все поля содержат имена эквивалентные друг другу в оригинале.
//С заполнением проблем не должно быть будут проблемы
var gpia = 
    "QwP3iV8eOgIeH03zuvYUqeEVv0Ta4z2E2OAeSd9mBjmwR%2F1iLem7H53IM0mO39x6Th2tIoNKumisKV1254M6VKoZcPD7C0N%2Bs%2F%2FayK9tmTAdPreIYa%2F82ibqObz93blCmU39tO1qdO0SJ%2F0vjaGAWclaGJkSscfOGCYmmiPDhJWXt%2FGqx3RTzn77xCXbv6Zz19RseMAqMytXSM7LfAuOBU0TrH7AgYeKihRfgT6yQOyi81Nb7OJCzOrGbRABxN%2BAPTlPRS4%2BCDdzp5xd8CKjmp%2BsvHRDTucnmPc2S3t%2BS3rJhTVAAt64WAjsMsNxvw728fyBXKUdK2W8HADw8ODL53FOBPqftb3rPs1J%2Bf5eEdP7OEAZ5DyjXZbAG5LqqKFZ5Cj27yMLN8Olghr8Qxr7Jx701ES5pL6uxFRv5mxs%2B1JCK1moT8gL1sITIhiu0gWJmikFlwzsAqWdcH%2BBTW%2FO04liqeh9wU0A482zXee%2BPWCi%2BMm0lPushEcKSiyCuj2pqLoCKGtEHbkpAJf52I82dY3VQh07i6Xu%2BWrXjBRU7luMA%2Bj%2BnRyiC3Zj%2Bfd3D%2Fg8vFuEaTXBP5bMWzF02BPnMwy%2FNqoGdbpgbUVbER0mqIaRMl1c6D1NXB6c7Rg0dnd1Q6oQIxQvH4r%2F7Ml%2B%2Fx%2FQuU2IbVUfBmgZhQdzuPLpAxTZ6NfmjL9zcSesqzwwe6omBp4OiuFfTQfEffOY8tsadMyzha77o0Hac7f%2B5LedmIRmgtLiDFuoei04Wih5EfBNgUVfo1M5o3OFdGGPoEz8YZeDibAJ3pujHDC0AIR87iExrtgqmtzTamI2gFH0yKM9cw9RoD0PrJ6o%2FcPFroJXdaiKIrXsnNkGcp8jhm4egUWpOGMGj%2F2WQ7TDOIxIs86BoiJ0PqbZjTOEwOjVQq54iygJajrl1AgkVZwWKSOngrpUPy2kEWqmBZ2FUb8elcGgWMWncM02SN%2Ba2trCf7BlcjidJc2eQIC01vKz6SmALnH%2F43ElmPyrC56J4%2FM7sF0Xr%2Bc2Po8UrwmeowYk3DX9GN0h5HJHAyRIgV55FQBtJmFWM02W%2BkAawPcFL8hcd1l0GEtpi3UOmUT1m1vREYVCXckcaKnCnNdqBYVmCREwmmi10%2BAA4eS4b29Lye3IuWna";

var gi = 
    "%2BFn7oYWNA7ALGBrywEwmWjdVpbjRD7XtdkvQgfyWBj2SJfIy7Ox1ncF5sz%2BakarO5aCFqU2x1f6VhuHle5gLQiP8dtOjgHgOLpTDrEioiz6O%2FoZyO4tFsfBK%2BAg%2Bjz%2FaD8KfnxHwH6mHsAj8L%2ByKL2651hnJEZRZ4huAICM67bnHsAKzQbI64YvhVaTjngJH4E7DXlSrkkRPvY8aJe67Osp9ZEhMHiorqQvXKQK9PCyEgujFMP7AuN9c6d5mG2x9QLzJAoWHcvNVzXHtdPJn3zH50%2FCZDbsnrTc2%2FtteEUz%2B4G8UH63Dt8CF6wqOP89zCO%2FR%2BJ4qV56GV7ughRXhmK39a8il3svkNFpkOAFJPYw%3D";

var gg = 
    "tbNf3VSGB6VwAUgHU0Qxv2r%2FPV3hgkzXRxtYF8mpMh3ZNx6jCLKjfvxnBgs9VZQwzlFBdfywIBJbalFHFBd2TaFPv%2B1jT5kme8RHO36EyH4AdxgINqZZvjFwf6vldE0e4XZaX%2Fb5kngnJFqAI6MQHlPkgwqM7zE8MitiIaJPdee0bhgGFu1ZMtMhh3VFPlwjj6jmOLFqUa01qTLHK8JiFGvVeqijd8ba8cvmiD5gvSi%2FFxF8GJnTS2ZNLMxvZO3LRori2cVykq04TB4lz8y0DM8b4XnOfz%2B%2Fr3zRj3DjKypfldKKvLdWTXh4aExqU9nNB%2FgfYI0ZvBKYQ2pk%2FHx0vIrK32jScfEFKhESi4Rv%2FBvqMpaMwYtVJBRw69XUdarI53vHE1%2B4Fg7c5P%2FC61liwTfpUax36%2FOB9HDeetejgyNDa%2BSOaujDBHR6NEpCzOyiAifkttnqCIoRPpa4SiA8GlE5%2F7GEyQ7%2Fjymzh3Ei2oiHEgA1STeuuoB4iffJ5cqisWUgN2yGVAZ2tHU1tPpjHRAy2KffD9nxqjLYdO4rGMn4Y8JfE7qY0fjDg%2BsBNJz%2B3avU05DX9Pqy4SYt7V11X5CuMfxMmJnKXbGtWd8SydBpfCrKaFSIOxaAvR1Sn3nNBY26X83WNTcBOBNZzZwlyhCmAumYnMTGNLAFqlKGx0ZAiTT1InvBmpreidlRfiw%2BMeQ5HOjXxCxES%2BCh%2B11OfFseMeGnYOBfBeHMByz2c8%2FGoSHU337Oct2wkolmu8fTzWYu3fe%2F8zi4Tz8n7xRQ0I8r%2Bj%2BTvzDRqSqG4fMI6lbZNtvEGWGoR4qPMmBw66ZPWXpeS%2BVIeKPp%2FqLn%2Bqoqmwsqu4aZBbcKZH5Yoj%2BAGLU%3D";

var authkey = "nYQWqkTe0oWDdnt59tksPCLJvr-iwLUltUI-u67gEXU";

Console.WriteLine("Decrypted gpia: " + DecryptPlayIntegrityField(gpia, authkey));
Console.WriteLine("Decrypted gi: " + DecryptPlayIntegrityField(gi, authkey));
Console.WriteLine("Decrypted gg: " + DecryptPlayIntegrityField(gg, authkey));
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