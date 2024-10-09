using System.Net;
using System.Security.Cryptography;
using System.Text;

//Все поля содержат имена эквивалентные друг другу в оригинале.
//С заполнением проблем не должно быть будут проблемы
var gpia =
    "gjapYJ3Jg9XJAR7hKxPS7Kgj7driQRllfNR7vd%2BUy0WBW13UOrB23VfR1H09YhQ0CBLzTjAi6c2EYGfPGleWsFlhBzAxervPpvSjibwLRQOWYYazkAxHKEt1SQrfWwVK2H9F7TU0%2BkXo04FDMA5viPKZLNtNWfpo4aD2iPmwVb1JarVsL0F7s%2Bbp0JpwaI6A40wgDVtK26pw%2BkdlhH%2BM2y%2FEYXTeLmLmGVS%2BGiu9CY6%2FeGd4txa5%2BFjLPuy8fWJF8LIse0GoShaLHpe1PoJUKSF9beKfZWFtNTVkYmjN%2BjH7crsjYIDvW3rNxKoXH7M7El6eX0fsUip5iL54OtWHIVawRzbgtiBhc%2BeyfWQrroKcbX7JEEdJjs1f7nIdcR0tNhyx3LMHr7vs%2BlY0w1LXojkTqE6X%2FB4dURbyvu7Tcfh%2B1XWOY%2Ffv0Ja%2BXvXEjAx3ShRlcyqAXgyC84CymCkQEGwK3tAVVneldP3O83XaXOCNQtFUfHn8LzX%2Bsr%2BFfTiZf2dNtPTN64vEIVzHd8YiF82GUPMJPo34vx%2BvMs%2BYCEozl3pRoiRTlLYA3Ef6P1LI%2Bf7KD5qW2MGzhxUqEViixLCP79XFf%2BedFmEVYBbMTNZFAPRZ4ixa%2BLjtkWr7f7WSYSxY1jdru1hMfpd4egzxeT1e2eLqAPnkQNQ2pIqrXXn0mPURrcC4Z2a0yV6akmNDDJMoamRPTWRIu3IYbk9sx%2BU1JP19KW5Kp05bwQLnHPZf3E0Vn3SnzjVBPHliWj1E94ECe34evjsSx%2FtyQdq%2BHgSDNhPT1AyI%2B%2FCaL%2Br4PVWV7evuNXjvgGnSq4z62RfBAxz5O%2BrQsHdND%2FzEcitL4pg8jSh2HCQq7CkPTfHNK8xwYKEpJOE7cnmZHrAYyj6zKx6LD1IgUiWepS4X4dwkJZGEIujzqe%2FnwXe5121sR%2BdpD3gH29hmWlItGoFFrTAupK%2Bh6qzps4DS799urCkmIikxSwFmGeEeG9ADLk3W7nyFVeBgmDWh0610Ar0euo52KC2fEX1OD4Y5OdsYcir5BO30y%2FlbQMgpmoM%2BqbfdpluM6JM86XUleIWVM2aKo6lRRPmk9FVKGSMq2ckyR0AEkiau6M52EtGU%2Bb2blk0M%2BgcIsxP%2FleAoYec6walOsg7eubkDHwNITRgGVdNzzHe5rYnvkN4o6OAbH9b%2BslIF%2BZ8MNo3OwiOog7k2SkA9qG6MtL2Q2uSJVKS3lW0tJgMvKA%3D%3D";

var gi = "35nv%2FgglIvld84t5Fw72arEhz4wwdlS4qSAG0yzt6FCPIhSFTAdK%2B%2BTdEBHfI2UQVSM26IF8C3butIXsN2XCy%2BUh4GkwqEotsMd9oJflMdVYhdIzpPjNpWAyi7809zE84GkhGOzds7WviZYuf0lFbpqI93MHC1uw6nLXZmw8Kh3zZl0DHt7c9ozDDfmDJQoSbtsXAcUbmjvTAt1RV1zrLQcb3WdkdX%2FYRM%2B7O10VGnyEaSN8TCtHAlXMBAyS93LjZwGvtnvxoMpqG0LgHy%2BpcosZ2KtAeB2cPtQ3dJA5Hzl4EZ%2F0MYVOtOWisdOXLes76HgG2mQ6xmACsO7PBTV3eOzipGzLcPVA6cN5H63Fu9eEhefiVtK0lshd2eQlt7Ay2eOxcCJi92bPFmeymLITh1kEqws%2BM%2FNE52j5LiQPRA0jD5aeppU%2Fe86j%2BvwHgWQt";
var gg =
    "u8EVQqTrdYxYLxs%2FSlVdYKBRlvOzETbl1Avf%2FMcSpGwQ6gBTPnSgm0IT%2FCMsRt2VFyeTdk%2Bj4JNJO7oJdqqb9n10KKTaZw%2FC5uM39y9GhBduceUNq7GJNvEdgrUmNbq52Qdct3rtULqKPovUviazAu0awCGH2BQmi1EBgGznemY4lYmUqyhrRHOR9Tbmnqki%2FDUYot%2B2uk%2Bji6PZyAbV4xfhmYcmboe8lrU7RaISMWwXPhcOJXXOZI9qaJ%2FedoAQx1KisGHnRwH9kKPW7AfLnuaYM1lvL14NKIeRn04zKrV1aMf8TmSiagVr4Ucz6GyOHmW4kU6BOu9u%2BGgVNmc17w65R79V%2BynPjHWEoCVdEtrLjJKlPR6jOd%2Fi%2BnRY3EYh4yagkMn8Ic7D6gjqwygYg0BLYPbiMxCyB%2BR4O6v2crv2SBW623Lb2opLs59fF4Cd2E5maM%2Fok1btozyK5wNPb4C6i5CRLcAW7TSSrz%2Bv1BUclcIQ%2B5I4XeCJ8OkWeDY%2FMP4c9e7Cr6%2F2CSYjW3d%2Buwp%2BhE7akXSn5PxdnQj6ecb6wZZi62QnGhzN54Dqp3TWtyKkkGomvB5EeJlShdcm1xo16H9iTaWfIcraxyQTPAERYslDO%2BNOtAmy7wLasaortxmNq1fsg%2FMmjurzaZTUYszPQDPAm5w9wHKDZfdj0s58WPNYYAPTzgaMoV1ew9RgyR3wiCjZJsKn%2FuuWYFk4Y8lGSupDOGd4NjQN7tir7T24ft5dPgfAFfgI3pAxa%2Bi5ZboQ8I%2Foe0dmrlAy4g2cB9W%2BD5eZrTyUvLjNiw%2F%2F9DYW815JhAKToAR%2BvLe1ZudJXzRAW%2BHUnflgqmX3V49zU2GlFuh50SYLRkJdtOW86PY%3D";

var authkey = "J1LW-daDOqgSWusxShHc1-nCikr34AjRi_ToRLSlYS8";

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