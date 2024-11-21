using System.Net;
using System.Security.Cryptography;
using System.Text;

//Template with token
/*const string gpia = "wIoqbOjjWNI1KZ5cd2g71%2BrKkQiN45Ptl%2BNGNu5R3g2M7jMZ486%2FNBNspSwhEtYLcGmlYYn2RiRUJsztl43liVohZfrL5j8xIFguDeSe7x60sONEyuqmLiUXxRbBqDPOujflMFdI9%2FgP%2BxI7vyeKLuOwS%2Bf301EloLFNuIRkzzMTuWWYOQ7rqoo5jIBc%2B5VuWORqlJAC3QLVXySyRlEgyf0qlYUjJQtlLhQ3UdVC47q6kc7IMKghwm2YvOSkR8VFLi8WqrH2r2B8Z%2BY0dO5kspWidpiPqJkc4gOHvGaKm5XjSyhUg0FgMblxKts%2FHNGWtzX9F0GYor55Mvj9hMpMfkqDELzbIdRjSR5mTAcCjXQlfiDDHHuuDuVMzznhnoCjwx7WyNQfRxci4C4GaDfdNRi6%2BZc9ilqowmQsmUKEnZS2YSyIporZQZi%2BNl6aTAE4mIUylaSsh1p6ykiuV4RgJZk%2B%2BexHJbH4SCTQGcp0UYgurOHmbYY79PesmyH1b9B32PqWjQLkdKVdNiLXzr7DNfmbjFjpOiFLiiTWJ6ZWTWxqCuDRklQgYjZRa63DmOJWV%2F55eKgn0m3wO5AgVmmKIaOD0F6FyjrlwxBJNYgctv2tU%2B7Bhgh6FMFDOIRAsaUDnxd4ksbUrAskkGPRIIvKRcI46xtg81VqcY2TCC597YU4zQp85QPq3mRStcSnhOWVSoK794r1KveYoMxBSshfdHmqIlohzemNYcKnkMf9rvyGASKNAQgbFWOL4ra1RnlDAdXlCdvX7XxGLQTHYcV%2B4aIvuBZFEuApaq1Z5PiSO3YACHFY48e8JbFMVrQCBPjRJi5%2FTA0B8%2FiVF5%2BPnm0u7eC%2F%2F9g4twEIAleddBCWVvWCY0bB42je%2FDEma5IRcKMeSPUlA6WQAOmwOwHUuMYGp63fTj3tC2fON45xLtcpjc9mWc%2FWxDSiL2CXwczJ4w1A60f4tt0HqMstQ3zJ4ncusKpQBS1bZp4q6eTR3FouznkApyu2MENxriKrmgLr%2BRDjQ3H3xjnaSjFDdjy%2FSL%2BGyjhjSDXRdspnWVbyFF2CjzJyR5KRRLU0rz2ae%2FwknRh4t0Z8XZfGe3XLavh8Ssbt8HSFZilRVmj9tcBqUvQa%2BZo%3D";
const string gi = "N%2F%2B4yFrAs0Q7BhvC3bqJWl41u5NMJhxjju0pbzlNR%2FAsSYi5HBhHxLYdFhKA3%2Bn1Y0Ai7tFIpJisQBVsGUlEykzz%2B4CJinZ6hr2OnMaUJEsZHoA4SqLb417hs5HUVuSWg2gxiVGSJNIIcDJrQ6yei8Rl0YSqewR6g5lOPrbmKI%2FA%2FAhIhOj8xwl3KlCGg2AsqxKRchNDmDs4Gn6%2FgY0D2%2BILrZsYuTfCJUFJlIwKd%2FtcA3bQ0sHtrB%2BQ2OyoWYEpjYZMdQmDfhjUMJYpNUnxpRRpXcDuYQ0vYV3bcB9FmDSH7ctG2diCCyB7%2BSjmycoQDLOJuedFljYPQg%2FVFo5Va0HG%2BoSPHKDWroKSr25rLnerQOWwW19SETBFDyR2bl3%2BfT8Z%2B7g4gDRPX2cu7mJbAPp71lzPLC9%2FBYDhWwvAahDWC%2FeQErcCtD5wubGU7COvw7M6wlgsN23qRUGQayqlX7wPR7wAHTdIMm0LnCCNlmyY9tZSx5BARREfOejTOUfrYAmQi2nfQ1V6mGrBtcHY5Y9cMg2jlnL2RgFeKiit%2BCzakhM3UBYfA00JGHQ5Pl%2Fu";
const string gg = "77lZSCjhco6hbtszYINaXxEKkJIz4ajl46xck2D%2Bvo9by4dMswgsaRWgF8cnZOnjtIczeomVwlxZBVPcawj1cAid7DfM0i4234%2FPDsxC8DnJbjOytKYxcLv5BIcY1LhZqhyWAh5SCGUW08NzFbxGdGQWY5yfQ7CwJa1%2BuvPjzYsfhmeEnEShz5thqBmHR2J6owh8XXvyzz2APjv9esaywIvbqGumFHAFlvURoL8SpG1xz1yF%2FbQ0g1DzvdQ6luTVlGI3Puyxek%2BAdH%2F9047H6p8QQLenQXrPbDNKx%2BOxw4japx%2BikeFlsM6urAjcBVJGu2HjdpvUEUfvTrDkoneSvBO%2Blt0iO3%2FpkPUm%2BoU%2FGad7kS3f7wI3FswyEbxpNW8SCZUgBfrUJkICNQQvlUaXekiqy8oskXQdbV50cVfNThiagBvzjkQANyp6XjoNcPcQhKVUyABRqgEk4OkWY50wcnKSh6VB5mvXe3Ki8flCm5UEgm4pCyYFu5m%2BfXQ%2FG5ckUVN275zW1RK%2FF6dn7DEwqDIK0%2Fyip1KhW5zEOo%2BCL7vLnwiJN0rlEJvSuKn9fNfpU4M8kup2KU%2BmLGLc%2BHLGzH1FQYaQfQfb7vGufo9qqE9vT7sDxXXIEKKayjsp8xnrus10hR0ETlIHwy72gRXdfBCBCo9f17b%2Bclg8ho3iDkOAaphBgQ5w67JmTEVLxQwMJbDQvwqLOEZklgXq%2FqgwrnYFc097Ck56G5yWjd1qZOb2%2FJ5Mp9wL8g7z2aZTKNUV";*/
//Template no token (1002 error)
const string gpia = "TEY%2BDdXwr0eG%2FTDNxNep74kHwJgpYgvJAcWuDgo0I1UwOTxTc%2FceM%2FgQHNMeR2ly7aYzWQmcNllbgXKlbQRskSbJumLCuCsbPPtk9BQ4rL1DymM1HtxUc61OaQAndzcW6fogARB4JCCi1IhN4tS4blT%2BoXB1Pi51msaXz1muqxEC6S9M1FnqzcRbGmc%2FvlBKRbnhFgULLsI%2BljMPJpZmv8J96Y0spjmugNGRa0UgIewonFShkh70DPcvfRA1Ju61it%2B5rUFXN2UD7jac8D7Bcod75BB9ziaemPuo77pLehCDX8UBfFIj4y9WJkAOMQDhfFPASBxE94AME58vk0riP27oYFFer3bmjusozLIkDk2ioy0bFlTyIl0oZdzZnUrDsA2wuS7J4aoZmRsb9noHAQ%3D%3D";
const string gi = "SMwP8Cnk8xXYDmOx1GhfAcojA5Hhge57AtxC6eGUkoyH7CIgQ9KpVK%2BAZ82sH%2BTFveBd6d42gEElzwc1rEOHmajMuUx9MQTowrQzmoZxbatC9eD9cJjZGn2U9nPQn%2Fdg1qmGvjzp01WQ4G%2BcqHC%2BYTpg6QEW1kALU318Mjg3ngLZQwJZTGbkufYiaSKgUEaAFAZG9NrXH4Ww3pgtN8VOL3hMoTsyRXF32PHnSQ1Kut20hJNbiFLhMM2tdKBCBx%2BuARG9%2F8c8v%2BZqvS%2FK1g0PZyiufESRTpU6AWtj4hshGWu7WxPvkIFSWft9wpRicL%2BglMtLyCdFGhVreh%2BC80O2BbJFB5MzVfxHOBWAHvfltzL1LdnUL5X5jiAbsmemb7hKCvqyyOQAG%2Fwh9Vb6bQ4EYPeNH%2B%2FVAeESDj7ISUtfU61WNcM22bZQyB5jZKZhqTXFCT581YGJV4UnwnRvSUAO0l%2FBoXGj%2FOVzj8g7mmEa3NcZB404Hqk%2FVOI85O7WuswVl7VKj5aMyPm%2Fr7sgabYzvcRaXIW%2FRyE%2B9xqRTOGnUPLVBDxgXLWkCZh3%2BWXCeqtr";
const string gg = "Uz7mm0pL35Jz0Z1WhxavQsMwS84KmDy53OxRe6QuQBY%3D";

const string accessSessionId = "GdjKMP5eRf67Q_Ck-2hycQ";

const string authkey = "KJyaQuAcDeRgBpWmvggpespe7TQRquiQ_m-ad4T_e0o";

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