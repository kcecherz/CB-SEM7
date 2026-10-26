using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;

namespace Klucznik.Security;

public sealed class PasswordHasher
{
    public const int TimeCost = 2;
    public const int MemoryCostKibibytes = 19 * 1024;
    public const int Parallelism = 1;
    public const int HashLength = 32;

    private readonly Lazy<string> _dummyHash;

    public PasswordHasher()
    {
        _dummyHash = new Lazy<string>(() => Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(16))));
    }

    public string DummyHash => _dummyHash.Value;

    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var config = new Argon2Config
        {
            Type = Argon2Type.HybridAddressing,
            Version = Argon2Version.Nineteen,
            TimeCost = TimeCost,
            MemoryCost = MemoryCostKibibytes,
            Lanes = Parallelism,
            Threads = Parallelism,
            Salt = salt,
            Password = Encoding.UTF8.GetBytes(password),
            HashLength = HashLength,
            SecureArrayCall = SecureArray.DefaultCall,
        };

        return Argon2.Hash(config);
    }

    public bool Verify(string? encodedHash, string password)
    {
        if (string.IsNullOrWhiteSpace(encodedHash))
            return false;

        try
        {
            return Argon2.Verify(encodedHash, password, SecureArray.DefaultCall);
        }
        catch (Exception)
        {
            return false;
        }
    }
}
