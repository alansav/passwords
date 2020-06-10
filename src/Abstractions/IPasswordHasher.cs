namespace Savage.Passwords
{
    public interface IPasswordHasher
    {
        string AlgorithmName { get; }
        bool Compare(string passwordHash, byte[] password);
        bool Compare(string passwordHash, string password);
        string Hash(byte[] password, int iterations = 1024, int saltSize = 16);
        string Hash(string password, int iterations = 1024, int saltSize = 16);
    }
}
