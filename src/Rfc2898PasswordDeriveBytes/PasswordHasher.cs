using Savage.Providers;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Savage.Passwords.Rfc2898PasswordDeriveBytes
{
    public class PasswordHasher : IPasswordHasher
    {
        public string AlgorithmName { get => "rfc2898"; }

        public string Hash(byte[] password, int iterations = 1024, int saltSize = 16)
        {
            var salt = GenerateSalt(saltSize);
            
            var computedHash = ComputeHash(password, salt, iterations);

            return $"${AlgorithmName}${Convert.ToBase64String(salt)}${iterations}${Convert.ToBase64String(computedHash)}";
        }

        public string Hash(string password, int iterations = 1024, int saltSize = 16)
        {
            var passwordAsBytes = Encoding.UTF8.GetBytes(password);
            return Hash(passwordAsBytes, iterations, saltSize);
        }

        public bool Compare(string passwordHash, byte[] password)
        {
            var elements = passwordHash.Split('$');
            if (elements.Length != 5)
            {
                throw new ArgumentException($"Unable to parse: {nameof(passwordHash)}");
            }
            var hashingAlgorithm = elements[1];
            if (hashingAlgorithm != AlgorithmName)
            {
                throw new ArgumentException($"The algorithm used to hash the password does not match the expected algorithm: {AlgorithmName}");
            }

            var salt = Convert.FromBase64String(elements[2]);
            var iterations = int.Parse(elements[3]);
            var hashedPassword = Convert.FromBase64String(elements[4]);

            var computedHash = ComputeHash(password, salt, iterations);
            return hashedPassword.SequenceEqual(computedHash);
        }

        public bool Compare(string passwordHash, string password)
        {
            var passwordAsBytes = Encoding.UTF8.GetBytes(password);
            return Compare(passwordHash, passwordAsBytes);
        }

        private byte[] ComputeHash(byte[] password, byte[] salt, int iterations)
        {
            using (var passwordDeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                var key = passwordDeriveBytes.GetBytes(256);
                using (var hasher = SHA512.Create())
                {
                    return hasher.ComputeHash(key);
                }
            }
        }

        private byte[] GenerateSalt(int saltSize)
        {
            var randomBytesProvider = new RandomBytesProvider();
            return randomBytesProvider.GetBytes(saltSize);
        }
    }
}
