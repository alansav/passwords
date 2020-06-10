using Savage.Passwords;
using System;
using System.Collections;
using System.Collections.Generic;
using Xunit;

namespace UnitTests
{
    public class PasswordHasherTests
    {
        public class PasswordHashers : IEnumerable<object[]>
        {
            public IEnumerator<object[]> GetEnumerator()
            {
                yield return new[] { new Savage.Passwords.Rfc2898PasswordDeriveBytes.PasswordHasher() };
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        }
        
        [Theory]
        [ClassData(typeof(PasswordHashers))]
        public void Hash_returns_different_values_when_called_with_same_password(IPasswordHasher sut)
        {
            const string password = "password";

            var hash1 = sut.Hash(password);
            var hash2 = sut.Hash(password);

            Assert.NotEqual(hash1, hash2);
        }

        [Theory]
        [ClassData(typeof(PasswordHashers))]
        public void Compare_password_returns_true_when_password_is_same_as_password_used_to_hash(IPasswordHasher sut)
        {
            const string password = "password";

            var passwordHash = sut.Hash(password);

            var match = sut.Compare(passwordHash, password);

            Assert.True(match);
        }

        [Theory]
        [ClassData(typeof(PasswordHashers))]
        public void Compare_password_returns_false_when_password_is_different_to_password_used_to_hash(IPasswordHasher sut)
        {
            const string password = "password";

            var passwordHash = sut.Hash(password);

            var match = sut.Compare(passwordHash, "wrong");

            Assert.False(match);
        }

        [Theory]
        [ClassData(typeof(PasswordHashers))]
        public void Compare_throws_ArgumentException_when_passwordHash_contains_3_separators(IPasswordHasher sut)
        {
            var ex = Assert.Throws<ArgumentException>(() => sut.Compare("$2$3$4", "password"));
            Assert.Equal("Unable to parse: passwordHash", ex.Message);
        }

        [Theory]
        [ClassData(typeof(PasswordHashers))]
        public void Compare_throws_ArgumentException_when_passwordHash_contains_5_separators(IPasswordHasher sut)
        {
            var ex = Assert.Throws<ArgumentException>(() => sut.Compare("$2$3$4$5$6", "password"));
            Assert.Equal("Unable to parse: passwordHash", ex.Message);
        }

        [Theory]
        [ClassData(typeof(PasswordHashers))]
        public void Compare_throws_ArgumentException_when_first_element_is_not_valid(IPasswordHasher sut)
        {
            var passwordHash = "$invalid$3$4$5";

            var ex = Assert.Throws<ArgumentException>(() => sut.Compare(passwordHash, "password"));
            Assert.Equal("The algorithm used to hash the password does not match the expected algorithm: rfc2898", ex.Message);
        }
    }
}
