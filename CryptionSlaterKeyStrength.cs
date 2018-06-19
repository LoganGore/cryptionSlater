using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace CryptionSlater
{
    public sealed class KeyStrength
    {
        /// <summary>
        /// Gets or sets the regular expression string used to validate key strength. Default is @"(?x)^(?=.* ( \d | \p{P} | \p{S} )).{8,}". (Minimum 8 characters with a digit or symbol).
        /// </summary>
        public string KeyStrengthRegEx { get; private set; }

        public KeyStrength()
        {
            KeyStrengthRegEx = @"(?x)^(?=.* ( \d | \p{P} | \p{S} )).{8,}";
        }

        public KeyStrength(string keyStrengthRegEx)
        {
            if (String.IsNullOrEmpty(keyStrengthRegEx)) throw new NullReferenceException("Key strength regular expression cannot be null or empty.");
            KeyStrengthRegEx = keyStrengthRegEx;
        }

        /// <summary>
        /// Indicates whether the provided key passes regualar expression checking.
        /// </summary>
        /// <param name="key">A key.</param>
        public bool IsStrongKey(byte[] key)
        {
            string regX = KeyStrengthRegEx;
            string encodedPass = Encoding.UTF8.GetString(key);
            return Regex.IsMatch(encodedPass, regX);
        }

        /// <summary>
        /// Indicates whether the provided key passes regualar expression checking.
        /// </summary>
        /// <param name="key">A key.</param>
        public bool IsStrongKey(string key)
        {
            return IsStrongKey(Encoding.UTF8.GetBytes(key));
        }

        /// <summary>
        /// Returns a bool indicating if the supplied keys 1. are not null, 2. do not match, and 3. pass regular expression checking. By default keys must be at least
        /// 8 characters and contain a digit or a symbol.
        /// </summary>
        /// <param name="encryptionKey">The encryption key.</param>
        /// <param name="authenticationKey">The authentication key.</param>
        public bool AreKeysSecure(byte[] encryptionKey, byte[] authenticationKey)
        {
            return ( (authenticationKey !=null) &&
                     (encryptionKey !=null) &&
                     (encryptionKey != authenticationKey) &&
                     (IsStrongKey(encryptionKey)) &&
                     (IsStrongKey(authenticationKey))            
                );
        }

        /// <summary>
        /// Returns a bool indicating if the supplied keys 1. are not null, 2. do not match, and 3. pass regular expression checking. By default keys must be at least
        /// 8 characters and contain a digit or a symbol.
        /// </summary>
        /// <param name="encryptionKey">The encryption key.</param>
        /// <param name="authenticationKey">The authentication key.</param>
        public bool AreKeysSecure(string encryptionKey, string authenticationKey)
        {
            return AreKeysSecure(Encoding.UTF8.GetBytes(encryptionKey), Encoding.UTF8.GetBytes(authenticationKey));
        }
    }
}
