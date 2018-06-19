
/*
CryptionSlater - Generic CBC-HMAC Encryption Library for .NET/C# 4+
Copyright (C) 2015 Logan Gore

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
  
Contact Logan Gore at loganlgore@gmail.com
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace CryptionSlater
{
    public enum CryptionSlaterMode { HighPerformance=10, Performance = 1000, Balanced = 6000, Secure = 30000, AutoAdjust }
    
    public class CryptionSlater<TSymmetricAlgorithm, THmac> : IDisposable
        where TSymmetricAlgorithm : SymmetricAlgorithm, new()
        where THmac : HMAC, new()  
    {
        /// <summary>
        /// Holds the TimeSpan that represents the length of the last PBKDF2 stretching function to run for the authentication key (encryption phase only).
        /// </summary>
        public TimeSpan LastAuthenticationKeyStretchingTime { get; private set; }

        /// <summary>
        /// Holds the TimeSpan that represents the length of the last PBKDF2 stretching function to run for the encryption key (encryption phase only).
        /// </summary>
        public TimeSpan LastEncryptionKeyStretchingTime { get; private set; }

        /// <summary>
        /// Gets or sets the number of cycles the chained Rfc2898 stretch function will run to derive the encryption key.
        /// </summary>
        public Int32 EncryptionKeyStretchIterations { get; set; }

        /// <summary>
        /// Gets or sets the number of cycles the chained Rfc2898 stretch function will run to derive the authentication key.
        /// </summary>
        public Int32 AuthenticationKeyStretchIterations { get; set; }

        /// <summary>
        /// Controls the time the encryption key derivation function must run if using AutoAdjust. Default is 200ms.
        /// </summary>
        public int EncryptionKeyStretchTargetMS { get; set; }

        /// <summary>
        /// Controls the time the authentication key derivation function must run if using AutoAdjust. Default is 200ms.
        /// </summary>
        public int AuthenticationKeyStretchTargetMS { get; set; }

        /// <summary>
        /// Gets or sets the salt bit size. This will default to the key size. 
        /// If setting a salt size different than the key size, this will need to be set after the key size is set. Must be at least 64 bits/8 bytes.
        /// </summary>
        public Int16 SaltBitSize { get; set; }

        /// <summary>
        /// Gets or sets the block bit size. This will default to the largest size that the algorithm allows.
        /// </summary>
        public int BlockBitSize { get; set; }

        /// <summary>
        /// Gets or sets the encryption and authentication key bit size. Setting the key size will also set the salt bit size.
        /// </summary>
        public int KeyBitSize
        {
            get { return keyBitSize; }
            set { keyBitSize = value; SaltBitSize = (Int16)value; }
        }

        /// <summary>
        /// If set to true, authentication key stretch iterations will be automatically increased until the threshold in AuthenticationKeyStretchTargetMS is met.
        /// </summary>
        public bool AutoAdjustAuthenticationKeyStretching { get; set; }

        /// <summary>
        /// If set to true, authentication key stretch iterations will be automatically increased until the threshold in EncryptionKeyStretchTargetMS is met.
        /// </summary>
        public bool AutoAdjustEncryptionKeyStretching { get; set; }
      
        /// <summary>
        /// Indicates whether Dispose has been called.
        /// </summary>
        bool isDisposing;

        /// <summary>
        /// A byte[] of the encryption key provided in the constructor.
        /// </summary>
        byte[] EncryptionKey;

        /// <summary>
        /// A byte[] of the authentication key provided in the constructor.
        /// </summary>
        byte[] AuthenticationKey;

        /// <summary>
        /// The hmac bit size/length. This is obtained from the algorithm upon construction.
        /// </summary>
        private int hmacBitSize;

        /// <summary>
        /// The IV bit size/length. This is obtained from the algorithm upon construction.
        /// </summary>
        private int ivByteSize;

        /// <summary>
        /// The hmac bit size/length. This is obtained from the algorithm upon construction.
        /// </summary>
        private int keyBitSize;

        /// <summary>
        /// Sets the encryption and authentication keys and the security mode.
        /// </summary>
        /// <param name="encryptionKey">The key used for encryption.</param>
        /// <param name="authenticationKey">The key used to ensure data integrity.</param>
        /// <param name="mode">The enum used to easily control salt iterations to derive the keys. Default is 6000 iterations (Balanced Mode).</param>
        public CryptionSlater(byte[] encryptionKey, byte[] authenticationKey, CryptionSlaterMode mode)
        {
            this.EncryptionKey = encryptionKey;
            this.AuthenticationKey = authenticationKey;

            EncryptionKeyStretchTargetMS = 200;
            AuthenticationKeyStretchTargetMS = 200;

            hmacBitSize = new THmac().HashSize;
            ivByteSize = new TSymmetricAlgorithm().IV.Length;

            BlockBitSize = GetLargestValidBlockSize();
            KeyBitSize = GetLargestValidKeySize();
            SaltBitSize = (Int16)KeyBitSize;

            EncryptionKeyStretchIterations = (Int32)mode;
            AuthenticationKeyStretchIterations = (Int32)mode;

            if (mode == CryptionSlaterMode.AutoAdjust) AutoAdjustEncryptionKeyStretching = true;
            if (mode == CryptionSlaterMode.AutoAdjust) AutoAdjustAuthenticationKeyStretching = true;
        }

        /// <summary>
        /// Sets the encryption and authentication keys. Balanced mode is set by default.
        /// </summary>
        /// <param name="encryptionKey">The key used for encryption.</param>
        /// <param name="authenticationKey">The key used to ensure data integrity.</param>
        public CryptionSlater(byte[] encryptionKey, byte[] authenticationKey)
            : this(encryptionKey, authenticationKey, CryptionSlaterMode.Balanced)
        {
        }

        /// <summary>
        /// Sets the encryption and authentication keys and sets the security mode.
        /// </summary>
        /// <param name="encryptionKey">The key used for encryption.</param>
        /// <param name="authenticationKey">The key used to ensure data integrity.</param>
        /// <param name="mode">The enum used to easily control salt iterations to derive the keys. Default is 6000 iterations (Balanced).</param>
        public CryptionSlater(string encryptionKey, string authenticationKey, CryptionSlaterMode mode)
            : this(Encoding.UTF8.GetBytes(encryptionKey), Encoding.UTF8.GetBytes(authenticationKey), mode)
        {
        }

        /// <summary>
        /// Sets the encryption and authentication keys. Balanced mode will be used by default.
        /// </summary>
        /// <param name="encryptionKey">The key used for encryption.</param>
        /// <param name="authenticationKey">The key used to ensure data integrity.</param>
        public CryptionSlater(string encryptionKey, string authenticationKey)
            : this(Encoding.UTF8.GetBytes(encryptionKey), Encoding.UTF8.GetBytes(authenticationKey), CryptionSlaterMode.Balanced)
        {
        }

        ~CryptionSlater()
        {
            if (!isDisposing) Dispose();
        }

        /// <summary>
        /// Clears the byte[] keys.
        /// </summary>
        public void Dispose()
        {
            if (!isDisposing)
            {
                isDisposing = true;
                Array.Clear(AuthenticationKey, 0, AuthenticationKey.Length);
                Array.Clear(EncryptionKey, 0, EncryptionKey.Length);
            }
        }

        /// <summary>
        /// Encrypts and HMACs data.
        /// </summary>
        /// <param name="data">Plaintext as byte[]</param>
        /// <returns>Ciphertext as byte[]</returns>
        public byte[] EncryptToBytes(byte[] data)
        {
            return EncryptAndHmac(data);
        }

        /// <summary>
        /// Encrypts and HMACs data.
        /// </summary>
        /// <param name="data">Plaintext as byte[]</param>
        /// <returns>Ciphertext as a Base64 string</returns>
        public string EncryptToBase64(byte[] data)
        {
            return Convert.ToBase64String(EncryptAndHmac(data));
        }

        /// <summary>
        /// Encrypts and HMACs data.
        /// </summary>
        /// <param name="data">Plaintext as string.</param>
        /// <returns>Ciphertext as Base64 string.</returns>
        public string EncryptToBase64(string data)
        {
            return Convert.ToBase64String(EncryptAndHmac(Encoding.UTF8.GetBytes(data)));
        }

        /// <summary>
        /// Decrypts and authenticates a ciphertext.
        /// </summary>
        /// <param name="data">Ciphertext as Base64 string.</param>
        /// <returns>Plaintext as byte[].</returns>
        public byte[] DecryptBase64ToBytes(string data)
        {
            return DecryptAndAuthenticate(Convert.FromBase64String(data));
        }

        /// <summary>
        /// Decrypts and authenticates a ciphertext.
        /// </summary>
        /// <param name="data">Ciphertext as Base64 string.</param>
        /// <returns>Plaintext as UTF8 encoded string.</returns>
        public string DecryptBase64ToString(string data)
        {
            return Encoding.UTF8.GetString(DecryptAndAuthenticate(Convert.FromBase64String(data)));
        }

        /// <summary>
        /// Decrypts and authenticates a ciphertext.
        /// </summary>
        /// <param name="data">Ciphertext as byte[].</param>
        /// <returns>Plaintext as byte[].</returns>
        public byte[] DecryptToBytes(byte[] data)
        {
            return DecryptAndAuthenticate(data);
        }

        /// <summary>
        /// Returns the largest valid block size associated with the algorithm.
        /// </summary>
        /// <returns>The largest valid block size in bits.</returns>
        private int GetLargestValidBlockSize()
        {
            SymmetricAlgorithm s = new TSymmetricAlgorithm();
            var sizes = s.LegalBlockSizes;
            sizes.OrderBy(n => n.MaxSize);
            return sizes[0].MaxSize;
        }

        /// <summary>
        /// Returns the largest valid key size associated with the generic type parameter encryption algorithm.
        /// </summary>
        /// <returns>The largets valid key size in bits.</returns>
        private int GetLargestValidKeySize()
        {
            SymmetricAlgorithm s = new TSymmetricAlgorithm();
            var sizes = s.LegalKeySizes;
            sizes.OrderBy(n => n.MaxSize);
            return sizes[0].MaxSize;
        }

        /// <summary>
        /// Indicates whether the specified key bit size is allowed by the generic type parameter encryption algorithm.
        /// </summary>
        /// <param name="keyBitSize"></param>
        private bool IsValidKeySize(int keyBitSize)
        {
            SymmetricAlgorithm s = new TSymmetricAlgorithm();
            return s.ValidKeySize(keyBitSize);
        }

        /// <summary>
        /// Indicates whether the specified block size is allowed by the algorithm.
        /// </summary>
        /// <param name="blockBitSize"></param>
        /// <returns>A value indicating whether the input block size is allowed by the generic type parameter encryption algorithm.</returns>
        private bool IsValidBlockSize(int blockBitSize)
        {
            SymmetricAlgorithm s = new TSymmetricAlgorithm();
            return s.LegalBlockSizes.Contains(new KeySizes(blockBitSize, blockBitSize, 0));
        }

        /// <summary>
        /// Performs encryption only.
        /// </summary>
        /// <param name="data">The plaintext data.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>The ciphertext.</returns>
        private byte[] RawEncrypt(byte[] data, byte[] key)
        {
            byte[] ciphertext = null;

            using (var BlockCipher = new TSymmetricAlgorithm())
            {
                BlockCipher.KeySize = KeyBitSize;
                BlockCipher.BlockSize = BlockBitSize;
                BlockCipher.Key = key;
                BlockCipher.Mode = CipherMode.CBC;
                BlockCipher.Padding = PaddingMode.PKCS7;
                BlockCipher.GenerateIV();

                using (ICryptoTransform encryptor = BlockCipher.CreateEncryptor())

                using (MemoryStream memStrm = new MemoryStream())
                {
                    CryptoStream crptStrm = new CryptoStream(memStrm, encryptor, CryptoStreamMode.Write);

                    memStrm.Write(BlockCipher.IV, 0, BlockCipher.IV.Length);

                    crptStrm.Write(data, 0, data.Length);
                    crptStrm.FlushFinalBlock();
                    crptStrm.Close();
                    
                    BlockCipher.Clear();

                    ciphertext = memStrm.ToArray();
                }
            }

            return ciphertext;
        }

        /// <summary>
        /// Performs decryption only.
        /// </summary>
        /// <param name="data">The ciphertext.</param>
        /// <param name="key">The private key.</param>
        /// <returns>The plaintext.</returns>
        private byte[] RawDecrypt(byte[] data, byte[] key)
        {
            byte[] plaintext = null;

            using (var BlockCipher = new TSymmetricAlgorithm())
            {
                byte[] iv = new byte[ivByteSize];

                for (int i = 0; i < iv.Length; i++)
                    iv[i] = data[i];

                BlockCipher.Mode = CipherMode.CBC;
                BlockCipher.BlockSize = BlockBitSize;
                BlockCipher.Padding = PaddingMode.PKCS7;
                BlockCipher.KeySize = KeyBitSize;
                BlockCipher.Key = key;
                BlockCipher.IV = iv;

                using (ICryptoTransform decryptor = BlockCipher.CreateDecryptor())

                using (MemoryStream memStrm = new MemoryStream())
                {
                    CryptoStream crptStrm = new CryptoStream(memStrm, decryptor, CryptoStreamMode.Write);

                    crptStrm.Write(data, ivByteSize, data.Length - ivByteSize);
                    crptStrm.FlushFinalBlock();
                    crptStrm.Close();

                    BlockCipher.Clear();

                    plaintext = memStrm.ToArray();
                }
            }

            return plaintext;
        }

        /// <summary>
        /// Performs encryption and HMAC.
        /// </summary>
        /// <param name="plaintext"></param>
        /// <returns>A ciphertext.</returns>
        private byte[] EncryptAndHmac(byte[] plaintext)
        {
            if (isDisposing) throw new ObjectDisposedException("CryptionSlater");

            if (plaintext == null)
                throw new NullReferenceException("Plaintext cannot be null.");

            byte[] authSalt = GetSalt(SaltBitSize>>3);
            byte[] encSalt = GetSalt(SaltBitSize>>3);

            byte[] derivedAuthenticationKey=null;
            byte[] derivedEncryptionKey = null;

            TimeSpan encryptionStretchTime = new TimeSpan();

            if (AutoAdjustEncryptionKeyStretching)
            {
                int iterations = 0;
                TimedStretch(EncryptionKeyStretchTargetMS, EncryptionKey, encSalt, out iterations, out derivedEncryptionKey,out encryptionStretchTime);
                EncryptionKeyStretchIterations = iterations;
            }
            else if (EncryptionKeyStretchIterations > 0)
            {
                var start = DateTime.Now;
                derivedEncryptionKey = GetKeyFromPasswordAndSalt(EncryptionKey, encSalt, EncryptionKeyStretchIterations);
                var stop = DateTime.Now;
                encryptionStretchTime = stop - start;
            }
            else
            {
                derivedEncryptionKey = EncryptionKey;
            }

            LastEncryptionKeyStretchingTime = encryptionStretchTime;

            TimeSpan authenticationStretchTime = new TimeSpan();

            if (AutoAdjustAuthenticationKeyStretching)
            {
                int iterations = 0;       
                TimedStretch(AuthenticationKeyStretchTargetMS, AuthenticationKey, authSalt, out iterations, out derivedAuthenticationKey,out authenticationStretchTime);
                AuthenticationKeyStretchIterations = iterations;
            }
            else if (AuthenticationKeyStretchIterations > 0)
            {
                var start = DateTime.Now;
                derivedAuthenticationKey = GetKeyFromPasswordAndSalt(AuthenticationKey, authSalt, AuthenticationKeyStretchIterations);
                var stop = DateTime.Now;
                authenticationStretchTime = stop - start;
            }
            else
            {
                derivedAuthenticationKey = AuthenticationKey;
            }

            LastAuthenticationKeyStretchingTime = authenticationStretchTime;

            byte[] cipherText = new byte[0];
            cipherText = cipherText.Concat(BitConverter.GetBytes(EncryptionKeyStretchIterations)).ToArray();
            cipherText = cipherText.Concat(BitConverter.GetBytes(AuthenticationKeyStretchIterations)).ToArray();
            cipherText = cipherText.Concat(BitConverter.GetBytes(SaltBitSize)).ToArray();

            if (EncryptionKeyStretchIterations > 0)
            {
                cipherText = cipherText.Concat(encSalt).ToArray();
            }

            if(AuthenticationKeyStretchIterations > 0)
            {
                cipherText = cipherText.Concat(authSalt).ToArray();
            }

            cipherText = cipherText.Concat(RawEncrypt(plaintext, derivedEncryptionKey)).ToArray();
            cipherText = cipherText.Concat(GetHMAC(derivedAuthenticationKey, plaintext)).ToArray();

            return cipherText;
        }

        /// <summary
        /// Performs decryption and authentication.
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <returns>A plaintext value.</returns>
        private byte[] DecryptAndAuthenticate(byte[] ciphertext)
        {
            if (isDisposing) throw new ObjectDisposedException("CryptionSlater");

            if (ciphertext == null)
                throw new NullReferenceException("Ciphertext cannot be null.");

            int hmacByteSize = hmacBitSize >> 3;

            Int32 encryptionStretchIterations = BitConverter.ToInt32(ciphertext, 0);
            Int32 authenticationStretchIterations = BitConverter.ToInt32(ciphertext, 4);
            int saltSize = BitConverter.ToInt16(ciphertext, 8) >> 3;

            byte[] foundHmac = new byte[0];
            byte[] encSalt = new byte[0];
            byte[] authSalt = new byte[0];
            byte[] encryptedData = new byte[0];

            if (encryptionStretchIterations > 0 && authenticationStretchIterations > 0)
            {
                foundHmac = ciphertext.Skip(ciphertext.Length - hmacByteSize).ToArray();
                encSalt = ciphertext.Skip(10).ToArray().Take(saltSize).ToArray();
                authSalt = (ciphertext.Skip(saltSize + 10).ToArray()).Take(saltSize).ToArray();
                encryptedData = (ciphertext.Skip((saltSize * 2) + 10).ToArray()).Take(ciphertext.Length - ((saltSize * 2) + 10 + hmacByteSize)).ToArray();
            }
            else if(encryptionStretchIterations<1 && authenticationStretchIterations <1)
            {
                foundHmac = ciphertext.Skip(ciphertext.Length - hmacByteSize).ToArray();
                encryptedData = (ciphertext.Skip(10).Take(ciphertext.Length - (10 + hmacByteSize))).ToArray();
            }
            else if (encryptionStretchIterations > 0 && authenticationStretchIterations < 1)
            {
                foundHmac = ciphertext.Skip(ciphertext.Length - hmacByteSize).ToArray();
                encSalt = ciphertext.Skip(10).ToArray().Take(saltSize).ToArray();
                encryptedData = (ciphertext.Skip(saltSize + 10).ToArray()).Take(ciphertext.Length - (saltSize + 10 + hmacByteSize)).ToArray();
            }
            else if (encryptionStretchIterations < 1 && authenticationStretchIterations > 0)
            {
                foundHmac = ciphertext.Skip(ciphertext.Length - hmacByteSize).ToArray();
                authSalt = (ciphertext.Skip(saltSize + 10).ToArray()).Take(saltSize).ToArray();
                encryptedData = (ciphertext.Skip(saltSize + 10).ToArray()).Take(ciphertext.Length - (saltSize + 10 + hmacByteSize)).ToArray();
            }

            byte[] derivedEncryptionKey = (EncryptionKeyStretchIterations > 0) 
                ? GetKeyFromPasswordAndSalt(EncryptionKey, encSalt, encryptionStretchIterations) 
                : EncryptionKey;

            byte[] derivedAuthenticationKey = (AuthenticationKeyStretchIterations > 0) 
                ? GetKeyFromPasswordAndSalt(AuthenticationKey, authSalt, authenticationStretchIterations) 
                : AuthenticationKey;

            byte[] plaintext = RawDecrypt(encryptedData, derivedEncryptionKey);
            byte[] computedHmac = GetHMAC(derivedAuthenticationKey, plaintext);

            if (IsByteArrayMatch(foundHmac, computedHmac))
            {
                return plaintext;
            }
            else
            {
                throw new CryptographicException("HMAC does not authenticate.");
            }
        }

        /// <summary>
        /// Returns a cryptographically secure random salt.       
        /// </summary>
        /// <param name="saltByteSize">The size in bytes of byte[] salt that will be returned.</param>
        /// <returns>A random salt.</returns>
        private byte[] GetSalt(int saltByteSize)
        {
            byte[] salt = new byte[saltByteSize];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt); 
            }
            return salt;
        }

        /// <summary>
        /// Derives a key from the specified key, salt, and stretch iterations. Iterations of 1000 or greater are performed in 1000 iteration blocks (chained).
        /// </summary>
        /// <param name="key">The key to be stretched.</param>
        /// <param name="salt">The random salt.</param>
        /// <param name="iterations">The number of times Rfc2898DeriveBytes will run.</param>
        /// <returns>A derived key.</returns>
        private byte[] GetKeyFromPasswordAndSalt(byte[] key, byte[] salt, int iterations)
        {
            if (iterations > 1000)
            {
                int startIterations = iterations;

                for (int i = 0; i < iterations; )
                {
                    int iterationSegment = ((startIterations - 1000) >= 0) ? 1000 : startIterations;

                    using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(key, salt, iterationSegment))
                    {
                        key = rfc.GetBytes(KeyBitSize >> 3);
                    }

                    i += iterationSegment;
                }
            }
            else
            {
                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(key, salt, iterations))
                {
                    key = rfc.GetBytes(KeyBitSize >> 3);
                }
            }
            return key;
        }

        /// <summary>
        /// Sets the salt iterations and the stretched key according to the time in milliseconds that the stretching function should run.
        /// </summary>
        /// <param name="milliseconds">The milliseconds that the stretching function should run.</param>
        /// <param name="key">The key.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="stretchIterations">(OUT) The number of stretch iterations used to hit the target (ms) in the milliseconds parameter.</param>
        /// <param name="stretchedKey">(OUT) The stretched key.</param>
        /// <param name="time">(OUT) The time it took in milliseconds for the stretching function to complete.</param>
        private void TimedStretch(int milliseconds, byte[] key, byte[] salt, out int stretchIterations, out byte[] stretchedKey,out TimeSpan time)
        {
            int runTimeMs = 0;
            int runIterations = 0;

            var totalStart = DateTime.Now;

            while (runTimeMs < milliseconds)
            {
                var start = DateTime.Now;

                using (Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(key, salt, 1000))
                {
                    key = rfc.GetBytes(KeyBitSize >> 3);
                }

                var stop = DateTime.Now;

                runTimeMs += (stop - start).Milliseconds;

                runIterations += 1000;
            }

            var totalStop = DateTime.Now;

            stretchIterations = runIterations;
            stretchedKey = key;
            time = totalStop - totalStart;
        }

        /// <summary>
        /// Returns the HMAC of the plaintext.
        /// </summary>
        /// <param name="key">The authentication/HMAC key.</param>
        /// <param name="plainText">The message.</param>
        /// <returns>The hashed message authenication code.</returns>
        private byte[] GetHMAC(byte[] key, byte[] plainText)
        {
            using (var hmac = new THmac())
            {
                hmac.Key = key;
                return hmac.ComputeHash(plainText);
            }
        }

        /// <summary>
        /// Performs a byte-by-byte comparison on two byte arrays.
        /// </summary>
        /// <param name="a">Byte array A.</param>
        /// <param name="b">Byte array B.</param>
        /// <returns>Returns a bool value indicating whether the bytes in the input arrays are equal.</returns>
        private bool IsByteArrayMatch(byte[] a, byte[] b)
        {
            int mismatch = 0;

            for (int i = 0; i < a.Length; i++)
            {
                mismatch += a[i] == b[i] ? 0 : 1;
            }

            return mismatch == 0;
        }
    }
}
