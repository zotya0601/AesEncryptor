using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace AesEncrypt
{
    /// <summary>
    /// This class takes a passwword - provided by a user - and a standard AES key length (128 bit, 192 bit, 256 bit)
    /// Throws an error in case the key does not have proper length
    /// </summary>
    public class AesPasswordLocker
    {
        /// <summary>
        /// AesEncryptionManager object. Handles encryption and decryption
        /// </summary>
        private AesEncryptionManager _aesem { get; }
        /// <summary>
        /// Length of AES key
        /// </summary>
        private readonly int _keylen;
        /// <summary>
        /// Generated salt for the Rfc2898DeriveBytes method
        /// </summary>
        private readonly byte[] _salt;
        private int _keylenBytes => this._keylen / 8;
        /// <summary>
        /// List of valid AES key lengths
        /// </summary>
        private readonly int[] _stdaeskeylengths = { 128, 192, 256 };
        private readonly Rfc2898DeriveBytes _deriveBytes;

        public AesPasswordLocker(string pw, int keylen = 256)
        {
            // Check if the provided key length is standard
            if(!_stdaeskeylengths.Contains(keylen)) throw new Exception("AES key length can only be 128, 192 or 256");

            // Create new objects
            _aesem = new AesEncryptionManager();
            _keylen = keylen;
            // Generate safe random numbers, and fill up _salt with them
            _salt = new byte[_keylenBytes];
            RandomNumberGenerator.Create().GetNonZeroBytes(_salt);

            _deriveBytes = new Rfc2898DeriveBytes(pw, _salt);

            // Derive a key from the password and the generated salt, then take (keylength / 8) bytes
            _aesem.Aes.Key = _deriveBytes.GetBytes(_keylenBytes);
            _aesem.Aes.GenerateIV();

            _deriveBytes.Reset();
        }

        public byte[] Encrypt(string pw, object data)
        {
            var key = _deriveBytes.GetBytes(_keylenBytes);
            _deriveBytes.Reset();
            for (int i = 0; i < _aesem.Aes.Key.Length; i++)
                if (_aesem.Aes.Key[i] != key[i]) return null;
            return _aesem.Encrypt(data);
        }

        public byte[] Decrypt(string pw, byte[] data)
        {
            var key = _deriveBytes.GetBytes(_keylenBytes);
            _deriveBytes.Reset();
            for (int i = 0; i < _aesem.Aes.Key.Length; i++)
                if (_aesem.Aes.Key[i] != key[i]) return null;
            return _aesem.Decrypt(data);
        }

    }
}
