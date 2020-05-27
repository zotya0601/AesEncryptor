using System;
using System.Security.Cryptography;
using System.IO;

namespace AesEncrypt
{
    public class AesEncryptionUtils
    {
        /// <summary>
        /// Encrypts provided byte array with AES128
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns>Encrypted byte array</returns>
        public byte[] AesEncrypt(byte[] data, Aes aes)
        {
            byte[] res;
            using(MemoryStream ms = new MemoryStream())
            {
                using(CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                {
                    using(BinaryWriter bw = new BinaryWriter(cs))
                    {
                        bw.Write(data);
                    }
                }
                res = ms.ToArray();
            }
            return res;
        }

        /// <summary>
        /// Encrypts provided byte array with AES128, and also provides an AES implemetation 
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public byte[] AesEncrypt(byte[] data, out Aes aes)
        {
            aes = Aes.Create();
            return this.AesEncrypt(data, aes);
        }

        /// <summary>
        /// Encrypts provided object with AES128
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public byte[] AesEncrypt(object data, Aes aes)
        {
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            byte[] arr;
            using(MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, data);
                arr = ms.ToArray();
            }
            return this.AesEncrypt(arr, aes);
        }

        /// <summary>
        /// Encrypts provided byte array with AES128, and also provides an AES implemetation 
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public byte[] AesEncrypt(object data, out Aes aes)
        {
            aes = Aes.Create();
            return this.AesEncrypt(data, aes);
        }

        /// <summary>
        /// Encrypts provided byte array with AES128, and sends back the data as a Base64 encoded string
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public string AesEncryptToBase64(byte[] data, Aes aes) => Convert.ToBase64String(this.AesEncrypt(data, aes));

        /// <summary>
        /// Encrypts provided byte array with AES128, and also provides an AES implemetation. 
        /// Sends back encrypted data as Base64 encoded string
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public string AesEncryptToBase64(byte[] data, out Aes aes) => Convert.ToBase64String(this.AesEncrypt(data, out aes));

        /// <summary>
        /// Encrypts provided byte array with AES128, and sends back the data as a Base64 encoded string
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public string AesEncryptToBase64(object data, Aes aes) => Convert.ToBase64String(this.AesEncrypt(data, aes));

        /// <summary>
        /// Encrypts provided byte array with AES128, and also provides an AES implemetation. 
        /// Sends back encrypted data as Base64 encoded string
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public string AesEncryptToBase64(object data, out Aes aes) => Convert.ToBase64String(this.AesEncrypt(data, out aes));

        /// <summary>
        /// Decrypts data using the provided AES key
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public byte[] AesDecrypt(byte[] encryptedData, Aes aes)
        {
            byte[] res = null;

            using(MemoryStream ms = new MemoryStream(encryptedData))
            {
                using(CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
                {
                    using(BinaryReader br = new BinaryReader(cs))
                    {
                        res = br.ReadBytes(encryptedData.Length);
                    }
                }
            }
            return res;
        }

        /// <summary>
        /// Decrypts data using the provided AES key
        /// </summary>
        /// <param name="base64">BASE64 representation of data</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public byte[] AesDecrypt(string base64, Aes aes)
        {
            byte[] data = Convert.FromBase64String(base64);
            return this.AesDecrypt(data, aes);
        }

        private T DeserializeDecryptedByteArray<T>(byte[] b)
        {
            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter bf = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using(MemoryStream ms = new MemoryStream(b))
            {
                object o = bf.Deserialize(ms);
                if (o is T) return (T)o;
                else return default;
            }
        }

        /// <summary>
        /// Decrypts data using the provided AES key and returns it as the specified type
        /// </summary>
        /// <param name="data">BASE64 representation of data</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public T AesDecrypt<T>(byte[] data, Aes aes) => this.DeserializeDecryptedByteArray<T>(this.AesDecrypt(data, aes));
        /// <summary>
        /// Decrypts data using the provided AES key and returns it as the specified type
        /// </summary>
        /// <param name="base64">BASE64 representation of data</param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public T AesDecrypt<T>(string base64, Aes aes) => this.DeserializeDecryptedByteArray<T>(this.AesEncrypt(base64, aes));
    }
}
