using System.Security.Cryptography;

namespace AesEncrypt
{
    public class AesEncryptionManager
    {
        private AesEncryptionUtils _em;
        public Aes Aes { get; }

        public AesEncryptionManager()
        {
            _em = new AesEncryptionUtils();
            Aes = Aes.Create();
        }

        public byte[] Encrypt(object data)
        {
            if (data is byte[]) return _em.AesEncrypt(data as byte[], this.Aes);
            else return _em.AesEncrypt(data, this.Aes);
        }

        public byte[] Decrypt(byte[] data) => _em.AesDecrypt(data, this.Aes);
        public byte[] Decrypt(string base64) => _em.AesDecrypt(base64, this.Aes);
        public T Decrypt<T>(byte[] data) => _em.AesDecrypt<T>(data, this.Aes);
        public T Decrypt<T>(string base64) => _em.AesDecrypt<T>(base64, this.Aes);
    }
}
