using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;

namespace Asymmetric_receiver
{
    public class RsaWithXmlKey 
    {
        public void AssignNewKey(string publicKeyPath, string privateKeyPath)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;

                if (File.Exists(privateKeyPath))
                {
                    File.Delete(privateKeyPath);
                }

                if (File.Exists(publicKeyPath))
                {
                    File.Delete(publicKeyPath);
                }

                var publicKeyfolder = Path.GetDirectoryName(publicKeyPath);
                var privateKeyfolder = Path.GetDirectoryName(privateKeyPath);

                if (!Directory.Exists(publicKeyfolder))
                {
                    Directory.CreateDirectory(publicKeyfolder);
                }

                if (!Directory.Exists(privateKeyfolder))
                {
                    Directory.CreateDirectory(privateKeyfolder);
                }
           
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
                File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));
            }
        }

        public byte[] DecryptData(string privateKeyPath, byte[] dataToEncrypt)
        {
            byte[] plain;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;                
                rsa.FromXmlString(File.ReadAllText(privateKeyPath));
                RSAParameters parameters = rsa.ExportParameters(true);
                plain = rsa.Decrypt(dataToEncrypt, false);
                
            }

            return plain;
        }
    }
}