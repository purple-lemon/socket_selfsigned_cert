using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WebSocketEventListenerSample
{
    public class Utils
    {
        private const string CertKey = "HostCertPath";
        private const string CertKeyPassword = "CertPassword";
        private const string IssuerKey = "HostName";


        /// <summary>
        /// Returns path to configured certificate. If no path configured it will return path to default file {Machine Name}.pfx
        /// </summary>
        /// <returns></returns>
        public string GetIssuer()
        {
            string value = string.Empty;
            if (ConfigurationManager.AppSettings.AllKeys.Contains(IssuerKey) && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[IssuerKey]))
            {
                value = ConfigurationManager.AppSettings[IssuerKey];
            }
            else
            {
                value = Environment.MachineName;
            }
            return value;
        }

        /// <summary>
        /// Get public cert path. Needed when certificate should be generated
        /// </summary>
        /// <returns></returns>
        private string GetPublicCertPath()
        {
            return Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + "\\" + GetIssuer() + ".crt";
        }

        /// <summary>
        /// Returns path to configured certificate. If no path configured it will return path to default file {Machine Name}.pfx
        /// </summary>
        /// <returns></returns>
        public string GetCertPath()
        {
            string path = string.Empty;
            if (ConfigurationManager.AppSettings.AllKeys.Contains(CertKey) && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[CertKey]))
            {
                path = ConfigurationManager.AppSettings[CertKey];
            } else
            {
                path = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + "\\" + GetIssuer() + ".pfx";
            }
            return path;
        }

        /// <summary>
        /// Returns certificate password. If it's not provided default password will be used
        /// </summary>
        /// <returns></returns>
        public string GetCertPassword()
        {
            string value = string.Empty;
            if (ConfigurationManager.AppSettings.AllKeys.Contains(CertKeyPassword))
            {
                value = ConfigurationManager.AppSettings[CertKeyPassword];
            }
            else
            {
                value = "verint1!";
            }
            return value;
        }

        /// <summary>
        /// Gets certificate. If no certificates provided it will be generated and saved under execution path
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 GetCert()
        {
            X509Certificate2 x509 = null;
            var path = GetCertPath();
            var fInfo = new FileInfo(path);
            if (fInfo.Exists)
            {
                x509 = new X509Certificate2();
                var data = ReadFile(path);
                x509.Import(data, GetCertPassword(), X509KeyStorageFlags.DefaultKeySet);
            } else
            {
                x509 = GenerateCACertificate("CN=" + GetIssuer());
            }
            return x509;
        }

        /// <summary>
        /// Read File as binary data
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public byte[] ReadFile(string fileName)
        {
            var f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }

        /// <summary>
        /// Generates CRT and PFX files
        /// </summary>
        /// <param name="subjectName">should be same as domain where socket are used</param>
        /// <param name="keyStrength"></param>
        /// <returns></returns>
        public X509Certificate2 GenerateCACertificate(string subjectName, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);
            var x509 = new X509Certificate2(certificate.GetEncoded());
            // Add CA certificate to Root store

            // Genereate PFX
            GeneratePfx(issuerKeyPair, certificate, x509);

            // generate crt file
            var fileInfo = new FileInfo(GetPublicCertPath());
            if (!fileInfo.Exists)
            {
                ExportToPEM(x509);
            }

            return x509;
        }

        /// <summary>
        /// Base on certificate and key pairs generate pfx file
        /// </summary>
        /// <param name="issuerKeyPair"></param>
        /// <param name="certificate"></param>
        /// <param name="x509"></param>
        /// <returns></returns>
        private X509Certificate2 GeneratePfx(AsymmetricCipherKeyPair issuerKeyPair, Org.BouncyCastle.X509.X509Certificate certificate, X509Certificate2 x509)
        {
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            X509CertificateEntry certEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(certificate.SubjectDN.ToString(), certEntry); // use DN as the Alias.
            AsymmetricKeyEntry keyEntry = new AsymmetricKeyEntry(issuerKeyPair.Private);
            store.SetKeyEntry(certificate.SubjectDN.ToString() + "_key", keyEntry, new X509CertificateEntry[] { certEntry }); // 

            using (var filestream = new FileStream(GetCertPath(), FileMode.Create, FileAccess.ReadWrite))
            {
                store.Save(filestream, GetCertPassword().ToCharArray(), new SecureRandom());
            }

            // add private key to x509
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(issuerKeyPair.Private);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
               rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
            return x509;
        }

        /// <summary>
        /// Generate CRT file that should be trusted by services that want to use ssl sockets
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        public string ExportToPEM(X509Certificate2 cert)
        {

            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");


            File.WriteAllText(GetPublicCertPath(), builder.ToString());
            return builder.ToString();
        }
    }
}
