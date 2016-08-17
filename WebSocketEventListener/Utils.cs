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
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using vtortola.WebSockets;

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
            return PathWithName(GetIssuer() + ".crt");
        }

        /// <summary>
        /// Returns filename with full path that point to folder where app executed
        /// </summary>
        /// <param name="filename"></param>
        /// <returns></returns>
        public string PathWithName(string filename)
        {
            return Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + "\\" + filename;
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
        /// Returns certificate password. If it's not provided default password will be used. Default password is empty string
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
                value = "";
            }
            return value;
        }

        /// <summary>
        /// Gets certificate. If no certificates provided it will be generated and saved under execution path
        /// </summary>
        /// <returns></returns>
        public X509Certificate2 GetCert()
        {
            X509Certificate2 x509CA = null;
            var path = GetCertPath();
            var fInfo = new FileInfo(path);
            if (fInfo.Exists)
            {
                x509CA = new X509Certificate2();
                var data = File.ReadAllBytes(fInfo.FullName);
                x509CA.Import(data, GetCertPassword(), X509KeyStorageFlags.Exportable);
            }
            else
            {
                x509CA = GenerateCACertificate("CN=" + GetIssuer());
            }
            var issuerKey = TransformRSAPrivateKey(x509CA.PrivateKey);
            
            var cert = GenerateSelfSignedCertificate("CN=" + Environment.MachineName, x509CA.Issuer, issuerKey, GetSanNames());

            return cert;
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
            SaveToPFX(issuerKeyPair, x509, GetIssuer());

            // generate crt file
            //var fileInfo = new FileInfo(GetPublicCertPath());
            //if (!fileInfo.Exists)
            //{
            //    ExportToPEM(x509);
            //}

            return x509;
        }

        public static AsymmetricKeyParameter TransformRSAPrivateKey(AsymmetricAlgorithm privateKey)
        {
            RSACryptoServiceProvider prov = privateKey as RSACryptoServiceProvider;
            RSAParameters parameters = prov.ExportParameters(true);

            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent),
                new BigInteger(1, parameters.D),
                new BigInteger(1, parameters.P),
                new BigInteger(1, parameters.Q),
                new BigInteger(1, parameters.DP),
                new BigInteger(1, parameters.DQ),
                new BigInteger(1, parameters.InverseQ));
        }

        public List<string> GetSanNames()
        {
            var ipAdress = GetLocalIPAddress();
            var result = new List<string>();
            result.Add(Environment.MachineName);
            result.Add("localhost");
            if (!String.IsNullOrEmpty(ipAdress)) result.Add(ipAdress);
            return result;
        }

        public string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return string.Empty;
        }

        public X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, List<string> SAN, int keyStrength = 2048)
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
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(20);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);


            var sans = new List<GeneralName>();
            foreach (var n in SAN)
            {
                var san = new GeneralName(GeneralName.DnsName, n);
                sans.Add(san);
            }
            var names = new GeneralNames(sans.ToArray());
            var subjectAlternativeNames = new Asn1Encodable[]
            {
                names
            };

            var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);
            certificateGenerator.AddExtension(
            X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerPrivKey, random);

            // correcponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            // merge into X509Certificate2
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);

            // SaveToPFX(issuerKeyPair, x509, Environment.MachineName);

            return x509;
        }

        /// <summary>
        /// Base on certificate and key pairs generate pfx file
        /// </summary>
        /// <param name="issuerKeyPair"></param>
        /// <param name="certificate"></param>
        /// <param name="x509"></param>
        /// <returns></returns>
        private X509Certificate2 SaveToPFX(AsymmetricCipherKeyPair issuerKeyPair, X509Certificate2 x509, string fileName)
        {
            // add private key to x509
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(issuerKeyPair.Private);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
               rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);
            

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
            File.WriteAllBytes(PathWithName(fileName + ".pfx"), x509.Export(X509ContentType.Pkcs12, GetCertPassword()));
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

        public void ProcessMessage(WebSocket ws)
        {
            while (ws.IsConnected)
            {
                Thread.Sleep(1000);

                try
                {
                    var d = DateTime.Now.ToLongTimeString();
                    Console.WriteLine(d);
                    ws.WriteStringAsync(d, CancellationToken.None);
                }
                catch (Exception E)
                {

                }
            }

            //if (!ws.IsConnected)
            //{
            //    ws.Close();
            //}
        }
    }
}
