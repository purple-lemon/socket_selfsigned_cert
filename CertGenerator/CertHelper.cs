using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertGenerator
{
	public class Logger
	{
		public void info(string msg)
		{
			Console.WriteLine(msg);
		}

		public void debug(string msg)
		{
			Console.WriteLine(msg);
		}

		public void error(string msg)
		{
			Console.WriteLine(msg);
		}
	}

	public class GeneralUtils
	{
		public const string LOG_PREFIX = "ScreenCaptureProxy: ";
		public static string AddServicePrefix(string msg)
		{
			return string.Concat(LOG_PREFIX, msg);
		}

		/// <summary>
		/// Check that port number between 0 and 65535
		/// </summary>
		/// <param name="portNumber"></param>
		/// <returns></returns>
		public static bool IsValidPort(int portNumber)
		{
			return portNumber > 0 && portNumber <= 65535;
		}

		/// <summary>
		/// Returns filename with full path that points to folder where app executed
		/// </summary>
		/// <param name="filename"></param>
		/// <returns></returns>
		public virtual string PathWithName(string filename)
		{
			return Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + "\\" + filename;
		}
	}

	public class CertUtils
	{
		private const string CertKey = "HostCertPath";
		private const string CertKeyPassword = "CertPassword";
		private const string CAIssuer = "CAIssuer";
		private const string CertExpireYears = "CertExpireYears";
		const string signatureAlgorithm = "SHA256WithRSA";
		const string GenerateChildCert = "GenerateChildCert";

		public static Logger log = new Logger();

		/// <summary>
		/// Return certificate expiration years value from config. If no value exist in config, default value with 10 used
		/// </summary>
		/// <returns></returns>
		public virtual int GetCertExpireTerm()
		{
			int value = 100;
			if (ConfigurationManager.AppSettings.AllKeys.Contains(CertExpireYears) && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[CertExpireYears]))
			{
				if (!int.TryParse(ConfigurationManager.AppSettings[CertExpireYears], out value))
				{
					value = 100;
				}
			}
			log.info("Certificate expiration years value to use: " + value);
			return value;
		}

		/// <summary>
		/// Returns if certificate for Web socket configured
		/// </summary>
		public virtual bool GenerateChildCertificate
		{
			get
			{
				var value = false;
				if (ConfigurationManager.AppSettings.AllKeys.Contains(GenerateChildCert) && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[GenerateChildCert]))
				{
					value = ConfigurationManager.AppSettings[GenerateChildCert].Equals("true", StringComparison.InvariantCultureIgnoreCase);
					log.info("GenerateChildCertificate property was found in config and it's value: " + value);
				}
				else
				{
					log.info("GenerateChildCertificate property was NOT found in config and default value will be used. Default value: false");
				}

				return value;
			}
		}

		/// <summary>
		/// Returns configured gost name. If no host name provided or value empty, MachineName will be used
		/// </summary>
		/// <returns></returns>
		public virtual string GetCAIssuer()
		{
			string value = string.Empty;
			if (ConfigurationManager.AppSettings.AllKeys.Contains(CAIssuer) && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[CAIssuer]))
			{
				value = ConfigurationManager.AppSettings[CAIssuer];
			}
			else
			{
				value = "sslsocket.verint.com";
			}
			log.info("Following CA Issuer will be used for generating CA certificate " + value);
			return value;
		}

		/// <summary>
		/// Returns path to configured certificate. If no path configured it will return path to default file {Machine Name}.pfx
		/// </summary>
		/// <returns></returns>
		public virtual string GetCertPath()
		{
			string path = string.Empty;
			if (ConfigurationManager.AppSettings.AllKeys.Contains(CertKey) && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[CertKey]))
			{
				path = ConfigurationManager.AppSettings[CertKey];
				// if it's relative path, make sure it's from app execution folder
				if (!System.IO.Path.IsPathRooted(path))
				{

					string codeBase = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
					UriBuilder uri = new UriBuilder(codeBase);
					string assamblyPath = Uri.UnescapeDataString(uri.Path);
					return Path.Combine(Path.GetDirectoryName(assamblyPath), path);
				}
			}
			else
			{
				path = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory) + "\\" + GetCAIssuer() + ".pfx";
			}
			log.debug("Path to CA certificate that will be used " + path);
			return path;
		}

		/// <summary>
		/// Returns certificate password. If it's not provided default password will be used. Default password is empty string
		/// </summary>
		/// <returns></returns>
		public virtual string GetCertPassword()
		{
			string value = string.Empty;
			if (ConfigurationManager.AppSettings.AllKeys.Contains(CertKeyPassword))
			{
				value = ConfigurationManager.AppSettings[CertKeyPassword];
			}
			else
			{
				value = string.Empty;
			}

			return value;
		}

		/// <summary>
		/// Gets certificate. If no certificates provided it will be generated and saved under execution path
		/// </summary>
		/// <returns></returns>
		public virtual X509Certificate2 GetCert()
		{
			X509Certificate2 x509CA = null;
			var path = GetCertPath();
			log.info(GeneralUtils.AddServicePrefix("Looking for cert file in following dir: " + path));
			var fInfo = new FileInfo(path);

			if (fInfo.Exists)
			{
				log.info(GeneralUtils.AddServicePrefix("x509 cert file found. Service will use it to start socket or create self signed cert"));
				x509CA = new X509Certificate2();
				var data = File.ReadAllBytes(fInfo.FullName);
				x509CA.Import(data, GetCertPassword(), X509KeyStorageFlags.Exportable);
				log.info(GeneralUtils.AddServicePrefix("x509 cert file successfully read"));
			}
			else
			{
				log.info(GeneralUtils.AddServicePrefix("x509 cert file not found. Service will generate it"));
				x509CA = GenerateCACertificate("CN=" + GetCAIssuer());
			}

			if (!GenerateChildCertificate)
			{
				log.info("Child certificate for wss host will NOT be generated. Configured certificate will be used for hosting");
				return x509CA;
			}
			else
			{
				log.info("Child certificate for wss host will be generated");
				AsymmetricKeyParameter issuerKey = null;
				try
				{
					issuerKey = ExtractSigningKey(fInfo.FullName);
					if (issuerKey == null) throw new Exception("extracted private key is null");
				}
				catch (Exception e)
				{
					log.error("Extracting private key from .pfx file error");
					throw;
				}
				// this part is commented since 
				//var privateKey = x509CA.PrivateKey;
				//var issuerKey = TransformRSAPrivateKey(privateKey);
				var cert = GenerateSelfSignedCertificate("CN=" + Environment.MachineName, x509CA.Issuer, issuerKey);

				return cert;
			}
		}

		/// <summary>
		/// In windows 7 work with X509Certificate2 class properties like PrivateKey and PublicKey leads to start random UPD port listening. 
		/// This method gets private key with help of Bouncy castle. It helps prevent UDP port starting
		/// </summary>
		/// <param name="filePath"></param>
		/// <returns></returns>
		public AsymmetricKeyParameter ExtractSigningKey(string filePath)
		{
			var pkcs = new Pkcs12Store(File.Open(filePath, FileMode.Open), GetCertPassword().ToCharArray());
			var aliases = pkcs.Aliases;
			var name = string.Empty;
			foreach (var a in aliases)
			{
				name = a.ToString();
				break;
			}
			if (String.IsNullOrEmpty(name)) throw new Exception("Can not retrieve certificate alias name from PFX file");

			// get certificate 
			var certEntry = pkcs.GetCertificate(name.ToString());
			if (certEntry == null) throw new Exception("Can not get certificate from pfx file by alias name");
			// get certificate private key
			var issuerKey = pkcs.GetKey(name.ToString()).Key;
			return issuerKey;
		}

		/// <summary>
		/// Transformas AsymmetricAlgorithm to AsymmetricKeyParameter needed to sign certificates. Works with RSA only
		/// </summary>
		/// <param name="privateKey"></param>
		/// <returns></returns>
		public virtual AsymmetricKeyParameter TransformRSAPrivateKey(AsymmetricAlgorithm privateKey)
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

		/// <summary>
		/// Generates CA certificate
		/// </summary>
		/// <param name="subjectName">should be same as domain where socket are used</param>
		/// <param name="keyStrength"></param>
		/// <returns></returns>
		public X509Certificate2 GenerateCACertificate(string subjectName, int keyStrength = 2048, bool savePfx = true)
		{
			log.info(GeneralUtils.AddServicePrefix("Generating CA certificate process started"));
			log.debug(GeneralUtils.AddServicePrefix("Certificate will be IssuedBy/To: " + GetCAIssuer()));
			// Generating Random Numbers
			var randomGenerator = new CryptoApiRandomGenerator();
			var random = new SecureRandom(randomGenerator);

			// The Certificate Generator
			var certificateGenerator = new X509V3CertificateGenerator();

			// Serial Number
			var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
			log.debug("CA cert serial: " + serialNumber);
			certificateGenerator.SetSerialNumber(serialNumber);

			// Signature Algorithm
			certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

			// Issuer and Subject Name
			var subjectDN = new X509Name(subjectName);
			var issuerDN = subjectDN;
			certificateGenerator.SetIssuerDN(issuerDN);
			certificateGenerator.SetSubjectDN(subjectDN);

			log.info(string.Format("CA cert issued by: {0} and issued to: {1}", subjectName, subjectName));

			// Valid For
			var notBefore = DateTime.UtcNow.Date;
			var notAfter = notBefore.AddYears(GetCertExpireTerm());
			log.debug(string.Format("CA cert valid utc dates: {0} - {1}", notBefore.ToShortDateString(), notAfter.ToShortDateString()));
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
			if (savePfx)
			{
				log.info("generated pfx will be saved to file system");
				SaveToPFX(issuerKeyPair, x509, GetCAIssuer());
			}

			log.info(GeneralUtils.AddServicePrefix("Generating certificate process completed successfully"));
			return x509;
		}

		/// <summary>
		/// Generate certificate that signed by CA certificate with private key
		/// </summary>
		/// <param name="subjectName"></param>
		/// <param name="issuerName"></param>
		/// <param name="issuerPrivKey"></param>
		/// <param name="SAN">Subject alternate names</param>
		/// <param name="keyStrength"></param>
		/// <returns></returns>
		public X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
		{
			// Generating Random Numbers
			var randomGenerator = new CryptoApiRandomGenerator();
			var random = new SecureRandom(randomGenerator);

			// The Certificate Generator
			var certificateGenerator = new X509V3CertificateGenerator();

			// Serial Number
			var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
			log.debug("self signed cert serial: " + serialNumber);
			certificateGenerator.SetSerialNumber(serialNumber);

			// Signature Algorithm
			certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

			// Issuer and Subject Name
			var subjectDN = new X509Name(subjectName);
			var issuerDN = new X509Name(issuerName);
			certificateGenerator.SetIssuerDN(issuerDN);
			certificateGenerator.SetSubjectDN(subjectDN);
			log.info(string.Format("self signed cert issued by: {0} and issued to: {1}", issuerName, subjectName));

			// Valid For
			var notBefore = DateTime.UtcNow.Date;
			var notAfter = notBefore.AddYears(GetCertExpireTerm());
			log.info(string.Format("self signed cert valid utc dates: {0} - {1}", notBefore.ToShortDateString(), notAfter.ToShortDateString()));

			certificateGenerator.SetNotBefore(notBefore);
			certificateGenerator.SetNotAfter(notAfter);

			// Subject Public Key
			AsymmetricCipherKeyPair subjectKeyPair;
			var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
			var keyPairGenerator = new RsaKeyPairGenerator();
			keyPairGenerator.Init(keyGenerationParameters);
			subjectKeyPair = keyPairGenerator.GenerateKeyPair();

			certificateGenerator.SetPublicKey(subjectKeyPair.Public);


			var subjectAlternativeNames = new List<Asn1Encodable>();
			subjectAlternativeNames.Add(new GeneralName(GeneralName.DnsName, Environment.MachineName));
			subjectAlternativeNames.AddRange(GetIpNames());

			var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames.ToArray());
			certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, subjectAlternativeNamesExtension);

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

			SaveToPFX(issuerKeyPair, x509, "MyCert");

			return x509;
		}

		/// <summary>
		/// Save certificate as pfx file with private key
		/// </summary>
		/// <param name="issuerKeyPair"></param>
		/// <param name="x509"></param>
		/// <param name="fileName"></param>
		/// <returns></returns>
		private X509Certificate2 SaveToPFX(AsymmetricCipherKeyPair issuerKeyPair, X509Certificate2 x509, string fileName)
		{
			// add private key to x509
			PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(issuerKeyPair.Private);
			var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
			// It should thow if seq.cunt != 9 because folowing info should be stored in RSA key. 
			// following page has more info: https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
			// version           Version,
			// modulus INTEGER,  --n
			// publicExponent INTEGER,  --e
			// privateExponent INTEGER,  --d
			// prime1 INTEGER,  --p
			// prime2 INTEGER,  --q
			// exponent1 INTEGER,  --d mod(p - 1)
			// exponent2 INTEGER,  --d mod(q - 1)
			// coefficient INTEGER,  --(inverse of q) mod p
			// otherPrimeInfos OtherPrimeInfos OPTIONAL
			if (seq.Count != 9)
				throw new PemException("malformed sequence in RSA private key");

			var rsa = new RsaPrivateKeyStructure(seq);
			RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
			   rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);


			x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
			var utils = new GeneralUtils();
			if (!fileName.EndsWith(".pfx")) fileName += ".pfx";
			File.WriteAllBytes(utils.PathWithName(fileName), x509.Export(X509ContentType.Pkcs12, GetCertPassword()));
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


			File.WriteAllText(GetCertPath(), builder.ToString());
			return builder.ToString();
		}

		/// <summary>
		/// Get general names with local ip addresses
		/// </summary>
		/// <returns></returns>
		public List<GeneralName> GetIpNames()
		{
			var result = new List<GeneralName>();
			foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
			{
				if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
				{
					foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
					{
						if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
						{
							result.Add(new GeneralName(GeneralName.IPAddress, ip.Address.ToString()));
						}
					}
				}
			}
			return result;
		}
	}
}
