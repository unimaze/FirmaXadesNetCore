using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Threading;

namespace FirmaXadesNetCore.Compatibility
{
	internal static class Net462CryptoConfig
	{
#if NET462
		private static int _initialized; // 0 = false, 1 = true

		public static void EnsureRegistered()
		{
			if (Interlocked.Exchange(ref _initialized, 1) == 1) return;

			// Digests
			CryptoConfig.AddAlgorithm(typeof(SHA256CryptoServiceProvider), "http://www.w3.org/2001/04/xmlenc#sha256");
			CryptoConfig.AddAlgorithm(typeof(SHA384CryptoServiceProvider), "http://www.w3.org/2001/04/xmldsig-more#sha384"); // if you use sha384
			CryptoConfig.AddAlgorithm(typeof(SHA512CryptoServiceProvider), "http://www.w3.org/2001/04/xmlenc#sha512");

			// Signature descriptions (these classes are already in the repo under Microsoft.Xades)
			CryptoConfig.AddAlgorithm(typeof(Microsoft.Xades.RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
			CryptoConfig.AddAlgorithm(typeof(Microsoft.Xades.RSAPKCS1SHA512SignatureDescription), 				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
		}
#endif
	}
}
