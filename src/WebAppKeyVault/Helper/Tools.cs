using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using System.Web.Configuration;

namespace WebAppKeyVault.Helper
{
    public static class Tools
    {
        public static X509Certificate2 FindCertificateByThumbprint(string findValue)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindByThumbprint,
                    findValue, false); // Don't validate certs, since the test root isn't installed.
                if (col == null || col.Count == 0)
                    return null;
                return col[0];
            }
            finally
            {
                store.Close();
            }
        }

        private static ClientAssertionCertificate _AssertionCert;
        public static ClientAssertionCertificate AssertionCert {
            get {
                if (_AssertionCert == null)
                {
                    var clientAssertionCertPfx = FindCertificateByThumbprint(WebConfigurationManager.AppSettings["thumbprint"]);
                    _AssertionCert = new ClientAssertionCertificate(WebConfigurationManager.AppSettings["clientid"], clientAssertionCertPfx);
                }
                return _AssertionCert;
            }
        }
        
        public static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, AssertionCert);
            return result.AccessToken;
        }
    }
}