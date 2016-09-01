using System;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Azure.KeyVault;
using System.Configuration;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace KeyVaultPlugin
{
    public class KeyVaultPlugin : IPlugin
	{
		public void Execute(IServiceProvider serviceProvider)
		{
			IPluginExecutionContext context = (IPluginExecutionContext)
					serviceProvider.GetService(typeof(IPluginExecutionContext));

			var organizationServiceFactory = (IOrganizationServiceFactory)
					serviceProvider.GetService(typeof (IOrganizationServiceFactory));

			AssertNull(context, "context");
			AssertNull(organizationServiceFactory, "organizationServiceFactory");

			var organizationService = organizationServiceFactory.CreateOrganizationService(context.UserId);

            AssertNull(organizationService, "organizationService");

            QueryExpression query = new QueryExpression("account");
            query.ColumnSet.AllColumns = true;

            var accounts = organizationService.RetrieveMultiple(query);

            AssertNull(accounts, "accounts");
            AssertNull(accounts.Entities, "accounts.Entities");

            // get the pfx file from KeyVault
            var kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(GetToken));
            var key = kv.GetSecretAsync(@"https://sudhakarkeyvault.vault.azure.net:443/secrets/TestPfxFile/d375341c177b4e34ac4c6eb020f87f45").Result;

            NetworkCredential creds = new NetworkCredential("", key.Value);
            byte[] data = Convert.FromBase64String(creds.Password);
            X509Certificate2 cert = new X509Certificate2(data, "reset123", X509KeyStorageFlags.MachineKeySet |
                                     X509KeyStorageFlags.PersistKeySet |
                                     X509KeyStorageFlags.Exportable);

            //Encrypting the text using the public key            
            string encyrptedString = string.Empty;
            byte[] bytesData = Encoding.UTF8.GetBytes("Sample Text Input");
            byte[] bytesEncrypted = null;
            using (RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PublicKey.Key)
            {
                bytesEncrypted = csp.Encrypt(bytesData, false);
                encyrptedString = Convert.ToBase64String(bytesEncrypted);
            }

            // decrypting the text using private key
            string decryptedString = string.Empty;
            using (RSACryptoServiceProvider csp = (RSACryptoServiceProvider)cert.PrivateKey)
            {
                byte[] bytesDecrypted = csp.Decrypt(bytesEncrypted, false);
                decryptedString = Encoding.UTF8.GetString(bytesDecrypted);
            }
        }

        //the method that will be provided to the KeyVaultClient
        private async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential("78a191c0-a24d-4508-a908-38709541c594",
                                                               "SFrnl8PhQESeEmn2HF+74BHENM16CguGONGLjtA1gEc=");
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        private void AssertNull(object obj, string msg)
		{
			if (obj == null)
				throw new  InvalidPluginExecutionException(msg);
		}
	}
}
