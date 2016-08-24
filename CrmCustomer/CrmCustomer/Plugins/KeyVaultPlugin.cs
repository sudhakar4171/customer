using System;
using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;


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

            // call to CRM Web service
			var accounts = organizationService.RetrieveMultiple(query);
			AssertNull(accounts, "accounts");
			AssertNull(accounts.Entities, "accounts.Entities");

            // make any calls to Azure KeyVault

			
		}

		private void AssertNull(object obj, string msg)
		{
			if (obj == null)
				throw new  InvalidPluginExecutionException(msg);
		}
	}
}
