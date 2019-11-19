'use strict';

module.exports = {
  authRedirectUri: 'URL FROM APP REGISTRATION -- CORRESPONDS TO APP CLIENT ID',

  retries: 2,

  retryExponentialBackoffFactor: 2,

  retryMinTimeoutInMiliseconds: 50,

  retryMaxTimeoutInMiliseconds: 1500,

  authVersion: 'ADAL, MSAL, OTHER',

  //   Leave this as is if your code is in a public repo (or delete it if you want).
  aadInstance: 'https://login.microsoftonline.com/', // Replace only if using AAD non-public instances.

  aadTenant: 'AZURE ACTIVE DIRECTORY TENANT GOES HERE',

  clientId: 'AZURE ACTIVE DIRECTORY APP REGISTRATION CLIENT ID HERE',

  instrumentationKey: 'APP INSIGHTS GOES HERE',

  useAppInsights: false
};
