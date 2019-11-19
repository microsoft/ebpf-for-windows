'use strict';

const baseConfig = require('config/baseConfig');

const config = Object.assign({}, baseConfig, {
  clientId: process.env.REACT_APP_CLIENT_ID,
  aadTenant: process.env.REACT_APP_TENANT,
  instrumentationKey: process.env.REACT_APP_APP_INSIGHTS_KEY,
  authVersion: process.env.REACT_APP_AUTH,
  authRedirectUri: process.env.REACT_APP_REDIRECT_URI
});

module.exports = config;
