'use strict';

const prodConfig = require('config/prodConfig');
const devConfig = require('config/devConfig');
const config = process.env.REACT_APP_ENVIRONMENT === 'production' ? prodConfig : devConfig;

export default config;
