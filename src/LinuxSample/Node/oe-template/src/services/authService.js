'use strict';
import * as msalService from 'services/msalService';
import * as adalService from 'services/adalService';
import * as authActions from 'actions/authActions';
import config from 'config';
import appInsights from 'appInsights';

const authVersion = config.authVersion;

const testAuthVersion = 'TEST';
const testLoginAction = ({ type: 'TEST_LOGIN' });
const testLogOutAction = ({ type: 'TEST_LOGOUT' });
const testAlias = 'Test@test.test';
const testToken = 'testToken';

export const login = (dispatch) => {
  appInsights.trackEvent('Login');
  dispatch(authActions.loginInProgress());
  switch (authVersion) {
    case testAuthVersion:
      dispatch(testLoginAction);
      break;
    case msalService.authVersion:
      dispatch(msalService.login);
      break;
    default:
      dispatch(adalService.login);
  }
};

export const logOut = (dispatch) => {
  appInsights.trackEvent('Logout');
  switch (authVersion) {
    case testAuthVersion:
      dispatch(testLogOutAction);
      break;
    case msalService.authVersion:
      dispatch(msalService.logOut);
      break;
    default:
      dispatch(adalService.logOut);
  }
};

export const clearCache = () => {
  switch (authVersion) {
    case msalService.authVersion:
      msalService.clearCache();
      break;
    case testAuthVersion:
      break;
    default:
      adalService.clearCache();
  }
};

export const isLoggedIn = () => {
  switch (authVersion) {
    case testAuthVersion:
      return false;
    case msalService.authVersion:
      return msalService.isLoggedIn();
    default:
      return adalService.isLoggedIn();
  }
};

export const getUserAlias = (user) => {
  switch (authVersion) {
    case testAuthVersion:
      return testAlias;
    case msalService.authVersion:
      return msalService.getUserAlias(user);
    default:
      return adalService.getUserAlias(user);
  }
};

export const getToken = (scopes) => {
  switch (authVersion) {
    case testAuthVersion:
      return testToken;
    case msalService.authVersion:
      return msalService.getToken(scopes);
    default:
      return adalService.getToken();
  }
};

export const loginInProgress = () => {
  switch (authVersion) {
    case testAuthVersion:
      return false;
    case msalService.authVersion:
      return msalService.loginInProgress();
    default:
      return adalService.loginInProgress();
  }
};
