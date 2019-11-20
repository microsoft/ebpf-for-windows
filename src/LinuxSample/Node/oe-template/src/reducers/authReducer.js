

import { USER_LOGGED_IN, USER_LOGGED_OUT, USER_LOGIN_ERROR, LOGIN_IN_PROGRESS } from 'actions/authActions.js';
import * as authService from 'services/authService';

const getDefaultState = () => {
  const defaultState = {
    isLoggedIn: authService.isLoggedIn(),
    loginInProgress: authService.loginInProgress(),
    signInAutomatically: true,
    userAlias: authService.getUserAlias()
  };
  return defaultState;
}

const authReducer = (state = getDefaultState(), action) => {
  switch (action.type) {
    case LOGIN_IN_PROGRESS:
      return {
        ...state,
        loginInProgress: true,
        error: null
      };
    case USER_LOGGED_IN:
      return {
        ...state,
        isLoggedIn: true,
        error: null,
        loginInProgress: false,
        signInAutomatically: true,
        userAlias: authService.getUserAlias(action.user)
      };
    case USER_LOGGED_OUT:
      return {
        ...state,
        isLoggedIn: false,
        error: null,
        loginInProgress: false,
        signInAutomatically: false,
        userAlias: null
      };
    case USER_LOGIN_ERROR:
      return {
        ...state,
        isLoggedIn: false,
        error: action.error,
        loginInProgress: false,
        userAlias: null
      };
    default:
      return state;
  }
}

export default authReducer;
