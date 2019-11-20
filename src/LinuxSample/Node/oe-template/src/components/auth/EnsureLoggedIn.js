

import React from 'react';
import { connect } from 'react-redux';

import Login from 'components/auth/Login';
import LoginError from 'components/auth/LoginError';

export const EnsureLoggedInContainer = ({ error, isLoggedIn, children }) => {
  if (error) {
    return <LoginError />;
  }
  if (isLoggedIn) {
    return children;
  }
  return <Login />;
}

export const mapStateToProps = (state) => {
  return {
    isLoggedIn: state.auth.isLoggedIn,
    error: state.auth.error
  };
}

export default connect(mapStateToProps)(EnsureLoggedInContainer);