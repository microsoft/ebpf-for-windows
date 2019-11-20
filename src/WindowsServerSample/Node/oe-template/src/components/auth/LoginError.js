
import React from 'react';
import { connect } from 'react-redux';

export const LoginError = ({ error }) => {
  return (
    <div>
      There was a problem logging you in! {error}
    </div>
  );
};

export function mapStateToProps(state) {
  return {
    error: state.auth.error
  };
};

export default connect(mapStateToProps)(LoginError);
