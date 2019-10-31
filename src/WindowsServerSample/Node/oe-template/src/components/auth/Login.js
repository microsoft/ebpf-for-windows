import React from 'react'
import { connect } from 'react-redux'

import { login } from 'services/authService'

export class Login extends React.Component {
  componentDidMount() {
    // exported separately for testing
    LoginComponentDidMount(this.props)
  }

  render() {
    const { dispatch } = this.props
    return (
      <button id='SignIn' onClick={() => dispatch(login)}>Sign In</button>
    )
  }
}

export const LoginComponentDidMount = ({
  isLoggedIn,
  loginInProgress,
  signInAutomatically,
  dispatch
}) => {
  if (!isLoggedIn && !loginInProgress && signInAutomatically) {
    dispatch(login)
  }
}

export const mapStateToProps = (state) => {
  return {
    ...state.auth
  }
}

export default connect(mapStateToProps)(Login)
