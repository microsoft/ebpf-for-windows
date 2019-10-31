import React from 'react';
import { connect } from 'react-redux'

import logo from 'assets/logo.svg';
import 'styles/App.css'
import LoadingPage from 'components/LoadingPage'
import Greeting from 'components/Greeting'

export const App = ({ user }) => {
  return user ?
    (
      <div className="App">
        <header className="App-header">
          <img src={logo} className="App-logo" alt="logo" />
          <Greeting userAlias={user} />
        </header>
        <p className="App-intro">
          To get started, edit <code>src/App.js</code> and save to reload.
            </p>
        <div id="response"></div>
      </div>
    )
  :
  <LoadingPage />
}

export const mapStateToProps = (state) => ({
  user: state.auth.userAlias  
})

export default connect(mapStateToProps)(App)
