
import React, { Component } from 'react';
import { Provider } from 'react-redux';

import EnsureLoggedIn from 'components/auth/EnsureLoggedIn';
import App from 'containers/App';

class AuthenticatedContainer extends Component {
  render() {
    return (
      <Provider store={this.props.store}>
        <div>
          <EnsureLoggedIn>
            <App store={this.props.store} />
          </EnsureLoggedIn>
        </div>
      </Provider>
    );
  }
}

export default AuthenticatedContainer;
