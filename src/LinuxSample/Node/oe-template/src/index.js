
import React from 'react';
import ReactDOM from 'react-dom';

import 'styles/index.css';
import AuthenticatedContainer from 'containers/AuthenticatedContainer';
import { store } from './configureStore';
import registerServiceWorker from 'registerServiceWorker';

ReactDOM.render(
  <AuthenticatedContainer store={store} />,
  document.getElementById('root')
);

registerServiceWorker();
