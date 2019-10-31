import { combineReducers } from 'redux'

import authReducer from 'reducers/authReducer'
import monitoringReducer from 'reducers/monitorReducer'

const defaultState = {
  auth: {
    isLoggedIn: null,
    loginInProgress: null,
    signInAutomatically: true,
    userAlias: null
  },
  monitoring: {
    monitoringInProgress: true
  }
}

const rootReducer = combineReducers({
  defaultState,
  auth: authReducer,
  monitoring: monitoringReducer
})

export default rootReducer
