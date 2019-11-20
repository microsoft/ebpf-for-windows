

import { UserAgentApplication } from 'msal'

import * as authActions from 'actions/authActions'
import config from 'config'

const clientId = config.clientId

export const authVersion = 'msal'
const windowDoesntExistRejection = 'MSAL library cannot function in a headless broswer; the window object must exist'
const defaultScopes = [clientId]
const authority = config.aadInstance + config.aadTenant
const userAgentApplication = new UserAgentApplication(clientId, authority, null, { redirectUri: config.authRedirectUri, validateAuthority: true })

export const getAuthContext = () => {
  if (typeof window !== 'undefined' && !!window) {
    return window.msal
      ? window.msal
      : userAgentApplication
  }
  return msalServiceHeadlessBrowserMode
}

export const login = (dispatch) => {
  if (typeof window !== 'undefined' && !!window) {
    getAuthContext().loginPopup()
      .then(
        () => dispatch(authActions.userLoggedIn(getAuthContext().getUser())),
        err => dispatch(authActions.userLoginError(err))
      )
  } else {
    dispatch(authActions.userLoginError(windowDoesntExistRejection))
  }
}

export const logOut = (dispatch) => {
  getAuthContext().logOut()
  dispatch(authActions.userLoggedOut())
}

export const clearCache = () => {
  getAuthContext().clearCache()
}

export const isLoggedIn = () => {
  const context = getAuthContext()
  const user = context.getUser()
  return user
    ? !!(context.getCachedToken({ scopes: defaultScopes, authority }, user))
    : false
}

export const getUserAlias = (passedInUser) => {
  const user = passedInUser || getAuthContext().getUser()
  return (user && user.displayableId)
    ? extractAliasFromUserName(user.displayableId)
    : null
}

const extractAliasFromUserName = (userName) => {
  return userName.slice(0, userName.indexOf('@'))
}

export const getToken = (scopes) => getAuthContext()
  .acquireTokenSilent(scopes)

export const loginInProgress = () => getAuthContext()._loginInProgress

const failOnNoWindow = () => Promise.reject(windowDoesntExistRejection)

const msalServiceHeadlessBrowserMode = ({
  loginRedirect: () => { },
  loginPopup: failOnNoWindow,
  logout: () => { },
  acquireTokenSilent: failOnNoWindow,
  acquireTokenPopup: failOnNoWindow,
  acquireTokenRedirect: () => { },
  getUser: () => null
})

export default getAuthContext
