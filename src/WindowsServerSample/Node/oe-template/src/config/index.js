
const config = process.env.REACT_APP_ENVIRONMENT === 'production' ? require('config/prodConfig') : require('config/devConfig')

export default config
