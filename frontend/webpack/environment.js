module.exports = {
  CONFIG_API_URL: process.env.hasOwnProperty('CONFIG_API_URL') ? process.env.CONFIG_API_URL : '/api',
  __VERSION__: process.env.hasOwnProperty('APP_VERSION') ? process.env.APP_VERSION : 'DEV',
  __DEBUG_INFO_ENABLED__: false,
};
