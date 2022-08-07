const webpack = require('webpack');
const path = require('path');
const WebpackNotifierPlugin = require('webpack-notifier');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const ESLintPlugin = require('eslint-webpack-plugin');

const environment = require('./environment');

module.exports = async (config, options, targetOptions) => {

  config.cache = {
    // 1. Set cache type to filesystem
    type: 'filesystem',
    cacheDirectory: path.resolve(__dirname, '../target/webpack'),
    buildDependencies: {
      // 2. Add your config as buildDependency to get cache invalidation on config change
      config: [
        __filename,
        path.resolve(__dirname, 'webpack.custom.js'),
        path.resolve(__dirname, '../angular.json'),
        path.resolve(__dirname, '../tsconfig.app.json'),
        path.resolve(__dirname, '../tsconfig.json'),
      ],
    },
  };

  config.output.publicPath = options.deployUrl || '/';// process.env.PUBLIC_PATH;
  config.output.crossOriginLoading = 'anonymous';

  // PLUGINS
  if (config.mode === 'development') {
    config.plugins.push(
      new ESLintPlugin({
        extensions: ['js', 'ts'],
      }),
      new WebpackNotifierPlugin({
        title: 'OpenVPN admin UI',
      })
    );
  }

  // configuring proxy for back end service
  // const isTls = Boolean(config.devServer && config.devServer.https);
  if (config.devServer) {
    config.devServer.allowedHosts = 'all';
  }

  const patterns = [
    // assets to pack
  ];

  if (patterns.length > 0) {
    config.plugins.push(new CopyWebpackPlugin({ patterns }));
  }

  config.plugins.push(new webpack.DefinePlugin({
    // APP_VERSION is passed as an environment variable from the Gradle / Maven build tasks.
    __VERSION__: JSON.stringify(environment.__VERSION__),
    __DEBUG_INFO_ENABLED__: false, // environment.__DEBUG_INFO_ENABLED__ || config.mode === 'development',
    CONFIG_API_URL: JSON.stringify(environment.CONFIG_API_URL),
  }));

  return config;
};
