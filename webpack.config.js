const webpack = require('webpack');
const path = require('path');

module.exports = {
	mode       : 'production',
	entry      : {
		main: './src/index.ts',
	},
	output     : {
		path         : path.resolve(__dirname, './dist'),
		filename     : 'index.min.js',
		libraryTarget: 'commonjs'
	},
	resolve    : {
		extensions: ['.ts', '.js'],
		fallback  : {
			buffer: require.resolve('buffer'),
			crypto: require.resolve('crypto-browserify'),
			stream: require.resolve('stream-browserify')
		}
	},
	module     : {
		rules: [
			{
				test  : /\.ts$/,
				loader: 'ts-loader'
			}
		]
	},
	plugins    : [
		new webpack.ProvidePlugin({
			Buffer: ['buffer', 'Buffer', 'crypt'],
		}),
	],
	performance: {
		maxEntrypointSize: 700000,
		maxAssetSize     : 700000
	},
};
