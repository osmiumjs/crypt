const crypto = require('crypto');
const msgpack = require('notepack.io');
const crc32 = require('crc').crc32;
const zlib = require('zlib');

const cryptTools = {
	crypto: crypto,
	hash  : (what, mode = 'sha256', encoding = 'utf8', digest = 'hex') =>
		crypto.createHash(mode).update(what, encoding).digest(digest),
	isHash: (what, type = 'sha256') =>
		(new RegExp(`[0-9a-f]{${cryptTools.hash('', type).length}}`, 'i')).test(what)
};

class Serializer {
	constructor(options) {
		this.options = Object.assign({
			useMsgpack   : true,
			useCrc32     : true,
			useZlib      : true,
			useZlibMinLen: 128
		}, options);

		Object.assign(this.options, {
			serializeVersion: 1,
			headerMinLength : 4
		});
	}

	deflate(data) {
		return new Promise((resolve => zlib.deflate(data, (err, data) => resolve(data))));
	}

	inflate(data) {
		return new Promise((resolve => zlib.inflate(data, (err, data) => resolve(data))));
	}

	async serialize(what) {
		let encoded = this.options.useMsgpack ? msgpack.encode(what) : Buffer.from(JSON.stringify(what));
		const useZlib = this.options.useZlib && (this.options.useZlibMinLen >= encoded.length);

		if (useZlib) encoded = await this.deflate(encoded);

		const crcBuf = Buffer.from(this.options.useCrc32 ? crc32(encoded).toString(16) : '', 'hex');

		let header = [];
		header[0] = String.fromCharCode(this.options.serializeVersion);
		header[1] = this.options.useMsgpack ? 'm' : 'j';
		header[2] = String.fromCharCode(crcBuf.length);
		header[3] = useZlib ? 'z' : 'n';

		const headerBuf = Buffer.from(header.join(''));
		const headerLength = Buffer.from(String.fromCharCode(headerBuf.length));
		if (headerLength.length !== 1) return false;

		return Buffer.concat([headerLength, headerBuf, crcBuf, encoded]);
	}

	async deserialize(what) {
		if (!Buffer.isBuffer(what)) return 1;
		const headerLength = what.toString('utf8', 0, 1).charCodeAt();
		const header = what.toString('utf8', 1, headerLength + 1).split('');
		if (header.length < this.options.headerMinLength) return 2;

		const serializeVersion = header[0].charCodeAt();
		const useMsgpack = header[1] === 'm';
		const crcLength = header[2].charCodeAt();
		const useZlib = header[3] === 'z';

		if (serializeVersion !== this.options.serializeVersion) return 3;

		let encoded = what.slice(1 + headerLength + crcLength);

		if (crcLength > 0) {
			const msgCrc = what.toString('hex', 1 + headerLength, 1 + headerLength + crcLength);
			if (crc32(encoded).toString(16) !== msgCrc) return 4;
		}

		if (useZlib) encoded = await this.inflate(encoded);

		return useMsgpack ? msgpack.decode(encoded) : JSON.parse(encoded.toString());
	}
}

class Crypt {
	constructor(options) {
		this.options = Object.assign({
			keyMode          : 'sha512',
			keySalt          : 'tuMF9r47Tp444f',
			cryptMode        : 'aes-256-cbc',
			useSerializer    : true,
			serializerOptions: {}
		}, options);
		Object.assign(this.options, {
			version: 1
		});

		if (this.options.useSerializer) this.serializer = new Serializer(this.options.serializerOptions);
	}

	genKey(passkey, id = '') {
		return cryptTools.hash(`${this.options.keySalt}${id}${passkey}`, this.options.keyMode);
	}

	_process(processor, data) {
		return new Promise((resolve, reject) => {
			try {
				let out = Buffer.from('');

				processor.on('readable', () => {
					const data = processor.read();
					if (!Buffer.isBuffer(data)) return;
					out = Buffer.concat([out, data]);
				});
				processor.on('end', () => {
					resolve(out);
				});

				processor.write(data);
				processor.end();
			} catch (e) {
				reject(e);
			}
		});
	}

	async encrypt(key, data, id = '', useSerializer = true) {
		id = '' + id;
		if (this.options.useSerializer && useSerializer) data = await this.serializer.serialize(data, this.options.serializerOptions);
		const cipher = crypto.createCipher(this.options.cryptMode, this.genKey(key, id));
		data = await this._process(cipher, data);

		const idBuffer = Buffer.from(id);

		let header = [];
		header[0] = String.fromCharCode(this.options.version);
		header[1] = String.fromCharCode(idBuffer.length);
		header[2] = String.fromCharCode(0); //@todo: for cryptMode flag
		header[3] = String.fromCharCode(0); //@todo: for keyMode flag

		if (header.length >= 128 || id.length >= 128) return false;
		const headerBuffer = Buffer.from(header.join(''));
		const headerLength = Buffer.from(String.fromCharCode(header.length));

		return Buffer.concat([headerLength, headerBuffer, idBuffer, data]);
	}

	async decrypt(key, data, useSerializer = true) {
		if (!Buffer.isBuffer(data)) return null;
		try {
			const headerLength = data.toString('utf8', 0, 1).charCodeAt();
			let header = data.toString('utf8', 1, headerLength + 1).split('');
			if (header.length !== headerLength) return null;
			if (header[0].charCodeAt() !== this.options.version) return null;
			const idLength = header[1].charCodeAt();
			const id = data.slice(1 + headerLength, 1 + headerLength + idLength);
			data = data.slice(1 + headerLength + idLength);

			const decipher = crypto.createDecipher(this.options.cryptMode, this.genKey(key, id));
			data = await this._process(decipher, data);
		} catch (e) {
			return null;
		}
		return (this.options.useSerializer && useSerializer) ? await this.serializer.deserialize(data, this.options.serializerOptions) : data;
	}
}

module.exports = Object.assign({Crypt, Serializer}, cryptTools);