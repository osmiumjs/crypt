const crypto = require('crypto');
const {Serialize, DataDecoder, DataEncoder, Serializer, Deserializer, tools} = require('osmium-serializer');

function pbkdf2(password, salt = 'superSalt', iterations = 1, keylen = 32, digest = 'sha512') {
	return new Promise(resolve =>
		crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, derivedKey) => resolve(err ? false : derivedKey)));
}

async function pbkdf2b66(password, salt = 'superSalt', iterations = 1, keylen = 32, digest = 'sha512') {
	return tools.base66Encode(await pbkdf2(password, salt, iterations, keylen, digest));
}

Object.assign(tools, {
	crypto,
	pbkdf2,
	pbkdf2b66,
	hash  : (what, mode = 'sha256', encoding = 'utf8', digest = 'hex') => crypto.createHash(mode).update(what, encoding).digest(digest),
	isHash: (what, type = 'sha256') => (new RegExp(`[0-9a-f]{${tools.hash('', type).length}}`, 'i')).test(what)
});

class Crypt {
	constructor(options) {
		this.options = Object.assign({
			keyMode  : 'sha512',
			keySize  : 256,
			keySalt  : 'TqX8FaxYXWG6qXNleRM10tusrHUvLYWM',
			cryptMode: 'aes-256-cbc',
			ivLength : 16,
			useCoder : true
		}, options);
		Object.assign(this.options, {
			version: 4
		});

		if (this.options.useCoder) {
			this.dataEncoder = Serialize.encoder;
			this.dataDecoder = Serialize.decoder;
			this.serializer = Serialize.serializer;
			this.deserializer = Serialize.deserializer;
		}
	}

	coderUse(val) {
		Serialize.use(val);
	}

	async genKey(passkey, id = false) {
		return await pbkdf2(`${id !== false ? id : ''}${passkey}`, this.options.keySalt, 1, this.options.keySize / 8, this.options.keyMode);
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
				processor.on('end', () => resolve(out));
				processor.write(data);
				processor.end();
			} catch (e) {
				reject(e);
			}
		});
	}

	async encrypt(key, data, id = false, userData = false, useDataCoder = true) {
		let iv = crypto.randomBytes(this.options.ivLength);
		key = typeof key === 'function' ? await key(userData) : key;

		data = this.options.useCoder && useDataCoder ? this.dataEncoder.auto(data) : data;
		userData = this.options.useCoder && useDataCoder ? this.dataEncoder.auto(userData) : userData;

		const cipher = crypto.createCipheriv(this.options.cryptMode, await this.genKey(key, id), iv);
		const payload = await this._process(cipher, data);

		const packet = {
			version: this.options.version,
			useDataCoder,
			id,
			userData,
			iv,
			payload
		};

		return this.serializer.serialize(packet);
	}

	async decrypt(key, data, returnExtended = false) {
		if (!Buffer.isBuffer(data)) return null;
		const packet = this.deserializer.deserialize(data, ['version', 'useDataCoder', 'id', 'userData', 'iv', 'payload']);

		let id, iv, userData, payload;

		try {
			key = typeof key === 'function' ? await key(packet.userData) : key;
			const decipher = crypto.createDecipheriv(this.options.cryptMode, await this.genKey(key, packet.id), packet.iv);
			payload = await this._process(decipher, packet.payload);

			payload = packet.useDataCoder ? this.dataDecoder.decode(payload) : payload;
			userData = packet.useDataCoder ? this.dataDecoder.decode(packet.userData) : packet.userData;
			id = packet.id;
			iv = packet.iv;
		} catch (e) {
			return null;
		}

		return returnExtended ? {id, iv, userData, payload} : payload;
	}
}

module.exports = {Crypt, Serialize, DataDecoder, DataEncoder, Serializer, Deserializer, tools};
