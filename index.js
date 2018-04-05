const crypto = require('crypto');
const msgpack = require('notepack.io');
const crc32 = require('crc').crc32;
const zlib = require('zlib');

function makeWBuffer(int, name, length) {
	const buf = Buffer.alloc(length);
	buf[name](int);
	return buf;
}

const tools = {
	crypto     : crypto,
	hash       : (what, mode = 'sha256', encoding = 'utf8', digest = 'hex') =>
		crypto.createHash(mode).update(what, encoding).digest(digest),
	isHash     : (what, type = 'sha256') =>
		(new RegExp(`[0-9a-f]{${tools.hash('', type).length}}`, 'i')).test(what),
	int8ToBuf  : (int) => makeWBuffer(int, 'writeInt8', 1),
	int8UToBuf : (int) => makeWBuffer(int, 'writeUInt8', 1),
	int16ToBuf : (int, be) => makeWBuffer(int, `writeInt16${be ? 'BE' : 'LE'}`, 2),
	int16UToBuf: (int, be) => makeWBuffer(int, `writeUInt16${be ? 'BE' : 'LE'}`, 2),
	int32ToBuf : (int, be) => makeWBuffer(int, `writeInt32${be ? 'BE' : 'LE'}`, 4),
	int32UToBuf: (int, be) => makeWBuffer(int, `writeUInt32${be ? 'BE' : 'LE'}`, 4),
	intToBuf   : (int, len = 7, be) => {
		const buf = Buffer.alloc(len);
		buf[`writeInt${be ? 'BE' : 'LE'}`](int, 0, len);
		return buf;
	},
	bufToInt8  : (buf) => buf.readInt8(),
	bufToInt8U : (buf) => buf.readUInt8(),
	bufToInt16 : (buf, be) => buf[`readInt16${be ? 'BE' : 'LE'}`](),
	bufToInt16U: (buf, be) => buf[`readUInt16${be ? 'BE' : 'LE'}`](),
	bufToInt32 : (buf, be) => buf[`readInt32${be ? 'BE' : 'LE'}`](),
	bufToInt32U: (buf, be) => buf[`readUInt32${be ? 'BE' : 'LE'}`](),
	bufToInt   : (buf, len = 7, be) => buf[`readInt${be ? 'BE' : 'LE'}`](0, len),
	pad        : (str, z = 8) => str.length < z ? tools.pad('0' + str, z) : str,
	bufTobinStr: (buf) => tools.pad(tools.bufToInt8U(buf).toString(2)),
	binStrToBuf: (str) => tools.int8UToBuf(parseInt(str, 2))
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
			version        : 1,
			headerMinLength: 4
		});
	}

	deflate(data) {
		return new Promise((resolve => zlib.deflate(data, (err, data) => resolve(data))));
	}

	inflate(data) {
		return new Promise((resolve => zlib.inflate(data, (err, data) => resolve(data))));
	}

	constructHeader(flags, crc32) {
		if (flags.length > 6) return false;
		flags = Object.assign(Array(6).fill(0), flags);
		flags = flags.concat([crc32 === false ? 0 : 1, 0]);
		const crc32buf = crc32 !== false ? tools.int32UToBuf(crc32) : Buffer.from('');

		const header = Buffer.concat([tools.binStrToBuf(flags.join('')), crc32buf]);
		return Buffer.concat([tools.int8UToBuf(this.options.version), tools.int8UToBuf(header.length), header]);
	}

	async serialize(what) {
		let encoded = this.options.useMsgpack ? msgpack.encode(what) : Buffer.from(JSON.stringify(what));
		const useZlib = this.options.useZlib && (this.options.useZlibMinLen <= encoded.length);

		if (useZlib) encoded = await this.deflate(encoded);

		const header = this.constructHeader(
			[this.options.useMsgpack ? 1 : 0, useZlib ? 1 : 0],
			this.options.useCrc32 ? crc32(encoded) : false
		);

		return Buffer.concat([header, encoded]);
	}

	parsePacket(msg) {
		const version = tools.bufToInt8(msg.slice(0, 1));
		if (version !== this.options.version || msg.length < 2) return false;

		const headerLen = tools.bufToInt8U(msg.slice(1, 2));
		if (msg.length < headerLen + 2) return false;

		const headerBuf = msg.slice(2, headerLen + 2);

		const flags = tools.bufTobinStr(headerBuf.slice(0, 1));
		const useCrc = !!parseInt(flags[6]);
		const crc32 = useCrc ? tools.bufToInt32U(headerBuf.slice(1, 5)) : false;
		const payload = msg.slice(headerLen + 2);

		return {
			flags,
			crc32,
			payload
		};
	}

	async deserialize(what) {
		if (!Buffer.isBuffer(what)) return null;
		const parsed = this.parsePacket(what);
		if (!parsed) return null;

		let encoded = parsed.payload;

		if (parsed.crc32 !== false) {
			if (crc32(encoded) !== parsed.crc32) return null;
		}
		const useMsgpack = !!parseInt(parsed.flags[0]);
		const useZlib = !!parseInt(parsed.flags[1]);

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
			useMsgpack       : true,
			serializerOptions: {}
		}, options);
		Object.assign(this.options, {
			version: 1
		});

		if (this.options.useSerializer) this.serializer = new Serializer(this.options.serializerOptions);
	}

	genKey(passkey, id = false) {
		return tools.hash(`${this.options.keySalt}${id !== false ? id : ''}${passkey}`, this.options.keyMode);
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

	constructHeader(id, userData) {
		if (userData !== false) {
			userData = this.options.useMsgpack ? msgpack.encode(userData) : Buffer.from(JSON.stringify(userData));
		} else {
			userData = Buffer.from('');
		}

		const flags = tools.binStrToBuf(Object.assign(Array(8).fill(0), [
			this.options.useMsgpack ? 1 : 0,
			this.options.useSerializer ? 1 : 0,
			id !== false ? 1 : 0,
			userData.length !== 0 ? 1 : 0
		]).join(''));

		let info = flags;
		if (id !== false) {
			id = '' + id;
			info = Buffer.concat([info, tools.int8UToBuf(id.length), Buffer.from(id)]);
		}

		let header = Buffer.concat([
			tools.int8UToBuf(this.options.version),
			tools.int8UToBuf(info.length),
			info
		]);

		if (userData.length !== 0) header = Buffer.concat([header, tools.int32UToBuf(userData.length), userData]);

		return header;
	}

	async encrypt(key, data, id = false, userData = false, useSerializer = true) {
		const header = this.constructHeader(id, userData);
		if (this.options.useSerializer && useSerializer) data = await this.serializer.serialize(data);
		key = typeof key === 'function' ? await key(userData) : key;

		const cipher = crypto.createCipher(this.options.cryptMode, this.genKey(key, id));
		const encrypted = await this._process(cipher, data);

		return Buffer.concat([header, encrypted]);
	}

	parsePacket(packet) {
		const version = tools.bufToInt8U(packet.slice(0, 1));
		if (version !== this.options.version) return false;

		const infoLength = tools.bufToInt8U(packet.slice(1, 2));
		const info = packet.slice(2, infoLength + 2);

		const flags = tools.bufTobinStr(info.slice(0, 1));
		const useMsgpack = !!parseInt(flags[0]);
		const useSerializer = !!parseInt(flags[1]);
		const hasId = !!parseInt(flags[2]);
		const hasUserData = !!parseInt(flags[3]);

		let id = false;
		let userData = false;
		let userDataLen = 0;

		if (hasId) {
			const idLen = tools.bufToInt8U(info.slice(1, 2));
			id = info.slice(2, idLen + 2).toString();
		}

		if (hasUserData) {
			userDataLen = tools.bufToInt32U(packet.slice(2 + info.length, 2 + info.length + 4));
			const userDataRaw = packet.slice(2 + info.length + 4, 2 + info.length + 4 + userDataLen);
			userData = useMsgpack ? msgpack.decode(userDataRaw) : JSON.stringify(userDataRaw.toString());
		}
		const payload = packet.slice(2 + info.length + (hasUserData ? 4 : 0) + userDataLen);

		return {payload, id, userData, useSerializer};
	}

	async decrypt(key, data, returnExtended = false) {
		if (!Buffer.isBuffer(data)) return null;
		let payload, id, userData;

		try {
			const packet = this.parsePacket(data);
			key = typeof key === 'function' ? await key(packet.userData) : key;

			const decipher = crypto.createDecipher(this.options.cryptMode, this.genKey(key, packet.id));
			payload = await this._process(decipher, packet.payload);

			id = packet.id;
			userData = packet.userData;
			payload = (packet.useSerializer) ? await this.serializer.deserialize(payload) : payload;
		} catch (e) {
			return null;
		}

		return returnExtended ? {id, userData, payload} : payload;
	}
}

module.exports = Object.assign({Crypt, Serializer}, tools);