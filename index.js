const crypto = require('crypto');
const msgpack = require('notepack.io');
const crc32 = require('crc').crc32;
const zlib = require('zlib');
const BaseX = require('base-x');

const BASE_ALPHABETS = {
	BASE16: '0123456789abcdef',
	BASE32: '0123456789ABCDEFGHJKMNPQRSTVWXYZ',
	BASE36: '0123456789abcdefghijklmnopqrstuvwxyz',
	BASE58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
	BASE62: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
	BASE64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
	BASE66: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~'
};

function makeWBuffer(int, name, length) {
	const buf = Buffer.alloc(length);
	buf[name](int);
	return buf;
}

function pbkdf2(password, salt = 'superSalt', iterations = 1, keylen = 32, digest = 'sha512') {
	return new Promise(resolve =>
		crypto.pbkdf2(password, salt, iterations, keylen, digest, (err, derivedKey) =>
			resolve(err ? false : derivedKey)
		));
}

async function pbkdf2b66(password, salt = 'superSalt', iterations = 1, keylen = 32, digest = 'sha512') {
	return tools.base66Encode(await pbkdf2(password, salt, iterations, keylen, digest));
}

function baseXEncode(what, base) {return BaseX(base).encode(Buffer.isBuffer(what) ? what : Buffer.from(what));}

function baseXDecode(what, base, asBuffer = false) {return BaseX(base).decode(what)[asBuffer ? 'asBuffer' : 'toString']();}

const tools = {
	BASE_ALPHABETS,
	BaseX,
	crypto,
	pbkdf2,
	pbkdf2b66,
	base16Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE16),
	base16Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE16, asBuffer),
	base32Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE32),
	base32Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE32, asBuffer),
	base36Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE36),
	base36Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE36, asBuffer),
	base58Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE58),
	base58Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE58, asBuffer),
	base62Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE62),
	base62Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE62, asBuffer),
	base64Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE64),
	base64Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE64, asBuffer),
	base66Encode: (what) => baseXEncode(what, BASE_ALPHABETS.BASE66),
	base66Decode: (what, asBuffer = false) => baseXDecode(what, BASE_ALPHABETS.BASE66, asBuffer),
	hash        : (what, mode = 'sha256', encoding = 'utf8', digest = 'hex') =>
		crypto.createHash(mode).update(what, encoding).digest(digest),
	isHash      : (what, type = 'sha256') =>
		(new RegExp(`[0-9a-f]{${tools.hash('', type).length}}`, 'i')).test(what),
	int8ToBuf   : (int) => makeWBuffer(int, 'writeInt8', 1),
	int8UToBuf  : (int) => makeWBuffer(int, 'writeUInt8', 1),
	int16ToBuf  : (int, be) => makeWBuffer(int, `writeInt16${be ? 'BE' : 'LE'}`, 2),
	int16UToBuf : (int, be) => makeWBuffer(int, `writeUInt16${be ? 'BE' : 'LE'}`, 2),
	int32ToBuf  : (int, be) => makeWBuffer(int, `writeInt32${be ? 'BE' : 'LE'}`, 4),
	int32UToBuf : (int, be) => makeWBuffer(int, `writeUInt32${be ? 'BE' : 'LE'}`, 4),
	intToBuf    : (int, len = 7, be) => {
		const buf = Buffer.alloc(len);
		buf[`writeInt${be ? 'BE' : 'LE'}`](int, 0, len);
		return buf;
	},
	bufToInt8   : (buf) => buf.readInt8(0),
	bufToInt8U  : (buf) => buf.readUInt8(0),
	bufToInt16  : (buf, be) => buf[`readInt16${be ? 'BE' : 'LE'}`](0),
	bufToInt16U : (buf, be) => buf[`readUInt16${be ? 'BE' : 'LE'}`](0),
	bufToInt32  : (buf, be) => buf[`readInt32${be ? 'BE' : 'LE'}`](0),
	bufToInt32U : (buf, be) => buf[`readUInt32${be ? 'BE' : 'LE'}`](0),
	bufToInt    : (buf, len = 7, be) => buf[`readInt${be ? 'BE' : 'LE'}`](0, len),
	pad         : (str, z = 8) => str.length < z ? tools.pad('0' + str, z) : str,
	bufTobinStr : (buf) => tools.pad(tools.bufToInt8U(buf).toString(2)),
	binStrToBuf : (str) => tools.int8UToBuf(parseInt(str, 2))
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
			version        : 2,
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
		let encoded = this.options.useMsgpack ? Buffer.from(msgpack.encode(what)) : Buffer.from(JSON.stringify(what));
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

class PacketExtracor {
	constructor(packet) {
		this.packet = packet;
		this.position = 0;
	}

	getBuf() {
		const dataLength = tools.bufToInt32U(this.packet.slice(this.position, this.position + 4));
		this.position += 4;
		const data = this.packet.slice(this.position, this.position + dataLength);
		this.position += dataLength;
		return data;
	}

	getBufFin() {
		return this.packet.slice(this.position);
	}

	getFlags(fields) {
		const flags = tools.bufTobinStr(this.packet.slice(this.position, this.position + 1));
		this.position++;

		let out = {};
		fields.forEach((field, idx) => out[field] = parseInt(flags[idx]));
		return out;
	}

	getInt8U() {
		this.position++;
		return tools.bufToInt8U(this.packet.slice(this.position - 1, this.position));
	}
}

class PacketConstructor {
	constructor() {
		this.packet = Buffer.from([]);
	}

	add(what) {
		what = Buffer.from(what);
		this.packet = Buffer.concat([this.packet, what]);
	}

	addFlags(flags) {
		this.add(tools.binStrToBuf(Object.assign(Array(8).fill(0), flags).join('')));
	}

	addBuf(buf) {
		buf = Buffer.from(buf);
		this.add(tools.int32UToBuf(buf.length));
		this.add(buf);
	}

	addPacket(packet) {
		this.add(packet.make(true));
	}

	addInt8U(int) {
		this.add(tools.int8UToBuf(int));
	}

	make(withLen = true) {
		return withLen ? Buffer.concat([tools.int32UToBuf(this.packet.length), this.packet]) : this.packet;
	}
}

class Crypt {
	constructor(options) {
		this.options = Object.assign({
			keyMode          : 'sha512',
			keySize          : 256,
			keySalt          : 'TUXwgjuGR9aPhB',
			cryptMode        : 'aes-256-cbc',
			ivLength         : 16,
			useSerializer    : true,
			useMsgpack       : true,
			serializerOptions: {}
		}, options);
		Object.assign(this.options, {
			version: 3
		});

		if (this.options.useSerializer) this.serializer = new Serializer(this.options.serializerOptions);
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

	constructHeader(iv, id = false, userData = {}) {
		userData = userData === false
		           ? Buffer.from('')
		           : this.options.useMsgpack ? msgpack.encode(userData) : Buffer.from(JSON.stringify(userData));

		let info = new PacketConstructor();
		info.addFlags([
			this.options.useMsgpack ? 1 : 0,
			this.options.useSerializer ? 1 : 0,
			id !== false ? 1 : 0,
			userData.length !== 0 ? 1 : 0
		]);
		info.addBuf(iv);
		if (id !== false) info.addBuf(Buffer.from('' + id));
		if (userData.length !== 0) info.addBuf(userData);

		let header = new PacketConstructor();
		header.addInt8U(this.options.version);
		header.addPacket(info);

		return header.make(false);
	}

	async encrypt(key, data, id = false, userData = false, useSerializer = true) {
		if (this.options.useSerializer && useSerializer) data = await this.serializer.serialize(data);
		key = typeof key === 'function' ? await key(userData) : key;
		let iv = crypto.randomBytes(this.options.ivLength);
		const header = this.constructHeader(iv, id, userData);
		const cipher = crypto.createCipheriv(this.options.cryptMode, await this.genKey(key, id), iv);
		const encrypted = await this._process(cipher, data);

		return Buffer.concat([header, encrypted]);
	}

	parsePacket(packetRaw) {
		let packet = new PacketExtracor(packetRaw);
		const version = packet.getInt8U();
		if (version !== this.options.version) return false;

		const info = new PacketExtracor(packet.getBuf());
		const flags = info.getFlags(['useMsgpack', 'useSerializer', 'hasId', 'hasUserData']);

		let userData = false;

		const iv = info.getBuf();
		const id = flags.hasId ? info.getBuf().toString() : false;

		if (flags.hasUserData) {
			const userDataRaw = info.getBuf();
			userData = flags.useMsgpack ? msgpack.decode(userDataRaw) : JSON.stringify(userDataRaw.toString());
		}
		const payload = packet.getBufFin();

		return {payload, id, iv, userData, useSerializer: flags.useSerializer};
	}

	async decrypt(key, data, returnExtended = false) {
		if (!Buffer.isBuffer(data)) return null;
		let payload, id, iv, userData;
		const packet = this.parsePacket(data);

		try {
			key = typeof key === 'function' ? await key(packet.userData) : key;

			const decipher = crypto.createDecipheriv(this.options.cryptMode, await this.genKey(key, packet.id), packet.iv);
			payload = await this._process(decipher, packet.payload);

			id = packet.id;
			iv = packet.iv;
			userData = packet.userData;
			payload = (packet.useSerializer) ? await this.serializer.deserialize(payload) : payload;
		} catch (e) {
			return null;
		}

		return returnExtended ? {id, iv, userData, payload} : payload;
	}
}

module.exports = Object.assign({Crypt, Serializer}, tools);
