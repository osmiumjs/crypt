import * as crypto from 'crypto';
import {ec as EC} from 'elliptic';
import {AESCryptOptions, PBKInput} from './types';
import {Transform} from 'stream';

import {Serializer, DataCoder, coderTools, nTools} from '@osmium/coder';
import {DetectorCallback} from '@osmium/coder/src/types';
import {BinaryToTextEncoding} from 'crypto';

export {Serializer, DataCoder, coderTools, nTools};

function pbkdf2(password: PBKInput, salt: PBKInput = 'vWiq8rHuWKur6bsnTa0aAHugsc0stJS5', iterations = 1, keyLength = 32, digest = 'sha512'): Promise<boolean | Buffer> {
	return new Promise(resolve =>
		crypto.pbkdf2(password, salt, iterations, keyLength, digest, (err, derivedKey) => resolve(err ? false : derivedKey)));
}

async function pbkdf2b66(password: PBKInput, salt: PBKInput = 'RGkLdvP36a1MIDEY5f0u714C3BipXR8k', iterations = 1, keyLength = 32, digest = 'sha512'): Promise<string | boolean> {
	const res = await pbkdf2(password, salt, iterations, keyLength, digest);
	if (!res) return false;

	return coderTools.base66Encode(res.toString());
}

export const cryptTools = Object.assign(coderTools, {
	crypto,
	pbkdf2,
	pbkdf2b66,
	hash  : (what: any, mode = 'sha256', encoding: crypto.Encoding = 'utf8', digest: crypto.BinaryToTextEncoding = 'hex') =>
		crypto.createHash(mode)
		      .update(what, encoding)
		      .digest(digest),
	isHash: (what: any, type = 'sha256') =>
		(new RegExp(`[0-9a-f]{${cryptTools.hash('', type).length}}`, 'i')).test(what)
});

export class AesCrypt {
	options: AESCryptOptions & object;
	private readonly coder: DataCoder | null;
	private readonly serializer: Serializer;

	constructor(options = {}) {
		this.options = Object.assign({
			keyMode  : 'sha512',
			keySize  : 256,
			keySalt  : 'wS3frnWL5TysVZixQgHW0UuxUVZpR2Yp',
			cryptMode: 'aes-256-cbc',
			ivLength : 16,
			useCoder : true
		}, options);

		Object.assign(this.options, {
			version: 1
		});

		this.coder = null;

		if (this.options.useCoder) {
			// @ts-ignore
			this.coder = this.options.useCoder?.coder || new DataCoder();
		}

		// @ts-ignore
		this.serializer = this.options.useCoder?.serializer || new Serializer(this.options.useCoder?.coder);
	}

	use<T>(id: number, detector: DetectorCallback, encode: (arg: T) => Buffer, decode: (arg: Buffer) => T): void {
		if (!this.options.useCoder || !this.coder || !this.serializer) return;

		this.coder.use<T>(id, detector, encode, decode);
		this.serializer.use<T>(id, detector, encode, decode);
	}

	async genKey(passkey: PBKInput, id = false): Promise<boolean | Buffer> {
		return await pbkdf2(`${id ? id : ''}${passkey}`, this.options.keySalt, 1, this.options.keySize / 8, this.options.keyMode);
	}

	private _process(processor: Transform, data: any): Promise<Buffer> {
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

	async encrypt<T>(key: PBKInput | Function, data: T, id = false, publicData = false, useDataCoder = true): Promise<Boolean | Buffer> {
		let iv = crypto.randomBytes(this.options.ivLength);
		key = typeof key === 'function' ? await key(publicData) : key;

		const _data = this.options.useCoder && this.coder && useDataCoder ? this.coder.encode(data) : data;
		const _publicData = this.options.useCoder && this.coder && useDataCoder ? this.coder.encode(publicData) : publicData;

		const cipher = crypto.createCipheriv(this.options.cryptMode, <Buffer>(await this.genKey(<PBKInput>key, id)), iv);
		const payload = await this._process(cipher, _data);

		const packet = {
			version   : this.options.version,
			useDataCoder,
			id,
			publicData: _publicData,
			iv,
			payload
		};

		return this.serializer.serialize(packet);
	}

	async slicePublicData<T>(data: Buffer): Promise<T | null> {
		if (!Buffer.isBuffer(data)) return null;
		try {
			const packet = this.serializer.deserialize(data, ['version', 'useDataCoder', 'id', 'publicData', 'iv', 'payload']);
			return this.coder ? this.coder.decode(packet.publicData) : packet.publicData;
		} catch (e) {
			return null;
		}
	}

	async decrypt(key: PBKInput | Function, data: Buffer, returnExtended = false) {
		if (!Buffer.isBuffer(data)) return null;
		const packet = this.serializer.deserialize(data, ['version', 'useDataCoder', 'id', 'publicData', 'iv', 'payload']);

		let id, iv, publicData;
		let payload: Buffer;

		try {
			publicData = packet.useDataCoder && this.coder ? this.coder.decode(packet.publicData) : packet.publicData;
			key = typeof key === 'function' ? await key(publicData) : key;
			const decipher = crypto.createDecipheriv(this.options.cryptMode, <Buffer>(await this.genKey(<PBKInput>key, packet.id)), packet.iv);
			payload = await this._process(decipher, packet.payload);
			payload = packet.useDataCoder && this.coder ? this.coder.decode(payload) : payload;
			id = packet.id;
			iv = packet.iv;
		} catch (e) {
			return null;
		}

		return returnExtended ? {id, iv, publicData, payload} : payload;
	}
}

export type ECDH_KeyPair = {
	privKey: string,
	pubKey: string
}

export class ECDH_Key {
	ser: Serializer;
	VERSION: Number = 1;
	CURVE: string = 'ed25519';
	ec: EC;

	constructor() {
		this.ser = new Serializer();
		this.ec = new EC(this.CURVE as string);
	}

	private hexToB62(hex: string, isPrivate = false) {
		hex = !(hex.length % 2) ? hex : '0' + hex;
		const out = this.ser.serialize({
			VERSION: this.VERSION,
			CURVE  : this.CURVE,
			data   : Buffer.from(hex, 'hex'),
			isPrivate
		});

		return cryptTools.base62Encode(out as Buffer);
	}

	private b62PrivToHex(b62str: string) {
		const buffer = cryptTools.base62Decode(b62str, true);
		let parsed;
		try {
			parsed = this.ser.deserialize(buffer as Buffer, ['VERSION', 'CURVE', 'data', 'isPrivate']);
		} catch (e) {
			console.error('Error, wrong private key format');
			process.exit();
		}

		if (!parsed.isPrivate) {
			console.error('Error, not private key');
			process.exit();
		}

		return parsed.data.toString('hex');
	}

	generate(): ECDH_KeyPair {
		const key = this.ec.genKeyPair();
		const privKey = this.hexToB62(key.getPrivate().toString('hex'), true);
		const pubKey = this.hexToB62(key.getPublic().encode('hex', false));

		return {privKey, pubKey};
	}

	static generate(): ECDH_KeyPair {
		return (new ECDH_Key()).generate();
	}

	getPublicFromPrivate(privKey: string): ECDH_KeyPair {
		const keyPair = this.ec.keyFromPrivate(this.b62PrivToHex(privKey), 'hex');
		const pubKey = this.hexToB62(keyPair.getPublic().encode('hex', false));

		return {privKey, pubKey};
	}

	static getPublicFromPrivate(privKey: string): ECDH_KeyPair {
		return (new ECDH_Key()).getPublicFromPrivate(privKey);
	}
}

export class ECDH_KeyDerivation {
	private serializer: Serializer;
	keyFormatVersion: number;
	ec: EC | boolean;
	curve: any;
	ourKey: EC.KeyPair;
	theirKey: EC.KeyPair;
	sharedKey: Buffer | boolean;

	static createInstance(keyPair: ECDH_KeyPair) {
		return new ECDH_KeyDerivation(keyPair.privKey, keyPair.pubKey);
	}

	constructor(ourPrivate: string | Buffer, theirPublic: string | Buffer) {
		this.keyFormatVersion = 1;

		this.ec = false;
		this.curve = false;

		this.serializer = new Serializer();

		const ourKeyHex = this._decodePayload(ourPrivate, true);
		// @ts-ignore
		this.ourKey = this.ec?.keyFromPrivate(ourKeyHex, 'hex');
		// @ts-ignore
		this.theirKey = this.ec?.keyFromPublic(this._decodePayload(theirPublic), 'hex');

		this.sharedKey = false;
	}

	private _decodePayload(b62str: string | Buffer, asPrivate = false): string {
		const _b62str = Buffer.isBuffer(b62str) ? Buffer.from(b62str).toString() : b62str;

		let buffer = cryptTools.base62Decode(_b62str, true);

		let parsed;
		try {
			// @ts-ignore
			parsed = this.serializer.deserialize(buffer, ['ver', 'curve', 'data', 'isPrivate']);
		} catch (e) {
			throw new Error('Wrong private key format');
		}

		if (this.keyFormatVersion !== parsed.ver) {
			throw new Error(`Wrong key version, has ${parsed.ver} must be ${this.keyFormatVersion}`);
		}

		if (asPrivate && !parsed.isPrivate) {
			throw new Error('Not private key');
		}

		if (!asPrivate && parsed.isPrivate) {
			throw new Error('Not public key');
		}

		if (this.curve && this.curve !== parsed.curve) {
			throw new Error('Keys has different curve');
		}

		if (!this.ec) {
			this.ec = new EC(parsed.curve);
			this.curve = parsed.curve;
		}

		return parsed.data.toString('hex');
	}

	getSharedKey(): Buffer {
		if (this.sharedKey) return <Buffer>this.sharedKey;
		return this.sharedKey = this.ourKey.derive(this.theirKey.getPublic()).toBuffer('be');
	}
}

export default {Serializer, DataCoder, coderTools, nTools, cryptTools, ECDH_Key, ECDH_KeyDerivation};
