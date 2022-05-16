import * as crypto from 'crypto';
import {ec as EC} from 'elliptic';
import {Transform} from 'stream';
import {BinaryToTextEncoding} from 'crypto';

import {Serializer, DataCoder, CoderTools} from '@osmium/coder';

import TypedArray = NodeJS.TypedArray;

export type PBKInput = string | Buffer | TypedArray | DataView;

export interface AESCryptOptions {
	keyMode: string;
	keySize: number;
	keySalt: PBKInput;
	cryptMode: string;
	ivLength: number;
	useCoder: boolean;
	customCoder: DataCoder | null,
	customSerializer: Serializer | null,
	version: number;
}

export interface AESCryptOptionsArgs {
	keyMode?: string;
	keySize?: number;
	keySalt?: PBKInput;
	cryptMode?: string;
	ivLength?: number;
	useCoder?: boolean;
	customCoder?: DataCoder | null,
	customSerializer?: Serializer | null,
	version?: number;
}

export class CryptTools extends CoderTools {
	static crypto = crypto;

	static async pbkdf2(password: PBKInput, salt: PBKInput = 'vWiq8rHuWKur6bsnTa0aAHugsc0stJS5', iterations = 1, keyLength = 32, digest = 'sha512'): Promise<boolean | Buffer> {
		return new Promise(resolve =>
			crypto.pbkdf2(password, salt, iterations, keyLength, digest, (err, derivedKey) =>
				resolve(err ? false : derivedKey)
			)
		);
	}

	static async pbkdf2b66(password: PBKInput, salt: PBKInput = 'RGkLdvP36a1MIDEY5f0u714C3BipXR8k', iterations = 1, keyLength = 32, digest = 'sha512'): Promise<string | boolean> {
		const res = await CryptTools.pbkdf2(password, salt, iterations, keyLength, digest);
		if (!res) return false;

		return CryptTools.base66Encode(res.toString());
	}

	static hash(what: any, mode = 'sha256', encoding: crypto.Encoding = 'utf8', digest: BinaryToTextEncoding = 'hex'): string {
		return crypto
			.createHash(mode)
			.update(what, encoding)
			.digest(digest);
	}

	static isHash(what: any, type = 'sha256'): boolean {
		return (new RegExp(`[0-9a-f]{${CryptTools.hash('', type).length}}`, 'i')).test(what);
	}
}

export interface AesCryptPacket {
	version: number,
	useDataCoder: boolean,
	id: null | string,
	publicData: null | object | Buffer,
	iv: Buffer,
	payload: Buffer
}

const AesCryptPacketSchema = ['version', 'useDataCoder', 'id', 'publicData', 'iv', 'payload'];

export interface AesCryptDecryptResult<PayloadType, PublicDataType> {
	id: string | null,
	iv: Buffer,
	publicData: PublicDataType | null,
	payload: PayloadType | null | object
}

export class AesCrypt {
	private readonly options: AESCryptOptions;
	private readonly coder: DataCoder | null;
	private readonly serializer: Serializer;

	constructor(options: AESCryptOptionsArgs = {}) {
		this.options = {
			keyMode         : 'sha512',
			keySize         : 256,
			keySalt         : 'h4xtHPsG5PzePQk41WrciTx4FQzbgtcb',
			cryptMode       : 'aes-256-cbc',
			ivLength        : 16,
			useCoder        : true,
			customCoder     : null,
			customSerializer: null,
			version         : 3
		};

		Object.assign(this.options, options);

		this.coder = null;

		if (this.options.useCoder) {
			this.coder = this.options.customCoder || new DataCoder();
		}

		this.serializer = this.options.customSerializer || new Serializer(this.coder || undefined);
		this.serializer.registerSchema(1, AesCryptPacketSchema);
	}

	use<T>(id: number, detector: Function, encode: (arg: T) => Buffer, decode: (arg: Buffer) => T): void {
		if (!this.options.useCoder || !this.coder || !this.serializer) return;

		this.coder.use(id, detector, encode, decode);
		this.serializer.use(id, detector, encode, decode);
	}

	async genKey(passkey: PBKInput, id: null | string = null): Promise<boolean | Buffer> {
		return CryptTools.pbkdf2(`${id ? id : ''}${passkey}`, this.options.keySalt, 1, this.options.keySize / 8, this.options.keyMode);
	}

	private _process(processor: Transform, data: any): Promise<Buffer> {
		return new Promise((resolve, reject) => {
			try {
				let out = Buffer.from('');

				processor.on('readable', () => {
					const block = processor.read();
					if (!Buffer.isBuffer(block)) return;
					out = Buffer.concat([out, block]);
				});
				processor.on('end', () => resolve(out));
				processor.write(data);
				processor.end();
			} catch (e) {
				reject(e);
			}
		});
	}

	async encrypt<T>(key: PBKInput | Function, data: T, id: null | string = null, publicData: null | object = null, useDataCoder: boolean = true): Promise<Buffer> {
		let iv = crypto.randomBytes(this.options.ivLength);
		key = typeof key === 'function' ? await key(publicData) : key;

		const _data = this.options.useCoder && this.coder && useDataCoder ? this.coder.encode(data) : data;
		const _publicData = this.options.useCoder && this.coder && useDataCoder ? this.coder.encode(publicData) : publicData;

		const cipher = crypto.createCipheriv(this.options.cryptMode, <Buffer>(await this.genKey(<PBKInput>key, id)), iv);
		const payload = await this._process(cipher, _data);

		const packet: AesCryptPacket = {
			version   : this.options.version,
			useDataCoder,
			id,
			publicData: _publicData,
			iv,
			payload
		};

		return this.serializer.serialize<AesCryptPacket>(packet);
	}

	async slicePublicData<T>(data: Buffer): Promise<T | object | null> {
		if (!Buffer.isBuffer(data)) return null;
		try {
			const packet = this.serializer.deserialize<AesCryptPacket>(data);
			return packet.publicData
			       ? this.coder && Buffer.isBuffer(packet.publicData)
			         ? this.coder.decode(packet.publicData)
			         : packet.publicData
			       : null;
		} catch (e) {
			return null;
		}
	}

	async decrypt<PayloadType, PublicDataType = null>(key: PBKInput | Function, data: Buffer, returnExtended = false): Promise<AesCryptDecryptResult<PayloadType, PublicDataType> | PayloadType> {
		if (!Buffer.isBuffer(data)) {
			throw new Error('Input data is not Buffer');
		}

		const packet = this.serializer.deserialize<AesCryptPacket>(data);

		let id, iv;
		let publicData: PublicDataType;
		let outPayload: PayloadType;

		try {
			publicData = (packet.useDataCoder && this.coder && Buffer.isBuffer(packet.publicData)
			              ? this.coder.decode<PublicDataType>(packet.publicData)
			              : packet.publicData) as PublicDataType;
			key = typeof key === 'function' ? await key(publicData) : key;

			const decipher = crypto.createDecipheriv(this.options.cryptMode, <Buffer>(await this.genKey(<PBKInput>key, packet.id)), packet.iv);

			const rawPayload = await this._process(decipher, packet.payload);
			outPayload = (packet.useDataCoder && this.coder ? this.coder.decode<PayloadType>(rawPayload) : rawPayload) as PayloadType;

			id = packet.id;
			iv = packet.iv;
		} catch (e) {
			throw new Error('Cant decrypt message');
		}

		return returnExtended ? {
			id,
			iv,
			publicData,
			payload: outPayload
		} : outPayload;
	}
}

export type ECDHKeyPair = {
	privKey: string,
	pubKey: string
}

export interface ECDHKeyPacket {
	version: number,
	curve: string,
	data: Buffer,
	isPrivate: string
}

const ECDHKeyPacketSchema: string[] = ['version', 'curve', 'data', 'isPrivate'];

export class ECDHKey {
	ser: Serializer;
	version: number = 2;
	curve: string;
	ec: EC;

	constructor(curve = 'ed25519') {
		this.curve = curve;

		this.ser = new Serializer();
		this.ser.registerSchema(1, ECDHKeyPacketSchema);

		this.ec = new EC(this.curve);
	}

	private hexToB62(hex: string, isPrivate = false) {
		hex = !(hex.length % 2) ? hex : '0' + hex;

		const out = this.ser.serialize({
			version: this.version,
			curve  : this.curve,
			data   : Buffer.from(hex, 'hex'),
			isPrivate
		});

		return CryptTools.base62Encode(out);
	}

	private b62PrivToHex(b62str: string): string {
		const buffer = CryptTools.base62Decode(b62str, true) as Buffer;
		let parsed: ECDHKeyPacket;

		try {
			parsed = this.ser.deserialize<ECDHKeyPacket>(buffer);
		} catch (e) {
			throw new Error('Error, wrong private key format');
		}

		if (!parsed.isPrivate) {
			throw new Error('Error, not private key');
		}

		return parsed.data.toString('hex');
	}

	generate(): ECDHKeyPair {
		const key = this.ec.genKeyPair();
		const privKey = this.hexToB62(key.getPrivate().toString('hex'), true);
		const pubKey = this.hexToB62(key.getPublic().encode('hex', false));

		return {
			privKey,
			pubKey
		};
	}

	static generate(): ECDHKeyPair {
		return (new ECDHKey()).generate();
	}

	getPublicFromPrivate(privKey: string): ECDHKeyPair {
		const keyPair = this.ec.keyFromPrivate(this.b62PrivToHex(privKey), 'hex');
		const pubKey = this.hexToB62(keyPair.getPublic().encode('hex', false));

		return {
			privKey,
			pubKey
		};
	}

	static getPublicFromPrivate(privKey: string): ECDHKeyPair {
		return (new ECDHKey()).getPublicFromPrivate(privKey);
	}
}

export type ECDHDerivationKeyPair = {
	ourPrivate: string | Buffer,
	theirPublic: string | Buffer
}

export class ECDHKeyDerivation {
	private serializer: Serializer;
	keyFormatVersion: number;
	ec: EC;
	ourKey: EC.KeyPair;
	theirKey: EC.KeyPair;
	curve: string;
	sharedKey: Buffer | null;

	static createInstance(keyPair: ECDHDerivationKeyPair, curve = 'ed25519') {
		return new ECDHKeyDerivation(keyPair.ourPrivate, keyPair.theirPublic, curve);
	}

	constructor(ourPrivate: string | Buffer, theirPublic: string | Buffer, curve = 'ed25519') {
		this.keyFormatVersion = 2;

		this.curve = curve;
		this.ec = new EC(this.curve);

		this.serializer = new Serializer();
		this.serializer.registerSchema(1, ECDHKeyPacketSchema);

		const ourKeyHex = this._decodePayload(ourPrivate, true);

		this.ourKey = this.ec.keyFromPrivate(ourKeyHex, 'hex');
		this.theirKey = this.ec.keyFromPublic(this._decodePayload(theirPublic), 'hex');

		this.sharedKey = null;
	}

	private _decodePayload(b62str: string | Buffer, asPrivate = false): string {
		const _b62str = Buffer.isBuffer(b62str) ? Buffer.from(b62str).toString() : b62str;

		let buffer = CryptTools.base62Decode(_b62str, true) as Buffer;

		let parsed: ECDHKeyPacket;
		try {
			parsed = this.serializer.deserialize<ECDHKeyPacket>(buffer);
		} catch (e) {
			throw new Error('Wrong private key format');
		}

		if (this.keyFormatVersion !== parsed.version) {
			const err = `Wrong key version, has ${parsed.version} must be ${this.keyFormatVersion}`;
			throw new Error(err);
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
		if (this.sharedKey) return this.sharedKey;

		return this.ourKey.derive(this.theirKey.getPublic()).toBuffer('be');
	}
}
