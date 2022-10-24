/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import * as crypto from 'crypto';
import { ec as EC } from 'elliptic';
import { BinaryToTextEncoding } from 'crypto';
import { Serializer, DataCoder, CoderTools } from '@osmium/coder';
import TypedArray = NodeJS.TypedArray;
export declare type PBKInput = string | Buffer | TypedArray | DataView;
export interface AESCryptOptions {
    keyMode: string;
    keySize: number;
    keySalt: PBKInput;
    cryptMode: string;
    ivLength: number;
    useCoder: boolean;
    customCoder: DataCoder | null;
    customSerializer: Serializer | null;
    version: number;
}
export interface AESCryptOptionsArgs {
    keyMode?: string;
    keySize?: number;
    keySalt?: PBKInput;
    cryptMode?: string;
    ivLength?: number;
    useCoder?: boolean;
    customCoder?: DataCoder | null;
    customSerializer?: Serializer | null;
    version?: number;
}
export declare class CryptTools extends CoderTools {
    static crypto: typeof crypto;
    /** Like Math.random() */
    static random: () => number;
    /** GUIDv4 string */
    static GUID(mask?: string): string;
    /** Generate 128bit unique id */
    static UID(prefix?: string, mask?: string): string;
    static pbkdf2(password: PBKInput, salt?: PBKInput, iterations?: number, keyLength?: number, digest?: string): Promise<boolean | Buffer>;
    static pbkdf2b66(password: PBKInput, salt?: PBKInput, iterations?: number, keyLength?: number, digest?: string): Promise<string | boolean>;
    static hash(what: any, mode?: string, encoding?: crypto.Encoding, digest?: BinaryToTextEncoding): string;
    static isHash(what: any, type?: string): boolean;
}
export interface AesCryptPacket {
    version: number;
    useDataCoder: boolean;
    id: null | string;
    publicData: null | object | Buffer;
    iv: Buffer;
    payload: Buffer;
}
export interface AesCryptDecryptResult<PayloadType, PublicDataType> {
    id: string | null;
    iv: Buffer;
    publicData: PublicDataType | null;
    payload: PayloadType | null | object;
}
export declare class AesCrypt {
    private readonly options;
    private readonly coder;
    private readonly serializer;
    constructor(options?: AESCryptOptionsArgs);
    use<T>(id: number, detector: Function, encode: (arg: T) => Buffer, decode: (arg: Buffer) => T): void;
    genKey(passkey: PBKInput, id?: null | string): Promise<boolean | Buffer>;
    private _process;
    encrypt<T>(key: PBKInput | Function, data: T, id?: null | string, publicData?: null | object, useDataCoder?: boolean): Promise<Buffer>;
    slicePublicData<T>(data: Buffer): Promise<T | object | null>;
    decrypt<PayloadType, PublicDataType = null>(key: PBKInput | Function, data: Buffer, returnExtended?: boolean): Promise<AesCryptDecryptResult<PayloadType, PublicDataType> | PayloadType>;
}
export declare type ECDHKeyPair = {
    privKey: string;
    pubKey: string;
};
export interface ECDHKeyPacket {
    version: number;
    curve: string;
    data: Buffer;
    isPrivate: string;
}
export declare class ECDHKey {
    ser: Serializer;
    version: number;
    curve: string;
    ec: EC;
    constructor(curve?: string);
    private hexToB62;
    private b62PrivToHex;
    generate(): ECDHKeyPair;
    static generate(): ECDHKeyPair;
    getPublicFromPrivate(privKey: string): ECDHKeyPair;
    static getPublicFromPrivate(privKey: string): ECDHKeyPair;
}
export declare type ECDHDerivationKeyPair = {
    ourPrivate: string | Buffer;
    theirPublic: string | Buffer;
};
export declare class ECDHKeyDerivation {
    private serializer;
    keyFormatVersion: number;
    ec: EC;
    ourKey: EC.KeyPair;
    theirKey: EC.KeyPair;
    curve: string;
    sharedKey: Buffer | null;
    static createInstance(keyPair: ECDHDerivationKeyPair, curve?: string): ECDHKeyDerivation;
    constructor(ourPrivate: string | Buffer, theirPublic: string | Buffer, curve?: string);
    private _decodePayload;
    getSharedKey(): Buffer;
}
