import TypedArray = NodeJS.TypedArray;

export type PBKInput = string | Buffer | TypedArray | DataView;

export interface AESCryptOptions {
	keyMode: string;
	keySize: number;
	keySalt: PBKInput;
	cryptMode: string;
	ivLength: number;
	useCoder: boolean;
	version?: number;
}
