/// <reference types="node" />
import TypedArray = NodeJS.TypedArray;
export declare type PBKInput = string | Buffer | TypedArray | DataView;
export interface AESCryptOptions {
    keyMode: string;
    keySize: number;
    keySalt: PBKInput;
    cryptMode: string;
    ivLength: number;
    useCoder: boolean;
    version?: number;
}
