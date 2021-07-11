const {describe, it} = require('mocha');
const {expect} = require('chai');
const {nTools, cryptTools, AesCrypt, ECDH_KeyDerivation, ECDH_Key} = require('../dist/index');


async function encryptDecryptTest(value, key, options = {}, id = false, publicData = false, useDataCoder) {
	const aes = new AesCrypt(options);
	const encrypted = await aes.encrypt(key, value, id, publicData, useDataCoder);
	return aes.decrypt(key, encrypted, true);
}

const sample = {key1: true, key2: 291, key3: 'hello+1', key4: [{a: 1, b: -20, c: 'hello'}, null]};
const id = nTools.UID('ID-');
const publicData = {test: 'ok'};

const key = {
	privKey: 'BeZOpFXSHKxMWfowVVjNLpOcvacHJLWR1B9dqBLoxlIszn3dYlZyDntfMAzvM5F3bnDmra',
	pubKey : '3MTUWfbHYYrKZ4G896ba1AoGcUylSMwRcPFULj1SbbAOyJE4qrIDuJmD2YPiieUyQglqynQrdoikB0CdGzpaUPmNKjEeymbrgUlKaT7zLLR2xpISM0j'
};

describe('Tests', function () {
	describe('ECDH key derivation', function () {
		it('Key derivation', async function () {
			const sharedKey = '7255c12e6c08b6aed9d2f819497bd79458cfa4fefa7e505fa1091efbcbf491a3';

			expect(ECDH_KeyDerivation.createInstance(key).getSharedKey().toString('hex')).to.eql(sharedKey);
		});

		it('Key generation', async function () {
			expect(ECDH_Key.getPublicFromPrivate(ECDH_Key.generate().privKey).pubKey).be.an('string');
		});
	});

	describe('AES encrypting', function () {
		it('Simple encrypt test', async function () {
			const result = await encryptDecryptTest(sample, '1111');
			expect(result.payload).to.eql(sample);
		});

		it('Full encrypt test - default', async function () {
			const result = await encryptDecryptTest(sample, '1111', {}, id, publicData);
			expect(result.payload).to.eql(sample);
			expect(result.id).to.eql(id);
			expect(result.publicData).to.eql(publicData);
		});

		it('Full encrypt test - modifed', async function () {
			const result = await encryptDecryptTest(sample, '1111', {keyMode: 'sha1', keySalt: ''}, id, publicData);
			expect(result.payload).to.eql(sample);
			expect(result.id).to.eql(id);
			expect(result.publicData).to.eql(publicData);
		});
	});

});
