const {describe, it} = require('mocha');
const {expect} = require('chai');
const oTools = require('@osmium/tools');

function doTests(coderName, title) {
	const {AesCrypt, ECDHKeyDerivation, ECDHKey} = require(`../dist/${coderName}`);

	async function encryptDecryptTest(value, key, options = {}, id = false, publicData = false, useDataCoder) {
		const aes = new AesCrypt(options);
		const encrypted = await aes.encrypt(key, value, id, publicData, useDataCoder);
		return aes.decrypt(key, encrypted, true);
	}

	const sample = {key1: true, key2: 291, key3: 'hello+1', key4: [{a: 1, b: -20, c: 'hello'}, null]};
	const id = oTools.UID('ID-');
	const publicData = {test: 'ok'};

	const keyOne = {
		ourPrivate : 'xbWTGMloxaCNbseq1pu271JumCEWEuCTmLGrVXBPGBATeSax0qu0fPu0ZSpksUstBFxnugslY',
		theirPublic: '2aiuyORVnGLKVzkuFBd59uEg1ToSVEShA6oDQ0Cp1gwYEyRWzfpLqZc5O96iCLk8v6lUFafrDYJIT2zdw9ppwz5wOwsWWi06zcAmn03CTRnFaTyRyzzGGm'
	};

	const keyTwo = {
		ourPrivate : 'xedrVfZxTnO8LBnCt6kBITlE8uopkcCR7OEdwlMfIZutv6QZIDOBWqsJX1QcqvSY2m6jYOuWK',
		theirPublic: '2ahUbXXqpHwhq3CHlRBPz3D5cLFU0FrsE9BSkKGeZ2itY275ASZRq8uZT3hhiRL8xDMJjHoY804Hisj3fBLgKlpETfSgwnLmurmBH2gJVM4XXnyW7OwzQu'
	};

	describe(`==== Test for "${title}" version ====`, function () {
		describe('ECDH key derivation', function () {
			it('Key derivation', async function () {
				const sharedKey = '6bb75f65c2c8b3af54c437f92fe77f0b36100a5bba1b3cece55c5ad5e1e89bc6';
				const [dKeyOne, dKeyTwo] = [keyOne, keyTwo].map(key => ECDHKeyDerivation.createInstance(key).getSharedKey().toString('hex'));

				expect(dKeyOne).to.eql(dKeyTwo);
				expect(dKeyOne).to.eql(sharedKey);
			});

			it('Key generation', async function () {
				expect(ECDHKey.getPublicFromPrivate(ECDHKey.generate().privKey).pubKey).be.an('string');
			});
		});

		describe('AES encrypting', function () {
			it('Simple encrypt test', async function () {
				const result = await encryptDecryptTest(sample, oTools.UID());
				expect(result.payload).to.eql(sample);
			});

			it('Full encrypt test - default', async function () {
				const result = await encryptDecryptTest(sample, oTools.UID(), {}, id, publicData);
				expect(result.payload).to.eql(sample);
				expect(result.id).to.eql(id);
				expect(result.publicData).to.eql(publicData);
			});

			it('Full encrypt test - modifed', async function () {
				const result = await encryptDecryptTest(sample, oTools.UID(), {keyMode: 'sha1', keySalt: ''}, id, publicData);
				expect(result.payload).to.eql(sample);
				expect(result.id).to.eql(id);
				expect(result.publicData).to.eql(publicData);
			});
		});
	});
}

doTests('index', 'Full');
//doTests('index.min', 'Minimifed');
