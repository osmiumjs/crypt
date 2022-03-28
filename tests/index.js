const {describe, it} = require('mocha');
const {expect} = require('chai');


function doTests(coderName, title) {
	const {oTools, AesCrypt, ECDHKeyDerivation, ECDHKey} = require(`../dist/${coderName}`);

	async function encryptDecryptTest(value, key, options = {}, id = false, publicData = false, useDataCoder) {
		const aes = new AesCrypt(options);
		const encrypted = await aes.encrypt(key, value, id, publicData, useDataCoder);
		return aes.decrypt(key, encrypted, true);
	}

	const sample = {key1: true, key2: 291, key3: 'hello+1', key4: [{a: 1, b: -20, c: 'hello'}, null]};
	const id = oTools.UID('ID-');
	const publicData = {test: 'ok'};

	const keyOne = {
		ourPrivate : 'xdArwxSpa4yi5RTEVXVxfdZg0KeAv0wia3l7bhfoLogu6iyjYzs3y5jrzKM1rGpQ6MafKljvt',
		theirPublic: '2afdRSsysuKKBspudsjvrxZMPXC1d0WKsVnxenOF50bqjr7Tn8NrKRY7W1zYqbmONu6J79GOjrFWvUaHCezZWH1RQsnC1r9nfP886vFP2qiyuIGsrMOrdw'
	};

	const keyTwo = {
		ourPrivate : 'xbUvZ8nC06I0lIr0ZIWD6h8OLosOuRtD5Savvxj6fEsQfZWFDabI2FTZ5wKXJI6Oarn66o4vh',
		theirPublic: '2acrrbVGLqcdKpNsAV4TTsJ2msXaNO1tQpSdICpfDPxLJ54idcmrF4tCAiYHQ1Q9uFyLNJfQ1xBdStVnEKqFFuUXrMtCqhPy2jqUZcIvrnKu6PpXJfchdE'
	};

	describe(`==== Test for "${title}" version ====`, function () {
		describe('ECDH key derivation', function () {
			it('Key derivation', async function () {
				const sharedKey = '25c29f1f9cb8d1ba414a22f7d14b3194cf6f7feb9cb4897a4ea08f904a4dacdb';
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
