if (window.rcmail) {
	rcmail.addEventListener('init', function(evt) {
		rcmail.register_command('plugin.twofactor_webauthn_prepare', twofactor_webauthn_prepare, true);
		rcmail.register_command('plugin.twofactor_webauthn_rename', twofactor_webauthn_rename, true);
		rcmail.register_command('plugin.twofactor_webauthn_delete', twofactor_webauthn_delete, true);
		rcmail.register_command('plugin.twofactor_webauthn_save', twofactor_webauthn_save, true);
		rcmail.register_command('plugin.twofactor_webauthn_test', twofactor_webauthn_test);
		rcmail.addEventListener('plugin.twofactor_webauthn_challenge', twofactor_webauthn_challenge);
		rcmail.addEventListener('plugin.twofactor_webauthn_list', twofactor_webauthn_list);
		if (rcmail.env.twofactor_webauthn_keylist) twofactor_webauthn_list(JSON.parse(rcmail.env.twofactor_webauthn_keylist));
		else rcmail.http_get('plugin.twofactor_webauthn_list');
		$('#twofactor_activate').on('change', function() {
			if (!this.checked) $('#twofactor_lock').prop('checked', false);
		});
	});
}

function twofactor_webauthn_prepare() {
	rcmail.http_post('plugin.twofactor_webauthn_prepare');
}
function twofactor_webauthn_rename(id, name) {
	rcmail.http_post('plugin.twofactor_webauthn_rename', { id: id, name: name });
}
function twofactor_webauthn_delete(id) {
	rcmail.http_post('plugin.twofactor_webauthn_delete', { id: id });
}
function twofactor_webauthn_test() {
	rcmail.http_post('plugin.twofactor_webauthn_test');
}
function twofactor_webauthn_save() {
	rcmail.http_post('plugin.twofactor_webauthn_save', {
		activate: $('#twofactor_activate').prop('checked'),
		lock: $('#twofactor_lock').prop('checked')
	});
}

function twofactor_webauthn_challenge(data) {
	if (data.mode == 'register') {
		webauthnRegister(data.challenge, function(success, info) {
			if (success) {
				var name = prompt(rcmail.gettext('request_key_name', 'twofactor_webauthn'));
				rcmail.http_post('plugin.twofactor_webauthn_register', { response: info, name: name });
			}
			else { console.log('webauthRegister failed:', info); }
		});
	}
	else if (data.mode == 'test') {
		webauthnAuthenticate(data.challenge, function(success, info) {
			if (success) {
				rcmail.http_post('plugin.twofactor_webauthn_check', { response: info });
			}
			else { console.log('webauthnAuthenticate failed:', info); }
		});
	}
}

function twofactor_webauthn_list(data) {
	let ul = $('#twofactor_webauthn_keylist');
	ul.empty();
	if (!data || !data.length) {
		ul.append(rcmail.gettext('no_keys_yet', 'twofactor_webauthn'));
		rcmail.enable_command('plugin.twofactor_webauthn_test', false);
		return;
	}
	rcmail.enable_command('plugin.twofactor_webauthn_test', true);
	for (key of data) {
		ul.append('<li title="' + key.id + '">' + (key.name??key.id) +
			' <span class="rename" onclick="var name = prompt(\'' + rcmail.gettext('edit_key_name', 'twofactor_webauthn') + ' ' + (key.name?key.name:key.id) + '\');' +
			'if (name) { return rcmail.command(\'plugin.twofactor_webauthn_rename\', \'' + key.id + '\', name); }">✎</span>' +
			'<span class="delete" onclick="if (confirm(\'' + rcmail.gettext('confirm_delete_key', 'twofactor_webauthn') + ' ' + key.id + (key.name?' ('+key.name+')':'') +
			'?\')) { return rcmail.command(\'plugin.twofactor_webauthn_delete\', \'' + key.id + '\'); } else return false;">✖</span>'
		);
	}
}

// WebAuthn support by David Earl - https://github.com/davidearl/webauthn/ - License: MIT - Version: 2022-12-08
function webauthnRegister(key, callback){
	key = JSON.parse(key);
	key.publicKey.attestation = undefined;
	key.publicKey.challenge = new Uint8Array(key.publicKey.challenge); // convert type for use by key
	key.publicKey.user.id = new Uint8Array(key.publicKey.user.id);

	navigator.credentials.create({publicKey: key.publicKey})
		.then(function (aNewCredentialInfo) {
			var cd = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)));
			if (key.b64challenge != cd.challenge) {
				return callback(false, 'key returned something unexpected (1)');
			}
			if ('https://'+key.publicKey.rp.name != cd.origin) {
				return callback(false, 'key returned something unexpected (2)');
			}
			if (! ('type' in cd)) {
				return callback(false, 'key returned something unexpected (3)');
			}
			if (cd.type != 'webauthn.create') {
				return callback(false, 'key returned something unexpected (4)');
			}

			var ao = [];
			(new Uint8Array(aNewCredentialInfo.response.attestationObject)).forEach(function(v){
				ao.push(v);
			});
			var rawId = [];
			(new Uint8Array(aNewCredentialInfo.rawId)).forEach(function(v){
				rawId.push(v);
			});
			var info = {
				rawId: rawId,
				id: aNewCredentialInfo.id,
				type: aNewCredentialInfo.type,
				response: {
					attestationObject: ao,
					clientDataJSON:
					  JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)))
				}
			};
			callback(true, JSON.stringify(info));
		})
		.catch(function (aErr) {
			if (
				("name" in aErr) && (aErr.name == "AbortError" || aErr.name == "NS_ERROR_ABORT")
				|| aErr.name == 'NotAllowedError'
			) {
				callback(false, 'abort');
			} else {
				callback(false, aErr.toString());
			}
		});
}
function webauthnAuthenticate(key, cb){
	var pk = JSON.parse(key);
	var originalChallenge = pk.challenge;
	pk.challenge = new Uint8Array(pk.challenge);
	pk.allowCredentials.forEach(function(k, idx){
		pk.allowCredentials[idx].id = new Uint8Array(k.id);
	});
	navigator.credentials.get({publicKey: pk})
		.then(function(aAssertion) {
			var ida = [];
			(new Uint8Array(aAssertion.rawId)).forEach(function(v){ ida.push(v); });
			var cd = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aAssertion.response.clientDataJSON)));
			var cda = [];
			(new Uint8Array(aAssertion.response.clientDataJSON)).forEach(function(v){ cda.push(v); });
			var ad = [];
			(new Uint8Array(aAssertion.response.authenticatorData)).forEach(function(v){ ad.push(v); });
			var sig = [];
			(new Uint8Array(aAssertion.response.signature)).forEach(function(v){ sig.push(v); });
			var info = {
				type: aAssertion.type,
				originalChallenge: originalChallenge,
				rawId: ida,
				response: {
					authenticatorData: ad,
					clientData: cd,
					clientDataJSONarray: cda,
					signature: sig
				}
			};
			cb(true, JSON.stringify(info));
		})
		.catch(function (aErr) {
			if (("name" in aErr) && (aErr.name == "AbortError" || aErr.name == "NS_ERROR_ABORT" ||
									 aErr.name == "NotAllowedError")) {
				cb(false, 'abort');
			} else {
				cb(false, aErr.toString());
			}
		});
}
