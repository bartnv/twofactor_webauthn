if (window.rcmail) {
  rcmail.addEventListener('init', function() {
    rcmail.addEventListener('plugin.twofactor_webauthn_redirect', twofactor_webauthn_redirect);

    $('form').hide();
    $('.box-inner').append('<p id="tw_message" style="color: white; text-align: center;"></p>');
    if (rcmail.env.twofactor_webauthn_challenge) {
      $('#tw_message').html(rcmail.gettext('please_activate_key', 'twofactor_webauthn'));
      setTimeout(twofactor_webauthn_auth, 100);
    }
    else $('#tw_message').html('Error: did not received challenge from server');
    tw_timeout = setTimeout("location = './';", 60000);
  });
};

function twofactor_webauthn_auth() {
  webauthnAuthenticate(rcmail.env.twofactor_webauthn_challenge, function(success, info) {
    clearTimeout(tw_timeout);
    if (success) {
      tw_timeout = setTimeout("location = './';", 60000);
      rcmail.http_post('plugin.twofactor_webauthn_login', { response: info });
      $('#tw_message').html(rcmail.gettext('verifying_key', 'twofactor_webauthn'));
    }
    else {
      $('#tw_message').html(rcmail.gettext('authentication_cancelled', 'twofactor_webauthn'));
      tw_timeout = setTimeout("location = './';", 10000);
    }
  });
}

function twofactor_webauthn_redirect(data) {
  if (data.delay) tw_timeout = setTimeout(`location = '${data.url}';`, data.delay*1000);
  else location = data.url;
}

// WebAuthn support by David Earl - https://github.com/davidearl/webauthn/
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
			var cd = JSON.parse(String.fromCharCode.apply(null,
														  new Uint8Array(aAssertion.response.clientDataJSON)));
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
