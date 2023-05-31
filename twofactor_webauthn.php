<?php
/**
 * Two-factor WebAuthn/FIDO2 authentication for RoundCube
 *
 * This RoundCube plugin adds WebAuthn/FIDO2 verification to the login process
 *
 * @version 1.2.0
 * @author Bart Noordervliet <bart@mmvi.nl>
 * @url https://github.com/bartnv/twofactor_webauthn
 */

require('3rdparty/WebAuthn/WebAuthn.php');
require('3rdparty/CBOR/CBOREncoder.php');
require('3rdparty/CBOR/Types/CBORByteString.php');

class twofactor_webauthn extends rcube_plugin {
  function init() {
		$rcmail = rcmail::get_instance();

		$this->add_hook('settings_actions', array($this, 'settings_actions'));
  	$this->add_hook('login_after', array($this, 'login_after'));
  	$this->add_hook('send_page', array($this, 'check_status'));
		$this->add_texts('localization/', true);

		$this->register_action('twofactor_webauthn', array($this, 'twofactor_webauthn_init'));
    $this->register_action('plugin.twofactor_webauthn_list', array($this, 'twofactor_webauthn_list'));
    $this->register_action('plugin.twofactor_webauthn_save', array($this, 'twofactor_webauthn_save'));
		$this->register_action('plugin.twofactor_webauthn_prepare', array($this, 'twofactor_webauthn_prepare'));
    $this->register_action('plugin.twofactor_webauthn_register', array($this, 'twofactor_webauthn_register'));
    $this->register_action('plugin.twofactor_webauthn_rename', array($this, 'twofactor_webauthn_rename'));
    $this->register_action('plugin.twofactor_webauthn_delete', array($this, 'twofactor_webauthn_delete'));
    $this->register_action('plugin.twofactor_webauthn_test', array($this, 'twofactor_webauthn_test'));
    $this->register_action('plugin.twofactor_webauthn_check', array($this, 'twofactor_webauthn_check'));
    $this->register_action('plugin.twofactor_webauthn_login', array($this, 'twofactor_webauthn_login'));
	}

  function settings_actions($args) {
    $args['actions'][] = [
      'action' => 'plugin.twofactor_webauthn',
      'type' => 'link',
      'label' => 'twofactor_webauthn.config',
      'title' => 'twofactor_webauthn.config'
    ];
    return $args;
  }

  // Re-use the regular login form, removing inputs with jquery (see twofactor_webauthn_form.js)
  function login_after($args) {
		$rcmail = rcmail::get_instance();

		$config = $this->getConfig();
		if (!$config['activate'] || empty($config['keys']) || ($config['keys'] == '[]')) {
      $_SESSION['twofactor_webauthn_checked'] = 1;
      return;
    }

    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
    $challenge = $webauthn->prepareForLogin($config['keys']);
    $this->saveConfig($config);
    $rcmail->output->set_env('twofactor_webauthn_challenge', $challenge);
		$rcmail->output->set_pagetitle($this->gettext('twofactor_webauthn'));
		$this->add_texts('localization', true);
		$this->include_script('twofactor_webauthn_form.js');

  	$rcmail->output->send('login');
  }

	function check_status($p) {
    if (!empty($_SESSION['twofactor_webauthn_checked'])) return $p;

		$rcmail = rcmail::get_instance();
    if ($rcmail->task == 'login') return $p;

		$config = $this->getConfig();
		if (!empty($config['activate'])) {
			header('Location: ?_task=logout&_token=' . $rcmail->get_request_token());
      exit();
		}

    $_SESSION['twofactor_webauthn_checked'] = 1;
		return $p;
	}

  function twofactor_webauthn_init() {
    $rcmail = rcmail::get_instance();
    $this->register_handler('plugin.body', array($this, 'twofactor_webauthn_form'));
    $rcmail->output->set_pagetitle($this->gettext('twofactor_webauthn'));
    $rcmail->output->send('plugin');
  }

  function twofactor_webauthn_list() {
    $list = $this->getList();
    $rcmail->output->command('plugin.twofactor_webauthn_list', $list);
  }

  function twofactor_webauthn_save() {
    $rcmail = rcmail::get_instance();
    $activate = rcube_utils::get_input_value('activate', rcube_utils::INPUT_POST);
    $lock = rcube_utils::get_input_value('lock', rcube_utils::INPUT_POST);
    if ($activate === 'true') $activate = true;
    elseif ($activate === 'false') $activate = false;
    else {
      error_log('Received invalid response on webauthn save');
      return;
    }
    if ($lock === 'true') $lock = true;
    elseif ($lock === 'false') $lock = false;
    else {
      error_log('Received invalid response on webauthn save');
      return;
    }
    $config = $this->getConfig();
    if (isset($config['lock']) && $config['lock'] === true) {
      $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
      $challenge = $webauthn->prepareForLogin($config['keys']);
      if ($config['activate'] != $activate) $config['setactivate'] = $activate;
      if ($config['lock'] != $lock) $config['setlock'] = $lock;
      if (isset($config['setactivate']) || isset($config['setlock'])) {
        $this->saveConfig($config);
        $rcmail->output->command('plugin.twofactor_webauthn_challenge', [ 'mode' => 'test', 'challenge' => $challenge ]);
        return;
      }
    }
    $config['activate'] = $activate;
    $config['lock'] = $lock;
    $this->saveConfig($config);
    $rcmail->output->show_message($this->gettext('successfully_saved'), 'confirmation');
  }

  function twofactor_webauthn_prepare() {
    $rcmail = rcmail::get_instance();
    $config = $this->getConfig();
    if (isset($config['lock']) && $config['lock'] === true) {
      $rcmail->output->show_message($this->gettext('error_locked'), 'error');
      return;
    }
    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
    $challenge = $webauthn->prepareChallengeForRegistration('RoundCube', '1', true);
    $rcmail->output->command('plugin.twofactor_webauthn_challenge', [ 'mode' => 'register', 'challenge' => $challenge ]);
  }

  function twofactor_webauthn_test() {
    $rcmail = rcmail::get_instance();
    $config = $this->getConfig();
    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
    $challenge = $webauthn->prepareForLogin($config['keys']);
    $this->saveConfig($config);
    $rcmail->output->command('plugin.twofactor_webauthn_challenge', [ 'mode' => 'test', 'challenge' => $challenge ]);
  }

  function twofactor_webauthn_check() {
    $response = rcube_utils::get_input_value('response', rcube_utils::INPUT_POST);
    if (empty($response)) {
      error_log('Received empty response on webauthn challenge');
      return;
    }
    $rcmail = rcmail::get_instance();
    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
    $config = $this->getConfig();
    if ($webauthn->authenticate($response, $config['keys'])) {
      if (isset($config['setactivate']) || isset($config['setlock'])) {
        if (isset($config['setactivate'])) {
          $config['activate'] = $config['setactivate'];
          unset($config['setactivate']);
        }
        if (isset($config['setlock'])) {
          $config['lock'] = $config['setlock'];
          unset($config['setlock']);
        }
        $this->saveConfig($config);
        $rcmail->output->show_message($this->gettext('successfully_saved'), 'confirmation');
        return;
      }
      $this->saveConfig($config);
      $response = json_decode($response);
      $rcmail->output->show_message($this->gettext('key_checked') . ' ' . dechex(crc32(implode('', $response->rawId))), 'confirmation');
    }
    else {
      $rcmail->output->show_message($this->gettext('authentication_failed'), 'warning');
    }
  }

  function twofactor_webauthn_register() {
    $response = rcube_utils::get_input_value('response', rcube_utils::INPUT_POST);
    if (empty($response)) {
      error_log('Received empty response on webauthn challenge');
      return;
    }
    $name = rcube_utils::get_input_value('name', rcube_utils::INPUT_POST);
    $rcmail = rcmail::get_instance();
    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
    $config = $this->getConfig();
    $config['keys'] = $webauthn->register($response, $config['keys'] ?? '', $name);
    $this->saveConfig($config);
    $rcmail->output->show_message($this->gettext('key_registered'), 'confirmation');
    $rcmail->output->command('plugin.twofactor_webauthn_list', $this->getList($config));
  }

  function twofactor_webauthn_rename() {
    $id = rcube_utils::get_input_value('id', rcube_utils::INPUT_POST);
    if (empty($id)) {
      error_log('Received empty id on webauthn rename');
      return;
    }
    $name = rcube_utils::get_input_value('name', rcube_utils::INPUT_POST);
    if (empty($name)) {
      error_log('Received empty name on webauthn rename');
      return;
    }
    $rcmail = rcmail::get_instance();
    $config = $this->getConfig();
    if (isset($config['lock']) && $config['lock'] === true) {
      $rcmail->output->show_message($this->gettext('error_locked'), 'error');
      return;
    }
    $keys = json_decode($config['keys']);
    foreach ($keys as &$key) {
      if (dechex(crc32(implode('', $key->id))) === $id) {
        $key->name = $name;
      }
    }
    $config['keys'] = json_encode($keys);
    $this->saveConfig($config);
    $rcmail->output->show_message($this->gettext('key_renamed') . ' ' . $name, 'confirmation');
    $rcmail->output->command('plugin.twofactor_webauthn_list', $this->getList($config));
  }

  function twofactor_webauthn_delete() {
    $id = rcube_utils::get_input_value('id', rcube_utils::INPUT_POST);
    if (empty($id)) {
      error_log('Received empty id on webauthn delete');
      return;
    }
    $rcmail = rcmail::get_instance();
    $config = $this->getConfig();
    if (isset($config['lock']) && $config['lock'] === true) {
      $rcmail->output->show_message($this->gettext('error_locked'), 'error');
      return;
    }
    $newkeys = [];
    foreach (json_decode($config['keys']) as $key) {
      if (dechex(crc32(implode('', $key->id))) === $id) continue;
      $newkeys[] = $key;
    }
    $config['keys'] = json_encode($newkeys);
    $this->saveConfig($config);
    $rcmail->output->show_message($this->gettext('key_deleted'), 'confirmation');
    $rcmail->output->command('plugin.twofactor_webauthn_list', $this->getList($config));
  }

  function twofactor_webauthn_login() {
    $response = rcube_utils::get_input_value('response', rcube_utils::INPUT_POST);
    if (empty($response)) {
      error_log('Received empty response on webauthn login');
      return;
    }
    $rcmail = rcmail::get_instance();
    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);
    $config = $this->getConfig();
    if ($webauthn->authenticate($response, $config['keys'])) {
      $_SESSION['twofactor_webauthn_checked'] = 1;
      $rcmail->output->show_message($this->gettext('authentication_succeeded'), 'confirmation');
      $rcmail->output->command('plugin.twofactor_webauthn_redirect', [ 'url' => $rcmail->url(['_task'=>'mail'], true, false, true), 'delay' => 1 ]);
    }
    else {
      $rcmail->output->show_message($this->gettext('authentication_failed'), 'warning');
      $rcmail->output->command('plugin.twofactor_webauthn_redirect', [ 'url' => $rcmail->url([], true), 'delay' => 10 ]);
    }
    $this->saveConfig($config);
  }

  public function twofactor_webauthn_form() {
    $rcmail = rcmail::get_instance();
    $config = $this->getConfig();

    $rcmail->output->set_env('product_name', $rcmail->config->get('product_name'));
    $rcmail->output->set_env('twofactor_webauthn_keylist', json_encode($this->getList($config)));

    $keys = html::tag('legend', [], rcube::Q($this->gettext('registered_keys')));
    $keys .= html::tag('ul', [ 'id' => 'twofactor_webauthn_keylist' ], rcube::Q($this->gettext('loading')));
    $keys .= $rcmail->output->button([
      'command' => 'plugin.twofactor_webauthn_prepare',
      'class' => 'button',
      'label' => 'twofactor_webauthn.add_new'
    ]);

    $test_button = html::p([ 'class' => 'formbuttons footerleft' ], $rcmail->output->button([
      'command' => 'plugin.twofactor_webauthn_test',
      'class' => 'button status',
      'label' => 'twofactor_webauthn.test_key'
    ]));

    $table = new html_table([ 'cols' => 2, 'class' => 'propform' ]);

    $field_id = 'twofactor_activate';
    $checkbox_activate = new html_checkbox([ 'name' => $field_id, 'id' => $field_id, 'type' => 'checkbox' ]);
    $table->add('title', html::label($field_id, rcube::Q($this->gettext('activate'))));
    $table->add(null, $checkbox_activate->show($config['activate']==true?false:true));

    $field_id = 'twofactor_lock';
    $checkbox_lock = new html_checkbox([ 'name' => $field_id, 'id' => $field_id, 'type' => 'checkbox' ]);
    $hint = html::tag('div', [ 'class' => 'hint', 'style' => 'margin-top: -0.5rem' ], rcube::Q($this->gettext('lock_hint')));
    $table->add('title', html::label($field_id, rcube::Q($this->gettext('lock_config'))) . $hint);
    $table->add(null, $checkbox_lock->show($config['lock']==true?false:true));

    $rcmail->output->add_gui_object('webauthnform', 'twofactor_webauthn-form');
	  $form = $rcmail->output->form_tag([
	    'id' => 'twofactor_webauthn-form',
	    'name' => 'twofactor_webauthn-form',
	    'method' => 'post',
	    'action' => './?_task=settings&_action=plugin.twofactor_webauthn_save',
	  ], $table->show());

    $submit_button = html::p([ 'class' => 'formbuttons footerleft' ], $rcmail->output->button([
      'command' => 'plugin.twofactor_webauthn_save',
      'class' => 'button mainaction submit',
      'label' => 'save'
    ]));

    $title = html::div([ 'id' => 'prefs-title', 'class' => 'boxtitle' ], $this->gettext('twofactor_webauthn'));
    $keyscontent = html::div([ 'class' => 'boxcontent formcontent' ], $keys);
    $formcontent = html::div([ 'class' => 'boxcontent formcontent' ], $form);
    $box = html::div([ 'class' => 'box formcontainer scroller' ], $keyscontent . $test_button . $formcontent . $submit_button);

    $this->include_stylesheet('settings.css');
    $this->include_script('twofactor_webauthn.js');

  	return $title . $box;
	}

  private function getConfig() {
    $rcmail = rcmail::get_instance();
    $prefs = $rcmail->user->get_prefs();
    $config = $prefs['twofactor_webauthn'] ?? [];
    if (!isset($config['activate'])) $config['activate'] = false;
    if (!isset($config['lock'])) $config['lock'] = false;
    if (!isset($config['keys'])) $config['keys'] = '[]';
    return $config;
  }
  private function saveConfig($config) {
    $rcmail = rcmail::get_instance();
    $prefs = $rcmail->user->get_prefs();
    $prefs['twofactor_webauthn'] = $config;
    $rcmail->user->save_prefs($prefs);
  }
  private function getList($config = null) {
    if (!$config) $config = $this->getConfig();
    $list = [];
    foreach (json_decode($config['keys']) as $key) {
      $list[] = [ 'id' => dechex(crc32(implode('', $key->id))), 'name' => empty($key->name)?null:$key->name ];
    }
    return $list;
  }
}
