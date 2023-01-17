#!/usr/bin/env php
<?php
/*
 +-----------------------------------------------------------------------+
 | This file is part of the twofactor_webauthn plugin                    |
 |                                                                       |
 | Copyright (C) The Roundcube Dev Team                                  |
 | Copyright (C) Kolab Systems AG                                        |
 | Copyright (C) 2023 Bart Noordervliet                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 |                                                                       |
 | PURPOSE:                                                              |
 |   Disable 2-factor authentication for a user in case they've been     |
 |   locked out.                                                         |
 +-----------------------------------------------------------------------+
 | Author: Bart Noordervliet <bart@mmvi.nl>                              |
 +-----------------------------------------------------------------------+
*/

define('INSTALL_PATH', realpath(__DIR__ . '/../../') . '/');

require INSTALL_PATH . 'program/include/clisetup.php';

$rcmail = rcube::get_instance();

if (empty($_SERVER['argv'][1])) {
    print_usage();
    exit;
}

function print_usage() {
    print "Usage: " . $_SERVER['argv'][0] . " <username> [hostname]\n";
    print "  [hostname] corresponds to the imap_host config item in Roundcube\n";
    print "             where the username is valid; defaults to 'localhost'\n";
}

function get_user($username, $host) {
    global $rcmail;

    $db = $rcmail->get_dbh();

    // find user in local database
    $user = rcube_user::query($username, $host);

    if (empty($user)) {
        rcube::raise_error("User does not exist: $username");
        exit;
    }

    return $user;
}

$username = $_SERVER['argv'][1];
$user = get_user($username, $_SERVER['argv'][2] ?? 'localhost');
$prefs = $user->get_prefs();
if (empty($prefs['twofactor_webauthn'])) {
    rcube::raise_error("MFA not configured for user $username");
    exit;
}
if ($prefs['twofactor_webauthn']['activate']) {
  $prefs['twofactor_webauthn']['activate'] = false;
  print "MFA disabled for user $username\n";
}
else {
  if (count($prefs['twofactor_webauthn']['keys']) < 1) {
    rcube::raise_error("Cannot enable MFA (no keys configured)");
    exit;
  }
  $prefs['twofactor_webauthn']['activate'] = true;
  print "MFA enabled for user $username\n";
}
$user->save_prefs($prefs);
