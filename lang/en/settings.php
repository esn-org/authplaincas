<?php
$lang['name'] = 'CAS login service name';
$lang['logourl'] = 'URL to a logo for the CAS service. If serving login pages via HTTPS, make sure this is either relative (/...) or an HTTPS URL.';
//$lang['localname'] = 'Local login service name';
//$lang['jshidelocal'] = 'Use JavaScript to hide the local login form until required?';

$lang['server'] = 'CAS server hostnamme (cas.example.com)';
$lang['port'] = 'CAS server port (443)';
$lang['rootcas'] = 'CAS server uri (/cas)';



$lang['handlelogoutrequest'] = 'Handle logout requests';
$lang['handlelogoutrequestTrustedHosts'] = 'trusted hosts for logout requests';

// $lang['autologin'] = 'login automatically';
// $lang['caslogout'] = 'CAS logout on server';
// an additional switch for logging out would need to be set otherwise the user will be loged in again after the logout.
$lang['autologinout'] = 'login automatically and logout from CAS';

$lang['localusers'] = 'Allow local users (authplain list) -> switch athentication to "authplain" to manage the userlist';
$lang['minimalgroups'] = 'Comma separated list of groups of which a CAS user needs at least one to be created in the system. (group1, group2) leave empty to allow all users.';
