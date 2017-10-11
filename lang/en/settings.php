<?php
$lang['name'] = 'CAS login service name';
$lang['logourl'] = 'URL to a logo for the CAS service. If serving login pages via HTTPS, make sure this is either relative (/...) or an HTTPS URL.';
//$lang['localname'] = 'Local login service name';
//$lang['jshidelocal'] = 'Use JavaScript to hide the local login form until required?';

$lang['server'] = 'CAS server hostnamme (cas.example.com)';
$lang['port'] = 'CAS server port (443)';
$lang['rootcas'] = 'CAS server uri (/cas)';



$lang['handlelogoutrequest'] = 'handle CAS logout requests';
$lang['handlelogoutrequestTrustedHosts'] = 'trusted hosts for logout requests';

$lang['autologin'] = 'login automatically';

$lang['localusers'] = 'Allow local users (authplain list) -> switch athentication to "authplain" to manage the userlist';
$lang['minimalgroups'] = 'Comma separated list of groups of which a CAS user needs at least one to be created in the system. (group1, group2) leave empty to allow all users.';

$lang['force_redirect'] = 'Redirect user to CAS if permission is required or ACT=login (no login message)';
