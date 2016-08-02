<?php
/**
 * Plain CAS authentication plugin
 * 
 * @licence   GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author    Fabian Bircher
 * @version   0.0.2
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

require_once(DOKU_PLUGIN.'authplaincas/phpCAS/CAS.php');

class auth_plugin_authplaincas extends DokuWiki_Auth_Plugin {
  /** @var array user cache */
  protected $users = null;

  /** @var array filter pattern */
  protected $_pattern = array();
  
  var $_options = array();
  var $_userInfo = array();

  var $casuserfile = null;
  var $localuserfile = NULL;

  /**
   * Constructor
   *
   * Carry out sanity checks to ensure the object is
   * able to operate. Set capabilities.
   *
   * @author     Fabian Bircher <fabian@esn.org>
   */
  public function __construct() {
    parent::__construct();
    global $config_cascade;
    global $conf;
    
    // allow the preloading to configure other user files
    if( isset($config_cascade['plaincasauth.users']) && isset($config_cascade['plaincasauth.users']['default']) ) {
      $this->casuserfile = $config_cascade['plaincasauth.users']['default'];
    }
    else {
      $this->casuserfile = DOKU_CONF . 'users.auth.plaincas.php';
    }
    $this->localuserfile = $config_cascade['plainauth.users']['default'];

    // check the state of the file with the users and attempt to create it.
    if (!@is_readable($this->casuserfile)) {
      if(! fopen($this->casuserfile, 'w') ) {
        msg("plainCAS: The CAS users file could not be opened.", -1);
        $this->success = false;
      }
      elseif(!@is_readable($this->casuserfile)){
        $this->success = false;
      }
      else{
        $this->success = true;
      }
      // die( "bitch!" );
    }
    if ($this->success) {
      // the users are not managable through the wiki
      $this->cando['addUser']      = false;
      $this->cando['delUser']      = true;
      $this->cando['modLogin']     = false; //keep this false as CAS name is constant
      $this->cando['modPass']      = false;
      $this->cando['modName']      = false;
      $this->cando['modMail']      = false;
      $this->cando['modGroups']    = false;
      $this->cando['getUsers']     = true;
      $this->cando['getUserCount'] = true;

      $this->cando['external'] = true;
      $this->cando['login'] = true;
      $this->cando['logout'] = true;
      $this->cando['logoff'] = true;
      
      // The default options which need to be set in the settins file.
      $defaults = array(
        // 'server' => 'galaxy.esn.org',
        // 'rootcas' => '/cas',
        // 'port' => '443',
        // 'autologin' => false,
        // 'handlelogoutrequest' => true,
        // 'handlelogoutrequestTrustedHosts' => "galaxy.esn.org",
        // 'caslogout' => false,
        // 'minimalgroups' => NULL,
        // 'customgroups' => false,
        'logFile' => NULL,
        'cert' => NULL,
        'cacert' => NULL,
        'debug' => false,
        'settings_file' => DOKU_CONF . 'plaincas.settings.php',
        
        'defaultgroup' => $conf['defaultgroup'],
        'superuser' => $conf['superuser'],
        
      );
      $this->_options = (array) $conf['plugin']['authplaincas'] + $defaults;
      
      // Options are set in the configuration and have a proper default value there.
      $this->_options['server'] = $this->getConf('server');
      $this->_options['rootcas'] = $this->getConf('rootcas');
      $this->_options['port'] = $this->getConf('port');
      $this->_options['samlValidate'] = $this->getConf('samlValidate');
      $this->_options['handlelogoutrequest'] = $this->getConf('handlelogoutrequest');
      $this->_options['handlelogoutrequestTrustedHosts'] = $this->getConf('handlelogoutrequestTrustedHosts');
      $this->_options['minimalgroups'] = $this->getConf('minimalgroups');
      $this->_options['localusers'] = $this->getConf('localusers');
      // $this->_options['defaultgroup'] = $this->getConf('defaultgroup');
      // $this->_options['superuser'] = $this->getConf('superuser');

      // Configure support for autologin (gateway mode) and redirecting on logout for CAS server single-logout
      if (preg_match("#(bot)|(slurp)|(netvibes)#i", $_SERVER['HTTP_USER_AGENT'])) {
        // bots (like search engine indexers) should never be given 302 redirects
        $this->_options['autologin'] = false;
        $this->_options['caslogout'] = false;
      } elseif ($this->getConf('autologinout') == true) {
        // the "autologinout" configuration parameter enables both gateway mode and external CAS server logout
        $this->_options['autologin'] = true;
        $this->_options['caslogout'] = true;
      } else {
        // otherwise, fall back to the individual configuration parameters "autologin" and "caslogout"
        $this->_options['autologin'] = $this->getConf('autologin');
        $this->_options['caslogout'] = $this->getConf('caslogout');
      }

      // no local users at the moment
      $this->_options['localusers'] = false;
      
      if($this->_options['localusers'] && !@is_readable($this->localuserfile)) {
        msg("plainCAS: The local users file is not readable.", -1);
        $this->success = false;
      }
      
      if($this->_getOption("logFile")){ phpCAS::setDebug($this->_getOption("logFile"));} 
      //If $conf['auth']['cas']['logFile'] exist we start phpCAS in debug mode

      $server_version  = CAS_VERSION_2_0;
      if($this->_getOption("samlValidate")) {
          $server_version = SAML_VERSION_1_1;
      }
      phpCAS::client($server_version, $this->_getOption('server'), (int) $this->_getOption('port'), $this->_getOption('rootcas'), true);
      //Note the last argument true, to allow phpCAS to change the session_id so he will be able to destroy the session after a CAS logout request - Enable Single Sign Out

      // curl extension is needed
      if(!function_exists('curl_init')) {
        if ($this->_getOption('debug')) {
          msg("CAS err: CURL extension not found.",-1,__LINE__,__FILE__);
        }
        $this->success = false;
        return;
      }

      // when using autologin (gateway mode), how often will autologin be attempted
      if ($this->getConf('autologinonce', false)) {
        // cache a failed autologin attempt "forever" until the current
        // anonymous session expires or the user clicks the login button
        phpCAS::setCacheTimesForAuthRecheck(-1);
      } else {
        // retry autologin every pageview, but cache a failed gateway attempt 1
        // time, to avoid a second gateway attempt on the indexer.php page
        // asset on the same pageview
        phpCAS::setCacheTimesForAuthRecheck(1);
      }

      if($this->_getOption('cert')) {
        phpCAS::setCasServerCert($this->_getOption('cert'));
      }
      elseif($this->_getOption('cacert')) {
        phpCAS::setCasServerCACert($this->_getOption('cacert'));
      }
      else {
        phpCAS::setNoCasServerValidation();
      }

      if($this->_getOption('handlelogoutrequest')) {
        phpCAS::handleLogoutRequests(true, $this->_getOption('handlelogoutrequestTrustedHosts'));
      }
      else {
        phpCAS::handleLogoutRequests(false);
      }
      
      if (@is_readable($this->_getOption('settings_file'))) {
        include_once($this->_getOption('settings_file'));
      }
      else {
        include_once(DOKU_PLUGIN . 'authplaincas/plaincas.settings.php');
      }
      
    }
    //
  }
    
  function _getOption ($optionName)
  {
    if (isset($this->_options[$optionName])) {
      switch( $optionName ){
        case 'minimalgroups':
        case 'superusers':
          if (!$this->_options[$optionName]) {
            return null;
          }
        case 'handlelogoutrequestTrustedHosts':
          $arr = explode(',', $this->_options[$optionName]);
          foreach( $arr as $key => $item ){
            $arr[$key] = trim($item);
          }
          return $arr;
          break;
        default:
          return $this->_options[$optionName];
      }
    }
    return NULL;
  }
  
  /**
   * Inherited canDo function, may be useful for localusers
   *
   * @param string $cap
   * @return bool
   */
  public function canDo($cap) {
    // We might need to do something to redefine the capabilities for local users
    return parent::canDo($cap);
  }

  public function logIn() {
    global $QUERY;
    $login_url = DOKU_URL . 'doku.php?id=' . $QUERY;
    phpCAS::setFixedServiceURL($login_url);
    phpCAS::forceAuthentication();
  }
    
  public function logOff() {
    global $QUERY;
    
    if($this->_getOption('caslogout')) { // dokuwiki + cas logout
      @session_start();
      session_destroy();
      $logout_url = DOKU_URL . 'doku.php?id=' . $QUERY;
      phpCAS::logoutWithRedirectService($logout_url);
    }
    else { // dokuwiki logout only
      @session_start();
      session_destroy();
      unset($_SESSION['phpCAS']);
    }
    
  }
  
function trustExternal ($user,$pass,$sticky=false)
  {
    global $USERINFO;
    $sticky ? $sticky = true : $sticky = false; //sanity check
    
    if (phpCAS::isAuthenticated() || ( $this->_getOption('autologin') && phpCAS::checkAuthentication() )) {

      $remoteUser = phpCAS::getUser();
      $this->_userInfo = $this->getUserData($remoteUser);
      // msg(print_r($this->_userInfo,true) . __LINE__);
      
      // Create the user if he doesn't exist
      if ($this->_userInfo === false) {
        $attributes = plaincas_user_attributes(phpCAS::getAttributes());
        $this->_userInfo = array(              
          'uid' => $remoteUser, 
          'name' => $attributes['name'], 
          'mail' => $attributes['mail']
        );
        
        $this->_assembleGroups($remoteUser);
        $this->_saveUserGroup();
        $this->_saveUserInfo();

        // msg(print_r($this->_userInfo,true) . __LINE__);
        
        $USERINFO = $this->_userInfo;
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $USERINFO['uid'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SERVER['REMOTE_USER'] = $USERINFO['uid'];
        return true;

      // User exists, check for updates
      } else {
        $this->_userInfo['uid'] = $remoteUser;
        $this->_assembleGroups($remoteUser);

        $attributes = plaincas_user_attributes(phpCAS::getAttributes());

        if ($this->_userInfo['grps'] != $this->_userInfo['tmp_grps'] ||
            $attributes['name'] !== $this->_userInfo['name'] ||
            $attributes['mail'] !== $this->_userInfo['mail']
            ) {
          //msg("new roles, email, or name");
          $this->deleteUsers(array($remoteUser));
          $this->_userInfo = array(              
            'uid' => $remoteUser, 
            'name' => $attributes['name'], 
            'mail' => $attributes['mail']
          );
          $this->_assembleGroups($remoteUser);
          $this->_saveUserGroup();
          $this->_saveUserInfo();
        }

        $USERINFO = $this->_userInfo;
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $USERINFO['uid'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SERVER['REMOTE_USER'] = $USERINFO['uid'];
          
        return true;
      }
      
    }
    // else{
    // }

    return false;
  }


  function _assembleGroups($remoteUser) {
  
    $this->_userInfo['tmp_grps'] = array();
    
    if (NULL !== $this->_getOption('defaultgroup')) {
      $this->_addUserGroup($this->_getOption('defaultgroup'));
    }
    
    if ((NULL !== $this->_getOption('superusers')) && 
          is_array($this->_getOption('superusers')) && 
          in_array($remoteUser, $this->_getOption('superusers'))) {
          
      $this->_addUserGroup($this->_getOption('admingroup'));
    }
    
    $this->_setCASGroups();
    $this->_setCustomGroups($remoteUser);
  }


  function _setCASGroups ()
  {
    if( phpCAS::checkAuthentication() ) {
      $attributes = plaincas_pattern_attributes(phpCAS::getAttributes());
      if (!is_array($attributes)) {
        $attributes = array($attributes);
      }
      $patterns = plaincas_group_patterns();
      if (!empty($patterns)) {
        foreach ($patterns as $role => $pattern) {
          foreach ($attributes as $attribute) {
            // An invalid pattern will generate a php warning and will not be considered.
            if (preg_match($pattern, $attribute)) { 
              $this->_addUserGroup($role);
            }
          }
        }
      }
      else {
        foreach ($attributes as $attribute) {
          // Add all attributes as groups
          $this->_addUserGroup($attribute);
        }
      }
    }
  }


  function _setCustomGroups ($userId)
  {
    // assert existence of function for backwards compatibility
    if (!function_exists('plaincas_custom_groups')) {
      return;
    }
    $customGroups = plaincas_custom_groups();
    
    if (! is_array($customGroups) || empty($customGroups)) {
      return;
    }
    
    foreach ($customGroups as $groupName => $groupMembers) {
      if (! is_array($groupMembers) || empty($groupMembers)) {
        continue;
      }      
      if (in_array($userId, $groupMembers)) {
        $this->_addUserGroup($groupName);
      }
    }

  }


  function _addUserGroup ($groupName)
  {
    if (! isset($this->_userInfo['tmp_grps'])) {
      $this->_userInfo['tmp_grps'] = array();
    }
    if( !in_array(trim($groupName), $this->_userInfo['tmp_grps'])) {
      $this->_userInfo['tmp_grps'][] = trim($groupName);
    }
      
  }
  
  function _saveUserGroup()
  {
    $this->_userInfo['grps'] = $this->_userInfo['tmp_grps'];
  }

  function _minimalGroupCheck() {
    $groups = $this->_getOption('minimalgroups');
    if( ! $groups || empty($groups) ) {
      return true;
    }
    elseif (count( array_intersect( $this->_userInfo['grps'], $groups  ) )) {
      return true;
    }
    else {
      return false;
    }
  
  }

  function _saveUserInfo ()
  { 
    $save = true;
    if(!$this->_minimalGroupCheck()) {
      $save = false;
      $this->_userInfo['grps'] = array();
      $this->_userInfo['tmp_grps'] = array();
    }
    global $USERINFO;
    
    $USERINFO = $this->_userInfo;
    $_SESSION[DOKU_COOKIE]['auth']['user'] = $USERINFO['uid'];
    $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
    
    // Despite setting the user into the session, DokuWiki still uses hard-coded REMOTE_USER variable    
    $_SERVER['REMOTE_USER'] = $USERINFO['uid'];

    // user mustn't already exist
    if ($this->getUserData($USERINFO['uid']) === false && $save) {
      // prepare user line
      $groups = join(',',$USERINFO['grps']);
      $userline = join(':',array($USERINFO['uid'], $USERINFO['name'], $USERINFO['mail'], $groups))."\n";

      if (io_saveFile($this->casuserfile,$userline,true)) {
        $this->users[$USERINFO['uid']] = compact('name','mail','grps');
      }else{
        msg('The '.$this->casuserfile.' file is not writable. Please inform the Wiki-Admin',-1);
      }
    }
    $this->_log($this->_userInfo);
  }


  function _log ($value)
  {
    if ($this->_getOption('debug')) {
      error_log(print_r($value, true));
      var_dump($value);
    }
  }

  /**
   * Modify user data
   *
   * @author  Chris Smith <chris@jalakai.co.uk>
   * @param   $user      nick of the user to be changed
   * @param   $changes   array of field/value pairs to be changed (password will be clear text)
   * @return  bool
   */
  function modifyUser($user, $changes) {
    global $conf;

    // sanity checks, user must already exist and there must be something to change
    if (($userinfo = $this->getUserData($user)) === false) return false;
//      if (!(count($changes) == 1 and isset($changes['grps']))) return false;
    if (!is_array($changes) || !count($changes)) return true;

    foreach ($changes as $field => $value) {
      $userinfo[$field] = $value;
    }

    $groups = join(',',$userinfo['grps']);
    $userline = join(':',array($user, $userinfo['name'], $userinfo['mail'], $groups))."\n";

    if (!$this->deleteUsers(array($user))) {
      msg('Unable to modify user data. Please inform the Wiki-Admin',-1);
      return false;
    }

    if (!io_saveFile($this->casuserfile,$userline,true)) {
      msg('There was an error modifying the user data. Please inform the Wiki-Admin.',-1);
      return false;
    }

    $this->users[$user] = $userinfo;
    return true;
  }

  /**
   *  Remove one or more users from the list of registered users
   *
   *  @author  Christopher Smith <chris@jalakai.co.uk>
   *  @param   array  $users   array of users to be deleted
   *  @return  int             the number of users deleted
   */
  function deleteUsers($users) {
    if (!is_array($users) || empty($users)) return 0;

    if ($this->users === null) $this->_loadUserData();

    $deleted = array();
    foreach ($users as $user) {
      if (isset($this->users[$user])) $deleted[] = preg_quote($user,'/');
    }

    if (empty($deleted)) return 0;

    $pattern = '/^('.join('|',$deleted).'):/';

    if (io_deleteFromFile($this->casuserfile,$pattern,true)) {
      foreach ($deleted as $user) unset($this->users[$user]);
      return count($deleted);
    }

    // problem deleting, reload the user list and count the difference
    $count = count($this->users);
    $this->_loadUserData();
    $count -= count($this->users);
    return $count;
  }

  
  /**
   * Return user info
   *
   * Returns info about the given user needs to contain
   * at least these fields:
   *
   * name string  full name of the user
   * mail string  email addres of the user
   * grps array   list of groups the user is in
   *
   * @author  Andreas Gohr <andi@splitbrain.org>
   */
  function getUserData($user){
    if($this->users === null) $this->_loadUserData();
    return isset($this->users[$user]) ? $this->users[$user] : false;
  }

  /**
   * Load all user data
   *
   * loads the user file into a datastructure
   *
   * @author  Andreas Gohr <andi@splitbrain.org>
   * @author  Martin Kos <martin@kos.li>
   */
  function _loadUserData(){
    $this->users = array();

    if(!@file_exists($this->casuserfile)) return;

    $lines = file($this->casuserfile);
    foreach($lines as $line){
      $line = preg_replace('/#.*$/','',$line); //ignore comments
      $line = trim($line);
      if(empty($line)) continue;

      $row    = explode(":",$line,5);
      $groups = explode(",",$row[3]);
      // msg(print_r($row,true). __LINE__);

      $this->users[$row[0]]['name'] = $row[1];
      $this->users[$row[0]]['mail'] = $row[2];
      $this->users[$row[0]]['grps'] = $groups;
    }
  }
  
  
  /**
   * Return a count of the number of user which meet $filter criteria
   *
   * @author  Chris Smith <chris@jalakai.co.uk>
   */
  function getUserCount($filter=array()) {

    if($this->users === null) $this->_loadUserData();

    if (!count($filter)) return count($this->users);

    $count = 0;
    $this->_constructPattern($filter);

    foreach ($this->users as $user => $info) {
      $count += $this->_filter($user, $info);
    }

    return $count;
  }

  /**
   * Bulk retrieval of user data
   *
   * @author  Chris Smith <chris@jalakai.co.uk>
   * @param   start     index of first user to be returned
   * @param   limit     max number of users to be returned
   * @param   filter    array of field/pattern pairs
   * @return  array of userinfo (refer getUserData for internal userinfo details)
   */
  function retrieveUsers($start=0,$limit=0,$filter=array()) {
    if ($this->users === null) $this->_loadUserData();

    ksort($this->users);

    $i = 0;
    $count = 0;
    $out = array();
    $this->_constructPattern($filter);

    foreach ($this->users as $user => $info) {
      if ($this->_filter($user, $info)) {
        if ($i >= $start) {
          $out[$user] = $info;
          $count++;
          if (($limit > 0) && ($count >= $limit)) break;
        }
        $i++;
      }
    }

    return $out;
  }
  
  function cleanUser($user) {
    $user = str_replace('@', '_', $user);
    $user = str_replace(':', '_', $user);
    return $user;
  }

  function cleanGroup($group) {
    return $group;
  }

  /**
   * return 1 if $user + $info match $filter criteria, 0 otherwise
   *
   * @author   Chris Smith <chris@jalakai.co.uk>
   */
  function _filter($user, $info) {
    // FIXME
    foreach ($this->_pattern as $item => $pattern) {
      if ($item == 'user') {
        if (!preg_match($pattern, $user)) return 0;
      } else if ($item == 'grps') {
        if (!count(preg_grep($pattern, $info['grps']))) return 0;
      } else {
        if (!preg_match($pattern, $info[$item])) return 0;
      }
    }
    return 1;
  }

  function _constructPattern($filter) {
    $this->_pattern = array();
    foreach ($filter as $item => $pattern) {
//        $this->_pattern[$item] = '/'.preg_quote($pattern,"/").'/i';          // don't allow regex characters
      $this->_pattern[$item] = '/'.str_replace('/','\/',$pattern).'/i';    // allow regex characters
    }
  }

}
