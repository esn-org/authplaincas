<?php
/*
 * Pure CAS login
 *
 * The CAS authenticated users are being stored, so that dokuwiki
 * can display their name and mail address in the revision history.
 *
 * @author		Fabian Bircher <fabian@esn.org>
 * @license		GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @copyright	Fabian Bircher 2012-11-26
 * @version		0.1.0
 *
 */
 

define('DOKU_AUTH', dirname(__FILE__));

define('PLAINCAS_AUTH_USERFILE',DOKU_CONF.'users.auth.plaincas.php');

//require_once(DOKU_INC.'inc/auth/plain.class.php');
include_once(DOKU_INC.'inc/phpCAS/CAS.php');

class auth_plaincas extends auth_basic
{
  
  var $_options = array();
  var $_userInfo = array();
  var $users = null;

  function __construct() {
		global $conf;
    parent::__construct();
    
    //session_destroy();
    
    if (!@is_readable(PLAINCAS_AUTH_USERFILE)) {
      if(! fopen(PLAINCAS_AUTH_USERFILE, 'w') ) {
        $this->success = false;
      }
      elseif(!@is_readable(PLAINCAS_AUTH_USERFILE)){
        $this->success = false;
      }
      else{
        $this->success = true;
      }
      // die( "bitch!" );
    }
    if($this->success){
      
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

      $this->cando['external'] = (preg_match("#(bot)|(slurp)|(netvibes)#i", $_SERVER['HTTP_USER_AGENT'])) ? false : true; //Disable CAS redirection for bots/crawlers/readers
      $this->cando['login'] = true;
      $this->cando['logout'] = true;
      $this->cando['logoff'] = true;
      
      $defaults = array(
          'server' => '', 
          'rootcas' => '/', 
          'port' => '443', 
          'autologin' => false, 
          'handlelogoutrequest' => true, 
          'handlelogoutrequestTrustedHosts' => '', 
          'caslogout' => false, 
          'logFile' => NULL,
          'cert' => NULL, 
          'cacert' => NULL, 
          'debug' => false,
          'superusers' => NULL, 
          'defaultgroup' => $conf['defaultgroup'], 
          'admingroup' => 'admin',
          'settings_file' => DOKU_CONF . 'plaincas.settings.php',
          'minimalgroups' => NULL,
          'customgroups' => false, 
          'customgroups_file' => DOKU_CONF . 'custom_groups.php', 
      );
        
      $this->_options = (array) $conf['auth']['plaincas'] + $defaults;
      
      if($this->_getOption("logFile")){ phpCAS::setDebug($this->_getOption("logFile"));} 
      //If $conf['auth']['cas']['logFile'] exist we start phpCAS in debug mode

      phpCAS::client(CAS_VERSION_2_0, $this->_getOption('server'), (int) $this->_getOption('port'), $this->_getOption('rootcas'), true); 
      //Note the last argument true, to allow phpCAS to change the session_id so he will be able to destroy the session after a CAS logout request - Enable Single Sign Out

      // curl extension is needed
      if(!function_exists('curl_init')) {
          if ($this->_getOption('debug'))
              msg("CAS err: CURL extension not found.",-1,__LINE__,__FILE__);
          $this->success = false;
          return;
      }
      // automatically log the user when there is a cas session opened
      if($this->_getOption('autologin')) {
          phpCAS::setCacheTimesForAuthRecheck(1);
      }
      else {
          phpCAS::setCacheTimesForAuthRecheck(-1);
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
          include_once(DOKU_AUTH . '/plaincas.settings.php');
      }
    }
  }
   
	public function autoLogin() {
  
	}
  
  function _getOption ($optionName)
  {
    if (isset($this->_options[$optionName])) {
      switch( $optionName ){
        case 'superusers':
        case 'minimalgroups':
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
    
    if ((phpCAS::isAuthenticated() || $this->_getOption('autologin') ) && phpCAS::checkAuthentication()) {

      $remoteUser = phpCAS::getUser();
      // Create the user if he doesn't exist
      $this->_userInfo = $this->getUserData($remoteUser);
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

        $USERINFO = $this->_userInfo;
        $_SESSION[DOKU_COOKIE]['auth']['user'] = $USERINFO['uid'];
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
        $_SERVER['REMOTE_USER'] = $USERINFO['uid'];
        return true;
      
      }else {
        $this->_userInfo['uid'] = $remoteUser;
        $this->_assembleGroups($remoteUser);
        if( $this->_userInfo['grps'] != $this->_userInfo['tmp_grps'])
        {
          //msg("new roles");
          $this->deleteUsers(array($remoteUser));
          $attributes = plaincas_user_attributes(phpCAS::getAttributes());
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
    if (! $this->_getOption('customgroups')) {
      return;
    }
    
    $groupsFile = $this->_getOption('customgroups_file');
    if (! file_exists($groupsFile)) {
      $this->_log(sprintf("Non-existent custom groups file '%s'.", $groupsFile));
      return;
    }
    
    $customGroups = array();
    @include $groupsFile;
    // include $groupsFile;
    
    if (! isset($customGroups)) {
      $this->_log('Custom groups variable not found.');
      return;
    }
    
    if (! is_array($customGroups) || empty($customGroups)) {
      $this->_log('No custom groups specified.');
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


  function _saveUserInfo ()
  { 
    $save = true;
    if($this->_getOption('minimalgroups') && ( ! count( array_intersect( $this->_userInfo['grps'], $this->_getOption('minimalgroups' ) ) ) ) ) {
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

      if (io_saveFile(PLAINCAS_AUTH_USERFILE,$userline,true)) {
        $this->users[$USERINFO['uid']] = compact('name','mail','grps');
      }else{
        msg('The '.PLAINCAS_AUTH_USERFILE.' file is not writable. Please inform the Wiki-Admin',-1);
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

    if (!io_saveFile(PLAINCAS_AUTH_USERFILE,$userline,true)) {
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

    if (io_deleteFromFile(PLAINCAS_AUTH_USERFILE,$pattern,true)) {
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

    if(!@file_exists(PLAINCAS_AUTH_USERFILE)) return;

    $lines = file(PLAINCAS_AUTH_USERFILE);
    foreach($lines as $line){
      $line = preg_replace('/#.*$/','',$line); //ignore comments
      $line = trim($line);
      if(empty($line)) continue;

      $row    = split(":",$line,5);
      $groups = split(",",$row[3]);

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

