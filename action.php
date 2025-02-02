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

if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');
require_once(DOKU_PLUGIN.'action.php');

class action_plugin_authplaincas extends DokuWiki_Action_Plugin {
  function getInfo() {
    return array (
      'author' => 'Fabian Bircher',
      'email' => 'fabian@esn.org',
      'date' => '2013-06-13',
      'name' => 'plain CAS Plugin',
      'desc' => 'Authenticate DokuWiki users via CAS',
    );
  }

  function register (Doku_Event_Handler $controller) {
      $controller->register_hook ('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_login_form'); // old < 2022 "igor"
      $controller->register_hook ('FORM_LOGIN_OUTPUT', 'BEFORE', $this, 'handle_login_form'); // new >= 2022 "igor"
      $controller->register_hook ('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_action');
      $controller->register_hook ('ACTION_ACT_PREPROCESS', 'AFTER', $this, 'handle_action_after');
      $controller->register_hook ('TPL_ACT_UNKNOWN', 'BEFORE', $this, 'handle_template');
  }

  function _self () {
    global $ID;
    return wl($ID, '', true, '');
  }

  function _selfdo ($do) {
    global $ID;
    return wl($ID, 'do=' . $do, true, '&');
  }

  function _redirect ($url) {
    header ('Location: ' . $url);
    exit;
  }

  function handle_login_form (&$event, $param) {
    global $auth;
    global $conf;
    global $lang;
    global $ID;

    if($conf['authtype'] == 'authplaincas') {

      if ($this->getConf('logourl') != '') {
        $caslogo = '<img src="'.$this->getConf('logourl').'" alt="" style="vertical-align: middle;" /> ';
      } else {
        $caslogo = '';
      }

      $form = $event->data;

      if (is_a($form, \dokuwiki\Form\Form::class)) {
        // new Form >= 2022 "igor"

        // remove default login form
        $nelement = $form->elementCount();
        for($pos=0; $pos<$nelement; $pos++) {
          $form->removeElement(0);
        }

        $form->addFieldsetOpen($this->getConf('name'));
        $href = $form->addTagOpen('a');
        $href->attr('href', $this->_selfdo('caslogin'));
        $form->addHTML($caslogo);
        // Add remember me checkbox using addCheckbox
        $form->addCheckbox('remember', $lang['remember_me']);
        $form->addHTML($lang['btn_login']);
        $form->addTagClose('a');
        $form->addFieldsetClose();

        if ($auth && $auth->canDo('modPass') && actionOK('resendpwd')) {
          $form->addHTML('<p>'.$lang['pwdforget'].': <a href="'.wl($ID,'do=resendpwd').'" rel="nofollow" class="wikilink1">'.$lang['btn_resendpwd'].'</a></p>');
        }

      } else {
        // old form < 2022 "igor" (kept for backward compatibility)

        //var_dump($event->data->_content);
        $event->data->_content = array(); // remove the login form

        $event->data->insertElement(0,'<fieldset><legend>'.$this->getConf('name').'</legend>');
        $event->data>insertElement(1, form_makeCheckboxField('remember', '1', $lang['remember_me'], 'remember', 'remember__me'));
        $event->data->insertElement(2,'<p style="text-align: center;"><a href="'.$this->_selfdo('caslogin').'"><div>'.$caslogo.'</div>'.$lang['btn_login'].'</a></p>');
        $event->data->insertElement(3,'</fieldset>');

        //instead of removing, one could implement a local login here...
        // if ($this->getConf('jshidelocal')) {
        // $event->data->insertElement(3,'<p id="normalLoginToggle" style="display: none; text-align: center;"><a href="#" onClick="javascript:document.getElementById(\'normalLogin\').style.display = \'block\'; document.getElementById(\'normalLoginToggle\').style.display = \'none\'; return false;">Show '.$this->getConf('localname').'</a></p><p style="text-align: center;">Only use this if you cannot use the '.$this->getConf('name').' above.</p>');
        // $event->data->replaceElement(4,'<fieldset id="normalLogin" style="display: block;"><legend>'.$this->getConf('localname').'</legend><script type="text/javascript">document.getElementById(\'normalLoginToggle\').style.display = \'block\'; document.getElementById(\'normalLogin\').style.display = \'none\';</script>');
      // } else {
        // $event->data->replaceElement(3,'<fieldset><legend>'.$this->getConf('localname').'</legend>');
      // }

        if ($auth && $auth->canDo('modPass') && actionOK('resendpwd')) {
          $event->data->insertElement(4,'<p>'.$lang['pwdforget'].': <a href="'.wl($ID,'do=resendpwd').'" rel="nofollow" class="wikilink1">'.$lang['btn_resendpwd'].'</a></p>');
        }
      }
    }
  }

  function handle_caslogin () {
    global $auth;
    $auth->logIn();
  }

  function handle_caslogout () {
    auth_logoff();
  }

  function handle_action (&$event, $param) {
    if ($event->data == 'caslogin') {
      $event->preventDefault();
      $this->handle_caslogin();
    }
    if ($event->data == 'logout') {
      $this->handle_caslogout();
    }
  }

  function handle_action_after (&$event, $param){
    global $ACT, $auth, $USERINFO, $MSG;

    if(
        (($ACT == 'denied' && empty($USERINFO)) || $ACT == 'login') &&
        $this->getConf('force_redirect') &&
        !($auth && $auth->canDo('modPass') && actionOK('resendpwd'))
      ){
        // check $MSG
        if(is_array($MSG)){
            foreach ($MSG as $m) {
              if($m && info_msg_allowed($m)){
                return;
                // Has messages, don't execute the redirector below
              }
            }
        }

        $this->handle_caslogin(); // will jump out if redirect is required
    }
  }

  function handle_template (&$event, $param) {
    if ($event->data == 'caslogin') {
      $event->preventDefault();
    }
  }
}
