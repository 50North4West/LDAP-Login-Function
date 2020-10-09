<?php

  //LDAP params
  define('LDAP_SERVER', '');
  define('LDAP_DOMAIN', '');
  define('LDAP_PORT', 389);
  define('LDAP_DN', '');
  define('LDAP_USER', '');
  define('LDAP_PSWD', '');

  function ldapLogin() {

	 //make a connection to the LDAP server
    $connection = ldap_connect(LDAP_SERVER, LDAP_PORT);
    if (!$connection) {
      $result = 'false, Could not connect to the LDAP Server';
      return $result;
    }

    //set LDAP protopcol version etc.
    ldap_set_option($connection , LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($connection , LDAP_OPT_REFERRALS, 0);

    //Send credentials
    $bind = @ldap_bind($connection, LDAP_USER.LDAP_DOMAIN, LDAP_PSWD);
    if (!$bind) {
      $result = 'false, Your credentials were incorrect';
      return $result;
    }

    //Set filter attributes
	$user = substr(strrchr($_SERVER['AUTH_USER'], '\\'), 1); //Get the logged in username
    $filter = "(sAMAccountName=" . $user . ")";
    $attr = array("memberof", "cn", "givenname", "sn");

    //Do the search
    $search = ldap_search($connection, LDAP_DN, $filter, $attr);
    if (!$search) {
      $result = 'false, Unable to search the LDAP Server';
      return $result;
    }

    //Iterate through the entries and check membership
    $entries = ldap_get_entries($connection, $search);
    $givenname = $entries[0]['givenname'][0];

    //Shut the connection the LDAP server
    ldap_unbind($connection);

    //Check membership status and set session data
    foreach($entries[0]['memberof'] as $commonNames)
    {
      //Member of Intranet Admins
      if (strpos($commonNames, 'IntranetAdmin')) {
        $_SESSION['userGroup'] = 'AdminGroup';
        $_SESSION['userFirstName'] = $entries[0]['givenname'][0];
		$_SESSION['userFullName'] = $entries[0]['givenname'][0].' '.$entries[0]['sn'][0];
        $result = 'true, Authenticated';
        return $result;
      }

      //Member of Intranet Users
      if (strpos($commonNames, 'IntranetUsers')) {
        $_SESSION['userGroup'] = 'UsersGroup';
        $_SESSION['userFirstName'] = $entries[0]['givenname'][0];
		$_SESSION['userFullName'] = $entries[0]['givenname'][0].' '.$entries[0]['sn'][0];
        $result = 'true, You have been successfully logged in';
        return $result;
      }

	  $_SESSION['userGroup'] = 'NoGroup';
	  $_SESSION['userFirstName'] = $entries[0]['givenname'][0];
	  $_SESSION['userFullName'] = $entries[0]['givenname'][0].' '.$entries[0]['sn'][0];
    }

    //We got this far, no idea how; send false anyway
    $result = 'false, An unknown error occured';
    return $result;
  }