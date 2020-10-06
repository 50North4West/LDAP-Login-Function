<?php

  function ldapLogin($username, $password) {

    //make a connection to the LDAP server
    $connection = ldap_connect(LDAP_SERVER, LDAP_PORT);
    if (!$connection) {
      $result = 'false, Could not connect to the LDAP Server';
      return $result;
      exit;
    }

    //set LDAP protopcol version etc.
    ldap_set_option($connection , LDAP_OPT_PROTOCOL_VERSION, 3);
    ldap_set_option($connection , LDAP_OPT_REFERRALS, 0);

    //Send credentials
    $bind = @ldap_bind($connection, $username.LDAP_DOMAIN, $password);
    if (!$bind) {
      $result = 'false, Your credentials were incorrect';
      return $result;
      exit;
    }

    var_dump($bind);

    //Set filter attributes
    $filter = "(sAMAccountName=" . $username . ")";
    $attr = array("memberof", "cn", "givenname", "sn");

    //Do the search
    $search = ldap_search($connection, LDAP_DN, $filter, $attr);
    if (!$search) {
      $result = 'false, Unable to search the LDAP Server';
      return $result;
      exit;
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
        $_SESSION['userFullName'] = $entries[0]['givenname'][0];
        $result = 'true, Authenticated';
        return $result;
        exit;
      }

      //Member of Intranet Users
      if (strpos($commonNames, 'IntranetUsers')) {
        $_SESSION['userGroup'] = 'UsersGroup';
        $_SESSION['userFullName'] = $entries[0]['givenname'][0];
        $result = 'true, You have been successfully logged in';
        return $result;
        exit;
      }
    }

    //We got this far, no idea how; send false anyway
    $result = 'false, An unknown error occured';
    return $result;
    exit;
  }