<?php
/*
 * The function plaincas_group_patterns has to return an array
 * with the groups as keys and the corresponding regular expressions as values.
 * Other groups can be assigned with the custom groups. 
 */
function plaincas_group_patterns() {
  $casGroups = array(
    //'manager' => '/^(International\.(webProjectAdministrator|ITChair))$/',
    'manager' => '/^([A-Z]{2}-[A-Z]{4}-[A-Z]{3}_International\.(webProjectAdministrator|ITChair))$/',
  );
  
  return $casGroups;
}

/*
 * The function plaincas_pattern_attributes has to return an array
 * with the CAS attributes which will be matched against the regular expressions
 * $attributes = phpCAS::getAttributes();
 */
function plaincas_pattern_attributes( $attributes ){
  $matchAttributes = array();

  // in this example the attribute 'roles' is an array
  // and all of the elements will be prepended by the attribute 'sc'
  $roles = $attributes['roles'];
  $section = $attributes['sc'];

  foreach ($roles as $role) {
    $matchAttributes[] = $section . '_' . $role;
  }

  // finally the array is returned.
  return $matchAttributes;
}

/*
 * The function plaincas_user_attributes has to return an array
 * with keys 'name' and 'mail' representing the user.
 * $attributes = phpCAS::getAttributes();
 */
function plaincas_user_attributes( $attributes ){
  return array(
    'name' => $attributes['first'] . ' ' . $attributes['last'], 
    'mail' => $attributes['mail'],
  );
}


