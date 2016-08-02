<?php
/*
 * The function plaincas_group_patterns has to return an array
 * with the groups as keys and the corresponding regular expressions as values.
 * Other groups can be assigned with the custom groups. 
 */
function plaincas_group_patterns() {
  $groups = array(
    'group1' => '/^(some-attribute)$/',
    
  );
  
  return $groups;
}

/*
 * The function plaincas_pattern_attributes has to return an array
 * with the CAS attributes which will be matched against the regular expressions
 * $attributes = phpCAS::getAttributes();
 */
function plaincas_pattern_attributes( $attributes ){
  if (is_array($attributes['roles'])) {
    return $attributes['roles'];
  }
  else {
    return array($attributes['roles']);
  }
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

/*
 * The function plaincas_custom_groups has to return an array
 * with groupnames as keys and an array or usernames.
 * 
 * Custom groups are independent of CAS attributes or groups but the group names can be the same.
 */
function plaincas_custom_groups(){
  
  $groups = array(
    'group1' => array('username1', 'userame2'),
    'group2' => array('username3', 'userame4'),
  );

  return $groups;
}


