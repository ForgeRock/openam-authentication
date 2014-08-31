<?php 
/*
Plugin Name: OpenAM Authentication
Plugin URI: http://www.forgerock.org
Description: This plugin is used to authenticate users using OpenAM. The plugin uses REST calls to the OpenAM. The required REST APIs are: /json/authenticate; /json/users/ and /json/sessions. Therefore you need OpenAM 11.0 and above.
Version: 0.6
Author: Victor info@forgerock.com, openam@forgerock.org (subscribe to mailing list firt)
Author URI: http://www.forgerok.com/
*/

/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at http://forgerock.org/projects/cddlv1-0/. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014 ForgeRock AS.
 */


add_filter( 'authenticate',   'openam_auth', 10, 3 );
add_action( 'admin_menu',     'openam_rest_plugin_menu' );
add_filter( 'logout_url',     'openam_logout', 10,2 );
add_filter( 'login_url',      'openam_login_url',10,2 );
 
// Options
// OpenAM General configuration parameters
add_option( 'openam_rest_enabled',                 0 );
add_option( 'openam_cookie_name',                  'iPlanetDirectoryPro' );
add_option( 'openam_base_url',                     'https://openam.example.com:443/openam' );
add_option( 'openam_realm',                        '' );
add_option( 'openam_authn_module',                 '' );
add_option( 'openam_service_chain',                '' );
add_option( 'openam_logout_too',                   0);
add_option( 'openam_wordpress_attributes',         'uid,mail' );
add_option( 'openam_do_redirect',                   0);

// Constants
// OpenAM General Configuration parameters
define( 'OPENAM_REST_ENABLED',                      get_option( 'openam_rest_enabled' ) );
define( 'OPENAM_COOKIE_NAME',                       get_option( 'openam_cookie_name' ) );
define( 'OPENAM_BASE_URL',                          get_option( 'openam_base_url' ) );
define( 'OPENAM_REALM',                             get_option( 'openam_realm' ) );
define( 'OPENAM_AUTHN_MODULE',                      get_option( 'openam_authn_module' ) );
define( 'OPENAM_SERVICE_CHAIN',                     get_option( 'openam_service_chain' ) );
define( 'OPENAM_WORDPRESS_ATTRIBUTES',              get_option( 'openam_wordpress_attributes' ) );
define( 'OPENAM_LOGOUT_TOO',                        get_option( 'openam_logout_too' ) );
define( 'OPENAM_DO_REDIRECT',                       get_option( 'openam_do_redirect' ) );

// OpenAM API endpoints
define( 'OPENAM_AUTHN_URI',                         '/json/authenticate' );
define( 'OPENAM_ATTRIBUTES_URI',                    '/json/users/' );
define( 'OPENAM_SESSION_URI',                       '/json/sessions/' );

// Other constants
define( 'REALM_PARAM',                              'realm');
define( 'SERVICE_PARAM',                            'service');
define( 'MODULE_PARAM',                             'module');
define( 'AUTH_TYPE',                                'authIndexType');
define( 'AUTH_VALUE',                               'authIndexValue');
define( 'DOMAIN',                                   substr($_SERVER['HTTP_HOST'], strpos($_SERVER['HTTP_HOST'], '.')));

/* Main function */
function openam_auth($user, $username, $password) {

    if (OPENAM_REST_ENABLED) {
        // Let's see if the user is already logged in the IDP
        $tokenId = $_COOKIE[OPENAM_COOKIE_NAME];
        if (!empty($tokenId) AND !is_user_logged_in()) {
            if (($_GET['action'] != 'logout') OR ($_GET['loggedout'] != 'yes')) {
            $am_response = isSessionValid($tokenId);
            if ($am_response['valid'] or $am_response['valid' == 'true']) { // Session was valid
                $amAttributes = getAttributesFromOpenAM($tokenId, $am_response['uid'], OPENAM_WORDPRESS_ATTRIBUTES);
                $user = loadUser($amAttributes['uid'][0], $amAttributes['mail'][0]);
                remove_action('authenticate', 'wp_authenticate_username_password', 20);
                return $user;
            }
            }
        }

        // If no username nor password, then we are starting here
        if ($username != '' and $password != '') {

            $tokenId = authenticateWithOpenAM($username, $password);
            if (!$tokenId) {
                // User does not exist,  send back an error message
                $user = new WP_Error('denied', __("<strong>ERROR</strong>: The combination username/password was not correct"));
            } elseif ($tokenId == 2) {
                $user = new WP_Error('denied', __("<strong>ERROR</strong>: Error when trying to reach the OpenAM"));
            } else {
                $amAttributes = getAttributesFromOpenAM($tokenId, $username, OPENAM_WORDPRESS_ATTRIBUTES);
                if ($amAttributes) {
                    $user = loadUser($amAttributes['uid'][0], $amAttributes['mail'][0]);
                    remove_action('authenticate', 'wp_authenticate_username_password', 20);
                    return $user;
                }
            }
        }
    }
    return;
}

/* Verifies that the OpenAM session is valid */
function isSessionValid($tokenId) {
     $sessions_url=OPENAM_BASE_URL . OPENAM_SESSION_URI;
     $headers = array( 'Content-Type' => 'application/json' );
     $response = wp_remote_post( $sessions_url . $tokenId . "?_action=validate", 
     array( 'headers' => $headers , 
            'sslverify' => false ,
          ) );        
     $amResponse = json_decode( $response['body'], true );
     return $amResponse;
}

/* Loads a user if found, if not it creates it in the local database using the 
 * attributes pulled from OpenaM
 */
function loadUser($login,$mail) {
        $userobj = new WP_User();
        $user = $userobj->get_data_by( 'login', $login );
        $user = new WP_User($user->ID); // Attempt to load up the user with that ID
         
        if( $user->ID == 0 ) { // User did not exist
             $userdata = array( 'user_email' => $mail,
                                'user_login' => $login
                               );
             $new_user_id = wp_insert_user( $userdata ); // A new user has been created
             // Load the new user info
             $user = new WP_User ($new_user_id);
        } 
        return $user;
}

/* Authenticates a user in OpenAM using the credentials passed  */
function authenticateWithOpenAM($username, $password) {

    // $authentication_url = OPENAM_BASE_URL . OPENAM_AUTHN_URI;
    $authentication_url = createAuthenticationURL();
    $headers = array('X-OpenAM-Username' => $username,
        'X-OpenAM-Password' => $password,
        'Content-Type' => 'application/json');
    $response = wp_remote_post($authentication_url, array('headers' => $headers,
        'body' => '{}',
        'sslverify' => false,
            ));
    if (empty($response->errors['http_request_failed'])) {
        if ($response['response']['code'] == 200) {
            $amResponse = json_decode($response['body'], true);
            $number_of_hours = 2;
            $expiration_date = time() + 60 * 60 * $number_of_hours;
            setrawcookie(OPENAM_COOKIE_NAME, $amResponse['tokenId'], $expiration_date, '/', DOMAIN);
            return $amResponse['tokenId'];
        }
        return 0;
    }
    else
        return 2;
}

/* Creates the proper OpenAM authentication URL using the parameters configured */
function createAuthenticationURL() {

    $authentication_url = OPENAM_BASE_URL . OPENAM_AUTHN_URI;
    if (OPENAM_REALM != '') {
        $authentication_url .= "?" . REALM_PARAM . "=" . OPENAM_REALM;
    }
    if (OPENAM_AUTHN_MODULE != '') {
        if (!stripos($authentication_url, '?')) {
            $authentication_url .= "?" . AUTH_TYPE . "=" . MODULE_PARAM . "&" .
                AUTH_VALUE . "=" . OPENAM_AUTHN_MODULE;
        } else {
            $authentication_url .= "&" . AUTH_TYPE . "=" . MODULE_PARAM . "&" .
                AUTH_VALUE . "=" . OPENAM_AUTHN_MODULE;
        }
    } else {
        if (OPENAM_SERVICE_CHAIN != '') {
            if (!stripos($authentication_url, '?')) {
                $authentication_url .= "?" . AUTH_TYPE . "=" . SERVICE_PARAM . "&" .
                AUTH_VALUE . "=" . OPENAM_SERVICE_CHAIN;
            } else {
                $authentication_url .= "&" . AUTH_TYPE . "=" . SERVICE_PARAM . "&" .
                AUTH_VALUE . "=" . OPENAM_SERVICE_CHAIN;
            }
        }
    }
    return $authentication_url;
}

/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromOpenAM($tokenId, $username, $attributes) {
    $attributes_url=createAttributesURL();
    $headers = array( OPENAM_COOKIE_NAME => $tokenId ,
                    'Content-Type' => 'application/json' );
    $url = $attributes_url . $username . "?_fields=" . $attributes;
    $response = wp_remote_get( $url, 
    array( 'headers' => $headers , 
            'sslverify' => false ,
         ) );
    $amResponse = json_decode( $response['body'], true );
    if ($response['response']['code'] == 200 ) 
        return $amResponse;
    else return 0;

}

/* Creates the proper OpenAM Attributes URL using the configured parameters */
function createAttributesURL() {

    $attributes_url = OPENAM_BASE_URL . OPENAM_ATTRIBUTES_URI;
    if (OPENAM_REALM != '' and OPENAM_REALM != '/') {
        $attributes_url = str_replace("/users", OPENAM_REALM . "/users", $attributes_url);
    }
    return $attributes_url;
}



/* Returns a modified logout url, where the user is redirected back to the
 * users's blog url (instead of the wp-login page.
 */
function openam_logout($logout_url, $redirect=null) {    
    return $logout_url . '&amp;redirect_to=' . urlencode( get_bloginfo('url'));  
}


/*
 * It logs out a user from Wordpress and if it was opted to destory the OpenAM session,
 * it will logout the user from OpenAM as well.
 */
if ( !function_exists( 'wp_logout' ) ) :
function wp_logout() {    

    if (OPENAM_REST_ENABLED and OPENAM_LOGOUT_TOO) {
        $tokenId=$_COOKIE[OPENAM_COOKIE_NAME];
        if(!empty($tokenId) AND is_user_logged_in()) {     
            do_action('wp_logout');     
            $headers = array(OPENAM_COOKIE_NAME => $tokenId,
                             'Content-Type' => 'application/json');
            $url = OPENAM_BASE_URL . OPENAM_SESSION_URI . "?_action=logout";
            $response = wp_remote_post($url, array('headers' => $headers,
                'sslverify' => false,
                    ));
            $expiration_date = time() - 60 ;
            setcookie(OPENAM_COOKIE_NAME, '', $expiration_date, '/', DOMAIN);
        }
    } 
    wp_clear_auth_cookie();
    do_action('wp_logout');   
}
endif;

/* Creates the proper OpenAM authentication URL using the parameters configured */
function createOpenAMLoginURL() {

    $authentication_url = OPENAM_BASE_URL . "/UI/Login";
    if (OPENAM_REALM != '') {
        $authentication_url .= "?" . REALM_PARAM . "=" . OPENAM_REALM;
    }
    if (OPENAM_AUTHN_MODULE != '') {
        if (!stripos($authentication_url, '?')) {
            $authentication_url .= "?" . MODULE_PARAM . "=" . OPENAM_AUTHN_MODULE;
        } else {
            $authentication_url .= "&" . MODULE_PARAM . "=" . OPENAM_AUTHN_MODULE;
        }
    } else {
        if (OPENAM_SERVICE_CHAIN != '') {
            if (!stripos($authentication_url, '?')) {
                $authentication_url .= "?" . SERVICE_PARAM . "=" . OPENAM_SERVICE_CHAIN;
            } else {
                $authentication_url .= "&" . SERVICE_PARAM . "=" . OPENAM_SERVICE_CHAIN;
            }
        }
    }
    return $authentication_url;
}

function openam_login_url($login_url, $redirect = null) {
    if (OPENAM_DO_REDIRECT) {
        $new_url = createOpenAMLoginURL();
        if (!stripos($new_url, '?')) {
            $new_url .= "?" . "goto=" . urlencode($login_url);
        } else {
            $new_url .= "&" . "goto=" . urlencode($login_url);
        }
        return $new_url;
    } else {
        return $login_url;
    }
}

// Functions from here and down are used for the administration of the plugin
// in the wordpress admin panel

/*
 * Function used to add the options menu in the wordpress console
 */
function openam_rest_plugin_menu() {
  add_options_page('OpenAM-REST Plugin Options', 'OpenAM-REST Plugin', 8, 'openam', 'openam_rest_plugin_options');
}

/*
 * This function creates the options menu in the Wordpress console
 */
function openam_rest_plugin_options() {
?>
<div class="wrap">
<div id="icon-options-general" class="icon32"><br /></div>
<h2>OpenAM-REST Plugin</h2>

<form method="post" action="options.php">
<?php wp_nonce_field('update-options'); ?>

<table class="form-table">

<tr valign="top">
<th scope="row"><?php _e('OpenAM-REST enabled') ?></th>
<td> <fieldset><legend class="screen-reader-text"><span><?php _e('OpenAM REST enabled') ?></span></legend><label for="openam_rest_enabled">
<input name="openam_rest_enabled" type="checkbox" id="openam_rest_enabled" value="1" <?php checked('1', get_option('openam_rest_enabled')); ?> />
<?php _e('This checkbox enables or disables this plugin') ?></label>
</fieldset></td>

<tr valign="top">
<th scope="row"><label for="openam_cookie_name"><?php _e('OpenAM Session cookie') ?></label></th>
<td><input type="text" name="openam_cookie_name" value="<?php echo get_option('openam_cookie_name'); ?>" class="regular-text code" />
    <span class="description">
        <?php _e('Default in OpenAM is <code>iPlanetDirectoryPro</code>, but can be something different. Check with the OpenAM Administrator') ?>
    </span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_base_url"><?php _e('OpenAM base URL') ?></label></th>
<td><input type="text" name="openam_base_url" value="<?php echo get_option('openam_base_url'); ?>" class="regular-text code" />
    <span class="description">
               <?php _e('The OpenAM deployment URL. Example: <code>http://openam.example.com:80/openam/</code>') ?>
    </span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_realm"><?php _e('OpenAM realm where users reside') ?></label></th>
<td><input type="text" name="openam_realm" value="<?php echo get_option('openam_realm'); ?>" class="regular-text code" />
    <span class="description">
               <?php _e('The OpenAM realm where users reside. Example: <code>/</code> or <code>/myrealm</code>') ?>
    </span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_authn_module"><?php _e('OpenAM Authentication Module') ?></label></th>
<td><input type="text" name="openam_authn_module" value="<?php echo get_option('openam_authn_module'); ?>" class="regular-text code" />
    <span class="description">
               <?php _e('The Authentication module to use in the OpenAM. Example: <code>DataStore</code> or <code>LDAP</code>
                   <br/><italic>Note: Module and Service Chain can not be used at the same time. This option can be left empty, in which case the default module configured in OpenAM wil be used. 
                   The module should only accept user and password, if that is not the case then enable \'Redirect to OpenAM for Login\'.</italic>') ?>
    </span>
</td>
</tr>


<tr valign="top">
<th scope="row"><label for="openam_service_chain"><?php _e('OpenAM Authentication Service (Chain)') ?></label></th>
<td><input type="text" name="openam_service_chain" value="<?php echo get_option('openam_service_chain'); ?>" class="regular-text code" />
    <span class="description">
               <?php _e('The Authentication Service or Chain to be used in the OpenAM. Example: <code>ldapService</code> or <code>myChain</code>
                   <br/><italic>Note: Service Chain and Module can not be used at the same time. This option can be left empty, in which case the default service configured in OpenAM wil be used.
                   The modules in the chain should only accept user and password, if that is not the case then enable \'Redirect to OpenAM for Login\'.</italic>') ?>
    </span>
</td>
</tr>

<tr valign="top">
<th scope="row"><?php _e('Logout from OpenAM when logging out from Wordpress') ?></th>
<td>
    <fieldset><legend class="screen-reader-text"><span>
        <?php _e('Logout from OpenAM when logging out from Wordpress') ?>
            </span></legend><label for="openam_logout_too">
<input name="openam_logout_too" type="checkbox" id="openam_logout_too" value="1" <?php checked('1', get_option('openam_logout_too')); ?> />
<?php _e('If selected, when the user logs out from Wordpress it will also terminate the session in OpenAM.') ?></label>
</fieldset></td>

<tr valign="top">
<th scope="row"><label for="openam_wordpress_attributes"><?php _e('OpenAM attributes to map Login Name and Mail address') ?></label></th>
<td><input type="text" name="openam_wordpress_attributes" value="<?php echo get_option('openam_wordpress_attributes'); ?>" class="regular-text code" />
    <span class="description">
        <?php _e('Comma separated name of the OpenAM attributes to map login name and mail. Example: <code>uid,mail</code>') ?>
    </span>
</td>
</tr>

<tr valign="top">
<th scope="row"><?php _e('Redirect to OpenAM for Login') ?></th>
<td>
    <fieldset><legend class="screen-reader-text"><span>
        <?php _e('Redirect to OpenAM for Login') ?>
            </span></legend><label for="openam_do_redirect">
<input name="openam_do_redirect" type="checkbox" id="openam_logout_too" value="1" <?php checked('1', get_option('openam_do_redirect')); ?> />
<?php _e('For authentication chains and modules with a more complex workflow than user/password, redirect to OpenAM') ?></label>
</fieldset></td>

</table>

<input type="hidden" name="action" value="update" />
<input type="hidden" name="page_options" value="openam_rest_enabled,openam_cookie_name,openam_base_url,
       openam_realm,openam_authn_module,openam_service_chain,openam_logout_too,openam_do_redirect,openam_wordpress_attributes" />

<p class="submit">
<input type="submit" class="button-primary" value="<?php _e('Save Changes') ?>" />
</p>

</form>
</div>
<?php
}

?>