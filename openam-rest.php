<?php 
/*
Plugin Name: OpenAM Authentication
Plugin URI: http://www.forgerock.org
Description: This plugin is used to authenticate users using OpenAM. The plugin uses REST calls to the OpenAM. The required REST APIs are: /json/authenticate; /json/users/ and /json/sessions. Therefore you need OpenAM 11.0 and above.
Version: 0.5
Author: Victor.Ake@ForgeRock.Com
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


add_filter( 'authenticate', 'openam_auth', 10, 3 );
add_action( 'admin_menu', 'openam_rest_plugin_menu' );
// add_action('wp_authenticate', 'login', 10, 2);
 
// Options
add_option( 'openam_rest_enabled',                 0 );
add_option( 'openam_cookie_name',                  'RockshopSession' );
add_option( 'openam_base_url',                     'http://mac.openrock.org:8080/openam' );
add_option( 'openam_authn_uri',                    '/json/authenticate' );
add_option( 'openam_attributes_uri',               '/json/users/' );
add_option( 'openam_session_uri',                  '/json/sessions/' );
add_option( 'openam_wordpress_attributes',         'uid,mail' );

define( 'OPENAM_REST_ENABLED',                      get_option( 'openam_rest_enabled' ) );
define( 'OPENAM_COOKIE_NAME',                       get_option( 'openam_cookie_name' ) );
define( 'OPENAM_BASE_URL',                          get_option( 'openam_base_url' ) );
define( 'OPENAM_AUTHN_URI',                         get_option( 'openam_authn_uri' ) );
define( 'OPENAM_ATTRIBUTES_URI',                    get_option( 'openam_attributes_uri' ) );
define( 'OPENAM_SESSION_URI',                       get_option( 'openam_session_uri' ) );
define( 'OPENAM_WORDPRESS_ATTRIBUTES',              get_option( 'openam_wordpress_attributes' ) );


function openam_auth($user, $username, $password) {

    if (OPENAM_REST_ENABLED) {
        // Let's see if the user is already logged in the IDP
        $tokenId = $_COOKIE[OPENAM_COOKIE_NAME];
        if (!empty($tokenId) AND !is_user_logged_in()) {
            $ext_auth = isSessionValid($tokenId);
            if ($ext_auth['valid']) { // Session was valid
                $externalAttributes = getAttributesFromOpenAM($tokenId, $ext_auth['uid'], OPENAM_WORDPRESS_ATTRIBUTES);
                $user = loadUser($externalAttributes['uid'][0], $externalAttributes['mail'][0]);
            }
        }

        // Make sure a username and password are present for us to work with
        if ($username == '' || $password == '')
            $user = new WP_Error('denied', __("<strong>ERROR</strong>: username and password can not be empty"));

        $tokenId = authenticateWithOpenAM($username, $password);
        if (!$tokenId) {
            // User does not exist,  send back an error message
            $user = new WP_Error('denied', __("<strong>ERROR</strong>: The combination username/password was not correct"));
        } else {
            $ext_auth = getAttributesFromOpenAM($tokenId, $username, OPENAM_WORDPRESS_ATTRIBUTES);
            if ($ext_auth) {
                $user = loadUser($ext_auth['uid'][0], $ext_auth['mail'][0]);
            }
        }
        remove_action('authenticate', 'wp_authenticate_username_password', 20);
    }
    return $user;
}

function isSessionValid($tokenId) {
     $sessions_url=OPENAM_BASE_URL . OPENAM_SESSION_URI;
     $headers = array( 'Content-Type' => 'application/json' );
     $response = wp_remote_post( $sessions_url . $tokenId . "?_action=validate", 
     array( 'headers' => $headers , 
            'sslverify' => false ,
          ) );         
     $ext_auth = json_decode( $response['body'], true );
     return $ext_auth;
}

function loadUser($uid,$mail) {
        $userobj = new WP_User();
        $user = $userobj->get_data_by( 'login', $uid );
        $user = new WP_User($user->ID); // Attempt to load up the user with that ID
         
        if( $user->ID == 0 ) { // User did not exist
             $userdata = array( 'user_email' => $mail,
                                'user_login' => $uid
                               );
             $new_user_id = wp_insert_user( $userdata ); // A new user has been created
             // Load the new user info
             $user = new WP_User ($new_user_id);
        } 
        return $user;
}

function authenticateWithOpenAM($username, $password) {
    $authentication_url=OPENAM_BASE_URL . OPENAM_AUTHN_URI;
    $headers = array(   'X-OpenAM-Username' => $username , 
                        'X-OpenAM-Password' => $password , 
                        'Content-Type' => 'application/json');
    $response = wp_remote_post( $authentication_url, 
            array( 'headers' => $headers , 
                    'body' => '{}' ,
                    'sslverify' => false ,
                     ) );
    $ext_auth = json_decode( $response['body'], true );
 
    if( $response['response']['code']  == 200 )  return $ext_auth['tokenId'];
    else return 0;
}


function getAttributesFromOpenAM($tokenId, $username, $attributes) {
    $attributes_url=OPENAM_BASE_URL . OPENAM_ATTRIBUTES_URI;
    $headers = array( OPENAM_COOKIE_NAME => $tokenId ,
                    'Content-Type' => 'application/json' );
    $url = $attributes_url . $username . "?_fields=" . $attributes;
    $response = wp_remote_get( $url, 
    array( 'headers' => $headers , 
            'sslverify' => false ,
         ) );
    $ext_auth = json_decode( $response['body'], true );
    if ($response['response']['code'] == 200 ) 
        return $ext_auth;
    else return 0;

}

/*
 * It logs out a user from Wordpress and if there is an OpenAM SSO cookie,
 * it also logs out the session
 */
if ( !function_exists( 'wp_logout' ) ) :
function wp_logout() {
    
    if (OPENAM_REST_ENABLED) {
        $tokenId=$_COOKIE[OPENAM_COOKIE_NAME];
        if(!empty($tokenId) AND is_user_logged_in()) {        
            do_action('wp_logout');     
            $headers = array(OPENAM_COOKIE_NAME => $tokenId,
                             'Content-Type' => 'application/json');
            $url = OPENAM_BASE_URL . OPENAM_SESSION_URI . "?_action=logout";
            $response = wp_remote_post($url, array('headers' => $headers,
                'sslverify' => false,
                    ));
            // $ext_auth = json_decode($response['body'], true);
        }
    } 
    wp_clear_auth_cookie();
    do_action('wp_logout');
    wp_redirect(get_option('siteurl'));
    
}
endif;

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
<th scope="row"><label for="openam_cookie_name"><?php _e('OpenAM cookie name') ?></label></th>
<td><input type="text" name="openam_cookie_name" value="<?php echo get_option('openam_cookie_name'); ?>" class="regular-text code" /><span class="description"><?php _e('Default in OpenAM is <code>iPlanetDirectoryPro</code> unless you have changed it.') ?></span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_base_url"><?php _e('OpenAM base URL') ?></label></th>
<td><input type="text" name="openam_base_url" value="<?php echo get_option('openam_base_url'); ?>" class="regular-text code" /><span class="description"><?php _e('The OpenAM deployment URL. Example: <code>http://openam.example.com:80/openam/</code>') ?></span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_authn_uri"><?php _e('OpenAM Authentication URI') ?></label></th>
<td><input type="text" name="openam_authn_uri" value="<?php echo get_option('openam_authn_uri'); ?>" class="regular-text code" /><span class="description"><?php _e('URI of the authenticate API. Example (default in OpenAM): <code>/json/authenticate</code>') ?></span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_attributes_uri"><?php _e('OpenAM Attributes URI') ?></label></th>
<td><input type="text" name="openam_attributes_uri" value="<?php echo get_option('openam_attributes_uri'); ?>" class="regular-text code" /><span class="description"><?php _e('URI of the IdM API. Example (default in OpenAM): <code>/json/users/</code>') ?></span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_session_uri"><?php _e('OpenAM Sessions URI') ?></label></th>
<td><input type="text" name="openam_session_uri" value="<?php echo get_option('openam_session_uri'); ?>" class="regular-text code" /><span class="description"><?php _e('URI of the sessions API. Example (default in OpenAM): <code>/json/sessions/</code>') ?></span>
</td>
</tr>

<tr valign="top">
<th scope="row"><label for="openam_wordpress_attributes"><?php _e('OpenAM WordPress attribute') ?></label></th>
<td><input type="text" name="openam_wordpress_attributes" value="<?php echo get_option('openam_wordpress_attributes'); ?>" class="regular-text code" /><span class="description"><?php _e('The name of the OpenAM attributes to be used to locate the local account, it is assumed uid is mapped to the localaccount.') ?></span>
</td>
</tr>

</table>

<input type="hidden" name="action" value="update" />
<input type="hidden" name="page_options" value="openam_rest_enabled,openam_cookie_name,openam_base_url,openam_authn_uri,
       openam_attributes_uri,openam_session_uriopensso_,openam_logout_uri,openam_wordpress_attributes" />

<p class="submit">
<input type="submit" class="button-primary" value="<?php _e('Save Changes') ?>" />
</p>

</form>
</div>
<?php
}

?>