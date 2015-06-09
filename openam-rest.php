<?php 
/*
Plugin Name: OpenAM Authentication
Plugin URI: https://forgerock.org
Description: This plugin is used to authenticate users using OpenAM. The plugin uses REST calls to the OpenAM. The required REST APIs are: /json/authenticate; /json/users/ and /json/sessions. Therefore you need OpenAM 11.0 and above.
Version: 1.2
Author: Victor info@forgerock.com, openam@forgerock.org (subscribe to mailing list firt)
Author URI: http://www.forgerock.com
Text Domain: openam-auth
*/

/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at https://forgerock.org/projects/cddlv1-0/. See the License for the
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
add_action( 'plugins_loaded', 'openam_i18n' );
add_action( 'plugins_loaded', 'openam_sso' );
add_action( 'wp_logout',      'openam_wp_logout' );
 
// Options
// OpenAM General configuration parameters
function openam_plugin_activate() {
    add_option( 'openam_rest_enabled',                 0 );
    add_option( 'openam_legacy_apis_enabled',          0 );
    add_option( 'openam_cookie_name',                  'iPlanetDirectoryPro' );
    add_option( 'openam_cookie_domain',                 $_SERVER['HTTP_HOST'] );
    add_option( 'openam_base_url',                     'https://openam.example.com:443/openam' );
    add_option( 'openam_realm',                        '' );
    add_option( 'openam_authn_module',                 '' );
    add_option( 'openam_service_chain',                '' );
    add_option( 'openam_logout_too',                   0);
    add_option( 'openam_wordpress_attributes',         'uid,mail' );
    add_option( 'openam_do_redirect',                  0);
    add_option( 'openam_debug_enabled',                0);
    add_option( 'openam_debug_file',                   get_temp_dir() . DIRECTORY_SEPARATOR . wp_unique_filename( get_temp_dir(), 'openam-' . wp_generate_password( mt_rand( 32, 64 ), false ) ); // generate semi-secret filename for logging
}
register_activation_hook( __FILE__, 'openam_plugin_activate' );

// Constants
// OpenAM General Configuration parameters
define( 'OPENAM_REST_ENABLED',                      get_option( 'openam_rest_enabled' ) );
define( 'OPENAM_LEGACY_APIS_ENABLED',               get_option( 'openam_legacy_apis_enabled' ) );
define( 'OPENAM_COOKIE_NAME',                       get_option( 'openam_cookie_name' ) );
define( 'DOMAIN',                                   get_option( 'openam_cookie_domain'));
define( 'OPENAM_BASE_URL',                          get_option( 'openam_base_url' ) );
define( 'OPENAM_REALM',                             get_option( 'openam_realm' ) );
define( 'OPENAM_AUTHN_MODULE',                      get_option( 'openam_authn_module' ) );
define( 'OPENAM_SERVICE_CHAIN',                     get_option( 'openam_service_chain' ) );
define( 'OPENAM_WORDPRESS_ATTRIBUTES',              get_option( 'openam_wordpress_attributes' ) );
$OPENAM_WORDPRESS_ATTRIBUTES_ARRAY =  explode(',', OPENAM_WORDPRESS_ATTRIBUTES);
define( 'OPENAM_WORDPRESS_ATTRIBUTES_USERNAME',     $OPENAM_WORDPRESS_ATTRIBUTES_ARRAY[0] );
define( 'OPENAM_WORDPRESS_ATTRIBUTES_MAIL',         $OPENAM_WORDPRESS_ATTRIBUTES_ARRAY[1] );
define( 'OPENAM_LOGOUT_TOO',                        get_option( 'openam_logout_too' ) );
define( 'OPENAM_DO_REDIRECT',                       get_option( 'openam_do_redirect' ) );
define( 'OPENAM_DEBUG_ENABLED',                     get_option( 'openam_debug_enabled' ) );
define( 'OPENAM_DEBUG_FILE',                        get_option( 'openam_debug_file' ) );

// OpenAM API endpoints
define( 'OPENAM_AUTHN_URI',                         '/json/authenticate' );
define( 'OPENAM_ATTRIBUTES_URI',                    '/json/users/' );
define( 'OPENAM_SESSION_URI',                       '/json/sessions/' );
define( 'OPENAM_SESSION_VALIDATION',                '/identity/isTokenValid' );
define( 'OPENAM_IDENTITY_ATTRIBUTES_URI',           '/identity/attributes' );

// Legacy
define( 'OPENAM_LEGACY_AUTHN_URI',                  '/identity/json/authenticate' );
define( 'OPENAM_LEGACY_ATTRIBUTES_URI',             '/identity/json/attributes' );
define( 'OPENAM_LEGACY_SESSION_VALIDATION',         '/identity/json/isTokenValid' );
define( 'OPENAM_LEGACY_SESSION_LOGOUT',             '/identity/logout' );

// Other constants
define( 'REALM_PARAM',                              'realm');
define( 'SERVICE_PARAM',                            'service');
define( 'MODULE_PARAM',                             'module');
define( 'AUTH_TYPE',                                'authIndexType');
define( 'AUTH_VALUE',                               'authIndexValue');


/**
 * Auto-login the user
 */
function openam_sso() {
    if ( ( isset( $_GET['action'] ) && 'logout' == $_GET['action'] ) || ( isset( $_GET['loggedout'] ) && 'yes' == $_GET['loggedout'] ) ) {
        return false;
    }
    // Let's see if the user is already logged in the IDP
    if ( isset( $_COOKIE[ OPENAM_COOKIE_NAME ] ) ) {
        $tokenId = $_COOKIE[ OPENAM_COOKIE_NAME ];
        if ( ! empty( $tokenId ) && ! is_user_logged_in() ) {
            openam_debug( 'openam_auth: TOKENID:' . $tokenId );
            if ( $am_response = openam_sessionsdata( $tokenId ) ) {

                openam_debug( 'openam_auth: Authentication was successful SUCCESS' );
                openam_debug( 'openam_auth: am_response ' . print_r( $am_response, true ) );

                $amAttributes = getAttributesFromOpenAM( $tokenId, $am_response[ OPENAM_WORDPRESS_ATTRIBUTES_USERNAME ], OPENAM_WORDPRESS_ATTRIBUTES );
                $usernameAttr = get_attribute_value( $amAttributes, OPENAM_WORDPRESS_ATTRIBUTES_USERNAME );
                $mailAttr = get_attribute_value( $amAttributes, OPENAM_WORDPRESS_ATTRIBUTES_MAIL );

                openam_debug( 'openam_auth: UID: ' . print_r( $usernameAttr, true ) );
                openam_debug( 'openam_auth: MAIL: ' . print_r( $mailAttr, true ) );

                // This should return a WP_User instance https://codex.wordpress.org/Class_Reference/WP_User
                $user = loadUser( $usernameAttr, $mailAttr );
                wp_set_current_user( $user->ID, $user->user_login );
                wp_set_auth_cookie( $user->ID);
                do_action( 'wp_login', $user->user_login );
                
                return true;
            }
        }
    }
    return false;
}

/* Main function */
function openam_auth($user, $username, $password) {

    if (OPENAM_REST_ENABLED) {

        // If username and password has been supplied then we are starting here
        if ($username != '' and $password != '') {
            $tokenId = authenticateWithOpenAM($username, $password);
            if (!$tokenId) {
                // User does not exist,  send back an error message
                return new WP_Error('denied', esc_html__( 'The combination username/password was not correct', 'openam-auth' ) );
            } elseif ($tokenId == 2) {
                return new WP_Error('denied', esc_html__( 'Error when trying to reach the OpenAM', 'openam-auth' ) );
            } else {
                $amAttributes = getAttributesFromOpenAM($tokenId, $username, OPENAM_WORDPRESS_ATTRIBUTES);
                if ($amAttributes) {
                    $usernameAttr = get_attribute_value($amAttributes,  OPENAM_WORDPRESS_ATTRIBUTES_USERNAME);
                    $mailAttr = get_attribute_value($amAttributes,  OPENAM_WORDPRESS_ATTRIBUTES_MAIL);
                    openam_debug("openam_auth: UID: " . print_r($usernameAttr, TRUE));
                    openam_debug("openam_auth: MAIL: " . print_r($mailAttr, TRUE));
                    $user = loadUser($usernameAttr, $mailAttr);
                    remove_action('authenticate', 'wp_authenticate_username_password', 20);
                    return $user;
                }
            }
        }
    }
    return false;
}

function openam_sessionsdata($tokenId)
{

    if (!OPENAM_LEGACY_APIS_ENABLED) {
        openam_debug("openam_sessionsdata: Legacy Mode Disabled");
        $isTokenValid_am_response = wp_remote_post(OPENAM_BASE_URL . OPENAM_SESSION_VALIDATION, array('method' => 'POST', 'timeout' => 45, 'redirection' => 5, 'httpversion' => '1.0', 'blocking' => true, 'headers' => array(), 'body' => array('tokenid' => $tokenId), 'sslverify' => false, 'cookies' => array()));

        if (is_wp_error($isTokenValid_am_response)) {
            $error_message = $isTokenValid_am_response->get_error_message();
            openam_debug("openam_sessionsdata: is_wp_error" . $error_message);
        }

        openam_debug("openam_sessionsdata: isTokenValid_am_response " . print_r($isTokenValid_am_response['body'], TRUE));

        $response_string = $isTokenValid_am_response['body'];
        if (strpos($response_string, 'true') !== FALSE) {
            openam_debug("openam_sessionsdata: returning true from -> strpos");

            $uid_am_response = wp_remote_post(OPENAM_BASE_URL . OPENAM_IDENTITY_ATTRIBUTES_URI . "?subjectid=" . $tokenId . "&attributenames=uid", array('method' => 'GET', 'timeout' => 45, 'redirection' => 5, 'httpversion' => '1.0', 'blocking' => true, 'headers' => array(), 'sslverify' => false, 'cookies' => array()));

            openam_debug("openam_sessionsdata: username_am_response: " . print_r($uid_am_response, TRUE));

            $am_response = array();

            $lines = preg_split('/\R/', $uid_am_response['body']);

            $mode = 'key';
            $values = [];
            $key = 'UNDEFINED';
            foreach ($lines as $l)
            {
                $parts = explode("=", $l);
                if ($parts[0] != 'userdetails.token.id') {
                    if ($mode == 'key')
                    {
                        $key = $parts[1];
                        $mode = 'value';
                    }
                    else
                    {
                        $values[$key] = $parts[1];
                        $mode = 'key';
                    }
                }
            }

            openam_debug("openam_sessionsdata: values: " . print_r($values, TRUE));
            $am_response[OPENAM_WORDPRESS_ATTRIBUTES_USERNAME] = $values[OPENAM_WORDPRESS_ATTRIBUTES_USERNAME];
            openam_debug("openam_sessionsdata: am_response: " . $am_response);
            return $am_response;
        }

    } else {
        openam_debug("openam_sessionsdata: Legacy Mode Enabled");
        $sessions_url = OPENAM_BASE_URL . OPENAM_LEGACY_SESSION_VALIDATION;
        $response = wp_remote_post($sessions_url . "?tokenid=" . $tokenId, array('sslverify' => false,));
        openam_debug("openam_sessionsdata: isValid Response: " . print_r($response, TRUE));
        $amResponse = json_decode($response['body'], true);
        return $amResponse;
    }
    return false;
}


/* Loads a user if found, if not it creates it in the local database using the 
 * attributes pulled from OpenaM
 */
function loadUser($login,$mail) {
        $userobj = new WP_User();
        $user = $userobj->get_data_by( 'login', $login );
        openam_debug("loadUser: user object: " . print_r($user, TRUE));
        $user = new WP_User($user->ID); // Attempt to load up the user with that ID
         
        if( $user->ID == 0 ) { // User did not exist
             $userdata = array( 'user_email' => $mail,
                                'user_login' => $login
                               );
             $new_user_id = wp_insert_user( $userdata ); // A new user has been created
             // Load the new user info
             $user = new WP_User ($new_user_id);
        } 
        openam_debug("loadUser: WP_User loaded: " . print_r($user, TRUE));
        return $user;
}

/* Authenticates a user in OpenAM using the credentials passed  */
function authenticateWithOpenAM($username, $password) {
    if (!OPENAM_LEGACY_APIS_ENABLED) {
        return authenticateWithModernOpenAM($username, $password);      
    } else {
        return authenticateWithLegacyOpenAM($username, $password);
    }
}

/* Authenticates a user in a modern OpenAM using the credentials passed  */
function authenticateWithModernOpenAM($username, $password) {
    $authentication_url = createAuthenticationURL();
    openam_debug("authenticateWithModernOpenAM: AUTHN URL: " . $authentication_url);
    $headers = array('X-OpenAM-Username' => $username,
        'X-OpenAM-Password' => $password,
        'Content-Type' => 'application/json');
    $response = wp_remote_post($authentication_url, array('headers' => $headers,
        'body' => '{}',
        'sslverify' => false
            ));
    openam_debug("authenticateWithModernOpenAM: RAW AUTHN RESPONSE: " . print_r($response, TRUE));
    if (empty($response->errors['http_request_failed'])) {
        if ($response['response']['code'] == 200) {
            $amResponse = json_decode($response['body'], true);
            $number_of_hours = 2;
            $expiration_date = time() + 60 * 60 * $number_of_hours;
            setrawcookie(OPENAM_COOKIE_NAME, $amResponse['tokenId'], $expiration_date, '/', DOMAIN);
            openam_debug("authenticateWithModernOpenAM:: AUTHN Response: " . print_r($amResponse,TRUE));
            return $amResponse['tokenId'];
        }
        return 0;
    }
    else
        return 2;
}

/* Authenticates a user with a legacy OpenAM using the credentials passed  */
function authenticateWithLegacyOpenAM($username, $password) {
    $authentication_url = OPENAM_BASE_URL . OPENAM_LEGACY_AUTHN_URI;
    openam_debug("authenticateWithLegacyOpenAM: AUTHN URL: " . $authentication_url);
    $uri_param = createLegacyAuthenticationURIParams();
    $uri = "?username=" . $username . "&password=" . $password . 
            $uri_param;
    $response = wp_remote_post($authentication_url . $uri, array('headers' => $headers,
        'sslverify' => false,
            ));
    openam_debug("authenticateWithLegacyOpenAM: RAW AUTHN RESPONSE: " . print_r($response, TRUE));
    if (empty($response->errors['http_request_failed'])) {
        if ($response['response']['code'] == 200) {
            $amResponse = json_decode($response['body'], true);
            $number_of_hours = 2;
            $expiration_date = time() + 60 * 60 * $number_of_hours;
            setrawcookie(OPENAM_COOKIE_NAME, $amResponse['tokenId'], $expiration_date, '/', DOMAIN);
            openam_debug("authenticateWithLegacyOpenAM: AUTHN RESPONSE: " . print_r($amResponse, TRUE));
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

/* Creates the proper OpenAM authentication URL using the parameters configured */
function createLegacyAuthenticationURIParams() {

    $uri = '';
    if (OPENAM_REALM != '') {
        $uri = REALM_PARAM . "=" . OPENAM_REALM;
    }
    if (OPENAM_AUTHN_MODULE != '') {
        if ($uri != '') {
            $uri .= "&" . MODULE_PARAM . "=" . OPENAM_AUTHN_MODULE;
        } else {
            $uri = MODULE_PARAM . "=" . OPENAM_AUTHN_MODULE;
        }
    } else {
        if (OPENAM_SERVICE_CHAIN != '') {
            if ($uri != '') {
                $uri .= "&" . SERVICE_PARAM . "=" . OPENAM_SERVICE_CHAIN;
            } else {
                $uri = SERVICE_PARAM . "=" . OPENAM_SERVICE_CHAIN;
            }
        }
    }
    $uri_param = '';
    if ($uri != '') {
        $uri_param = "&uri=" . urlencode($uri);
    }
    return $uri_param;
}


/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromOpenAM($tokenId, $username, $attributes) {
    if (!OPENAM_LEGACY_APIS_ENABLED) {
        openam_debug("getAttributesFromOpenAM: LEGACY NOT ENABLED");
        return getAttributesFromModernOpenAM($tokenId, $username, $attributes);      
    } else {
        openam_debug("getAttributesFromOpenAM: LEGACY ENABLED");
        return getAttributesFromLegacyOpenAM($tokenId, $attributes);
    }
}


/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromModernOpenAM($tokenId, $username, $attributes) {
    $attributes_url=createAttributesURL();
    openam_debug("getAttributesFromModernOpenAM: ATTRIBUTE URL: " . $attributes_url);
    $headers = array( OPENAM_COOKIE_NAME => $tokenId ,
                    'Content-Type' => 'application/json' );
    $url = $attributes_url . $username . "?_fields=" . $attributes;
    openam_debug("getAttributesFromModernOpenAM: full url: " . $url);
    $response = wp_remote_get( $url, 
    array( 'headers' => $headers , 
            'sslverify' => false 
         ) );
    openam_debug("getAttributesFromModernOpenAM: RAW ATTR RESPONSE: " . 
            print_r($response, TRUE));
    $amResponse = json_decode( $response['body'], true );
    openam_debug("getAttributesFromModernOpenAM: ATTRIBUTE RESP: " . 
            print_r($amResponse, TRUE));
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

/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromLegacyOpenAM($tokenId, $attributes) {
    $attributes_url=createAttributesLegacyURL($tokenId);
    openam_debug("getAttributesFromLegacyOpenAM: Attributes URL: " . $attributes_url);
    $response = wp_remote_get( $attributes_url, 
    array( 'sslverify' => false
         ) );
    openam_debug("getAttributesFromLegacyOpenAM: RAW ATTRS RESPONSE: " . 
            print_r($response, TRUE));
    $amResponse = json_decode( $response['body'], true );
    openam_debug("getAttributesFromLegacyOpenAM: ATTRIBUTES RESPONSE: " . 
            print_r($amResponse, TRUE));
    if ($response['response']['code'] == 200 ) {
        $attr1 = $amResponse['attributes'];
        $amResponse2 = array();
        foreach ($attr1 as $json_attr){
           $attr_name = $json_attr['name'];
           $attr_value = $json_attr['values'];
           $amResponse2[$attr_name] = $attr_value;
        }   
        openam_debug("getAttributesFromLegacyOpenAM: Attributes: " . 
                print_r($amResponse2, TRUE));
        return $amResponse2;
    } else return 0;

}

/* Creates the proper OpenAM Attributes URL using the configured parameters */
function createAttributesLegacyURL($tokenId) {

    $attributes_url = OPENAM_BASE_URL . OPENAM_LEGACY_ATTRIBUTES_URI . 
            "?subjectid=" . $tokenId;
    if (OPENAM_WORDPRESS_ATTRIBUTES != '') {
        $attributes = explode(',', OPENAM_WORDPRESS_ATTRIBUTES);
        $attribute_uri = '';
        foreach ($attributes as $attributename) {
            $attribute_uri .= "&attributenames=" . $attributename;
        }
        $attributes_url .= $attribute_uri;
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
function openam_wp_logout() {

    if ( OPENAM_REST_ENABLED && OPENAM_LOGOUT_TOO ) {
        $tokenId = $_COOKIE[ OPENAM_COOKIE_NAME ];
        if( ! empty( $tokenId ) ) {
            $headers = array( OPENAM_COOKIE_NAME => $tokenId,
                'Content-Type' => 'application/json');
            $url = OPENAM_BASE_URL . OPENAM_SESSION_URI . "?_action=logout";
            $response = wp_remote_post($url, array( 'headers' => $headers,
                'sslverify' => false,
            ));
            openam_debug( 'wp_logout: RAW RESPONSE LOGOUT: ' .
                print_r( $response, TRUE ) );
            $expiration_date = time() - 60 ;
            setcookie( OPENAM_COOKIE_NAME, '', $expiration_date, '/', DOMAIN );
        }
    }
}

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

/* Writes to the debug file if debugging has been enabled 
 * 
 */
function openam_debug($message) {
    if (OPENAM_DEBUG_ENABLED) {
        chmod( OPENAM_DEBUG_FILE, 0600 );
        error_log($message . "\n", 3, OPENAM_DEBUG_FILE);
    }
}


/*
 * Select the attribute value :
 * if it's an array, we return the first value of it. if not, we directly return the attribute value
 */
function get_attribute_value($attributes, $attributeId) {
    if(is_array($attributes[$attributeId])) {
        return $attributes[$attributeId][0];
    } else {
        return $attributes[$attributeId];
    }
}


// Functions from here and down are used for the administration of the plugin
// in the wordpress admin panel

/*
 * Function used to add the options menu in the wordpress console
 */
function openam_rest_plugin_menu() {
  add_options_page('OpenAM-REST Plugin Options', 'OpenAM-REST Plugin', 'manage_options', 'openam', 'openam_rest_plugin_options');
}

/*
 * This function creates the options menu in the Wordpress console
 */
function openam_rest_plugin_options() {
    ?>
    <div class="wrap">
        <div id="icon-options-general" class="icon32"><br /></div>
        <h2><?php esc_html_e( 'OpenAM REST Plugin', 'openam-auth' ); ?></h2>

        <form method="post" action="options.php">
            <?php wp_nonce_field( 'update-options' ); ?>

            <table class="form-table">

                <tr valign="middle">
                    <td><?php esc_html_e( 'OpenAM REST enabled', 'openam-auth' ) ?></td>
                    <td> <fieldset><legend class="screen-reader-text"><?php esc_html_e( 'OpenAM REST enabled', 'openam-auth' ); ?></legend><label for="openam_rest_enabled">
                                <input name="openam_rest_enabled" type="checkbox" id="openam_rest_enabled" value="1" <?php checked( '1', get_option( 'openam_rest_enabled' ) ); ?> />
                    </td><td ><span class="description"><?php esc_html_e( 'Enable or disable this plugin', 'openam-auth' ); ?></label>
        </span></fieldset></td></tr>

                <tr valign="middle">
                    <td><?php esc_html_e( 'OpenAM-Legacy enabled', 'openam-auth' ); ?></td>
                    <td> <fieldset><legend class="screen-reader-text"><?php esc_html_e( 'OpenAM Legacy enabled', 'openam-auth' ); ?></legend><label for="openam_legacy_apis_enabled">
                                <input name="openam_legacy_apis_enabled" type="checkbox" id="openam_legacy_apis_enabled" value="1" <?php checked( '1', get_option( 'openam_legacy_apis_enabled' ) ); ?> />
                    </td><td><span class="description"><?php esc_html_e( 'Enable or disable the use of legacy REST APIs (For OpenAM 11.0 and older)', 'openam-auth' ); ?></label>
        </span></fieldset></td></tr>

                <tr valign="middle">
                    <td><label for="openam_cookie_name"><?php esc_html_e( 'OpenAM Session cookie', 'openam-auth' ); ?></label></td>
                    <td><input type="text" name="openam_cookie_name" value="<?php echo esc_attr( get_option( 'openam_cookie_name' ) ); ?>" class="regular-text code" />
                    </td><td><span class="description">
        <?php printf( esc_html__( 'Default in OpenAM is %s, but can be something different. Check with the OpenAM Administrator', 'openam-auth' ), '<code>iPlanetDirectoryPro</code>' ); ?>
    </span>
                    </td>
                </tr>

                <tr valign="middle">
                    <td><label for="openam_cookie_domain"><?php esc_html_e( 'Cookie domain', 'openam-auth' ); ?></label></td>
                    <td><input type="text" name="openam_cookie_domain" value="<?php echo esc_attr( get_option( 'openam_cookie_domain' ) ); ?>" class="regular-text code" />
                    </td><td><span class="description">
        <?php esc_html_e( 'The Domain where the above cookie will be set, once the user authenticates. Default is the last 2 components of the domain, if available, but can be something different. Depends on your deployment', 'openam-auth' ); ?>
    </span>
                    </td>
                </tr>

                <tr valign="middle">
                    <td><label for="openam_base_url"><?php esc_html_e( 'OpenAM base URL', 'openam-auth' ); ?></label></td>
                    <td valign="top"><input type="text" name="openam_base_url" value="<?php echo esc_attr( get_option('openam_base_url' ) ); ?>" class="regular-text code" />
                    </td><td><span class="description">
        <?php printf( esc_html__( 'The OpenAM deployment URL. Example: %s', 'openam-auth' ), '<code>https://openam.example.com:443/openam</code>' ); ?>
    </span>
                    </td>
                </tr>

                <tr valign="middle">
                    <td><label for="openam_realm"><?php esc_html_e( 'OpenAM realm where users reside', 'openam-auth' ); ?></label></td>
                    <td><input type="text" name="openam_realm" value="<?php echo esc_attr( get_option( 'openam_realm' ) ); ?>" class="regular-text code" />
                    </td><td>
        <span class="description">
               <?php printf( esc_html__( 'The OpenAM realm where users reside. Example: %1$s or %2$s', 'openam-auth' ), '<code>/</code>', '<code>/myrealm</code>' ); ?>
    </span>
                    </td>
                </tr>

                <tr valign="middle">
                    <td><label for="openam_authn_module"><?php esc_html_e( 'OpenAM Authentication Module', 'openam-auth' ); ?></label></td>
                    <td valign="top"><input type="text" name="openam_authn_module" value="<?php echo esc_attr( get_option( 'openam_authn_module' ) ); ?>" class="regular-text code" />
                    </td>
                    <td>
                        <span class="description">
                            <?php printf( esc_html__( 'The Authentication module to use in the OpenAM. Example: %1$s or %2$', 'openam-auth' ), '<code>DataStore</code>', '<code>LDAP</code>' ) ; ?>
                            <br/>
                            <italic><?php esc_html_e( 'Note: Module and Service Chain can not be used at the same time. This option can be left empty, in which case the default module configured in OpenAM wil be used.
                   The module should only accept user and password, if that is not the case then enable “Redirect to OpenAM for Login”.', 'openam-auth' ); ?></italic>
                        </span>
                    </td>
                </tr>


                <tr valign="middle">
                    <td><label for="openam_service_chain"><?php esc_html_e( 'OpenAM Authentication Service (Chain)', 'openam-auth' ); ?></label></td>
                    <td><input type="text" name="openam_service_chain" value="<?php echo esc_attr( get_option( 'openam_service_chain' ) ); ?>" class="regular-text code" />
                    </td>
                    <td>
                        <span class="description">
                            <?php printf( esc_html__( 'The Authentication Service or Chain to be used in the OpenAM. Example: %1$s or %2$s', 'openam-auth' ), '<code>ldapService</code>', '<code>myChain</code>' ); ?>
                            <br/><italic>
                                <?php printf( 'Note: Service Chain and Module can not be used at the same time. This option can be left empty, in which case the default service configured in OpenAM wil be used.
                   The modules in the chain should only accept user and password, if that is not the case then enable “Redirect to OpenAM for Login”.', 'openam-auth' ); ?></italic>
    </span>
                    </td>
                </tr>

                <tr valign="middle">
                    <td><?php esc_html_e( 'Logout from OpenAM when logging out from Wordpress', 'openam-auth' ); ?></td>
                    <td>
                        <fieldset><legend class="screen-reader-text"><span>
        <?php esc_html_e( 'Logout from OpenAM when logging out from Wordpress', 'openam-auth' ); ?>
            </span></legend><label for="openam_logout_too">
                                <input name="openam_logout_too" type="checkbox" id="openam_logout_too" value="1" <?php checked( '1', get_option( 'openam_logout_too' ) ); ?> />
                    </td><td><span class="description"><?php esc_html_e( 'If selected, when the user logs out from Wordpress it will also terminate the session in OpenAM.', 'openam-auth' ); ?></label>
        </span></fieldset></td>

                <tr valign="middle">
                    <td><label for="openam_wordpress_attributes"><?php esc_html_e( 'OpenAM attributes to map Login Name and Mail address', 'openam-auth' ); ?></label></td>
                    <td><input type="text" name="openam_wordpress_attributes" value="<?php echo esc_attr( get_option( 'openam_wordpress_attributes' ) ); ?>" class="regular-text code" />
                    </td><td><span class="description">
        <?php printf( esc_html__( 'Comma separated name of the OpenAM attributes to map login name and mail. Example: %s', 'openam-auth' ), '<code>uid,mail</code>' ); ?>
    </span>
                    </td>
                </tr>

                <tr valign="middle">
                    <td><?php esc_html_e( 'Redirect to OpenAM for Login', 'openam-auth' ); ?></td>
                    <td>
                        <fieldset><legend class="screen-reader-text"><span>
        <?php esc_html_e( 'Redirect to OpenAM for Login', 'openam-auth' ); ?>
            </span></legend><label for="openam_do_redirect">
                                <input name="openam_do_redirect" type="checkbox" id="openam_do_redirect" value="1" <?php checked( '1', get_option( 'openam_do_redirect' ) ); ?> />
                    </td><td><span class="description"><?php esc_html_e( 'For authentication chains and modules with a more complex workflow than user/password, redirect to OpenAM', 'openam-auth' ); ?></label>
        </span></fieldset></td></tr>

                <tr valign="middle">

                    <td><?php esc_html_e( 'Enable debug', 'openam-auth' ); ?></td>
                    <td>
                        <fieldset><legend class="screen-reader-text"><span>
        <?php esc_html_e( 'Enable debug', 'openam-auth' ); ?>
            </span></legend><label for="openam_debug_enabled">
                                <input name="openam_debug_enabled" type="checkbox" id="openam_debug_enabled" value="1" <?php checked( '1', get_option( 'openam_debug_enabled' ) ); ?> />
                    </td><td><span class="description"><?php esc_html_e( 'Enables debug in the module. If enabled, the debug file must be specified. Remember to turn off in production environment', 'openam-auth' ); ?></label>
        </span></fieldset></td>
                </tr>

                <tr valign="middle">
                    <td><label for="openam_debug_file"><?php esc_html_e( 'Name of the debug file', 'openam-auth' ); ?></label></td>
                    <td><input type="text" name="openam_debug_file" value="<?php echo esc_attr( get_option( 'openam_debug_file' ) ); ?>" class="regular-text code" />
                    </td><td><span class="description">
        <?php esc_html_e( 'Name of the debug file', 'openam-auth' ); ?>
    </span>
                    </td>
                </tr>

            </table>

            <input type="hidden" name="action" value="update" />
            <input type="hidden" name="page_options" value="openam_rest_enabled,
       openam_legacy_apis_enabled,openam_cookie_name,openam_cookie_domain,
       openam_base_url,openam_realm,openam_authn_module,openam_service_chain,
       openam_logout_too,openam_do_redirect,openam_wordpress_attributes,
       openam_debug_enabled, openam_debug_file, openam_loginbyemail" />

            <p class="submit">
                <input type="submit" class="button-primary" value="<?php esc_attr_e( 'Save Changes', 'openam-auth' ); ?>" />
            </p>

        </form>
    </div>
<?php
}

/**
 * Load the translation
 */
function openam_i18n() {
    load_plugin_textdomain( 'openam-auth', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}


