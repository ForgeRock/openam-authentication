<?php
/*
Plugin Name: OpenAM Authentication
Plugin URI: https://forgerock.org
Description: This plugin is used to authenticate users using OpenAM. The plugin uses REST calls to the OpenAM. The required REST APIs are: /json/authenticate; /json/users/ and /json/sessions. Therefore you need OpenAM 11.0 and above. This plugin is not supported officially by ForgeRock.
Version: 1.5
Author: Victor info@forgerock.com, openam@forgerock.org (subscribe to mailing list firt)
Author URI: http://www.forgerock.org
Text Domain: openam-auth
*/

/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at https://forgerock.org/cddlv1-0/. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2014-2017 ForgeRock AS.
 */

defined( 'ABSPATH' ) or die();

define( 'OPENAM_PLUGIN_VERSION', '1.5' );

include 'openam-settings.php';
include 'plugin-update.php';

add_filter( 'authenticate',   'openam_auth', 10, 3 );
add_filter( 'logout_url',     'openam_logout', 10, 2 );
add_filter( 'login_url',      'openam_login_url', 10, 2 );
add_action( 'plugins_loaded', 'openam_maybe_update', 8 ); // first thing to run here
add_action( 'plugins_loaded', 'openam_setup_constants', 9 ); // second thing to run here
add_action( 'plugins_loaded', 'openam_i18n' );
add_action( 'plugins_loaded', 'openam_sso' );
add_action( 'wp_logout',      'openam_wp_logout' );

// Options
// OpenAM General configuration parameters
function openam_plugin_activate() {
	update_option( 'openam_plugin_version',            OPENAM_PLUGIN_VERSION );

	add_option( 'openam_rest_enabled',                 0 );
	add_option( 'openam_api_version',                  '1.0' );
	add_option( 'openam_cookie_name',                  'iPlanetDirectoryPro' );
	add_option( 'openam_cookie_domain',                sanitize_file_name( substr( $_SERVER['HTTP_HOST'], 0, strpos($_SERVER['HTTP_HOST'], ':') ) ) );
	add_option( 'openam_base_url',                     'https://openam.example.com:443/openam' );
	add_option( 'openam_realm',                        '' );
	add_option( 'openam_authn_module',                 '' );
	add_option( 'openam_service_chain',                '' );
	add_option( 'openam_logout_too',                   0 );
	add_option( 'openam_wordpress_attributes',         'uid,mail' );
	add_option( 'openam_do_redirect',                  0 );
	add_option( 'openam_success_redirect', 		   home_url() );
	add_option( 'openam_debug_enabled',                0 );

	add_option( 'openam_sslverify',                    'false' );

	add_option( 'openam_debug_file',                   get_temp_dir() . DIRECTORY_SEPARATOR . wp_unique_filename( get_temp_dir(), 'openam-' . wp_generate_password( mt_rand( 32, 64 ), false ) ) ); // generate semi-secret filename for logging
}
register_activation_hook( __FILE__, 'openam_plugin_activate' );



// Constants
function openam_setup_constants() {
	// OpenAM General Configuration parameters
	define( 'OPENAM_REST_ENABLED',                      get_option( 'openam_rest_enabled' ) );
	define( 'OPENAM_API_VERSION',                       get_option( 'openam_api_version' ) );
	define( 'OPENAM_LEGACY_APIS_ENABLED',               ( 'legacy' == OPENAM_API_VERSION ? true : false ) );
	define( 'OPENAM_COOKIE_NAME',                       get_option( 'openam_cookie_name' ) );
	define( 'DOMAIN',                                   get_option( 'openam_cookie_domain'));
	define( 'OPENAM_BASE_URL',                          get_option( 'openam_base_url' ) );
	define( 'OPENAM_REALM',                             get_option( 'openam_realm' ) );
	define( 'OPENAM_AUTHN_MODULE',                      get_option( 'openam_authn_module' ) );
	define( 'OPENAM_SERVICE_CHAIN',                     get_option( 'openam_service_chain' ) );
	define( 'OPENAM_WORDPRESS_ATTRIBUTES',              get_option( 'openam_wordpress_attributes' ) );
	$OPENAM_WORDPRESS_ATTRIBUTES_ARRAY =  explode( ',', OPENAM_WORDPRESS_ATTRIBUTES );
	define( 'OPENAM_WORDPRESS_ATTRIBUTES_USERNAME',     $OPENAM_WORDPRESS_ATTRIBUTES_ARRAY[0] );
	define( 'OPENAM_WORDPRESS_ATTRIBUTES_MAIL',         $OPENAM_WORDPRESS_ATTRIBUTES_ARRAY[1] );
	define( 'OPENAM_LOGOUT_TOO',                        get_option( 'openam_logout_too' ) );
	define( 'OPENAM_SUCCESS_REDIRECT',                  get_option( 'openam_success_redirect' ) );
	define( 'OPENAM_DO_REDIRECT',                       get_option( 'openam_do_redirect' ) );
	define( 'OPENAM_DEBUG_ENABLED',                     get_option( 'openam_debug_enabled' ) );
	define( 'OPENAM_DEBUG_FILE',                        get_option( 'openam_debug_file' ) );
	define( 'OPENAM_SSLVERIFY',                         ( 'true' == get_option( 'openam_sslverify' ) ? true : false ) );

	// OpenAM API endpoints
	define( 'OPENAM_AUTHN_URI',                         '/json/authenticate' );
	define( 'OPENAM_ATTRIBUTES_URI',                    '/json/users/' );
	define( 'OPENAM_SESSION_URI',                       '/json/sessions/' );

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
}

/**
 * Auto-login the user
 */
function openam_sso() {
	if ( ( isset( $_GET['action'] ) && 'logout' == $_GET['action'] ) || ( isset( $_GET['loggedout'] ) && 'yes' == $_GET['loggedout'] ) ) {
		return;
	}
	// Let's see if the user is already logged in the IDP.
        // Notice that the OPENAM_COOKIE_NAME Will be accessible for this plugin only if the OpenAM and Wordpress are in the SAME DOMAIN!
	if ( isset( $_COOKIE[ OPENAM_COOKIE_NAME ] ) ) {
		$tokenId = trim($_COOKIE[ OPENAM_COOKIE_NAME ], '"');
		if ( ! empty( $tokenId ) && ! is_user_logged_in() ) {
			openam_debug( 'openam_auth: TOKENID:' . $tokenId );
			if ( $am_response = openam_sessionsdata( $tokenId ) ) {

				openam_debug( 'openam_auth: Authentication was successful SUCCESS' );
				openam_debug( 'openam_auth: am_response ' . print_r( $am_response, true ) );

				$amAttributes = getAttributesFromOpenAM( $tokenId, $am_response[ OPENAM_WORDPRESS_ATTRIBUTES_USERNAME ], OPENAM_WORDPRESS_ATTRIBUTES );
				$usernameAttr = openam_get_attribute_value( $amAttributes, OPENAM_WORDPRESS_ATTRIBUTES_USERNAME );
				$mailAttr = openam_get_attribute_value( $amAttributes, OPENAM_WORDPRESS_ATTRIBUTES_MAIL );

				openam_debug( 'openam_auth: UID: ' . print_r( $usernameAttr, true ) );
				openam_debug( 'openam_auth: MAIL: ' . print_r( $mailAttr, true ) );

				// This should return a WP_User instance https://codex.wordpress.org/Class_Reference/WP_User
				$user = loadUser( $usernameAttr, $mailAttr );

				// Log in the user
				wp_set_current_user( $user->ID, $user->user_login );
				wp_set_auth_cookie( $user->ID );
				do_action( 'wp_login', $user->user_login, $user );
			}
		}
	}
}

/* Main function */
function openam_auth( $user, $username, $password ) {

	if ( OPENAM_REST_ENABLED ) {

		// If username and password has been supplied then we are starting here
		if ( '' != $username && '' != $password ) {
			$tokenId = authenticateWithOpenAM( $username, $password );
			if ( ! $tokenId ) {
				// User does not exist,  send back an error message
				return new WP_Error( 'denied', esc_html__( 'The combination username/password was not correct', 'openam-auth' ) );
			} elseif ( 2 == $tokenId ) {
				return new WP_Error( 'denied', esc_html__( 'Error when trying to reach the OpenAM', 'openam-auth' ) );
			} else {
				$amAttributes = getAttributesFromOpenAM( $tokenId, $username, OPENAM_WORDPRESS_ATTRIBUTES );
				if ( $amAttributes ) {
					$usernameAttr = openam_get_attribute_value( $amAttributes, OPENAM_WORDPRESS_ATTRIBUTES_USERNAME );
					$mailAttr = openam_get_attribute_value( $amAttributes, OPENAM_WORDPRESS_ATTRIBUTES_MAIL );
					openam_debug( 'openam_auth: UID: ' . print_r( $usernameAttr, true ) );
					openam_debug( 'openam_auth: MAIL: ' . print_r( $mailAttr, true ) );
					$user = loadUser( $usernameAttr, $mailAttr );
					remove_action( 'authenticate', 'wp_authenticate_username_password', 20 );

					return $user;
				}
			}
		}
	}

	return $user;
}

/**
 * Validate a session
 */
function openam_sessionsdata( $tokenId ) {

	if ( ! OPENAM_LEGACY_APIS_ENABLED ) {
		openam_debug( 'openam_sessionsdata: Legacy Mode Disabled' );
		$isTokenValid_am_response = wp_remote_post( OPENAM_BASE_URL . OPENAM_SESSION_URI . $tokenId . '?_action=validate' , array(
			'method'      => 'POST',
			'timeout'     => 45,
			'redirection' => 5,
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => array('Content-Type' => 'application/json', 'Accept-API-Version' => 'resource=1.0, protocol=1.0'),
			'body'        => array(),
			'sslverify'   => OPENAM_SSLVERIFY,
			'cookies'     => array(),
		) );

		if ( is_wp_error( $isTokenValid_am_response ) ) {
			$error_message = $isTokenValid_am_response->get_error_message();
			openam_debug( 'openam_sessionsdata: is_wp_error' . $error_message );
		}

		openam_debug( 'openam_sessionsdata: isTokenValid_am_response ' . print_r( $isTokenValid_am_response['body'], true ) );

		$response_string = $isTokenValid_am_response['body'];
		$response = json_decode( $response_string );

		if ( true == $response->valid ) {
			openam_debug( 'openam_sessionsdata: returning true from -> $response->valid' );

			$am_response = (array) $response;

			openam_debug( 'openam_sessionsdata: am_response: ' . $am_response );

			return $am_response;
		}

	} else {
		openam_debug( 'openam_sessionsdata: Legacy Mode Enabled' );
		$sessions_url = OPENAM_BASE_URL . OPENAM_LEGACY_SESSION_VALIDATION;
		$response     = wp_remote_post( $sessions_url . '?tokenid=' . $tokenId, array( 'sslverify' => OPENAM_SSLVERIFY ) );
		openam_debug( 'openam_sessionsdata: isValid Response: ' . print_r( $response, true ) );
		$amResponse   = json_decode( $response['body'], true );

		return $amResponse;
	}

	return false;
}


/* Loads a user if found, if not it creates it in the local database using the
 * attributes pulled from OpenaM
 */
function loadUser( $login, $mail ) {
	$userobj = new WP_User();
	$user    = $userobj->get_data_by( 'login', $login );
	$user    = new WP_User( $user->ID ); // Attempt to load up the user with that ID
	openam_debug( 'loadUser: user object: ' . print_r( $user, true ) );

	if ( 0 == $user->ID ) { // User did not exist
		$userdata = array(
			'user_email' => $mail,
			'user_login' => $login,
		);
		$new_user_id = wp_insert_user( $userdata ); // A new user has been created
		// Load the new user info
		$user = new WP_User( $new_user_id );
	}
	openam_debug( 'loadUser: WP_User loaded: ' . print_r( $user, true ) );

	return $user;
}

/* Authenticates a user in OpenAM using the credentials passed  */
function authenticateWithOpenAM( $username, $password ) {
	if ( ! OPENAM_LEGACY_APIS_ENABLED ) {
		return authenticateWithModernOpenAM( $username, $password );
	} else {
		return authenticateWithLegacyOpenAM( $username, $password );
	}
}

/* Authenticates a user in a modern OpenAM using the credentials passed  */
function authenticateWithModernOpenAM( $username, $password ) {
	$authentication_url = createAuthenticationURL();
	openam_debug( 'authenticateWithModernOpenAM: AUTHN URL: ' . $authentication_url );
	$headers = array(
		'X-OpenAM-Username' => $username,
		'X-OpenAM-Password' => $password,
		'Content-Type'      => 'application/json',
	);
	$response = wp_remote_post( $authentication_url, array(
		'headers'   => $headers,
		'body'      => '{}',
		'sslverify' => OPENAM_SSLVERIFY,
	) );
	openam_debug( 'authenticateWithModernOpenAM: RAW AUTHN RESPONSE: ' . print_r( $response, true ) );

	if ( empty( $response->errors['http_request_failed'] ) ) {
		if ( 200 == $response['response']['code'] ) {
			$amResponse      = json_decode( $response['body'], true );
			$number_of_hours = 2;
			$expiration_date = time() + 60 * 60 * $number_of_hours;
			setrawcookie( OPENAM_COOKIE_NAME, $amResponse['tokenId'], $expiration_date, '/', DOMAIN );
			openam_debug( 'authenticateWithModernOpenAM:: AUTHN Response: ' . print_r( $amResponse, true ) );

			return $amResponse['tokenId'];
		}

		return 0;
	} else {
		return 2;
	}
}

/* Authenticates a user with a legacy OpenAM using the credentials passed  */
function authenticateWithLegacyOpenAM( $username, $password ) {
	$authentication_url = OPENAM_BASE_URL . OPENAM_LEGACY_AUTHN_URI;
	openam_debug( 'authenticateWithLegacyOpenAM: AUTHN URL: ' . $authentication_url );
	$uri_param = createLegacyAuthenticationURIParams();
	$uri       = '?username=' . $username . '&password=' . $password . $uri_param;
	$response  = wp_remote_post( $authentication_url . $uri, array(
		'headers'   => $headers,
		'sslverify' => OPENAM_SSLVERIFY,
	) );
	openam_debug( 'authenticateWithLegacyOpenAM: RAW AUTHN RESPONSE: ' . print_r( $response, true ) );

	if ( empty( $response->errors['http_request_failed'] ) ) {
		if ( 200 == $response['response']['code'] ) {
			$amResponse      = json_decode( $response['body'], true );
			$number_of_hours = 2;
			$expiration_date = time() + 60 * 60 * $number_of_hours;
			setrawcookie( OPENAM_COOKIE_NAME, $amResponse['tokenId'], $expiration_date, '/', DOMAIN );
			openam_debug( 'authenticateWithLegacyOpenAM: AUTHN RESPONSE: ' . print_r( $amResponse, true ) );

			return $amResponse['tokenId'];
		}

		return 0;
	} else {
		return 2;
	}
}


/* Creates the proper OpenAM authentication URL using the parameters configured */
function createAuthenticationURL() {

	$authentication_url = OPENAM_BASE_URL . OPENAM_AUTHN_URI;

	if ( '' != OPENAM_REALM ) {
		$authentication_url .= '?' . REALM_PARAM . '=' . OPENAM_REALM;
	}

	if ( '' != OPENAM_AUTHN_MODULE ) {
		if ( ! stripos( $authentication_url, '?' ) ) {
			$authentication_url .= '?' . AUTH_TYPE . '=' . MODULE_PARAM . '&' . AUTH_VALUE . '=' . OPENAM_AUTHN_MODULE;
		} else {
			$authentication_url .= '&' . AUTH_TYPE . '=' . MODULE_PARAM . '&' . AUTH_VALUE . '=' . OPENAM_AUTHN_MODULE;
		}
	} else {
		if ( '' != OPENAM_SERVICE_CHAIN ) {
			if ( ! stripos( $authentication_url, '?' ) ) {
				$authentication_url .= '?' . AUTH_TYPE . '=' . SERVICE_PARAM . '&' . AUTH_VALUE . '=' . OPENAM_SERVICE_CHAIN;
			} else {
				$authentication_url .= '&' . AUTH_TYPE . '=' . SERVICE_PARAM . '&' . AUTH_VALUE . '=' . OPENAM_SERVICE_CHAIN;
			}
		}
	}

	return $authentication_url;
}

/* Creates the proper OpenAM authentication URL using the parameters configured */
function createLegacyAuthenticationURIParams() {

	$uri = '';

	if ( '' != OPENAM_REALM ) {
		$uri = REALM_PARAM . '=' . OPENAM_REALM;
	}

	if ( '' != OPENAM_AUTHN_MODULE ) {
		if ( '' != $uri ) {
			$uri .= '&' . MODULE_PARAM . '=' . OPENAM_AUTHN_MODULE;
		} else {
			$uri = MODULE_PARAM . '=' . OPENAM_AUTHN_MODULE;
		}
	} else {
		if ( '' != OPENAM_SERVICE_CHAIN ) {
			if ( '' != $uri ) {
				$uri .= '&' . SERVICE_PARAM . '=' . OPENAM_SERVICE_CHAIN;
			} else {
				$uri = SERVICE_PARAM . '=' . OPENAM_SERVICE_CHAIN;
			}
		}
	}

	$uri_param = '';
	if ( '' != $uri ) {
		$uri_param = '&uri=' . urlencode( $uri );
	}

	return $uri_param;
}


/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromOpenAM( $tokenId, $username, $attributes ) {
	if ( ! OPENAM_LEGACY_APIS_ENABLED ) {
		openam_debug( 'getAttributesFromOpenAM: LEGACY NOT ENABLED' );

		return getAttributesFromModernOpenAM( $tokenId, $username, $attributes );
	} else {
		openam_debug( 'getAttributesFromOpenAM: LEGACY ENABLED' );

		return getAttributesFromLegacyOpenAM( $tokenId, $attributes );
	}
}


/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromModernOpenAM( $tokenId, $username, $attributes ) {
	$attributes_url = createAttributesURL();
	openam_debug( 'getAttributesFromModernOpenAM: ATTRIBUTE URL: ' . $attributes_url );
	$headers = array(
		OPENAM_COOKIE_NAME => $tokenId,
		'Content-Type'     => 'application/json',
	);
	$url = $attributes_url . $username . '?_fields=' . $attributes;
	openam_debug( 'getAttributesFromModernOpenAM: full url: ' . $url );
	$response = wp_remote_get( $url, array(
		'headers'   => $headers,
		'sslverify' => OPENAM_SSLVERIFY,
	) );
	openam_debug( 'getAttributesFromModernOpenAM: RAW ATTR RESPONSE: ' . print_r( $response, true ) );
	$amResponse = json_decode( $response['body'], true );
	openam_debug( 'getAttributesFromModernOpenAM: ATTRIBUTE RESP: ' . print_r( $amResponse, true ) );
	if ( 200 == $response['response']['code'] ) {
		return $amResponse;
	} else {
		return 0;
	}

}

/* Creates the proper OpenAM Attributes URL using the configured parameters */
function createAttributesURL() {

	$attributes_url = OPENAM_BASE_URL . OPENAM_ATTRIBUTES_URI;
	if ( '' != OPENAM_REALM && '/' != OPENAM_REALM ) {
		$attributes_url = str_replace( '/users', OPENAM_REALM . '/users', $attributes_url );
	}

	return $attributes_url;
}

/* Pulls attributes from OpenAM using the existing session and username */
function getAttributesFromLegacyOpenAM( $tokenId, $attributes ) {
	$attributes_url = createAttributesLegacyURL( $tokenId );

	openam_debug( 'getAttributesFromLegacyOpenAM: Attributes URL: ' . $attributes_url );
	$response = wp_remote_get( $attributes_url, array( 'sslverify' => OPENAM_SSLVERIFY ) );
	openam_debug( 'getAttributesFromLegacyOpenAM: RAW ATTRS RESPONSE: ' . print_r( $response, true ) );
	$amResponse = json_decode( $response['body'], true );
	openam_debug( 'getAttributesFromLegacyOpenAM: ATTRIBUTES RESPONSE: ' . print_r( $amResponse, true ) );
	if ( 200 == $response['response']['code'] ) {
		$attr1       = $amResponse['attributes'];
		$amResponse2 = array();
		foreach ( $attr1 as $json_attr ){
			$attr_name  = $json_attr['name'];
			$attr_value = $json_attr['values'];
			$amResponse2[ $attr_name ] = $attr_value;
		}
		openam_debug( 'getAttributesFromLegacyOpenAM: Attributes: ' . print_r( $amResponse2, true ) );

		return $amResponse2;
	} else {
		return 0;
	}

}

/* Creates the proper OpenAM Attributes URL using the configured parameters */
function createAttributesLegacyURL( $tokenId ) {

	$attributes_url = OPENAM_BASE_URL . OPENAM_LEGACY_ATTRIBUTES_URI . '?subjectid=' . $tokenId;
	if ( '' != OPENAM_WORDPRESS_ATTRIBUTES ) {
		$attributes    = explode( ',', OPENAM_WORDPRESS_ATTRIBUTES );
		$attribute_uri = '';
		foreach ( $attributes as $attributename ) {
			$attribute_uri .= '&attributenames=' . $attributename;
		}
		$attributes_url .= $attribute_uri;
	}

	return $attributes_url;
}


/* Returns a modified logout url, where the user is redirected back to the
 * users's blog url (instead of the wp-login page.
 */
function openam_logout( $logout_url, $redirect = null ) {
	return $logout_url . '&amp;redirect_to=' . urlencode( get_bloginfo( 'url' ) );
}


/*
 * It logs out a user from Wordpress and if it was opted to destory the OpenAM session,
 * it will logout the user from OpenAM as well.
 */
function openam_wp_logout() {

	if ( OPENAM_REST_ENABLED && OPENAM_LOGOUT_TOO ) {

		$tokenId = $_COOKIE[ OPENAM_COOKIE_NAME ];

		if( ! empty( $tokenId ) ) {
			$headers = array(
				OPENAM_COOKIE_NAME => $tokenId,
				'Content-Type'     => 'application/json',
			);
			$url = OPENAM_BASE_URL . OPENAM_SESSION_URI . '?_action=logout';
			$response = wp_remote_post( $url, array(
				'headers'   => $headers,
				'sslverify' => OPENAM_SSLVERIFY,
			) );
			openam_debug( 'wp_logout: RAW RESPONSE LOGOUT: ' . print_r( $response, true ) );
			$expiration_date = time() - 3600;
			setcookie( OPENAM_COOKIE_NAME, '', $expiration_date, '/', DOMAIN );
		}
	}
}

/* Creates the proper OpenAM authentication URL using the parameters configured */
function createOpenAMLoginURL() {

	$authentication_url = OPENAM_BASE_URL . '/UI/Login';
	if ( '' != OPENAM_REALM ) {
		$authentication_url .= '?' . REALM_PARAM . '=' . OPENAM_REALM;
	}

	if ( '' != OPENAM_AUTHN_MODULE ) {
		if ( ! stripos( $authentication_url, '?' ) ) {
			$authentication_url .= '?' . MODULE_PARAM . '=' . OPENAM_AUTHN_MODULE;
		} else {
			$authentication_url .= '&' . MODULE_PARAM . '=' . OPENAM_AUTHN_MODULE;
		}
	} else {
		if ( '' != OPENAM_SERVICE_CHAIN ) {
			if ( ! stripos( $authentication_url, '?' ) ) {
				$authentication_url .= '?' . SERVICE_PARAM . '=' . OPENAM_SERVICE_CHAIN;
			} else {
				$authentication_url .= '&' . SERVICE_PARAM . '=' . OPENAM_SERVICE_CHAIN;
			}
		}
	}

	return $authentication_url;
}

function openam_login_url( $login_url, $redirect = null ) {
	openam_debug('openam_login_url: The current login URL is: ' . $login_url);

	if ( OPENAM_DO_REDIRECT ) {
		$new_url = createOpenAMLoginURL();
		if ( ! stripos( $new_url, '?' ) ) {
			$new_url .= '?' . 'goto=' . urlencode( OPENAM_SUCCESS_REDIRECT );
		} else {
			$new_url .= '&' . 'goto=' . urlencode( OPENAM_SUCCESS_REDIRECT );
		}
		openam_debug('openam_login_url: New Login URL is: ' . $new_url);
		return $new_url;
	} else {
		return $login_url;
	}
}

/* Writes to the debug file if debugging has been enabled
 *
 */
function openam_debug( $message ) {
	if ( OPENAM_DEBUG_ENABLED ) {
		error_log( $message . "\n", 3, OPENAM_DEBUG_FILE );
		chmod( OPENAM_DEBUG_FILE, 0600 );
	}
}


/*
 * Select the attribute value :
 * if it's an array, we return the first value of it. if not, we directly return the attribute value
 */
function openam_get_attribute_value( $attributes, $attributeId ) {
	if( is_array( $attributes[$attributeId] ) ) {
		return $attributes[ $attributeId ][0];
	} else {
		return $attributes[ $attributeId ];
	}
}


/**
 * Load the translation
 */
function openam_i18n() {
	load_plugin_textdomain( 'openam-auth', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}
