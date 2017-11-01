<?php
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
 * Copyright 2015-2017 ForgeRock AS.
 */

defined( 'ABSPATH' ) or die();

add_action( 'admin_menu', 'openam_add_admin_menu' );
add_action( 'admin_init', 'openam_settings_init' );


function openam_add_admin_menu() {
	add_options_page( 'OpenAM REST Plugin', 'OpenAM REST', 'manage_options', 'openam', 'openam_options_page' );
}


function openam_settings_init() {

	register_setting( 'openam_options', 'openam_rest_enabled' );
	register_setting( 'openam_options', 'openam_api_version' );
	register_setting( 'openam_options', 'openam_cookie_name' );
	register_setting( 'openam_options', 'openam_cookie_domain' );
	register_setting( 'openam_options', 'openam_base_url' );
	register_setting( 'openam_options', 'openam_realm' );
	register_setting( 'openam_options', 'openam_authn_module' );
	register_setting( 'openam_options', 'openam_service_chain' );
	register_setting( 'openam_options', 'openam_logout_too' );
	register_setting( 'openam_options', 'openam_wordpress_attributes' );
	register_setting( 'openam_options', 'openam_do_redirect' );
	register_setting( 'openam_options', 'openam_success_redirect' );
	register_setting( 'openam_options', 'openam_debug_enabled' );
	register_setting( 'openam_options', 'openam_debug_file' );
	register_setting( 'openam_options', 'openam_sslverify', 'openam_sslverify_sanitize_callback' );


	/**
	 * Sections
	 */
	add_settings_section(
		'openam_api_settings_section',
		__( 'API Settings', 'openam-auth' ),
		'openam_settings_section_api_callback',
		'openam_options'
	);

	add_settings_section(
		'openam_cookies_settings_section',
		__( 'Cookie Settings', 'openam-auth' ),
		'openam_settings_section_cookies_callback',
		'openam_options'
	);

	add_settings_section(
		'openam_openam_settings_section',
		__( 'OpenAM Settings', 'openam-auth' ),
		'openam_settings_section_openam_callback',
		'openam_options'
	);

	add_settings_section(
		'openam_wordpress_settings_section',
		__( 'WordPress Settings', 'openam-auth' ),
		'openam_settings_section_wordpress_callback',
		'openam_options'
	);

	add_settings_section(
		'openam_debug_settings_section',
		__( 'Debugging', 'openam-auth' ),
		'openam_settings_section_debugging_callback',
		'openam_options'
	);

	/**
	 * Fields
	 */

	/* API Settings Fields */

	add_settings_field(
		'openam_rest_enabled',
		__( 'OpenAM REST enabled', 'openam-auth' ),
		'openam_rest_enabled_settings_field_render',
		'openam_options',
		'openam_api_settings_section'
	);

	add_settings_field(
		'openam_api_version',
		__( 'OpenAM API Version', 'openam-auth' ),
		'openam_api_version_settings_field_render',
		'openam_options',
		'openam_api_settings_section'
	);

	/* Cookie Settings Fields */

	add_settings_field(
		'openam_cookie_name',
		__( 'OpenAM Session Cookie', 'openam-auth' ),
		'openam_cookie_name_settings_field_render',
		'openam_options',
		'openam_cookies_settings_section'
	);

	add_settings_field(
		'openam_cookie_domain',
		__( 'Cookie Domain', 'openam-auth' ),
		'openam_cookie_domain_settings_field_render',
		'openam_options',
		'openam_cookies_settings_section'
	);

	/* OpenAM Settings Fields */

	add_settings_field(
		'openam_base_url',
		__( 'OpenAM base URL', 'openam-auth' ),
		'openam_base_url_settings_field_render',
		'openam_options',
		'openam_openam_settings_section'
	);

	add_settings_field(
		'openam_realm',
		__( 'OpenAM realm where users reside', 'openam-auth' ),
		'openam_realm_settings_field_render',
		'openam_options',
		'openam_openam_settings_section'
	);

	add_settings_field(
		'openam_authn_module',
		__( 'OpenAM Authentication Module', 'openam-auth' ),
		'openam_authn_module_settings_field_render',
		'openam_options',
		'openam_openam_settings_section'
	);

	add_settings_field(
		'openam_service_chain',
		__( 'OpenAM Authentication Service (Chain)', 'openam-auth' ),
		'openam_service_chain_settings_field_render',
		'openam_options',
		'openam_openam_settings_section'
	);

	add_settings_field(
		'openam_sslverify',
		__( 'Verify SSL/TLS certificate', 'openam-auth' ),
		'openam_sslverify_settings_field_render',
		'openam_options',
		'openam_openam_settings_section'
	);

	/* WordPress Settings Fields */

	add_settings_field(
		'openam_logout_too',
		__( 'Logout from OpenAM when logging out from Wordpress', 'openam-auth' ),
		'openam_logout_too_settings_field_render',
		'openam_options',
		'openam_wordpress_settings_section'
	);

	add_settings_field(
		'openam_wordpress_attributes',
		__( 'OpenAM attributes to map Login Name and Mail address', 'openam-auth' ),
		'openam_wordpress_attributes_settings_field_render',
		'openam_options',
		'openam_wordpress_settings_section'
	);

	add_settings_field(
		'openam_do_redirect',
		__( 'Redirect to OpenAM for Login', 'openam-auth' ),
		'openam_do_redirect_settings_field_render',
		'openam_options',
		'openam_wordpress_settings_section'
	);

	add_settings_field(
		'openam_success_redirect',
		__( 'Page to go after OpenAM Successful login', 'openam-auth' ),
		'openam_success_redirect_settings_field_render',
		'openam_options',
		'openam_wordpress_settings_section'
	);

	/* Debugging Settings Fields */

	add_settings_field(
		'openam_debug_enabled',
		__( 'Enable debug', 'openam-auth' ),
		'openam_debug_enabled_settings_field_render',
		'openam_options',
		'openam_debug_settings_section'
	);

	add_settings_field(
		'openam_debug_file',
		__( 'Debug File', 'openam-auth' ),
		'openam_debug_file_settings_field_render',
		'openam_options',
		'openam_debug_settings_section'
	);


}


/*
 * Sanitation callbacks
 */

function openam_sslverify_sanitize_callback( $value ) {
	if ( 'true' != $value ) {
		$value = 'false';
	}

	return $value;
}



/*
 * Render fields
 */

function openam_rest_enabled_settings_field_render() {
	?>
	<label>
		<input name="openam_rest_enabled" type="checkbox" id="openam_rest_enabled" value="1" <?php checked( '1', get_option( 'openam_rest_enabled' ) ); ?>>
		<?php esc_html_e( 'Enabled', 'openam-auth' ); ?>
	</label>
	<p class="description">
		<?php esc_html_e( 'Enable or disable this plugin', 'openam-auth' ); ?>
	</p>
	<?php

}


function openam_api_version_settings_field_render() {

	$openam_api_version = get_option( 'openam_api_version' );
	?>
	<select name="openam_api_version" id="openam_api_version">
		<option value="1.0" <?php selected( '1.0', $openam_api_version ); ?>>1.0 (OpenAM 12 and 13)</option>
		<option value="legacy" <?php selected( 'legacy', $openam_api_version ); ?>>Legacy (OpenAM 9, 10 and 11)</option>
	</select>

	<p class="description" style="<?php if ( '1.0' != $openam_api_version ) { echo 'display:none;'; } ?>" data-openam-api-version="1.0">
		<?php esc_html_e( 'Notice that legacy versions of the OpenAM API will be deprecated in the short future', 'openam-auth' ); ?>
	</p>
	<p class="description" style="<?php if ( 'legacy' != $openam_api_version ) { echo 'display:none;'; } ?>" data-openam-api-version='legacy'>
		<?php esc_html_e( 'Legacy mode is selected. SSO is available.', 'openam-auth' ); ?>
	</p>

	<script>
	jQuery('#openam_api_version').on( 'change', function() {
		var version = jQuery(this).val();
		jQuery('.description[data-openam-api-version').hide();
		jQuery('.description[data-openam-api-version="'+version+'"]').fadeIn();
	} );
	</script>

<?php

}


function openam_cookie_name_settings_field_render() {

	?>
	<input type="text" name="openam_cookie_name" value="<?php echo esc_attr( get_option( 'openam_cookie_name' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php printf( esc_html__( 'Default in OpenAM is %s, but can be something different. Check with the OpenAM Administrator', 'openam-auth' ), '<code>iPlanetDirectoryPro</code>' ); ?>
	</p>
	<?php

}


function openam_cookie_domain_settings_field_render() {

	?>
	<input type="text" name="openam_cookie_domain" value="<?php echo esc_attr( get_option( 'openam_cookie_domain' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php esc_html_e( 'The Domain where the above cookie will be set, once the user authenticates. The default is the host server name, but it can be the domain component. It REALLY depends on your deployment, for SSO to WORK PROPERLY you should check with your OpenAM admininstrator. If you do not understand cookies and domains check with the OpenAM Administrator.', 'openam-auth' ); ?>
	</p>
	<?php

}


function openam_base_url_settings_field_render() {

	?>
	<input type="text" name="openam_base_url" value="<?php echo esc_attr( get_option( 'openam_base_url' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php printf( esc_html__( 'The OpenAM deployment URL. Example: %s', 'openam-auth' ), '<code>https://openam.example.com:443/openam</code>' ); ?>
	</p>
	<?php

}


function openam_realm_settings_field_render() {

	?>
	<input type="text" name="openam_realm" value="<?php echo esc_attr( get_option( 'openam_realm' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php printf( esc_html__( 'The OpenAM realm where users reside. Example: %1$s or %2$s', 'openam-auth' ), '<code>/</code>', '<code>/myrealm</code>' ); ?>
	</p>
	<?php

}


function openam_authn_module_settings_field_render() {

	?>
	<input type="text" name="openam_authn_module" value="<?php echo esc_attr( get_option( 'openam_authn_module' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php printf( esc_html__( 'The Authentication module to use in the OpenAM. Example: %1$s or %2$', 'openam-auth' ), '<code>DataStore</code>', '<code>LDAP</code>' ); ?>
		<br>
		<italic><?php esc_html_e( 'Note: Module and Service Chain can not be used at the same time. This option can be left empty, in which case the default module configured in OpenAM wil be used.
The module should only accept user and password, if that is not the case then enable “Redirect to OpenAM for Login”.', 'openam-auth' ); ?></italic>
	</p>
	<?php

}


function openam_service_chain_settings_field_render() {

	?>
	<input type="text" name="openam_service_chain" value="<?php echo esc_attr( get_option( 'openam_service_chain' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php printf( esc_html__( 'The Authentication Service or Chain to be used in the OpenAM. Example: %1$s or %2$s', 'openam-auth' ), '<code>ldapService</code>', '<code>myChain</code>' ); ?>
		<br><italic>
		<?php printf( 'Note: Service Chain and Module can not be used at the same time. This option can be left empty, in which case the default service configured in OpenAM wil be used. The modules in the chain should only accept user and password, if that is not the case then enable “Redirect to OpenAM for Login”.', 'openam-auth' ); ?></italic>
	</p>
	<?php

}

function openam_sslverify_settings_field_render() {

	?>
	<label>
		<input name="openam_sslverify" type="checkbox" id="openam_sslverify" value="true" <?php checked( 'true', get_option( 'openam_sslverify' ) ); ?>>
		<?php esc_html_e( 'Enabled', 'openam-auth' ); ?>
	</label>
	<p class="description">
		<?php esc_html_e( 'If the OpenAM server use a valid SSL/TLS certificate signed by a CA recognized by this server, you can enable verfication of the certificate for improved security.', 'openam-auth' ); ?>
	</p>
	<?php
}


function openam_logout_too_settings_field_render() {

	?>
	<label>
		<input name="openam_logout_too" type="checkbox" id="openam_logout_too" value="1" <?php checked( '1', get_option( 'openam_logout_too' ) ); ?>>
		<?php esc_html_e( 'Enabled', 'openam-auth' ); ?>
	</label>
	<p class="description">
		<?php esc_html_e( 'If selected, when the user logs out from Wordpress it will also terminate the session in OpenAM.', 'openam-auth' ); ?>
	</p>
	<?php

}


function openam_wordpress_attributes_settings_field_render() {

	?>
	<input type="text" name="openam_wordpress_attributes" value="<?php echo esc_attr( get_option( 'openam_wordpress_attributes' ) ); ?>" class="regular-text code">
	<p class="description">
		<?php printf( esc_html__( 'Comma separated name of the OpenAM attributes to map login name and mail. Example: %s', 'openam-auth' ), '<code>uid,mail</code>' ); ?>
	</p>
	<?php

}


function openam_do_redirect_settings_field_render() {

	$options = get_option( 'openam_settings' );
	?>
	<label>
		<input name="openam_do_redirect" type="checkbox" id="openam_do_redirect" value="1" <?php checked( '1', get_option( 'openam_do_redirect' ) ); ?>>
                <?php esc_html_e( 'Redirect to OpenAM for Login', 'openam-auth' ); ?>
	</label>
	<p class="description">
		<?php esc_html_e( 'For authentication chains and modules with a more complex workflow than user/password, redirect to OpenAM', 'openam-auth' ); ?>
	</p>
	<?php

}

function openam_success_redirect_settings_field_render() {

	$options = get_option( 'openam_settings' );
	?>

	<label>
		<input name="openam_success_redirect" type="text" id="openam_success_redirect" value="<?php echo esc_attr( get_option( 'openam_success_redirect' ) ); ?>" class="regular-text code" />
	</label>
	<p class="description">
		<?php esc_html_e( 'If Redirect to OpenAM was enabled, then this is the page to redirect back after a successful login in OpenAM', 'openam-auth' ); ?>
	</p>
	<?php

}

function openam_debug_enabled_settings_field_render() {

	?>
	<label for="openam_debug_enabled">
		<input name="openam_debug_enabled" type="checkbox" id="openam_debug_enabled" value="1" <?php checked( '1', get_option( 'openam_debug_enabled' ) ); ?>>
		<?php esc_html_e( 'Enable debug', 'openam-auth' ); ?>
	</label>
	<p class="description">
		<?php esc_html_e( 'Enables debug in the module. If enabled, the debug file must be specified. Remember to turn off in production environment', 'openam-auth' ); ?>
	</p>
	<?php

}


function openam_debug_file_settings_field_render() {

	?>
	<input type="text" name="openam_debug_file" value="<?php echo esc_attr( get_option( 'openam_debug_file' ) ); ?>" class="regular-text code"/>
	<p class="description">
		<?php esc_html_e( 'Name of the debug file', 'openam-auth' ); ?>
	</p>
	<?php

}


function openam_settings_section_api_callback() {
	//esc_html_e( 'This section description', 'openam-auth' );
}


function openam_settings_section_cookies_callback() {
	//esc_html_e( 'This section description', 'openam-auth' );
}


function openam_settings_section_openam_callback() {
	//esc_html_e( 'This section description', 'openam-auth' );
}


function openam_settings_section_wordpress_callback() {
	//esc_html_e( 'This section description', 'openam-auth' );
}


function openam_settings_section_debugging_callback() {
	//esc_html_e( 'This section description', 'openam-auth' );
}


function openam_options_page() {

	?>
	<form action='options.php' method='post'>

		<h2><?php esc_html_e( 'OpenAM REST Plugin Options', 'openam-auth' ); ?></h2>

		<?php
		settings_fields( 'openam_options' );
		do_settings_sections( 'openam_options' );
		submit_button();
		?>

	</form>
	<?php

}
