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
 * Copyright 2017 ForgeRock AS.
 */

defined( 'ABSPATH' ) or die();


function openam_maybe_update() {

	$registered_version = get_option( 'openam_plugin_version', 0 );

	if ( -1 == version_compare( $registered_version, OPENAM_PLUGIN_VERSION ) ) {

		if ( -1 == version_compare( $registered_version, '1.3' ) ) {
			openam_update_to_1_3();
		}

    if ( -1 == version_compare( $registered_version, '1.4' ) ) {
			openam_update_to_1_4();
		}

		if ( -1 == version_compare( $registered_version, '1.5' ) ) {
			openam_update_to_1_4();
		}

		update_option( 'openam_plugin_version', OPENAM_PLUGIN_VERSION );
	}
}

function openam_update_to_1_3() {
	$openam_api_version = get_option( 'openam_api_version', 0 );

        if ( ! $openam_api_version ) {
                if ( get_option( 'openam_legacy_apis_enabled', 0 ) ) {
                        update_option( 'openam_api_version', 'legacy' );
                } else {
                        update_option( 'openam_api_version', '1.0' );
                }
		update_option( 'openam_sslverify', 'false' );
	}
}

function openam_update_to_1_4() {
	update_option( 'openam_success_redirect', home_url() );
}
