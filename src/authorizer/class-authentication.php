<?php
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

namespace Authorizer;

use Authorizer\Helper;
use Authorizer\Options;
use Authorizer\Authorization;

/**
 * Implements the authentication (is user who they say they are?) features of
 * the plugin.
 */
class Authentication extends Static_Instance {

	/**
	 * Authenticate against an external service.
	 *
	 * Filter: authenticate
	 *
	 * @param WP_User $user     user to authenticate.
	 * @param string  $username optional username to authenticate.
	 * @param string  $password optional password to authenticate.
	 * @return WP_User|WP_Error WP_User on success, WP_Error on failure.
	 */
	public function custom_authenticate( $user, $username, $password ) {
		// Pass through if already authenticated.
		if ( is_a( $user, 'WP_User' ) ) {
			return $user;
		} else {
			$user = null;
		}

		// If username and password are blank, this isn't a log in attempt.
		$is_login_attempt = strlen( $username ) > 0 && strlen( $password ) > 0;

		// Check to make sure that $username is not locked out due to too
		// many invalid login attempts. If it is, tell the user how much
		// time remains until they can try again.
		$unauthenticated_user            = $is_login_attempt ? get_user_by( 'login', $username ) : false;
		$unauthenticated_user_is_blocked = false;
		if ( $is_login_attempt && false !== $unauthenticated_user ) {
			$last_attempt = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
			$num_attempts = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
			// Also check the auth_blocked user_meta flag (users in blocked list will get this flag).
			$unauthenticated_user_is_blocked = get_user_meta( $unauthenticated_user->ID, 'auth_blocked', true ) === 'yes';
		} else {
			$last_attempt = get_option( 'auth_settings_advanced_lockouts_time_last_failed' );
			$num_attempts = get_option( 'auth_settings_advanced_lockouts_failed_attempts' );
		}

		// Inactive users should be treated like deleted users (we just
		// do this to preserve any content they created, but here we should
		// pretend they don't exist).
		if ( $unauthenticated_user_is_blocked ) {
			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
			return new \WP_Error( 'empty_password', __( '<strong>ERROR</strong>: Incorrect username or password.', 'authorizer' ) );
		}

		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Make sure $last_attempt (time) and $num_attempts are positive integers.
		// Note: this addresses resetting them if either is unset from above.
		$last_attempt = abs( intval( $last_attempt ) );
		$num_attempts = abs( intval( $num_attempts ) );

		// Create semantic lockout variables.
		$lockouts                        = $auth_settings['advanced_lockouts'];
		$time_since_last_fail            = time() - $last_attempt;
		$reset_duration                  = $lockouts['reset_duration'] * 60; // minutes to seconds.
		$num_attempts_long_lockout       = $lockouts['attempts_1'] + $lockouts['attempts_2'];
		$num_attempts_short_lockout      = $lockouts['attempts_1'];
		$seconds_remaining_long_lockout  = $lockouts['duration_2'] * 60 - $time_since_last_fail;
		$seconds_remaining_short_lockout = $lockouts['duration_1'] * 60 - $time_since_last_fail;

		// Check if we need to institute a lockout delay.
		if ( $is_login_attempt && $time_since_last_fail > $reset_duration ) {
			// Enough time has passed since the last invalid attempt and
			// now that we can reset the failed attempt count, and let this
			// login attempt go through.
			$num_attempts = 0; // This does nothing, but include it for semantic meaning.
		} elseif ( $is_login_attempt && $num_attempts > $num_attempts_long_lockout && $seconds_remaining_long_lockout > 0 ) {
			// Stronger lockout (1st/2nd round of invalid attempts reached)
			// Note: set the error code to 'empty_password' so it doesn't
			// trigger the wp_login_failed hook, which would continue to
			// increment the failed attempt count.
			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
			return new \WP_Error(
				'empty_password',
				sprintf(
					/* TRANSLATORS: 1: username 2: duration of lockout in seconds 3: duration of lockout as a phrase 4: lost password URL */
					__( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?', 'authorizer' ),
					$username,
					$seconds_remaining_long_lockout,
					Helper::seconds_as_sentence( $seconds_remaining_long_lockout ),
					wp_lostpassword_url()
				)
			);
		} elseif ( $is_login_attempt && $num_attempts > $num_attempts_short_lockout && $seconds_remaining_short_lockout > 0 ) {
			// Normal lockout (1st round of invalid attempts reached)
			// Note: set the error code to 'empty_password' so it doesn't
			// trigger the wp_login_failed hook, which would continue to
			// increment the failed attempt count.
			remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
			return new \WP_Error(
				'empty_password',
				sprintf(
					/* TRANSLATORS: 1: username 2: duration of lockout in seconds 3: duration of lockout as a phrase 4: lost password URL */
					__( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?', 'authorizer' ),
					$username,
					$seconds_remaining_short_lockout,
					Helper::seconds_as_sentence( $seconds_remaining_short_lockout ),
					wp_lostpassword_url()
				)
			);
		}

		// Start external authentication.
		$externally_authenticated_emails = array();
		$authenticated_by                = '';
		$result                          = null;

		// Try Google authentication if it's enabled and we don't have a
		// successful login yet.
		if (
			'1' === $auth_settings['google'] &&
			0 === count( $externally_authenticated_emails ) &&
			! is_wp_error( $result )
		) {
			$result = $this->custom_authenticate_google( $auth_settings );
			if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
				if ( is_array( $result['email'] ) ) {
					$externally_authenticated_emails = $result['email'];
				} else {
					$externally_authenticated_emails[] = $result['email'];
				}
				$authenticated_by = $result['authenticated_by'];
			}
		}

		// Try CAS authentication if it's enabled and we don't have a
		// successful login yet.
		if (
			'1' === $auth_settings['cas'] &&
			0 === count( $externally_authenticated_emails ) &&
			! is_wp_error( $result )
		) {
			$result = $this->custom_authenticate_cas( $auth_settings );
			if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
				if ( is_array( $result['email'] ) ) {
					$externally_authenticated_emails = $result['email'];
				} else {
					$externally_authenticated_emails[] = $result['email'];
				}
				$authenticated_by = $result['authenticated_by'];
			}
		}

		// Try LDAP authentication if it's enabled and we don't have an
		// authenticated user yet.
		if (
			'1' === $auth_settings['ldap'] &&
			0 === count( $externally_authenticated_emails ) &&
			! is_wp_error( $result )
		) {
			$result = $this->custom_authenticate_ldap( $auth_settings, $username, $password );
			if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
				if ( is_array( $result['email'] ) ) {
					$externally_authenticated_emails = $result['email'];
				} else {
					$externally_authenticated_emails[] = $result['email'];
				}
				$authenticated_by = $result['authenticated_by'];
			}
		}

		// Skip to WordPress authentication if we don't have an externally
		// authenticated user.
		if ( count( array_filter( $externally_authenticated_emails ) ) < 1 ) {
			return $result;
		}

		// Remove duplicate and blank emails, if any.
		$externally_authenticated_emails = array_filter( array_unique( $externally_authenticated_emails ) );

		/**
		 * If we've made it this far, we should have an externally
		 * authenticated user. The following should be set:
		 *   $externally_authenticated_emails
		 *   $authenticated_by
		 */

		// Look for an existing WordPress account matching the externally
		// authenticated user. Perform the match either by username or email.
		if ( isset( $auth_settings['cas_link_on_username'] ) && 1 === intval( $auth_settings['cas_link_on_username'] ) ) {
			// Get the external user's WordPress account by username. This is less
			// secure, but a user reported having an installation where a previous
			// CAS plugin had created over 9000 WordPress accounts without email
			// addresses. This option was created to support that case, and any
			// other CAS servers where emails are not used as account identifiers.
			$user = get_user_by( 'login', $result['username'] );
		} else {
			// Get the external user's WordPress account by email address. This is
			// the normal behavior (and the most secure).
			foreach ( $externally_authenticated_emails as $externally_authenticated_email ) {
				$user = get_user_by( 'email', Helper::lowercase( $externally_authenticated_email ) );
				// Stop trying email addresses once we have found a match.
				if ( false !== $user ) {
					break;
				}
			}
		}

		// We'll track how this user was authenticated in user meta.
		if ( $user ) {
			update_user_meta( $user->ID, 'authenticated_by', $authenticated_by );
		}

		// Check this external user's access against the access lists
		// (pending, approved, blocked).
		$result = Authorization::get_instance()->check_user_access( $user, $externally_authenticated_emails, $result );

		// Fail with message if there was an error creating/adding the user.
		if ( is_wp_error( $result ) || 0 === $result ) {
			return $result;
		}

		// If we have a valid user from check_user_access(), log that user in.
		if ( get_class( $result ) === 'WP_User' ) {
			$user = $result;
		}

		// If we haven't exited yet, we have a valid/approved user, so authenticate them.
		return $user;
	}


	/**
	 * Validate this user's credentials against Google.
	 *
	 * @param  array $auth_settings Plugin settings.
	 * @return array|WP_Error       Array containing email, authenticated_by, first_name,
	 *                              last_name, and username strings for the successfully
	 *                              authenticated user, or WP_Error() object on failure,
	 *                              or null if not attempting a google login.
	 */
	protected function custom_authenticate_google( $auth_settings ) {
		// Move on if Google auth hasn't been requested here.
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( empty( $_GET['external'] ) || 'google' !== $_GET['external'] ) {
			return null;
		}

		// Get one time use token.
		session_start();
		$token = array_key_exists( 'token', $_SESSION ) ? json_decode( $_SESSION['token'], true ) : null;

		// No token, so this is not a succesful Google login.
		if ( empty( $token ) ) {
			return null;
		}

		// Add Google API PHP Client.
		// @see https://github.com/googleapis/google-api-php-client/releases v2.2.4_PHP54
		if ( ! class_exists( 'Google_Client' ) ) {
			require_once dirname( plugin_root() ) . '/vendor/google-api-php-client-v2/vendor/autoload.php';
		}

		// Build the Google Client.
		$client = new \Google_Client();
		$client->setApplicationName( 'WordPress' );
		$client->setClientId( $auth_settings['google_clientid'] );
		$client->setClientSecret( $auth_settings['google_clientsecret'] );
		$client->setRedirectUri( 'postmessage' );

		/**
		 * If the hosted domain parameter is set, restrict logins to that domain
		 * (only available in google-api-php-client v2 or higher).
		 */
		if (
			array_key_exists( 'google_hosteddomain', $auth_settings ) &&
			strlen( $auth_settings['google_hosteddomain'] ) > 0 &&
			$client::LIBVER >= '2.0.0'
		) {
			$google_hosteddomains = explode( "\n", str_replace( "\r", '', $auth_settings['google_hosteddomain'] ) );
			$google_hosteddomain = trim( $google_hosteddomains[0] );
			$client->setHostedDomain( $google_hosteddomain );
		}

		// Verify this is a successful Google authentication.
		// NOTE:  verifyIdToken originally returned an object as per vendor/google/auth/src/OAuth2.php.
		// However, it looks as though this function is overridden by src/Google/Client.php and returns an array instead
		// in the v2 library.  Treating as an array for purposes of this functionality.
		// See https://github.com/googleapis/google-api-php-client/blob/master/src/Google/AccessToken/Verify.php#L77
		try {
			$ticket = $client->verifyIdToken( $token['id_token'], $auth_settings['google_clientid'] );
		} catch ( Google_Auth_Exception $e ) {
			// Invalid ticket, so this in not a successful Google login.
			return new \WP_Error( 'invalid_google_login', __( 'Invalid Google credentials provided.', 'authorizer' ) );
		}

		// Invalid ticket, so this in not a successful Google login.
		if ( ! $ticket ) {
			return new \WP_Error( 'invalid_google_login', __( 'Invalid Google credentials provided.', 'authorizer' ) );
		}

		// Get email address.
		// Edge case: if another plugin has already defined the Google_Client class,
		// and it's a version earlier than v2, then we need to handle $token as a
		// json-encoded string instead of an array.
		if ( is_object( $ticket ) && method_exists( $ticket, 'getAttributes' ) ) {
			$attributes = $ticket->getAttributes();
			$email = Helper::lowercase( $attributes['payload']['email'] );
		} else {
			$email = Helper::lowercase( $ticket['email'] );
		}

		$email_domain = substr( strrchr( $email, '@' ), 1 );
		$username     = current( explode( '@', $email ) );

		/**
		 * Fail if hd param is set and the logging in user's email address doesn't
		 * match the allowed hosted domain.
		 *
		 * See: https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
		 * See: https://github.com/google/google-api-php-client/blob/v1-master/src/Google/Client.php#L407-L416
		 *
		 * Note: this is a failsafe if the setHostedDomain() feature in v2 does not work above.
		 */
		if (
			array_key_exists( 'google_hosteddomain', $auth_settings ) &&
			strlen( $auth_settings['google_hosteddomain'] ) > 0
		) {
			// Allow multiple whitelisted domains.
			$google_hosteddomains = explode( "\n", str_replace( "\r", '', $auth_settings['google_hosteddomain'] ) );
			if ( ! in_array( $email_domain, $google_hosteddomains, true ) ) {
				$this->custom_logout();
				return new \WP_Error( 'invalid_google_login', __( 'Google credentials do not match the allowed hosted domain', 'authorizer' ) );
			}
		}

		return array(
			'email'             => $email,
			'username'          => $username,
			'first_name'        => '',
			'last_name'         => '',
			'authenticated_by'  => 'google',
			'google_attributes' => $ticket,
		);
	}


	/**
	 * Validate this user's credentials against CAS.
	 *
	 * @param  array $auth_settings Plugin settings.
	 * @return array|WP_Error       Array containing 'email' and 'authenticated_by' strings
	 *                              for the successfully authenticated user, or WP_Error()
	 *                              object on failure, or null if not attempting a CAS login.
	 */
	protected function custom_authenticate_cas( $auth_settings ) {
		// Move on if CAS hasn't been requested here.
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( empty( $_GET['external'] ) || 'cas' !== $_GET['external'] ) {
			return null;
		}

		/**
		 * Get the CAS server version (default to SAML_VERSION_1_1).
		 *
		 * @see: https://developer.jasig.org/cas-clients/php/1.3.4/docs/api/group__public.html
		 */
		$cas_version = SAML_VERSION_1_1;
		if ( 'CAS_VERSION_3_0' === $auth_settings['cas_version'] ) {
			$cas_version = CAS_VERSION_3_0;
		} elseif ( 'CAS_VERSION_2_0' === $auth_settings['cas_version'] ) {
			$cas_version = CAS_VERSION_2_0;
		} elseif ( 'CAS_VERSION_1_0' === $auth_settings['cas_version'] ) {
			$cas_version = CAS_VERSION_1_0;
		}

		// Set the CAS client configuration.
		\phpCAS::client( $cas_version, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'] );

		// Allow redirects at the CAS server endpoint (e.g., allow connections
		// at an old CAS URL that redirects to a newer CAS URL).
		\phpCAS::setExtraCurlOption( CURLOPT_FOLLOWLOCATION, true );

		// Use the WordPress certificate bundle at /wp-includes/certificates/ca-bundle.crt.
		\phpCAS::setCasServerCACert( ABSPATH . WPINC . '/certificates/ca-bundle.crt' );

		// Set the CAS service URL (including the redirect URL for WordPress when it comes back from CAS).
		$cas_service_url   = site_url( '/wp-login.php?external=cas' );
		$login_querystring = array();
		if ( isset( $_SERVER['QUERY_STRING'] ) ) {
			parse_str( $_SERVER['QUERY_STRING'], $login_querystring ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}
		if ( isset( $login_querystring['redirect_to'] ) ) {
			$cas_service_url .= '&redirect_to=' . rawurlencode( $login_querystring['redirect_to'] );
		}
		\phpCAS::setFixedServiceURL( $cas_service_url );

		// Authenticate against CAS.
		try {
			\phpCAS::forceAuthentication();
		} catch ( \CAS_AuthenticationException $e ) {
			// CAS server threw an error in isAuthenticated(), potentially because
			// the cached ticket is outdated. Try renewing the authentication.
			error_log( __( 'CAS server returned an Authentication Exception. Details:', 'authorizer' ) ); // phpcs:ignore
			error_log( $e->getMessage() ); // phpcs:ignore

			// CAS server is throwing errors on this login, so try logging the
			// user out of CAS and redirecting them to the login page.
			\phpCAS::logoutWithRedirectService( wp_login_url() );
			die();
		}

		// Get username (as specified by the CAS server).
		$username = \phpCAS::getUser();

		// Get email that successfully authenticated against the external service (CAS).
		$externally_authenticated_email = strtolower( $username );
		if ( ! filter_var( $externally_authenticated_email, FILTER_VALIDATE_EMAIL ) ) {
			// If we can't get the user's email address from a CAS attribute,
			// try to guess the domain from the CAS server hostname. This will only
			// be used if we can't discover the email address from CAS attributes.
			$domain_guess                   = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['cas_host'], $matches ) === 1 ? $matches[0] : '';
			$externally_authenticated_email = Helper::lowercase( $username ) . '@' . $domain_guess;
		}

		// Retrieve the user attributes (e.g., email address, first name, last name) from the CAS server.
		$cas_attributes = \phpCAS::getAttributes();

		// Get user email if it is specified in another field.
		if ( array_key_exists( 'cas_attr_email', $auth_settings ) && strlen( $auth_settings['cas_attr_email'] ) > 0 ) {
			// If the email attribute starts with an at symbol (@), assume that the
			// email domain is manually entered there (instead of a reference to a
			// CAS attribute), and combine that with the username to create the email.
			// Otherwise, look up the CAS attribute for email.
			if ( substr( $auth_settings['cas_attr_email'], 0, 1 ) === '@' ) {
				$externally_authenticated_email = Helper::lowercase( $username . $auth_settings['cas_attr_email'] );
			} elseif (
				// If a CAS attribute has been specified as containing the email address, use that instead.
				// Email attribute can be a string or an array of strings.
				array_key_exists( $auth_settings['cas_attr_email'], $cas_attributes ) && (
					(
						is_array( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) &&
						count( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) > 0
					) || (
						is_string( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) &&
						strlen( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) > 0
					)
				)
			) {
				// Each of the emails in the array needs to be set to lowercase.
				if ( is_array( $cas_attributes[ $auth_settings['cas_attr_email'] ] ) ) {
					$externally_authenticated_email = array();
					foreach ( $cas_attributes[ $auth_settings['cas_attr_email'] ] as $external_email ) {
						$externally_authenticated_email[] = Helper::lowercase( $external_email );
					}
				} else {
					$externally_authenticated_email = Helper::lowercase( $cas_attributes[ $auth_settings['cas_attr_email'] ] );
				}
			}
		}

		// Get user first name and last name.
		$first_name = array_key_exists( 'cas_attr_first_name', $auth_settings ) && strlen( $auth_settings['cas_attr_first_name'] ) > 0 && array_key_exists( $auth_settings['cas_attr_first_name'], $cas_attributes ) && strlen( $cas_attributes[ $auth_settings['cas_attr_first_name'] ] ) > 0 ? $cas_attributes[ $auth_settings['cas_attr_first_name'] ] : '';
		$last_name  = array_key_exists( 'cas_attr_last_name', $auth_settings ) && strlen( $auth_settings['cas_attr_last_name'] ) > 0 && array_key_exists( $auth_settings['cas_attr_last_name'], $cas_attributes ) && strlen( $cas_attributes[ $auth_settings['cas_attr_last_name'] ] ) > 0 ? $cas_attributes[ $auth_settings['cas_attr_last_name'] ] : '';

		return array(
			'email'            => $externally_authenticated_email,
			'username'         => $username,
			'first_name'       => $first_name,
			'last_name'        => $last_name,
			'authenticated_by' => 'cas',
			'cas_attributes'   => $cas_attributes,
		);
	}


	/**
	 * Validate this user's credentials against LDAP.
	 *
	 * @param  array  $auth_settings Plugin settings.
	 * @param  string $username      Attempted username from authenticate action.
	 * @param  string $password      Attempted password from authenticate action.
	 * @return array|WP_Error        Array containing 'email' and 'authenticated_by' strings
	 *                               for the successfully authenticated user, or WP_Error()
	 *                               object on failure, or null if skipping LDAP auth and
	 *                               falling back to WP auth.
	 */
	protected function custom_authenticate_ldap( $auth_settings, $username, $password ) {
		// Get LDAP search base(s).
		$search_bases = explode( "\n", str_replace( "\r", '', trim( $auth_settings['ldap_search_base'] ) ) );

		// Fail silently (fall back to WordPress authentication) if no search base specified.
		if ( count( $search_bases ) < 1 ) {
			return null;
		}

		// Get the FQDN from the first LDAP search base domain components (dc). For
		// example, ou=people,dc=example,dc=edu,dc=uk would yield user@example.edu.uk.
		$search_base_components = explode( ',', trim( $search_bases[0] ) );
		$domain                 = array();
		foreach ( $search_base_components as $search_base_component ) {
			$component = explode( '=', $search_base_component );
			if ( 2 === count( $component ) && 'dc' === $component[0] ) {
				$domain[] = $component[1];
			}
		}
		$domain = implode( '.', $domain );

		// If we can't get the logging in user's email address from an LDAP attribute,
		// just use the domain from the LDAP host. This will only be used if we
		// can't discover the email address from an LDAP attribute.
		if ( empty( $domain ) ) {
			$domain = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['ldap_host'], $matches ) === 1 ? $matches[0] : '';
		}

		// remove @domain if it exists in the username (i.e., if user entered their email).
		$username = str_replace( '@' . $domain, '', $username );

		// Fail silently (fall back to WordPress authentication) if both username
		// and password are empty (this will be the case when visiting wp-login.php
		// for the first time, or when clicking the Log In button without filling
		// out either field.
		if ( empty( $username ) && empty( $password ) ) {
			return null;
		}

		// Fail with error message if username or password is blank.
		if ( empty( $username ) ) {
			return new \WP_Error( 'empty_username', __( 'You must provide a username or email.', 'authorizer' ) );
		}
		if ( empty( $password ) ) {
			return new \WP_Error( 'empty_password', __( 'You must provide a password.', 'authorizer' ) );
		}

		// If php5-ldap extension isn't installed on server, fall back to WP auth.
		if ( ! function_exists( 'ldap_connect' ) ) {
			return null;
		}

		// Authenticate against LDAP using options provided in plugin settings.
		$result       = false;
		$ldap_user_dn = '';
		$first_name   = '';
		$last_name    = '';
		$email        = '';

		// Construct LDAP connection parameters. ldap_connect() takes either a
		// hostname or a full LDAP URI as its first parameter (works with OpenLDAP
		// 2.x.x or later). If it's an LDAP URI, the second parameter, $port, is
		// ignored, and port must be specified in the full URI. An LDAP URI is of
		// the form ldap://hostname:port or ldaps://hostname:port.
		$ldap_host   = $auth_settings['ldap_host'];
		$ldap_port   = intval( $auth_settings['ldap_port'] );
		$parsed_host = wp_parse_url( $ldap_host );
		// Fail (fall back to WordPress auth) if invalid host is specified.
		if ( false === $parsed_host ) {
			return null;
		}
		// If a scheme is in the LDAP host, use full LDAP URI instead of just hostname.
		if ( array_key_exists( 'scheme', $parsed_host ) ) {
			// If the port isn't in the LDAP URI, use the one in the LDAP port field.
			if ( ! array_key_exists( 'port', $parsed_host ) ) {
				$parsed_host['port'] = $ldap_port;
			}
			$ldap_host = Helper::build_url( $parsed_host );
		}

		// Establish LDAP connection.
		$ldap = ldap_connect( $ldap_host, $ldap_port );
		ldap_set_option( $ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
		if ( 1 === intval( $auth_settings['ldap_tls'] ) ) {
			if ( ! ldap_start_tls( $ldap ) ) {
				return null;
			}
		}

		// Set bind credentials; attempt an anonymous bind if not provided.
		$bind_rdn      = null;
		$bind_password = null;
		if ( strlen( $auth_settings['ldap_user'] ) > 0 ) {
			$bind_rdn      = $auth_settings['ldap_user'];
			$bind_password = Helper::decrypt( $auth_settings['ldap_password'] );
		}

		// Attempt LDAP bind.
		$result = @ldap_bind( $ldap, $bind_rdn, stripslashes( $bind_password ) ); // phpcs:ignore
		if ( ! $result ) {
			// Can't connect to LDAP, so fall back to WordPress authentication.
			return null;
		}
		// Look up the bind DN (and first/last name) of the user trying to
		// log in by performing an LDAP search for the login username in
		// the field specified in the LDAP settings. This setup is common.
		$ldap_attributes_to_retrieve = array( 'dn' );
		if ( array_key_exists( 'ldap_attr_first_name', $auth_settings ) && strlen( $auth_settings['ldap_attr_first_name'] ) > 0 ) {
			array_push( $ldap_attributes_to_retrieve, $auth_settings['ldap_attr_first_name'] );
		}
		if ( array_key_exists( 'ldap_attr_last_name', $auth_settings ) && strlen( $auth_settings['ldap_attr_last_name'] ) > 0 ) {
			array_push( $ldap_attributes_to_retrieve, $auth_settings['ldap_attr_last_name'] );
		}
		if ( array_key_exists( 'ldap_attr_email', $auth_settings ) && strlen( $auth_settings['ldap_attr_email'] ) > 0 && substr( $auth_settings['ldap_attr_email'], 0, 1 ) !== '@' ) {
			array_push( $ldap_attributes_to_retrieve, Helper::lowercase( $auth_settings['ldap_attr_email'] ) );
		}

		// Create default LDAP search filter. If LDAP email attribute is provided,
		// use (|(uid=$username)(mail=$username)) instead (so logins with either a
		// username or an email address will work). Otherwise use (uid=$username).
		if ( array_key_exists( 'ldap_attr_email', $auth_settings ) && strlen( $auth_settings['ldap_attr_email'] ) > 0 && substr( $auth_settings['ldap_attr_email'], 0, 1 ) !== '@' ) {
			$search_filter =
				'(|' .
					'(' . $auth_settings['ldap_uid'] . '=' . $username . ')' .
					'(' . $auth_settings['ldap_attr_email'] . '=' . $username . ')' .
				')';
		} else {
			$search_filter = '(' . $auth_settings['ldap_uid'] . '=' . $username . ')';
		}

		/**
		 * Filter LDAP search filter.
		 *
		 * Allows for custom LDAP authentication rules (e.g., restricting login
		 * access to users in multiple groups, or having certain attributes).
		 *
		 * @param string $search_filter The filter to pass to ldap_search().
		 * @param string $ldap_uid      The attribute to compare username against (from Authorizer Settings).
		 * @param string $username      The username attempting to log in.
		 */
		$search_filter = apply_filters( 'authorizer_ldap_search_filter', $search_filter, $auth_settings['ldap_uid'], $username );

		// Multiple search bases can be provided, so iterate through them until a match is found.
		foreach ( $search_bases as $search_base ) {
			$ldap_search  = ldap_search(
				$ldap,
				$search_base,
				$search_filter,
				$ldap_attributes_to_retrieve
			);
			$ldap_entries = ldap_get_entries( $ldap, $ldap_search );
			if ( $ldap_entries['count'] > 0 ) {
				break;
			}
		}

		// If we didn't find any users in ldap, fall back to WordPress authentication.
		if ( $ldap_entries['count'] < 1 ) {
			return null;
		}

		// Get the bind dn and first/last names; if there are multiple results returned, just get the last one.
		for ( $i = 0; $i < $ldap_entries['count']; $i++ ) {
			$ldap_user_dn = $ldap_entries[ $i ]['dn'];

			// Get user first name and last name.
			$ldap_attr_first_name = array_key_exists( 'ldap_attr_first_name', $auth_settings ) ? Helper::lowercase( $auth_settings['ldap_attr_first_name'] ) : '';
			if ( strlen( $ldap_attr_first_name ) > 0 && array_key_exists( $ldap_attr_first_name, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_first_name ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_first_name ][0] ) > 0 ) {
				$first_name = $ldap_entries[ $i ][ $ldap_attr_first_name ][0];
			}
			$ldap_attr_last_name = array_key_exists( 'ldap_attr_last_name', $auth_settings ) ? Helper::lowercase( $auth_settings['ldap_attr_last_name'] ) : '';
			if ( strlen( $ldap_attr_last_name ) > 0 && array_key_exists( $ldap_attr_last_name, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_last_name ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_last_name ][0] ) > 0 ) {
				$last_name = $ldap_entries[ $i ][ $ldap_attr_last_name ][0];
			}
			// Get user email if it is specified in another field.
			$ldap_attr_email = array_key_exists( 'ldap_attr_email', $auth_settings ) ? Helper::lowercase( $auth_settings['ldap_attr_email'] ) : '';
			if ( strlen( $ldap_attr_email ) > 0 ) {
				// If the email attribute starts with an at symbol (@), assume that the
				// email domain is manually entered there (instead of a reference to an
				// LDAP attribute), and combine that with the username to create the email.
				// Otherwise, look up the LDAP attribute for email.
				if ( substr( $ldap_attr_email, 0, 1 ) === '@' ) {
					$email = Helper::lowercase( $username . $ldap_attr_email );
				} elseif ( array_key_exists( $ldap_attr_email, $ldap_entries[ $i ] ) && $ldap_entries[ $i ][ $ldap_attr_email ]['count'] > 0 && strlen( $ldap_entries[ $i ][ $ldap_attr_email ][0] ) > 0 ) {
					$email = Helper::lowercase( $ldap_entries[ $i ][ $ldap_attr_email ][0] );
				}
			}
		}

		$result = @ldap_bind( $ldap, $ldap_user_dn, stripslashes( $password ) ); // phpcs:ignore
		if ( ! $result ) {
			// We have a real ldap user, but an invalid password. Pass
			// through to wp authentication after failing LDAP (since
			// this could be a local account that happens to be the
			// same name as an LDAP user).
			return null;
		}

		// User successfully authenticated against LDAP, so set the relevant variables.
		$externally_authenticated_email = Helper::lowercase( $username . '@' . $domain );

		// If an LDAP attribute has been specified as containing the email address, use that instead.
		if ( strlen( $email ) > 0 ) {
			$externally_authenticated_email = Helper::lowercase( $email );
		}

		return array(
			'email'            => $externally_authenticated_email,
			'username'         => $username,
			'first_name'       => $first_name,
			'last_name'        => $last_name,
			'authenticated_by' => 'ldap',
			'ldap_attributes'  => $ldap_entries,
		);
	}


	/**
	 * Log out of the attached external service.
	 *
	 * Action: wp_logout
	 *
	 * @return void
	 */
	public function custom_logout() {
		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Reset option containing old error messages.
		delete_option( 'auth_settings_advanced_login_error' );

		if ( session_id() === '' ) {
			session_start();
		}

		$current_user_authenticated_by = get_user_meta( get_current_user_id(), 'authenticated_by', true );

		// If we didn't find an authenticated method, check $_REQUEST (if this is a
		// pending user facing the "no access" message, their logout link will
		// include "external=?" since they don't have a WP_User to attach the
		// "authenticated_by" usermeta to).
		if ( empty( $current_user_authenticated_by ) && ! empty( $_REQUEST['external'] ) ) {
			$current_user_authenticated_by = $_REQUEST['external'];
		}

		// If logged in to CAS, Log out of CAS.
		if ( 'cas' === $current_user_authenticated_by && '1' === $auth_settings['cas'] ) {
			if ( ! array_key_exists( 'PHPCAS_CLIENT', $GLOBALS ) || ! array_key_exists( 'phpCAS', $_SESSION ) ) {

				/**
				 * Get the CAS server version (default to SAML_VERSION_1_1).
				 *
				 * @see: https://developer.jasig.org/cas-clients/php/1.3.4/docs/api/group__public.html
				 */
				$cas_version = SAML_VERSION_1_1;
				if ( 'CAS_VERSION_3_0' === $auth_settings['cas_version'] ) {
					$cas_version = CAS_VERSION_3_0;
				} elseif ( 'CAS_VERSION_2_0' === $auth_settings['cas_version'] ) {
					$cas_version = CAS_VERSION_2_0;
				} elseif ( 'CAS_VERSION_1_0' === $auth_settings['cas_version'] ) {
					$cas_version = CAS_VERSION_1_0;
				}

				// Set the CAS client configuration if it hasn't been set already.
				\phpCAS::client( $cas_version, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'] );
				// Allow redirects at the CAS server endpoint (e.g., allow connections
				// at an old CAS URL that redirects to a newer CAS URL).
				\phpCAS::setExtraCurlOption( CURLOPT_FOLLOWLOCATION, true );
				// Restrict logout request origin to the CAS server only (prevent DDOS).
				\phpCAS::handleLogoutRequests( true, array( $auth_settings['cas_host'] ) );
			}
			if ( \phpCAS::isAuthenticated() || \phpCAS::isInitialized() ) {
				// Redirect to home page, or specified page if it's been provided.
				$redirect_to = site_url( '/' );
				if ( ! empty( $_REQUEST['redirect_to'] ) && isset( $_REQUEST['_wpnonce'] ) && wp_verify_nonce( sanitize_key( $_REQUEST['_wpnonce'] ), 'log-out' ) ) {
					$redirect_to = esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) );
				}

				\phpCAS::logoutWithRedirectService( $redirect_to );
			}
		}

		// If session token set, log out of Google.
		if ( 'google' === $current_user_authenticated_by || array_key_exists( 'token', $_SESSION ) ) {
			$token = $_SESSION['token'];

			// Edge case: if another plugin has already defined the Google_Client class,
			// and it's a version earlier than v2, then we need to handle $token as a
			// json-encoded string instead of an array.
			if ( ! is_array( $token ) ) {
				$token = json_decode( $token, true );
			}

			$access_token = isset( $token['access_token'] ) ? $token['access_token'] : null;

			// Add Google API PHP Client.
			// @see https://github.com/google/google-api-php-client branch:v1-master.
			if ( ! class_exists( 'Google_Client' ) ) {
				require_once dirname( plugin_root() ) . '/vendor/google-api-php-client-v2/src/Google/autoload.php';
			}

			// Build the Google Client.
			$client = new \Google_Client();
			$client->setApplicationName( 'WordPress' );
			$client->setClientId( $auth_settings['google_clientid'] );
			$client->setClientSecret( $auth_settings['google_clientsecret'] );
			$client->setRedirectUri( 'postmessage' );

			// Revoke the token.
			$client->revokeToken( $access_token );

			// Remove the credentials from the user's session.
			unset( $_SESSION['token'] );
		}
	}

}
