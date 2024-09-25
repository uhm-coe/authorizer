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
class Authentication extends Singleton {

	/**
	 * Tracks the external service used by the user currently logging out.
	 *
	 * @var string
	 */
	private static $authenticated_by = '';

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
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20, 3 );
			return new \WP_Error( 'empty_password', __( '<strong>ERROR</strong>: Incorrect username or password.', 'authorizer' ) );
		}

		// Grab plugin settings.
		$options       = Options::get_instance();
		$auth_settings = $options->get_all( Helper::SINGLE_CONTEXT, 'allow override' );

		// Make sure $last_attempt (time) and $num_attempts are positive integers.
		// Note: this addresses resetting them if either is unset from above.
		$last_attempt = absint( $last_attempt );
		$num_attempts = absint( $num_attempts );

		// Create semantic lockout variables.
		$lockouts                        = $auth_settings['advanced_lockouts'];
		$time_since_last_fail            = time() - $last_attempt;
		$reset_duration                  = absint( $lockouts['reset_duration'] ) * 60; // minutes to seconds.
		$num_attempts_long_lockout       = absint( $lockouts['attempts_1'] ) + absint( $lockouts['attempts_2'] );
		$num_attempts_short_lockout      = absint( $lockouts['attempts_1'] );
		$seconds_remaining_long_lockout  = absint( $lockouts['duration_2'] ) * 60 - $time_since_last_fail;
		$seconds_remaining_short_lockout = absint( $lockouts['duration_1'] ) * 60 - $time_since_last_fail;

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
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20, 3 );
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
			remove_filter( 'authenticate', 'wp_authenticate_email_password', 20, 3 );
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

		// Try OAuth2 authentication if it's enabled and we don't have a
		// successful login yet.
		if (
			'1' === $auth_settings['oauth2'] &&
			0 === count( $externally_authenticated_emails ) &&
			! is_wp_error( $result )
		) {
			$result = $this->custom_authenticate_oauth2( $auth_settings );
			if ( ! is_null( $result ) && ! is_wp_error( $result ) ) {
				if ( is_array( $result['email'] ) ) {
					$externally_authenticated_emails = $result['email'];
				} else {
					$externally_authenticated_emails[] = $result['email'];
				}
				$authenticated_by = $result['authenticated_by'];
			}
		}

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

		// If we don't have an externally authenticated user, either skip to
		// WordPress authentication (if WordPress logins are enabled), or return
		// an error (if WordPress logins are disabled and at least one external
		// service is enabled).
		if ( count( array_filter( $externally_authenticated_emails ) ) < 1 ) {
			if (
				array_key_exists( 'advanced_disable_wp_login', $auth_settings ) &&
				'1' === $auth_settings['advanced_disable_wp_login'] &&
				(
					'1' === $auth_settings['cas'] ||
					'1' === $auth_settings['oauth2'] ||
					'1' === $auth_settings['google'] ||
					'1' === $auth_settings['ldap']
				)
			) {
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				remove_filter( 'authenticate', 'wp_authenticate_email_password', 20, 3 );

				$error = new \WP_Error();

				if ( empty( $username ) ) {
					$error->add( 'empty_username', __( '<strong>ERROR</strong>: The username field is empty.' ) );
				}

				if ( empty( $password ) ) {
					$error->add( 'empty_password', __( '<strong>ERROR</strong>: The password field is empty.' ) );
				}

				return $error;
			}

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
	 * Validate this user's credentials against selected OAuth2 provider.
	 *
	 * @param  array $auth_settings Plugin settings.
	 * @return array|WP_Error       Array containing email, authenticated_by, first_name,
	 *                              last_name, and username strings for the successfully
	 *                              authenticated user, or WP_Error() object on failure,
	 *                              or null if not attempting an oauth2 login.
	 */
	protected function custom_authenticate_oauth2( $auth_settings ) {
		// Move on if oauth2 hasn't been requested here.
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( empty( $_GET['external'] ) || 'oauth2' !== $_GET['external'] ) {
			// Note: because Azure oauth2 provider doesn't let us specify a querystring
			// in the redirect_uri, we have to detect those redirects separately because
			// we can't include external=oauth2 in the redirect_uri. Instead, detect the
			// absence of the `external` param, and the presence of `code` and `state`
			// params.
			if ( ! empty( $_GET['external'] ) || ( empty( $_GET['code'] ) && empty( $_GET['state'] ) ) ) {
				return null;
			}
		}

		// Fetch the Oauth2 Client ID (allow overrides from filter or constant).
		if ( defined( 'AUTHORIZER_OAUTH2_CLIENT_ID' ) ) {
			$auth_settings['oauth2_clientid'] = \AUTHORIZER_OAUTH2_CLIENT_ID;
		}
		/**
		 * Filters the Oauth2 Client ID used by Authorizer to authenticate.
		 *
		 * @since 3.9.0
		 *
		 * @param string $oauth2_client_id  The stored Oauth2 Client ID.
		 */
		$auth_settings['oauth2_clientid'] = apply_filters( 'authorizer_oauth2_client_id', $auth_settings['oauth2_clientid'] );

		// Fetch the Oauth2 Client Secret (allow overrides from filter or constant).
		if ( defined( 'AUTHORIZER_OAUTH2_CLIENT_SECRET' ) ) {
			$auth_settings['oauth2_clientsecret'] = \AUTHORIZER_OAUTH2_CLIENT_SECRET;
		}
		/**
		 * Filters the Oauth2 Client Secret used by Authorizer to authenticate.
		 *
		 * @since 3.6.1
		 *
		 * @param string $oauth2_client_secret  The stored Oauth2 Client Secret.
		 */
		$auth_settings['oauth2_clientsecret'] = apply_filters( 'authorizer_oauth2_client_secret', $auth_settings['oauth2_clientsecret'] );

		// Move on if required params aren't specified in settings.
		if (
			empty( $auth_settings['oauth2_clientid'] ) ||
			empty( $auth_settings['oauth2_clientsecret'] )
		) {
			return null;
		}

		// Authenticate with GitHub.
		// See: https://github.com/thephpleague/oauth2-github.
		if ( 'github' === $auth_settings['oauth2_provider'] ) {
			session_start();
			$provider = new \League\OAuth2\Client\Provider\Github( array(
				'clientId'     => $auth_settings['oauth2_clientid'],
				'clientSecret' => $auth_settings['oauth2_clientsecret'],
				'redirectUri'  => site_url( '/wp-login.php?external=oauth2' ),
			) );

			// If we don't have an authorization code, then get one.
			if ( ! isset( $_REQUEST['code'] ) ) {
				$auth_url                = $provider->getAuthorizationUrl( array(
					'scope' => 'user:email',
				) );
				$_SESSION['oauth2state'] = $provider->getState();
				header( 'Location: ' . $auth_url );
				exit;

			} elseif ( empty( $_REQUEST['state'] ) || empty( $_SESSION['oauth2state'] ) || $_REQUEST['state'] !== $_SESSION['oauth2state'] ) {
				// Check state against previously stored one to mitigate CSRF attacks.
				unset( $_SESSION['oauth2state'] );
				exit;

			} else {
				// Try to get an access token (using the authorization code grant).
				try {
					$token = $provider->getAccessToken( 'authorization_code', array(
						'code' => $_REQUEST['code'],
					) );
				} catch ( \Exception $e ) {
					// Failed to get token; try again from the beginning. Usually a
					// bad_verification_code error. See: https://docs.github.com/en/free-pro-team@latest/developers/apps/troubleshooting-oauth-app-access-token-request-errors#bad-verification-code.
					$auth_url                = $provider->getAuthorizationUrl( array(
						'scope' => 'user:email',
					) );
					$_SESSION['oauth2state'] = $provider->getState();
					header( 'Location: ' . $auth_url );
					exit;
				}

				try {
					// Look up user using token.
					$user = $provider->getResourceOwner( $token );

					$email      = $user->getEmail();
					$username   = $user->getNickname();
					$attributes = $user->toArray();

					// If user has no public email, fetch all emails and use those.
					if ( empty( $email ) ) {
						$request              = $provider->getAuthenticatedRequest(
							'GET',
							$provider->getResourceOwnerDetailsUrl( $token ) . '/emails',
							$token
						);
						$attributes['emails'] = array_filter( array_map(
							function ( $entry ) {
								return empty( $entry['email'] ) ? '' : $entry['email'];
							},
							(array) $provider->getParsedResponse( $request )
						) );
						$email                = $attributes['emails'];
					}
				} catch ( \Exception $e ) {
					// Failed to get user details.
					return null;
				}
			}
		} elseif ( 'azure' === $auth_settings['oauth2_provider'] ) {
			// Authenticate with the Microsoft Azure oauth2 client.
			// See: https://github.com/thenetworg/oauth2-azure.
			session_start();
			try {
				// Save the redirect URL for WordPress so we can restore it after a
				// successful login (note: we can't add the redirect_to querystring
				// param to the redirectUri param below because it won't match the
				// approved URI set in the Azure portal).
				$login_querystring = array();
				if ( isset( $_SERVER['QUERY_STRING'] ) ) {
					parse_str( $_SERVER['QUERY_STRING'], $login_querystring ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				}
				if ( isset( $login_querystring['redirect_to'] ) ) {
					$_SESSION['azure_redirect_to'] = $login_querystring['redirect_to'];
				}

				$provider = new \TheNetworg\OAuth2\Client\Provider\Azure( array(
					'clientId'     => $auth_settings['oauth2_clientid'],
					'clientSecret' => $auth_settings['oauth2_clientsecret'],
					'redirectUri'  => site_url( '/wp-login.php' ),
					'tenant'       => empty( $auth_settings['oauth2_tenant_id'] ) ? 'common' : $auth_settings['oauth2_tenant_id'],
				) );
				// Use v2 API. Set to Azure::ENDPOINT_VERSION_1_0 to use v1 API.
				$provider->defaultEndPointVersion = \TheNetworg\OAuth2\Client\Provider\Azure::ENDPOINT_VERSION_2_0;

				$baseGraphUri    = $provider->getRootMicrosoftGraphUri( null );
				$provider->scope = 'openid profile email offline_access ' . $baseGraphUri . '/User.Read';
			} catch ( \Exception $e ) {
				// Invalid configuration, so this in not a successful login. Show error
				// message to user.
				return new \WP_Error( 'empty_username', $e->getMessage() );
			}

			// If we don't have an authorization code, then get one.
			if ( ! isset( $_REQUEST['code'] ) ) {
				try {
					$auth_url                = $provider->getAuthorizationUrl( array(
						'scope' => $provider->scope,
					) );
					$_SESSION['oauth2state'] = $provider->getState();
					header( 'Location: ' . $auth_url );
					exit;
				} catch ( \Exception $e ) {
					// Invalid configuration, so this in not a successful login. Show error
					// message to user.
					return new \WP_Error( 'empty_username', $e->getMessage() );
				}
			} elseif ( empty( $_REQUEST['state'] ) || empty( $_SESSION['oauth2state'] ) || $_REQUEST['state'] !== $_SESSION['oauth2state'] ) {
				// Check state against previously stored one to mitigate CSRF attacks.
				unset( $_SESSION['oauth2state'] );
				exit;
			} else {
				// Try to get an access token (using the authorization code grant).
				try {
					$token = $provider->getAccessToken( 'authorization_code', array(
						'code'  => $_REQUEST['code'],
						'scope' => $provider->scope,
					) );
				} catch ( \Exception $e ) {
					// Failed to get token; try again from the beginning.
					$auth_url                = $provider->getAuthorizationUrl( array(
						'scope' => $provider->scope,
					) );
					$_SESSION['oauth2state'] = $provider->getState();
					header( 'Location: ' . $auth_url );
					exit;
				}

				try {
					// Look up user using token.
					$user = $provider->getResourceOwner( $token );

					$attributes = $user->toArray();
					$email      = empty( $attributes['email'] ) ? '' : $attributes['email'];
					$username   = empty( $attributes['preferred_username'] ) ? '' : $attributes['preferred_username'];

					// Attempt to find an email address in the resource owner attributes
					// if we couldn't find one in the `email` attribute.
					if ( empty( $email ) ) {
						$email = Helper::find_emails_in_multi_array( $attributes );
					}
				} catch ( \Exception $e ) {
					// Failed to get user details.
					return null;
				}

				/**
				 * Filter the generic oauth2 authenticated user email.
				 *
				 * @param  string $email      Discovered email (or empty string).
				 *
				 * @param  array  $attributes Resource Owner attributes returned from oauth2 endpoint.
				 */
				$email = apply_filters( 'authorizer_oauth2_generic_authenticated_email', $email, $attributes );

				/**
				 * Filter the azure oauth2 authenticated user email.
				 *
				 * @param  string $email      Discovered email (or empty string).
				 *
				 * @param  array  $attributes Resource Owner attributes returned from oauth2 endpoint.
				 */
				$email = apply_filters( 'authorizer_oauth2_azure_authenticated_email', $email, $attributes );

				// Set the username to the email prefix (if we don't have one).
				if ( ! empty( $email ) && empty( $username ) ) {
					if ( is_array( $email ) && ! empty( $email[0] ) ) {
						$username = current( explode( '@', $email[0] ) );
					} else {
						$username = current( explode( '@', $email ) );
					}
				}
			}
		} elseif ( 'generic' === $auth_settings['oauth2_provider'] ) {
			// Authenticate with the generic oauth2 client.
			// See: https://github.com/thephpleague/oauth2-client.
			// Move on if required params aren't specified in settings.
			if (
				empty( $auth_settings['oauth2_url_authorize'] ) ||
				empty( $auth_settings['oauth2_url_token'] ) ||
				empty( $auth_settings['oauth2_url_resource'] )
			) {
				return null;
			}

			session_start();
			$provider = new \League\OAuth2\Client\Provider\GenericProvider( array(
				'clientId'                => $auth_settings['oauth2_clientid'],
				'clientSecret'            => $auth_settings['oauth2_clientsecret'],
				'redirectUri'             => site_url( '/wp-login.php?external=oauth2' ),
				'urlAuthorize'            => $auth_settings['oauth2_url_authorize'],
				'urlAccessToken'          => $auth_settings['oauth2_url_token'],
				'urlResourceOwnerDetails' => $auth_settings['oauth2_url_resource'],
			) );

			// If we don't have an authorization code, then get one.
			if ( ! isset( $_REQUEST['code'] ) ) {
				$auth_url = $provider->getAuthorizationUrl(
					/**
					 * Filter the parameters passed to the generic oauth2 authorization endpoint.
					 *
					 * @param array() $params Array of key/value pairs where keys represent
					 *                        a GET param and value is its value.
					 */
					apply_filters( 'authorizer_oauth2_generic_authorization_parameters', array() )
				);
				$_SESSION['oauth2state'] = $provider->getState();
				header( 'Location: ' . $auth_url );
				exit;
			} elseif ( empty( $_REQUEST['state'] ) || empty( $_SESSION['oauth2state'] ) || $_REQUEST['state'] !== $_SESSION['oauth2state'] ) {
				// Check state against previously stored one to mitigate CSRF attacks.
				unset( $_SESSION['oauth2state'] );
				exit;
			} else {
				// Try to get an access token (using the authorization code grant).
				try {
					$token = $provider->getAccessToken( 'authorization_code', array(
						'code' => $_REQUEST['code'],
					) );
				} catch ( \Exception $e ) {
					// Failed to get token; try again from the beginning.
					$auth_url = $provider->getAuthorizationUrl(
						/**
						 * Filter the parameters passed to the generic oauth2 authorization endpoint.
						 *
						 * @param array() $params Array of key/value pairs where keys represent
						 *                        a GET param and value is its value.
						 */
						apply_filters( 'authorizer_oauth2_generic_authorization_parameters', array() )
					);
					$_SESSION['oauth2state'] = $provider->getState();
					header( 'Location: ' . $auth_url );
					exit;
				}

				try {
					// Look up user using token.
					$user = $provider->getResourceOwner( $token );

					$email      = '';
					$username   = '';
					$attributes = $user->toArray();

					// Attempt to find an email address in the resource owner attributes.
					$email = Helper::find_emails_in_multi_array( $attributes );
				} catch ( \Exception $e ) {
					// Failed to get user details.
					return null;
				}

				// Get custom username attribute, if specified (handle string or array results from attribute).
				$oauth2_attr_username = $auth_settings['oauth2_attr_username'] ?? '';
				if ( ! empty( $oauth2_attr_username ) && ! empty( $attributes[ $oauth2_attr_username ] ) ) {
					if ( is_string( $attributes[ $oauth2_attr_username ] ) ) {
						$username = trim( $attributes[ $oauth2_attr_username ] );
					} elseif ( is_array( $attributes[ $oauth2_attr_username ] ) ) {
						$username = trim( array_shift( $attributes[ $oauth2_attr_username ] ) );
					}
				}

				// Get custom email attribute, if specified.
				$oauth2_attr_email = $auth_settings['oauth2_attr_email'] ?? '';
				if ( ! empty( $oauth2_attr_email ) && ! empty( $attributes[ $oauth2_attr_email ] ) ) {
					if ( is_string( $attributes[ $oauth2_attr_email ] ) ) {
						$email = trim( $attributes[ $oauth2_attr_email ] );
					} elseif ( is_array( $attributes[ $oauth2_attr_email ] ) ) {
						$email = $attributes[ $oauth2_attr_email ];
					}
				}

				/**
				 * Filter the generic oauth2 authenticated user email.
				 *
				 * @param  string|array $email      Discovered email or array of emails (or empty string).
				 * @param  array        $attributes Resource Owner attributes returned from oauth2 endpoint.
				 */
				$email = apply_filters( 'authorizer_oauth2_generic_authenticated_email', $email, $attributes );

				// Set the username to the email prefix (if we don't have one).
				if ( ! empty( $email ) && empty( $username ) ) {
					if ( is_array( $email ) && ! empty( $email[0] ) ) {
						$username = current( explode( '@', $email[0] ) );
					} else {
						$username = current( explode( '@', $email ) );
					}
				}
			}
		} else {
			// Move on if a supported providers wasn't selected.
			return null;
		}

		// Make sure email is lowercase.
		if ( is_array( $email ) ) {
			$externally_authenticated_email = array();
			foreach ( $email as $external_email ) {
				$externally_authenticated_email[] = Helper::lowercase( $external_email );
			}
		} else {
			$externally_authenticated_email = array_filter( array( Helper::lowercase( $email ) ) );
		}

		// Move on if no emails were found.
		if ( empty( $externally_authenticated_email ) ) {
			return null;
		}

		/**
		 * Fail if hosteddomain param is set and the logging in user's email address
		 * doesn't match the allowed hosted domain.
		 */
		if (
			array_key_exists( 'oauth2_hosteddomain', $auth_settings ) &&
			strlen( $auth_settings['oauth2_hosteddomain'] ) > 0
		) {
			// Allow multiple whitelisted domains.
			$oauth2_hosteddomains = explode( "\n", str_replace( "\r", '', $auth_settings['oauth2_hosteddomain'] ) );
			$valid_domain         = false;
			foreach ( $externally_authenticated_email as $email ) {
				$email_domain = substr( strrchr( $email, '@' ), 1 );
				if ( in_array( $email_domain, $oauth2_hosteddomains, true ) ) {
					$valid_domain = true;
				}
			}
			if ( ! $valid_domain ) {
				$this->custom_logout();
				return new \WP_Error( 'invalid_oauth2_login', __( 'Email address does not match the allowed hosted domain', 'authorizer' ) );
			}
		}

		// Get user first name (handle string or array results from attribute).
		$first_name             = '';
		$oauth2_attr_first_name = $auth_settings['oauth2_attr_first_name'] ?? '';
		if ( ! empty( $oauth2_attr_first_name ) && ! empty( $attributes[ $oauth2_attr_first_name ] ) ) {
			if ( is_string( $attributes[ $oauth2_attr_first_name ] ) ) {
				$first_name = $attributes[ $oauth2_attr_first_name ];
			} elseif ( is_array( $attributes[ $oauth2_attr_first_name ] ) ) {
				$first_name = trim( implode( ' ', $attributes[ $oauth2_attr_first_name ] ) );
			}
		}

		// Get user last name (handle string or array results from attribute).
		$last_name             = '';
		$oauth2_attr_last_name = $auth_settings['oauth2_attr_last_name'] ?? '';
		if ( ! empty( $oauth2_attr_last_name ) && ! empty( $attributes[ $oauth2_attr_last_name ] ) ) {
			if ( is_string( $attributes[ $oauth2_attr_last_name ] ) ) {
				$last_name = $attributes[ $oauth2_attr_last_name ];
			} elseif ( is_array( $attributes[ $oauth2_attr_last_name ] ) ) {
				$last_name = trim( implode( ' ', $attributes[ $oauth2_attr_last_name ] ) );
			}
		}

		return array(
			'email'             => $externally_authenticated_email,
			'username'          => sanitize_user( $username ),
			'first_name'        => $first_name,
			'last_name'         => $last_name,
			'authenticated_by'  => 'oauth2',
			'oauth2_provider'   => $auth_settings['oauth2_provider'],
			'oauth2_attributes' => $attributes,
		);
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
		$token = array_key_exists( 'token', $_SESSION ) ? $_SESSION['token'] : null;

		// No token, so this is not a succesful Google login.
		if ( empty( $token ) ) {
			return null;
		}

		// Fetch the Google Client ID (allow overrides from filter or constant).
		if ( defined( 'AUTHORIZER_GOOGLE_CLIENT_ID' ) ) {
			$auth_settings['google_clientid'] = \AUTHORIZER_GOOGLE_CLIENT_ID;
		}
		/**
		 * Filters the Google Client ID used by Authorizer to authenticate.
		 *
		 * @since 3.9.0
		 *
		 * @param string $google_client_id  The stored Google Client ID.
		 */
		$auth_settings['google_clientid'] = apply_filters( 'authorizer_google_client_id', $auth_settings['google_clientid'] );

		// Fetch the Google Client Secret (allow overrides from filter or constant).
		if ( defined( 'AUTHORIZER_GOOGLE_CLIENT_SECRET' ) ) {
			$auth_settings['google_clientsecret'] = \AUTHORIZER_GOOGLE_CLIENT_SECRET;
		}
		/**
		 * Filters the Google Client Secret used by Authorizer to authenticate.
		 *
		 * @since 3.6.1
		 *
		 * @param string $google_client_secret  The stored Google Client Secret.
		 */
		$auth_settings['google_clientsecret'] = apply_filters( 'authorizer_google_client_secret', $auth_settings['google_clientsecret'] );

		// Build the Google Client.
		$client = new \Google_Client();
		$client->setApplicationName( 'WordPress' );
		$client->setClientId( trim( $auth_settings['google_clientid'] ) );
		$client->setClientSecret( trim( $auth_settings['google_clientsecret'] ) );
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
			$google_hosteddomain  = trim( $google_hosteddomains[0] );
			$client->setHostedDomain( $google_hosteddomain );
		}

		// Allow minor clock drift between this server's clock and Google's.
		// See: https://github.com/googleapis/google-api-php-client/issues/1630
		\Firebase\JWT\JWT::$leeway = 30;

		// Verify this is a successful Google authentication.
		try {
			$payload = $client->verifyIdToken( $token );
		} catch ( \Firebase\JWT\BeforeValidException $e ) {
			// Server clock out of sync with Google servers.
			return new \WP_Error( 'invalid_google_login', __( 'The authentication timestamp is too old, please try again.', 'authorizer' ) );
		} catch ( Google_Auth_Exception $e ) {
			// Invalid ticket, so this in not a successful Google login.
			return new \WP_Error( 'invalid_google_login', __( 'Invalid Google credentials provided.', 'authorizer' ) );
		}

		// Invalid ticket, so this in not a successful Google login.
		if ( empty( $payload['email'] ) ) {
			return new \WP_Error( 'invalid_google_login', __( 'Invalid Google credentials provided.', 'authorizer' ) );
		}

		// Get email address.
		$email = Helper::lowercase( $payload['email'] );

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
			'google_attributes' => $payload,
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
		// Move on if CAS hasn't been requested here or the CAS server ID is invalid.
		if ( empty( $auth_settings['cas_num_servers'] ) ) {
			$auth_settings['cas_num_servers'] = 1;
		}
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( empty( $_GET['external'] ) || 'cas' !== $_GET['external'] || empty( $_GET['id'] ) || ! in_array( intval( $_GET['id'] ), range( 1, 10 ), true ) || intval( $_GET['id'] ) > intval( $auth_settings['cas_num_servers'] ) ) {
			return null;
		}
		// Get the CAS server id (since multiple CAS servers can be configured), and
		// the relevant CAS settings for that server.
		// phpcs:ignore WordPress.Security.NonceVerification
		$cas_server_id       = intval( $_GET['id'] );
		$suffix              = $cas_server_id > 1 ? '_' . $cas_server_id : '';
		$cas_host            = $auth_settings[ 'cas_host' . $suffix ];
		$cas_port            = $auth_settings[ 'cas_port' . $suffix ];
		$cas_path            = $auth_settings[ 'cas_path' . $suffix ];
		$cas_method          = $auth_settings[ 'cas_method' . $suffix ];
		$cas_version         = $auth_settings[ 'cas_version' . $suffix ];
		$cas_attr_email      = $auth_settings[ 'cas_attr_email' . $suffix ];
		$cas_attr_first_name = $auth_settings[ 'cas_attr_first_name' . $suffix ];
		$cas_attr_last_name  = $auth_settings[ 'cas_attr_last_name' . $suffix ];

		/**
		 * Get the CAS server protocol version (default to SAML 1.1).
		 *
		 * @see: https://apereo.github.io/phpCAS/api/group__public.html#gadea9415f40b8d2afc39f140c9be83bbe
		 */
		$cas_version = Options\External\Cas::get_instance()->sanitize_cas_version( $cas_version );

		/**
		 * Get valid service URLs for the CAS client to validate against.
		 *
		 * @see: https://github.com/apereo/phpCAS/security/advisories/GHSA-8q72-6qq8-xv64
		 */
		$valid_base_urls = Options\External\Cas::get_instance()->get_valid_cas_service_urls();

		// Set the CAS client configuration.
		if ( 'PROXY' === strtoupper( $cas_method ) ) {
			\phpCAS::proxy( $cas_version, $cas_host, intval( $cas_port ), $cas_path, $valid_base_urls );
		} else {
			\phpCAS::client( $cas_version, $cas_host, intval( $cas_port ), $cas_path, $valid_base_urls );
		}

		// Allow redirects at the CAS server endpoint (e.g., allow connections
		// at an old CAS URL that redirects to a newer CAS URL).
		\phpCAS::setExtraCurlOption( CURLOPT_FOLLOWLOCATION, true );

		// Use the WordPress certificate bundle at /wp-includes/certificates/ca-bundle.crt.
		\phpCAS::setCasServerCACert( ABSPATH . WPINC . '/certificates/ca-bundle.crt' );

		// Set the CAS service URL (including the redirect URL for WordPress when it comes back from CAS).
		$cas_service_url   = site_url( '/wp-login.php?external=cas&id=' . $cas_server_id );
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
			// phpcs:ignore Squiz.PHP.CommentedOutCode
			// \phpCAS::setDebug( dirname( __FILE__ ) . '/../../debug.log' );
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
			$domain_guess                   = preg_match( '/[^.]*\.[^.]*$/', $cas_host, $matches ) === 1 ? $matches[0] : '';
			$externally_authenticated_email = Helper::lowercase( $username ) . '@' . $domain_guess;
		}

		// Retrieve the user attributes (e.g., email address, first name, last name) from the CAS server.
		$cas_attributes = \phpCAS::getAttributes();

		// Get user email if it is specified in another field.
		if ( ! empty( $cas_attr_email ) ) {
			// If the email attribute starts with an at symbol (@), assume that the
			// email domain is manually entered there (instead of a reference to a
			// CAS attribute), and combine that with the username to create the email.
			// Otherwise, look up the CAS attribute for email.
			if ( substr( $cas_attr_email, 0, 1 ) === '@' ) {
				$externally_authenticated_email = Helper::lowercase( $username . $cas_attr_email );
			} elseif (
				// If a CAS attribute has been specified as containing the email address, use that instead.
				// Email attribute can be a string or an array of strings.
				array_key_exists( $cas_attr_email, $cas_attributes ) && (
					(
						is_array( $cas_attributes[ $cas_attr_email ] ) &&
						count( $cas_attributes[ $cas_attr_email ] ) > 0
					) || (
						is_string( $cas_attributes[ $cas_attr_email ] ) &&
						strlen( $cas_attributes[ $cas_attr_email ] ) > 0
					)
				)
			) {
				// Each of the emails in the array needs to be set to lowercase.
				if ( is_array( $cas_attributes[ $cas_attr_email ] ) ) {
					$externally_authenticated_email = array();
					foreach ( $cas_attributes[ $cas_attr_email ] as $external_email ) {
						$externally_authenticated_email[] = Helper::lowercase( $external_email );
					}
				} else {
					$externally_authenticated_email = Helper::lowercase( $cas_attributes[ $cas_attr_email ] );
				}
			}
		}

		// Get user first name (handle string or array results from CAS attribute).
		$first_name = '';
		if ( ! empty( $cas_attr_first_name ) && ! empty( $cas_attributes[ $cas_attr_first_name ] ) ) {
			if ( is_string( $cas_attributes[ $cas_attr_first_name ] ) ) {
				$first_name = $cas_attributes[ $cas_attr_first_name ];
			} elseif ( is_array( $cas_attributes[ $cas_attr_first_name ] ) ) {
				$first_name = trim( implode( ' ', $cas_attributes[ $cas_attr_first_name ] ) );
			}
		}

		// Get user last name (handle string or array results from CAS attribute).
		$last_name = '';
		if ( ! empty( $cas_attr_last_name ) && ! empty( $cas_attributes[ $cas_attr_last_name ] ) ) {
			if ( is_string( $cas_attributes[ $cas_attr_last_name ] ) ) {
				$last_name = $cas_attributes[ $cas_attr_last_name ];
			} elseif ( is_array( $cas_attributes[ $cas_attr_last_name ] ) ) {
				$last_name = trim( implode( ' ', $cas_attributes[ $cas_attr_last_name ] ) );
			}
		}

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
	 * @param  array  $debug         If provided, filled with an array of debug
	 *                               messages. Defaults to null.
	 *
	 * @return array|WP_Error        Array containing 'email' and 'authenticated_by' strings
	 *                               for the successfully authenticated user, or WP_Error()
	 *                               object on failure, or null if skipping LDAP auth and
	 *                               falling back to WP auth.
	 */
	public function custom_authenticate_ldap( $auth_settings, $username, $password, &$debug = null ) {
		// Make sure all LDAP settings are defined (user and password can be
		// overridden by constant or filter and may not exist in auth_settings).
		$defaults      = array(
			'ldap'                      => '',
			'ldap_host'                 => '',
			'ldap_port'                 => '389',
			'ldap_tls'                  => '1',
			'ldap_search_base'          => '',
			'ldap_search_filter'        => '',
			'ldap_uid'                  => 'uid',
			'ldap_attr_email'           => '',
			'ldap_user'                 => '',
			'ldap_password'             => '',
			'ldap_lostpassword_url'     => '',
			'ldap_attr_first_name'      => '',
			'ldap_attr_last_name'       => '',
			'ldap_attr_update_on_login' => '',
			'ldap_test_user'            => '',
		);
		$auth_settings = wp_parse_args( $auth_settings, $defaults );

		// Initialize debug array if a variable was passed in.
		if ( ! is_null( $debug ) ) {
			$debug = array(
				/* TRANSLATORS: Current time */
				sprintf( __( '[%s] Attempting to authenticate via LDAP.', 'authorizer' ), wp_date( get_option( 'time_format' ) ) ),
			);
		}

		// Get LDAP host(s), and attempt each until we have a valid connection.
		$ldap_hosts = explode( "\n", str_replace( "\r", '', trim( $auth_settings['ldap_host'] ) ) );

		// Fail silently (fall back to WordPress authentication) if no LDAP host specified.
		if ( count( $ldap_hosts ) < 1 ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: no LDAP Host(s) specified.', 'authorizer' );
			}
			return null;
		}

		// Get LDAP search base(s).
		$search_bases = explode( "\n", str_replace( "\r", '', trim( $auth_settings['ldap_search_base'] ) ) );

		// Fail silently (fall back to WordPress authentication) if no search base specified.
		if ( count( $search_bases ) < 1 ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: no LDAP Search Base(s) specified.', 'authorizer' );
			}
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
			$domain = preg_match( '/[^.]*\.[^.]*$/', $ldap_hosts[0], $matches ) === 1 ? $matches[0] : '';
		}

		// remove @domain if it exists in the username (i.e., if user entered their email).
		$username = str_replace( '@' . $domain, '', $username );

		// Fail silently (fall back to WordPress authentication) if both username
		// and password are empty (this will be the case when visiting wp-login.php
		// for the first time, or when clicking the Log In button without filling
		// out either field.
		if ( empty( $username ) && empty( $password ) ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: empty username and password.', 'authorizer' );
			}
			return null;
		}

		// Fail with error message if username or password is blank.
		if ( empty( $username ) ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: empty username.', 'authorizer' );
			}
			return new \WP_Error( 'empty_username', __( 'You must provide a username or email.', 'authorizer' ) );
		}
		if ( empty( $password ) ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: empty password.', 'authorizer' );
			}
			return new \WP_Error( 'empty_password', __( 'You must provide a password.', 'authorizer' ) );
		}

		// If php5-ldap extension isn't installed on server, fall back to WP auth.
		if ( ! function_exists( 'ldap_connect' ) ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: php-ldap extension not installed.', 'authorizer' );
			}
			return null;
		}

		// Authenticate against LDAP using options provided in plugin settings.
		$result       = false;
		$ldap_user_dn = '';
		$first_name   = '';
		$last_name    = '';
		$email        = '';

		// Attempt each LDAP host until we have a valid connection.
		$ldap_valid = false;
		foreach ( $ldap_hosts as $ldap_host ) {
			// Construct LDAP connection parameters. In PHP < 8.3, ldap_connect()
			// takes either a hostname or a full LDAP URI as its first parameter
			// (works with OpenLDAP 2.x.x or later). If it's an LDAP URI, the second
			// parameter, $port, is ignored, and port must be specified in the full
			// URI. An LDAP URI is of the form ldap://hostname:port or
			// ldaps://hostname:port.
			// In PHP 8.3, ldap_connect() only takes a single param (the signature
			// with 2 params is deprecated). We thus convert all LDAP hosts to a full
			// LDAP URI, defaulting to ldap:// if the full URI isn't provided.
			$ldap_port   = intval( $auth_settings['ldap_port'] );
			$parsed_host = wp_parse_url( $ldap_host );

			// Fail if invalid host is specified.
			if ( false === $parsed_host ) {
				if ( is_array( $debug ) ) {
					/* TRANSLATORS: LDAP Host */
					$debug[] = sprintf( __( 'Warning: could not parse host %s with wp_parse_url().', 'authorizer' ), $ldap_host );
				}
				continue;
			}

			// If a scheme is in the LDAP host, use full LDAP URI instead of just hostname.
			if ( array_key_exists( 'scheme', $parsed_host ) ) {
				// If the port isn't in the LDAP URI, use the one in the LDAP port field.
				if ( ! array_key_exists( 'port', $parsed_host ) ) {
					$parsed_host['port'] = $ldap_port;
				}
				$ldap_host = Helper::build_url( $parsed_host );
			} else {
				// Construct the LDAP URI from the provided host and port.
				$ldap_host = 'ldap://' . $ldap_host . ':' . $ldap_port;
			}

			// Create LDAP connection.
			$ldap = ldap_connect( $ldap_host );
			ldap_set_option( $ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
			ldap_set_option( $ldap, LDAP_OPT_REFERRALS, 0 );

			// Fail if we don't have a plausible LDAP URI.
			if ( false === $ldap ) {
				if ( is_array( $debug ) ) {
					/* TRANSLATORS: LDAP Host */
					$debug[] = sprintf( __( 'Warning: syntax check failed on host %s in ldap_connect().', 'authorizer' ), $ldap_host );
				}
				continue;
			}

			// Attempt to start TLS if that setting is checked and we're not using ldaps protocol.
			if ( 1 === intval( $auth_settings['ldap_tls'] ) && false === strpos( $ldap_host, 'ldaps://' ) ) {
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( ! @ldap_start_tls( $ldap ) ) {
					if ( is_array( $debug ) ) {
						/* TRANSLATORS: LDAP Host */
						$debug[] = sprintf( __( 'Warning: unable to start TLS on host %s:', 'authorizer' ), $ldap_host );
						$debug[] = ldap_error( $ldap );
					}
					continue;
				}
			}

			// Allow overrides of the LDAP user from filter or constant.
			if ( defined( 'AUTHORIZER_LDAP_USER' ) ) {
				$auth_settings['ldap_user'] = \AUTHORIZER_LDAP_USER;
			}
			/**
			 * Filters the LDAP user used by Authorizer to authenticate.
			 *
			 * @since 3.6.2
			 *
			 * @param string $ldap_user  The stored Oauth2 Client Secret.
			 */
			$auth_settings['ldap_user'] = apply_filters( 'authorizer_ldap_user', $auth_settings['ldap_user'] );

			// Allow overrides of the LDAP password from filter or constant.
			if ( defined( 'AUTHORIZER_LDAP_PASSWORD' ) ) {
				$auth_settings['ldap_password'] = \AUTHORIZER_LDAP_PASSWORD;
			}
			/**
			 * Filters the LDAP password used by Authorizer to authenticate.
			 *
			 * @since 3.6.2
			 *
			 * @param string $ldap_password  The stored Oauth2 Client Secret.
			 */
			$auth_settings['ldap_password'] = apply_filters( 'authorizer_ldap_password', $auth_settings['ldap_password'] );

			// Set bind credentials; attempt an anonymous bind if not provided.
			$bind_rdn      = null;
			$bind_password = null;
			if ( strlen( $auth_settings['ldap_user'] ) > 0 ) {
				$bind_rdn      = $auth_settings['ldap_user'];
				$bind_password = $auth_settings['ldap_password'];

				// Decrypt LDAP password if coming from wp_options database (not needed
				// if it was provided via constant or filter).
				if ( ! defined( 'AUTHORIZER_LDAP_PASSWORD' ) && ! has_filter( 'authorizer_ldap_password' ) ) {
					$bind_password = Helper::decrypt( $bind_password );
				}

				// If the bind user contains the [username] wildcard, replace it with
				// the username and password of the user logging in.
				if ( false !== strpos( $bind_rdn, '[username]' ) ) {
					$bind_rdn      = str_replace( '[username]', $username, $bind_rdn );
					$bind_password = $password;

					if ( is_array( $debug ) ) {
						/* TRANSLATORS: LDAP User DN */
						$debug[] = sprintf( __( 'Performing bind as user logging in: %s.', 'authorizer' ), $bind_rdn );
					}
				}
			}

			// Attempt LDAP bind.
			$result = @ldap_bind( $ldap, $bind_rdn, stripslashes( $bind_password ) ); // phpcs:ignore
			if ( ! $result ) {
				if ( is_array( $debug ) ) {
					/* TRANSLATORS: LDAP Host */
					$debug[] = sprintf( __( 'Warning: unable to bind on host %1$s using directory user:', 'authorizer' ), $ldap_host );
					$debug[] = ldap_error( $ldap );
				}

				// We failed either an anonymous bind or a bind with a service account,
				// so try to bind with the logging in user's credentials before failing.
				// Note: multiple search bases can be provided, so iterate through them
				// trying to bind as the user logging in.
				foreach ( $search_bases as $search_base ) {
					$bind_user_dn = $auth_settings['ldap_uid'] . '=' . $username . ',' . $search_base;
					$result = @ldap_bind( $ldap, $bind_user_dn, stripslashes( $password ) ); // phpcs:ignore
					if ( $result ) {
						if ( is_array( $debug ) ) {
							/* TRANSLATORS: LDAP User DN */
							$debug[] = sprintf( __( 'Successful bind using LDAP user DN %s instead of directory user.', 'authorizer' ), $bind_user_dn );
						}

						break;
					}
				}

				if ( ! $result ) {
					if ( is_array( $debug ) ) {
						/* TRANSLATORS: LDAP User */
						$debug[] = sprintf( __( 'Failed: password incorrect for LDAP user %s.', 'authorizer' ), $username );
						$debug[] = ldap_error( $ldap );
					}

					// Can't connect to LDAP, so fall back to WordPress authentication.
					continue;
				}
			}

			// If we've reached this, we have a valid ldap connection and bind.
			$ldap_valid = true;
			if ( is_array( $debug ) ) {
				/* TRANSLATORS: LDAP Host */
				$debug[] = sprintf( __( 'Connected to LDAP host %s.', 'authorizer' ), $ldap_host );
			}
			break;
		}

		// Move to next authentication method if we don't have a valid LDAP connection.
		if ( ! $ldap_valid ) {
			if ( is_array( $debug ) ) {
				$debug[] = __( 'Failed: unable to connect to any LDAP host.', 'authorizer' );
			}
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

		/**
		 * Specify additional LDAP user attributes to retrieve during authentication.
		 * May be used by plugins in `authorizer_user_register`.
		 *
		 * @param array $attributes LDAP attributes to retrieve in addition to first name, last name and email.
		 */
		$additional_ldap_attributes_to_retrieve = apply_filters( 'authorizer_additional_ldap_attributes_to_retrieve', array() );
		$ldap_attributes_to_retrieve            = array_merge( $ldap_attributes_to_retrieve, $additional_ldap_attributes_to_retrieve );

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

		// Merge LDAP search filter from plugin settings if it exists.
		$ldap_search_filter = trim( $auth_settings['ldap_search_filter'] );
		if ( ! empty( $ldap_search_filter ) ) {
			$search_filter = '(&' . $search_filter . $ldap_search_filter . ')';
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

		if ( is_array( $debug ) ) {
			/* TRANSLATORS: LDAP search filter */
			$debug[] = sprintf( __( 'Using LDAP search filter: %s', 'authorizer' ), $search_filter );
		}

		// Multiple search bases can be provided, so iterate through them until a match is found.
		foreach ( $search_bases as $search_base ) {
			$ldap_search  = @ldap_search( // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$ldap,
				$search_base,
				$search_filter,
				$ldap_attributes_to_retrieve
			);
			$ldap_entries = empty( $ldap_search ) ? array( 'count' => 0 ) : ldap_get_entries( $ldap, $ldap_search );
			if ( $ldap_entries['count'] > 0 ) {
				if ( is_array( $debug ) ) {
					/* TRANSLATORS: 1: LDAP user 2: LDAP search base */
					$debug[] = sprintf( __( 'Found user %1$s in search base: %2$s', 'authorizer' ), $username, $search_base );
				}
				break;
			} elseif ( is_array( $debug ) ) {
				/* TRANSLATORS: 1: LDAP user 2: LDAP search base */
				$debug[] = sprintf( __( 'Failed to find user %1$s in %2$s. Trying next search base.', 'authorizer' ), $username, $search_base );
			}
		}

		// If we didn't find any users in ldap, fall back to WordPress authentication.
		if ( $ldap_entries['count'] < 1 ) {
			if ( is_array( $debug ) ) {
				/* TRANSLATORS: LDAP User */
				$debug[] = sprintf( __( 'Failed: no LDAP user %s found.', 'authorizer' ), $username );
			}
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
			if ( is_array( $debug ) ) {
				/* TRANSLATORS: LDAP User */
				$debug[] = sprintf( __( 'Failed: password incorrect for LDAP user %s.', 'authorizer' ), $username );
			}
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

		if ( is_array( $debug ) ) {
			/* TRANSLATORS: 1: Current time 2: LDAP User 3: LDAP user email */
			$debug[] = sprintf( __( '[%1$s] Successfully authenticated user %2$s (%3$s) via LDAP.', 'authorizer' ), wp_date( get_option( 'time_format' ) ), $username, $externally_authenticated_email );
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
	 * Fetch the logging out user's external service (so we can log out of it
	 * below in the wp_logout hook).
	 *
	 * Action: clear_auth_cookie
	 *
	 * @return void
	 */
	public function pre_logout() {
		self::$authenticated_by = get_user_meta( get_current_user_id(), 'authenticated_by', true );

		// If we didn't find an authenticated method, check $_REQUEST (if this is a
		// pending user facing the "no access" message, their logout link will
		// include "external=?" since they don't have a WP_User to attach the
		// "authenticated_by" usermeta to).
		if ( empty( self::$authenticated_by ) && ! empty( $_REQUEST['external'] ) ) {
			self::$authenticated_by = $_REQUEST['external'];
		}
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

		// If logged in to CAS, Log out of CAS.
		if ( 'cas' === self::$authenticated_by && '1' === $auth_settings['cas'] ) {
			if ( ! array_key_exists( 'PHPCAS_CLIENT', $GLOBALS ) || ! array_key_exists( 'phpCAS', $_SESSION ) ) {

				/**
				 * Get the CAS server protocol version (default to SAML 1.1).
				 *
				 * @see: https://apereo.github.io/phpCAS/api/group__public.html#gadea9415f40b8d2afc39f140c9be83bbe
				 */
				$cas_version = Options\External\Cas::get_instance()->sanitize_cas_version( $auth_settings['cas_version'] );

				/**
				 * Get valid service URLs for the CAS client to validate against.
				 *
				 * @see: https://github.com/apereo/phpCAS/security/advisories/GHSA-8q72-6qq8-xv64
				 */
				$valid_base_urls = Options\External\Cas::get_instance()->get_valid_cas_service_urls();

				// Set the CAS client configuration if it hasn't been set already.
				if ( 'PROXY' === strtoupper( $auth_settings['cas_method'] ) ) {
					\phpCAS::proxy( $cas_version, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'], $valid_base_urls );
				} else {
					\phpCAS::client( $cas_version, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'], $valid_base_urls );
				}
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
		if ( session_id() === '' ) {
			session_start();
		}
		if ( 'google' === self::$authenticated_by && array_key_exists( 'token', $_SESSION ) ) {
			$token = $_SESSION['token'];

			// Fetch the Google Client ID (allow overrides from filter or constant).
			if ( defined( 'AUTHORIZER_GOOGLE_CLIENT_ID' ) ) {
				$auth_settings['google_clientid'] = \AUTHORIZER_GOOGLE_CLIENT_ID;
			}
			/**
			 * Filters the Google Client ID used by Authorizer to authenticate.
			 *
			 * @since 3.9.0
			 *
			 * @param string $google_client_id  The stored Google Client ID.
			 */
			$auth_settings['google_clientid'] = apply_filters( 'authorizer_google_client_id', $auth_settings['google_clientid'] );

			// Fetch the Google Client Secret (allow overrides from filter or constant).
			if ( defined( 'AUTHORIZER_GOOGLE_CLIENT_SECRET' ) ) {
				$auth_settings['google_clientsecret'] = \AUTHORIZER_GOOGLE_CLIENT_SECRET;
			}
			/**
			 * Filters the Google Client Secret used by Authorizer to authenticate.
			 *
			 * @since 3.6.1
			 *
			 * @param string $google_client_secret  The stored Google Client Secret.
			 */
			$auth_settings['google_clientsecret'] = apply_filters( 'authorizer_google_client_secret', $auth_settings['google_clientsecret'] );

			// Build the Google Client.
			$client = new \Google_Client();
			$client->setApplicationName( 'WordPress' );
			$client->setClientId( trim( $auth_settings['google_clientid'] ) );
			$client->setClientSecret( trim( $auth_settings['google_clientsecret'] ) );
			$client->setRedirectUri( 'postmessage' );

			// Revoke the token.
			$client->revokeToken( $token );

			// Remove the credentials from the user's session.
			unset( $_SESSION['token'] );
		}
	}
}
