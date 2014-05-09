<?php
/*
Plugin Name: Authorizer
Plugin URI: http://hawaii.edu/coe/dcdc/
Description: Authorizer restricts access to students enrolled in university courses, using CAS or LDAP for authentication and a whitelist of users with permission to access the site.
Version: 1.1
Author: Paul Ryan
Author URI: http://www.linkedin.com/in/paulrryan/
License: GPL2
*/

/*
Copyright 2014  Paul Ryan  (email: prar@hawaii.edu)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as 
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/*
Portions forked from Restricted Site Access plugin: http://wordpress.org/plugins/restricted-site-access/
Portions forked from wpCAS plugin: http://wordpress.org/extend/plugins/cas-authentication/
Portions forked from Limit Login Attempts: http://wordpress.org/plugins/limit-login-attempts/
*/


// Add phpCAS library if it's not included.
// @see https://wiki.jasig.org/display/CASC/phpCAS+installation+guide
if ( ! defined( 'PHPCAS_VERSION' ) ) {
	include_once dirname(__FILE__) . '/assets/inc/CAS-1.3.2/CAS.php';
}


if ( !class_exists( 'WP_Plugin_Authorizer' ) ) {
	/**
	 * Define class for plugin: Authorizer.
	 *
	 * @category Authentication
	 * @package  Authorizer
	 * @author   Paul Ryan <prar@hawaii.edu>
	 * @license  http://www.gnu.org/licenses/gpl-2.0.html GPL2
	 * @link     http://hawaii.edu/coe/dcdc/wordpress/authorizer/doc/
	 */
	class WP_Plugin_Authorizer {
		
		/**
		 * Constructor.
		 */
		public function __construct() {
			// Installation and uninstallation hooks.
			register_activation_hook( __FILE__, array( $this, 'activate' ) );
			register_deactivation_hook( __FILE__, array( $this, 'deactivate' ) );
			register_uninstall_hook( __FILE__, array( $this, 'uninstall' ) );

			// Register filters.

			// Custom wp authentication routine using external service.
			add_filter( 'authenticate', array( $this, 'custom_authenticate' ), 1, 3 );

			// Custom logout action using external service.
			add_action( 'wp_logout', array( $this, 'custom_logout' ) );

			// Removing this bypasses Wordpress authentication (so if external auth fails,
			// no one can log in); with it enabled, it will run if external auth fails.
			//remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

			// Create settings link on Plugins page
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'plugin_settings_link' ) );

			// Modify login page to with custom password url and labels.
			if ( strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ) {
				add_filter( 'lostpassword_url', array( $this, 'custom_lostpassword_url' ) );
				add_filter( 'gettext', array( $this, 'custom_login_form_labels' ), 20, 3 );
			}

			// If we have a custom login error, add the filter to show it.
			// Caveat: Don't show the error on the admin bypass login.
			$error = get_option( 'auth_settings_advanced_login_error' );
			$is_admin_bypass = ! empty($_GET['login'] ) && $_GET['login'] === 'wordpress';
			if ( $error && strlen( $error ) > 0 && ! $is_admin_bypass ) {
				add_filter( 'login_errors', array( $this, 'show_advanced_login_error' ) );
			}

			// Register actions.

			// Update the user meta with this user's failed login attempt.
			add_action('wp_login_failed', array( $this, 'update_login_failed_count' ) );

			// Create menu item in Settings
			add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );

			// Create options page
			add_action( 'admin_init', array( $this, 'page_init' ) );

			// Enqueue javascript and css only on the plugin's options page and the dashboard (for the widget)
			add_action( 'load-settings_page_authorizer', array( $this, 'load_options_page' ) );
			add_action( 'admin_head-index.php', array( $this, 'load_options_page' ) );

			// Add custom css and js to wp-login.php
			add_action( 'login_head', array( $this, 'load_login_css_and_js' ) );

			// Verify current user has access to page they are visiting
			add_action( 'parse_request', array( $this, 'restrict_access' ), 1 );

			// ajax save options from dashboard widget
			add_action( 'wp_ajax_save_auth_dashboard_widget', array( $this, 'ajax_save_auth_dashboard_widget' ) );

			// Add dashboard widget so instructors can add/edit users with access.
			// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
			add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widgets' ) );

			// If we have a custom admin message, add the action to show it.
			$notice = get_option( 'auth_settings_advanced_admin_notice' );
			if ( $notice && strlen( $notice ) > 0 ) {
				add_action( 'admin_notices', array( $this, 'show_advanced_admin_notice' ) );
			}

			// Load custom javascript for the main site (e.g., for displaying alerts).
			add_action( 'wp_enqueue_scripts', array( $this, 'auth_public_scripts' ), 20 );

		} // END __construct()


		/**
		 * Plugin activation hook.
		 * Will also activate the plugin for all sites/blogs if this is a "Network enable."
		 *
		 * @return void
		 */
		public function activate() {
			global $wpdb;

			// If we're in a multisite environment, run the plugin activation for each site when network enabling
			if ( is_multisite() ) {
				if ( isset($_GET['networkwide'] ) && ( $_GET['networkwide'] == 1 ) ) {
					$old_blog = $wpdb->blogid;
					// Get all blog ids
					$blogids = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs" ) );
					foreach ( $blogids as $blog_id ) {
						switch_to_blog( $blog_id );
						// Set meaningful defaults for other sites in the network.
						$this->set_default_options();
					}
					switch_to_blog( $old_blog );
					return;
				}
			}

			// Set meaningful defaults for this site.
			$this->set_default_options();
		}

		/**
		 * Plugin deactivation.
		 *
		 * @return void
		 */
		public function deactivate() {
			// Do nothing.
		} // END deactivate()


		/**
		 * Plugin uninstallation. Runs when plugin is deleted (not disabled).
		 *
		 * @return void
		 */
		public function uninstall() {
			// Delete options in database.
			if ( get_option( 'auth_settings' ) ) {
				delete_option( 'auth_settings' );
			}
			if ( get_option( 'auth_settings_advanced_admin_notice' ) ) {
				delete_option( 'auth_settings_advanced_admin_notice' );
			}

		} // END deactivate()



		/**
		 ****************************
		 * External Authentication
		 ****************************
		 */



		/**
		 * Authenticate against an external service.
		 *
		 * @param WP_User $user     user to authenticate
		 * @param string  $username optional username to authenticate.
		 * @param string  $password optional password to authenticate.
		 *
		 * @return WP_User or WP_Error
		 */
		public function custom_authenticate( $user, $username, $password ) {
			// Pass through if already authenticated.
			if ( is_a( $user, 'WP_User' ) ) {
				return $user;
			} else {
				$user = null;
			}

			// Check to make sure that $username is not locked out due to too
			// many invalid login attempts. If it is, tell the user how much
			// time remains until they can try again.
			$unauthenticated_user = get_user_by( 'login', $username );
			if ( $unauthenticated_user !== FALSE ) {
				$last_attempt = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
				$num_attempts = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
			} else {
				$last_attempt = get_option( 'auth_settings_advanced_lockouts_time_last_failed' );
				$num_attempts = get_option( 'auth_settings_advanced_lockouts_failed_attempts' );
			}

			// Make sure $last_attempt (time) and $num_attempts are positive integers.
			// Note: this addresses resetting them if either is unset from above.
			$last_attempt = abs( intval( $last_attempt ) );
			$num_attempts = abs( intval( $num_attempts ) );

			// Grab plugin settings.
			$auth_settings = get_option( 'auth_settings' );

			// Create semantic lockout variables.
			$lockouts = $auth_settings['advanced_lockouts'];
			$time_since_last_fail = time() - $last_attempt;
			$reset_duration = $lockouts['reset_duration'] * 60; // minutes to seconds
			$num_attempts_long_lockout = $lockouts['attempts_1'] + $lockouts['attempts_2'];
			$num_attempts_short_lockout = $lockouts['attempts_1'];
			$seconds_remaining_long_lockout = $lockouts['duration_2'] * 60 - $time_since_last_fail;
			$seconds_remaining_short_lockout = $lockouts['duration_1'] * 60 - $time_since_last_fail;

			// Check if we need to institute a lockout delay
			if ( $time_since_last_fail > $reset_duration ) {
				// Enough time has passed since the last invalid attempt and
				// now that we can reset the failed attempt count, and let this
				// login attempt go through.
				$num_attempts = 0; // This does nothing, but include it for semantic meaning.
			} else if ( $num_attempts > $num_attempts_long_lockout && $seconds_remaining_long_lockout > 0 ) {
				// Stronger lockout (1st/2nd round of invalid attempts reached)
				// Note: set the error code to 'empty_password' so it doesn't
				// trigger the wp_login_failed hook, which would continue to
				// increment the failed attempt count.
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error( 'empty_password', sprintf( __( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?' ), $username, $seconds_remaining_long_lockout, $this->seconds_as_sentence( $seconds_remaining_long_lockout ), wp_lostpassword_url() ) );
			} else if ( $num_attempts > $num_attempts_short_lockout && $seconds_remaining_short_lockout > 0 ) {
				// Normal lockout (1st round of invalid attempts reached)
				// Note: set the error code to 'empty_password' so it doesn't
				// trigger the wp_login_failed hook, which would continue to
				// increment the failed attempt count.
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error( 'empty_password', sprintf( __( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?' ), $username, $seconds_remaining_short_lockout, $this->seconds_as_sentence( $seconds_remaining_short_lockout ), wp_lostpassword_url() ) );
			}


			// Admin bypass: skip cas login and proceed to WordPress login if
			// querystring variable 'login' is set to 'wordpress'--for example:
			// https://www.example.com/wp-login.php?login=wordpress
			if ( ! empty($_GET['login'] ) && $_GET['login'] === 'wordpress' ) {
				remove_filter( 'authenticate', array( $this, 'custom_authenticate' ), 1, 3 );
				return new WP_Error( 'using_wp_authentication', 'Bypassing external authentication in favor of WordPress authentication...' );
			}

			// Admin bypass: if we have populated username/password data,
			// and the page we're coming from is the admin bypass, let
			// WordPress handle the authentication (by passing on null).
			if ( ! empty( $username ) && ! empty( $password ) && strpos( $_SERVER['HTTP_REFERER'], 'login=wordpress' ) !== false ) {
				return null;
			}

			// If we're not restricting view access access at all, don't check
			// against an external service; instead, pass through to default
			// WP authentication.
			if ( $auth_settings['access_restriction'] === 'everyone' ) {
				return new WP_Error( 'using_wp_authentication', 'Moving on to WordPress authentication...' );
			}

			// Start external authentication.
			if ( $auth_settings['external_service'] === 'cas' ) {
				// Set the CAS client configuration
				phpCAS::client( CAS_VERSION_2_0, $auth_settings['cas_host'], intval($auth_settings['cas_port']), $auth_settings['cas_path'] );

				// Update server certificate bundle if it doesn't exist or is older
				// than 3 months, then use it to ensure CAS server is legitimate.
				$cacert_path = plugin_dir_path( __FILE__ ) . 'assets/inc/cacert.pem';
				$time_90_days = 90 * 24 * 60 * 60; // days * hours * minutes * seconds
				$time_90_days_ago = time() - $time_90_days;
				if ( ! file_exists( $cacert_path ) || filemtime( $cacert_path ) < $time_90_days_ago ) {
					$cacert_contents = file_get_contents( 'http://curl.haxx.se/ca/cacert.pem' );
					if ( $cacert_contents !== false ) {
						file_put_contents( $cacert_path, $cacert_contents );
					} else {
						return new WP_Error( 'cannot_update_cacert', 'Unable to update outdated server certificates from http://curl.haxx.se/ca/cacert.pem.' );
					}
				}
				phpCAS::setCasServerCACert( $cacert_path );

				// Authenticate against CAS
				if ( ! phpCAS::isAuthenticated() ) {
					phpCAS::forceAuthentication();
					die();
				}

				// Get the TLD from the CAS host for use in matching email addresses
				// For example: hawaii.edu is the TLD for login.its.hawaii.edu, so user
				// 'bob' will have the following email address: bob@hawaii.edu.
				$tld = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['cas_host'], $matches ) === 1 ? $matches[0] : '';

				// Get username that successfully authenticated against the external service (CAS).
				$externally_authenticated_username = strtolower( phpCAS::getUser() );

			} else if ( $auth_settings['external_service'] === 'ldap' ) {

				// Custom UH code: remove @hawaii.edu if it exists in the username
				$username = str_replace( '@hawaii.edu', '', $username );

				// Fail with error message if username or password is blank.
				if ( empty( $username ) ) {
					return null;
				}
				if ( empty( $password ) ) {
					return new WP_Error( 'empty_password', 'You must provide a password.' );
				}

				// Authenticate against LDAP using options provided in plugin settings.
				$result = false;
				$ldap_user_dn = '';

				$ldap = ldap_connect( $auth_settings['ldap_host'], $auth_settings['ldap_port'] );
				ldap_set_option( $ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
				if ( $auth_settings['ldap_tls'] == 1 ) {
					ldap_start_tls( $ldap );
				}
				$result = @ldap_bind( $ldap, $auth_settings['ldap_user'], $this->decrypt( base64_decode( $auth_settings['ldap_password'] ) ) );
				if ( !$result ) {
					// Can't connect to LDAP, so fall back to WordPress authentication.
					return new WP_Error( 'ldap_error', 'Could not authenticate using LDAP.' );
				}
				// Look up the bind DN of the user trying to log in by
				// performing an LDAP search for the login username in the
				// field specified in the LDAP settings. This setup is common.
				$ldap_search = ldap_search(
					$ldap,
					$auth_settings['ldap_search_base'],
					"(" . $auth_settings['ldap_uid'] . "=" . $username . ")",
					array('dn') // Just get the dn (no other attributes)
				);
				$ldap_entries = ldap_get_entries( $ldap, $ldap_search );

				// If we didn't find any users in ldap, exit with error (rely on default wordpress authentication)
				if ( $ldap_entries['count'] < 1 ) {
					return new WP_Error( 'no_ldap', 'No LDAP user found.' );
				}

				// Get the bind dn; if there are multiple results returned, just get the last one.
				for ( $i = 0; $i < $ldap_entries['count']; $i++ ) {
					$ldap_user_dn = $ldap_entries[$i]['dn'];
				}

				$result = @ldap_bind( $ldap, $ldap_user_dn, $password );
				if ( !$result ) {
					// We have a real ldap user, but an invalid password, so we shouldn't
					// pass through to wp authentication after failing ldap. Instead,
					// remove the WordPress authenticate function, and return an error.
					remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
					return new WP_Error( 'incorrect_password', sprintf( __( '<strong>ERROR</strong>: The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s" title="Password Lost and Found">Lost your password</a>?' ), $username, wp_lostpassword_url() ) );
				}

				// Get the TLD from the LDAP host for use in matching email addresses
				// For example: example.edu is the TLD for ldap.example.edu, so user
				// 'bob' will have the following email address: bob@example.edu.
				$tld = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['ldap_host'], $matches ) === 1 ? $matches[0] : '';

				// User successfully authenticated against LDAP, so set the relevant variables.
				$externally_authenticated_username = $username;
			}

			// If we've made it this far, we have an externally authenticated user.
			// $externally_authenticated_username and $tld should both be set.

			// Check if the external user has a WordPress account (with the same username or email address)
			if ( ! $user ) {
				$user = get_user_by( 'login', $externally_authenticated_username );
			}
			if ( ! $user ) {
				$user = get_user_by( 'email', $externally_authenticated_username . '@' . $tld );
			}

			// If we've made it this far, we have an externally authenticated
			// user. Deal with them differently based on which list they're in
			// (pending, blocked, or approved).
			if ( $this->is_username_in_list( $externally_authenticated_username, 'blocked' ) ) {
				// If the blocked external user has a WordPress account, remove it. In a
				// multisite environment, just remove them from the current blog.
				// IMPORTANT NOTE: this deletes all of the user's posts.
				// @TODO: switch this up to use a "blocked" or "inactive" flag in usermeta, so we don't have to delete user accounts (and possibly lose user data). this makes further sense if we tie the approved list to, say, UH Groupings, where we can specify a class roster. this roster is likely to change over time, which might mean removing users. note, however, that they will probably not go on the block list. as it stands right now, they just are removed from the approved list, but still have wordpress accounts. if they try to log in again, they'll be put on the pending list. HOLE: the one security hole is if they know about wp-login.php?login=wordpress, where they can fill out the lost password form with their email, reset their password, and then log in with their wordpress account. we need to decide how to deal with this, and if it's worth it.
				if ( $user ) {
					if ( is_multisite() ) {
						remove_user_from_blog( $user->ID, get_current_blog_id() );
					} else {
						wp_delete_user( $user->ID );
					}
				}

				// Notify user about blocked status
				$error_message = 'Sorry ' . $externally_authenticated_username . ', it seems you don\'t have access to ' . get_bloginfo( 'name' ) . '. If this is a mistake, please contact your instructor.';
				$error_message .= '<hr /><p style="text-align: center;"><a class="button" href="' . home_url() . '">Check Again</a> <a class="button" href="' . wp_logout_url() . '">Log Out</a></p>';
				update_option( 'auth_settings_advanced_login_error', $error_message );
				wp_die( $error_message, get_bloginfo( 'name' ) . ' - Access Restricted' );
				return;
			} else if ( $this->is_username_in_list( $externally_authenticated_username, 'approved' ) ) {
				$user_info = $this->get_user_info_from_list( $externally_authenticated_username, $auth_settings['access_users_approved'] );

				// If the approved external user does not have a WordPress account, create it
				if ( ! $user ) {
					$result = wp_insert_user(
						array(
							'user_login' => strtolower( $user_info['username'] ),
							'user_pass' => wp_generate_password(), // random password
							'first_name' => '',
							'last_name' => '',
							'user_email' => strtolower( $user_info['email'] ),
							'user_registered' => date( 'Y-m-d H:i:s' ),
							'role' => $user_info['role'],
						)
					);

					// Fail with message if error.
					if ( is_wp_error( $result ) ) {
						return $result;
					}

					// Authenticate as new user
					$user = new WP_User( $result );
				}

				// If this is multisite, add new user to current blog.
				if ( is_multisite() && ! is_user_member_of_blog( $user->ID ) ) {
					$result = add_user_to_blog( get_current_blog_id(), $user->ID, $user_info['role'] );

					// Fail with message if error.
					if ( is_wp_error( $result ) ) {
						return $result;
					}
				}

				// Ensure user has the same role as their entry in the approved list.
				// (This is just a precaution, the role should already be set when
				// saving admin options in the sanitizing function.)
				if ( $user_info && ! array_key_exists( $user_info['role'], $user->roles ) ) {
					$user->set_role( $user_info['role'] );
				}

			} else if ( $user && in_array( 'administrator', $user->roles ) ) {
				// User has a WordPress account, but is not in the blocked or approved
				// list. If they are an administrator, let them in.
			} else {
				// User isn't an admin, is not blocked, and is not approved.
				// Add them to the pending list and notify them and their instructor.
				if ( ! $this->is_username_in_list( $externally_authenticated_username, 'pending' ) ) {
					$pending_user = array();
					$pending_user['username'] = $externally_authenticated_username;
					$pending_user['email'] = $externally_authenticated_username . '@' . $tld;
					$pending_user['role'] = $auth_settings['access_default_role'];
					$pending_user['date_added'] = '';
					if ( ! is_array ( $auth_settings['access_users_pending'] ) ) {
						$auth_settings['access_users_pending'] = array();
					}
					array_push( $auth_settings['access_users_pending'], $pending_user );
					update_option( 'auth_settings', $auth_settings );

					// Notify instructor about new pending user if that option is set.
					foreach ( get_users( array( 'role' => $auth_settings['access_role_receive_pending_emails'] ) ) as $user_recipient ) {
						wp_mail(
							$user_recipient->user_email,
							'Action required: Pending user ' . $pending_user['email'] . ' at ' . get_bloginfo( 'name' ),
							"A new user has tried to access the " . get_bloginfo( 'name' ) . " site you manage at:\n" . get_bloginfo( 'url' ) . ".\n\n Please log in to approve or deny their request:\n" . admin_url( 'options-general.php?page=authorizer' )
						);
					}
				}

				// Notify user about pending status and return without authenticating them.
				$error_message = $auth_settings['access_pending_redirect_to_message'];
				$error_message .= '<hr /><p style="text-align: center;"><a class="button" href="' . home_url() . '">Check Again</a> <a class="button" href="' . wp_logout_url() . '">Log Out</a></p>';
				update_option( 'auth_settings_advanced_login_error', $error_message );
				wp_die( $error_message, get_bloginfo( 'name' ) . ' - Access Restricted' );
				return;
			}

			// If we haven't exited yet, we have a valid/approved user, so authenticate them.
			return $user;
		}


		/**
		 * Log out of the attached external service.
		 *
		 * @return void
		 */
		public function custom_logout() {
			// Grab plugin settings.
			$auth_settings = get_option( 'auth_settings' );

			// Reset option containing old error messages.
			update_option( 'auth_settings_advanced_login_error', $error_message );

			// Log out of external service.
			if ( $auth_settings['external_service'] === 'cas' ) {
				// Set the CAS client configuration if it hasn't been set already.
				if ( ! array_key_exists( 'PHPCAS_CLIENT', $GLOBALS ) && ! ( isset( $_SESSION ) && array_key_exists( 'phpCAS', $_SESSION ) ) ) {
					phpCAS::client( CAS_VERSION_2_0, $auth_settings['cas_host'], intval($auth_settings['cas_port']), $auth_settings['cas_path'] );
				}

				// Log out of CAS.
				phpCAS::logoutWithRedirectService( get_option( 'siteurl' ) );

			} else if ( $auth_settings['external_service'] === 'ldap' ) {
				// Log out of LDAP.
				// Nothing to do here, just pass on to wp logout.
			}
		}



		/**
		 ****************************
		 * Access Restriction
		 ****************************
		 */



		/**
		 * Restrict access to WordPress site based on settings (everyone, university, approved_users, user).
		 * Hook: parse_request http://codex.wordpress.org/Plugin_API/Action_Reference/parse_request
		 *
		 * @param array $wp WordPress object.
		 *
		 * @return void
		 */
		public function restrict_access( $wp ) {
			remove_action( 'parse_request', array( $this, 'restrict_access' ), 1 );	// only need it the first time

			$auth_settings = get_option( 'auth_settings' );

			$has_access = (
				// Always allow access if WordPress is installing
				( defined( 'WP_INSTALLING' ) && isset( $_GET['key'] ) ) ||
				// Always allow access to admins
				( is_admin() ) ||
				// Allow access if option is set to 'everyone'
				( $auth_settings['access_restriction'] == 'everyone' ) ||
				// Allow access to logged in users if option is set to 'university' community
				( $auth_settings['access_restriction'] == 'university' && $this->is_user_logged_in_and_blog_user() ) ||
				// Allow access to approved external users and logged in users if option is set to 'approved_users'
				( $auth_settings['access_restriction'] == 'approved_users' && $this->is_user_logged_in_and_blog_user() )
			);

			// Fringe case: In a multisite, a user of a different blog can
			// successfully log in, but they aren't on the 'approved' whitelist
			// for this blog. Flag these users, and redirect them to their
			// profile page with a message (so we don't get into a redirect
			// loop on the wp-login.php page).
			if ( is_multisite() && is_user_logged_in() && !$has_access ) {
				wp_redirect( admin_url( 'profile.php' ), 302 );
				exit;
			}

			/**
			 * Developers can use the `authorizer_has_access` filter
			 * to override restricted access on certain pages. Note that the
			 * restriction checks happens before WordPress executes any queries, so
			 * use the global `$wp` variable to investigate what the visitor is
			 * trying to load.
			 *
			 * For example, to unblock an RSS feed, place the following PHP code in
			 * the theme's functions.php file or in a simple plug-in:
			 *
			 *   function my_rsa_feed_access_override( $has_access ) {
			 *     global $wp;
			 *     // check query variables to see if this is the feed
			 *     if ( ! empty( $wp->query_vars['feed'] ) )
			 *       $has_access = true;
			 *     return $has_access;
			 *   }
			 *   add_filter( 'authorizer_has_access', 'my_rsa_feed_access_override' );
			 */
			if ( apply_filters( 'authorizer_has_access', $has_access, $wp ) === true ) {
				// Turn off the public notice about browsing anonymously
				update_option( 'auth_settings_advanced_public_notice', false);

				// We've determined that the current user has access, so simply return to grant access.
				return;
			}

			// We've determined that the current user doesn't have access, so we deal with them now.

			// Check to see if the requested page is public. If so, show it.
			if ( in_array( $this->get_id_from_pagename( $wp->query_vars['pagename'] ), $auth_settings['access_public_pages'] ) ) {
				update_option( 'auth_settings_advanced_public_notice', true);
				return;
			}

			// Check to see if the requested page is the home page and if it is public. If so, show it.
			if ( empty( $wp->request ) && in_array( 'home', $auth_settings['access_public_pages'] ) ) {
				update_option( 'auth_settings_advanced_public_notice', true);
				return;
			}

			$current_path = empty( $_SERVER['REQUEST_URI'] ) ? home_url() : $_SERVER['REQUEST_URI'];
			switch ( $auth_settings['access_redirect'] ) :
			case 'message':
				wp_die( $auth_settings['access_redirect_to_message'] . '<hr /><p style="text-align:center;margin-bottom:-15px;"><a class="button" href="' . wp_login_url( $current_path ) . '">Log In</a></p>', get_bloginfo( 'name' ) . ' - Access Restricted' );
				break;
			case 'login':
			default:
				wp_redirect( wp_login_url( $current_path ), 302 );
				exit;
			endswitch;

			// Sanity check: we should never get here
			wp_die( '<p>Access denied.</p>', 'Site Access Restricted' );
		}



		/**
		 ****************************
		 * Custom filters and actions
		 ****************************
		 */


		/**
		 * Implements hook: do_action( 'wp_login_failed', $username );
		 * Update the user meta for the user that just failed logging in.
		 * Keep track of time of last failed attempt and number of failed attempts.
		 */
		function update_login_failed_count( $username ) {
			// Grab plugin settings.
			$auth_settings = get_option( 'auth_settings' );

			// Get user trying to log in.
			// If this isn't a real user, update the global failed attempt
			// variables. We'll use these global variables to institute the
			// lockouts on nonexistent accounts. We do this so an attacker
			// won't be able to determine which accounts are real by which
			// accounts get locked out on multiple invalid attempts.
			$user = get_user_by( 'login', $username );

			if ( $user !== FALSE ) {
				$last_attempt = get_user_meta( $user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
				$num_attempts = get_user_meta( $user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
			} else {
				$last_attempt = get_option( 'auth_settings_advanced_lockouts_time_last_failed' );
				$num_attempts = get_option( 'auth_settings_advanced_lockouts_failed_attempts' );
			}

			// Make sure $last_attempt (time) and $num_attempts are positive integers.
			// Note: this addresses resetting them if either is unset from above.
			$last_attempt = abs( intval( $last_attempt ) );
			$num_attempts = abs( intval( $num_attempts ) );

			// Reset the failed attempt count if the time since the last
			// failed attempt is greater than the reset duration.
			$time_since_last_fail = time() - $last_attempt;
			$reset_duration = $auth_settings['advanced_lockouts']['reset_duration'] * 60; // minutes to seconds
			if ( $time_since_last_fail > $reset_duration ) {
				$num_attempts = 0;
			}

			// Set last failed time to now and increment last failed count.
			if ( $user !== FALSE ) {
				update_user_meta( $user->ID, 'auth_settings_advanced_lockouts_time_last_failed', time() );
				update_user_meta( $user->ID, 'auth_settings_advanced_lockouts_failed_attempts', $num_attempts + 1 );
			} else {
				update_option( 'auth_settings_advanced_lockouts_time_last_failed', time() );
				update_option( 'auth_settings_advanced_lockouts_failed_attempts', $num_attempts + 1 );
			}
		}

		/**
		 * Overwrite the URL for the lost password link on the login form.
		 * If we're authenticating against an external service, standard
		 * WordPress password resets won't work.
		 */
		function custom_lostpassword_url( $lostpassword_url ) {
			$auth_settings = get_option( 'auth_settings' );
			if (
				array_key_exists( 'advanced_lostpassword_url', $auth_settings ) &&
				filter_var( $auth_settings['advanced_lostpassword_url'], FILTER_VALIDATE_URL ) &&
				array_key_exists( 'access_restriction', $auth_settings ) &&
				$auth_settings['access_restriction'] !== 'everyone'
			) {
				$lostpassword_url = $auth_settings['advanced_lostpassword_url'];
			}
			return $lostpassword_url;
		}

		/**
		 * Overwrite the username and password labels on the login form.
		 */
		function custom_login_form_labels( $translated_text, $text, $domain ) {
			$auth_settings = get_option( 'auth_settings' );

			if ( $translated_text === 'Username' ) {
				$translated_text = 'Username';
			}

			if ( $translated_text === 'Password' ) {
				$translated_text = 'Password';
			}

			return $translated_text;
		}

		/**
		 * Show custom admin notice.
		 * Filter: admin_notice
		 */
		function show_advanced_admin_notice() {
			$notice = get_option( 'auth_settings_advanced_admin_notice' );
			delete_option( 'auth_settings_advanced_admin_notice' );

			if ( $notice && strlen( $notice ) > 0 ) {
				?>
				<div class="error">
					<p><?php _e( $notice ); ?></p>
				</div>
				<?php
			}
		}

		/**
		 * Add custom error message to login screen.
		 * Filter: login_errors
		 */
		function show_advanced_login_error( $errors ) {
			$error = get_option( 'auth_settings_advanced_login_error' );
			delete_option( 'auth_settings_advanced_login_error' );

			//$errors .= '    ' . $error . "<br />\n";
			$errors = '    ' . $error . "<br />\n";
			return $errors;
		}



		/**
		 * Load external resources for the public-facing site.
		 */
		function auth_public_scripts() {
			// Load (and localize) public scripts
			wp_enqueue_script( 'auth_public_scripts', plugins_url( '/assets/js/authorizer-public.js', __FILE__ ) );
			$auth_localized = array(
				'wp_login_url' => wp_login_url(),
				'public_warning' => get_option( 'auth_settings_advanced_public_notice' )
			);
			wp_localize_script( 'auth_public_scripts', 'auth', $auth_localized );
			//update_option( 'auth_settings_advanced_public_notice', false);

			// Load public css
			wp_register_style( 'authorizer-public-css', plugins_url( 'assets/css/authorizer-public.css', __FILE__ ) );
			wp_enqueue_style( 'authorizer-public-css' );
		}



		/**
		 ****************************
		 * Options page
		 ****************************
		 */



		/**
		 * Add a link to this plugin's settings page from the WordPress Plugins page.
		 * Called from "plugin_action_links" filter in __construct() above.
		 *
		 * @param array $links array of links in the admin sidebar
		 *
		 * @return array of links to show in the admin sidebar.
		 */
		public function plugin_settings_link( $links ) {
			$settings_link = '<a href="options-general.php?page=authorizer">Settings</a>';
			array_unshift( $links, $settings_link );
			return $links;
		} // END plugin_settings_link()



		/**
		 * Create the options page under Dashboard > Settings
		 * Run on action hook: admin_menu
		 */
		public function add_plugin_page() {
			// @see http://codex.wordpress.org/Function_Reference/add_options_page
			add_options_page(
				'Authorizer', // Page title
				'Authorizer', // Menu title
				'manage_options', // Capability
				'authorizer', // Menu slug
				array( $this, 'create_admin_page' ) // function
			);
		}



		/**
		 * Output the HTML for the options page
		 */
		public function create_admin_page() {
			?>
			<div class="wrap">
				<h2>Authorizer Settings</h2>
				<form method="post" action="options.php" autocomplete="off">
					<?php
						// This prints out all hidden settings fields
						// @see http://codex.wordpress.org/Function_Reference/settings_fields
						settings_fields( 'auth_settings_group' );
						// This prints out all the sections
						// @see http://codex.wordpress.org/Function_Reference/do_settings_sections
						do_settings_sections( 'authorizer' );
					?>
					<?php submit_button(); ?>
				</form>
			</div>
			<?php
		}



		/**
		 * Load external resources on this plugin's options page.
		 * Run on action hook: load-settings_page_authorizer
		 */
		public function load_options_page() {
			wp_enqueue_script(
				'authorizer',
				plugins_url( 'assets/js/authorizer.js', __FILE__ ),
				array( 'jquery-effects-shake' ), '5.0', true
			);
			$js_auth_config = array( 'baseurl' => get_bloginfo( 'url' ) );
			wp_localize_script( 'authorizer', 'auth_config',  $js_auth_config );

			wp_enqueue_script(
				'jquery.multi-select',
				plugins_url( 'assets/inc/jquery.multi-select/js/jquery.multi-select.js', __FILE__ ),
				array( 'jquery' ), '1.8', true
			);

			wp_register_style( 'authorizer-css', plugins_url( 'assets/css/authorizer.css', __FILE__ ) );
			wp_enqueue_style( 'authorizer-css' );

			wp_register_style( 'jquery-multi-select-css', plugins_url( 'assets/inc/jquery.multi-select/css/multi-select.css', __FILE__ ) );
			wp_enqueue_style( 'jquery-multi-select-css' );

			add_action( 'admin_notices', array( $this, 'admin_notices' ) ); // Add any notices to the top of the options page.
			add_action( 'admin_head', array( $this, 'admin_head' ) ); // Add help documentation to the options page.
		}



		/**
		 * Load external resources on the wp-login.php page.
		 * Run on action hook: login_head
		 */
		function load_login_css_and_js() {
			$auth_settings = get_option( 'auth_settings' );

			?>
			<script type="text/javascript" src="<?php print plugins_url( 'assets/js/domready.js', __FILE__ ); ?>"></script>
			<script type="text/javascript" src="<?php print plugins_url( 'assets/js/authorizer-login.js', __FILE__ ); ?>"></script>
			<?php

			if ( $auth_settings['advanced_branding'] === 'custom_uh' ):
				?>
				<link rel="stylesheet" type="text/css" href="<?php print plugins_url( 'assets/css/authorizer-login-custom_uh.css', __FILE__ ); ?>" />
				<script type="text/javascript" src="<?php print plugins_url( 'assets/js/authorizer-login-custom_uh.js', __FILE__ ); ?>"></script>
				<?php
			endif;
		}



		/**
		 * Add notices to the top of the options page.
		 * Run on action hook chain: load-settings_page_authorizer > admin_notices
		 * Description: Check for invalid settings combinations and show a warning message, e.g.:
		 *   if (cas url inaccessible) {
		 *     print "<div class='updated settings-error'><p>Can't reach Sakai.</p></div>";
		 *   }
		 */
		public function admin_notices() {
			$auth_settings = get_option( 'auth_settings' );

			if ( $auth_settings['external_service'] === 'cas' ) {
				// Check if provided CAS URL is accessible.
				$protocol = $auth_settings['cas_port'] == '80' ? 'http' : 'https';
				if ( ! $this->url_is_accessible( $protocol . '://' . $auth_settings['cas_host'] . $auth_settings['cas_path'] ) ) {
					print "<div class='updated settings-error'><p>Can't reach CAS server. Please provide <a href='javascript:chooseTab(\"external\");'>accurate CAS settings</a> if you intend to use it.</p></div>";
				}
			}
		}



		/**
		 * Add help documentation to the options page.
		 * Run on action hook chain: load-settings_page_authorizer > admin_head
		 */
		public function admin_head() {
			$screen = get_current_screen();
			
			// Add help tab for Access Lists Settings
			$help_auth_settings_access_lists_content = '
				<p><strong>Pending Users</strong>: Pending users are users who have successfully logged in to the site, but who haven\'t yet been approved (or blocked) by you.</p>
				<p><strong>Approved Users</strong>: Approved users have access to the site once they successfully log in.</p>
				<p><strong>Blocked Users</strong>: Blocked users will receive an error message when they try to visit the site after authenticating.</p>
				<p>Users in the <strong>Pending</strong> list appear automatically after a new user tries to log in from the configured external authentication service. You can add users to the <strong>Approved</strong> or <strong>Blocked</strong> lists by typing them in manually, or by clicking the <em>Approve</em> or <em>Block</em> buttons next to a user in the <strong>Pending</strong> list.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_access_lists_content',
					'title' => 'Access Lists',
					'content' => $help_auth_settings_access_lists_content,
				)
			);

			// Add help tab for Private Access Settings
			$help_auth_settings_access_content = '
				<p><strong>Who can view the site?</strong>: Choose the level of access restriction you\'d like to use on your site here. You can leave the site open to <strong>everyone</strong> (the default), restrict it to anyone with a WordPress account or an account on an external service like CAS or LDAP (<strong>university community</strong>), restrict it to WordPress users and only the external users that you specify via the <em>Access Lists</em> (<strong>approved users</strong>), or restrict access to only users with WordPress accounts (<strong>users with prior access</strong>).</p>
				<p><strong>Which role should receive email notifications about pending users?</strong>: If you\'ve restricted access to <strong>approved users</strong>, you can determine which WordPress users will receive a notification email everytime a new external user successfully logs in and is added to the pending list. All users of the specified role will receive an email, and the external user will get a message (specified below) telling them their access is pending approval.</p>
				<p><strong>What message should pending users see after attempting to log in?</strong>: Here you can specify the exact message a new external user will see once they try to log in to the site for the first time.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_access_content',
					'title' => 'Private Access',
					'content' => $help_auth_settings_access_content,
				)
			);

			// Add help tab for Public Access Settings
			$help_auth_settings_access_public_content = '
				<p><strong>What happens to people without access when they visit a private page?</strong>: Choose the response anonymous users receive when visiting the site. You can choose between immediately taking them to the <strong>login screen</strong>, or simply showing them a <strong>message</strong>.</p>
				<p><strong>What message should people without access see?</strong>: If you chose to show new users a <strong>message</strong> above, type that message here.</p>
				<p><strong>What pages (if any) should be available to everyone?</strong>: If you\'d like to declare certain pages on your site as always public (such as the course syllabus, introduction, or calendar), specify those pages here. These pages will always be available no matter what access restrictions exist.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_access_public_content',
					'title' => 'Public Access',
					'content' => $help_auth_settings_access_public_content,
				)
			);

			// Add help tab for External Service (CAS, LDAP) Settings
			// @TODO: add ldap settings, and select dropdown to choose between the two
			$help_auth_settings_external_content = '
				<p><strong>Type of external service to authenticate against</strong>: Choose which authentication service type you will be using. You\'ll have to fill out different fields below depending on which service you choose.</p>
				<p><strong>Default role for new CAS users</strong>: Specify which role new external users will get by default. Be sure to choose a role with limited permissions!</p>
				<p><strong><em>If you chose CAS as the external service type:</em></strong></p>
				<p><strong>CAS server hostname</strong>: Enter the hostname of the CAS server you authenticate against (e.g., login.its.hawaii.edu).</p>
				<p><strong>CAS server port</strong>: Enter the port on the CAS server to connect to (e.g., 443).</p>
				<p><strong>CAS server path/context</strong>: Enter the path to the login endpoint on the CAS server (e.g., /cas).</p>
				<p><strong><em>If you chose LDAP as the external service type:</em></strong></p>
				<p><strong>LDAP Host</strong>: Enter the URL of the LDAP server you authenticate against.</p>
				<p><strong>LDAP Search Base</strong>: Enter the LDAP string that represents the search base, e.g., ou=people,dc=example,dc=edu</p>
				<p><strong>LDAP Directory User</strong>: Enter the name of the LDAP user that has permissions to browse the directory.</p>
				<p><strong>LDAP Directory User Password</strong>: Enter the password for the LDAP user that has permission to browse the directory.</p>
				<p><strong>Secure Connection (TLS)</strong>: Select whether all communication with the LDAP server should be performed over a TLS-secured connection.</p>			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_external_content',
					'title' => 'External Service',
					'content' => $help_auth_settings_external_content,
				)
			);

			// Add help tab for Advanced Settings
			$help_auth_settings_advanced_content = '
				<p><strong>Custom lost password URL</strong>: The WordPress login page contains a link to recover a lost password. If you have external users who shouldn\'t change the password on their WordPress account, point them to the appropriate location to change the password on their external authentication service here.</p>
				<p><strong>Custom WordPress login branding</strong>: If you\'d like to use the custom University of Hawai&#8216;i and DCDC branding on the WordPress login page, select that here.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_advanced_content',
					'title' => 'Advanced',
					'content' => $help_auth_settings_advanced_content,
				)
			);
		}



		/**
		 * Create sections and options
		 * Run on action hook: admin_init
		 */
		public function page_init() {
			// Create one setting that holds all the options (array)
			// @see http://codex.wordpress.org/Function_Reference/register_setting
			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			// @see http://codex.wordpress.org/Function_Reference/add_settings_field
			register_setting(
				'auth_settings_group', // Option group
				'auth_settings', // Option name
				array( $this, 'sanitize_options' ) // Sanitize callback
			);

			add_settings_section(
				'auth_settings_tabs', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_tabs' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);

			// Create Access Lists section
			add_settings_section(
				'auth_settings_lists', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_access_lists' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_access_users_pending', // HTML element ID
				'Pending Users', // HTML element Title
				array( $this, 'print_combo_auth_access_users_pending' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_lists' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_users_approved', // HTML element ID
				'Approved Users', // HTML element Title
				array( $this, 'print_combo_auth_access_users_approved' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_lists' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_users_blocked', // HTML element ID
				'Blocked Users', // HTML element Title
				array( $this, 'print_combo_auth_access_users_blocked' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_lists' // Section this setting is shown on
			);

			// Create Private Access section
			add_settings_section(
				'auth_settings_access', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_access' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_access_restriction', // HTML element ID
				'Who can view the site?', // HTML element Title
				array( $this, 'print_radio_auth_access_restriction' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_role_receive_pending_emails', // HTML element ID
				'Which role should receive email notifications about pending users?', // HTML element Title
				array( $this, 'print_select_auth_access_role_receive_pending_emails' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_pending_redirect_to_message', // HTML element ID
				'What message should pending users see after attempting to log in?', // HTML element Title
				array( $this, 'print_wysiwyg_auth_access_pending_redirect_to_message' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access' // Section this setting is shown on
			);


			// Create Public Access section
			add_settings_section(
				'auth_settings_access_public', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_access_public' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_access_redirect', // HTML element ID
				'What happens to people without access when they visit a private page?', // HTML element Title
				array( $this, 'print_radio_auth_access_redirect' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_public' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_redirect_to_message', // HTML element ID
				'What message should people without access see?', // HTML element Title
				array( $this, 'print_wysiwyg_auth_access_redirect_to_message' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_public' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_public_pages', // HTML element ID
				'What pages (if any) should be available to everyone?', // HTML element Title
				array( $this, 'print_multiselect_auth_access_public_pages' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_public' // Section this setting is shown on
			);

			// Create External Service Settings section
			add_settings_section(
				'auth_settings_external', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_external' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_external_service', // HTML element ID
				'Type of external service to authenticate against', // HTML element Title
				array( $this, 'print_radio_auth_external_service' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_default_role', // HTML element ID
				'Default role for new users', // HTML element Title
				array( $this, 'print_select_auth_access_default_role' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_cas_host', // HTML element ID
				'CAS server hostname', // HTML element Title
				array( $this, 'print_text_cas_host' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_cas_port', // HTML element ID
				'CAS server port', // HTML element Title
				array( $this, 'print_text_cas_port' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_cas_path', // HTML element ID
				'CAS server path/context', // HTML element Title
				array( $this, 'print_text_cas_path' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_host', // HTML element ID
				'LDAP Host', // HTML element Title
				array( $this, 'print_text_ldap_host' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_port', // HTML element ID
				'LDAP Port', // HTML element Title
				array( $this, 'print_text_ldap_port' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_search_base', // HTML element ID
				'LDAP Search Base', // HTML element Title
				array( $this, 'print_text_ldap_search_base' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_uid', // HTML element ID
				'LDAP attribute containing username', // HTML element Title
				array( $this, 'print_text_ldap_uid' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_user', // HTML element ID
				'LDAP Directory User', // HTML element Title
				array( $this, 'print_text_ldap_user' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_password', // HTML element ID
				'LDAP Directory User Password', // HTML element Title
				array( $this, 'print_password_ldap_password' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_ldap_tls', // HTML element ID
				'Secure Connection (TLS)', // HTML element Title
				array( $this, 'print_checkbox_ldap_tls' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);

			// Create Advanced Settings section
			add_settings_section(
				'auth_settings_advanced', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_advanced' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_advanced_lockouts', // HTML element ID
				'Limit invalid login attempts', // HTML element Title
				array( $this, 'print_text_auth_advanced_lockouts' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_advanced' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_advanced_lostpassword_url', // HTML element ID
				'Custom lost password URL', // HTML element Title
				array( $this, 'print_text_auth_advanced_lostpassword_url' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_advanced' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_advanced_branding', // HTML element ID
				'Custom WordPress login branding', // HTML element Title
				array( $this, 'print_radio_auth_advanced_branding' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_advanced' // Section this setting is shown on
			);
		}


		/**
		 * Set meaningful defaults for the plugin options.
		 * Note: This function is called on plugin activation.
		 */
		function set_default_options() {
			global $wp_roles;
			$auth_settings = get_option( 'auth_settings' );
			if ( $auth_settings === FALSE ) {
				$auth_settings = array();
			}

			// Access Lists Defaults.
			if ( !array_key_exists( 'access_users_pending', $auth_settings ) ) {
				$auth_settings['access_users_pending'] = array();
			}
			if ( !array_key_exists( 'access_users_approved', $auth_settings ) ) {
				$auth_settings['access_users_approved'] = array();
			}
			if ( !array_key_exists( 'access_users_blocked', $auth_settings ) ) {
				$auth_settings['access_users_blocked'] = array();
			}

			// Private Access Defaults.
			if ( !array_key_exists( 'access_restriction', $auth_settings ) ) {
				$auth_settings['access_restriction'] = 'everyone';
			}
			if ( !array_key_exists( 'access_role_receive_pending_emails', $auth_settings ) ) {
				$auth_settings['access_role_receive_pending_emails'] = '---';
			}
			if ( !array_key_exists( 'access_pending_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_pending_redirect_to_message'] = '<p>You\'re not currently on the roster for this course. Your instructor has been notified, and once he/she has approved your request, you will be able to access this site. If you need any other help, please contact your instructor.</p>';
			}

			// Public Access Defaults.
			if ( !array_key_exists( 'access_redirect', $auth_settings ) ) {
				$auth_settings['access_redirect'] = 'login';
			}
			if ( !array_key_exists( 'access_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_redirect_to_message'] = '<p><strong>Notice</strong>: You are browsing this site anonymously, and only have access to a portion of its content.</p>';
			}
			if ( !array_key_exists( 'access_public_pages', $auth_settings ) ) {
				$auth_settings['access_public_pages'] = array('home');
			}

			// External Service Defaults.
			if ( !array_key_exists( 'access_default_role', $auth_settings ) ) {
				// Set default role to 'student' if that role exists, 'subscriber' otherwise.
				$all_roles = $wp_roles->roles;
				$editable_roles = apply_filters( 'editable_roles', $all_roles );
				if ( array_key_exists( 'student', $editable_roles ) ) {
					$auth_settings['access_default_role'] = 'student';
				} else {
					$auth_settings['access_default_role'] = 'subscriber';
				}
			}
			if ( !array_key_exists( 'external_service', $auth_settings ) ) {
				$auth_settings['external_service'] = 'cas';
			}

			if ( !array_key_exists( 'cas_host', $auth_settings ) ) {
				$auth_settings['cas_host'] = '';
			}
			if ( !array_key_exists( 'cas_port', $auth_settings ) ) {
				$auth_settings['cas_port'] = '';
			}
			if ( !array_key_exists( 'cas_path', $auth_settings ) ) {
				$auth_settings['cas_path'] = '';
			}

			if ( !array_key_exists( 'ldap_host', $auth_settings ) ) {
				$auth_settings['ldap_host'] = '';
			}
			if ( !array_key_exists( 'ldap_port', $auth_settings ) ) {
				$auth_settings['ldap_port'] = '';
			}
			if ( !array_key_exists( 'ldap_search_base', $auth_settings ) ) {
				$auth_settings['ldap_search_base'] = '';
			}
			if ( !array_key_exists( 'ldap_uid', $auth_settings ) ) {
				$auth_settings['ldap_uid'] = '';
			}
			if ( !array_key_exists( 'ldap_user', $auth_settings ) ) {
				$auth_settings['ldap_user'] = '';
			}
			if ( !array_key_exists( 'ldap_password', $auth_settings ) ) {
				$auth_settings['ldap_password'] = '';
			}
			if ( !array_key_exists( 'ldap_tls', $auth_settings ) ) {
				$auth_settings['ldap_tls'] = '1';
			}

			// Advanced defaults.
			if ( !array_key_exists( 'advanced_lockouts', $auth_settings ) ) {
				$auth_settings['advanced_lockouts'] = array(
					'attempts_1' => 10,
					'duration_1' => 1,
					'attempts_2' => 10,
					'duration_2' => 10,
					'reset_duration' => 120,
				);
			}
			if ( !array_key_exists( 'advanced_lostpassword_url', $auth_settings ) ) {
				$auth_settings['advanced_lostpassword_url'] = '';
			}
			if ( !array_key_exists( 'advanced_branding', $auth_settings ) ) {
				$auth_settings['advanced_branding'] = 'default';
			}

			update_option( 'auth_settings', $auth_settings );
		}


		/**
		 * Settings sanitizer callback
		 */
		function sanitize_options( $auth_settings ) {
			// If the pending user list isn't a list, make it.
			if ( ! is_array( $auth_settings['access_users_pending'] ) ) {
				$auth_settings['access_users_pending'] = array();
			}

			// If the approved user list isn't a list, make it.
			if ( ! is_array( $auth_settings['access_users_approved'] ) ) {
				$auth_settings['access_users_approved'] = array();
			}

			// Make sure the WordPress user accounts for people in the approved
			// list have the same role as what's chosen in the approved list.
			foreach( $auth_settings['access_users_approved'] as $user_info ) {
				$wp_user = get_user_by( 'email', $user_info['email'] );
				if ( $wp_user && ! array_key_exists( $user_info['role'], $wp_user->roles ) ) {
					$wp_user->set_role( $user_info['role'] );
				}
			}

			// If the blocked user list isn't a list, make it.
			if ( ! is_array( $auth_settings['access_users_blocked'] ) ) {
				$auth_settings['access_users_blocked'] = array();
			}

			// Default to "Everyone" view access restriction.
			if ( ! in_array( $auth_settings['access_restriction'], array( 'everyone', 'university', 'approved_users' ) ) ) {
				$auth_settings['access_restriction'] = 'everyone';
			}

			// Default to WordPress login access redirect.
			if ( ! in_array( $auth_settings['access_redirect'], array( 'login', 'page', 'message' ) ) ) {
				$auth_settings['access_redirect'] = 'login';
			}

			// Sanitize CAS Host setting
			$auth_settings['cas_host'] = filter_var( $auth_settings['cas_host'], FILTER_SANITIZE_URL );

			// Sanitize LDAP and CAS Port (int)
			$auth_settings['ldap_port'] = filter_var( $auth_settings['ldap_port'], FILTER_SANITIZE_NUMBER_INT );
			$auth_settings['cas_port'] = filter_var( $auth_settings['cas_port'], FILTER_SANITIZE_NUMBER_INT );

			// Sanitize LDAP Host setting
			$auth_settings['ldap_host'] = filter_var( $auth_settings['ldap_host'], FILTER_SANITIZE_URL );

			// Sanitize LDAP attributes (basically make sure they don't have any parantheses)
			$auth_settings['ldap_uid'] = filter_var( $auth_settings['ldap_uid'], FILTER_SANITIZE_EMAIL );

			// Obfuscate LDAP directory user password
			if ( strlen( $auth_settings['ldap_password'] ) > 0 ) {
				// encrypt the directory user password for some minor obfuscation in the database.
				$auth_settings['ldap_password'] = base64_encode( $this->encrypt( $auth_settings['ldap_password'] ) );
			}

			// Make sure public pages is an empty array if it's empty
			if ( ! is_array ( $auth_settings['access_public_pages'] ) ) {
				$auth_settings['access_public_pages'] = array();
			}

			// Make sure all lockout options are integers (attempts_1,
			// duration_1, attempts_2, duration_2, reset_duration).
			foreach ( $auth_settings['advanced_lockouts'] as $key => $value ) {
				$auth_settings['advanced_lockouts'][$key] = filter_var( $value, FILTER_SANITIZE_NUMBER_INT );
			}

			return $auth_settings;
		}


		/**
		 * Settings print callbacks
		 */
		function print_section_info_tabs() {
			?><h2 class="nav-tab-wrapper">
				<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:chooseTab('access_lists');">Access Lists</a>
				<a class="nav-tab nav-tab-access" href="javascript:chooseTab('access');">Private Access</a>
				<a class="nav-tab nav-tab-access_public" href="javascript:chooseTab('access_public');">Public Access</a>
				<a class="nav-tab nav-tab-external" href="javascript:chooseTab('external');">External Service</a>
				<a class="nav-tab nav-tab-advanced" href="javascript:chooseTab('advanced');">Advanced</a>
			</h2><?php
		}

		function print_section_info_access_lists() {
			?><div id="section_info_access_lists" class="section_info">
				<p>Manage who has access to this site using these lists.</p>
				<ol>
					<li><strong>Pending</strong> users are users who have successfully logged in to the site, but who haven't yet been approved (or blocked) by you.</li>
					<li><strong>Approved</strong> users have access to the site once they successfully log in.</li>
					<li><strong>Blocked</strong> users will receive an error message when they try to visit the site after authenticating.</li>
				</ol>
				<p>If you don't see any lists here, enable access restriction to "Only approved users" from the <a href="javascript:chooseTab('access');">Private Access</a> tab.</p>
			</div><?php
		}

		function print_combo_auth_access_users_pending( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><ul id="list_auth_settings_access_users_pending" style="margin:0;">
				<?php if ( array_key_exists( 'access_users_pending', $auth_settings ) && is_array( $auth_settings['access_users_pending'] ) && count( $auth_settings['access_users_pending'] ) > 0 ) : ?>
					<?php foreach ( $auth_settings['access_users_pending'] as $key => $pending_user ): ?>
						<?php if ( empty( $pending_user ) || count( $pending_user ) < 1 ) continue; ?>
						<?php $pending_user['is_wp_user'] = false; ?>
						<li>
							<input type="text" name="auth_settings[access_users_pending][<?= $key; ?>][username]" value="<?= $pending_user['username'] ?>" readonly="true" class="auth-username" />
							<input type="text" id="auth_settings_access_users_pending_<?= $key; ?>" name="auth_settings[access_users_pending][<?= $key; ?>][email]" value="<?= $pending_user['email']; ?>" readonly="true" class="auth-email" />
							<select name="auth_settings[access_users_pending][<?= $key; ?>][role]" class="auth-role">
								<?php $this->wp_dropdown_permitted_roles( $pending_user['role'] ); ?>
							</select>
							<input type="button" class="button-primary" id="approve_user_<?= $key; ?>" onclick="auth_add_user(this, 'approved'); auth_ignore_user(this, 'pending');" value="Approve" />
							<input type="button" class="button-primary" id="block_user_<?= $key; ?>" onclick="auth_add_user(this, 'blocked'); auth_ignore_user(this, 'pending');" value="Block" />
							<input type="button" class="button" id="ignore_user_<?= $key; ?>" onclick="auth_ignore_user(this);" value="&times;" />
						</li>
					<?php endforeach; ?>
				<?php else: ?>
						<li class="auth-empty"><em>No pending users</em></li>
				<?php endif; ?>
			</ul>
			<?php
		}

		function print_combo_auth_access_users_approved( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><ul id="list_auth_settings_access_users_approved" style="margin:0;">
				<?php if ( array_key_exists( 'access_users_approved', $auth_settings ) && is_array( $auth_settings['access_users_approved'] ) ) : ?>
					<?php foreach ( $auth_settings['access_users_approved'] as $key => $approved_user ): ?>
						<?php $is_current_user = false; ?>
						<?php if ( empty( $approved_user ) || count( $approved_user ) < 1 ) continue; ?>
						<?php if ( $approved_wp_user = get_user_by( 'email', $approved_user['email'] ) ): ?>
							<?php $approved_user['username'] = $approved_wp_user->user_login; ?>
							<?php $approved_user['email'] = $approved_wp_user->user_email; ?>
							<?php $approved_user['role'] = array_shift( $approved_wp_user->roles ); ?>
							<?php $approved_user['date_added'] = $approved_wp_user->user_registered; ?>
							<?php $approved_user['is_wp_user'] = true; ?>
							<?php $is_current_user = $approved_wp_user->ID === get_current_user_id(); ?>
						<?php else: ?>
							<?php $approved_user['is_wp_user'] = false; ?>
						<?php endif; ?>
						<li>
							<input type="text" name="auth_settings[access_users_approved][<?= $key; ?>][username]" value="<?= $approved_user['username'] ?>" readonly="true" class="auth-username" />
							<input type="text" id="auth_settings_access_users_approved_<?= $key; ?>" name="auth_settings[access_users_approved][<?= $key; ?>][email]" value="<?= $approved_user['email']; ?>" readonly="true" class="auth-email" />
							<select name="auth_settings[access_users_approved][<?= $key; ?>][role]" class="auth-role" onchange="save_auth_settings_access(this);">
								<?php $this->wp_dropdown_permitted_roles( $approved_user['role'], $is_current_user ); ?>
							</select>
							<input type="text" name="auth_settings[access_users_approved][<?= $key; ?>][date_added]" value="<?= date( 'M Y', strtotime( $approved_user['date_added'] ) ); ?>" readonly="true" class="auth-date-added" />
							<input type="button" class="button" id="ignore_user_<?= $key; ?>" onclick="auth_ignore_user(this, 'approved');" value="&times;" <?php if ( $is_current_user ) print 'disabled="disabled" '; ?>/>
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
			<div id="new_auth_settings_access_users_approved">
				<input type="text" name="new_approved_user_name" id="new_approved_user_name" placeholder="username" class="auth-username" />
				<input type="text" name="new_approved_user_email" id="new_approved_user_email" placeholder="email address" class="auth-email" />
				<select name="new_approved_user_role" id="new_approved_user_role" class="auth-role">
					<?php $this->wp_dropdown_permitted_roles( $auth_settings['access_default_role'] ); ?>
				</select>
				<input class="button-primary" type="button" id="approve_user_new" onclick="auth_add_user(this, 'approved');" value="Approve" /><br />
			</div>
			<?php
		}

		function print_combo_auth_access_users_blocked( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><ul id="list_auth_settings_access_users_blocked" style="margin:0;">
				<?php if ( array_key_exists( 'access_users_blocked', $auth_settings ) && is_array( $auth_settings['access_users_blocked'] ) ) : ?>
					<?php foreach ( $auth_settings['access_users_blocked'] as $key => $blocked_user ): ?>
						<?php if ( empty( $blocked_user ) || count( $blocked_user ) < 1 ) continue; ?>
						<?php if ( $blocked_wp_user = get_user_by( 'email', $blocked_user['email'] ) ): ?>
							<?php $blocked_user['username'] = $blocked_wp_user->user_login; ?>
							<?php $blocked_user['email'] = $blocked_wp_user->user_email; ?>
							<?php $blocked_user['role'] = array_shift( $blocked_wp_user->roles ); ?>
							<?php $blocked_user['date_added'] = $blocked_wp_user->user_registered; ?>
							<?php $blocked_user['is_wp_user'] = true; ?>
						<?php else: ?>
							<?php $blocked_user['is_wp_user'] = false; ?>
						<?php endif; ?>
						<li>
							<input type="text" name="auth_settings[access_users_blocked][<?= $key; ?>][username]" value="<?= $blocked_user['username'] ?>" readonly="true" class="auth-username" />
							<input type="text" id="auth_settings_access_users_blocked_<?= $key; ?>" name="auth_settings[access_users_blocked][<?= $key; ?>][email]" value="<?= $blocked_user['email']; ?>" readonly="true" class="auth-email" />
							<select name="auth_settings[access_users_blocked][<?= $key; ?>][role]" class="auth-role">
								<?php $this->wp_dropdown_permitted_roles( $blocked_user['role'] ); ?>
							</select>
							<input type="text" name="auth_settings[access_users_blocked][<?= $key; ?>][date_added]" value="<?= date( 'M Y', strtotime( $blocked_user['date_added'] ) ); ?>" readonly="true" class="auth-date-added" />
							<input type="button" class="button" id="ignore_user_<?= $key; ?>" onclick="auth_ignore_user(this, 'blocked');" value="&times;" />
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
			<div id="new_auth_settings_access_users_blocked">
				<input type="text" name="new_blocked_user_name" id="new_blocked_user_name" placeholder="username" class="auth-username" />
				<input type="text" name="new_blocked_user_email" id="new_blocked_user_email" placeholder="email address" class="auth-email" />
				<select name="new_blocked_user_role" id="new_blocked_user_role" class="auth-role">
					<option value="<?= $auth_settings['access_default_role']; ?>"><?= ucfirst( $auth_settings['access_default_role'] ); ?></option>
				</select>
				<input class="button-primary" type="button" id="block_user_new" onclick="auth_add_user(this, 'blocked');" value="Block" /><br />
			</div>
			<?php
		}


		function print_section_info_external() {
			?><div id="section_info_external" class="section_info">
				<p><span class="red">Important Note</span>: If you're configuring an external authentication system (like CAS or LDAP) for the first time, make sure you do <strong>not</strong> log out of your administrator account in WordPress until you are sure it works. You risk locking yourself out of your WordPress installation. Use a different browser (or incognito/safe-browsing mode) to test, and leave your adminstrator account logged in here.</p>
				<p>As a safeguard, you can always access the default WordPress login panel (and bypass any external authentication system) by visiting wp-login.php?login=wordpress like so:<br />
					<a href="<?php print wp_login_url() . '?login=wordpress'; ?>"><?php print wp_login_url() . '?login=wordpress'; ?></a></p>
				<p>Enter your external server settings below.</p>
			</div><?php
		}

		function print_select_auth_access_default_role( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><select id="auth_settings_access_default_role" name="auth_settings[access_default_role]">
				<?php wp_dropdown_roles( $auth_settings['access_default_role'] ); ?>
			</select><?php
		}

		function print_radio_auth_external_service( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="radio" id="radio_auth_settings_external_service_cas" name="auth_settings[external_service]" value="cas"<?php checked( 'cas' == $auth_settings['external_service'] ); ?> /> CAS<br />
			<input type="radio" id="radio_auth_settings_external_service_ldap" name="auth_settings[external_service]" value="ldap"<?php checked( 'ldap' == $auth_settings['external_service'] ); ?> /> LDAP<br /><?php
		}

		function print_text_cas_host( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_cas_host" name="auth_settings[cas_host]" value="<?= $auth_settings['cas_host']; ?>" placeholder="login.its.example.edu" /><?php
		}

		function print_text_cas_port( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_cas_port" name="auth_settings[cas_port]" value="<?= $auth_settings['cas_port']; ?>" placeholder="443" style="width:50px;" /><?php
		}

		function print_text_cas_path( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_cas_path" name="auth_settings[cas_path]" value="<?= $auth_settings['cas_path']; ?>" placeholder="/cas" /><?php
		}

		function print_text_ldap_host( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_ldap_host" name="auth_settings[ldap_host]" value="<?= $auth_settings['ldap_host']; ?>" placeholder="ldap.example.edu" /><?php
		}
		function print_text_ldap_port( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_ldap_port" name="auth_settings[ldap_port]" value="<?= $auth_settings['ldap_port']; ?>" placeholder="389" /><?php
		}
		function print_text_ldap_search_base( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_ldap_search_base" name="auth_settings[ldap_search_base]" value="<?= $auth_settings['ldap_search_base']; ?>" placeholder="ou=people,dc=example,dc=edu" style="width:225px;" /><?php
		}
		function print_text_ldap_uid( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_ldap_uid" name="auth_settings[ldap_uid]" value="<?= $auth_settings['ldap_uid']; ?>" placeholder="uid" /><?php
		}
		function print_text_ldap_user( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_ldap_user" name="auth_settings[ldap_user]" value="<?= $auth_settings['ldap_user']; ?>" placeholder="cn=directory-user,ou=specials,dc=example,dc=edu" style="width:330px;" /><?php
		}
		function print_password_ldap_password( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="password" id="garbage_to_stop_autofill" name="garbage" value="" autocomplete="off" style="display:none;" />
			<input type="password" id="auth_settings_ldap_password" name="auth_settings[ldap_password]" value="<?= $this->decrypt(base64_decode($auth_settings['ldap_password'])); ?>" autocomplete="off" /><?php
		}
		function print_checkbox_ldap_tls( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="checkbox" id="auth_settings_ldap_tls" name="auth_settings[ldap_tls]" value="1"<?php checked( 1 == $auth_settings['ldap_tls'] ); ?> /> Use TLS<?php
		}


		function print_section_info_access() {
			?><div id="section_info_access" class="section_info">
				<?php wp_nonce_field( 'save_auth_settings_access', 'nonce_save_auth_settings_access' ); ?>
				<p>Choose how you want to restrict access to this site below.</p>
			</div><?php
		}

		function print_radio_auth_access_restriction( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="radio" id="radio_auth_settings_access_restriction_everyone" name="auth_settings[access_restriction]" value="everyone"<?php checked( 'everyone' == $auth_settings['access_restriction'] ); ?> /> Everyone (No access restriction: all anonymous and all WordPress users)<br />
			<input type="radio" id="radio_auth_settings_access_restriction_university" name="auth_settings[access_restriction]" value="university"<?php checked( 'university' == $auth_settings['access_restriction'] ); ?> /> Only the university community (All external service users and all WordPress users)<br />
			<input type="radio" id="radio_auth_settings_access_restriction_approved_users" name="auth_settings[access_restriction]" value="approved_users"<?php checked( 'approved_users' == $auth_settings['access_restriction'] ); ?> /> Only <a href="javascript:chooseTab('access_lists');" id="dashboard_link_approved_users">approved users</a> (Approved external users and all WordPress users)<br /><?php
		}

		function print_select_auth_access_role_receive_pending_emails( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><select id="auth_settings_access_role_receive_pending_emails" name="auth_settings[access_role_receive_pending_emails]">
				<option value="---" <?php selected( $auth_settings['access_role_receive_pending_emails'], '---' ); ?>>None (Don't send notification emails)</option>
				<?php wp_dropdown_roles( $auth_settings['access_role_receive_pending_emails'] ); ?>
			</select><?php
		}

		function print_wysiwyg_auth_access_pending_redirect_to_message( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			wp_editor(
				$auth_settings['access_pending_redirect_to_message'],
				'auth_settings_access_pending_redirect_to_message',
				array(
					'media_buttons' => false,
					'textarea_name' => 'auth_settings[access_pending_redirect_to_message]',
					'textarea_rows' => 5,
					'tinymce' => true,
					'teeny' => true,
					'quicktags' => false,
				)
			);
		}


		function print_section_info_access_public() {
			?><div id="section_info_access_public" class="section_info">
				<p>Choose your public access options here. If you don't see any options here, enable access restriction from the <a href="javascript:chooseTab('access');">Private Access</a> tab.</p>
			</div><?php
		}

		function print_radio_auth_access_redirect( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="radio" id="radio_auth_settings_access_redirect_to_login" name="auth_settings[access_redirect]" value="login"<?php checked( 'login' == $auth_settings['access_redirect'] ); ?> /> Send them to the login screen<br />
				<input type="radio" id="radio_auth_settings_access_redirect_to_message" name="auth_settings[access_redirect]" value="message"<?php checked( 'message' == $auth_settings['access_redirect'] ); ?> /> Show them a simple message<?php
		}

		function print_wysiwyg_auth_access_redirect_to_message( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			wp_editor(
				$auth_settings['access_redirect_to_message'],
				'auth_settings_access_redirect_to_message',
				array(
					'media_buttons' => false,
					'textarea_name' => 'auth_settings[access_redirect_to_message]',
					'textarea_rows' => 5,
					'tinymce' => true,
					'teeny' => true,
					'quicktags' => false,
				)
			);
		}

		function print_multiselect_auth_access_public_pages( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><select id="auth_settings_access_public_pages" multiple="multiple" name="auth_settings[access_public_pages][]">
				<optgroup label="Special">
					<option value="home" <?php print in_array( 'home', $auth_settings['access_public_pages'] ) ? 'selected="selected"' : ''; ?>>Home Page</option>
				</optgroup>
				<?php $post_types = get_post_types( '', 'names' ); ?>
				<?php $post_types = is_array( $post_types ) ? $post_types : array(); ?>
				<?php foreach ( $post_types as $post_type ): ?>
					<optgroup label="<?php print ucfirst( $post_type ); ?>">
					<?php $pages = get_pages( array( 'post_type' => $post_type ) ); ?>
					<?php $pages = is_array( $pages ) ? $pages : array(); ?>
					<?php foreach ( $pages as $page ): ?>
						<option value="<?php print $page->ID; ?>" <?php print in_array( $page->ID, $auth_settings['access_public_pages'] ) ? 'selected="selected"' : ''; ?>><?php print $page->post_title; ?></option>
					<?php endforeach; ?>
					</optgroup>
				<?php endforeach; ?>
			</select><?php
		}


		function print_section_info_advanced() {
			?><div id="section_info_advanced" class="section_info">
				<p>You may optionally specify some advanced settings below.</p>
			</div><?php
		}

		function print_text_auth_advanced_lockouts() {
			$auth_settings = get_option( 'auth_settings' );
			?>After
			<input type="text" id="auth_settings_advanced_lockouts_attempts_1" name="auth_settings[advanced_lockouts][attempts_1]" value="<?= $auth_settings['advanced_lockouts']['attempts_1']; ?>" placeholder="10" style="width:30px;" />
			invalid password attempts, delay further attempts on that username for
			<input type="text" id="auth_settings_advanced_lockouts_duration_1" name="auth_settings[advanced_lockouts][duration_1]" value="<?= $auth_settings['advanced_lockouts']['duration_1']; ?>" placeholder="1" style="width:30px;" />
			minute(s).
			<br />
			After
			<input type="text" id="auth_settings_advanced_lockouts_attempts_2" name="auth_settings[advanced_lockouts][attempts_2]" value="<?= $auth_settings['advanced_lockouts']['attempts_2']; ?>" placeholder="10" style="width:30px;" />
			more invalid attempts, increase the delay to
			<input type="text" id="auth_settings_advanced_lockouts_duration_2" name="auth_settings[advanced_lockouts][duration_2]" value="<?= $auth_settings['advanced_lockouts']['duration_2']; ?>" placeholder="10" style="width:30px;" />
			minutes.
			<br />
			Reset the delays after
			<input type="text" id="auth_settings_advanced_lockouts_reset_duration" name="auth_settings[advanced_lockouts][reset_duration]" value="<?= $auth_settings['advanced_lockouts']['reset_duration']; ?>" placeholder="240" style="width:40px;" />
			minutes with no invalid attempts.<?php
		}

		function print_text_auth_advanced_lostpassword_url() {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="text" id="auth_settings_advanced_lostpassword_url" name="auth_settings[advanced_lostpassword_url]" value="<?= $auth_settings['advanced_lostpassword_url']; ?>" placeholder="https://myuh.hawaii.edu:8888/am-forgot-password" style="width: 400px;" /><?php
		}

		function print_radio_auth_advanced_branding( $args = '' ) {
			$auth_settings = get_option( 'auth_settings' );
			?><input type="radio" id="radio_auth_settings_advanced_branding_default" name="auth_settings[advanced_branding]" value="default"<?php checked( 'default' == $auth_settings['advanced_branding'] ); ?> /> Default WordPress login screen<br />
				<input type="radio" id="radio_auth_settings_advanced_branding_custom_uh" name="auth_settings[advanced_branding]" value="custom_uh"<?php checked( 'custom_uh' == $auth_settings['advanced_branding'] ); ?> /> Custom University of Hawai'i login screen<?php
		}



		/**
		 ****************************
		 * Dashboard widget
		 ****************************
		 */
		function add_dashboard_widgets() {
			// Only users who can edit can see the authorizer dashboard widget
			if ( current_user_can( 'edit_posts' ) ) {
				// Add dashboard widget for adding/editing users with access
				wp_add_dashboard_widget( 'auth_dashboard_widget', 'Authorizer Settings', array( $this, 'add_auth_dashboard_widget' ) );
			}
		}

		function add_auth_dashboard_widget() {
			$auth_settings = get_option( 'auth_settings' );
			?>
			<div class="inside">
				<form method="post" id="auth_settings_access_form" action="">
					<input type="hidden" id="auth_settings_cas_host" name="auth_settings[cas_host]" value="<?php print $auth_settings['cas_host']; ?>" />
					<p><?php $this->print_section_info_access(); ?></p>
					<div style="display: none;">
						<h2>Who can view the site?</h2>
						<?php $this->print_radio_auth_access_restriction(); ?>
					</div>
					<div>
						<h2>Pending Users</h2>
						<?php $this->print_combo_auth_access_users_pending(); ?>
					</div>
					<div>
						<h2>Approved Users</h2>
						<?php $this->print_combo_auth_access_users_approved(); ?>
					</div>
					<div>
						<h2>Blocked Users</h2>
						<?php $this->print_combo_auth_access_users_blocked(); ?>
					</div>
					<br class="clear" />
				</form>
			</div>
			<?php
		}

		function ajax_save_auth_dashboard_widget() {
			// Make sure posted variables exist.
			if ( empty( $_POST['access_restriction'] ) || empty( $_POST['nonce_save_auth_settings_access'] ) ) {
				die('');
			}

			// Nonce check.
			if ( ! wp_verify_nonce( $_POST['nonce_save_auth_settings_access'], 'save_auth_settings_access' ) ) {
				die('');
			}

			// If invalid input, set access restriction to only approved users.
			if ( ! in_array( $_POST['access_restriction'], array( 'everyone', 'university', 'approved_users' ) ) ) {
				$_POST['access_restriction'] = 'approved_users';
			}

			$auth_settings = get_option( 'auth_settings' );

			$auth_settings['access_restriction'] = stripslashes( $_POST['access_restriction'] );
			$auth_settings['access_users_pending'] = $_POST['access_users_pending'];
			$auth_settings['access_users_approved'] = $_POST['access_users_approved'];
			$auth_settings['access_users_blocked'] = $_POST['access_users_blocked'];

			// Only users who can edit can see the Sakai dashboard widget
			if ( current_user_can( 'edit_posts' ) ) {
				update_option( 'auth_settings', $auth_settings );
			}
		}



		/**
		 ****************************
		 * Helper functions
		 ****************************
		 */



		/**
		 * Basic encryption using a public (not secret!) key. Used for general
		 * database obfuscation of passwords.
		 */
		private static $key = '8QxnrvjdtweisvCBKEY!+0';
		function encrypt( $text ) {
			return mcrypt_encrypt( MCRYPT_RIJNDAEL_256, self::$key, $text, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' );
		}
		function decrypt( $secret ) {
			$str = '';
			return rtrim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, self::$key, $secret, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' ), "\0$str" );
		}

		/**
		 * In a multisite environment, returns true if the current user is logged
		 * in and a user of the current blog. In single site mode, simply returns
		 * true if the current user is logged in.
		 */
		function is_user_logged_in_and_blog_user() {
			$is_user_logged_in_and_blog_user = false;
			if ( is_multisite() ) {
				$is_user_logged_in_and_blog_user = is_user_logged_in() && is_user_member_of_blog( get_current_user_id() );
			} else {
				$is_user_logged_in_and_blog_user = is_user_logged_in();
			}
			return $is_user_logged_in_and_blog_user;
		}

		/**
		 * Helper function to determine whether a given username is in one of
		 * the lists (pending, approved, blocked). Defaults to the list of
		 * approved users.
		 */
		function is_username_in_list($username = '', $list = 'approved') {
			if ( empty( $username ) )
				return false;

			$auth_settings = get_option( 'auth_settings' );

			switch ( $list ) {
				case 'pending':
					return $this->in_multi_array( $username, $auth_settings['access_users_pending'] );
					break;
				case 'blocked':
					return $this->in_multi_array( $username, $auth_settings['access_users_blocked'] );
					break;
				case 'approved':
				default:
					return $this->in_multi_array( $username, $auth_settings['access_users_approved'] );
					break;
			}
		}

		/**
		 * Helper function to search a multidimensional array for a value.
		 */
		function in_multi_array( $needle = '', $haystack = array(), $strict = false, $case_sensitive = false ) {
			if ( ! is_array( $haystack ) ) {
				return false;
			}
			if ( ! $case_sensitive ) {
				$needle = strtolower( $needle );
			}
			foreach ( $haystack as $item ) {
				if ( ! $case_sensitive && ! is_array( $item ) ) {
					$item = strtolower( $item );
				}
				if ( ( $strict ? $item === $needle : $item == $needle ) || ( is_array( $item ) && $this->in_multi_array( $needle, $item, $strict, $case_sensitive ) ) ) {
					return true;
				}
			}
			return false;
		}

		// Helper function to get a WordPress page ID from the pagename.
		function get_id_from_pagename( $pagename = '' ) {
			global $wpdb;
			$page_id = $wpdb->get_var("SELECT ID FROM $wpdb->posts WHERE post_name = '" . sanitize_title_for_query( $pagename ) . "'");
			return $page_id;
		}

		// Helper function to determine if a URL is accessible.
		function url_is_accessible( $url ) {
			// Use curl to retrieve the URL.
			$handle = curl_init( $url );
			curl_setopt( $handle,  CURLOPT_RETURNTRANSFER, TRUE );
			$response = curl_exec( $handle );
			$httpCode = curl_getinfo( $handle, CURLINFO_HTTP_CODE );
			curl_close( $handle );

			// Return true if the document has loaded successfully without any redirection or error
			return $httpCode >= 200 && $httpCode < 400;
		}

		// Helper function that builds option tags for a select element for all
		// roles the current user has permission to assign.
		function wp_dropdown_permitted_roles( $selected_role = 'subscriber', $is_current_user = false ) {
			$roles = get_editable_roles();
			$current_user = wp_get_current_user();
			$next_level = 'level_' . ( $current_user->user_level + 1 );

			// Remove unpermitted roles from the roles array.
			foreach ($roles as $name => $role) {
				if ( isset( $role['capabilities'][$next_level] ) ) {
					unset( $roles[$name] );
				}
			}

			// If the specified $selected_role is not permitted, the select
			// element will be readonly/disabled.
			if ( ! array_key_exists( $selected_role, $roles ) ) {
				?><option value="<?php print $selected_role; ?>" disabled="disabled"><?php print ucfirst( $selected_role ); ?></option><?php
				return;
			}

			// Print an option element for each permitted role.
			foreach ($roles as $name => $role) {
				$selected = $selected_role == $name ? ' selected="selected"' : '';
				$disabled = $is_current_user ? ' disabled="disabled"' : ''; // Don't let a user change their own role
				?><option value="<?php print $name; ?>"<?= $selected . $disabled; ?>><?php print $role['name']; ?></option><?php
			}
		}

		// Helper function to get a single user info array from one of the
		// access control lists (pending, approved, or blocked).
		// Returns: false if not found; otherwise
		// 	array( 'username' => '', 'email' => '', 'role' => '', 'date_added' => '');
		function get_user_info_from_list( $username, $list ) {
			foreach ( $list as $user_info ) {
				if ( $user_info['username'] === $username ) {
					return $user_info;
				}
			}
			return false;
		}

		// Helper function to convert seconds to human readable text.
		// Source: http://csl.name/php-secs-to-human-text/
		function seconds_as_sentence($secs) {
			$units = array(
				"week"   => 7*24*3600,
				"day"    =>   24*3600,
				"hour"   =>      3600,
				"minute" =>        60,
				"second" =>         1,
			);

			// specifically handle zero
			if ( $secs == 0 ) return "0 seconds";

			$s = "";

			foreach ( $units as $name => $divisor ) {
				if ( $quot = intval($secs / $divisor) ) {
					$s .= "$quot $name";
					$s .= (abs($quot) > 1 ? "s" : "") . ", ";
					$secs -= $quot * $divisor;
				}
			}

			return substr($s, 0, -2);
		}

	} // END class WP_Plugin_Authorizer
}

// Instantiate the plugin class.
$wp_plugin_authorizer = new WP_Plugin_Authorizer();
