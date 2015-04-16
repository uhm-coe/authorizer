<?php
/*
Plugin Name: Authorizer
Plugin URI: https://github.com/figureone/authorizer
Description: Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., Google, LDAP, or CAS).
Version: 2.2.3
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
	require_once dirname(__FILE__) . '/inc/CAS-1.3.3/CAS.php';
}

// Add Google API PHP Client if it's not included.
// @see https://github.com/google/google-api-php-client
if ( ! class_exists( 'Google_Client' ) ) {
	set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/inc/google-api-php-client/src' );
	require_once dirname(__FILE__) . '/inc/google-api-php-client/src/Google/Client.php';
}

if ( ! class_exists( 'WP_Plugin_Authorizer' ) ) {
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
			add_filter( 'network_admin_plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'network_admin_plugin_settings_link' ) );

			// Modify login page with a custom password url (if option is set).
			add_filter( 'lostpassword_url', array( $this, 'custom_lostpassword_url' ) );

			// If we have a custom login error, add the filter to show it.
			$error = get_option( 'auth_settings_advanced_login_error' );
			if ( $error && strlen( $error ) > 0 ) {
				add_filter( 'login_errors', array( $this, 'show_advanced_login_error' ) );
			}

			// Register actions.

			// Perform plugin updates if newer version installed.
			add_action( 'plugins_loaded', array( $this, 'auth_update_check' ) );

			// Update the user meta with this user's failed login attempt.
			add_action( 'wp_login_failed', array( $this, 'update_login_failed_count' ) );

			// Create menu item in Settings
			add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );

			// Create options page
			add_action( 'admin_init', array( $this, 'page_init' ) );

			// Update user role in approved list if it's changed in the WordPress edit user page.
			add_action( 'edit_user_profile_update', array( $this, 'edit_user_profile_update_role' ) );

			// Enqueue javascript and css on the plugin's options page, the
			// dashboard (for the widget), and the network admin.
			add_action( 'load-settings_page_authorizer', array( $this, 'load_options_page' ) );
			add_action( 'admin_head-index.php', array( $this, 'load_options_page' ) );
			add_action( 'load-toplevel_page_authorizer', array( $this, 'load_options_page' ) );

			// Add custom css and js to wp-login.php
			add_action( 'login_enqueue_scripts', array( $this, 'login_enqueue_scripts_and_styles' ) );
			add_action( 'login_footer', array( $this, 'load_login_footer_js' ) );

			// Modify login page with external auth links (if enabled; e.g., google or cas)
			add_action( 'login_form', array( $this, 'login_form_add_external_service_links' ) );

			// Verify current user has access to page they are visiting
			add_action( 'parse_request', array( $this, 'restrict_access' ), 1 );

			// ajax save options from dashboard widget
			add_action( 'wp_ajax_update_auth_user', array( $this, 'ajax_update_auth_user' ) );

			// ajax save options from multisite options page
			add_action( 'wp_ajax_save_auth_multisite_settings', array( $this, 'ajax_save_auth_multisite_settings' ) );

			// ajax save usermeta from options page
			add_action( 'wp_ajax_update_auth_usermeta', array( $this, 'ajax_update_auth_usermeta' ) );

			// ajax verify google login
			add_action( 'wp_ajax_process_google_login', array( $this, 'ajax_process_google_login' ) );
			add_action( 'wp_ajax_nopriv_process_google_login', array( $this, 'ajax_process_google_login' ) );

			// Add dashboard widget so instructors can add/edit users with access.
			// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
			add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widgets' ) );

			// If we have a custom admin message, add the action to show it.
			$notice = get_option( 'auth_settings_advanced_admin_notice' );
			if ( $notice && strlen( $notice ) > 0 ) {
				add_action( 'admin_notices', array( $this, 'show_advanced_admin_notice' ) );
				add_action( 'network_admin_notices', array( $this, 'show_advanced_admin_notice' ) );
			}

			// Load custom javascript for the main site (e.g., for displaying alerts).
			add_action( 'wp_enqueue_scripts', array( $this, 'auth_public_scripts' ), 20 );

			// If multisite, add network admin options page (global settings for all sites)
			if ( is_multisite() ) {
				add_action( 'network_admin_menu', array( $this, 'network_admin_menu' ) );
			}

			// Create login cookie (used by google login)
			if ( ! isset( $_COOKIE['login_unique'] ) ) {
				setcookie( 'login_unique', $this->get_cookie_value(), time()+1800, '/', defined( COOKIE_DOMAIN ) ? COOKIE_DOMAIN : '' );
			}

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
			if ( is_multisite() && isset( $_GET['networkwide'] ) && $_GET['networkwide'] == 1 ) {
				$old_blog = $wpdb->blogid;
				// Get all blog ids
				$blogs = wp_get_sites( array( 'limit' => 999999 ) );
				foreach ( $blogs as $blog ) {
					switch_to_blog( $blog['blog_id'] );
					// Set meaningful defaults for other sites in the network.
					$this->set_default_options();
					// Add current WordPress users to the approved list.
					$this->add_wp_users_to_approved_list();
				}
				switch_to_blog( $old_blog );
			} else {
				// Set meaningful defaults for this site.
				$this->set_default_options();
				// Add current WordPress users to the approved list.
				$this->add_wp_users_to_approved_list();
			}

		} // END activate()

		/**
		 * Adds all WordPress users in the current site to the approved list,
		 * unless they are already in the blocked list. Also removes them
		 * from the pending list if they are there.
		 *
		 * Runs in plugin activation hook.
		 *
		 * @return void
		 */
		private function add_wp_users_to_approved_list() {
			// Add current WordPress users to the approved list.
			$auth_multisite_settings_access_users_approved = is_multisite() ? get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved', array() ) : array();
			$auth_settings_access_users_pending = $this->get_plugin_option( 'access_users_pending', 'single admin' );
			$auth_settings_access_users_approved = $this->get_plugin_option( 'access_users_approved', 'single admin' );
			$auth_settings_access_users_blocked = $this->get_plugin_option( 'access_users_blocked', 'single admin' );
			$default_role = $this->get_plugin_option( 'access_default_role', 'single admin', 'allow override' );
			$updated = false;
			foreach ( get_users() as $user ) {
				// Skip if user is in blocked list.
				if ( $this->in_multi_array( $user->user_email, $auth_settings_access_users_blocked ) ) {
					continue;
				}
				// Skip if user is in multisite approved list.
				if ( $this->in_multi_array( $user->user_email, $auth_multisite_settings_access_users_approved ) ) {
					continue;
				}
				// Add to approved list if not there.
				if ( ! $this->in_multi_array( $user->user_email, $auth_settings_access_users_approved ) ) {
					$approved_user = array(
						'email' => $user->user_email,
						'role' => count( $user->roles ) > 0 ? $user->roles[0] : $default_role,
						'date_added' => date( 'M Y', strtotime( $user->user_registered ) ),
						'local_user' => true,
					);
					array_push( $auth_settings_access_users_approved, $approved_user );
					$updated = true;
				}
				// Remove from pending list if there.
				foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
					if ( $pending_user['email'] == $user->user_email ) {
						unset( $auth_settings_access_users_pending[$key] );
						$updated = true;
					}
				}
			}
			if ( $updated ) {
				update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}
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

			// If username and password are blank, this isn't a log in attempt
			$is_login_attempt = strlen( $username ) > 0 && strlen( $password ) > 0;

			// Check to make sure that $username is not locked out due to too
			// many invalid login attempts. If it is, tell the user how much
			// time remains until they can try again.
			$unauthenticated_user = $is_login_attempt ? get_user_by( 'login', $username ) : false;
			$unauthenticated_user_is_blocked = false;
			if ( $is_login_attempt && $unauthenticated_user !== false ) {
				$last_attempt = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_time_last_failed', true );
				$num_attempts = get_user_meta( $unauthenticated_user->ID, 'auth_settings_advanced_lockouts_failed_attempts', true );
				// Also check the auth_blocked user_meta flag (users in blocked list will get this flag)
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
				return new WP_Error( 'empty_password', __( '<strong>ERROR</strong>: Incorrect username or password.' ) );
			}

			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			// Make sure $last_attempt (time) and $num_attempts are positive integers.
			// Note: this addresses resetting them if either is unset from above.
			$last_attempt = abs( intval( $last_attempt ) );
			$num_attempts = abs( intval( $num_attempts ) );

			// Create semantic lockout variables.
			$lockouts = $auth_settings['advanced_lockouts'];
			$time_since_last_fail = time() - $last_attempt;
			$reset_duration = $lockouts['reset_duration'] * 60; // minutes to seconds
			$num_attempts_long_lockout = $lockouts['attempts_1'] + $lockouts['attempts_2'];
			$num_attempts_short_lockout = $lockouts['attempts_1'];
			$seconds_remaining_long_lockout = $lockouts['duration_2'] * 60 - $time_since_last_fail;
			$seconds_remaining_short_lockout = $lockouts['duration_1'] * 60 - $time_since_last_fail;

			// Check if we need to institute a lockout delay
			if ( $is_login_attempt && $time_since_last_fail > $reset_duration ) {
				// Enough time has passed since the last invalid attempt and
				// now that we can reset the failed attempt count, and let this
				// login attempt go through.
				$num_attempts = 0; // This does nothing, but include it for semantic meaning.
			} else if ( $is_login_attempt && $num_attempts > $num_attempts_long_lockout && $seconds_remaining_long_lockout > 0 ) {
				// Stronger lockout (1st/2nd round of invalid attempts reached)
				// Note: set the error code to 'empty_password' so it doesn't
				// trigger the wp_login_failed hook, which would continue to
				// increment the failed attempt count.
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error( 'empty_password', sprintf( __( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?' ), $username, $seconds_remaining_long_lockout, $this->seconds_as_sentence( $seconds_remaining_long_lockout ), wp_lostpassword_url() ) );
			} else if ( $is_login_attempt && $num_attempts > $num_attempts_short_lockout && $seconds_remaining_short_lockout > 0 ) {
				// Normal lockout (1st round of invalid attempts reached)
				// Note: set the error code to 'empty_password' so it doesn't
				// trigger the wp_login_failed hook, which would continue to
				// increment the failed attempt count.
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				return new WP_Error( 'empty_password', sprintf( __( '<strong>ERROR</strong>: There have been too many invalid login attempts for the username <strong>%1$s</strong>. Please wait <strong id="seconds_remaining" data-seconds="%2$s">%3$s</strong> before trying again. <a href="%4$s" title="Password Lost and Found">Lost your password</a>?' ), $username, $seconds_remaining_short_lockout, $this->seconds_as_sentence( $seconds_remaining_short_lockout ), wp_lostpassword_url() ) );
			}

			// Start external authentication.
			$externally_authenticated_email = '';
			$authenticated_by = '';

			// Try Google authentication if it's enabled and we don't have a
			// successful login yet.
			if ( $auth_settings['google'] === '1' ) {
				$result = $this->custom_authenticate_google( $auth_settings );
				if ( ! is_wp_error( $result ) ) {
					$externally_authenticated_email = $result['email'];
					$authenticated_by = $result['authenticated_by'];
				}
			}

			// Try CAS authentication if it's enabled and we don't have a
			// successful login yet.
			if ( $auth_settings['cas'] === '1' && strlen ( $externally_authenticated_email ) === 0 ) {
				$result = $this->custom_authenticate_cas( $auth_settings );
				if ( ! is_wp_error( $result ) ) {
					$externally_authenticated_email = $result['email'];
					$authenticated_by = $result['authenticated_by'];
				}
			}

			// Try LDAP authentication if it's enabled and we don't have an
			// authenticated user yet.
			if ( $auth_settings['ldap'] === '1' && strlen ( $externally_authenticated_email ) === 0 ) {
				$result = $this->custom_authenticate_ldap( $auth_settings, $username, $password );
				if ( ! is_wp_error( $result ) ) {
					$externally_authenticated_email = $result['email'];
					$authenticated_by = $result['authenticated_by'];
				}
			}

			// Skip to WordPress authentication if we don't have an externally
			// authenticated user.
			if ( strlen( $externally_authenticated_email ) < 1 ) {
				return null;
			}

			// If we've made it this far, we should have an externally
			// authenticated user. The following should be set:
			//   $externally_authenticated_email
			//   $authenticated_by

			// Get the external user's WordPress account by email address.
			$user = get_user_by( 'email', $externally_authenticated_email );

			// Check this external user's access against the access lists
			// (pending, approved, blocked)
			$result = $this->check_user_access( $user, $externally_authenticated_email );

			// Fail with message if error.
			if ( is_wp_error( $result ) ) {
				return $result;
			}

			// If we created a new user in check_user_access(), log that user in.
			if ( get_class( $result ) === 'WP_User' ) {
				$user = $result;
			}

			// We'll track how this user was authenticated in user meta.
			if ( $user ) {
				update_user_meta( $user->ID, 'authenticated_by', $authenticated_by );
			}

			// If we haven't exited yet, we have a valid/approved user, so authenticate them.
			return $user;
		} // END custom_authenticate()


		/**
		 * This function will fail with a wp_die() message to the user if they
		 * don't have access.
		 * @param  WP_User $user       User to check
		 * @param  [type] $user_email  User's plaintext email (in case current user doesn't have a WP account)
		 * @return  WP_Error if there was an error on user creation / adding user to blog
		 * 			wp_die() if user does not have access
		 * 			null if user has access (success)
		 */
		private function check_user_access( $user, $user_email ) {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );
			$auth_settings_access_users_pending = $this->sanitize_user_list(
				$this->get_plugin_option( 'access_users_pending', 'single admin' )
			);
			$auth_settings_access_users_approved = $this->sanitize_user_list(
				array_merge(
					$this->get_plugin_option( 'access_users_approved', 'single admin' ),
					$this->get_plugin_option( 'access_users_approved', 'multisite admin' )
				)
			);

			// Check our externally authenticated user against the block list.
			// If they are blocked, set the relevant user meta field, and show
			// them an error screen.
			if ( $this->is_email_in_list( $user_email, 'blocked' ) ) {
				// If the blocked external user has a WordPress account, change
				// its password and mark it as blocked.
				if ( $user ) {
					// Mark user as blocked (enforce block in this->authenticate()).
					update_user_meta( $user->ID, 'auth_blocked', 'yes' );
				}

				// Notify user about blocked status and return without authenticating them.
				$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : home_url();
				$page_title = get_bloginfo( 'name' ) . ' - Access Restricted';
				$error_message = apply_filters( 'the_content', $auth_settings['access_blocked_redirect_to_message'] );
				$error_message .= '<hr /><p style="text-align: center;"><a class="button" href="' . wp_logout_url( $redirect_to ) . '">Back</a></p>';
				update_option( 'auth_settings_advanced_login_error', $error_message );
				wp_die( $error_message, $page_title );
			}

			// If this externally authenticated user isn't in the approved list
			// and login access is set to "All authenticated users," add them
			// to the approved list (they'll get an account created below if
			// they don't have one yet).
			if ( ! $this->is_email_in_list( $user_email, 'approved' ) && $auth_settings['access_who_can_login'] === 'external_users' ) {
				// If this user happens to be in the pending list (rare),
				// remove them from pending before adding them to approved.
				if ( $this->is_email_in_list( $user_email, 'pending' ) ) {
					foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
						if ( $pending_user['email'] === $user_email ) {
							unset( $auth_settings_access_users_pending[ $key ] );
							break;
						}
					}
				}

				// Add this user to the approved list.
				$approved_role = $user && is_array( $user->roles ) && count( $user->roles) > 0 ? $user->roles[0] : $auth_settings['access_default_role'];
				$approved_user = array(
					'email' => $user_email,
					'role' => $approved_role,
					'date_added' => date( "Y-m-d H:i:s" ),
				);
				array_push( $auth_settings_access_users_approved, $approved_user );
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}

			// Check our externally authenticated user against the approved
			// list. If they are approved, log them in (and create their account
			// if necessary)
			if ( $this->is_email_in_list( $user_email, 'approved' ) ) {
				$user_info = $this->get_user_info_from_list( $user_email, $auth_settings_access_users_approved );

				// If the approved external user does not have a WordPress account, create it
				if ( ! $user ) {
					// If there's already a user with this username (e.g.,
					// johndoe/johndoe@gmail.com exists, and we're trying to add
					// johndoe/johndoe@example.com), use the full email address
					// as the username.
					$username = explode( "@", $user_info['email'] );
					$username = $username[0];
					if ( get_user_by( 'login', $username ) !== false ) {
						$username = $approved_user['email'];
					}
					$result = wp_insert_user(
						array(
							'user_login' => strtolower( $username ),
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

				return $user;

			} else if ( $user && in_array( 'administrator', $user->roles ) ) {
				// User has a WordPress account, but is not in the blocked or approved
				// list. If they are an administrator, let them in.
				return;
			} else {
				// User isn't an admin, is not blocked, and is not approved.
				// Add them to the pending list and notify them and their instructor.
				if ( strlen( $user_email ) > 0 && ! $this->is_email_in_list( $user_email, 'pending' ) ) {
					$pending_user = array();
					$pending_user['email'] = $user_email;
					$pending_user['role'] = $auth_settings['access_default_role'];
					$pending_user['date_added'] = '';
					array_push( $auth_settings_access_users_pending, $pending_user );
					update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );

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
				$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : home_url();
				$page_title = get_bloginfo( 'name' ) . ' - Access Pending';
				$error_message = apply_filters( 'the_content', $auth_settings['access_pending_redirect_to_message'] );
				$error_message .= '<hr /><p style="text-align: center;"><a class="button" href="' . wp_logout_url( $redirect_to ) . '">Back</a></p>';
				update_option( 'auth_settings_advanced_login_error', $error_message );
				wp_die( $error_message, $page_title );
			}

		} // END check_user_access()


		/**
		 * Verify the Google login and set a session token.
		 *
		 * Flow: "Sign in with Google" button clicked; JS Google library
		 * called; JS function signInCallback() fired with results from Google;
		 * signInCallback() posts code and nonce (via AJAX) to this function;
		 * This function checks the token using the Google PHP library, and
		 * saves it to a session variable if it's authentic; control passes
		 * back to signInCallback(), which will reload the current page
		 * (wp-login.php) on success; wp-login.php reloads; custom_authenticate
		 * hooked into authenticate action fires again, and
		 * custom_authenticate_google() runs to verify the token; once verified
		 * custom_authenticate proceeds as normal with the google email address
		 * as a successfully authenticated external user.
		 *
		 * @return void, but die with the value to return to the success() function in AJAX call signInCallback()
		 */
		function ajax_process_google_login() {
			$nonce = array_key_exists( 'nonce', $_POST ) ? $_POST['nonce'] : '';
			$code = array_key_exists( 'code', $_POST ) ? $_POST['code'] : null;

			// Nonce check.
			if ( ! wp_verify_nonce( $nonce, 'google_csrf_nonce' ) ) {
				return '';
			}

			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			// Build the Google Client.
			$client = new Google_Client();
			$client->setApplicationName( 'WordPress' );
			$client->setClientId( $auth_settings['google_clientid'] );
			$client->setClientSecret( $auth_settings['google_clientsecret'] );
			$client->setRedirectUri( 'postmessage' );

			// Get one time use token (if it doesn't exist, we'll create one below)
			session_start();
			$token = array_key_exists( 'token', $_SESSION ) ? json_decode( $_SESSION['token'] ) : null;

			if ( empty( $token ) ) {
				// Exchange the OAuth 2.0 authorization code for user credentials.
				$client->authenticate( $code );
				$token = json_decode( $client->getAccessToken() );

				// Store the token in the session for later use.
				$_SESSION['token'] = json_encode( $token );

				$response = "Successfully authenticated.";
			} else {
				$client->setAccessToken( json_encode( $token ) );

				$response = 'Already authenticated.';
			}

			die( $response );
		} // END ajax_process_google_login()


		/**
		 * Validate this user's credentials against Google.
		 * @param  array $auth_settings Plugin settings
		 * @return [mixed] Array containing 'email' and 'authenticated_by'
		 *                       strings for the successfully authenticated
		 *                       user, or WP_Error() object on failure.
		 */
		private function custom_authenticate_google( $auth_settings ) {
			// Get one time use token
			session_start();
			$token = array_key_exists( 'token', $_SESSION ) ? json_decode( $_SESSION['token'] ) : null;

			// No token, so this is not a succesful Google login.
			if ( is_null( $token ) ) {
				return new WP_Error( 'no_google_login', 'No Google credentials provided.' );
			}

			// Build the Google Client.
			$client = new Google_Client();
			$client->setApplicationName( 'WordPress' );
			$client->setClientId( $auth_settings['google_clientid'] );
			$client->setClientSecret( $auth_settings['google_clientsecret'] );
			$client->setRedirectUri( 'postmessage' );

			// Verify this is a successful Google authentication
			$ticket = $client->verifyIdToken( $token->id_token, $auth_settings['google_clientid'] );

			// Invalid ticket, so this in not a successful Google login.
			if ( ! $ticket ) {
				return new WP_Error( 'invalid_google_login', 'Invalid Google credentials provided.' );
			}

			// Get email address
			$attributes = $ticket->getAttributes();
			$email = $attributes['payload']['email'];

			return array(
				'email' => $email,
				'authenticated_by' => 'google',
			);
		} // END custom_authenticate_google()


		/**
		 * Validate this user's credentials against CAS.
		 * @param  array $auth_settings Plugin settings
		 * @return [mixed] Array containing 'email' and 'authenticated_by'
		 *                       strings for the successfully authenticated
		 *                       user, or WP_Error() object on failure.
		 */
		private function custom_authenticate_cas( $auth_settings ) {
			// Move on if CAS hasn't been requested here.
			if ( empty( $_GET['external'] ) || $_GET['external'] !== 'cas' ) {
				return new WP_Error( 'cas_not_available', 'CAS is not enabled.' );
			}

			// Set the CAS client configuration
			phpCAS::client( SAML_VERSION_1_1, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'] );

			// Update server certificate bundle if it doesn't exist or is older
			// than 3 months, then use it to ensure CAS server is legitimate.
			$cacert_path = plugin_dir_path( __FILE__ ) . 'inc/cacert.pem';
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
			// For example: example.edu is the TLD for authn.example.edu, so user
			// 'bob' will have the following email address: bob@example.edu.
			$tld = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['cas_host'], $matches ) === 1 ? $matches[0] : '';

			// Get username that successfully authenticated against the external service (CAS).
			$externally_authenticated_email = strtolower( phpCAS::getUser() ) . '@' . $tld;

			// We'll track how this user was authenticated in user meta.
			$authenticated_by = 'cas';

			return array(
				'email' => $externally_authenticated_email,
				'authenticated_by' => $authenticated_by,
			);
		} // END custom_authenticate_cas()


		/**
		 * Validate this user's credentials against LDAP.
		 * @param  array $auth_settings  Plugin settings
		 * @param  string $username      Attempted username from authenticate action
		 * @param  string $password      Attempted password from authenticate action
		 * @return [mixed] Array containing 'email' and 'authenticated_by'
		 *                       strings for the successfully authenticated
		 *                       user, or WP_Error() object on failure.
		 */
		private function custom_authenticate_ldap( $auth_settings, $username, $password ) {
			// Get the TLD from the LDAP host for use in matching email addresses
			// For example: example.edu is the TLD for ldap.example.edu, so user
			// 'bob' will have the following email address: bob@example.edu.
			$tld = preg_match( '/[^.]*\.[^.]*$/', $auth_settings['ldap_host'], $matches ) === 1 ? $matches[0] : '';

			// remove top level domain if it exists in the username (i.e., if user entered their email)
			$username = str_replace( '@' . $tld, '', $username );

			// Fail with error message if username or password is blank.
			if ( empty( $username ) ) {
				return null;
			}
			if ( empty( $password ) ) {
				return new WP_Error( 'empty_password', 'You must provide a password.' );
			}

			// Make sure php5-ldap extension is installed on server.
			if ( ! function_exists( 'ldap_connect' ) ) {
				// Note: this error message won't get shown to the user because
				// authenticate will fall back to WP auth when this fails.
				return new WP_Error( 'ldap_not_installed', 'LDAP logins are disabled because this server does not support them.');
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
			if ( ! $result ) {
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
			if ( ! $result ) {
				// We have a real ldap user, but an invalid password. Pass
				// through to wp authentication after failing LDAP (since
				// this could be a local account that happens to be the
				// same name as an LDAP user).
				return new WP_Error( 'using_wp_authentication', 'Moving on to WordPress authentication...' );
			}

			// User successfully authenticated against LDAP, so set the relevant variables.
			$externally_authenticated_email = $username . '@' . $tld;

			// We'll track how this user was authenticated in user meta.
			$authenticated_by = 'ldap';

			return array(
				'email' => $externally_authenticated_email,
				'authenticated_by' => 'ldap',
			);
		} // END custom_authenticate_ldap()


		/**
		 * Log out of the attached external service.
		 *
		 * @return void
		 */
		public function custom_logout() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			// Reset option containing old error messages.
			delete_option( 'auth_settings_advanced_login_error' );

			if ( session_id() == '' ) {
				session_start();
			}

			// If logged in to CAS, Log out of CAS.
			if ( ! array_key_exists( 'PHPCAS_CLIENT', $GLOBALS ) || ! array_key_exists( 'phpCAS', $_SESSION ) ) {
				// Set the CAS client configuration if it hasn't been set already.
				phpCAS::client( SAML_VERSION_1_1, $auth_settings['cas_host'], intval( $auth_settings['cas_port'] ), $auth_settings['cas_path'] );
				// Restrict logout request origin to the CAS server only (prevent DDOS).
				phpCAS::handleLogoutRequests( true, array( $auth_settings['cas_host'] ) );
			}
			if ( phpCAS::isAuthenticated() ) {
				phpCAS::logoutWithRedirectService( get_option( 'siteurl' ) );
			}

			// If session token set, log out of Google.
			if ( array_key_exists( 'token', $_SESSION ) ) {
				$token = json_decode( $_SESSION['token'] )->access_token;

				// Build the Google Client.
				$client = new Google_Client();
				$client->setApplicationName( 'WordPress' );
				$client->setClientId( $auth_settings['google_clientid'] );
				$client->setClientSecret( $auth_settings['google_clientsecret'] );
				$client->setRedirectUri( 'postmessage' );

				// Revoke the token
				$client->revokeToken( $token );

				// Remove the credentials from the user's session.
				$_SESSION['token'] = '';
			}

		} // END custom_logout()



		/**
		 ****************************
		 * Access Restriction
		 ****************************
		 */



		/**
		 * Restrict access to WordPress site based on settings (everyone, logged_in_users).
		 * Hook: parse_request http://codex.wordpress.org/Plugin_API/Action_Reference/parse_request
		 *
		 * @param array $wp WordPress object.
		 *
		 * @return void
		 */
		public function restrict_access( $wp ) {
			remove_action( 'parse_request', array( $this, 'restrict_access' ), 1 );	// only need it the first time

			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			$has_access = (
				// Always allow access if WordPress is installing
				( defined( 'WP_INSTALLING' ) && isset( $_GET['key'] ) ) ||
				// Always allow access to admins
				( is_admin() ) ||
				// Allow access if option is set to 'everyone'
				( $auth_settings['access_who_can_view'] == 'everyone' ) ||
				// Allow access to approved external users and logged in users if option is set to 'logged_in_users'
				( $auth_settings['access_who_can_view'] == 'logged_in_users' && $this->is_user_logged_in_and_blog_user() )
			);

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
				update_option( 'auth_settings_advanced_public_notice', false );

				// We've determined that the current user has access, so simply return to grant access.
				return;
			}

			// We've determined that the current user doesn't have access, so we deal with them now.

			// Fringe case: In a multisite, a user of a different blog can
			// successfully log in, but they aren't on the 'approved' whitelist
			// for this blog. Flag these users, and redirect them to their
			// profile page with a message (so we don't get into a redirect
			// loop on the wp-login.php page).
			if ( is_multisite() && is_user_logged_in() && ! $has_access ) {
				$current_user = wp_get_current_user();

				// Check user access; block if not, add them to pending list if open, let them through otherwise.
				$result = $this->check_user_access( $current_user, $current_user->user_email );
			}

			// Check to see if the requested page is public. If so, show it.
			$current_page_id = empty( $wp->request ) ? 'home' : $this->get_id_from_pagename( $wp->query_vars['pagename'] );
			if ( ! is_array( $auth_settings['access_public_pages'] ) ) {
				$auth_settings['access_public_pages'] = array();
			}
			if ( in_array( $current_page_id, $auth_settings['access_public_pages'] ) ) {
				if ( $auth_settings['access_public_warning'] === 'no_warning' ) {
					update_option( 'auth_settings_advanced_public_notice', false );
				} else {
					update_option( 'auth_settings_advanced_public_notice', true );
				}
				return;
			}

			$current_path = empty( $_SERVER['REQUEST_URI'] ) ? home_url() : $_SERVER['REQUEST_URI'];
			if ( $auth_settings['access_redirect'] === 'message' ) {
				$page_title = get_bloginfo( 'name' ) . ' - Access Restricted';
				$error_message = apply_filters( 'the_content', $auth_settings['access_redirect_to_message'] );
				$error_message .= '<hr /><p style="text-align:center;margin-bottom:-15px;"><a class="button" href="' . wp_login_url( $current_path ) . '">Log In</a></p>';
				wp_die( $error_message, $page_title );
			} else { // if ( $auth_settings['access_redirect'] === 'login' ) {
				wp_redirect( wp_login_url( $current_path ), 302 );
				exit;
			}

			// Sanity check: we should never get here
			wp_die( '<p>Access denied.</p>', 'Site Access Restricted' );
		} // END restrict_access()



		/**
		 ****************************
		 * Login page (wp-login.php)
		 ****************************
		 */



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
		} // END show_advance_login_error()


		/**
		 * Load external resources for the public-facing site.
		 */
		function auth_public_scripts() {
			// Load (and localize) public scripts
			$current_path = empty( $_SERVER['REQUEST_URI'] ) ? home_url() : $_SERVER['REQUEST_URI'];
			wp_enqueue_script( 'auth_public_scripts', plugins_url( '/js/authorizer-public.js', __FILE__ ) );
			$auth_localized = array(
				'wp_login_url' => wp_login_url( $current_path ),
				'public_warning' => get_option( 'auth_settings_advanced_public_notice' )
			);
			wp_localize_script( 'auth_public_scripts', 'auth', $auth_localized );
			//update_option( 'auth_settings_advanced_public_notice', false);

			// Load public css
			wp_register_style( 'authorizer-public-css', plugins_url( 'css/authorizer-public.css', __FILE__ ) );
			wp_enqueue_style( 'authorizer-public-css' );
		} // END auth_public_scripts()


		/**
		 * Enqueue JS scripts and CSS styles appearing on wp-login.php.
		 * @return void
		 */
		function login_enqueue_scripts_and_styles() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			// Enqueue scripts appearing on wp-login.php.
			wp_enqueue_script( 'auth_login_scripts', plugins_url( '/js/authorizer-login.js', __FILE__ ), array( 'jquery' ) );

			// Enqueue styles appearing on wp-login.php.
			wp_register_style( 'authorizer-login-css', plugins_url( '/css/authorizer-login.css', __FILE__ ) );
			wp_enqueue_style( 'authorizer-login-css' );

			/**
			 * Developers can use the `authorizer_add_branding_option` filter
			 * to add a radio button for "Custom WordPress login branding"
			 * under the "Advanced" tab in Authorizer options. Example:
			 *
			 * function my_authorizer_add_branding_option( $branding_options ) {
			 *   $new_branding_option = array(
			 *   	'value' => 'your_brand'
			 *   	'description' => 'Custom Your Brand Login Screen',
			 *   	'css_url' => 'http://url/to/your_brand.css',
			 *   	'js_url' => 'http://url/to/your_brand.js',
			 *   );
			 *   array_push( $branding_options, $new_branding_option );
			 *   return $branding_options;
			 * }
			 * add_filter( 'authorizer_add_branding_option', 'my_authorizer_add_branding_option' );
			 */
			$branding_options = array();
			$branding_options = apply_filters( 'authorizer_add_branding_option', $branding_options );
			foreach ( $branding_options as $branding_option ) {
				// Make sure the custom brands have the required values
				if ( ! ( is_array( $branding_option ) && array_key_exists( 'value', $branding_option ) && array_key_exists( 'css_url', $branding_option ) && array_key_exists( 'js_url', $branding_option ) ) ) {
					continue;
				}
				if ( $auth_settings['advanced_branding'] === $branding_option['value'] ) {
					wp_enqueue_script( 'auth_login_custom_scripts-' . sanitize_title( $branding_option['value'] ), $branding_option['js_url'], array( 'jquery' ) );
					wp_register_style( 'authorizer-login-custom-css-' . sanitize_title( $branding_option['value'] ), $branding_option['css_url'] );
					wp_enqueue_style( 'authorizer-login-custom-css-' . sanitize_title( $branding_option['value'] ) );
				}
			}

			// If we're using Google logins, load those resources.
			if ( $auth_settings['google'] === '1' ) {
				wp_enqueue_script( 'authorizer-login-custom-google', plugins_url( '/js/authorizer-login-custom_google.js', __FILE__ ), array( 'jquery' ) );
				?>
				<meta name="google-signin-clientid" content="<?php echo $auth_settings['google_clientid']; ?>" />
				<meta name="google-signin-scope" content="email" />
				<meta name="google-signin-cookiepolicy" content="single_host_origin" />
				<?php
			}
		} // END login_enqueue_scripts_and_styles()


		/**
		 * Load external resources in the footer of the wp-login.php page.
		 * Run on action hook: login_footer
		 */
		function load_login_footer_js() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			?>
			<?php if ( $auth_settings['google'] === '1' ): ?>
				<script type="text/javascript">
					// Reload login page if reauth querystring param exists,
					// since reauth interrupts external logins (e.g., google).
					if ( location.search.indexOf( 'reauth=1' ) >= 0 ) {
						location.href = location.href.replace( 'reauth=1', '' );
					}

					function signInCallback( authResult ) {
						var $ = jQuery;
						if ( authResult['status'] && authResult['status']['signed_in'] ) {
							// Hide the sign-in button now that the user is authorized, for example:
							$( '#googleplus_button' ).attr( 'style', 'display: none' );

							// Send the code to the server
							var ajaxurl = '<?php echo admin_url("admin-ajax.php"); ?>';
							$.post(ajaxurl, {
								action: 'process_google_login',
								'code': authResult['code'],
								'nonce': $('#nonce_google_auth-<?php echo $this->get_cookie_value(); ?>').val(),
							}, function( response ) {
								// Handle or verify the server response if necessary.
								//console.log( response );

								// Reload wp-login.php to continue the authentication process.
								location.reload();
							});
						} else {
							// Update the app to reflect a signed out user
							// Possible error values:
							//   "user_signed_out" - User is signed-out
							//   "access_denied" - User denied access to your app
							//   "immediate_failed" - Could not automatically log in the user
							//console.log('Sign-in state: ' + authResult['error']);
						}
					}
				</script>
			<?php endif; ?>

			<?php
		} // END load_login_footer_js()


		/**
		 * Create links for any external authentication services that are enabled.
		 */
		function login_form_add_external_service_links() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			$auth_url_cas = '';
			if ( $auth_settings['cas'] === '1' ) {
				$auth_url_cas = 'http' . ( isset( $_SERVER['HTTPS'] ) ? 's' : '' ) . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
				// Remove force reauth param if it exists so this
				// authentication attempt doesn't get stopped by WordPress.
				if ( strpos( $auth_url_cas, 'reauth=1' ) !== false ) {
					if ( strpos( $auth_url_cas, '&reauth=1' ) !== false ) {
						// There are parames before reauth, so just remove reauth
						$auth_url_cas = str_replace( '&reauth=1', '', $auth_url_cas );
					} else if ( strpos( $auth_url_cas, '?reauth=1&' ) !== false ) {
						// Reauth is first param with others behind it, so remove it and next delimiter.
						$auth_url_cas = str_replace( 'reauth=1&', '', $auth_url_cas );
					} else {
						// Reauth is first and only param, so remove it and '?'
						$auth_url_cas = str_replace( '?reauth=1', '', $auth_url_cas );
					}

				}
				// Add special param indicating this is CAS authentication attempt.
				if ( strpos( $auth_url_cas, 'external=cas' ) === false ) {
					$auth_url_cas .= strpos( $auth_url_cas, '?' ) !== false ? '&external=cas' : '?external=cas';
				}
			}

			?>
			<div id="auth-external-service-login">
				<?php if ( $auth_settings['google'] === '1' ): ?>
					<p><a id="googleplus_button" class="button button-primary button-external button-google"><span class="dashicons dashicons-googleplus"></span><span class="label">Sign in with Google</span></a></p>
					<?php wp_nonce_field( 'google_csrf_nonce', 'nonce_google_auth-' . $this->get_cookie_value() ); ?>
				<?php endif; ?>

				<?php if ( $auth_settings['cas'] === '1' ): ?>
					<p><a class="button button-primary button-external button-cas" href="<?php echo $auth_url_cas; ?>"><span class="dashicons dashicons-lock"></span><span class="label">Sign in with <?php echo $auth_settings['cas_custom_label']; ?></span></a></p>
				<?php endif; ?>

				<?php if ( $auth_settings['advanced_hide_wp_login'] === '1' && strpos( $_SERVER['QUERY_STRING'], 'external=wordpress' ) === false ): ?>
					<style type="text/css">
						#loginform {
							padding-bottom: 8px;
						}
						#loginform p>label, #loginform p.forgetmenot, #loginform p.submit, p#nav {
							display: none;
						}
					</style>
				<?php elseif ( $auth_settings['cas'] === '1' || $auth_settings['google'] === '1' ): ?>
					<h3> &mdash; or &mdash; </h3>
				<?php endif; ?>
			</div>
			<?php

		} // END login_form_add_external_service_links()


		/**
		 * Implements hook: do_action( 'wp_login_failed', $username );
		 * Update the user meta for the user that just failed logging in.
		 * Keep track of time of last failed attempt and number of failed attempts.
		 */
		function update_login_failed_count( $username ) {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

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
		} // END update_login_failed_count()

		/**
		 * Overwrite the URL for the lost password link on the login form.
		 * If we're authenticating against an external service, standard
		 * WordPress password resets won't work.
		 */
		function custom_lostpassword_url( $lostpassword_url ) {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			if (
				array_key_exists( 'ldap_lostpassword_url', $auth_settings ) &&
				filter_var( $auth_settings['ldap_lostpassword_url'], FILTER_VALIDATE_URL )
			) {
				$lostpassword_url = $auth_settings['ldap_lostpassword_url'];
			}
			return $lostpassword_url;
		} // END custom_lostpassword_url()



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
		 * Add a link to this plugin's network settings page from the WordPress Plugins page.
		 * Called from "network_admin_plugin_action_links" filter in __construct() above.
		 *
		 * @param array $links array of links in the network admin sidebar
		 *
		 * @return array of links to show in the network admin sidebar.
		 */
		public function network_admin_plugin_settings_link( $links ) {
			$settings_link = '<a href="admin.php?page=authorizer">Network Settings</a>';
			array_unshift( $links, $settings_link );
			return $links;
		} // END network_admin_plugin_settings_link()



		/**
		 * Create the options page under Dashboard > Settings
		 * Run on action hook: admin_menu
		 */
		public function add_plugin_page() {
			$admin_menu = $this->get_plugin_option( 'advanced_admin_menu' );
			if ( $admin_menu === 'settings' ) {
				// @see http://codex.wordpress.org/Function_Reference/add_options_page
				add_options_page(
					'Authorizer', // Page title
					'Authorizer', // Menu title
					'manage_options', // Capability
					'authorizer', // Menu slug
					array( $this, 'create_admin_page' ) // function
				);
			} else {
				// @see http://codex.wordpress.org/Function_Reference/add_menu_page
				add_menu_page(
					'Authorizer', // Page title
					'Authorizer', // Menu title
					'manage_options', // Capability
					'authorizer', // Menu slug
					array( $this, 'create_admin_page' ), // callback
					'dashicons-groups', // icon
					'99.0018465' // position (decimal is to make overlap with other plugins less likely)
				);
			}
		} // END add_plugin_page()


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
		} // END create_admin_page()



		/**
		 * Load external resources on this plugin's options page.
		 * Run on action hooks: load-settings_page_authorizer, load-toplevel_page_authorizer, admin_head-index.php
		 */
		public function load_options_page() {
			wp_enqueue_script(
				'authorizer',
				plugins_url( 'js/authorizer.js', __FILE__ ),
				array( 'jquery-effects-shake' ), '5.0', true
			);
			$js_auth_config = array( 'baseurl' => get_bloginfo( 'url' ) );
			wp_localize_script( 'authorizer', 'auth_config',  $js_auth_config );

			wp_enqueue_script(
				'jquery.multi-select',
				plugins_url( 'inc/jquery.multi-select/js/jquery.multi-select.js', __FILE__ ),
				array( 'jquery' ), '1.8', true
			);

			wp_register_style( 'authorizer-css', plugins_url( 'css/authorizer.css', __FILE__ ) );
			wp_enqueue_style( 'authorizer-css' );

			wp_register_style( 'jquery-multi-select-css', plugins_url( 'inc/jquery.multi-select/css/multi-select.css', __FILE__ ) );
			wp_enqueue_style( 'jquery-multi-select-css' );

			add_action( 'admin_notices', array( $this, 'admin_notices' ) ); // Add any notices to the top of the options page.
			add_action( 'admin_head', array( $this, 'admin_head' ) ); // Add help documentation to the options page.
		} // END load_options_page()



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
		} // END show_advanced_admin_notice()


		/**
		 * Add notices to the top of the options page.
		 * Run on action hook chain: load-settings_page_authorizer > admin_notices
		 * Description: Check for invalid settings combinations and show a warning message, e.g.:
		 *   if (cas url inaccessible) {
		 *     echo "<div class='updated settings-error'><p>Can't reach Sakai.</p></div>";
		 *   }
		 */
		public function admin_notices() {
			// Grab plugin settings.
			$auth_settings = $this->get_plugin_options( 'single admin', 'allow override' );

			if ( $auth_settings['cas'] === '1' ) {
				// Check if provided CAS URL is accessible.
				$protocol = $auth_settings['cas_port'] == '80' ? 'http' : 'https';
				if ( ! $this->url_is_accessible( $protocol . '://' . $auth_settings['cas_host'] . $auth_settings['cas_path'] ) ) {
					echo "<div class='updated settings-error'><p>Can't reach CAS server. Please provide <a href='javascript:choose_tab(\"external\");'>accurate CAS settings</a> if you intend to use it.</p></div>";
				}
			}
		} // END admin_notices()


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

			// Create Login Access section
			add_settings_section(
				'auth_settings_access_login', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_access_login' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_access_who_can_login', // HTML element ID
				'Who can log into the site?', // HTML element Title
				array( $this, 'print_radio_auth_access_who_can_login' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_role_receive_pending_emails', // HTML element ID
				'Which role should receive email notifications about pending users?', // HTML element Title
				array( $this, 'print_select_auth_access_role_receive_pending_emails' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_pending_redirect_to_message', // HTML element ID
				'What message should pending users see after attempting to log in?', // HTML element Title
				array( $this, 'print_wysiwyg_auth_access_pending_redirect_to_message' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_blocked_redirect_to_message', // HTML element ID
				'What message should blocked users see after attempting to log in?', // HTML element Title
				array( $this, 'print_wysiwyg_auth_access_blocked_redirect_to_message' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_should_email_approved_users', // HTML element ID
				'Send welcome email to new approved users?', // HTML element Title
				array( $this, 'print_checkbox_auth_access_should_email_approved_users' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_email_approved_users_subject', // HTML element ID
				'Welcome email subject', // HTML element Title
				array( $this, 'print_text_auth_access_email_approved_users_subject' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_email_approved_users_body', // HTML element ID
				'Welcome email body', // HTML element Title
				array( $this, 'print_wysiwyg_auth_access_email_approved_users_body' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_login' // Section this setting is shown on
			);


			// Create Public Access section
			add_settings_section(
				'auth_settings_access_public', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_access_public' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_access_who_can_view', // HTML element ID
				'Who can view the site?', // HTML element Title
				array( $this, 'print_radio_auth_access_who_can_view' ), // Callback (echos form element)
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
			add_settings_field(
				'auth_settings_access_redirect', // HTML element ID
				'What happens to people without access when they visit a private page?', // HTML element Title
				array( $this, 'print_radio_auth_access_redirect' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_access_public' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_access_public_warning', // HTML element ID
				'What happens to people without access when they visit a public page?', // HTML element Title
				array( $this, 'print_radio_auth_access_public_warning' ), // Callback (echos form element)
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

			// Create External Service Settings section
			add_settings_section(
				'auth_settings_external', // HTML element ID
				'', // HTML element Title
				array( $this, 'print_section_info_external' ), // Callback (echos section content)
				'authorizer' // Page this section is shown on (slug)
			);
			add_settings_field(
				'auth_settings_access_default_role', // HTML element ID
				'Default role for new users', // HTML element Title
				array( $this, 'print_select_auth_access_default_role' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_external_google', // HTML element ID
				'Google Logins', // HTML element Title
				array( $this, 'print_checkbox_auth_external_google' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_google_clientid', // HTML element ID
				'Google Client ID', // HTML element Title
				array( $this, 'print_text_google_clientid' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_google_clientsecret', // HTML element ID
				'Google Client Secret', // HTML element Title
				array( $this, 'print_text_google_clientsecret' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_external_cas', // HTML element ID
				'CAS Logins', // HTML element Title
				array( $this, 'print_checkbox_auth_external_cas' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_external' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_cas_custom_label', // HTML element ID
				'CAS custom label', // HTML element Title
				array( $this, 'print_text_cas_custom_label' ), // Callback (echos form element)
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
				'auth_settings_external_ldap', // HTML element ID
				'LDAP Logins', // HTML element Title
				array( $this, 'print_checkbox_auth_external_ldap' ), // Callback (echos form element)
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
			add_settings_field(
				'auth_settings_ldap_lostpassword_url', // HTML element ID
				'Custom lost password URL', // HTML element Title
				array( $this, 'print_text_ldap_lostpassword_url' ), // Callback (echos form element)
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
				'auth_settings_advanced_hide_wp_login', // HTML element ID
				'Hide WordPress Login', // HTML element Title
				array( $this, 'print_checkbox_auth_advanced_hide_wp_login' ), // Callback (echos form element)
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
			add_settings_field(
				'auth_settings_advanced_admin_menu', // HTML element ID
				'Authorizer admin menu item location', // HTML element Title
				array( $this, 'print_radio_auth_advanced_admin_menu' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_advanced' // Section this setting is shown on
			);
			add_settings_field(
				'auth_settings_advanced_usermeta', // HTML element ID
				'Show custom usermeta in user list', // HTML element Title
				array( $this, 'print_select_auth_advanced_usermeta' ), // Callback (echos form element)
				'authorizer', // Page this setting is shown on (slug)
				'auth_settings_advanced' // Section this setting is shown on
			);
		} // END page_init()


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
			$auth_settings_access_users_pending = get_option( 'auth_settings_access_users_pending' );
			if ( $auth_settings_access_users_pending === FALSE ) {
				$auth_settings_access_users_pending = array();
			}
			$auth_settings_access_users_approved = get_option( 'auth_settings_access_users_approved' );
			if ( $auth_settings_access_users_approved === FALSE ) {
				$auth_settings_access_users_approved = array();
			}
			$auth_settings_access_users_blocked = get_option( 'auth_settings_access_users_blocked' );
			if ( $auth_settings_access_users_blocked === FALSE ) {
				$auth_settings_access_users_blocked = array();
			}

			// Login Access Defaults.
			if ( ! array_key_exists( 'access_who_can_login', $auth_settings ) ) {
				$auth_settings['access_who_can_login'] = 'approved_users';
			}
			if ( ! array_key_exists( 'access_role_receive_pending_emails', $auth_settings ) ) {
				$auth_settings['access_role_receive_pending_emails'] = '---';
			}
			if ( ! array_key_exists( 'access_pending_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_pending_redirect_to_message'] = '<p>You\'re not currently allowed to view this site. Your administrator has been notified, and once he/she has approved your request, you will be able to log in. If you need any other help, please contact your administrator.</p>';
			}
			if ( ! array_key_exists( 'access_blocked_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_blocked_redirect_to_message'] = '<p>You\'re not currently allowed to log into this site. If you think this is a mistake, please contact your administrator.</p>';
			}
			if ( ! array_key_exists( 'access_should_email_approved_users', $auth_settings ) ) {
				$auth_settings['access_should_email_approved_users'] = '';
			}
			if ( ! array_key_exists( 'access_email_approved_users_subject', $auth_settings ) ) {
				$auth_settings['access_email_approved_users_subject'] = 'Welcome to [site_name]!';
			}
			if ( ! array_key_exists( 'access_email_approved_users_body', $auth_settings ) ) {
				$auth_settings['access_email_approved_users_body'] =
					'Hello [user_email],' . PHP_EOL .
					'Welcome to [site_name]! You now have access to all content on the site. Please visit us here:' . PHP_EOL .
					'[site_url]';
			}

			// Public Access to Private Page Defaults.
			if ( ! array_key_exists( 'access_who_can_view', $auth_settings ) ) {
				$auth_settings['access_who_can_view'] = 'everyone';
			}
			if ( ! array_key_exists( 'access_public_pages', $auth_settings ) ) {
				$auth_settings['access_public_pages'] = array();
			}
			if ( ! array_key_exists( 'access_redirect', $auth_settings ) ) {
				$auth_settings['access_redirect'] = 'login';
			}
			if ( ! array_key_exists( 'access_public_warning', $auth_settings ) ) {
				$auth_settings['access_public_warning'] = 'no_warning';
			}
			if ( ! array_key_exists( 'access_redirect_to_message', $auth_settings ) ) {
				$auth_settings['access_redirect_to_message'] = '<p><strong>Notice</strong>: You are browsing this site anonymously, and only have access to a portion of its content.</p>';
			}


			// External Service Defaults.
			if ( ! array_key_exists( 'access_default_role', $auth_settings ) ) {
				// Set default role to 'student' if that role exists, 'subscriber' otherwise.
				$all_roles = $wp_roles->roles;
				$editable_roles = apply_filters( 'editable_roles', $all_roles );
				if ( array_key_exists( 'student', $editable_roles ) ) {
					$auth_settings['access_default_role'] = 'student';
				} else {
					$auth_settings['access_default_role'] = 'subscriber';
				}
			}

			if ( ! array_key_exists( 'google', $auth_settings ) ) {
				$auth_settings['google'] = '';
			}
			if ( ! array_key_exists( 'cas', $auth_settings ) ) {
				$auth_settings['cas'] = '';
			}
			if ( ! array_key_exists( 'ldap', $auth_settings ) ) {
				$auth_settings['ldap'] = '';
			}

			if ( ! array_key_exists( 'google_clientid', $auth_settings ) ) {
				$auth_settings['google_clientid'] = '';
			}
			if ( ! array_key_exists( 'google_clientsecret', $auth_settings ) ) {
				$auth_settings['google_clientsecret'] = '';
			}

			if ( ! array_key_exists( 'cas_custom_label', $auth_settings ) ) {
				$auth_settings['cas_custom_label'] = 'CAS';
			}
			if ( ! array_key_exists( 'cas_host', $auth_settings ) ) {
				$auth_settings['cas_host'] = '';
			}
			if ( ! array_key_exists( 'cas_port', $auth_settings ) ) {
				$auth_settings['cas_port'] = '';
			}
			if ( ! array_key_exists( 'cas_path', $auth_settings ) ) {
				$auth_settings['cas_path'] = '';
			}

			if ( ! array_key_exists( 'ldap_host', $auth_settings ) ) {
				$auth_settings['ldap_host'] = '';
			}
			if ( ! array_key_exists( 'ldap_port', $auth_settings ) ) {
				$auth_settings['ldap_port'] = '';
			}
			if ( ! array_key_exists( 'ldap_search_base', $auth_settings ) ) {
				$auth_settings['ldap_search_base'] = '';
			}
			if ( ! array_key_exists( 'ldap_uid', $auth_settings ) ) {
				$auth_settings['ldap_uid'] = '';
			}
			if ( ! array_key_exists( 'ldap_user', $auth_settings ) ) {
				$auth_settings['ldap_user'] = '';
			}
			if ( ! array_key_exists( 'ldap_password', $auth_settings ) ) {
				$auth_settings['ldap_password'] = '';
			}
			if ( ! array_key_exists( 'ldap_tls', $auth_settings ) ) {
				$auth_settings['ldap_tls'] = '1';
			}
			if ( ! array_key_exists( 'ldap_lostpassword_url', $auth_settings ) ) {
				$auth_settings['ldap_lostpassword_url'] = '';
			}

			// Advanced defaults.
			if ( ! array_key_exists( 'advanced_lockouts', $auth_settings ) ) {
				$auth_settings['advanced_lockouts'] = array(
					'attempts_1' => 10,
					'duration_1' => 1,
					'attempts_2' => 10,
					'duration_2' => 10,
					'reset_duration' => 120,
				);
			}
			if ( ! array_key_exists( 'advanced_hide_wp_login', $auth_settings ) ) {
				$auth_settings['advanced_hide_wp_login'] = '';
			}
			if ( ! array_key_exists( 'advanced_branding', $auth_settings ) ) {
				$auth_settings['advanced_branding'] = 'default';
			}
			if ( ! array_key_exists( 'advanced_admin_menu', $auth_settings ) ) {
				$auth_settings['advanced_admin_menu'] = 'top';
			}
			if ( ! array_key_exists( 'advanced_usermeta', $auth_settings ) ) {
				$auth_settings['advanced_usermeta'] = '';
			}

			// Save default options to database.
			update_option( 'auth_settings', $auth_settings );
			update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
			update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );

			// Multisite defaults.
			if ( is_multisite() ) {
				$auth_multisite_settings = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', array() );

				if ( $auth_multisite_settings === FALSE ) {
					$auth_multisite_settings = array();
				}
				// Global switch for enabling multisite options.
				if ( ! array_key_exists( 'multisite_override', $auth_multisite_settings ) ) {
					$auth_multisite_settings['multisite_override'] = '';
				}
				// Access Lists Defaults.
				$auth_multisite_settings_access_users_approved = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved' );
				if ( $auth_multisite_settings_access_users_approved === FALSE ) {
					$auth_multisite_settings_access_users_approved = array();
				}
				// Login Access Defaults.
				if ( ! array_key_exists( 'access_who_can_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['access_who_can_login'] = 'approved_users';
				}
				// View Access Defaults.
				if ( ! array_key_exists( 'access_who_can_view', $auth_multisite_settings ) ) {
					$auth_multisite_settings['access_who_can_view'] = 'everyone';
				}
				// External Service Defaults.
				if ( ! array_key_exists( 'access_default_role', $auth_multisite_settings ) ) {
					// Set default role to 'student' if that role exists, 'subscriber' otherwise.
					$all_roles = $wp_roles->roles;
					$editable_roles = apply_filters( 'editable_roles', $all_roles );
					if ( array_key_exists( 'student', $editable_roles ) ) {
						$auth_multisite_settings['access_default_role'] = 'student';
					} else {
						$auth_multisite_settings['access_default_role'] = 'subscriber';
					}
				}
				if ( ! array_key_exists( 'google', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google'] = '';
				}
				if ( ! array_key_exists( 'cas', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas'] = '';
				}
				if ( ! array_key_exists( 'ldap', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap'] = '';
				}
				if ( ! array_key_exists( 'google_clientid', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google_clientid'] = '';
				}
				if ( ! array_key_exists( 'google_clientsecret', $auth_multisite_settings ) ) {
					$auth_multisite_settings['google_clientsecret'] = '';
				}
				if ( ! array_key_exists( 'cas_custom_label', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_custom_label'] = 'CAS';
				}
				if ( ! array_key_exists( 'cas_host', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_host'] = '';
				}
				if ( ! array_key_exists( 'cas_port', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_port'] = '';
				}
				if ( ! array_key_exists( 'cas_path', $auth_multisite_settings ) ) {
					$auth_multisite_settings['cas_path'] = '';
				}
				if ( ! array_key_exists( 'ldap_host', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_host'] = '';
				}
				if ( ! array_key_exists( 'ldap_port', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_port'] = '';
				}
				if ( ! array_key_exists( 'ldap_search_base', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_search_base'] = '';
				}
				if ( ! array_key_exists( 'ldap_uid', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_uid'] = '';
				}
				if ( ! array_key_exists( 'ldap_user', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_user'] = '';
				}
				if ( ! array_key_exists( 'ldap_password', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_password'] = '';
				}
				if ( ! array_key_exists( 'ldap_tls', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_tls'] = '1';
				}
				if ( ! array_key_exists( 'ldap_lostpassword_url', $auth_multisite_settings ) ) {
					$auth_multisite_settings['ldap_lostpassword_url'] = '';
				}
				// Advanced defaults.
				if ( ! array_key_exists( 'advanced_lockouts', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_lockouts'] = array(
						'attempts_1' => 10,
						'duration_1' => 1,
						'attempts_2' => 10,
						'duration_2' => 10,
						'reset_duration' => 120,
					);
				}
				if ( ! array_key_exists( 'advanced_hide_wp_login', $auth_multisite_settings ) ) {
					$auth_multisite_settings['advanced_hide_wp_login'] = '';
				}
				// Save default network options to database.
				update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', $auth_multisite_settings );
				update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
			}
		} // END set_default_options()


		/**
		 * List sanitizer.
		 * $side_effect = 'none' or 'update roles' to make sure WP user roles match
		 * $multisite_mode = 'single' or 'multisite' to indicate which user roles to change (this site or all sites)
		 */
		function sanitize_user_list( $list, $side_effect = 'none', $multisite_mode = 'single' ) {
			// If it's not a list, make it so.
			if ( ! is_array( $list ) ) {
				$list = array();
			}
			foreach ( $list as $key => $user_info ) {
				if ( strlen( $user_info['email'] ) < 1 ) {
					// Make sure there are no empty entries in the list
					unset( $list[$key] );
				} else if ( $side_effect === 'update roles' ) {
					// Make sure the WordPress user accounts have the same role
					// as that indicated in the list.
					$wp_user = get_user_by( 'email', $user_info['email'] );
					if ( $wp_user ) {
						if ( is_multisite() && $multisite_mode === 'multisite' ) {
							foreach ( get_blogs_of_user( $wp_user->ID ) as $blog ) {
								add_user_to_blog( $blog->userblog_id, $wp_user->ID, $user_info['role'] );
							}
						} else {
							$wp_user->set_role( $user_info['role'] );
						}
					}
				}
			}
			return $list;
		}

		/**
		 * Settings sanitizer callback
		 */
		function sanitize_options( $auth_settings, $multisite_mode = 'single' ) {
			// Default to "Approved Users" login access restriction.
			if ( ! in_array( $auth_settings['access_who_can_login'], array( 'external_users', 'approved_users' ) ) ) {
				$auth_settings['access_who_can_login'] = 'approved_users';
			}

			// Default to "Everyone" view access restriction.
			if ( ! in_array( $auth_settings['access_who_can_view'], array( 'everyone', 'logged_in_users' ) ) ) {
				$auth_settings['access_who_can_view'] = 'everyone';
			}

			// Default to WordPress login access redirect.
			if ( ! in_array( $auth_settings['access_redirect'], array( 'login', 'page', 'message' ) ) ) {
				$auth_settings['access_redirect'] = 'login';
			}

			// Default to warning message for anonymous users on public pages.
			if ( ! in_array( $auth_settings['access_public_warning'], array( 'no_warning', 'warning' ) ) ) {
				$auth_settings['access_public_warning'] = 'no_warning';
			}

			// Sanitize Enable Google Logins (checkbox: value can only be '1' or empty string)
			if ( array_key_exists( 'google', $auth_settings ) && strlen( $auth_settings['google'] ) > 0 ) {
				$auth_settings['google'] = '1';
			}

			// Sanitize Enable CAS Logins (checkbox: value can only be '1' or empty string)
			if ( array_key_exists( 'cas', $auth_settings ) && strlen( $auth_settings['cas'] ) > 0 ) {
				$auth_settings['cas'] = '1';
			}

			// Sanitize Enable LDAP Logins (checkbox: value can only be '1' or empty string)
			if ( array_key_exists( 'ldap', $auth_settings ) && strlen( $auth_settings['ldap'] ) > 0 ) {
				$auth_settings['ldap'] = '1';
			}

			// Sanitize CAS Host setting
			$auth_settings['cas_host'] = filter_var( $auth_settings['cas_host'], FILTER_SANITIZE_URL );

			// Sanitize CAS Port (int)
			$auth_settings['cas_port'] = filter_var( $auth_settings['cas_port'], FILTER_SANITIZE_NUMBER_INT );

			// Sanitize LDAP Host setting
			$auth_settings['ldap_host'] = filter_var( $auth_settings['ldap_host'], FILTER_SANITIZE_URL );

			// Sanitize LDAP Port (int)
			$auth_settings['ldap_port'] = filter_var( $auth_settings['ldap_port'], FILTER_SANITIZE_NUMBER_INT );

			// Sanitize LDAP attributes (basically make sure they don't have any parantheses)
			$auth_settings['ldap_uid'] = filter_var( $auth_settings['ldap_uid'], FILTER_SANITIZE_EMAIL );

			// Sanitize LDAP TLS (checkbox: value can only be '1' or empty string)
			if ( array_key_exists( 'ldap_tls', $auth_settings ) && strlen( $auth_settings['ldap_tls'] ) > 0 ) {
				$auth_settings['ldap_tls'] = '1';
			}

			// Sanitize LDAP Lost Password URL
			$auth_settings['ldap_lostpassword_url'] = filter_var( $auth_settings['ldap_lostpassword_url'], FILTER_SANITIZE_URL );

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

			// Sanitize Hide WordPress logins (checkbox: value can only be '1' or empty string)
			if ( array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && strlen( $auth_settings['advanced_hide_wp_login'] ) > 0 ) {
				$auth_settings['advanced_hide_wp_login'] = '1';
			}

			return $auth_settings;
		} // END sanitize_options()


		/**
		 * Keep authorizer approved users' roles in sync with WordPress roles
		 * if someone changes the role via the WordPress Edit User options page.
		 *
		 * @action edit_user_profile_update
		 * @ref https://codex.wordpress.org/Plugin_API/Action_Reference/edit_user_profile_update
		 * @param  int $user_id The user ID of the user being edited
		 */
		function edit_user_profile_update_role( $user_id ) {
			if ( ! current_user_can( 'edit_user', $user_id ) ) {
				return;
			}

			// If user is in approved list, update his/her associated role.
			$wp_user = get_user_by( 'id', $user_id );
			if ( $this->is_email_in_list( $wp_user->get( 'user_email' ), 'approved' ) ) {
				$auth_settings_access_users_approved = $this->sanitize_user_list(
					$this->get_plugin_option( 'access_users_approved', 'single admin' )
				);
				// Find approved user and update their role.
				foreach ( $auth_settings_access_users_approved as $key => $user ) {
					if ( $user['email'] === $wp_user->get( 'user_email' ) ) {
						$auth_settings_access_users_approved[$key]['role'] = $_REQUEST['role'];
					}
				}

				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}
		}

		/**
		 * Settings print callbacks
		 */
		function print_section_info_tabs( $args = '' ) {
			if ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ): ?>
				<h2 class="nav-tab-wrapper">
					<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:choose_tab('access_lists');">Access Lists</a>
					<a class="nav-tab nav-tab-external" href="javascript:choose_tab('external');">External Service</a>
					<a class="nav-tab nav-tab-advanced" href="javascript:choose_tab('advanced');">Advanced</a>
				</h2>
			<?php else: ?>
				<h2 class="nav-tab-wrapper">
					<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:choose_tab('access_lists');">Access Lists</a>
					<a class="nav-tab nav-tab-access_login" href="javascript:choose_tab('access_login');">Login Access</a>
					<a class="nav-tab nav-tab-access_public" href="javascript:choose_tab('access_public');">Public Access</a>
					<a class="nav-tab nav-tab-external" href="javascript:choose_tab('external');">External Service</a>
					<a class="nav-tab nav-tab-advanced" href="javascript:choose_tab('advanced');">Advanced</a>
				</h2>
			<?php endif;
		} // END print_section_info_tabs()


		function print_section_info_access_lists( $args = '' ) {
			?><div id="section_info_access_lists" class="section_info">
				<p>Manage who has access to this site using these lists.</p>
				<ol>
					<li><strong>Pending</strong> users are users who have successfully logged in to the site, but who haven't yet been approved (or blocked) by you.</li>
					<li><strong>Approved</strong> users have access to the site once they successfully log in.</li>
					<li><strong>Blocked</strong> users will receive an error message when they try to visit the site after authenticating.</li>
				</ol>
			</div>
			<table class="form-table">
				<tbody>
					<tr>
						<th scope="row">Pending Users</th>
						<td><?php $this->print_combo_auth_access_users_pending(); ?></td>
					</tr>
					<tr>
						<th scope="row">Approved Users</th>
						<td><?php $this->print_combo_auth_access_users_approved(); ?></td>
					</tr>
					<tr>
						<th scope="row">Blocked Users</th>
						<td><?php $this->print_combo_auth_access_users_blocked(); ?></td>
					</tr>
				</tbody>
			</table>
			<?php
		} // END print_section_info_access_lists()

		function print_combo_auth_access_users_pending( $args = '' ) {
			// Get plugin option.
			$option = 'access_users_pending';
			$auth_settings_option = $this->get_plugin_option( $option );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Print option elements.
			?><ul id="list_auth_settings_access_users_pending" style="margin:0;">
				<?php if ( count( $auth_settings_option ) > 0 ) : ?>
					<?php foreach ( $auth_settings_option as $key => $pending_user ): ?>
						<?php if ( empty( $pending_user ) || count( $pending_user ) < 1 ) continue; ?>
						<?php $pending_user['is_wp_user'] = false; ?>
						<li>
							<input type="text" id="auth_settings_<?php echo $option; ?>_<?php echo $key; ?>" name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][email]" value="<?php echo $pending_user['email']; ?>" readonly="true" class="auth-email" />
							<select name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][role]" class="auth-role">
								<?php $this->wp_dropdown_permitted_roles( $pending_user['role'] ); ?>
							</select>
							<input type="button" class="button-primary" id="approve_user_<?php echo $key; ?>" onclick="auth_add_user( this, 'approved', false ); auth_ignore_user( this, 'pending' );" value="Approve" />
							<input type="button" class="button-primary" id="block_user_<?php echo $key; ?>" onclick="auth_add_user( this, 'blocked', false ); auth_ignore_user( this, 'pending' );" value="Block" />
							<a class="button" id="ignore_user_<?php echo $key; ?>" onclick="auth_ignore_user( this, 'pending' );" title="Remove user"><span class="glyphicon glyphicon-remove"></span></a>
						</li>
					<?php endforeach; ?>
				<?php else: ?>
						<li class="auth-empty"><em>No pending users</em></li>
				<?php endif; ?>
			</ul>
			<?php
		} // END print_combo_auth_access_users_pending()

		function print_combo_auth_access_users_approved( $args = '' ) {
			// Get plugin option.
			$option = 'access_users_approved';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'no override' );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Get multisite approved users (add them to top of list, greyed out).
			$auth_multisite_settings = $this->get_plugin_options( 'multisite admin' );
			$option_multisite = 'access_users_approved';
			$auth_settings_option_multisite = array();
			if (
				is_multisite() &&
				array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
				$auth_multisite_settings['multisite_override'] === '1'
			) {
				$auth_settings_option_multisite = $this->get_plugin_option( $option, 'multisite admin', 'allow override' );
				$auth_settings_option_multisite = is_array( $auth_settings_option_multisite ) ? $auth_settings_option_multisite : array();
			}

			// Get default role for new user dropdown.
			$access_default_role = $this->get_plugin_option( 'access_default_role', 'single admin', 'allow override' );

			// Get custom usermeta field to show.
			$advanced_usermeta = $this->get_plugin_option( 'advanced_usermeta' );

			// Adjust javascript function prefixes if multisite.
			$js_function_prefix = $admin_mode === 'multisite admin' ? 'auth_multisite_' : 'auth_';
			$multisite_admin_page = $admin_mode === 'multisite admin';

			?><ul id="list_auth_settings_access_users_approved" style="margin:0;">
				<?php if ( ! $multisite_admin_page ) : ?>
					<?php foreach ( $auth_settings_option_multisite as $key => $approved_user ): ?>
						<?php if ( empty( $approved_user ) || count( $approved_user ) < 1 ) continue; ?>
						<?php if ( $approved_wp_user = get_user_by( 'email', $approved_user['email'] ) ) :
							$approved_user['email'] = $approved_wp_user->user_email;
							$approved_user['role'] = $multisite_admin_page || count( $approved_wp_user->roles ) === 0 ? $approved_user['role'] : array_shift( $approved_wp_user->roles );
							$approved_user['date_added'] = $approved_wp_user->user_registered;
						endif; ?>
						<?php if ( $approved_wp_user && strlen( $advanced_usermeta ) > 0 ) {
							$approved_user['usermeta'] = get_user_meta( $approved_wp_user->ID, $advanced_usermeta, true );
							if ( is_array( $approved_user['usermeta'] ) || is_object( $approved_user['usermeta'] ) ) {
								$approved_user['usermeta'] = serialize( $approved_user['usermeta'] );
							}
						} else {
							$approved_user['usermeta'] = '';
						} ?>
						<li>
							<input type="text" id="auth_multisite_settings_<?php echo $option; ?>_<?php echo $key; ?>" name="auth_multisite_settings_<?php echo $option; ?>[<?php echo $key; ?>][email]" value="<?php echo $approved_user['email']; ?>" readonly="true" class="auth-email auth-multisite-email" />
							<select name="auth_multisite_settings_<?php echo $option; ?>[<?php echo $key; ?>][role]" class="auth-role auth-multisite-role" disabled="disabled">
								<?php $this->wp_dropdown_permitted_roles( $approved_user['role'] ); ?>
							</select>
							<input type="text" name="auth_multisite_settings_<?php echo $option; ?>[<?php echo $key; ?>][date_added]" value="<?php echo date( 'M Y', strtotime( $approved_user['date_added'] ) ); ?>" readonly="true" class="auth-date-added auth-multisite-date-added" disabled="disabled" />
							<?php if ( strlen( $advanced_usermeta ) > 0 ) : ?>
								<input type="text" name="auth_multisite_settings_<?php echo $option; ?>[<?php echo $key; ?>][usermeta]" value="<?php echo htmlspecialchars( $approved_user['usermeta'], ENT_COMPAT ); ?>" readonly="true" class="auth-usermeta auth-multisite-usermeta" disabled="disabled" />
							<?php endif; ?>
							&nbsp;&nbsp;<a title="WordPress Multisite user" class="auth-multisite-user"><span class="glyphicon glyphicon-globe"></span></a>
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
				<?php foreach ( $auth_settings_option as $key => $approved_user ): ?>
					<?php $is_current_user = false; ?>
					<?php $local_user_icon = array_key_exists( 'local_user', $approved_user ) && $approved_user['local_user'] === 'true' ? '&nbsp;<a title="Local WordPress user" class="auth-local-user"><span class="glyphicon glyphicon-user"></span></a>' : ''; ?>
					<?php if ( empty( $approved_user ) || count( $approved_user ) < 1 ) continue; ?>
					<?php $approved_user['usermeta'] = ''; ?>
					<?php if ( $approved_wp_user = get_user_by( 'email', $approved_user['email'] ) ) {
						$approved_user['email'] = $approved_wp_user->user_email;
						$approved_user['role'] = $multisite_admin_page || count( $approved_wp_user->roles ) === 0 ? $approved_user['role'] : array_shift( $approved_wp_user->roles );
						$approved_user['date_added'] = $approved_wp_user->user_registered;
						$approved_user['is_wp_user'] = true;
						$is_current_user = $approved_wp_user->ID === get_current_user_id();
					} else {
						$approved_user['is_wp_user'] = false;
					} ?>
					<?php if ( $approved_wp_user && strlen( $advanced_usermeta ) > 0 ) {
						$approved_user['usermeta'] = get_user_meta( $approved_wp_user->ID, $advanced_usermeta, true );
						if ( is_array( $approved_user['usermeta'] ) || is_object( $approved_user['usermeta'] ) ) {
							$approved_user['usermeta'] = serialize( $approved_user['usermeta'] );
						}
					} else {
						$approved_user['usermeta'] = '';
					} ?>
					<li>
						<input type="text" id="auth_settings_<?php echo $option; ?>_<?php echo $key; ?>" name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][email]" value="<?php echo $approved_user['email']; ?>" readonly="true" class="auth-email" />
						<select name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][role]" class="auth-role" onchange="<?php echo $js_function_prefix; ?>change_role( this );">
							<?php $disable_input = $is_current_user ? 'disabled' : null; ?>
							<?php $this->wp_dropdown_permitted_roles( $approved_user['role'], $disable_input ); ?>
						</select>
						<input type="text" name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][date_added]" value="<?php echo date( 'M Y', strtotime( $approved_user['date_added'] ) ); ?>" readonly="true" class="auth-date-added" />
						<?php if ( strlen( $advanced_usermeta ) > 0 ) : ?>
							<input type="text" name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][usermeta]" value="<?php echo htmlspecialchars( $approved_user['usermeta'], ENT_COMPAT ); ?>" class="auth-usermeta" />
							<a class="button button-small button-primary" id="update_usermeta_<?php echo $key; ?>" onclick="<?php echo $js_function_prefix; ?>update_usermeta( this );" title="Update usermeta"><span class="glyphicon glyphicon-floppy-saved"></span></a>
						<?php endif; ?>
						<?php if ( ! $is_current_user ): ?>
							<?php if ( ! $multisite_admin_page ) : ?>
								<a class="button" id="block_user_<?php echo $key; ?>" onclick="<?php echo $js_function_prefix; ?>add_user( this, 'blocked', false ); <?php echo $js_function_prefix; ?>ignore_user( this, 'approved' );" title="Block/Ban user"><span class="glyphicon glyphicon-ban-circle"></span></a>
							<?php endif; ?>
							<a class="button" id="ignore_user_<?php echo $key; ?>" onclick="<?php echo $js_function_prefix; ?>ignore_user(this, 'approved');" title="Remove user"><span class="glyphicon glyphicon-remove"></span></a>
						<?php endif; ?>
						<?php echo $local_user_icon; ?>
					</li>
				<?php endforeach; ?>
			</ul>
			<div id="new_auth_settings_<?php echo $option; ?>">
				<input type="text" name="new_approved_user_email" id="new_approved_user_email" placeholder="email address" class="auth-email new" />
				<select name="new_approved_user_role" id="new_approved_user_role" class="auth-role">
					<?php $this->wp_dropdown_permitted_roles( $access_default_role ); ?>
				</select>
				<div class="btn-group">
					<input type="button" class="btn button-primary dropdown-toggle" id="approve_user_new" onclick="<?php echo $js_function_prefix; ?>add_user(this, 'approved');" value="Approve" />
					<button type="button" class="btn button-primary dropdown-toggle" data-toggle="dropdown">
						<span class="caret"></span>
						<span class="sr-only">Toggle Dropdown</span>
					</button>
					<ul class="dropdown-menu" role="menu">
						<li><a href="javascript:void(0);" onclick="<?php echo $js_function_prefix; ?>add_user( document.getElementById('approve_user_new'), 'approved', true);">Create a local WordPress <br />account instead, and email <br />the user their password.</a></li>
					</ul>
				</div>
			</div>
			<?php
		} // END print_combo_auth_access_users_approved()

		function print_combo_auth_access_users_blocked( $args = '' ) {
			// Get plugin option.
			$option = 'access_users_blocked';
			$auth_settings_option = $this->get_plugin_option( $option );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			// Get default role for new blocked user dropdown.
			$access_default_role = $this->get_plugin_option( 'access_default_role', 'single admin', 'allow override' );

			// Print option elements.
			?><ul id="list_auth_settings_<?php echo $option; ?>" style="margin:0;">
				<?php foreach ( $auth_settings_option as $key => $blocked_user ): ?>
					<?php if ( empty( $blocked_user ) || count( $blocked_user ) < 1 ) continue; ?>
					<?php if ( $blocked_wp_user = get_user_by( 'email', $blocked_user['email'] ) ): ?>
						<?php $blocked_user['email'] = $blocked_wp_user->user_email; ?>
						<?php $blocked_user['role'] = array_shift( $blocked_wp_user->roles ); ?>
						<?php $blocked_user['date_added'] = $blocked_wp_user->user_registered; ?>
						<?php $blocked_user['is_wp_user'] = true; ?>
					<?php else: ?>
						<?php $blocked_user['is_wp_user'] = false; ?>
					<?php endif; ?>
					<li>
						<input type="text" id="auth_settings_<?php echo $option; ?>_<?php echo $key; ?>" name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][email]" value="<?php echo $blocked_user['email']; ?>" readonly="true" class="auth-email" />
						<select name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][role]" class="auth-role">
							<?php $this->wp_dropdown_permitted_roles( $blocked_user['role'] ); ?>
						</select>
						<input type="text" name="auth_settings_<?php echo $option; ?>[<?php echo $key; ?>][date_added]" value="<?php echo date( 'M Y', strtotime( $blocked_user['date_added'] ) ); ?>" readonly="true" class="auth-date-added" />
						<a class="button" id="ignore_user_<?php echo $key; ?>" onclick="auth_ignore_user(this, 'blocked');" title="Remove user"><span class="glyphicon glyphicon-remove"></span></a>
					</li>
				<?php endforeach; ?>
			</ul>
			<div id="new_auth_settings_<?php echo $option; ?>">
				<input type="text" name="new_blocked_user_email" id="new_blocked_user_email" placeholder="email address" class="auth-email new" />
				<select name="new_blocked_user_role" id="new_blocked_user_role" class="auth-role">
					<option value="<?php echo $access_default_role; ?>"><?php echo ucfirst( $access_default_role ); ?></option>
				</select>
				<input class="button-primary" type="button" id="block_user_new" onclick="auth_add_user(this, 'blocked');" value="Block" /><br />
			</div>
			<?php
		} // END print_combo_auth_access_users_blocked()


		function print_section_info_access_login( $args = '' ) {
			?><div id="section_info_access_login" class="section_info">
				<?php wp_nonce_field( 'save_auth_settings', 'nonce_save_auth_settings' ); ?>
				<p>Choose who is able to log into this site below.</p>
			</div><?php
		} // END print_section_info_access_login()

		function print_radio_auth_access_who_can_login( $args = '' ) {
			// Get plugin option.
			$option = 'access_who_can_login';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Workaround: javascript code hides/shows other settings based
			// on the selection in this option. If this option is overridden
			// by a multisite option, it should show that value in order to
			// correctly display the other appropriate options.
			// Side effect: this site option will be overwritten by the
			// multisite option on save. Since this is a 2-item radio, we
			// determined this was acceptable.
			if ( is_multisite() && $admin_mode === 'single admin' && $this->get_plugin_option( 'multisite_override', 'multisite admin' ) === '1' ) {
				$auth_settings_option = $this->get_plugin_option( $option, 'multisite admin' );
			}

			// Print option elements.
			?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_external_users" name="auth_settings[<?php echo $option; ?>]" value="external_users"<?php checked( 'external_users' == $auth_settings_option ); ?> /> All authenticated users (All external service users and all WordPress users)<br />
			<input type="radio" id="radio_auth_settings_<?php echo $option; ?>_approved_users" name="auth_settings[<?php echo $option; ?>]" value="approved_users"<?php checked( 'approved_users' == $auth_settings_option ); ?> /> Only <a href="javascript:choose_tab('access_lists');" id="dashboard_link_approved_users">approved users</a> (Approved external users and all WordPress users)<br /><?php
		} // END print_radio_auth_access_who_can_login()

		function print_select_auth_access_role_receive_pending_emails( $args = '' ) {
			// Get plugin option.
			$option = 'access_role_receive_pending_emails';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><select id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]">
				<option value="---" <?php selected( $auth_settings_option, '---' ); ?>>None (Don't send notification emails)</option>
				<?php wp_dropdown_roles( $auth_settings_option ); ?>
			</select><?php
		} // END print_select_auth_access_role_receive_pending_emails()

		function print_wysiwyg_auth_access_pending_redirect_to_message( $args = '' ) {
			// Get plugin option.
			$option = 'access_pending_redirect_to_message';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 5,
					'tinymce' => true,
					'teeny' => true,
					'quicktags' => false,
				)
			);
		} // END print_wysiwyg_auth_access_pending_redirect_to_message()

		function print_wysiwyg_auth_access_blocked_redirect_to_message( $args = '' ) {
			// Get plugin option.
			$option = 'access_blocked_redirect_to_message';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 5,
					'tinymce' => true,
					'teeny' => true,
					'quicktags' => false,
				)
			);
		} // END print_wysiwyg_auth_access_blocked_redirect_to_message()

		function print_checkbox_auth_access_should_email_approved_users( $args = '' ) {
			// Get plugin option.
			$option = 'access_should_email_approved_users';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><input type="checkbox" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="1"<?php checked( 1 == $auth_settings_option ); ?> /> Send a welcome email when approving a new user<?php
		} // END print_checkbox_auth_external_ldap()

		function print_text_auth_access_email_approved_users_subject( $args = '' ) {
			// Get plugin option.
			$option = 'access_email_approved_users_subject';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="Welcome to [site_name]!" style="width:320px;" /><br /><small>You can use the <b>[site_name]</b> shortcode.</small><?php
		} // END print_text_auth_access_email_approved_users_subject()

		function print_wysiwyg_auth_access_email_approved_users_body( $args = '' ) {
			// Get plugin option.
			$option = 'access_email_approved_users_body';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 9,
					'tinymce' => true,
					'teeny' => true,
					'quicktags' => false,
				)
			);

			?><small>You can use <b>[site_name]</b>, <b>[site_url]</b>, and <b>[user_email]</b> shortcodes.</small><?php

		} // END print_wysiwyg_auth_access_email_approved_users_body()


		function print_section_info_access_public( $args = '' ) {
			?><div id="section_info_access_public" class="section_info">
				<p>Choose your public access options here.</p>
			</div><?php
		} // END print_section_info_access_public()

		function print_radio_auth_access_who_can_view( $args = '' ) {
			// Get plugin option.
			$option = 'access_who_can_view';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Workaround: javascript code hides/shows other settings based
			// on the selection in this option. If this option is overridden
			// by a multisite option, it should show that value in order to
			// correctly display the other appropriate options.
			// Side effect: this site option will be overwritten by the
			// multisite option on save. Since this is a 2-item radio, we
			// determined this was acceptable.
			if ( is_multisite() && $admin_mode === 'single admin' && $this->get_plugin_option( 'multisite_override', 'multisite admin' ) === '1' ) {
				$auth_settings_option = $this->get_plugin_option( $option, 'multisite admin' );
			}

			// Print option elements.
			?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_everyone" name="auth_settings[<?php echo $option; ?>]" value="everyone"<?php checked( 'everyone' == $auth_settings_option ); ?> /> Everyone can see the site<br />
			<input type="radio" id="radio_auth_settings_<?php echo $option; ?>_logged_in_users" name="auth_settings[<?php echo $option; ?>]" value="logged_in_users"<?php checked( 'logged_in_users' == $auth_settings_option ); ?> /> Only logged in users can see the site<br /><?php
		} // END print_radio_auth_access_who_can_view()

		function print_radio_auth_access_redirect( $args = '' ) {
			// Get plugin option.
			$option = 'access_redirect';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_to_login" name="auth_settings[<?php echo $option; ?>]" value="login"<?php checked( 'login' == $auth_settings_option ); ?> /> Send them to the login screen<br />
			<input type="radio" id="radio_auth_settings_<?php echo $option; ?>_to_message" name="auth_settings[<?php echo $option; ?>]" value="message"<?php checked( 'message' == $auth_settings_option ); ?> /> Show them the anonymous access message (below)<?php
		} // END print_radio_auth_access_redirect()

		function print_radio_auth_access_public_warning( $args = '' ) {
			// Get plugin option.
			$option = 'access_public_warning';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_no" name="auth_settings[<?php echo $option; ?>]" value="no_warning"<?php checked( 'no_warning' == $auth_settings_option ); ?> /> Show them the page <strong>without</strong> the anonymous access message<br />
			<input type="radio" id="radio_auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="warning"<?php checked( 'warning' == $auth_settings_option ); ?> /> Show them the page <strong>with</strong> the anonymous access message (marked up as a <a href="http://getbootstrap.com/components/#alerts-dismissable" target="_blank">Bootstrap Dismissable Alert</a>)<?php
		} // END print_radio_auth_access_public_warning()

		function print_wysiwyg_auth_access_redirect_to_message( $args = '' ) {
			// Get plugin option.
			$option = 'access_redirect_to_message';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			wp_editor(
				wpautop( $auth_settings_option ),
				"auth_settings_$option",
				array(
					'media_buttons' => false,
					'textarea_name' => "auth_settings[$option]",
					'textarea_rows' => 5,
					'tinymce' => true,
					'teeny' => true,
					'quicktags' => false,
				)
			);
		} // END print_wysiwyg_auth_access_redirect_to_message()

		function print_multiselect_auth_access_public_pages( $args = '' ) {
			// Get plugin option.
			$option = 'access_public_pages';
			$auth_settings_option = $this->get_plugin_option( $option );
			$auth_settings_option = is_array( $auth_settings_option ) ? $auth_settings_option : array();

			$post_types = get_post_types( '', 'names' );
			$post_types = is_array( $post_types ) ? $post_types : array();

			// Print option elements.
			?><select id="auth_settings_<?php echo $option; ?>" multiple="multiple" name="auth_settings[<?php echo $option; ?>][]">
				<optgroup label="Special">
					<option value="home" <?php echo in_array( 'home', $auth_settings_option ) ? 'selected="selected"' : ''; ?>>Home Page</option>
				</optgroup>
				<?php foreach ( $post_types as $post_type ): ?>
					<optgroup label="<?php echo ucfirst( $post_type ); ?>">
					<?php $pages = get_pages( array( 'post_type' => $post_type ) ); ?>
					<?php $pages = is_array( $pages ) ? $pages : array(); ?>
					<?php foreach ( $pages as $page ): ?>
						<option value="<?php echo $page->ID; ?>" <?php echo in_array( $page->ID, $auth_settings_option ) ? 'selected="selected"' : ''; ?>><?php echo $page->post_title; ?></option>
					<?php endforeach; ?>
					</optgroup>
				<?php endforeach; ?>
			</select><?php
		} // END print_multiselect_auth_access_public_pages()


		function print_section_info_external( $args = '' ) {
			?><div id="section_info_external" class="section_info">
				<p>Enter your external server settings below.</p>
			</div><?php
		} // END print_section_info_external()

		function print_select_auth_access_default_role( $args = '' ) {
			// Get plugin option.
			$option = 'access_default_role';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><select id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]">
				<?php wp_dropdown_roles( $auth_settings_option ); ?>
			</select><?php
		} // END print_select_auth_access_default_role()

		function print_checkbox_auth_external_google( $args = '' ) {
			// Get plugin option.
			$option = 'google';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Make sure php5-curl extension is installed on server.
			$curl_installed_message = ! function_exists( 'curl_init' ) ? '<span style="color: red;">(Warning: <a href="http://www.php.net//manual/en/curl.installation.php" target="_blank" style="color: red;">PHP CURL extension</a> is <strong>not</strong> installed)</span>' : '';

			// Print option elements.
			?><input type="checkbox" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="1"<?php checked( 1 == $auth_settings_option ); ?> /> Enable Google Logins <?php echo $curl_installed_message; ?><?php
		} // END print_checkbox_auth_external_google()

		function print_text_google_clientid( $args = '' ) {
			// Get plugin option.
			$option = 'google_clientid';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			$site_url_parts = parse_url( get_site_url() );
			$site_url_host = $site_url_parts['scheme'] . '://' . $site_url_parts['host'] . '/';
			?>If you don't have a Google Client ID and Secret, generate them by following these instructions:
			<ol>
				<li>Click <strong>Create a Project</strong> on the <a href="https://cloud.google.com/console" target="_blank">Google Developers Console</a>. You can name it whatever you want.</li>
				<li>Within the project, navigate to <em>APIs and Auth</em> &gt; <em>Credentials</em>, then click <strong>Create New Client ID</strong> under OAuth. Use these settings:
					<ul>
						<li>Application Type: <strong>Web application</strong></li>
						<li>Authorized Javascript Origins: <strong><?php echo $site_url_host; ?></strong></li>
						<li>Authorized Redirect URI: <em>none</em></li>
					</ul>
				</li>
				<li>Copy/paste your new Client ID/Secret pair into the fields below.</li>
				<li><strong>Note</strong>: Navigate to <em>APIs and Auth</em> &gt; <em>Consent screen</em> to change the way the Google consent screen appears after a user has successfully entered their password, but before they are redirected back to WordPress.</li>
			</ol>
			<input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="1234567890123-kdjr85yt6vjr6d8g7dhr8g7d6durjf7g.apps.googleusercontent.com" style="width:560px;" /><?php
		} // END print_text_google_clientid()

		function print_text_google_clientsecret( $args = '' ) {
			// Get plugin option.
			$option = 'google_clientsecret';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="sDNgX5_pr_5bly-frKmvp8jT" style="width:220px;" /><?php
		} // END print_text_google_clientsecret()

		function print_checkbox_auth_external_cas( $args = '' ) {
			// Get plugin option.
			$option = 'cas';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Make sure php5-curl extension is installed on server.
			$curl_installed_message = ! function_exists( 'curl_init' ) ? '<span style="color: red;">(Warning: <a href="http://www.php.net//manual/en/curl.installation.php" target="_blank" style="color: red;">PHP CURL extension</a> is <strong>not</strong> installed)</span>' : '';

			// Print option elements.
			?><input type="checkbox" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="1"<?php checked( 1 == $auth_settings_option ); ?> /> Enable CAS Logins <?php echo $curl_installed_message; ?><?php
		} // END print_checkbox_auth_external_cas()

		function print_text_cas_custom_label( $args = '' ) {
			// Get plugin option.
			$option = 'cas_custom_label';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?>The button on the login page will read:<p><a class="button-primary button-large" style="padding: 3px 16px; height: 36px;"><span class="dashicons dashicons-lock" style="margin: 4px 4px 0 0;"></span> <strong>Sign in with </strong><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="CAS" style="width: 100px;" /></a></p><?php
		} // END print_text_cas_custom_label()

		function print_text_cas_host( $args = '' ) {
			// Get plugin option.
			$option = 'cas_host';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="authn.example.edu" /><?php
		} // END print_text_cas_host()

		function print_text_cas_port( $args = '' ) {
			// Get plugin option.
			$option = 'cas_port';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="443" style="width:50px;" /><?php
		} // END print_text_cas_port()

		function print_text_cas_path( $args = '' ) {
			// Get plugin option.
			$option = 'cas_path';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="/cas" /><?php
		} // END print_text_cas_path()

		function print_checkbox_auth_external_ldap( $args = '' ) {
			// Get plugin option.
			$option = 'ldap';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Make sure php5-ldap extension is installed on server.
			$ldap_installed_message = ! function_exists( 'ldap_connect' ) ? '<span style="color: red;">(Warning: <a href="http://www.php.net/manual/en/ldap.installation.php" target="_blank" style="color: red;">PHP LDAP extension</a> is <strong>not</strong> installed)</span>' : '';

			// Print option elements.
			?><input type="checkbox" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="1"<?php checked( 1 == $auth_settings_option ); ?> /> Enable LDAP Logins <?php echo $ldap_installed_message; ?><?php
		} // END print_checkbox_auth_external_ldap()

		function print_text_ldap_host( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_host';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="ldap.example.edu" /><?php
		} // END print_text_ldap_host()

		function print_text_ldap_port( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_port';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="389" style="width:50px;" /><?php
		} // END print_text_ldap_port()

		function print_text_ldap_search_base( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_search_base';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="ou=people,dc=example,dc=edu" style="width:225px;" /><?php
		} // END print_text_ldap_search_base()

		function print_text_ldap_uid( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_uid';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="uid" style="width:80px;" /><?php
		} // END print_text_ldap_uid()

		function print_text_ldap_user( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_user';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="cn=directory-user,ou=specials,dc=example,dc=edu" style="width:330px;" /><?php
		} // END print_text_ldap_user()

		function print_password_ldap_password( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_password';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="password" id="garbage_to_stop_autofill" name="garbage" value="" autocomplete="off" style="display:none;" />
			<input type="password" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $this->decrypt( base64_decode( $auth_settings_option ) ); ?>" autocomplete="off" /><?php
		} // END print_password_ldap_password()

		function print_checkbox_ldap_tls( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_tls';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="checkbox" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="1"<?php checked( 1 == $auth_settings_option ); ?> /> Use TLS<?php
		} // END print_checkbox_ldap_tls

		function print_text_ldap_lostpassword_url( $args = '' ) {
			// Get plugin option.
			$option = 'ldap_lostpassword_url';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="text" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $auth_settings_option; ?>" placeholder="https://myschool.example.edu:8888/am-forgot-password" style="width: 400px;" /><?php
		} // END print_text_ldap_lostpassword_url()


		function print_section_info_advanced( $args = '' ) {
			?><div id="section_info_advanced" class="section_info">
				<p>You may optionally specify some advanced settings below.</p>
			</div><?php
		} // END print_section_info_advanced()

		function print_text_auth_advanced_lockouts( $args = '' ) {
			// Get plugin option.
			$option = 'advanced_lockouts';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?>After
			<input type="text" id="auth_settings_<?php echo $option; ?>_attempts_1" name="auth_settings[<?php echo $option; ?>][attempts_1]" value="<?php echo $auth_settings_option['attempts_1']; ?>" placeholder="10" style="width:30px;" />
			invalid password attempts, delay further attempts on that user for
			<input type="text" id="auth_settings_<?php echo $option; ?>_duration_1" name="auth_settings[<?php echo $option; ?>][duration_1]" value="<?php echo $auth_settings_option['duration_1']; ?>" placeholder="1" style="width:30px;" />
			minute(s).
			<br />
			After
			<input type="text" id="auth_settings_<?php echo $option; ?>_attempts_2" name="auth_settings[<?php echo $option; ?>][attempts_2]" value="<?php echo $auth_settings_option['attempts_2']; ?>" placeholder="10" style="width:30px;" />
			more invalid attempts, increase the delay to
			<input type="text" id="auth_settings_<?php echo $option; ?>_duration_2" name="auth_settings[<?php echo $option; ?>][duration_2]" value="<?php echo $auth_settings_option['duration_2']; ?>" placeholder="10" style="width:30px;" />
			minutes.
			<br />
			Reset the delays after
			<input type="text" id="auth_settings_<?php echo $option; ?>_reset_duration" name="auth_settings[<?php echo $option; ?>][reset_duration]" value="<?php echo $auth_settings_option['reset_duration']; ?>" placeholder="240" style="width:40px;" />
			minutes with no invalid attempts.<?php
		} // END print_text_auth_advanced_lockouts()

		function print_checkbox_auth_advanced_hide_wp_login( $args = '' ) {
			// Get plugin option.
			$option = 'advanced_hide_wp_login';
			$admin_mode = ( is_array( $args ) && array_key_exists( 'multisite_admin', $args ) && $args['multisite_admin'] === true ) ? 'multisite admin' : 'single admin';
			$auth_settings_option = $this->get_plugin_option( $option, $admin_mode, 'allow override', 'print overlay' );

			// Print option elements.
			?><input type="checkbox" id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]" value="1"<?php checked( 1 == $auth_settings_option ); ?> /> Hide WordPress Logins
			<p><small>Note: You can always access the WordPress logins by adding external=wordpress to the wp-login URL, like so:<br /><a href="<?php echo wp_login_url(); ?>?external=wordpress" target="_blank"><?php echo wp_login_url(); ?>?external=wordpress</a>.</p><?php
		} // END print_checkbox_auth_advanced_hide_wp_login()

		function print_radio_auth_advanced_branding( $args = '' ) {
			// Get plugin option.
			$option = 'advanced_branding';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_default" name="auth_settings[<?php echo $option; ?>]" value="default"<?php checked( 'default' == $auth_settings_option ); ?> /> Default WordPress login screen<br />
			<?php

			/**
			 * Developers can use the `authorizer_add_branding_option` filter
			 * to add a radio button for "Custom WordPress login branding"
			 * under the "Advanced" tab in Authorizer options. Example:
			 *
			 * function my_authorizer_add_branding_option( $branding_options ) {
			 *   $new_branding_option = array(
			 *   	'value' => 'your_brand'
			 *   	'description' => 'Custom Your Brand Login Screen',
			 *   	'css_url' => 'http://url/to/your_brand.css',
			 *   	'js_url' => 'http://url/to/your_brand.js',
			 *   );
			 *   array_push( $branding_options, $new_branding_option );
			 *   return $branding_options;
			 * }
			 * add_filter( 'authorizer_add_branding_option', 'my_authorizer_add_branding_option' );
			 */
			$branding_options = array();
			$branding_options = apply_filters( 'authorizer_add_branding_option', $branding_options );
			foreach ( $branding_options as $branding_option ) {
				// Make sure the custom brands have the required values
				if ( ! ( is_array( $branding_option ) && array_key_exists( 'value', $branding_option ) && array_key_exists( 'description', $branding_option ) ) ) {
					continue;
				}
				?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_<?php echo sanitize_title( $branding_option['value'] ); ?>" name="auth_settings[<?php echo $option; ?>]" value="<?php echo $branding_option['value']; ?>"<?php checked( $branding_option['value'] == $auth_settings_option ); ?> /> <?php echo $branding_option['description']; ?><br /><?php
			}

			// Print message about adding custom brands if there are none.
			if ( count( $branding_options ) === 0 ) {
				?><p><em><strong>Note for theme developers</strong>: Add more options here by using the `authorizer_add_branding_option` filter in your theme. You can see an example theme that implements this filter in the plugin directory under sample-theme-add-branding.</em></p><?php
			}
		} // END print_radio_auth_advanced_branding()

		function print_radio_auth_advanced_admin_menu( $args = '' ) {
			// Get plugin option.
			$option = 'advanced_admin_menu';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><input type="radio" id="radio_auth_settings_<?php echo $option; ?>_default" name="auth_settings[<?php echo $option; ?>]" value="settings"<?php checked( 'settings' == $auth_settings_option ); ?> /> Show in Settings menu<br />
			<input type="radio" id="radio_auth_settings_<?php echo $option; ?>_default" name="auth_settings[<?php echo $option; ?>]" value="top"<?php checked( 'top' == $auth_settings_option ); ?> /> Show in sidebar (top level)<br /><?php

		} // END print_radio_auth_advanced_admin_menu()

		function print_select_auth_advanced_usermeta( $args = '' ) {
			// Get plugin option.
			$option = 'advanced_usermeta';
			$auth_settings_option = $this->get_plugin_option( $option );

			// Print option elements.
			?><select id="auth_settings_<?php echo $option; ?>" name="auth_settings[<?php echo $option; ?>]">
				<option value="">-- None --</option>
				<?php foreach ( $this->get_all_usermeta_keys() as $meta_key ) : if ( substr( $meta_key, 0, 3 ) === 'wp_' ) continue; ?>
					<option value="<?php echo $meta_key; ?>" <?php if ( $auth_settings_option === $meta_key ) echo ' selected="selected"'; ?>><?php echo $meta_key; ?></option>
				<?php endforeach; ?>
			</select><?php
		} // END print_select_auth_advanced_usermeta()



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

			// Add help tab for Login Access Settings
			$help_auth_settings_access_login_content = '
				<p><strong>Who can log in to the site?</strong>: Choose the level of access restriction you\'d like to use on your site here. You can leave the site open to anyone with a WordPress account or an account on an external service like Google, CAS, or LDAP, or restrict it to WordPress users and only the external users that you specify via the <em>Access Lists</em>.</p>
				<p><strong>Which role should receive email notifications about pending users?</strong>: If you\'ve restricted access to <strong>approved users</strong>, you can determine which WordPress users will receive a notification email everytime a new external user successfully logs in and is added to the pending list. All users of the specified role will receive an email, and the external user will get a message (specified below) telling them their access is pending approval.</p>
				<p><strong>What message should pending users see after attempting to log in?</strong>: Here you can specify the exact message a new external user will see once they try to log in to the site for the first time.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_access_login_content',
					'title' => 'Login Access',
					'content' => $help_auth_settings_access_login_content,
				)
			);

			// Add help tab for Public Access Settings
			$help_auth_settings_access_public_content = '
				<p><strong>Who can view the site?</strong>: You can restrict the site\'s visibility by only allowing logged in users to see pages. If you do so, you can customize the specifics about the site\'s privacy using the settings below.</p>
				<p><strong>What pages (if any) should be available to everyone?</strong>: If you\'d like to declare certain pages on your site as always public (such as the course syllabus, introduction, or calendar), specify those pages here. These pages will always be available no matter what access restrictions exist.</p>
				<p><strong>What happens to people without access when they visit a <em>private</em> page?</strong>: Choose the response anonymous users receive when visiting the site. You can choose between immediately taking them to the <strong>login screen</strong>, or simply showing them a <strong>message</strong>.</p>
				<p><strong>What happens to people without access when they visit a <em>public</em> page?</strong>: Choose the response anonymous users receive when visiting a page on the site marked as public. You can choose between showing them the page without any message, or showing them a the page with a message above the content.</p>
				<p><strong>What message should people without access see?</strong>: If you chose to show new users a <strong>message</strong> above, type that message here.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_access_public_content',
					'title' => 'Public Access',
					'content' => $help_auth_settings_access_public_content,
				)
			);

			// Add help tab for External Service (CAS, LDAP) Settings
			$help_auth_settings_external_content = '
				<p><strong>Type of external service to authenticate against</strong>: Choose which authentication service type you will be using. You\'ll have to fill out different fields below depending on which service you choose.</p>
				<p><strong>Enable Google Logins</strong>: Choose if you want to allow users to log in with their Google Account credentials. You will need to enter your API Client ID and Secret to enable Google Logins.</p>
				<p><strong>Enable CAS Logins</strong>: Choose if you want to allow users to log in with via CAS (Central Authentication Service). You will need to enter details about your CAS server (host, port, and path) to enable CAS Logins.</p>
				<p><strong>Enable LDAP Logins</strong>: Choose if you want to allow users to log in with their LDAP (Lightweight Directory Access Protocol) credentials. You will need to enter details about your LDAP server (host, port, search base, uid attribute, directory user, directory user password, and whether to use TLS) to enable Google Logins.</p>
				<p><strong>Default role for new CAS users</strong>: Specify which role new external users will get by default. Be sure to choose a role with limited permissions!</p>
				<p><strong><em>If you enable Google logins:</em></strong></p>
				<ul>
					<li><strong>Google Client ID</strong>: You can generate this ID by creating a new Project in the <a href="https://cloud.google.com/console">Google Developers Console</a>. A Client ID typically looks something like this: 1234567890123-kdjr85yt6vjr6d8g7dhr8g7d6durjf7g.apps.googleusercontent.com</li>
					<li><strong>Google Client Secret</strong>: You can generate this secret by creating a new Project in the <a href="https://cloud.google.com/console">Google Developers Console</a>. A Client Secret typically looks something like this: sDNgX5_pr_5bly-frKmvp8jT</li>
				</ul>
				<p><strong><em>If you enable CAS logins:</em></strong></p>
				<ul>
					<li><strong>CAS server hostname</strong>: Enter the hostname of the CAS server you authenticate against (e.g., authn.example.edu).</li>
					<li><strong>CAS server port</strong>: Enter the port on the CAS server to connect to (e.g., 443).</li>
					<li><strong>CAS server path/context</strong>: Enter the path to the login endpoint on the CAS server (e.g., /cas).</li>
				</ul>
				<p><strong><em>If you enable LDAP logins:</em></strong></p>
				<ul>
					<li><strong>LDAP Host</strong>: Enter the URL of the LDAP server you authenticate against.</li>
					<li><strong>LDAP Port</strong>: Enter the port number that the LDAP server listens on.</li>
					<li><strong>LDAP Search Base</strong>: Enter the LDAP string that represents the search base, e.g., ou=people,dc=example,dc=edu</li>
					<li><strong>LDAP attribute containing username</strong>: Enter the name of the LDAP attribute that contains the usernames used by those attempting to log in. The plugin will search on this attribute to find the cn to bind against for login attempts.</li>
					<li><strong>LDAP Directory User</strong>: Enter the name of the LDAP user that has permissions to browse the directory.</li>
					<li><strong>LDAP Directory User Password</strong>: Enter the password for the LDAP user that has permission to browse the directory.</li>
					<li><strong>Secure Connection (TLS)</strong>: Select whether all communication with the LDAP server should be performed over a TLS-secured connection.</li>
				</ul>';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_external_content',
					'title' => 'External Service',
					'content' => $help_auth_settings_external_content,
				)
			);

			// Add help tab for Advanced Settings
			$help_auth_settings_advanced_content = '
				<p><strong>Limit invalid login attempts</strong>: Choose how soon (and for how long) to restrict access to individuals (or bots) making repeated invalid login attempts. You may set a shorter delay first, and then a longer delay after repeated invalid attempts; you may also set how much time must pass before the delays will be reset to normal.</p>
				<p><strong>Custom lost password URL</strong>: The WordPress login page contains a link to recover a lost password. If you have external users who shouldn\'t change the password on their WordPress account, point them to the appropriate location to change the password on their external authentication service here.</p>
				<p><strong>Hide WordPress Logins</strong>: If you want to hide the WordPress username and password fields and the Log In button on the wp-login screen, enable this option. Note: You can always access the WordPress logins by adding external=wordpress to the wp-login URL, like so: <a href="' . wp_login_url() . '?external=wordpress" target="_blank">' . wp_login_url() . '?external=wordpress</a>.</p>
				<p><strong>Custom WordPress login branding</strong>: If you\'d like to use custom branding on the WordPress login page, select that here. You will need to use the `authorizer_add_branding_option` filter in your theme to add it. You can see an example theme that implements this filter in the plugin directory under sample-theme-add-branding.</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_auth_settings_advanced_content',
					'title' => 'Advanced',
					'content' => $help_auth_settings_advanced_content,
				)
			);
		} // END admin_head()



		/**
		 ****************************
		 * Multisite: Network Admin Options page
		 ****************************
		 */


		/**
		 * Network Admin menu item
		 * Hook: network_admin_menu
		 *
		 * @param  none
		 * @return void
		 */
		public function network_admin_menu() {
			// @see http://codex.wordpress.org/Function_Reference/add_menu_page
			add_menu_page(
				'Authorizer', // Page title
				'Authorizer', // Menu title
				'manage_network_options', // Capability
				'authorizer', // Menu slug
				array( $this, 'create_network_admin_page' ),
				'dashicons-groups', // Icon URL
				89 // Position
			);
		} // END network_admin_menu()

		/**
		 * Output the HTML for the options page
		 */
		public function create_network_admin_page() {
			if ( ! current_user_can('manage_network_options') ) {
				wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
			}
			$auth_settings = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', array() );
			?>
			<div class="wrap">
				<form method="post" action="" autocomplete="off">
					<h2>Authorizer Settings</h2>
					<p>Most <strong>Authorizer</strong> settings are set in the individual sites, but you can specify a few options here that apply to <strong>all sites in the network</strong>. These settings will override settings in the individual sites.</p>

					<input type="checkbox" id="auth_settings_multisite_override" name="auth_settings[multisite_override]" value="1"<?php checked( 1 == $auth_settings['multisite_override'] ); ?> /> Override individual site settings with the settings below

					<div id="auth_multisite_settings_disabled_overlay" style="display: none;"></div>

					<div class="wrap" id="auth_multisite_settings">
						<?php $this->print_section_info_tabs( array( 'multisite_admin' => true ) ); ?>

						<?php wp_nonce_field( 'save_auth_settings', 'nonce_save_auth_settings' ); ?>

						<?php // Custom access lists (for network, we only really want approved list, not pending or blocked) ?>
						<div id="section_info_access_lists" class="section_info">
							<p>Manage who has access to all sites in the network.</p>
						</div>
						<table class="form-table"><tbody>
							<tr>
								<th scope="row">Who can log in to sites in this network?</th>
								<td><?php $this->print_radio_auth_access_who_can_login( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Who can view sites in this network?</th>
								<td><?php $this->print_radio_auth_access_who_can_view( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Approved Users (All Sites)<br /><small><em>Note: these users will <strong>not</strong> receive welcome emails when approved. Only users approved from individual sites can receive these messages.</em></small></th>
								<td><?php $this->print_combo_auth_access_users_approved( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
						</tbody></table>

						<?php $this->print_section_info_external(); ?>
						<table class="form-table"><tbody>
							<tr>
								<th scope="row">Default role for new users</th>
								<td><?php $this->print_select_auth_access_default_role( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Google Logins</th>
								<td><?php $this->print_checkbox_auth_external_google( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Google Client ID</th>
								<td><?php $this->print_text_google_clientid( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Google Client Secret</th>
								<td><?php $this->print_text_google_clientsecret( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">CAS Logins</th>
								<td><?php $this->print_checkbox_auth_external_cas( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">CAS Custom Label</th>
								<td><?php $this->print_text_cas_custom_label( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">CAS server hostname</th>
								<td><?php $this->print_text_cas_host( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">CAS server port</th>
								<td><?php $this->print_text_cas_port( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">CAS server path/context</th>
								<td><?php $this->print_text_cas_path( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP Logins</th>
								<td><?php $this->print_checkbox_auth_external_ldap( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP Host</th>
								<td><?php $this->print_text_ldap_host( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP Port</th>
								<td><?php $this->print_text_ldap_port( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP Search Base</th>
								<td><?php $this->print_text_ldap_search_base( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP attribute containing username</th>
								<td><?php $this->print_text_ldap_uid( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP Directory User</th>
								<td><?php $this->print_text_ldap_user( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">LDAP Directory User Password</th>
								<td><?php $this->print_password_ldap_password( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Secure Connection (TLS)</th>
								<td><?php $this->print_checkbox_ldap_tls( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Custom lost password URL</th>
								<td><?php $this->print_text_ldap_lostpassword_url( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
						</tbody></table>

						<?php $this->print_section_info_advanced(); ?>
						<table class="form-table"><tbody>
							<tr>
								<th scope="row">Limit invalid login attempts</th>
								<td><?php $this->print_text_auth_advanced_lockouts( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
							<tr>
								<th scope="row">Hide WordPress Logins</th>
								<td><?php $this->print_checkbox_auth_advanced_hide_wp_login( array( 'multisite_admin' => true ) ); ?></td>
							</tr>
						</tbody></table>

						<br class="clear" />
					</div>
					<input type="button" name="submit" id="submit" class="button button-primary" value="Save Changes" onclick="save_auth_multisite_settings(this);" />
				</form>
			</div>
			<?php
		} // END create_network_admin_page()

		/**
		 * Save multisite settings (ajax call).
		 */
		function ajax_save_auth_multisite_settings() {
			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'manage_network_options' ) ) {
				die( '' );
			}

			// Make sure nonce exists.
			if ( empty( $_POST['nonce_save_auth_settings'] ) ) {
				die( '' );
			}

			// Nonce check.
			if ( ! wp_verify_nonce( $_POST['nonce_save_auth_settings'], 'save_auth_settings' ) ) {
				die( '' );
			}

			// Assert multisite.
			if ( ! is_multisite() ) {
				die( '' );
			}

			// Get multisite settings.
			$auth_multisite_settings = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', array() );

			// Sanitize settings
			$auth_multisite_settings = $this->sanitize_options( $_POST, 'multisite' );

			// Filter options to only the allowed values (multisite options are a subset of all options)
			$allowed = array(
				'multisite_override',
				'access_who_can_login',
				'access_who_can_view',
				'access_default_role',
				'google',
				'google_clientid',
				'google_clientsecret',
				'cas',
				'cas_custom_label',
				'cas_host',
				'cas_port',
				'cas_path',
				'ldap',
				'ldap_host',
				'ldap_port',
				'ldap_search_base',
				'ldap_uid',
				'ldap_user',
				'ldap_password',
				'ldap_tls',
				'ldap_lostpassword_url',
				'advanced_lockouts',
				'advanced_hide_wp_login',
			);
			$auth_multisite_settings = array_intersect_key( $auth_multisite_settings, array_flip( $allowed ) );

			// Update multisite settings in database.
			update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', $auth_multisite_settings );

			// Return 'success' value to AJAX call.
			die( 'success' );
		} // END ajax_save_auth_multisite_settings()



		/**
		 ****************************
		 * Dashboard widget
		 ****************************
		 */



		function add_dashboard_widgets() {
			// Only users who can edit can see the authorizer dashboard widget
			if ( current_user_can( 'edit_users' ) ) {
				// Add dashboard widget for adding/editing users with access
				wp_add_dashboard_widget( 'auth_dashboard_widget', 'Authorizer Settings', array( $this, 'add_auth_dashboard_widget' ) );
			}
		} // END add_dashboard_widgets()


		function add_auth_dashboard_widget() {
			?><form method="post" id="auth_settings_access_form" action="">
				<?php $this->print_section_info_access_login(); ?>
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
			</form><?php
		} // END add_auth_dashboard_widget()


		function ajax_update_auth_usermeta() {

			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'edit_users' ) ) {
				die( '' );
			}

			// Nonce check.
			if ( empty( $_POST['nonce_save_auth_settings'] ) || ! wp_verify_nonce( $_POST['nonce_save_auth_settings'], 'save_auth_settings' ) ) {
				die( '' );
			}

			// Fail if required post data doesn't exist.
			if ( ! array_key_exists( 'email', $_REQUEST ) || ! array_key_exists( 'usermeta', $_REQUEST ) ) {
				die( '' );
			}

			// Fail if user doesn't exist.
			if ( ! ( $wp_user = get_user_by( 'email', $_REQUEST['email'] ) ) ) {
				die( '' );
			}

			// Update user's usermeta value for usermeta key stored in authorizer options.
			$meta_key = $this->get_plugin_option( 'advanced_usermeta' );
			$meta_value = $_REQUEST['usermeta'];
			if ( ! update_user_meta( $wp_user->ID, $meta_key, $meta_value ) ) {
				die( '' );
			}

			// Return 'success' value to AJAX call.
			die( 'success' );
		}


		function ajax_update_auth_user() {

			// Fail silently if current user doesn't have permissions.
			if ( ! current_user_can( 'edit_users' ) ) {
				die( '' );
			}

			// Nonce check.
			if ( empty( $_POST['nonce_save_auth_settings'] ) || ! wp_verify_nonce( $_POST['nonce_save_auth_settings'], 'save_auth_settings' ) ) {
				die( '' );
			}

			// Fail if requesting a change to an invalid setting.
			if ( ! in_array( $_POST['setting'], array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' ) ) ) {
				die( '' );
			}

			// Editing a pending list entry.
			if ( $_POST['setting'] === 'access_users_pending' ) {
				// Initialize posted data if empty.
				if ( ! ( array_key_exists( 'access_users_pending', $_POST ) && is_array( $_POST['access_users_pending'] ) ) ) {
					$_POST['access_users_pending'] = array();
				}

				// Deal with each modified user (add or remove).
				foreach ( $_POST['access_users_pending'] as $pending_user ) {

					if ( $pending_user['edit_action'] === 'add' ) {

						// Add new user to pending list and save (skip if it's
						// already there--someone else might have just done it).
						if ( ! $this->is_email_in_list( $pending_user['email'], 'pending' ) ) {
							$auth_settings_access_users_pending = $this->sanitize_user_list(
								$this->get_plugin_option( 'access_users_pending', 'single admin' )
							);
							array_push( $auth_settings_access_users_pending, $pending_user );
							update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
						}

					} else if ( $pending_user['edit_action'] === 'remove' ) {

						// Remove user from pending list and save
						if ( $this->is_email_in_list( $pending_user['email'], 'pending' ) ) {
							$auth_settings_access_users_pending = $this->sanitize_user_list(
								$this->get_plugin_option( 'access_users_pending', 'single admin' )
							);
							foreach ( $auth_settings_access_users_pending as $key => $existing_user ) {
								if ( $pending_user['email'] == $existing_user['email'] ) {
									unset( $auth_settings_access_users_pending[$key] );
									break;
								}
							}
							update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
						}

					}
				}
			}

			// Editing an approved list entry.
			if ( $_POST['setting'] === 'access_users_approved' ) {
				// Initialize posted data if empty.
				if ( ! ( array_key_exists( 'access_users_approved', $_POST ) && is_array( $_POST['access_users_approved'] ) ) ) {
					$_POST['access_users_approved'] = array();
				}

				// Deal with each modified user (add, remove, or change_role).
				foreach ( $_POST['access_users_approved'] as $approved_user ) {
					if ( $approved_user['edit_action'] === 'add' ) {

						// New user (create user, or add existing user to current site in multisite).
						$new_user = get_user_by( 'email', $approved_user['email'] );
						if ( $new_user !== false ) {
							if ( is_multisite() ) {
								add_user_to_blog( get_current_blog_id(), $new_user->ID, $approved_user['role'] );
							}
						} else if ( $approved_user['local_user'] === 'true' ) {
							// Create a WP account for this new *local* user and email the password.
							$plaintext_password = wp_generate_password(); // random password
							// If there's already a user with this username (e.g.,
							// johndoe/johndoe@gmail.com exists, and we're trying to add
							// johndoe/johndoe@example.com), use the full email address
							// as the username.
							$username = explode( "@", $approved_user['email'] );
							$username = $username[0];
							if ( get_user_by( 'login', $username ) !== false ) {
								$username = $approved_user['email'];
							}
							if ( $approved_user['multisite_user'] !== 'false' ) {
								$result = wpmu_create_user(
									strtolower( $username ),
									$plaintext_password,
									strtolower( $approved_user['email'] )
								);
							} else {
								$result = wp_insert_user(
									array(
										'user_login' => strtolower( $username ),
										'user_pass' => $plaintext_password,
										'first_name' => '',
										'last_name' => '',
										'user_email' => strtolower( $approved_user['email'] ),
										'user_registered' => date( 'Y-m-d H:i:s' ),
										'role' => $approved_user['role'],
									)
								);
							}
							if ( ! is_wp_error( $result ) ) {
								// Email password to new user
								wp_new_user_notification( $result, $plaintext_password );
							}

						}

						// Email new user welcome message if plugin option is set.
						$this->maybe_email_welcome_message( $approved_user['email'] );

						// Add new user to approved list and save (skip if it's
						// already there--someone else might have just done it).
						if ( $approved_user['multisite_user'] !== 'false' ) {
							if ( ! $this->is_email_in_list( $approved_user['email'], 'approved', 'multisite' ) ) {
								$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', 'multisite admin' )
								);
								$approved_user['date_added'] = date( 'M Y' );
								array_push( $auth_multisite_settings_access_users_approved, $approved_user );
								update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
							}
						} else {
							if ( ! $this->is_email_in_list( $approved_user['email'], 'approved' ) ) {
								$auth_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', 'single admin' )
								);
								$approved_user['date_added'] = date( 'M Y' );
								array_push( $auth_settings_access_users_approved, $approved_user );
								update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
							}
						}

						// If we've added a new multisite user, go through all pending/approved/blocked lists
						// on individual sites and remove this user from them (to prevent duplicate entries).
						if ( $approved_user['multisite_user'] !== 'false' && is_multisite() ) {
							$list_names = array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' );
							foreach ( wp_get_sites( array( 'limit' => 999999 ) ) as $site ) {
								foreach ( $list_names as $list_name ) {
									$user_list = get_blog_option( $site['blog_id'], 'auth_settings_' . $list_name, array() );
									$list_changed = false;
									foreach ( $user_list as $key => $user ) {
										if ( $user['email'] == $approved_user['email'] ) {
											unset( $user_list[$key] );
											$list_changed = true;
										}
									}
									if ( $list_changed ) {
										update_blog_option( $site['blog_id'], 'auth_settings_' . $list_name, $user_list );
									}
								}
							}
						}

					} else if ( $approved_user['edit_action'] === 'remove' ) {

						// Remove user from approved list and save
						if ( $approved_user['multisite_user'] !== 'false' ) {
							if ( $this->is_email_in_list( $approved_user['email'], 'approved', 'multisite' ) ) {
								$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', 'multisite admin' )
								);
								foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
									if ( $approved_user['email'] == $existing_user['email'] ) {
										unset( $auth_multisite_settings_access_users_approved[$key] );
										break;
									}
								}
								update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
							}
						} else {
							if ( $this->is_email_in_list( $approved_user['email'], 'approved' ) ) {
								$auth_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', 'single admin' )
								);
								foreach ( $auth_settings_access_users_approved as $key => $existing_user ) {
									if ( $approved_user['email'] == $existing_user['email'] ) {
										unset( $auth_settings_access_users_approved[$key] );
										break;
									}
								}
								update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
							}
						}

					} else if ( $approved_user['edit_action'] === 'change_role' ) {

						//  Update user's role in WordPress
						$changed_user = get_user_by( 'email', $approved_user['email'] );
						if ( $changed_user ) {
							if ( is_multisite() && $approved_user['multisite_user'] !== 'false' ) {
								foreach ( get_blogs_of_user( $changed_user->ID ) as $blog ) {
									add_user_to_blog( $blog->userblog_id, $changed_user->ID, $approved_user['role'] );
								}
							} else {
								$changed_user->set_role( $approved_user['role'] );
							}
						}

						if ( $approved_user['multisite_user'] !== 'false' ) {
							if ( $this->is_email_in_list( $approved_user['email'], 'approved', 'multisite' ) ) {
								$auth_multisite_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', 'multisite admin' )
								);
								foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
									if ( $approved_user['email'] == $existing_user['email'] ) {
										$auth_multisite_settings_access_users_approved[$key]['role'] = $approved_user['role'];
										break;
									}
								}
								update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
							}
						} else {
							// Update user's role in approved list and save.
							if ( $this->is_email_in_list( $approved_user['email'], 'approved' ) ) {
								$auth_settings_access_users_approved = $this->sanitize_user_list(
									$this->get_plugin_option( 'access_users_approved', 'single admin' )
								);
								foreach ( $auth_settings_access_users_approved as $key => $existing_user ) {
									if ( $approved_user['email'] == $existing_user['email'] ) {
										$auth_settings_access_users_approved[$key]['role'] = $approved_user['role'];
										break;
									}
								}
								update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
							}
						}

					}
				}
			}

			// Editing a blocked list entry.
			if ( $_POST['setting'] === 'access_users_blocked' ) {
				// Initialize posted data if empty.
				if ( ! ( array_key_exists( 'access_users_blocked', $_POST ) && is_array( $_POST['access_users_blocked'] ) ) ) {
					$_POST['access_users_blocked'] = array();
				}

				// Deal with each modified user (add or remove).
				foreach ( $_POST['access_users_blocked'] as $blocked_user ) {

					if ( $blocked_user['edit_action'] === 'add' ) {

						// Add new user to blocked list and save (skip if it's
						// already there--someone else might have just done it).
						if ( ! $this->is_email_in_list( $blocked_user['email'], 'blocked' ) ) {
							$auth_settings_access_users_blocked = $this->sanitize_user_list(
								$this->get_plugin_option( 'access_users_blocked', 'single admin' )
							);
							$blocked_user['date_added'] = date( 'M Y' );
							array_push( $auth_settings_access_users_blocked, $blocked_user );
							update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );
						}

					} else if ( $blocked_user['edit_action'] === 'remove' ) {

						// Remove auth_blocked usermeta for the user.
						$unblocked_user = get_user_by( 'email', $blocked_user['email'] );
						if ( $unblocked_user !== false ) {
							delete_user_meta( $unblocked_user->ID, 'auth_blocked', 'yes' );
						}

						// Remove user from blocked list and save
						if ( $this->is_email_in_list( $blocked_user['email'], 'blocked' ) ) {
							$auth_settings_access_users_blocked = $this->sanitize_user_list(
								$this->get_plugin_option( 'access_users_blocked', 'single admin' )
							);
							foreach ( $auth_settings_access_users_blocked as $key => $existing_user ) {
								if ( $blocked_user['email'] == $existing_user['email'] ) {
									unset( $auth_settings_access_users_blocked[$key] );
									break;
								}
							}
							update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );
						}

					}
				}
			}

			// Return 'success' value to AJAX call.
			die( 'success' );
		} // END update_auth_user()



		/**
		 ****************************
		 * Helper functions
		 ****************************
		 */


		/**
		 * Retrieves a specific plugin option from db. Multisite enabled.
		 * @param  string $option        Option name
		 * @param  string $admin_mode    'multisite admin' will retrieve the multisite value
		 * @param  string $override_mode 'allow override' will retrieve the multisite value if it exists
		 * @param  string $print_mode    'print overlay' will output overlay that hides this option on the settings page
		 * @return mixed                 Option value, or null on failure
		 */
		private function get_plugin_option( $option, $admin_mode = 'single admin', $override_mode = 'no override', $print_mode = 'no overlay' ) {

			// Special case for user lists (they are saved seperately to prevent concurrency issues).
			if ( in_array( $option, array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' ) ) ) {
				$list = $admin_mode === 'multisite admin' ? array() : get_option( 'auth_settings_' . $option );
				if ( is_multisite() && $admin_mode === 'multisite admin' ) {
					$list = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_' . $option, array() );
				}
				return $list;
			}

			// Get all plugin options.
			$auth_settings = $this->get_plugin_options( $admin_mode, $override_mode );

			// Set option to null if it wasn't found.
			if ( ! array_key_exists( $option, $auth_settings ) ) {
				return null;
			}

			// If the requested and appropriate, print the overlay hiding the
			// single site option that is overridden by a multisite option.
			if (
				$admin_mode !== 'multisite admin' &&
				$override_mode === 'allow override' &&
				$print_mode === 'print overlay' &&
				array_key_exists( 'multisite_override', $auth_settings ) &&
				$auth_settings['multisite_override'] === '1'
			) {
				// Get original plugin options (not overridden value). We'll
				// show this old value behind the disabled overlay.
				$auth_settings = $this->get_plugin_options( $admin_mode, 'no override' );

				$name = "auth_settings[$option]";
				$id = "auth_settings_$option";
				?>
				<div id="overlay-hide-auth_settings_<?php echo $option; ?>" class="auth_multisite_override_overlay">
					<span class="overlay-note">
						This setting is overridden by a <a href="<?php echo network_admin_url( 'admin.php?page=authorizer&tab=external' ); ?>">multisite option</a>.
					</span>
				</div>
				<?php
			}

			return $auth_settings[$option];
		}

		/**
		 * Retrieves all plugin options from db. Multisite enabled.
		 * @param  string $admin_mode    'multisite admin' will retrieve the multisite value
		 * @param  string $override_mode 'allow override' will retrieve the multisite value if it exists
		 * @return mixed                 Option value, or null on failure
		 */
		private function get_plugin_options( $admin_mode = 'single admin', $override_mode = 'no override' ) {
			// Grab plugin settings (skip if in multisite admin mode).
			$auth_settings = $admin_mode === 'multisite admin' ? array() : get_option( 'auth_settings' );

			// Initialize to empty array if the plugin option doesn't exist.
			if ( $auth_settings === FALSE ) {
				$auth_settings = array();
			}

			// Merge multisite options if we're in a network.
			if ( is_multisite() ) {
				// Get multisite options.
				$auth_multisite_settings = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', array() );

				// Return the multisite options if we're viewing the network admin options page.
				// Otherwise override options with their multisite equivalents.
				if ( $admin_mode === 'multisite admin' ) {
					$auth_settings = $auth_multisite_settings;
				} else if (
					$override_mode === 'allow override' &&
					array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
					$auth_multisite_settings['multisite_override'] === '1'
				) {
					// Keep track of the multisite override selection.
					$auth_settings['multisite_override'] = $auth_multisite_settings['multisite_override'];

					// Note: the options below should be the complete list of
					// overridden options. It is *not* the complete list of all
					// options (some options don't have a multisite equivalent)

					// Note: access_users_approved, access_users_pending, and
					// access_users_blocked do not get overridden. However,
					// since access_users_approved has a multisite equivalent,
					// you must retrieve them both seperately. This is done
					// because the two lists should be treated differently.
					// $approved_users    = $this->get_plugin_option( 'access_users_approved', 'single admin' );
					// $ms_approved_users = $this->get_plugin_option( 'access_users_approved', 'multisite admin' );

					// Override external services (google, cas, or ldap) and associated options
					$auth_settings['google'] = $auth_multisite_settings['google'];
					$auth_settings['google_clientid'] = $auth_multisite_settings['google_clientid'];
					$auth_settings['google_clientsecret'] = $auth_multisite_settings['google_clientsecret'];
					$auth_settings['cas'] = $auth_multisite_settings['cas'];
					$auth_settings['cas_custom_label'] = $auth_multisite_settings['cas_custom_label'];
					$auth_settings['cas_host'] = $auth_multisite_settings['cas_host'];
					$auth_settings['cas_port'] = $auth_multisite_settings['cas_port'];
					$auth_settings['cas_path'] = $auth_multisite_settings['cas_path'];
					$auth_settings['ldap'] = $auth_multisite_settings['ldap'];
					$auth_settings['ldap_host'] = $auth_multisite_settings['ldap_host'];
					$auth_settings['ldap_port'] = $auth_multisite_settings['ldap_port'];
					$auth_settings['ldap_search_base'] = $auth_multisite_settings['ldap_search_base'];
					$auth_settings['ldap_uid'] = $auth_multisite_settings['ldap_uid'];
					$auth_settings['ldap_user'] = $auth_multisite_settings['ldap_user'];
					$auth_settings['ldap_password'] = $auth_multisite_settings['ldap_password'];
					$auth_settings['ldap_tls'] = $auth_multisite_settings['ldap_tls'];
					$auth_settings['ldap_lostpassword_url'] = $auth_multisite_settings['ldap_lostpassword_url'];

					// Override access_who_can_login and access_who_can_view
					$auth_settings['access_who_can_login'] = $auth_multisite_settings['access_who_can_login'];
					$auth_settings['access_who_can_view'] = $auth_multisite_settings['access_who_can_view'];

					// Override access_default_role
					$auth_settings['access_default_role'] = $auth_multisite_settings['access_default_role'];

					// Override lockouts
					$auth_settings['advanced_lockouts'] = $auth_multisite_settings['advanced_lockouts'];

					// Override Hide WordPress login
					$auth_settings['advanced_hide_wp_login'] = $auth_multisite_settings['advanced_hide_wp_login'];
				}
			}
			return $auth_settings;
		}


		private function maybe_email_welcome_message( $email ) {
			// Get option for whether to email welcome messages.
			$should_email_new_approved_users = $this->get_plugin_option( 'access_should_email_approved_users' );

			// Do not send welcome email if option not enabled.
			if ( $should_email_new_approved_users !== '1' ) {
				return false;
			}

			// Make sure we didn't just email this user (can happen with
			// multiple admins saving at the same time, or by clicking
			// Approve button too rapidly).
			$recently_sent_emails = get_option( 'auth_settings_recently_sent_emails' );
			if ( $recently_sent_emails === FALSE ) {
				$recently_sent_emails = array();
			}
			foreach ( $recently_sent_emails as $key => $recently_sent_email ) {
				if ( $recently_sent_email['time'] < strtotime( 'now -1 minutes' ) ) {
					// Remove emails sent more than 1 minute ago.
					unset( $recently_sent_emails[$key] );
				} else if ( $recently_sent_email['email'] === $email ) {
					// Sent an email to this user within the last 1 minute, so
					// quit without sending.
					return false;
				}
			}
			// Add the email we're about to send to the list.
			$recently_sent_emails[] = array(
				'email' => $email,
				'time' => time(),
			);
			update_option( 'auth_settings_recently_sent_emails', $recently_sent_emails );

			// Get welcome email subject and body text
			$subject = $this->get_plugin_option( 'access_email_approved_users_subject' );
			$body = apply_filters( 'the_content', $this->get_plugin_option( 'access_email_approved_users_body' ) );

			// Fail if the subject/body options don't exist or are empty.
			if ( is_null( $subject ) || is_null( $body ) || strlen( $subject) === 0 || strlen( $body) === 0 ) {
				return false;
			}

			// Replace approved shortcode patterns in subject and body.
			$site_name = get_bloginfo( 'name' );
			$site_url = get_site_url();
			$subject = str_replace( '[site_name]', $site_name, $subject );
			$body = str_replace( '[site_name]', $site_name, $body );
			$body = str_replace( '[site_url]', $site_url, $body );
			$body = str_replace( '[user_email]', $email, $body );
			$headers = 'Content-type: text/html' . "\r\n";

			// Send email.
			wp_mail( $email, $subject, $body, $headers );

			// Indicate mail was sent.
			return true;
		}

		/**
		 * Generate a unique cookie to add to nonces to prevent CSRF.
		 */
		protected $cookie_value = null;
		function get_cookie_value() {
			if ( ! $this->cookie_value ) {
				if ( isset( $_COOKIE['login_unique'] ) ) {
					$this->cookie_value = $_COOKIE['login_unique'];
				} else {
					$this->cookie_value = md5( rand() );
				}
			}
			return $this->cookie_value;
		} // END get_cookie_value()

		/**
		 * Basic encryption using a public (not secret!) key. Used for general
		 * database obfuscation of passwords.
		 */
		private static $key = '8QxnrvjdtweisvCBKEY!+0';
		function encrypt( $text ) {
			$result = '';

			// Use mcrypt library (better) if php5-mcrypt extension is enabled.
			if ( function_exists( 'mcrypt_encrypt') ) {
				$result = mcrypt_encrypt( MCRYPT_RIJNDAEL_256, self::$key, $text, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' );
			} else {
				for ( $i = 0; $i < strlen( $text ); $i++ ) {
					$char = substr( $text, $i, 1 );
					$keychar = substr( self::$key, ( $i % strlen( self::$key ) ) - 1, 1 );
					$char = chr( ord( $char ) + ord( $keychar ) );
					$result .= $char;
				}
				$result = base64_encode( $result );
			}

			return $result;
		} // END encrypt()

		function decrypt( $secret ) {
			$result = '';

			// Use mcrypt library (better) if php5-mcrypt extension is enabled.
			if ( function_exists( 'mcrypt_decrypt') ) {
				$result = rtrim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, self::$key, $secret, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' ), "\0$result" );
			} else {
				$secret = base64_decode( $secret );
				for ( $i = 0; $i < strlen( $secret ); $i++ ) {
					$char = substr( $secret, $i, 1 );
					$keychar = substr( self::$key, ( $i % strlen( self::$key ) ) - 1, 1 );
					$char = chr( ord( $char ) - ord( $keychar ) );
					$result .= $char;
				}
			}

			return $result;
		} // END decrypt()

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
		} // END is_user_logged_in_and_blog_user()

		/**
		 * Helper function to determine whether a given email is in one of
		 * the lists (pending, approved, blocked). Defaults to the list of
		 * approved users.
		 */
		function is_email_in_list( $email = '', $list = 'approved', $multisite_mode = 'single' ) {
			if ( empty( $email ) )
				return false;

			switch ( $list ) {
				case 'pending':
					$auth_settings_access_users_pending = $this->get_plugin_option( 'access_users_pending', 'single admin' );
					return $this->in_multi_array( $email, $auth_settings_access_users_pending );
					break;
				case 'blocked':
					$auth_settings_access_users_blocked = $this->get_plugin_option( 'access_users_blocked', 'single admin' );
					return $this->in_multi_array( $email, $auth_settings_access_users_blocked );
					break;
				case 'approved':
				default:
					$auth_settings_access_users_approved = $multisite_mode !== 'single' ?
						$this->get_plugin_option( 'access_users_approved', 'multisite admin' )
						: array_merge(
							$this->get_plugin_option( 'access_users_approved', 'single admin' ),
							$this->get_plugin_option( 'access_users_approved', 'multisite admin' )
						);
					return $this->in_multi_array( $email, $auth_settings_access_users_approved );
					break;
			}
		} // END is_email_in_list

		/**
		 * Helper function to search a multidimensional array for a value.
		 */
		function in_multi_array( $needle = '', $haystack = array(), $strict_mode = 'not strict', $case_sensitivity = 'case insensitive' ) {
			if ( ! is_array( $haystack ) ) {
				return false;
			}
			if ( $case_sensitivity === 'case insensitive' ) {
				$needle = strtolower( $needle );
			}
			foreach ( $haystack as $item ) {
				if ( $case_sensitivity === 'case insensitive' && ! is_array( $item ) ) {
					$item = strtolower( $item );
				}
				if ( ( $strict_mode === 'strict' ? $item === $needle : $item == $needle ) || ( is_array( $item ) && $this->in_multi_array( $needle, $item, $strict_mode, $case_sensitivity ) ) ) {
					return true;
				}
			}
			return false;
		} // END in_multi_array()

		/**
		 * Helper function to get a WordPress page ID from the pagename.
		 * @param  string $pagename Page Slug
		 * @return int           	Page/Post ID
		 */
		function get_id_from_pagename( $pagename = '' ) {
			global $wpdb;
			$page_id = $wpdb->get_var("SELECT ID FROM $wpdb->posts WHERE post_name = '" . sanitize_title_for_query( $pagename ) . "'");
			return $page_id;
		} // END get_id_from_pagename()

		/**
		 * Helper function to determine if an URL is accessible.
		 * @param  string $url URL that should be publicly reachable
		 * @return boolean     Whether the URL is publicly reachable
		 */
		function url_is_accessible( $url ) {
			// Make sure php5-curl extension is installed on server.
			if ( ! function_exists( 'curl_init' ) ) {
				// Note: This will silently fail, saying url is not accessible.
				// Warn user elsewhere that they should install curl.
				return false;
			}

			// Use curl to retrieve the URL.
			$handle = curl_init( $url );
			curl_setopt( $handle,  CURLOPT_RETURNTRANSFER, TRUE );
			$response = curl_exec( $handle );
			$http_code = curl_getinfo( $handle, CURLINFO_HTTP_CODE );
			curl_close( $handle );

			// Return true if the document has loaded successfully without any redirection or error
			return $http_code >= 200 && $http_code < 400;
		} // END url_is_accessible()

		// Helper function that builds option tags for a select element for all
		// roles the current user has permission to assign.
		function wp_dropdown_permitted_roles( $selected_role = 'subscriber', $disable_input = 'not disabled' ) {
			$roles = get_editable_roles();
			$current_user = wp_get_current_user();

			// Make sure we have a selected role (default to subscriber).
			if ( strlen( $selected_role ) < 1 ) {
				$selected_role = 'subscriber';
			}

			// If the currently selected role is not in the list of roles, it
			// either doesn't exist or the current user is not permitted to
			// assign it.
			if ( ! array_key_exists( $selected_role, $roles ) ) {
				?><option value="<?php echo $selected_role; ?>"><?php echo ucfirst( $selected_role ); ?></option><?php

				// If the role exists, that means the user isn't permitted to
				// assign it, so assume they can't edit that user's role at
				// all. Return only the one role for the dropdown list.
				if ( ! is_null( get_role( $selected_role ) ) ) {
					return;
				}
			}

			// Print an option element for each permitted role.
			foreach ( $roles as $name => $role ) {
				$selected = $selected_role === $name ? ' selected="selected"' : '';

				// Don't let a user change their own role
				$disabled = $selected_role !== $name && $disable_input === 'disabled' ? ' disabled="disabled"' : '';

				// But network admins can always change their role.
				if ( is_multisite() && current_user_can( 'manage_network' ) ) {
					$disabled = '';
				}

				?><option value="<?php echo $name; ?>"<?php echo $selected . $disabled; ?>><?php echo $role['name']; ?></option><?php
			}
		} // END wp_dropdown_permitted_roles()

		// Helper function to get a single user info array from one of the
		// access control lists (pending, approved, or blocked).
		// Returns: false if not found; otherwise
		// 	array( 'email' => '', 'role' => '', 'date_added' => '');
		function get_user_info_from_list( $email, $list ) {
			foreach ( $list as $user_info ) {
				if ( $user_info['email'] === $email ) {
					return $user_info;
				}
			}
			return false;
		} // END get_user_info_from_list()

		// Helper function to convert seconds to human readable text.
		// Source: http://csl.name/php-secs-to-human-text/
		function seconds_as_sentence( $secs ) {
			$units = array(
				"week"   => 7 * 24 * 3600,
				"day"    =>     24 * 3600,
				"hour"   =>          3600,
				"minute" =>            60,
				"second" =>             1,
			);

			// specifically handle zero
			if ( $secs == 0 ) return "0 seconds";

			$s = "";

			foreach ( $units as $name => $divisor ) {
				if ( $quot = intval( $secs / $divisor ) ) {
					$s .= "$quot $name";
					$s .= ( abs( $quot ) > 1 ? "s" : "" ) . ", ";
					$secs -= $quot * $divisor;
				}
			}

			return substr( $s, 0, -2 );
		} // END seconds_as_sentence()

		// Helper function to get all available usermeta keys as an array.
		function get_all_usermeta_keys() {
			global $wpdb;
			$usermeta_keys = $wpdb->get_col( "SELECT DISTINCT $wpdb->usermeta.meta_key FROM $wpdb->usermeta" );
			return $usermeta_keys;
		}


		/**
		 * Plugin Update Routines.
		 */
		function auth_update_check() {
			// Update: migrate user lists to own options (addresses concurrency
			// when saving plugin options, since user lists are changed often
			// and we don't want to overwrite changes to the lists when an
			// admin saves all of the plugin options.)
			// Note: Pending user list is changed whenever a new user tries to
			// log in; approved and blocked lists are changed whenever an admin
			// changes them from the multisite panel, the dashboard widget, or
			// the plugin options page.
			$update_if_older_than = 20140709;
			$auth_version = get_option( 'auth_version' );
			if ( $auth_version === false || intval( $auth_version ) < $update_if_older_than ) {
				// Copy single site user lists to new options (if they exist).
				$auth_settings = get_option( 'auth_settings' );
				if ( is_array( $auth_settings ) && array_key_exists('access_users_pending', $auth_settings ) ) {
					update_option( 'auth_settings_access_users_pending', $auth_settings['access_users_pending'] );
					unset( $auth_settings['access_users_pending'] );
					update_option( 'auth_settings', $auth_settings );
				}
				if ( is_array( $auth_settings ) && array_key_exists('access_users_approved', $auth_settings ) ) {
					update_option( 'auth_settings_access_users_approved', $auth_settings['access_users_approved'] );
					unset( $auth_settings['access_users_approved'] );
					update_option( 'auth_settings', $auth_settings );
				}
				if ( is_array( $auth_settings ) && array_key_exists('access_users_blocked', $auth_settings ) ) {
					update_option( 'auth_settings_access_users_blocked', $auth_settings['access_users_blocked'] );
					unset( $auth_settings['access_users_blocked'] );
					update_option( 'auth_settings', $auth_settings );
				}
				// Copy multisite user lists to new options (if they exist).
				if ( is_multisite() ) {
					$auth_multisite_settings = get_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', array() );
					if ( is_array( $auth_multisite_settings ) && array_key_exists('access_users_pending', $auth_multisite_settings ) ) {
						update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_pending', $auth_multisite_settings['access_users_pending'] );
						unset( $auth_multisite_settings['access_users_pending'] );
						update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', $auth_multisite_settings );
					}
					if ( is_array( $auth_multisite_settings ) && array_key_exists('access_users_approved', $auth_multisite_settings ) ) {
						update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_approved', $auth_multisite_settings['access_users_approved'] );
						unset( $auth_multisite_settings['access_users_approved'] );
						update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', $auth_multisite_settings );
					}
					if ( is_array( $auth_multisite_settings ) && array_key_exists('access_users_blocked', $auth_multisite_settings ) ) {
						update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings_access_users_blocked', $auth_multisite_settings['access_users_blocked'] );
						unset( $auth_multisite_settings['access_users_blocked'] );
						update_blog_option( BLOG_ID_CURRENT_SITE, 'auth_multisite_settings', $auth_multisite_settings );
					}
				}
				// Update version to reflect this change has been made.
				update_option( 'auth_version', $update_if_older_than );
			}

			// // Update: TEMPLATE
			// $update_if_older_than = YYYYMMDD;
			// $auth_version = get_option( 'auth_version' );
			// if ( $auth_version === false || intval( $auth_version ) < $update_if_older_than ) {
			// 	UPDATE CODE HERE
			// 	update_option( 'auth_version', $update_if_older_than );
			// }
		}

	} // END class WP_Plugin_Authorizer
}

// Instantiate the plugin class.
$wp_plugin_authorizer = new WP_Plugin_Authorizer();
