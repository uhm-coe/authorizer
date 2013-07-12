<?php
/*
Plugin Name: CAS Admission
Plugin URI: http://hawaii.edu/coe/dcdc/
Description: CAS Admission restricts access to students enrolled in university courses, using CAS for authentication and a whitelist of users with permission to access the site.
Version: 0.1
Author: Paul Ryan
Author URI: http://www.linkedin.com/in/paulrryan/
License: GPL2
*/

/*
Copyright 2013  Paul Ryan  (email : prar@hawaii.edu)

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
Portions forked from Restricted Site Access plugin: http://10up.com/plugins/restricted-site-access-wordpress/
*/


if ( !class_exists( 'WP_Plugin_CAS_Admission' ) ) {
	/**
	 * Define class for plugin: CAS Admission.
	 *
	 * @category Authentication
	 * @package  CAS_Admission
	 * @author   Paul Ryan <prar@hawaii.edu>
	 * @license  http://www.gnu.org/licenses/gpl-2.0.html GPL2
	 * @link     http://hawaii.edu/coe/dcdc/wordpress/cas_admission/doc/
	 */
	class WP_Plugin_CAS_Admission {
		
		/**
		 * Constructor.
		 */
		public function __construct() {
			//$adldap = new adLDAP();

			// Register filters.

			// Custom wp authentication routine using CAS
			add_filter( 'authenticate', array( $this, 'ldap_authenticate' ), 1, 3 );

			// Removing this bypasses Wordpress authentication (so if ldap auth fails,
			// no one can log in); with it enabled, it will run if ldap auth fails.
			//remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

			// Create settings link on Plugins page
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'plugin_settings_link' ) );

			// Modify login page to help users use ldap to log in
			if ( strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ) {
				add_filter( 'lostpassword_url', array( $this, 'custom_lostpassword_url' ) );
				add_filter( 'gettext', array( $this, 'custom_login_form_labels' ), 20, 3 );
			}

			// If we have a custom login error, add the filter to show it.
			$error = get_option( 'lsa_settings_misc_login_error' );
			if ( $error && strlen( $error ) > 0 ) {
				add_filter( 'login_errors', array( $this, 'show_misc_login_error' ) );
			}

			// Register actions.

			// Create menu item in Settings
			add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );

			// Create options page
			add_action( 'admin_init', array( $this, 'page_init' ) );

			// Enqueue javascript and css only on the plugin's options page and the dashboard (for the widget)
			add_action( 'load-settings_page_cas_admission', array( $this, 'load_options_page' ) );
			add_action( 'admin_head-index.php', array( $this, 'load_options_page' ) );

			// Add custom css and js to wp-login.php
			add_action( 'login_head', array( $this, 'load_login_css_and_js' ) );

			// Verify current user has access to page they are visiting
			add_action( 'parse_request', array( $this, 'restrict_access' ), 1 );

			// ajax IP verification check
			add_action( 'wp_ajax_lsa_ip_check', array( $this, 'ajax_lsa_ip_check' ) );

			// ajax IP verification check
			add_action( 'wp_ajax_lsa_course_check', array( $this, 'ajax_lsa_course_check' ) );

			// ajax save options from dashboard widget
			add_action( 'wp_ajax_save_sakai_dashboard_widget', array( $this, 'ajax_save_sakai_dashboard_widget' ) );

			// Add dashboard widget so instructors can add/edit sakai courses with access.
			// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
			add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widgets' ) );

			// If we have a custom admin message, add the action to show it.
			$notice = get_option( 'lsa_settings_misc_admin_notice' );
			if ( $notice && strlen( $notice ) > 0 ) {
				add_action( 'admin_notices', array( $this, 'show_misc_admin_notice' ) );
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
			if ( function_exists( 'is_multisite' ) && is_multisite() ) {
				if ( isset($_GET['networkwide'] ) && ( $_GET['networkwide'] == 1 ) ) {
					$old_blog = $wpdb->blogid;
					// Get all blog ids
					$blogids = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs" ) );
					foreach ( $blogids as $blog_id ) {
						switch_to_blog( $blog_id );
						self::_single_blog_activate();
					}
					switch_to_blog( $old_blog );
					return;
				}
			}

			// Activet the plugin for the current site
			self::_single_blog_activate();
		}

		/**
		 * Plugin activation.
		 *
		 * @return void
		 */
		private static function _single_blog_activate() {
			global $wp_roles;

			// Set meaningful defaults (but if values already exist in db, use those).
			$lsa_settings = get_option( 'lsa_settings' );
			if ( $lsa_settings === FALSE ) {
				$lsa_settings = array();
			}
			if ( !array_key_exists( 'ldap_host', $lsa_settings ) ) {
				$lsa_settings['ldap_host'] = '';
			}
			if ( !array_key_exists( 'ldap_search_base', $lsa_settings ) ) {
				$lsa_settings['ldap_search_base'] = '';
			}
			if ( !array_key_exists( 'ldap_user', $lsa_settings ) ) {
				$lsa_settings['ldap_user'] = '';
			}
			if ( !array_key_exists( 'ldap_password', $lsa_settings ) ) {
				$lsa_settings['ldap_password'] = '';
			}
			if ( !array_key_exists( 'ldap_type', $lsa_settings ) ) {
				$lsa_settings['ldap_type'] = 'openldap';
			}
			if ( !array_key_exists( 'ldap_tls', $lsa_settings ) ) {
				$lsa_settings['ldap_tls'] = '1';
			}
			if ( !array_key_exists( 'sakai_base_url', $lsa_settings ) ) {
				$lsa_settings['sakai_base_url'] = '';
			}
			if ( !array_key_exists( 'access_restriction', $lsa_settings ) ) {
				$lsa_settings['access_restriction'] = 'everyone';
			}
			if ( !array_key_exists( 'access_courses', $lsa_settings ) ) {
				$lsa_settings['access_courses'] = '';
			}
			if ( !array_key_exists( 'access_redirect', $lsa_settings ) ) {
				$lsa_settings['access_redirect'] = 'login';
			}
			if ( !array_key_exists( 'access_redirect_to_url', $lsa_settings ) ) {
				$lsa_settings['access_redirect_to_url'] = '';
			}
			if ( !array_key_exists( 'access_redirect_to_message', $lsa_settings ) ) {
				$lsa_settings['access_redirect_to_message'] = '<p>Access to this site is restricted.</p>';
			}
			if ( !array_key_exists( 'access_redirect_to_page', $lsa_settings ) ) {
				$lsa_settings['access_redirect_to_page'] = '';
			}
			if ( !array_key_exists( 'misc_ips', $lsa_settings ) ) {
				$lsa_settings['misc_ips'] = '';
			}
			if ( !array_key_exists( 'misc_lostpassword_url', $lsa_settings ) ) {
				$lsa_settings['misc_lostpassword_url'] = '';
			}
			if ( !array_key_exists( 'access_default_role', $lsa_settings ) ) {
				// Set default role to 'student' if that role exists, 'subscriber' otherwise.
				$all_roles = $wp_roles->roles;
				$editable_roles = apply_filters( 'editable_roles', $all_roles );
				if ( array_key_exists( 'student', $editable_roles ) ) {
					$lsa_settings['access_default_role'] = 'student';
				} else if ( array_key_exists( 'subscriber', $editable_roles ) ) {
					$lsa_settings['access_default_role'] = 'subscriber';
				} else {
					$lsa_settings['access_default_role'] = 'subscriber';
				}
			}
			update_option( 'lsa_settings', $lsa_settings );
		} // END activate()


		/**
		 * Plugin deactivation.
		 *
		 * @return void
		 */
		public function deactivate() {
			// Do nothing.
		} // END deactivate()


		/**
		 * Plugin uninstallation.
		 *
		 * @return void
		 */
		public function uninstall() {
			// Delete options in database.
			if ( get_option( 'lsa_settings' ) ) {
				delete_option( 'lsa_settings' );
			}
			if ( get_option( 'lsa_settings_misc_admin_notice' ) ) {
				delete_option( 'lsa_settings_misc_admin_notice' );
			}

			// Delete sakai session token from user meta for all users.
			$all_user_ids = get_users( 'fields=ID' );
			foreach ( $all_user_ids as $user_id ) {
				delete_user_meta( $user_id, 'sakai_session_id' );
			}
		} // END deactivate()


		/**
		 ****************************
		 * Custom filters and actions
		 ****************************
		 */

		/**
		 * Overwrite the URL for the lost password link on the login form.
		 * If we're authenticating against LDAP, standard WordPress password resets
		 * won't work.
		 */
		function custom_lostpassword_url( $lostpassword_url ) {
			$lsa_settings = get_option( 'lsa_settings' );
			if (
				array_key_exists( 'misc_lostpassword_url', $lsa_settings ) &&
				filter_var( $lsa_settings['misc_lostpassword_url'], FILTER_VALIDATE_URL ) &&
				array_key_exists( 'access_restriction', $lsa_settings ) &&
				$lsa_settings['access_restriction'] !== 'everyone' &&
				$lsa_settings['access_restriction'] !== 'user'
			) {
				$lostpassword_url = $lsa_settings['misc_lostpassword_url'];
			}
			return $lostpassword_url;
		}

		/**
		 * Overwrite the username label on the login form.
		 */
		function custom_login_form_labels( $translated_text, $text, $domain ) {
			$lsa_settings = get_option( 'lsa_settings' );

			if ( $translated_text === 'Username' ) {
				if ( array_key_exists( 'ldap_type', $lsa_settings ) && $lsa_settings['ldap_type'] === 'custom_uh' ) {
					$translated_text = 'UH Username';
				}
			}

			if ( $translated_text === 'Password' ) {
				if ( array_key_exists( 'ldap_type', $lsa_settings ) && $lsa_settings['ldap_type'] === 'custom_uh' ) {
					$translated_text = 'UH Password';
				}
			}

			return $translated_text;
		}

		/**
		 * Show custom admin notice.
		 * Filter: admin_notice
		 */
		function show_misc_admin_notice() {
			$notice = get_option( 'lsa_settings_misc_admin_notice' );
			delete_option( 'lsa_settings_misc_admin_notice' );

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
		function show_misc_login_error( $errors ) {
			$error = get_option( 'lsa_settings_misc_login_error' );
			delete_option( 'lsa_settings_misc_login_error' );

			//$errors .= '    ' . $error . "<br />\n";
			$errors = '    ' . $error . "<br />\n";
			return $errors;
		}

		/**
		 ****************************
		 * LDAP Authentication
		 ****************************
		 */


		/**
		 * Authenticate using LDAP credentials.
		 *
		 * @param WP_User $user     user to authenticate
		 * @param string  $username optional username to authenticate.
		 * @param string  $password optional password to authenticate.
		 *
		 * @return WP_User or WP_Error
		 */
		public function ldap_authenticate( $user, $username, $password ) {
			// Pass through if already authenticated.
			if ( is_a( $user, 'WP_User' ) ) {
				return $user;
			}

			// Custom UH code: remove @hawaii.edu if it exists in the username
			$username = str_replace( '@hawaii.edu', '', $username );

			// Fail with error message if username or password is blank.
			if ( empty( $username ) ) {
				return new WP_Error( 'empty_username', 'Username cannot be blank.' );
			}
			if ( empty( $password ) ) {
				return new WP_Error( 'empty_password', 'You must provide a password.' );
			}

			// Authenticate against LDAP using options provided in plugin settings.
			$result = false;
			$ldap_user = array(
				'dn' => '0',
				'first' => 'nobody',
				'last' => '',
				'email' => '',
			);

			$lsa_settings = get_option( 'lsa_settings' );

			// If we're restricting access to only WP users, don't check against ldap;
			// Instead, pass through to default WP authentication.
			if ( $lsa_settings['access_restriction'] === 'user' ) {
				return new WP_Error( 'no_ldap', 'Only authenticate against local WP install (not LDAP).' );
			}

			switch ( $lsa_settings['ldap_type'] ) {
			case 'custom_uh': // University of Hawai'i
				$ldap = ldap_connect( $lsa_settings['ldap_host'] );
				ldap_set_option( $ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
				if ( $lsa_settings['ldap_tls'] == 1 ) {
					ldap_start_tls( $ldap );
				}
				$result = ldap_bind( $ldap, $lsa_settings['ldap_user'], $this->decrypt( base64_decode( $lsa_settings['ldap_password'] ) ) );
				if ( !$result ) {
					return new WP_Error( 'ldap_error', 'Could not authenticate.' );
				}
				// UH has an odd system; people cn's are their uhuuid's (8 digit
				// numbers), not their uids (unique email address usernames).
				// So here we need to do an extra search by uid to get a uhuuid,
				// and then attempt to authenticate with uhuuid and password.
				$ldap_search = ldap_search(
					$ldap,
					$lsa_settings['ldap_search_base'],
					"(uid=$username)",
					array(
						'givenName',
						'sn',
						'mail',
						'uhUuid',
					)
				);
				$ldap_entries = ldap_get_entries( $ldap, $ldap_search );

				// If we didn't find any users in ldap, exit with error (rely on default wordpress authentication)
				if ( $ldap_entries['count'] < 1 ) {
					return new WP_Error( 'no_ldap', 'No LDAP user found.' );
				}

				for ( $i = 0; $i < $ldap_entries['count']; $i++ ) {
					$ldap_user['dn'] = $ldap_entries[$i]['dn'];
					$ldap_user['first'] = $ldap_entries[$i]['givenname'][0];
					$ldap_user['last'] = $ldap_entries[$i]['sn'][0];
					$ldap_user['email'] = $ldap_entries[$i]['mail'][0];
				}

				$result = ldap_bind( $ldap, $ldap_user['dn'], $password );
				if ( !$result ) {
					// We have a real ldap user, but an invalid password, so we shouldn't
					// pass through to wp authentication after failing ldap. Instead,
					// remove the WordPress authenticate function, and return an error.
					remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
					return new WP_Error( 'ldap_error', "<strong>ERROR</strong>: The password you entered for the username <strong>$username</strong> is incorrect." );
				}

				break;
			case 'ad': // Active Directory
				/**
				@todo: incomplete authentication (via active directory)
				*/
				return new WP_Error( 'adldap_error', 'Incomplete authentication routine.' );
				// try {
				// 	$adldap = new adLDAP(
				// 		array(
				// 			'base_dn' => $lsa_settings['ldap_search_base'],
				// 			'domain_controllers' => array($lsa_settings['ldap_host']),
				// 			'admin_username' => $lsa_settings['ldap_user'],
				// 			'account_suffix' => '', // suffix should already be included in the admin_username
				// 			'admin_password' => $this->decrypt( base64_decode( $lsa_settings['ldap_password'] ) ),
				// 			'use_tls' => $lsa_settings['ldap_tls'] == 1,
				// 		)
				// 	);
				// 	$result = $adldap->authenticate( $username, $password );
				// 	if ( !$result ) {
				// 		//do_action( 'wp_login_failed', $username );
				// 		return new WP_Error( 'adldap_error', 'Could not authenticate against Active Directory.' );
				// 	}
				// } catch (adLDAPException $e) {;
				// 	//do_action( 'wp_login_failed', $username );
				// 	return new WP_Error( 'adldap_error', $e );
				// }
				break;
			case 'openldap': // OpenLDAP
				/**
				@todo: incomplete authentication (via openldap)
				*/
				return new WP_Error( 'openldap_error', 'Incomplete authentication routine.' );
				// $ldap = ldap_connect( $lsa_settings['ldap_host'] );
				// ldap_set_option( $ldap, LDAP_OPT_PROTOCOL_VERSION, 3 );
				// if ( $lsa_settings['ldap_tls'] == 1 ) {
				// 	ldap_start_tls( $ldap );
				// }
				// $result = ldap_bind( $ldap, $lsa_settings['ldap_user'], $lsa_settings['ldap_password'] );
				break;
			default:
				//do_action( 'wp_login_failed', $username );
				return new WP_Error( 'missing_ldap_type', 'An administrator must choose an LDAP type to authenticate against an LDAP server (Error: Missing ldap_type specification).' );
				break;
			}

			// Successfully authenticated now, so create/update the WordPress user.
			$user = get_user_by( 'login', $username );
			if ( ! ( $user && strcasecmp( $user->user_login, $username ) ) ) {
				// User doesn't exist in WordPress, so add it.
				$result = wp_insert_user(
					array(
						'user_login' => $username,
						'user_pass' => wp_generate_password(), // random password
						'first_name' => $ldap_user['first'],
						'last_name' => $ldap_user['last'],
						'user_email' => $ldap_user['email'],
						'user_registered' => date( 'Y-m-d H:i:s' ),
						'role' => $lsa_settings['access_default_role'],
					)
				);

				// Check to see if there's an error because another user has the ldap
				// user's email. If so, log user in as that WordPress user.
				if ( is_wp_error( $result ) && array_key_exists( 'existing_user_email', $result->errors ) ) {
					$result = get_user_by( 'email', $ldap_user['email'] );
				}

				// Check to see if there's an error because the user exists, but
				// isn't added to this site (can occur in multisite installs).
				if ( is_wp_error( $result ) && array_key_exists( 'existing_user_login', $result->errors ) ) {
					global $current_blog;
					$result = add_user_to_blog( $current_blog->blog_id, $user->ID, $lsa_settings['access_default_role'] );
					if ( !is_wp_error( $result ) ) {
						$result = $user->ID;
					}
				}

				// Fail with message if error.
				if ( is_wp_error( $result ) ) {
					return $result;
				}

				// Authenticate as new user (or as old user with same email address as ldap)
				$user = new WP_User( $result );
			}

			// Try to create a Sakai session if Sakai base URL option exists; save session id in user meta
			if ( strlen( $lsa_settings['sakai_base_url'] ) > 0 ) {
				$sakai_session = $this->call_api(
					'post',
					trailingslashit( $lsa_settings['sakai_base_url'] ) . 'session',
					array(
						'_username' => $username,
						'_password' => $password,
					)
				);
				if ( isset( $sakai_session ) ) {
					update_user_meta( $user->ID, 'sakai_session_id', $sakai_session );
				}
			}

			// Reset cached access so plugin checks against sakai to make sure this newly-logged in user still has access (if restricting access by sakai course)
			update_user_meta( $user->ID, 'has_access', false );

			// Make sure (if we're restricting access by courses) that the current user is enrolled in an allowed course
			$logged_in_but_no_access = (
				$lsa_settings['access_restriction'] == 'course' &&
				! $this->is_current_user_sakai_enrolled( $user->ID )
			);
			if ( $logged_in_but_no_access ) {
				$error = 'Sorry ' . $username . ', it seems you don\'t have access to ' . get_bloginfo( 'name' ) . '. If this is a mistake, please contact your instructor and have them add you to their Sakai/Laulima course.';
				update_option( 'lsa_settings_misc_login_error', $error );
				wp_logout();
				wp_redirect( wp_login_url(), 302 );
				exit;
			}

			return $user;
		}


		/**
		 ****************************
		 * Access Restriction
		 ****************************
		 */


		/**
		 * Restrict access to WordPress site based on settings (everyone, university, course).
		 * Hook: parse_request http://codex.wordpress.org/Plugin_API/Action_Reference/parse_request
		 *
		 * @param array $wp WordPress object.
		 *
		 * @return void
		 */
		public function restrict_access( $wp ) {
			remove_action( 'parse_request', array( $this, 'restrict_access' ), 1 );	// only need it the first time

			$lsa_settings = get_option( 'lsa_settings' );

			$has_access = (
				( defined( 'WP_INSTALLING' ) && isset( $_GET['key'] ) ) || // Always allow access if WordPress is installing
				( is_admin() ) || // Always allow access to admins
				( $lsa_settings['access_restriction'] == 'everyone' ) || // Allow access if option is set to 'everyone'
				( $lsa_settings['access_restriction'] == 'university' && $this->is_user_logged_in_and_blog_user() ) || // Allow access to logged in users if option is set to 'university' community
				( $lsa_settings['access_restriction'] == 'user' && $this->is_user_logged_in_and_blog_user() ) || // Allow access to logged in users if option is set to WP users (note: when this is set, don't allow ldap log in elsewhere)
				( $lsa_settings['access_restriction'] == 'course' && get_user_meta( get_current_user_id(), 'has_access', true ) ) || // Allow access to users enrolled in sakai course if option is set to 'course' members only (check cached result first)
				( $lsa_settings['access_restriction'] == 'course' && $this->is_current_user_sakai_enrolled() ) // Allow access to users enrolled in sakai course if option is set to 'course' members only (check against sakai if no cached value is present)
			);
			$is_restricted = !$has_access;

			// Fringe case: User successfully logged in, but they don't have access
			// to an allowed course. Flag these users, and redirect them to their
			// profile page with a message (so we don't get into a redirect loop on
			// the wp-login.php page).
			$logged_in_but_no_access = false;
			if ( $this->is_user_logged_in_and_blog_user() && !$has_access && $lsa_settings['access_restriction'] == 'course' ) {
				$logged_in_but_no_access = true;
			}

			/**
			 * Developers can use the `cas_admission_has_access` filter
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
			 *   add_filter( 'cas_admission_has_access', 'my_rsa_feed_access_override' );
			 */
			if ( apply_filters( 'cas_admission_has_access', $has_access, $wp ) === true ) {
				// We've determined that the current user has access, so simply return to grant access.
				return;
			}

			// Allow access from the ip address allow list; if it's empty, block everything
			if ( $allowed_ips = $lsa_settings['misc_ips'] ) {
				$current_user_ip = $_SERVER['REMOTE_ADDR'];
				if ( strpos( $current_user_ip, '.' ) !== false ) {
					$current_user_ip = str_replace( '::ffff:', '', $current_user_ip ); // Handle dual-stack addresses
				}
				$current_user_ip = inet_pton( $current_user_ip ); // Parse the remote ip
				foreach ( $allowed_ips as $line ) {
					list( $ip, $mask ) = explode( '/', $line . '/128' ); // get the ip and mask from the list
					$mask = str_repeat( 'f', $mask >> 2 ); //render the mask as bits, similar to info on the php.net man page discussion for inet_pton
					switch ( $mask % 4 ) {
					case 1:
						$mask .= '8';
						break;
					case 2:
						$mask .= 'c';
						break;
					case 3:
						$mask .= 'e';
						break;
					}
					$mask = pack( 'H*', $mask );
					// check if the masked versions match
					if ( ( inet_pton( $ip ) & $mask ) == ( $current_user_ip & $mask ) ) {
						return;
					}
				}
			}

			// We've determined that the current user doesn't have access, so we deal with them now.

			if ( $logged_in_but_no_access ) {
				$error = 'Sorry, it seems you don\'t have access to ' . get_bloginfo( 'name' ) . '. If this is a mistake, please contact your instructor and have them add you to their Sakai/Laulima course.';
				update_option( 'lsa_settings_misc_login_error', $error );
				wp_logout();
				wp_redirect( wp_login_url(), 302 );
				exit;
			}

			switch ( $lsa_settings['access_redirect'] ) :
			case 'url':
				wp_redirect( $lsa_settings['access_redirect_to_url'], 302 );
				exit;
			case 'message':
				wp_die( $lsa_settings['access_redirect_to_message'], get_bloginfo( 'name' ) . ' - Site Access Restricted' );
				break;
			case 'page':
				$page_id = get_post_field( 'ID', $lsa_settings['access_redirect_to_page'] );
				if ( is_wp_error( $page_id ) ) {
					wp_die( '<p>Access to this site is restricted.</p>', get_bloginfo( 'name' ) . ' - Site Access Restricted' );
				}
				unset( $wp->query_vars );
				$wp->query_vars['page_id'] = $page_id;
				return;
			case 'login':
			default:
				$current_path = empty( $_SERVER['REQUEST_URI'] ) ? home_url() : $_SERVER['REQUEST_URI'];
				wp_redirect( wp_login_url( $current_path ), 302 );
				exit;
			endswitch;

			// Sanity check: we should never get here
			wp_die( '<p>Access denied.</p>', 'Site Access Restricted' );
		}

		/**
		 * Determine if current user is enrolled in one of the allowed sakai courses.
		 *
		 * @returns BOOL true if the currently logged in user is enrolled in one of the sakai courses listed in the plugin options.
		 */
		function is_current_user_sakai_enrolled( $current_user = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );

			if ( $current_user === '' ) {
				$current_user = get_current_user_id();
			}

			// Sanity check: only evaluate if access restriction is set to 'course' (not 'everyone' or 'university')
			if ( $lsa_settings['access_restriction'] == 'everyone' || $lsa_settings['access_restriction'] == 'university' ) {
				return true;
			}
			$has_access = false;

			$sakai_session_id = get_user_meta( $current_user, 'sakai_session_id', true );
			foreach ( $lsa_settings['access_courses'] as $sakai_site_id ) {
				$request_url = trailingslashit( $lsa_settings['sakai_base_url'] ) . 'site/' . $sakai_site_id . '/userPerms/site.visit.json';
				$permission_to_visit = $this->call_api(
					'get',
					$request_url,
					array(
						'sakai.session' => $sakai_session_id,
					)
				);
				if ( isset( $permission_to_visit ) ) {
					if ( strpos( 'HTTP Status 403', $permission_to_visit ) !== false ) {
						// couldn't get sakai info because not logged in, so don't check any more site ids
						$has_access = false;
						break;
					} else if ( strpos( 'HTTP Status 500', $permission_to_visit ) !== false ) {
						// couldn't get sakai info because no permissions (this seems like a wrong error code from laulima...)
					} else {
						$permission_to_visit = json_decode( $permission_to_visit );
						if ( isset( $permission_to_visit ) && property_exists( $permission_to_visit, 'data' ) && in_array( 'site.visit', $permission_to_visit->data ) ) {
							$has_access = true;
							break;
						}
					}
				}
			}

			// Store the result in user meta so we don't have to keep checking against sakai on every page load
			update_user_meta( $current_user, 'has_access', $has_access );

			// If this user has access, store the sakai course site id in his/her usermeta, so we have a
			// record that they were enrolled in that course.
			if ( $has_access ) {
				$enrolled_courses = get_user_meta( $current_user, 'enrolled_courses' );
				if ( ! in_array( $sakai_session_id, $enrolled_courses ) ) {
					$enrolled_courses[] = $sakai_session_id;
					update_user_meta( $current_user, 'enrolled_courses', $enrolled_courses );
				}
			}

			return $has_access;
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
			$settings_link = '<a href="options-general.php?page=cas_admission">Settings</a>';
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
				'CAS Admission', // Page title
				'CAS Admission', // Menu title
				'manage_options', // Capability
				'cas_admission', // Menu slug
				array( $this, 'create_admin_page' ) // function
			);
		}


		/**
		 * Output the HTML for the options page
		 */
		public function create_admin_page() {
			?>
			<div class="wrap">
				<?php screen_icon(); ?>
				<h2>CAS Admission Settings</h2>
				<form method="post" action="options.php" autocomplete="off">
					<?php
						// This prints out all hidden settings fields
						// @see http://codex.wordpress.org/Function_Reference/settings_fields
						settings_fields( 'lsa_settings_group' );
						// This prints out all the sections
						// @see http://codex.wordpress.org/Function_Reference/do_settings_sections
						do_settings_sections( 'cas_admission' );
					?>
					<?php submit_button(); ?>
				</form>
			</div>
			<?php
		}


		/**
		 * Load external resources on this plugin's options page.
		 * Run on action hook: load-settings_page_cas_admission
		 */
		public function load_options_page() {
			wp_enqueue_script(
				'cas_admission',
				plugins_url( 'assets/js/cas_admission.js', __FILE__ ),
				array( 'jquery-effects-shake' ), '5.0', true
			);

			wp_register_style( 'cas_admission-css', plugins_url( 'assets/css/cas_admission.css', __FILE__ ) );
			wp_enqueue_style( 'cas_admission-css' );

			add_action( 'admin_notices', array( $this, 'admin_notices' ) ); // Add any notices to the top of the options page.
			add_action( 'admin_head', array( $this, 'admin_head' ) ); // Add help documentation to the options page.
		}


		/**
		 * Load external resources on the wp-login.php page.
		 * Run on action hook: login_head
		 */
		function load_login_css_and_js() {
			$lsa_settings = get_option( 'lsa_settings' );

			if ( $lsa_settings['ldap_type'] === 'custom_uh' ):
				?>
				<link rel="stylesheet" type="text/css" href="<?php print plugins_url( 'assets/css/cas_admission-login.css', __FILE__ ); ?>" />
				<script type="text/javascript" src="<?php print plugins_url( 'assets/js/cas_admission-login.js', __FILE__ ); ?>"></script>
				<?php
			endif;
		}


		/**
		 * Add notices to the top of the options page.
		 * Run on action hook chain: load-settings_page_cas_admission > admin_notices
		 @todo: add warning messages.
		 */
		public function admin_notices() {
			// Check for invalid settings combinations and show a warning message, e.g.:
			// if (sakai base url inaccessible) {
			//   print "<div class='updated settings-error'><p>Can't reach Sakai.</p></div>";
			// }
		}


		/**
		 * Add help documentation to the options page.
		 * Run on action hook chain: load-settings_page_cas_admission > admin_head
		 @todo: add documentation.
		 */
		public function admin_head() {
			$screen = get_current_screen();
			
			// Add help tab for LDAP Settings
			$help_lsa_settings_ldap_content = '
				<p><strong>LDAP Host</strong>: Enter the URL of the LDAP server you authenticate against.</p>
				<p><strong>LDAP Search Base</strong>: Enter the LDAP string that represents the search base, e.g., ou=people,dc=yourcompany,dc=com</p>
				<p><strong>LDAP Directory User</strong>: Enter the name of the LDAP user that has permissions to browse the directory.</p>
				<p><strong>LDAP Directory User Password</strong>: Enter the password for the LDAP user that has permission to browse the directory.</p>
				<p><strong>LDAP Installation type</strong>: Select whether your LDAP server is running an Active Directory-compatible LDAP instance, or an OpenLDAP-compatible instance.</p>
				<p><strong>Secure Connection (TLS)</strong>: Select whether all communication with the LDAP server should be performed over a TLS-secured connection.</p>
			';

			$screen->add_help_tab(
				array(
					'id' => 'help_lsa_settings_ldap',
					'title' => 'LDAP Settings',
					'content' => $help_lsa_settings_ldap_content,
				)
			);

			// Add help tab for Sakai Settings

			// Add help tab for Access Settings      
		}


		/**
		 * validate IP address entry on demand (AJAX)
		 */
		public function ajax_lsa_ip_check() {
			if ( empty( $_POST['ip_address'] ) ) {
				die('1');
			} else if ( $this->is_ip( stripslashes( $_POST['ip_address'] ) ) ) {
				die; // success
			} else {
				die('1');
			}
		}

		/**
		 * Is it a valid IP address? v4/v6 with subnet range
		 */
		public function is_ip( $ip_address ) {
			// very basic validation of ranges
			if ( strpos( $ip_address, '/' ) )
			{
				$ip_parts = explode( '/', $ip_address );
				if ( empty( $ip_parts[1] ) || !is_numeric( $ip_parts[1] ) || strlen( $ip_parts[1] ) > 3 )
					return false;
				$ip_address = $ip_parts[0];
			}

			// confirm IP part is a valid IPv6 or IPv4 IP
			if ( empty( $ip_address ) || !inet_pton( stripslashes( $ip_address ) ) )
				return false;

			return true;
		}


		/**
		 * Validate Sakai Site ID entry on demand (AJAX)
		 */
		public function ajax_lsa_course_check() {
			if ( empty( $_POST['sakai_site_id'] ) || empty( $_POST['sakai_base_url'] ) ) {
				die('&nbsp;');
			}

			$request_url = trailingslashit( $_POST['sakai_base_url'] ) . 'site/' . $_POST['sakai_site_id'] . '.json';
			$sakai_session_id = get_user_meta( get_current_user_id(), 'sakai_session_id', true );
			$course_details = $this->call_api(
				'get',
				$request_url,
				array(
					'sakai.session' => $sakai_session_id,
				)
			);
			if ( isset( $course_details ) ) {
				if ( strpos( 'HTTP Status 403', $course_details ) !== false ) {
					// couldn't get sakai info because not logged in
					die( '[Unknown course]' );
				} else {
					$course_details = json_decode( $course_details );
					if ( isset( $course_details ) && property_exists( $course_details, 'entityTitle' ) ) {
						die( $course_details->entityTitle ); // success
					} else {
						die( '[Unknown course]' ); // success
					}
				}
			} else {
				die( '1' );
			}
		}


		/**
		 * Wrapper for a RESTful call.
		 * Method: POST, PUT, GET etc
		 * Data: array( "param" => "value" ) ==> index.php?param=value
		 */
		private function call_api( $method, $url, $data = false ) {
			$curl = curl_init();
			switch ( strtoupper( $method ) ) {
				case 'POST':
					curl_setopt( $curl, CURLOPT_POST, 1 );
					if ( $data )
							curl_setopt( $curl, CURLOPT_POSTFIELDS, $data );
					break;
				case 'PUT':
					curl_setopt( $curl, CURLOPT_PUT, 1 );
					break;
				default:
					if ($data)
						$url = sprintf( '%s?%s', $url, http_build_query( $data ) );
			}

			// Optional Authentication:
			//curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
			//curl_setopt($curl, CURLOPT_USERPWD, "username:password");

			curl_setopt( $curl, CURLOPT_URL, $url );
			curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );
			return curl_exec( $curl );
		}


		/**
		 * Create sections and options
		 * Run on action hook: admin_init
		 */
		public function page_init() {
			// Create one setting that holds all the options (array)
			// @see http://codex.wordpress.org/Function_Reference/register_setting
			register_setting(
				'lsa_settings_group', // Option group
				'lsa_settings', // Option name
				array( $this, 'sanitize_lsa_settings' ) // Sanitize callback
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'lsa_settings_access', // HTML element ID
				'Access Settings', // HTML element Title
				array( $this, 'print_section_info_access' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_field
			add_settings_field(
				'lsa_settings_access_default_role', // HTML element ID
				'Default role for new LDAP users', // HTML element Title
				array( $this, 'print_select_lsa_access_default_role' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_access_restriction', // HTML element ID
				'Which people can access the site?', // HTML element Title
				array( $this, 'print_radio_lsa_access_restriction' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_access_courses', // HTML element ID
				'Course Site IDs with access (one per line)', // HTML element Title
				array( $this, 'print_combo_lsa_access_courses' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_access_redirect', // HTML element ID
				'What happens to people without access?', // HTML element Title
				array( $this, 'print_radio_lsa_access_redirect' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_access_redirect_to_url', // HTML element ID
				'Redirect to URL', // HTML element Title
				array( $this, 'print_text_lsa_access_redirect_to_url' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_access_redirect_to_page', // HTML element ID
				'Redirect to restricted notice page', // HTML element Title
				array( $this, 'print_select_lsa_access_redirect_to_page' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_access_redirect_to_message', // HTML element ID
				'Restriction message', // HTML element Title
				array( $this, 'print_wysiwyg_lsa_access_redirect_to_message' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_access' // Section this setting is shown on
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'lsa_settings_ldap', // HTML element ID
				'LDAP Settings', // HTML element Title
				array( $this, 'print_section_info_ldap' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_field
			add_settings_field(
				'lsa_settings_ldap_host', // HTML element ID
				'LDAP Host', // HTML element Title
				array( $this, 'print_text_lsa_ldap_host' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_ldap' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_ldap_search_base', // HTML element ID
				'LDAP Search Base', // HTML element Title
				array( $this, 'print_text_lsa_ldap_search_base' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_ldap' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_ldap_user', // HTML element ID
				'LDAP Directory User', // HTML element Title
				array( $this, 'print_text_lsa_ldap_user' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_ldap' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_ldap_password', // HTML element ID
				'LDAP Directory User Password', // HTML element Title
				array( $this, 'print_password_lsa_ldap_password' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_ldap' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_ldap_type', // HTML element ID
				'LDAP installation type', // HTML element Title
				array( $this, 'print_radio_lsa_ldap_type' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_ldap' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_ldap_tls', // HTML element ID
				'Secure Connection (TLS)', // HTML element Title
				array( $this, 'print_checkbox_lsa_ldap_tls' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_ldap' // Section this setting is shown on
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'lsa_settings_sakai', // HTML element ID
				'Sakai Settings', // HTML element Title
				array( $this, 'print_section_info_sakai' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_field
			add_settings_field(
				'lsa_settings_sakai_base_url', // HTML element ID
				'Sakai Base URL', // HTML element Title
				array( $this, 'print_text_lsa_sakai_base_url' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_sakai' // Section this setting is shown on
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'lsa_settings_misc', // HTML element ID
				'Advanced Settings', // HTML element Title
				array( $this, 'print_section_info_misc' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			add_settings_field(
				'lsa_settings_misc_lostpassword_url', // HTML element ID
				'Custom LDAP Lost Password URL', // HTML element Title
				array( $this, 'print_text_lsa_misc_lostpassword_url' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_misc' // Section this setting is shown on
			);
			add_settings_field(
				'lsa_settings_misc_ips', // HTML element ID
				'Unrestricted IP addresses', // HTML element Title
				array( $this, 'print_combo_lsa_misc_ips' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'lsa_settings_misc' // Section this setting is shown on
			);
		}


		/**
		 * Settings sanitizer callback
		 @todo: add sanitizer filters for the different options fields.
		 */
		function sanitize_lsa_settings( $lsa_settings ) {
			// Sanitize LDAP Host setting
			if ( filter_var( $lsa_settings['ldap_host'], FILTER_SANITIZE_URL ) === FALSE ) {
				$lsa_settings['ldap_host'] = '';
			}
			// Obfuscate LDAP directory user password
			if ( strlen( $lsa_settings['ldap_password'] ) > 0 ) {
				// base64 encode the directory user password for some minor obfuscation in the database.
				$lsa_settings['ldap_password'] = base64_encode( $this->encrypt( $lsa_settings['ldap_password'] ) );
			}
			// Default to "Everyone" access restriction
			if ( !in_array( $lsa_settings['access_restriction'], array( 'everyone', 'university', 'course', 'user' ) ) ) {
				$lsa_settings['access_restriction'] = 'everyone';
			}
			// Sanitize ABC setting
			if ( false ) {
				$lsa_settings['somesetting'] = '';
			}

			return $lsa_settings;
		}


		/**
		 * Settings print callbacks
		 */
		function print_section_info_ldap() {
			print 'Enter your LDAP server settings below:';
		}
		function print_text_lsa_ldap_host( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="text" id="lsa_settings_ldap_host" name="lsa_settings[ldap_host]" value="<?= $lsa_settings['ldap_host']; ?>" /><?php
		}
		function print_text_lsa_ldap_search_base( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="text" id="lsa_settings_ldap_search_base" name="lsa_settings[ldap_search_base]" value="<?= $lsa_settings['ldap_search_base']; ?>" style="width:225px;" /><?php
		}
		function print_text_lsa_ldap_user( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="text" id="lsa_settings_ldap_user" name="lsa_settings[ldap_user]" value="<?= $lsa_settings['ldap_user']; ?>" style="width:275px;" /><?php
		}
		function print_password_lsa_ldap_password( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="password" id="lsa_settings_ldap_password" name="lsa_settings[ldap_password]" value="<?= $this->decrypt(base64_decode($lsa_settings['ldap_password'])); ?>" /><?php
		}
		function print_radio_lsa_ldap_type( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="radio" name="lsa_settings[ldap_type]" value="ad"<?php checked( 'ad' == $lsa_settings['ldap_type'] ); ?> /> Active Directory<br />
				<input type="radio" name="lsa_settings[ldap_type]" value="openldap"<?php checked( 'openldap' == $lsa_settings['ldap_type'] ); ?> /> OpenLDAP<br />
				<input type="radio" name="lsa_settings[ldap_type]" value="custom_uh"<?php checked( 'custom_uh' == $lsa_settings['ldap_type'] ); ?> /> Custom: University of Hawai'i<?php
		}
		function print_checkbox_lsa_ldap_tls( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="checkbox" name="lsa_settings[ldap_tls]" value="1"<?php checked( 1 == $lsa_settings['ldap_tls'] ); ?> /> Use TLS<?php
		}

		function print_section_info_sakai() {
			print 'Enter your Sakai-based course management system settings below:';
		}
		function print_text_lsa_sakai_base_url( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="text" id="lsa_settings_sakai_base_url" name="lsa_settings[sakai_base_url]" value="<?= $lsa_settings['sakai_base_url']; ?>" style="width:275px;" /><?php
		}

		function print_section_info_access() {
			print 'Choose how you want to restrict access to this site below:';
		}
		function print_radio_lsa_access_restriction( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="radio" id="radio_lsa_settings_access_restriction_everyone" name="lsa_settings[access_restriction]" value="everyone"<?php checked( 'everyone' == $lsa_settings['access_restriction'] ); ?> /> Everyone<br />
				<input type="radio" id="radio_lsa_settings_access_restriction_university" name="lsa_settings[access_restriction]" value="university"<?php checked( 'university' == $lsa_settings['access_restriction'] ); ?> /> Only the university community (All LDAP and WP users)<br />
				<input type="radio" id="radio_lsa_settings_access_restriction_course" name="lsa_settings[access_restriction]" value="course"<?php checked( 'course' == $lsa_settings['access_restriction'] ); ?> /> Only students enrolled in specific courses (LDAP/Sakai)<br />
				<input type="radio" id="radio_lsa_settings_access_restriction_user" name="lsa_settings[access_restriction]" value="user"<?php checked( 'user' == $lsa_settings['access_restriction'] ); ?> /> Only WP users in this site<br /><?php
		}
		/**
		@todo: migrate this to a combo tool like below in Unrestricted IP addresses
		*/
		function print_combo_lsa_access_courses( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><ul id="list_lsa_settings_access_courses" style="margin:0;">
				<?php if ( array_key_exists( 'access_courses', $lsa_settings ) && is_array( $lsa_settings['access_courses'] ) ) : ?>
					<?php foreach ( $lsa_settings['access_courses'] as $key => $course_id ): ?>
						<?php if (empty($course_id)) continue; ?>
						<li>
							<input type="text" id="lsa_settings_access_courses_<?= $key; ?>" name="lsa_settings[access_courses][]" value="<?= esc_attr( $course_id ); ?>" readonly="true" style="width: 275px;" />
							<input type="button" class="button" id="remove_course_<?= $key; ?>" onclick="lsa_remove_course(this);" value="&minus;" />
							<?php if ( strlen( $lsa_settings['sakai_base_url'] ) ): ?>
								<label for="lsa_settings_access_courses_<?= $key; ?>"><span class="description"></span></label>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
			<div id="new_lsa_settings_access_courses">
				<input type="text" name="newcourse" id="newcourse" placeholder="7017b553-3d21-46ac-ad5c-9a6c335b9a24" style="width: 275px;" />
				<input class="button" type="button" id="addcourse" onclick="lsa_add_course(jQuery('#newcourse').val());" value="+" /><br />
				<label for="newcourse"><span class="description">Enter a Site ID for a course with access</span></label>
			</div>
			<?php
		}
		function print_radio_lsa_access_redirect( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="radio" id="radio_lsa_settings_access_redirect_to_login" name="lsa_settings[access_redirect]" value="login"<?php checked( 'login' == $lsa_settings['access_redirect'] ); ?> /> Send them to the WordPress login screen<br />
				<input type="radio" id="radio_lsa_settings_access_redirect_to_url" name="lsa_settings[access_redirect]" value="url"<?php checked( 'url' == $lsa_settings['access_redirect'] ); ?> /> Redirect them to a specific URL<br />
				<input type="radio" id="radio_lsa_settings_access_redirect_to_page" name="lsa_settings[access_redirect]" value="page"<?php checked( 'page' == $lsa_settings['access_redirect'] ); ?> /> Show them a specific WordPress page<br />
				<input type="radio" id="radio_lsa_settings_access_redirect_to_message" name="lsa_settings[access_redirect]" value="message"<?php checked( 'message' == $lsa_settings['access_redirect'] ); ?> /> Show them a simple message<?php
		}
		function print_text_lsa_access_redirect_to_url( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="text" id="lsa_settings_access_redirect_to_url" name="lsa_settings[access_redirect_to_url]" value="<?= $lsa_settings['access_redirect_to_url']; ?>" placeholder="http://www.example.com/" /><?php
		}
		function print_wysiwyg_lsa_access_redirect_to_message( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			wp_editor(
				$lsa_settings['access_redirect_to_message'],
				'lsa_settings_access_redirect_to_message',
				array(
					'media_buttons' => false,
					'textarea_name' => 'lsa_settings[access_redirect_to_message]',
					'textarea_rows' => 5,
					'tinymce' => false,
				)
			);
		}
		function print_select_lsa_access_redirect_to_page( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			wp_dropdown_pages(
				array( 
					'selected' => $lsa_settings['access_redirect_to_page'],
					'show_option_none' => 'Select a page',
					'name' => 'lsa_settings[access_redirect_to_page]',
					'id' => 'lsa_settings_access_redirect_to_page',
				)
			);
		}
		function print_select_lsa_access_default_role( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><select id="lsa_settings_access_default_role" name="lsa_settings[access_default_role]">
				<?php wp_dropdown_roles( $lsa_settings['access_default_role'] ); ?>
			</select><?php
		}

		function print_section_info_misc() {
			print 'You may optionally specify some advanced settings below:';
		}
		function print_combo_lsa_misc_ips( $args = '' ) {
			$lsa_settings = get_option( 'lsa_settings' );
			?><ul id="list_lsa_settings_misc_ips" style="margin:0;">
				<?php if ( array_key_exists( 'misc_ips', $lsa_settings ) && is_array( $lsa_settings['misc_ips'] ) ) : ?>
					<?php foreach ( $lsa_settings['misc_ips'] as $key => $ip ): ?>
						<?php if ( empty( $ip ) ) continue; ?>
						<li>
							<input type="text" id="lsa_settings_misc_ips_<?= $key; ?>" name="lsa_settings[misc_ips][]" value="<?= esc_attr($ip); ?>" readonly="true" />
							<input type="button" class="button" id="remove_ip_<?= $key; ?>" onclick="lsa_remove_ip(this);" value="&minus;" />
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
			<div id="new_lsa_settings_misc_ips">
				<input type="text" name="newip" id="newip" placeholder="127.0.0.1" />
				<input class="button" type="button" id="addip" onclick="lsa_add_ip(jQuery('#newip').val());" value="+" />
				<label for="newip"><span class="description"></span></label>
				<?php if ( !empty( $_SERVER['REMOTE_ADDR'] ) ): ?>
					<br /><input class="button" type="button" onclick="lsa_add_ip('<?= esc_attr($_SERVER['REMOTE_ADDR']); ?>');" value="Add My Current IP Address" /><br />
				<?php endif; ?>
			</div>
			<?php
		}
		function print_text_lsa_misc_lostpassword_url() {
			$lsa_settings = get_option( 'lsa_settings' );
			?><input type="text" id="lsa_settings_misc_lostpassword_url" name="lsa_settings[misc_lostpassword_url]" value="<?= $lsa_settings['misc_lostpassword_url']; ?>" placeholder="http://www.example.com/" /><?php
		}


		/**
		 ****************************
		 * Dashboard widget
		 ****************************
		 */
		function add_dashboard_widgets() {
			// Only users who can edit can see the Sakai dashboard widget
			if ( current_user_can( 'edit_post' ) ) {
				// Add dashboard widget for adding/editing sakai courses with access
				wp_add_dashboard_widget( 'sakai_dashboard_widget', 'Course Access Settings', array( $this, 'add_sakai_dashboard_widget' ) );
			}
		}

		function add_sakai_dashboard_widget() {
			$lsa_settings = get_option( 'lsa_settings' );
			?>
			<div class="inside">
				<form method="post" id="lsa_settings_access_form" action="">
					<p><?php $this->print_section_info_access(); ?></p>
					<div><?php $this->print_radio_lsa_access_restriction(); ?></div>
					<br class="clear" />
					<div><?php $this->print_combo_lsa_access_courses(); ?></div>
					<br class="clear" />
					<p class="submit">
						<span class="save-action">
							<input type="button" name="button_save_lsa_settings_access" id="button_save_lsa_settings_access" class="button-primary" value="Save" onclick="save_lsa_settings_access(this);" style="float: right;" />
							<span class="spinner"></span>
						</span>
						<?php wp_nonce_field( 'save_lsa_settings_access', 'nonce_save_lsa_settings_access' ); ?>
						<input type="hidden" id="lsa_settings_sakai_base_url" name="lsa_settings[sakai_base_url]" value="<?php print $lsa_settings['sakai_base_url']; ?>" />
					</p>
					<br class="clear" />
				</form>
			</div>
			<?php
		}

		function ajax_save_sakai_dashboard_widget() {
			// Make sure posted variables exist.
			if ( empty( $_POST['access_restriction'] ) || empty( $_POST['access_courses'] ) || empty( $_POST['nonce_save_lsa_settings_access'] ) ) {
				die('');
			}

			// Nonce check.
			if ( ! wp_verify_nonce( $_POST['nonce_save_lsa_settings_access'], 'save_lsa_settings_access' ) ) {
				die('');
			}

			// If invalid input, set access restriction to only WP users.
			if ( ! in_array( $_POST['access_restriction'], array( 'everyone', 'university', 'course', 'user' ) ) ) {
				$_POST['access_restriction'] = 'user';
			}

			$lsa_settings = get_option( 'lsa_settings' );

			$lsa_settings['access_restriction'] = stripslashes( $_POST['access_restriction'] );
			$lsa_settings['access_courses'] = $_POST['access_courses'];
			$lsa_settings['ldap_password'] = $this->decrypt( base64_decode( $lsa_settings['ldap_password'] ) );

			// Only users who can edit can see the Sakai dashboard widget
			if ( current_user_can( 'edit_post' ) ) {
				update_option( 'lsa_settings', $lsa_settings );
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

	} // END class WP_Plugin_CAS_Admission
}


/**
 * inet_pton is not included in PHP < 5.3 on Windows (WP requires PHP 5.2)
 */
if ( ! function_exists( 'inet_pton' ) ) :
	function inet_pton( $ip ) {
		if ( strpos( $ip, '.' ) !== false ) {
			// ipv4
			$ip = pack( 'N', ip2long( $ip ) );
		} elseif ( strpos( $ip, ':' ) !== false ) {
			// ipv6
			$ip = explode( ':', $ip );
			$res = str_pad( '', ( 4 * ( 8 - count( $ip ) ) ), '0000', STR_PAD_LEFT );
			foreach ( $ip as $seg ) {
				$res .= str_pad( $seg, 4, '0', STR_PAD_LEFT );
			}
			$ip = pack( 'H'.strlen( $res ), $res );
		}
		return $ip;
	}
endif;


// Installation and uninstallation hooks.
register_activation_hook( __FILE__, array( 'WP_Plugin_CAS_Admission', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WP_Plugin_CAS_Admission', 'deactivate' ) );
register_uninstall_hook( __FILE__, array( 'WP_Plugin_CAS_Admission', 'uninstall' ) );


// Instantiate the plugin class.
$wp_plugin_cas_admission = new WP_Plugin_CAS_Admission();
