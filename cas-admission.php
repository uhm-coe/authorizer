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
Copyright 2013  Paul Ryan  (email: prar@hawaii.edu)

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
Portions forked from wpCAS plugin:  http://wordpress.org/extend/plugins/cas-authentication/
*/


// Add phpCAS library if it's not included.
// @see https://wiki.jasig.org/display/CASC/phpCAS+installation+guide
if ( ! defined( 'PHPCAS_VERSION' ) ) {
	include_once dirname(__FILE__) . '/assets/inc/CAS-1.3.2/CAS.php';
}


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
			// Register filters.

			// Custom wp authentication routine using CAS
			add_filter( 'authenticate', array( $this, 'cas_authenticate' ), 1, 3 );

			// Custom logout action using CAS
			add_action( 'wp_logout', array( $this, 'cas_logout' ) );

			// Removing this bypasses Wordpress authentication (so if CAS auth fails,
			// no one can log in); with it enabled, it will run if CAS auth fails.
			//remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

			// Create settings link on Plugins page
			add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'plugin_settings_link' ) );

			// Modify login page to help users use CAS to log in
			if ( strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ) {
				add_filter( 'lostpassword_url', array( $this, 'custom_lostpassword_url' ) );
				add_filter( 'gettext', array( $this, 'custom_login_form_labels' ), 20, 3 );
			}

			// If we have a custom login error, add the filter to show it.
			$error = get_option( 'cas_settings_misc_login_error' );
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

			// ajax save options from dashboard widget
			add_action( 'wp_ajax_save_admission_dashboard_widget', array( $this, 'ajax_save_admission_dashboard_widget' ) );

			// Add dashboard widget so instructors can add/edit users with access.
			// Hint: For Multisite Network Admin Dashboard use wp_network_dashboard_setup instead of wp_dashboard_setup.
			add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widgets' ) );

			// If we have a custom admin message, add the action to show it.
			$notice = get_option( 'cas_settings_misc_admin_notice' );
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
			$cas_settings = get_option( 'cas_settings' );
			if ( $cas_settings === FALSE ) {
				$cas_settings = array();
			}

			if ( !array_key_exists( 'access_default_role', $cas_settings ) ) {
				// Set default role to 'student' if that role exists, 'subscriber' otherwise.
				$all_roles = $wp_roles->roles;
				$editable_roles = apply_filters( 'editable_roles', $all_roles );
				if ( array_key_exists( 'student', $editable_roles ) ) {
					$cas_settings['access_default_role'] = 'student';
				} else if ( array_key_exists( 'subscriber', $editable_roles ) ) {
					$cas_settings['access_default_role'] = 'subscriber';
				} else {
					$cas_settings['access_default_role'] = 'subscriber';
				}
			}
			if ( !array_key_exists( 'access_restriction', $cas_settings ) ) {
				$cas_settings['access_restriction'] = 'everyone';
			}
			if ( !array_key_exists( 'access_users_pending', $cas_settings ) ) {
				$cas_settings['access_users_pending'] = array();
			}
			if ( !array_key_exists( 'access_users_approved', $cas_settings ) ) {
				$cas_settings['access_users_approved'] = array();
			}
			if ( !array_key_exists( 'access_users_blocked', $cas_settings ) ) {
				$cas_settings['access_users_blocked'] = array();
			}
			if ( !array_key_exists( 'access_redirect', $cas_settings ) ) {
				$cas_settings['access_redirect'] = 'login';
			}
			if ( !array_key_exists( 'access_redirect_to_message', $cas_settings ) ) {
				$cas_settings['access_redirect_to_message'] = '<p>Access to this site is restricted.</p>';
			}
			if ( !array_key_exists( 'access_redirect_to_page', $cas_settings ) ) {
				$cas_settings['access_redirect_to_page'] = '';
			}

			if ( !array_key_exists( 'cas_host', $cas_settings ) ) {
				$cas_settings['cas_host'] = '';
			}
			if ( !array_key_exists( 'cas_port', $cas_settings ) ) {
				$cas_settings['cas_port'] = '';
			}
			if ( !array_key_exists( 'cas_path', $cas_settings ) ) {
				$cas_settings['cas_path'] = '';
			}

			if ( !array_key_exists( 'misc_lostpassword_url', $cas_settings ) ) {
				$cas_settings['misc_lostpassword_url'] = '';
			}
			if ( !array_key_exists( 'misc_branding', $cas_settings ) ) {
				$cas_settings['misc_branding'] = 'default';
			}

			update_option( 'cas_settings', $cas_settings );
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
			if ( get_option( 'cas_settings' ) ) {
				delete_option( 'cas_settings' );
			}
			if ( get_option( 'cas_settings_misc_admin_notice' ) ) {
				delete_option( 'cas_settings_misc_admin_notice' );
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
			$cas_settings = get_option( 'cas_settings' );
			if (
				array_key_exists( 'misc_lostpassword_url', $cas_settings ) &&
				filter_var( $cas_settings['misc_lostpassword_url'], FILTER_VALIDATE_URL ) &&
				array_key_exists( 'access_restriction', $cas_settings ) &&
				$cas_settings['access_restriction'] !== 'everyone' &&
				$cas_settings['access_restriction'] !== 'user'
			) {
				$lostpassword_url = $cas_settings['misc_lostpassword_url'];
			}
			return $lostpassword_url;
		}

		/**
		 * Overwrite the username and password labels on the login form.
		 */
		function custom_login_form_labels( $translated_text, $text, $domain ) {
			$cas_settings = get_option( 'cas_settings' );

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
		function show_misc_admin_notice() {
			$notice = get_option( 'cas_settings_misc_admin_notice' );
			delete_option( 'cas_settings_misc_admin_notice' );

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
			$error = get_option( 'cas_settings_misc_login_error' );
			delete_option( 'cas_settings_misc_login_error' );

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
		 * Authenticate using CAS credentials.
		 *
		 * @param WP_User $user     user to authenticate
		 * @param string  $username optional username to authenticate.
		 * @param string  $password optional password to authenticate.
		 *
		 * @return WP_User or WP_Error
		 */
		public function cas_authenticate( $user, $username, $password ) {
			// Pass through if already authenticated.
			if ( is_a( $user, 'WP_User' ) ) {
				return $user;
			} else {
				$user = null;
			}

			// Admin bypass: skip cas login and proceed to WordPress login if
			// querystring variable 'cas' is set to 'no' or 'false'--for example:
			// https://www.example.com/wp-login.php?cas=no
			if ( ! empty($_GET['cas'] ) && ( $_GET['cas'] === 'no' || $_GET['cas'] === 'false' ) ) {
				return new WP_Error( 'no_cas', 'Bypassing CAS authentication in favor of WordPress authentication...' );
			}

			// Grab plugin settings.
			$cas_settings = get_option( 'cas_settings' );

			// If we're restricting access to only WP users, don't check against CAS;
			// Instead, pass through to default WP authentication.
			if ( $cas_settings['access_restriction'] === 'user' ) {
				return new WP_Error( 'no_cas', 'Moving on to WordPress authentication...' );
			}

			// Set the CAS client configuration
			phpCAS::client( CAS_VERSION_2_0, $cas_settings['cas_host'], intval($cas_settings['cas_port']), $cas_settings['cas_path'] );

			// Add server certificate bundle to ensure CAS server is legitimate.
			phpCAS::setCasServerCACert( plugin_dir_path( __FILE__ ) . 'assets/inc/ca-bundle.crt' );

			// Authenticate against CAS
			if ( ! phpCAS::isAuthenticated() ) {
				phpCAS::forceAuthentication();
				die();
			}

			// Get the TLD from the CAS host for use in matching email addresses
			// For example: hawaii.edu is the TLD for login.its.hawaii.edu, so user
			// 'bob' will have the following email address: bob@hawaii.edu.
			$tld = preg_match( '/[^.]*\.[^.]*$/', $cas_settings['cas_host'], $matches ) === 1 ? $matches[0] : '';

			// Check if the CAS user has a WordPress account (with the same username or email address)
			if ( ! $user ) {
				$user = get_user_by( 'login', phpCAS::getUser() );
			}
			if ( ! $user ) {
				$user = get_user_by( 'email', phpCAS::getUser() . '@' . $tld );
			}

			// If we've made it this far, we have a CAS authenticated user. Deal with
			// them differently based on which list they're in (pending, blocked, or
			// approved).
			if ( $this->is_username_in_list( phpCAS::getUser(), 'blocked' ) ) {
				// The user is in the blocked list, so show them a message or redirect them (based on plugin options)

				/**
				@todo
				*/
				// If the blocked CAS user has a WordPress account, remove it. In a
				// multisite environment, just remove them from the current blog.
				if ( $user ) {
				}

				// Notify user about blocked status
				$error = 'Sorry ' . phpCAS::getUser() . ', it seems you don\'t have access to ' . get_bloginfo( 'name' ) . '. If this is a mistake, please contact your instructor.';
				update_option( 'cas_settings_misc_login_error', $error );
				wp_logout();
				wp_redirect( wp_login_url(), 302 );
				exit;
			} else if ( $this->is_username_in_list( phpCAS::getUser(), 'approved' ) ) {
				// If the approved CAS user does not have a WordPress account, create it
				if ( ! $user ) {
					$result = wp_insert_user(
						array(
							'user_login' => phpCAS::getUser(),
							'user_pass' => wp_generate_password(), // random password
							'first_name' => '',
							'last_name' => '',
							'user_email' => phpCAS::getUser() . '@' . $tld,
							'user_registered' => date( 'Y-m-d H:i:s' ),
							'role' => $cas_settings['access_default_role'],
						)
					);

					// Fail with message if error.
					if ( is_wp_error( $result ) ) {
						return $result;
					}

					// Authenticate as new user
					$user = new WP_User( $result );
				}
			} else if ( $user && ( ! in_array( $cas_settings['access_default_role'], $user->roles ) && ! in_array( 'subscriber', $user->roles ) ) ) {
				// User has a WordPress account, but is not in the blocked or approved
				// list. If they are any access level above the default CAS access
				// level (or the default subscriber role), let them in.
			} else {
				// User isn't an admin, is not blocked, and is not approved.
				// Add them to the pending list and notify them and their instructor.
				if ( ! $this->is_username_in_list( phpCAS::getUser(), 'pending' ) ) {
					$pending_user = array();
					$pending_user['username'] = phpCAS::getUser();
					$pending_user['email'] = phpCAS::getUser() . '@' . $tld;
					$pending_user['role'] = $cas_settings['access_default_role'];
					$pending_user['date_added'] = '';
					if ( ! is_array ( $cas_settings['access_users_pending'] ) ) {
						$cas_settings['access_users_pending'] = array();
					}
					array_push( $cas_settings['access_users_pending'], $pending_user );
					if ( current_user_can( 'edit_post' ) ) {
						update_option( 'cas_settings', $cas_settings );
					}

					// Notify instructor about new pending user
					/**
					@todo
					*/
				}

				// Notify user about pending status and return without authenticating them.
				$error = 'Sorry ' . phpCAS::getUser() . ', it seems you don\'t have access to ' . get_bloginfo( 'name' ) . '. If this is a mistake, please contact your instructor.';
				update_option( 'cas_settings_misc_login_error', $error );
				wp_logout();
				wp_redirect( wp_login_url(), 302 );
				exit;
			}

			// If we haven't exited yet, we have a valid/approved user, so authenticate them.
			return $user;
		}


		/**
		 * Log out of CAS.
		 *
		 * @return void
		 */
		public function cas_logout() {
			// Grab plugin settings.
			$cas_settings = get_option( 'cas_settings' );

			// Set the CAS client configuration
			phpCAS::client( CAS_VERSION_2_0, $cas_settings['cas_host'], intval($cas_settings['cas_port']), $cas_settings['cas_path'] );

			// Log out of CAS.
			phpCAS::logout( array( 'url' => get_option( 'siteurl' ) ) );
		}



		/**
		 ****************************
		 * Access Restriction
		 ****************************
		 */


		/**
		 * Restrict access to WordPress site based on settings (everyone, university, approved_cas, user).
		 * Hook: parse_request http://codex.wordpress.org/Plugin_API/Action_Reference/parse_request
		 *
		 * @param array $wp WordPress object.
		 *
		 * @return void
		 */
		public function restrict_access( $wp ) {
			remove_action( 'parse_request', array( $this, 'restrict_access' ), 1 );	// only need it the first time

			$cas_settings = get_option( 'cas_settings' );

			$has_access = (
				// Always allow access if WordPress is installing
				( defined( 'WP_INSTALLING' ) && isset( $_GET['key'] ) ) ||
				// Always allow access to admins
				( is_admin() ) ||
				// Allow access if option is set to 'everyone'
				( $cas_settings['access_restriction'] == 'everyone' ) ||
				// Allow access to logged in users if option is set to 'university' community
				( $cas_settings['access_restriction'] == 'university' && $this->is_user_logged_in_and_blog_user() ) ||
				// Allow access to logged in users if option is set to WP users (note: when this is set, don't allow CAS log in elsewhere)
				( $cas_settings['access_restriction'] == 'user' && $this->is_user_logged_in_and_blog_user() ) ||
				// Allow access to approved CAS users and logged in users if option is set to 'approved_cas'
				( $cas_settings['access_restriction'] == 'approved_cas' && $this->is_user_logged_in_and_blog_user() )
			);
			$is_restricted = !$has_access;

			// Fringe case: User successfully logged in, but they aren't on the
			// 'approved' whitelist. Flag these users, and redirect them to their
			// profile page with a message (so we don't get into a redirect loop on
			// the wp-login.php page).
			$logged_in_but_no_access = false;
			if ( $this->is_user_logged_in_and_blog_user() && !$has_access && $cas_settings['access_restriction'] == 'approved_cas' ) {
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

			// We've determined that the current user doesn't have access, so we deal with them now.

			if ( $logged_in_but_no_access ) {
				$error = 'Sorry, it seems you don\'t have access to ' . get_bloginfo( 'name' ) . '. If this is a mistake, please contact your instructor.';
				update_option( 'cas_settings_misc_login_error', $error );
				wp_logout();
				wp_redirect( wp_login_url(), 302 );
				exit;
			}

			switch ( $cas_settings['access_redirect'] ) :
			case 'message':
				wp_die( $cas_settings['access_redirect_to_message'], get_bloginfo( 'name' ) . ' - Site Access Restricted' );
				break;
			case 'page':
				$page_id = get_post_field( 'ID', $cas_settings['access_redirect_to_page'] );
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
						settings_fields( 'cas_settings_group' );
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
				plugins_url( 'assets/js/cas-admission.js', __FILE__ ),
				array( 'jquery-effects-shake' ), '5.0', true
			);

			wp_register_style( 'cas-admission-css', plugins_url( 'assets/css/cas-admission.css', __FILE__ ) );
			wp_enqueue_style( 'cas-admission-css' );

			add_action( 'admin_notices', array( $this, 'admin_notices' ) ); // Add any notices to the top of the options page.
			add_action( 'admin_head', array( $this, 'admin_head' ) ); // Add help documentation to the options page.
		}



		/**
		 * Load external resources on the wp-login.php page.
		 * Run on action hook: login_head
		 */
		function load_login_css_and_js() {
			$cas_settings = get_option( 'cas_settings' );

			if ( $cas_settings['misc_branding'] === 'custom_uh' ):
				?>
				<link rel="stylesheet" type="text/css" href="<?php print plugins_url( 'assets/css/cas-admission-login.css', __FILE__ ); ?>" />
				<script type="text/javascript" src="<?php print plugins_url( 'assets/js/cas-admission-login.js', __FILE__ ); ?>"></script>
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
			
			// Add help tab for CAS Settings
			$help_cas_settings_cas_content = '
				<p><strong>CAS server hostname</strong>: Enter the hostname of the CAS server you authenticate against (e.g., login.its.hawaii.edu).</p>
				<p><strong>CAS server port</strong>: Enter the port on the CAS server to connect to (e.g., 443).</p>
				<p><strong>CAS server path/context</strong>: Enter the path to the login endpoint on the CAS server (e.g., /cas/login).</p>
			';
			$screen->add_help_tab(
				array(
					'id' => 'help_cas_settings_ldap',
					'title' => 'LDAP Settings',
					'content' => $help_cas_settings_cas_content,
				)
			);

			// Add help tab for Access Settings      
		}



		/**
		 * Create sections and options
		 * Run on action hook: admin_init
		 */
		public function page_init() {
			// Create one setting that holds all the options (array)
			// @see http://codex.wordpress.org/Function_Reference/register_setting
			register_setting(
				'cas_settings_group', // Option group
				'cas_settings', // Option name
				array( $this, 'sanitize_cas_settings' ) // Sanitize callback
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'cas_settings_access', // HTML element ID
				'Access Settings', // HTML element Title
				array( $this, 'print_section_info_access' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_field
			add_settings_field(
				'cas_settings_access_default_role', // HTML element ID
				'Default role for new CAS users', // HTML element Title
				array( $this, 'print_select_cas_access_default_role' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_access_restriction', // HTML element ID
				'Who can access the site?', // HTML element Title
				array( $this, 'print_radio_cas_access_restriction' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_access_users_pending', // HTML element ID
				'Pending CAS Users', // HTML element Title
				array( $this, 'print_combo_cas_access_users_pending' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_access_users_approved', // HTML element ID
				'Approved CAS Users', // HTML element Title
				array( $this, 'print_combo_cas_access_users_approved' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_access_users_blocked', // HTML element ID
				'Blocked CAS Users', // HTML element Title
				array( $this, 'print_combo_cas_access_users_blocked' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
/**
END TODO
*/
			add_settings_field(
				'cas_settings_access_redirect', // HTML element ID
				'What happens to people without access?', // HTML element Title
				array( $this, 'print_radio_cas_access_redirect' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_access_redirect_to_page', // HTML element ID
				'Redirect to restricted notice page', // HTML element Title
				array( $this, 'print_select_cas_access_redirect_to_page' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_access_redirect_to_message', // HTML element ID
				'Restriction message', // HTML element Title
				array( $this, 'print_wysiwyg_cas_access_redirect_to_message' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_access' // Section this setting is shown on
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'cas_settings_cas', // HTML element ID
				'CAS Settings', // HTML element Title
				array( $this, 'print_section_info_cas' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_field
			add_settings_field(
				'cas_settings_cas_host', // HTML element ID
				'CAS server hostname', // HTML element Title
				array( $this, 'print_text_cas_host' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_cas' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_cas_port', // HTML element ID
				'CAS server port', // HTML element Title
				array( $this, 'print_text_cas_port' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_cas' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_cas_path', // HTML element ID
				'CAS server path/context', // HTML element Title
				array( $this, 'print_text_cas_path' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_cas' // Section this setting is shown on
			);

			// @see http://codex.wordpress.org/Function_Reference/add_settings_section
			add_settings_section(
				'cas_settings_misc', // HTML element ID
				'Advanced Settings', // HTML element Title
				array( $this, 'print_section_info_misc' ), // Callback (echos section content)
				'cas_admission' // Page this section is shown on (slug)
			);

			add_settings_field(
				'cas_settings_misc_lostpassword_url', // HTML element ID
				'Custom LDAP Lost Password URL', // HTML element Title
				array( $this, 'print_text_cas_misc_lostpassword_url' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_misc' // Section this setting is shown on
			);
			add_settings_field(
				'cas_settings_misc_branding', // HTML element ID
				'Custom WordPress login branding', // HTML element Title
				array( $this, 'print_radio_cas_misc_branding' ), // Callback (echos form element)
				'cas_admission', // Page this setting is shown on (slug)
				'cas_settings_misc' // Section this setting is shown on
			);
		}



		/**
		 * Settings sanitizer callback
		 @todo: add sanitizer filters for the different options fields.
		 */
		function sanitize_cas_settings( $cas_settings ) {
			// Sanitize LDAP Host setting
			if ( filter_var( $cas_settings['cas_host'], FILTER_SANITIZE_URL ) === FALSE ) {
				$cas_settings['cas_host'] = '';
			}
			// Default to "Everyone" access restriction
			if ( !in_array( $cas_settings['access_restriction'], array( 'everyone', 'university', 'approved_cas', 'user' ) ) ) {
				$cas_settings['access_restriction'] = 'everyone';
			}

			// Sanitize ABC setting (template)
			// if ( false ) {
			// 	$cas_settings['somesetting'] = '';
			// }

			return $cas_settings;
		}



		/**
		 * Settings print callbacks
		 */

		function print_section_info_cas() {
			print '<p><span class="red">Important Note</span>: If you\'re configuring CAS for the first time, make sure you do <strong>not</strong> log out of your administrator account in WordPress until you are sure CAS works. You risk locking yourself out of your WordPress installation. Use a different browser (or incognito/safe-browsing mode) to test CAS logins, and leave your adminstrator account logged in here.</p>';
			print '<p>As a safeguard, you can always access the default WordPress login panel (and bypass CAS) by visiting wp-login.php?cas=no like so:<br />';
			print '<a href="' . wp_login_url() . '?cas=no' . '">' . wp_login_url() . '?cas=no' . '</a></p>';
			print '<p>Enter your CAS server settings below:</p>';
		}

		function print_text_cas_host( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="text" id="cas_settings_cas_host" name="cas_settings[cas_host]" value="<?= $cas_settings['cas_host']; ?>" placeholder="login.its.hawaii.edu" /><?php
		}

		function print_text_cas_port( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="text" id="cas_settings_cas_port" name="cas_settings[cas_port]" value="<?= $cas_settings['cas_port']; ?>" placeholder="443" style="width:50px;" /><?php
		}

		function print_text_cas_path( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="text" id="cas_settings_cas_path" name="cas_settings[cas_path]" value="<?= $cas_settings['cas_path']; ?>" placeholder="/cas" /><?php
		}


		function print_section_info_access() {
			print 'Choose how you want to restrict access to this site below:';
		}

		function print_radio_cas_access_restriction( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="radio" id="radio_cas_settings_access_restriction_everyone" name="cas_settings[access_restriction]" value="everyone"<?php checked( 'everyone' == $cas_settings['access_restriction'] ); ?> /> Everyone<br />
				<input type="radio" id="radio_cas_settings_access_restriction_university" name="cas_settings[access_restriction]" value="university"<?php checked( 'university' == $cas_settings['access_restriction'] ); ?> /> Only the university community (All CAS and all WordPress users)<br />
				<input type="radio" id="radio_cas_settings_access_restriction_approved_cas" name="cas_settings[access_restriction]" value="approved_cas"<?php checked( 'approved_cas' == $cas_settings['access_restriction'] ); ?> /> Only specific students below (Approved CAS and all WordPress users)<br />
				<input type="radio" id="radio_cas_settings_access_restriction_user" name="cas_settings[access_restriction]" value="user"<?php checked( 'user' == $cas_settings['access_restriction'] ); ?> /> Only users with prior access (No CAS and all WordPress users)<br /><?php
		}
/**
TODO: modify pending user code to show list of cas users who have successfully logged in but who aren't in the 'approved' list below.
*/
		function print_combo_cas_access_users_pending( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><ul id="list_cas_settings_access_users_pending" style="margin:0;">
				<?php if ( array_key_exists( 'access_users_pending', $cas_settings ) && is_array( $cas_settings['access_users_pending'] ) && count( $cas_settings['access_users_pending'] ) > 0 ) : ?>
					<?php foreach ( $cas_settings['access_users_pending'] as $key => $email ): ?>
						<?php if ( empty( $email ) ) continue; ?>
						<li>
							<input type="text" name="discard[]" value="<?= array_shift( explode( '@', $email ) ); ?>" readonly="true" style="width: 80px;" />
							<input type="text" id="cas_settings_access_users_pending_<?= $key; ?>" name="cas_settings[access_users_pending][]" value="<?= esc_attr( $email ); ?>" readonly="true" style="width: 180px;" />
							<input type="button" class="button" id="approve_user_<?= $key; ?>" onclick="cas_approve_user(jQuery(this).parent());" value="Approve" />
							<input type="button" class="button" id="block_user_<?= $key; ?>" onclick="cas_block_user(jQuery(this).parent());" value="Block" />
							<input type="button" class="button" id="ignore_user_<?= $key; ?>" onclick="cas_ignore_user(jQuery(this).parent());" value="X" />
						</li>
					<?php endforeach; ?>
				<?php else: ?>
						<li><em>No pending users</em></li>
				<?php endif; ?>
			</ul>
			<?php
		}

		function print_combo_cas_access_users_approved( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><ul id="list_cas_settings_access_users_approved" style="margin:0;">
				<?php if ( array_key_exists( 'access_users_approved', $cas_settings ) && is_array( $cas_settings['access_users_approved'] ) ) : ?>
					<?php foreach ( $cas_settings['access_users_approved'] as $key => $approved_user ): ?>
						<?php if ( empty( $approved_user ) || count( $approved_user ) < 1 ) continue; ?>
						<?php if ( $approved_wp_user = get_user_by( 'email', $approved_user['email'] ) ): ?>
							<?php $approved_user['username'] = $approved_wp_user->user_login; ?>
							<?php $approved_user['email'] = $approved_wp_user->user_email; ?>
							<?php $approved_user['role'] = array_shift( $approved_wp_user->roles ); ?>
							<?php $approved_user['date_added'] = $approved_wp_user->user_registered; ?>
							<?php $approved_user['is_wp_user'] = true; ?>
						<? else: ?>
							<?php $approved_user['is_wp_user'] = false; ?>
						<?php endif; ?>
						<li>
							<input type="text" name="cas_settings[access_users_approved][<?= $key; ?>][username]" value="<?= $approved_user['username'] ?>" readonly="true" style="width: 80px;" class="cas-username" />
							<input type="text" id="cas_settings_access_users_approved_<?= $key; ?>" name="cas_settings[access_users_approved][<?= $key; ?>][email]" value="<?= $approved_user['email']; ?>" readonly="true" style="width: 180px;" class="cas-email" />
							<select name="cas_settings[access_users_approved][<?= $key; ?>][role]" class="cas-role">
								<option value="<?= $approved_user['role']; ?>" selected="selected"><?= ucfirst( $approved_user['role'] ); ?></option>
							</select>
							<input type="text" name="cas_settings[access_users_approved][<?= $key; ?>][date_added]" value="<?= date( 'M Y', strtotime( $approved_user['date_added'] ) ); ?>" readonly="true" style="width: 65px;" class="cas-date-added" />
							<input type="button" class="button" id="ignore_user_<?= $key; ?>" onclick="cas_ignore_user(this);" value="x" />
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
			<div id="new_cas_settings_access_users_approved">
				<input type="text" name="new_approved_user_name" id="new_approved_user_name" placeholder="username" style="width: 80px;" class="cas-username" />
				<input type="text" name="new_approved_user_email" id="new_approved_user_email" placeholder="email address" style="width: 180px;" class="cas-email" />
				<select name="new_approved_user_role" id="new_approved_user_role" class="cas-role">
					<option value="<?= $cas_settings['access_default_role']; ?>"><?= ucfirst( $cas_settings['access_default_role'] ); ?></option>
				</select>
				<input class="button-primary" type="button" id="approve_user_new" onclick="cas_add_user(this, 'approved');" value="Approve" /><br />
			</div>
			<?php
		}

		function print_combo_cas_access_users_blocked( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><ul id="list_cas_settings_access_users_blocked" style="margin:0;">
				<?php if ( array_key_exists( 'access_users_blocked', $cas_settings ) && is_array( $cas_settings['access_users_blocked'] ) ) : ?>
					<?php foreach ( $cas_settings['access_users_blocked'] as $key => $blocked_user ): ?>
						<?php if ( empty( $blocked_user ) || count( $blocked_user ) < 1 ) continue; ?>
						<?php if ( $blocked_wp_user = get_user_by( 'email', $blocked_user['email'] ) ): ?>
							<?php $blocked_user['username'] = $blocked_wp_user->user_login; ?>
							<?php $blocked_user['email'] = $blocked_wp_user->user_email; ?>
							<?php $blocked_user['role'] = array_shift( $blocked_wp_user->roles ); ?>
							<?php $blocked_user['date_added'] = $blocked_wp_user->user_registered; ?>
							<?php $blocked_user['is_wp_user'] = true; ?>
						<? else: ?>
							<?php $blocked_user['is_wp_user'] = false; ?>
						<?php endif; ?>
						<li>
							<input type="text" name="cas_settings[access_users_blocked][<?= $key; ?>][username]" value="<?= $blocked_user['username'] ?>" readonly="true" style="width: 80px;" class="cas-username" />
							<input type="text" id="cas_settings_access_users_blocked_<?= $key; ?>" name="cas_settings[access_users_blocked][<?= $key; ?>][email]" value="<?= $blocked_user['email']; ?>" readonly="true" style="width: 180px;" class="cas-email" />
							<select name="cas_settings[access_users_blocked][<?= $key; ?>][role]" class="cas-role">
								<option value="<?= $blocked_user['role']; ?>" selected="selected"><?= ucfirst( $blocked_user['role'] ); ?></option>
							</select>
							<input type="text" name="cas_settings[access_users_blocked][<?= $key; ?>][date_added]" value="<?= date( 'M Y', strtotime( $blocked_user['date_added'] ) ); ?>" readonly="true" style="width: 65px;" class="cas-date-added" />
							<input type="button" class="button" id="ignore_user_<?= $key; ?>" onclick="cas_ignore_user(this);" value="x" />
						</li>
					<?php endforeach; ?>
				<?php endif; ?>
			</ul>
			<div id="new_cas_settings_access_users_blocked">
				<input type="text" name="new_blocked_user_name" id="new_blocked_user_name" placeholder="username" style="width: 80px;" class="cas-username" />
				<input type="text" name="new_blocked_user_email" id="new_blocked_user_email" placeholder="email address" style="width: 180px;" class="cas-email" />
				<select name="new_blocked_user_role" id="new_blocked_user_role" class="cas-role">
					<option value="<?= $cas_settings['access_default_role']; ?>"><?= ucfirst( $cas_settings['access_default_role'] ); ?></option>
				</select>
				<input class="button-primary" type="button" id="block_user_new" onclick="cas_add_user(this, 'blocked');" value="Block" /><br />
			</div>
			<?php
		}

		function print_radio_cas_access_redirect( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="radio" id="radio_cas_settings_access_redirect_to_login" name="cas_settings[access_redirect]" value="login"<?php checked( 'login' == $cas_settings['access_redirect'] ); ?> /> Send them to the WordPress login screen<br />
				<input type="radio" id="radio_cas_settings_access_redirect_to_page" name="cas_settings[access_redirect]" value="page"<?php checked( 'page' == $cas_settings['access_redirect'] ); ?> /> Show them a specific WordPress page<br />
				<input type="radio" id="radio_cas_settings_access_redirect_to_message" name="cas_settings[access_redirect]" value="message"<?php checked( 'message' == $cas_settings['access_redirect'] ); ?> /> Show them a simple message<?php
		}

		function print_wysiwyg_cas_access_redirect_to_message( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			wp_editor(
				$cas_settings['access_redirect_to_message'],
				'cas_settings_access_redirect_to_message',
				array(
					'media_buttons' => false,
					'textarea_name' => 'cas_settings[access_redirect_to_message]',
					'textarea_rows' => 5,
					'tinymce' => false,
				)
			);
		}

		function print_select_cas_access_redirect_to_page( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			wp_dropdown_pages(
				array( 
					'selected' => $cas_settings['access_redirect_to_page'],
					'show_option_none' => 'Select a page',
					'name' => 'cas_settings[access_redirect_to_page]',
					'id' => 'cas_settings_access_redirect_to_page',
				)
			);
		}

		function print_select_cas_access_default_role( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><select id="cas_settings_access_default_role" name="cas_settings[access_default_role]">
				<?php wp_dropdown_roles( $cas_settings['access_default_role'] ); ?>
			</select><?php
		}


		function print_section_info_misc() {
			print 'You may optionally specify some advanced settings below:';
		}

		function print_text_cas_misc_lostpassword_url() {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="text" id="cas_settings_misc_lostpassword_url" name="cas_settings[misc_lostpassword_url]" value="<?= $cas_settings['misc_lostpassword_url']; ?>" placeholder="https://myuh.hawaii.edu:8888/am-forgot-password" style="width: 400px;" /><?php
		}

		function print_radio_cas_misc_branding( $args = '' ) {
			$cas_settings = get_option( 'cas_settings' );
			?><input type="radio" id="radio_cas_settings_misc_branding_default" name="cas_settings[misc_branding]" value="default"<?php checked( 'default' == $cas_settings['misc_branding'] ); ?> /> Default WordPress login screen<br />
				<input type="radio" id="radio_cas_settings_misc_branding_custom_uh" name="cas_settings[misc_branding]" value="custom_uh"<?php checked( 'custom_uh' == $cas_settings['misc_branding'] ); ?> /> Custom University of Hawai'i login screen<?php
		}



		/**
		 ****************************
		 * Dashboard widget
		 ****************************
		 */
		function add_dashboard_widgets() {
			// Only users who can edit can see the admissions dashboard widget
			if ( current_user_can( 'edit_post' ) ) {
				// Add dashboard widget for adding/editing users with access
				wp_add_dashboard_widget( 'admission_dashboard_widget', 'Course Admission Settings', array( $this, 'add_admission_dashboard_widget' ) );
			}
		}

/**
@todo: change dashboard widget to manage user lists instead of sakai list
*/
		function add_admission_dashboard_widget() {
			$cas_settings = get_option( 'cas_settings' );
			?>
			<div class="inside">
				<form method="post" id="cas_settings_access_form" action="">
					<p><?php $this->print_section_info_access(); ?></p>
					<div><?php $this->print_radio_cas_access_restriction(); ?></div>
					<br class="clear" />
					<div><?php //$this->print_combo_cas_access_courses(); ?></div>
					<br class="clear" />
					<p class="submit">
						<span class="save-action">
							<input type="button" name="button_save_cas_settings_access" id="button_save_cas_settings_access" class="button-primary" value="Save" onclick="save_cas_settings_access(this);" style="float: right;" />
							<span class="spinner"></span>
						</span>
						<?php wp_nonce_field( 'save_cas_settings_access', 'nonce_save_cas_settings_access' ); ?>
						<input type="hidden" id="cas_settings_sakai_base_url" name="cas_settings[sakai_base_url]" value="<?php print $cas_settings['sakai_base_url']; ?>" />
					</p>
					<br class="clear" />
				</form>
			</div>
			<?php
		}

		function ajax_save_admission_dashboard_widget() {
			// Make sure posted variables exist.
			if ( empty( $_POST['access_restriction'] ) || empty( $_POST['access_courses'] ) || empty( $_POST['nonce_save_cas_settings_access'] ) ) {
				die('');
			}

			// Nonce check.
			if ( ! wp_verify_nonce( $_POST['nonce_save_cas_settings_access'], 'save_cas_settings_access' ) ) {
				die('');
			}

			// If invalid input, set access restriction to only WP users.
			if ( ! in_array( $_POST['access_restriction'], array( 'everyone', 'university', 'approved_cas', 'user' ) ) ) {
				$_POST['access_restriction'] = 'user';
			}

			$cas_settings = get_option( 'cas_settings' );

			$cas_settings['access_restriction'] = stripslashes( $_POST['access_restriction'] );
			$cas_settings['access_courses'] = $_POST['access_courses'];
			$cas_settings['ldap_password'] = $this->decrypt( base64_decode( $cas_settings['ldap_password'] ) );

			// Only users who can edit can see the Sakai dashboard widget
			if ( current_user_can( 'edit_post' ) ) {
				update_option( 'cas_settings', $cas_settings );
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
		 * Helper function to determine whether a given username is in one of the
		 * CAS plugin lists (pending, approved, blocked). Defaults to the list of
		 * approved users.
		 */
		function is_username_in_list($username = '', $list = 'approved') {
			if ( empty( $username ) )
				return false;

			$cas_settings = get_option( 'cas_settings' );

			switch ( $list ) {
				case 'pending':
					return $this->in_multi_array( $username, $cas_settings['access_users_pending'] );
					break;
				case 'blocked':
					return $this->in_multi_array( $username, $cas_settings['access_users_blocked'] );
					break;
				case 'approved':
				default:
					return $this->in_multi_array( $username, $cas_settings['access_users_approved'] );
					break;
			}
		}

		/**
		 * Helper function to search a multidimensional array for a value.
		 */
		function in_multi_array( $needle = '', $haystack = array(), $strict = false ) {
			if ( ! is_array( $haystack ) )
				return false;
			foreach ( $haystack as $item ) {
				if ( ( $strict ? $item === $needle : $item == $needle ) || ( is_array( $item ) && $this->in_multi_array( $needle, $item, $strict ) ) ) {
					return true;
				}
			}
			return false;
		}

	} // END class WP_Plugin_CAS_Admission
}


// Installation and uninstallation hooks.
register_activation_hook( __FILE__, array( 'WP_Plugin_CAS_Admission', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WP_Plugin_CAS_Admission', 'deactivate' ) );
register_uninstall_hook( __FILE__, array( 'WP_Plugin_CAS_Admission', 'uninstall' ) );


// Instantiate the plugin class.
$wp_plugin_cas_admission = new WP_Plugin_CAS_Admission();
