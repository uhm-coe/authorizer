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

/**
 * Contains functions for rendering the Access Lists tab in Authorizer Settings.
 */
class Options extends Singleton {

	/**
	 * Retrieves a specific plugin option from db. Multisite enabled.
	 *
	 * @param  string $option        Option name.
	 * @param  string $admin_mode    Helper::NETWORK_CONTEXT will retrieve the multisite value.
	 * @param  string $override_mode 'allow override' will retrieve the multisite value if it exists.
	 * @param  string $print_mode    'print overlay' will output overlay that hides this option on the settings page.
	 * @return mixed                 Option value, or null on failure.
	 */
	public function get( $option, $admin_mode = Helper::SINGLE_CONTEXT, $override_mode = 'no override', $print_mode = 'no overlay' ) {
		// Special case for user lists (they are saved seperately to prevent concurrency issues).
		if ( in_array( $option, array( 'access_users_pending', 'access_users_approved', 'access_users_blocked' ), true ) ) {
			$list = Helper::NETWORK_CONTEXT === $admin_mode ? array() : get_option( 'auth_settings_' . $option, array() );
			if ( is_multisite() && Helper::NETWORK_CONTEXT === $admin_mode ) {
				$list = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_' . $option, array() );
			}
			return $list;
		}

		// Get all plugin options.
		$auth_settings = $this->get_all( $admin_mode, $override_mode );

		// Get multisite options (for checking if multisite override is prevented).
		$auth_multisite_settings = is_multisite() ? get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', array() ) : array();

		// Set option to null if it wasn't found.
		if ( ! array_key_exists( $option, $auth_settings ) ) {
			return null;
		}

		// If requested and appropriate, print the overlay hiding the
		// single site option that is overridden by a multisite option.
		if (
			Helper::NETWORK_CONTEXT !== $admin_mode &&
			'allow override' === $override_mode &&
			'print overlay' === $print_mode &&
			array_key_exists( 'multisite_override', $auth_settings ) &&
			'1' === $auth_settings['multisite_override'] &&
			(
				! array_key_exists( 'advanced_override_multisite', $auth_settings ) ||
				1 !== intval( $auth_settings['advanced_override_multisite'] ) ||
				! empty( $auth_multisite_settings['prevent_override_multisite'] )
			)
		) {
			// Get original plugin options (not overridden value). We'll
			// show this old value behind the disabled overlay.
			// $auth_settings = $this->get_all( $admin_mode, 'no override' );
			// (This feature is disabled).
			//
			$name = "auth_settings[$option]";
			$id   = "auth_settings_$option";
			// Get category of option so we can link directly to the appropriate tab
			// in multisite options (most options are on the External Service tab;
			// only access_who_can_login and access_who_can_view are on the Access
			// Lists tab; all options on the Advanced tab start with "advanced_").
			$tab = '&tab=external';
			if ( 'access_who_can_login' === $option || 'access_who_can_view' === $option ) {
				$tab = '&tab=access_lists';
			} elseif ( 0 === strpos( $option, 'advanced_' ) ) {
				$tab = '&tab=advanced';
			}
			?>
			<div id="overlay-hide-auth_settings_<?php echo esc_attr( $option ); ?>" class="auth_multisite_override_overlay">
				<span class="overlay-note">
					<?php esc_html_e( 'This setting is overridden by a', 'authorizer' ); ?> <a href="<?php echo esc_attr( network_admin_url( 'admin.php?page=authorizer' . $tab ) ); ?>"><?php esc_html_e( 'multisite option', 'authorizer' ); ?></a>.
				</span>
			</div>
			<?php
		}

		// If we're getting an option in a site that has overridden the multisite
		// override (and is not prevented from doing so), make sure we are returning
		// the option value from that site (not the multisite value).
		if (
			array_key_exists( 'advanced_override_multisite', $auth_settings ) &&
			1 === intval( $auth_settings['advanced_override_multisite'] ) &&
			empty( $auth_multisite_settings['prevent_override_multisite'] )
		) {
			$auth_settings = $this->get_all( $admin_mode, 'no override' );
		}

		// Set option to null if it wasn't found.
		if ( ! array_key_exists( $option, $auth_settings ) ) {
			return null;
		}

		return $auth_settings[ $option ];
	}

	/**
	 * Retrieves all plugin options from db. Multisite enabled.
	 *
	 * @param  string $admin_mode    Helper::NETWORK_CONTEXT will retrieve the multisite value.
	 * @param  string $override_mode 'allow override' will retrieve the multisite value if it exists.
	 * @return mixed                 Option value, or null on failure.
	 */
	public function get_all( $admin_mode = Helper::SINGLE_CONTEXT, $override_mode = 'no override' ) {
		// Grab plugin settings (skip if in Helper::NETWORK_CONTEXT mode).
		$auth_settings = Helper::NETWORK_CONTEXT === $admin_mode ? array() : get_option( 'auth_settings' );

		// Initialize to default values if the plugin option doesn't exist.
		if ( false === $auth_settings ) {
			$auth_settings = $this->set_default_options();
		}

		// Merge multisite options if we're in a network.
		if ( is_multisite() ) {
			// Get multisite options.
			$auth_multisite_settings = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', array() );

			// Return the multisite options if we're viewing the network admin options page.
			// Otherwise override options with their multisite equivalents.
			if ( Helper::NETWORK_CONTEXT === $admin_mode ) {
				$auth_settings = $auth_multisite_settings;
			} elseif (
				'allow override' === $override_mode &&
				array_key_exists( 'multisite_override', $auth_multisite_settings ) &&
				'1' === $auth_multisite_settings['multisite_override']
			) {
				// Keep track of the multisite override (and prevention) selection.
				$auth_settings['multisite_override']         = $auth_multisite_settings['multisite_override'];
				$auth_settings['prevent_override_multisite'] = $auth_multisite_settings['prevent_override_multisite'];

				// Don't merge multisite options if the current site has overridden them
				// (and isn't prevented from doing so).
				if (
					array_key_exists( 'advanced_override_multisite', $auth_settings ) &&
					1 === intval( $auth_settings['advanced_override_multisite'] ) &&
					empty( $auth_settings['prevent_override_multisite'] )
				) {
					return $auth_settings;
				}

				/**
				 * Note: the options below should be the complete list of overridden
				 * options. It is *not* the complete list of all options (some options
				 * don't have a multisite equivalent).
				 */

				/**
				 * Note: access_users_approved, access_users_pending, and
				 * access_users_blocked do not get overridden. However, since
				 * access_users_approved has a multisite equivalent, you must retrieve
				 * them both seperately. This is done because the two lists should be
				 * treated differently.
				 *
				 * $approved_users    = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
				 * $ms_approved_users = $options->get( 'access_users_approved', Helper::NETWORK_CONTEXT );
				 */

				// Override external services (google, cas, or ldap) and associated options.
				$auth_settings['oauth2']                    = $auth_multisite_settings['oauth2'];
				$auth_settings['oauth2_provider']           = $auth_multisite_settings['oauth2_provider'];
				$auth_settings['oauth2_custom_label']       = $auth_multisite_settings['oauth2_custom_label'];
				$auth_settings['oauth2_clientid']           = $auth_multisite_settings['oauth2_clientid'];
				$auth_settings['oauth2_clientsecret']       = $auth_multisite_settings['oauth2_clientsecret'];
				$auth_settings['oauth2_hosteddomain']       = $auth_multisite_settings['oauth2_hosteddomain'];
				$auth_settings['oauth2_tenant_id']          = $auth_multisite_settings['oauth2_tenant_id'];
				$auth_settings['oauth2_url_authorize']      = $auth_multisite_settings['oauth2_url_authorize'];
				$auth_settings['oauth2_url_token']          = $auth_multisite_settings['oauth2_url_token'];
				$auth_settings['oauth2_url_resource']       = $auth_multisite_settings['oauth2_url_resource'];
				$auth_settings['oauth2_auto_login']         = $auth_multisite_settings['oauth2_auto_login'] ?? '';
				$auth_settings['google']                    = $auth_multisite_settings['google'];
				$auth_settings['google_clientid']           = $auth_multisite_settings['google_clientid'];
				$auth_settings['google_clientsecret']       = $auth_multisite_settings['google_clientsecret'];
				$auth_settings['google_hosteddomain']       = $auth_multisite_settings['google_hosteddomain'];
				$auth_settings['cas']                       = $auth_multisite_settings['cas'];
				$auth_settings['cas_auto_login']            = $auth_multisite_settings['cas_auto_login'];
				$auth_settings['cas_custom_label']          = $auth_multisite_settings['cas_custom_label'];
				$auth_settings['cas_host']                  = $auth_multisite_settings['cas_host'];
				$auth_settings['cas_port']                  = $auth_multisite_settings['cas_port'];
				$auth_settings['cas_path']                  = $auth_multisite_settings['cas_path'];
				$auth_settings['cas_method']                = $auth_multisite_settings['cas_method'];
				$auth_settings['cas_version']               = $auth_multisite_settings['cas_version'];
				$auth_settings['cas_attr_email']            = $auth_multisite_settings['cas_attr_email'];
				$auth_settings['cas_attr_first_name']       = $auth_multisite_settings['cas_attr_first_name'];
				$auth_settings['cas_attr_last_name']        = $auth_multisite_settings['cas_attr_last_name'];
				$auth_settings['cas_attr_update_on_login']  = $auth_multisite_settings['cas_attr_update_on_login'];
				$auth_settings['cas_link_on_username']      = $auth_multisite_settings['cas_link_on_username'];
				$auth_settings['ldap']                      = $auth_multisite_settings['ldap'];
				$auth_settings['ldap_host']                 = $auth_multisite_settings['ldap_host'];
				$auth_settings['ldap_port']                 = $auth_multisite_settings['ldap_port'];
				$auth_settings['ldap_tls']                  = $auth_multisite_settings['ldap_tls'];
				$auth_settings['ldap_search_base']          = $auth_multisite_settings['ldap_search_base'];
				$auth_settings['ldap_search_filter']        = $auth_multisite_settings['ldap_search_filter'];
				$auth_settings['ldap_uid']                  = $auth_multisite_settings['ldap_uid'];
				$auth_settings['ldap_attr_email']           = $auth_multisite_settings['ldap_attr_email'];
				$auth_settings['ldap_user']                 = $auth_multisite_settings['ldap_user'];
				$auth_settings['ldap_password']             = $auth_multisite_settings['ldap_password'];
				$auth_settings['ldap_lostpassword_url']     = $auth_multisite_settings['ldap_lostpassword_url'];
				$auth_settings['ldap_attr_first_name']      = $auth_multisite_settings['ldap_attr_first_name'];
				$auth_settings['ldap_attr_last_name']       = $auth_multisite_settings['ldap_attr_last_name'];
				$auth_settings['ldap_attr_update_on_login'] = $auth_multisite_settings['ldap_attr_update_on_login'];
				$auth_settings['ldap_test_user']            = $auth_multisite_settings['ldap_test_user'] ?? '';

				// Override access_who_can_login and access_who_can_view.
				$auth_settings['access_who_can_login'] = $auth_multisite_settings['access_who_can_login'];
				$auth_settings['access_who_can_view']  = $auth_multisite_settings['access_who_can_view'];

				// Override access_default_role.
				$auth_settings['access_default_role'] = $auth_multisite_settings['access_default_role'];

				// Override lockouts.
				$auth_settings['advanced_lockouts'] = $auth_multisite_settings['advanced_lockouts'];

				// Override Hide WordPress login.
				$auth_settings['advanced_hide_wp_login'] = $auth_multisite_settings['advanced_hide_wp_login'];

				// Override Disable WordPress login.
				$auth_settings['advanced_disable_wp_login'] = $auth_multisite_settings['advanced_disable_wp_login'];

				// Override Users per page.
				$auth_settings['advanced_users_per_page'] = $auth_multisite_settings['advanced_users_per_page'];

				// Override Sort users by.
				$auth_settings['advanced_users_sort_by'] = $auth_multisite_settings['advanced_users_sort_by'];

				// Override Sort users order.
				$auth_settings['advanced_users_sort_order'] = $auth_multisite_settings['advanced_users_sort_order'];

				// Override Show Dashboard Widget.
				$auth_settings['advanced_widget_enabled'] = $auth_multisite_settings['advanced_widget_enabled'];
			}
		}
		return $auth_settings;
	}


	/**
	 * Set meaningful defaults for the plugin options.
	 *
	 * Note: This function is called on plugin activation.
	 *
	 * @param array $args {
	 *     Optional.
	 *
	 *     @type bool $set_multisite_options  Whether to also set the default
	 *                                        multisite options, if in multisite.
	 *                                        Defaults to true.
	 * }
	 */
	public function set_default_options( $args = array() ) {
		global $wp_roles;

		// Set default args.
		$defaults = array(
			'set_multisite_options' => true,
		);
		$args     = wp_parse_args( $args, $defaults );

		$auth_settings = get_option( 'auth_settings' );
		if ( false === $auth_settings ) {
			$auth_settings = array();
		}

		// Access Lists Defaults.
		$auth_settings_access_users_pending = get_option( 'auth_settings_access_users_pending' );
		if ( false === $auth_settings_access_users_pending ) {
			$auth_settings_access_users_pending = array();
		}
		$auth_settings_access_users_approved = get_option( 'auth_settings_access_users_approved' );
		if ( false === $auth_settings_access_users_approved ) {
			$auth_settings_access_users_approved = array();
		}
		$auth_settings_access_users_blocked = get_option( 'auth_settings_access_users_blocked' );
		if ( false === $auth_settings_access_users_blocked ) {
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
			$auth_settings['access_pending_redirect_to_message'] = '<p>' . __( "You're not currently allowed to view this site. Your administrator has been notified, and once he/she has approved your request, you will be able to log in. If you need any other help, please contact your administrator.", 'authorizer' ) . '</p>';
		}
		if ( ! array_key_exists( 'access_blocked_redirect_to_message', $auth_settings ) ) {
			$auth_settings['access_blocked_redirect_to_message'] = '<p>' . __( "You're not currently allowed to log into this site. If you think this is a mistake, please contact your administrator.", 'authorizer' ) . '</p>';
		}
		if ( ! array_key_exists( 'access_should_email_approved_users', $auth_settings ) ) {
			$auth_settings['access_should_email_approved_users'] = '';
		}
		if ( ! array_key_exists( 'access_email_approved_users_subject', $auth_settings ) ) {
			$auth_settings['access_email_approved_users_subject'] = sprintf(
				/* TRANSLATORS: %s: Shortcode for name of site */
				__( 'Welcome to %s!', 'authorizer' ),
				'[site_name]'
			);
		}
		if ( ! array_key_exists( 'access_email_approved_users_body', $auth_settings ) ) {
			$auth_settings['access_email_approved_users_body'] = sprintf(
				/* TRANSLATORS: 1: Shortcode for user email 2: Shortcode for site name 3: Shortcode for site URL */
				__( "Hello %1\$s,\nWelcome to %2\$s! You now have access to all content on the site. Please visit us here:\n%3\$s\n", 'authorizer' ),
				'[user_email]',
				'[site_name]',
				'[site_url]'
			);
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
			$auth_settings['access_redirect_to_message'] = '<p>' . __( 'Notice: You are browsing this site anonymously, and only have access to a portion of its content.', 'authorizer' ) . '</p>';
		}

		// External Service Defaults.
		if ( ! array_key_exists( 'access_default_role', $auth_settings ) ) {
			// Set default role to 'subscriber', or 'student' if that role exists.
			$auth_settings['access_default_role'] = 'subscriber';
			if ( ! empty( $wp_roles ) ) {
				$all_roles      = $wp_roles->roles;
				$editable_roles = apply_filters( 'editable_roles', $all_roles );
				if ( is_array( $editable_roles ) && array_key_exists( 'student', $editable_roles ) ) {
					$auth_settings['access_default_role'] = 'student';
				}
			}
		}

		if ( ! array_key_exists( 'oauth2', $auth_settings ) ) {
			$auth_settings['oauth2'] = '';
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
		if ( ! array_key_exists( 'google_hosteddomain', $auth_settings ) ) {
			$auth_settings['google_hosteddomain'] = '';
		}

		if ( ! array_key_exists( 'oauth2_provider', $auth_settings ) ) {
			$auth_settings['oauth2_provider'] = '';
		}
		if ( ! array_key_exists( 'oauth2_custom_label', $auth_settings ) ) {
			$auth_settings['oauth2_custom_label'] = 'OAuth2';
		}
		if ( ! array_key_exists( 'oauth2_clientid', $auth_settings ) ) {
			$auth_settings['oauth2_clientid'] = '';
		}
		if ( ! array_key_exists( 'oauth2_clientsecret', $auth_settings ) ) {
			$auth_settings['oauth2_clientsecret'] = '';
		}
		if ( ! array_key_exists( 'oauth2_hosteddomain', $auth_settings ) ) {
			$auth_settings['oauth2_hosteddomain'] = '';
		}
		if ( ! array_key_exists( 'oauth2_tenant_id', $auth_settings ) ) {
			$auth_settings['oauth2_tenant_id'] = 'common';
		}
		if ( ! array_key_exists( 'oauth2_url_authorize', $auth_settings ) ) {
			$auth_settings['oauth2_url_authorize'] = '';
		}
		if ( ! array_key_exists( 'oauth2_url_token', $auth_settings ) ) {
			$auth_settings['oauth2_url_token'] = '';
		}
		if ( ! array_key_exists( 'oauth2_url_resource', $auth_settings ) ) {
			$auth_settings['oauth2_url_resource'] = '';
		}
		if ( ! array_key_exists( 'oauth2_auto_login', $auth_settings ) ) {
			$auth_settings['oauth2_auto_login'] = '';
		}

		if ( ! array_key_exists( 'cas_auto_login', $auth_settings ) ) {
			$auth_settings['cas_auto_login'] = '';
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
		if ( ! array_key_exists( 'cas_method', $auth_settings ) ) {
			$auth_settings['cas_method'] = Options\External\Cas::get_instance()->sanitize_cas_method();
		}
		if ( ! array_key_exists( 'cas_version', $auth_settings ) ) {
			$auth_settings['cas_version'] = Options\External\Cas::get_instance()->sanitize_cas_version();
		}
		if ( ! array_key_exists( 'cas_attr_email', $auth_settings ) ) {
			$auth_settings['cas_attr_email'] = '';
		}
		if ( ! array_key_exists( 'cas_attr_first_name', $auth_settings ) ) {
			$auth_settings['cas_attr_first_name'] = '';
		}
		if ( ! array_key_exists( 'cas_attr_last_name', $auth_settings ) ) {
			$auth_settings['cas_attr_last_name'] = '';
		}
		if ( ! array_key_exists( 'cas_attr_update_on_login', $auth_settings ) ) {
			$auth_settings['cas_attr_update_on_login'] = '';
		}
		if ( ! array_key_exists( 'cas_link_on_username', $auth_settings ) ) {
			$auth_settings['cas_link_on_username'] = '';
		}

		if ( ! array_key_exists( 'ldap_host', $auth_settings ) ) {
			$auth_settings['ldap_host'] = '';
		}
		if ( ! array_key_exists( 'ldap_port', $auth_settings ) ) {
			$auth_settings['ldap_port'] = '389';
		}
		if ( ! array_key_exists( 'ldap_tls', $auth_settings ) ) {
			$auth_settings['ldap_tls'] = '1';
		}
		if ( ! array_key_exists( 'ldap_search_base', $auth_settings ) ) {
			$auth_settings['ldap_search_base'] = '';
		}
		if ( ! array_key_exists( 'ldap_search_filter', $auth_settings ) ) {
			$auth_settings['ldap_search_filter'] = '';
		}
		if ( ! array_key_exists( 'ldap_uid', $auth_settings ) ) {
			$auth_settings['ldap_uid'] = 'uid';
		}
		if ( ! array_key_exists( 'ldap_attr_email', $auth_settings ) ) {
			$auth_settings['ldap_attr_email'] = '';
		}
		if ( ! array_key_exists( 'ldap_user', $auth_settings ) ) {
			$auth_settings['ldap_user'] = '';
		}
		if ( ! array_key_exists( 'ldap_password', $auth_settings ) ) {
			$auth_settings['ldap_password'] = '';
		}
		if ( ! array_key_exists( 'ldap_lostpassword_url', $auth_settings ) ) {
			$auth_settings['ldap_lostpassword_url'] = '';
		}
		if ( ! array_key_exists( 'ldap_attr_first_name', $auth_settings ) ) {
			$auth_settings['ldap_attr_first_name'] = '';
		}
		if ( ! array_key_exists( 'ldap_attr_last_name', $auth_settings ) ) {
			$auth_settings['ldap_attr_last_name'] = '';
		}
		if ( ! array_key_exists( 'ldap_attr_update_on_login', $auth_settings ) ) {
			$auth_settings['ldap_attr_update_on_login'] = '';
		}
		if ( ! array_key_exists( 'ldap_test_user', $auth_settings ) ) {
			$auth_settings['ldap_test_user'] = '';
		}

		// Advanced defaults.
		if ( ! array_key_exists( 'advanced_lockouts', $auth_settings ) ) {
			$auth_settings['advanced_lockouts'] = array(
				'attempts_1'     => 10,
				'duration_1'     => 1,
				'attempts_2'     => 10,
				'duration_2'     => 10,
				'reset_duration' => 120,
			);
		}
		if ( ! array_key_exists( 'advanced_hide_wp_login', $auth_settings ) ) {
			$auth_settings['advanced_hide_wp_login'] = '';
		}
		if ( ! array_key_exists( 'advanced_disable_wp_login', $auth_settings ) ) {
			$auth_settings['advanced_disable_wp_login'] = '';
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
		if ( ! array_key_exists( 'advanced_users_per_page', $auth_settings ) ) {
			$auth_settings['advanced_users_per_page'] = 20;
		}
		if ( ! array_key_exists( 'advanced_users_sort_by', $auth_settings ) ) {
			$auth_settings['advanced_users_sort_by'] = 'created';
		}
		if ( ! array_key_exists( 'advanced_users_sort_order', $auth_settings ) ) {
			$auth_settings['advanced_users_sort_order'] = 'asc';
		}
		if ( ! array_key_exists( 'advanced_widget_enabled', $auth_settings ) ) {
			$auth_settings['advanced_widget_enabled'] = '1';
		}
		if ( ! array_key_exists( 'advanced_override_multisite', $auth_settings ) ) {
			$auth_settings['advanced_override_multisite'] = '';
		}

		// Save default options to database.
		update_option( 'auth_settings', $auth_settings );
		update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
		update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
		update_option( 'auth_settings_access_users_blocked', $auth_settings_access_users_blocked );

		// Multisite defaults.
		if ( is_multisite() && $args['set_multisite_options'] ) {
			$auth_multisite_settings = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', array() );

			if ( false === $auth_multisite_settings ) {
				$auth_multisite_settings = array();
			}
			// Global switch for enabling multisite options.
			if ( ! array_key_exists( 'multisite_override', $auth_multisite_settings ) ) {
				$auth_multisite_settings['multisite_override'] = '';
			}
			// Global switch for preventing sites from overriding multisite options.
			if ( ! array_key_exists( 'prevent_override_multisite', $auth_multisite_settings ) ) {
				$auth_multisite_settings['prevent_override_multisite'] = '';
			}
			// Access Lists Defaults.
			$auth_multisite_settings_access_users_approved = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved' );
			if ( false === $auth_multisite_settings_access_users_approved ) {
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
				// Set default role to 'subscriber', or 'student' if that role exists.
				$auth_multisite_settings['access_default_role'] = 'subscriber';
				if ( ! empty( $wp_roles ) ) {
					$all_roles      = $wp_roles->roles;
					$editable_roles = apply_filters( 'editable_roles', $all_roles );
					if ( is_array( $editable_roles ) && array_key_exists( 'student', $editable_roles ) ) {
						$auth_multisite_settings['access_default_role'] = 'student';
					}
				}
			}
			if ( ! array_key_exists( 'oauth2', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2'] = '';
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
			if ( ! array_key_exists( 'oauth2_provider', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_provider'] = '';
			}
			if ( ! array_key_exists( 'oauth2_custom_label', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_custom_label'] = 'OAuth2';
			}
			if ( ! array_key_exists( 'oauth2_clientid', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_clientid'] = '';
			}
			if ( ! array_key_exists( 'oauth2_clientsecret', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_clientsecret'] = '';
			}
			if ( ! array_key_exists( 'oauth2_hosteddomain', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_hosteddomain'] = '';
			}
			if ( ! array_key_exists( 'oauth2_tenant_id', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_tenant_id'] = 'common';
			}
			if ( ! array_key_exists( 'oauth2_url_authorize', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_url_authorize'] = '';
			}
			if ( ! array_key_exists( 'oauth2_url_token', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_url_token'] = '';
			}
			if ( ! array_key_exists( 'oauth2_url_resource', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_url_resource'] = '';
			}
			if ( ! array_key_exists( 'oauth2_auto_login', $auth_multisite_settings ) ) {
				$auth_multisite_settings['oauth2_auto_login'] = '';
			}
			if ( ! array_key_exists( 'google_clientid', $auth_multisite_settings ) ) {
				$auth_multisite_settings['google_clientid'] = '';
			}
			if ( ! array_key_exists( 'google_clientsecret', $auth_multisite_settings ) ) {
				$auth_multisite_settings['google_clientsecret'] = '';
			}
			if ( ! array_key_exists( 'google_hosteddomain', $auth_multisite_settings ) ) {
				$auth_multisite_settings['google_hosteddomain'] = '';
			}
			if ( ! array_key_exists( 'cas_auto_login', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_auto_login'] = '';
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
			if ( ! array_key_exists( 'cas_method', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_method'] = Options\External\Cas::get_instance()->sanitize_cas_method();
			}
			if ( ! array_key_exists( 'cas_version', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_version'] = Options\External\Cas::get_instance()->sanitize_cas_version();
			}
			if ( ! array_key_exists( 'cas_attr_email', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_attr_email'] = '';
			}
			if ( ! array_key_exists( 'cas_attr_first_name', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_attr_first_name'] = '';
			}
			if ( ! array_key_exists( 'cas_attr_last_name', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_attr_last_name'] = '';
			}
			if ( ! array_key_exists( 'cas_attr_update_on_login', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_attr_update_on_login'] = '';
			}
			if ( ! array_key_exists( 'cas_link_on_username', $auth_multisite_settings ) ) {
				$auth_multisite_settings['cas_link_on_username'] = '';
			}
			if ( ! array_key_exists( 'ldap_host', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_host'] = '';
			}
			if ( ! array_key_exists( 'ldap_port', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_port'] = '389';
			}
			if ( ! array_key_exists( 'ldap_tls', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_tls'] = '1';
			}
			if ( ! array_key_exists( 'ldap_search_base', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_search_base'] = '';
			}
			if ( ! array_key_exists( 'ldap_search_filter', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_search_filter'] = '';
			}
			if ( ! array_key_exists( 'ldap_uid', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_uid'] = 'uid';
			}
			if ( ! array_key_exists( 'ldap_attr_email', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_attr_email'] = '';
			}
			if ( ! array_key_exists( 'ldap_user', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_user'] = '';
			}
			if ( ! array_key_exists( 'ldap_password', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_password'] = '';
			}
			if ( ! array_key_exists( 'ldap_lostpassword_url', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_lostpassword_url'] = '';
			}
			if ( ! array_key_exists( 'ldap_attr_first_name', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_attr_first_name'] = '';
			}
			if ( ! array_key_exists( 'ldap_attr_last_name', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_attr_last_name'] = '';
			}
			if ( ! array_key_exists( 'ldap_attr_update_on_login', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_attr_update_on_login'] = '';
			}
			if ( ! array_key_exists( 'ldap_test_user', $auth_multisite_settings ) ) {
				$auth_multisite_settings['ldap_test_user'] = '';
			}
			// Advanced defaults.
			if ( ! array_key_exists( 'advanced_lockouts', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_lockouts'] = array(
					'attempts_1'     => 10,
					'duration_1'     => 1,
					'attempts_2'     => 10,
					'duration_2'     => 10,
					'reset_duration' => 120,
				);
			}
			if ( ! array_key_exists( 'advanced_hide_wp_login', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_hide_wp_login'] = '';
			}
			if ( ! array_key_exists( 'advanced_disable_wp_login', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_disable_wp_login'] = '';
			}
			if ( ! array_key_exists( 'advanced_users_per_page', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_users_per_page'] = 20;
			}
			if ( ! array_key_exists( 'advanced_users_sort_by', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_users_sort_by'] = 'created';
			}
			if ( ! array_key_exists( 'advanced_users_sort_order', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_users_sort_order'] = 'asc';
			}
			if ( ! array_key_exists( 'advanced_widget_enabled', $auth_multisite_settings ) ) {
				$auth_multisite_settings['advanced_widget_enabled'] = '1';
			}
			// Save default network options to database.
			update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', $auth_multisite_settings );
			update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
		}

		return $auth_settings;
	}


	/**
	 * List sanitizer.
	 *
	 * @param  array $user_list Array of users to sanitize.
	 * @return array            Array of sanitized users.
	 */
	public function sanitize_user_list( $user_list ) {
		// If it's not a list, make it so.
		if ( ! is_array( $user_list ) ) {
			$user_list = array();
		}
		foreach ( $user_list as $key => $user_info ) {
			if ( strlen( $user_info['email'] ) < 1 ) {
				// Make sure there are no empty entries in the list.
				unset( $user_list[ $key ] );
			}
		}
		return $user_list;
	}


	/**
	 * Settings sanitizer callback.
	 *
	 * @param  array $auth_settings Authorizer settings array.
	 * @return array                Sanitized Authorizer settings array.
	 */
	public function sanitize_options( $auth_settings ) {
		// Default to "Approved Users" login access restriction.
		if ( ! in_array( $auth_settings['access_who_can_login'], array( 'external_users', 'approved_users' ), true ) ) {
			$auth_settings['access_who_can_login'] = 'approved_users';
		}

		// Default to "Everyone" view access restriction.
		if ( ! in_array( $auth_settings['access_who_can_view'], array( 'everyone', 'logged_in_users' ), true ) ) {
			$auth_settings['access_who_can_view'] = 'everyone';
		}

		// Default to WordPress login access redirect.
		// Note: this option doesn't exist in multisite options, so we first
		// check to see if it exists.
		if ( array_key_exists( 'access_redirect', $auth_settings ) && ! in_array( $auth_settings['access_redirect'], array( 'login', 'page', 'message' ), true ) ) {
			$auth_settings['access_redirect'] = 'login';
		}

		// Default to warning message for anonymous users on public pages.
		// Note: this option doesn't exist in multisite options, so we first
		// check to see if it exists.
		if ( array_key_exists( 'access_public_warning', $auth_settings ) && ! in_array( $auth_settings['access_public_warning'], array( 'no_warning', 'warning' ), true ) ) {
			$auth_settings['access_public_warning'] = 'no_warning';
		}

		// Sanitize Send welcome email (checkbox: value can only be '1' or empty string).
		$auth_settings['access_should_email_approved_users'] = array_key_exists( 'access_should_email_approved_users', $auth_settings ) && strlen( $auth_settings['access_should_email_approved_users'] ) > 0 ? '1' : '';

		// Sanitize Enable OAuth2 Logins (checkbox: value can only be '1' or empty string).
		$auth_settings['oauth2'] = array_key_exists( 'oauth2', $auth_settings ) && strlen( $auth_settings['oauth2'] ) > 0 ? '1' : '';

		// Sanitize OAuth2 auto-login (checkbox: value can only be '1' or empty string).
		$auth_settings['oauth2_auto_login'] = array_key_exists( 'oauth2_auto_login', $auth_settings ) && strlen( $auth_settings['oauth2_auto_login'] ) > 0 ? '1' : '';

		// Sanitize Enable Google Logins (checkbox: value can only be '1' or empty string).
		$auth_settings['google'] = array_key_exists( 'google', $auth_settings ) && strlen( $auth_settings['google'] ) > 0 ? '1' : '';

		// Sanitize Enable CAS Logins (checkbox: value can only be '1' or empty string).
		$auth_settings['cas'] = array_key_exists( 'cas', $auth_settings ) && strlen( $auth_settings['cas'] ) > 0 ? '1' : '';

		// Sanitize CAS auto-login (checkbox: value can only be '1' or empty string).
		$auth_settings['cas_auto_login'] = array_key_exists( 'cas_auto_login', $auth_settings ) && strlen( $auth_settings['cas_auto_login'] ) > 0 ? '1' : '';

		// Sanitize CAS Host setting.
		$auth_settings['cas_host'] = filter_var( $auth_settings['cas_host'], FILTER_SANITIZE_URL );

		// Sanitize CAS Port (int).
		$auth_settings['cas_port'] = filter_var( $auth_settings['cas_port'], FILTER_SANITIZE_NUMBER_INT );

		// Sanitize CAS attribute update (select: value can only be 'update-if-empty', '1', or empty string).
		if ( ! isset( $auth_settings['cas_attr_update_on_login'] ) || ! in_array( $auth_settings['cas_attr_update_on_login'], array( '', '1', 'update-if-empty' ), true ) ) {
			$auth_settings['cas_attr_update_on_login'] = '';
		}

		// Sanitize CAS link on username (checkbox: value can only be '1' or empty string).
		$auth_settings['cas_link_on_username'] = array_key_exists( 'cas_link_on_username', $auth_settings ) && strlen( $auth_settings['cas_link_on_username'] ) > 0 ? '1' : '';

		// Sanitize Enable LDAP Logins (checkbox: value can only be '1' or empty string).
		$auth_settings['ldap'] = array_key_exists( 'ldap', $auth_settings ) && strlen( $auth_settings['ldap'] ) > 0 ? '1' : '';

		// Sanitize LDAP Port (int).
		$auth_settings['ldap_port'] = filter_var( $auth_settings['ldap_port'], FILTER_SANITIZE_NUMBER_INT );

		// Sanitize LDAP TLS (checkbox: value can only be '1' or empty string).
		$auth_settings['ldap_tls'] = array_key_exists( 'ldap_tls', $auth_settings ) && strlen( $auth_settings['ldap_tls'] ) > 0 ? '1' : '';

		// Sanitize LDAP attributes (basically make sure they don't have any parentheses).
		$auth_settings['ldap_uid'] = filter_var( $auth_settings['ldap_uid'], FILTER_SANITIZE_EMAIL );

		// Sanitize LDAP Lost Password URL.
		$auth_settings['ldap_lostpassword_url'] = filter_var( $auth_settings['ldap_lostpassword_url'], FILTER_SANITIZE_URL );

		// Obfuscate LDAP directory user password.
		if ( isset( $auth_settings['ldap_password'] ) && strlen( $auth_settings['ldap_password'] ) > 0 ) {
			// encrypt the directory user password for some minor obfuscation in the database.
			$auth_settings['ldap_password'] = Helper::encrypt( $auth_settings['ldap_password'] );
		}

		// Sanitize LDAP attribute update (select: value can only be 'update-if-empty', '1', or empty string).
		if ( ! isset( $auth_settings['ldap_attr_update_on_login'] ) || ! in_array( $auth_settings['ldap_attr_update_on_login'], array( '', '1', 'update-if-empty' ), true ) ) {
			$auth_settings['ldap_attr_update_on_login'] = '';
		}

		// Make sure public pages is an empty array if it's empty.
		// Note: this option doesn't exist in multisite options, so we first
		// check to see if it exists.
		if ( array_key_exists( 'access_public_pages', $auth_settings ) && ! is_array( $auth_settings['access_public_pages'] ) ) {
			$auth_settings['access_public_pages'] = array();
		}

		// Make sure all lockout options are integers (attempts_1, duration_1,
		// attempts_2, duration_2, reset_duration). Default to 0 if not.
		foreach ( $auth_settings['advanced_lockouts'] as $key => $value ) {
			$auth_settings['advanced_lockouts'][ $key ] = filter_var( $value, FILTER_SANITIZE_NUMBER_INT );
			if ( empty( $auth_settings['advanced_lockouts'][ $key ] ) ) {
				$auth_settings['advanced_lockouts'][ $key ] = 0;
			}
		}

		// Sanitize Hide WordPress logins (checkbox: value can only be '1' or empty string).
		$auth_settings['advanced_hide_wp_login'] = array_key_exists( 'advanced_hide_wp_login', $auth_settings ) && strlen( $auth_settings['advanced_hide_wp_login'] ) > 0 ? '1' : '';

		// Sanitize Disable WordPress logins (checkbox: value can only be '1' or empty string).
		$auth_settings['advanced_disable_wp_login'] = array_key_exists( 'advanced_disable_wp_login', $auth_settings ) && strlen( $auth_settings['advanced_disable_wp_login'] ) > 0 ? '1' : '';

		// Sanitize Users per page (text: value can only int from 1 to MAX_INT).
		$auth_settings['advanced_users_per_page'] = array_key_exists( 'advanced_users_per_page', $auth_settings ) && intval( $auth_settings['advanced_users_per_page'] ) > 0 ? intval( $auth_settings['advanced_users_per_page'] ) : 1;

		// Sanitize Sort users by (select: value can be 'email', 'role', 'date_added', 'created').
		if ( ! isset( $auth_settings['advanced_users_sort_by'] ) || ! in_array( $auth_settings['advanced_users_sort_by'], array( 'email', 'role', 'date_added', 'created' ), true ) ) {
			$auth_settings['advanced_users_sort_by'] = 'created';
		}

		// Sanitize Sort users order (select: value can be 'asc', 'desc').
		if ( ! isset( $auth_settings['advanced_users_sort_order'] ) || ! in_array( $auth_settings['advanced_users_sort_order'], array( 'asc', 'desc' ), true ) ) {
			$auth_settings['advanced_users_sort_order'] = 'asc';
		}

		// Sanitize Show Dashboard Widget (checkbox: value can only be '1' or empty string).
		$auth_settings['advanced_widget_enabled'] = array_key_exists( 'advanced_widget_enabled', $auth_settings ) && strlen( $auth_settings['advanced_widget_enabled'] ) > 0 ? '1' : '';

		// Sanitize Override multisite options (checkbox: value can only be '1' or empty string).
		$auth_settings['advanced_override_multisite'] = array_key_exists( 'advanced_override_multisite', $auth_settings ) && strlen( $auth_settings['advanced_override_multisite'] ) > 0 ? '1' : '';

		return $auth_settings;
	}


	/**
	 * Sanitizes an array of user update commands coming from the AJAX handler in Authorizer Settings.
	 *
	 * Example $users array:
	 * array(
	 *   array(
	 *     edit_action: 'add' or 'remove' or 'change_role',
	 *     email: 'johndoe@example.com',
	 *     role: 'subscriber',
	 *     date_added: 'Jun 2014',
	 *     local_user: 'true' or 'false',
	 *     multisite_user: 'true' or 'false',
	 *   ),
	 *   ...
	 * )
	 *
	 * @param  array $users Users to edit.
	 * @param  array $args  Options (e.g., 'allow_wildcard_email' => true).
	 * @return array        Sanitized users to edit.
	 */
	public function sanitize_update_auth_users( $users = array(), $args = array() ) {
		if ( ! is_array( $users ) ) {
			$users = array();
		}
		if ( isset( $args['allow_wildcard_email'] ) && $args['allow_wildcard_email'] ) {
			$users = array_map( array( $this, 'sanitize_update_auth_user_allow_wildcard_email' ), $users );
		} else {
			$users = array_map( array( $this, 'sanitize_update_auth_user' ), $users );
		}

		// Remove any entries that failed email address validation.
		$users = array_filter( $users, array( $this, 'remove_invalid_auth_users' ) );

		return $users;
	}


	/**
	 * Callback for array_map in sanitize_update_auth_users().
	 *
	 * @param  array $user User data to sanitize.
	 * @return array       Sanitized user data.
	 */
	public function sanitize_update_auth_user( $user ) {
		if ( array_key_exists( 'edit_action', $user ) ) {
			$user['edit_action'] = sanitize_text_field( $user['edit_action'] );
		}
		if ( isset( $user['email'] ) ) {
			$user['email'] = sanitize_email( $user['email'] );
		}
		if ( isset( $user['role'] ) ) {
			$user['role'] = sanitize_text_field( $user['role'] );
		}
		if ( isset( $user['date_added'] ) ) {
			$user['date_added'] = sanitize_text_field( $user['date_added'] );
		}
		if ( isset( $user['local_user'] ) ) {
			$user['local_user'] = 'true' === $user['local_user'] ? 'true' : 'false';
		}
		if ( isset( $user['multisite_user'] ) ) {
			$user['multisite_user'] = 'true' === $user['multisite_user'] ? 'true' : 'false';
		}

		return $user;
	}


	/**
	 * Settings print callback.
	 *
	 * @param  string $args Args (e.g., multisite admin mode).
	 * @return void
	 */
	public function print_section_info_tabs( $args = '' ) {
		if ( Helper::NETWORK_CONTEXT === Helper::get_context( $args ) ) :
			?>
			<h2 class="nav-tab-wrapper">
				<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:chooseTab('access_lists' );"><?php esc_html_e( 'Access Lists', 'authorizer' ); ?></a>
				<a class="nav-tab nav-tab-external" href="javascript:chooseTab('external' );"><?php esc_html_e( 'External Service', 'authorizer' ); ?></a>
				<a class="nav-tab nav-tab-advanced" href="javascript:chooseTab('advanced' );"><?php esc_html_e( 'Advanced', 'authorizer' ); ?></a>
			</h2>
		<?php else : ?>
			<h2 class="nav-tab-wrapper">
				<a class="nav-tab nav-tab-access_lists nav-tab-active" href="javascript:chooseTab('access_lists' );"><?php esc_html_e( 'Access Lists', 'authorizer' ); ?></a>
				<a class="nav-tab nav-tab-access_login" href="javascript:chooseTab('access_login' );"><?php esc_html_e( 'Login Access', 'authorizer' ); ?></a>
				<a class="nav-tab nav-tab-access_public" href="javascript:chooseTab('access_public' );"><?php esc_html_e( 'Public Access', 'authorizer' ); ?></a>
				<a class="nav-tab nav-tab-external" href="javascript:chooseTab('external' );"><?php esc_html_e( 'External Service', 'authorizer' ); ?></a>
				<a class="nav-tab nav-tab-advanced" href="javascript:chooseTab('advanced' );"><?php esc_html_e( 'Advanced', 'authorizer' ); ?></a>
			</h2>
			<?php
		endif;
	}


	/**
	 * This array filter will remove any users who failed email address validation
	 * (which would set their email to a blank string).
	 *
	 * @param  array $user User data to check for a valid email.
	 * @return bool  Whether to filter out the user.
	 */
	protected function remove_invalid_auth_users( $user ) {
		return isset( $user['email'] ) && strlen( $user['email'] ) > 0;
	}


	/**
	 * Callback for array_map in sanitize_update_auth_users().
	 *
	 * @param  array $user User data to sanitize.
	 * @return array       Sanitized user data.
	 */
	protected function sanitize_update_auth_user_allow_wildcard_email( $user ) {
		if ( array_key_exists( 'edit_action', $user ) ) {
			$user['edit_action'] = sanitize_text_field( $user['edit_action'] );
		}
		if ( isset( $user['email'] ) ) {
			if ( strpos( $user['email'], '@' ) === 0 ) {
				$user['email'] = sanitize_text_field( $user['email'] );
			} else {
				$user['email'] = sanitize_email( $user['email'] );
			}
		}
		if ( isset( $user['role'] ) ) {
			$user['role'] = sanitize_text_field( $user['role'] );
		}
		if ( isset( $user['date_added'] ) ) {
			$user['date_added'] = sanitize_text_field( $user['date_added'] );
		}
		if ( isset( $user['local_user'] ) ) {
			$user['local_user'] = 'true' === $user['local_user'] ? 'true' : 'false';
		}
		if ( isset( $user['multisite_user'] ) ) {
			$user['multisite_user'] = 'true' === $user['multisite_user'] ? 'true' : 'false';
		}

		return $user;
	}
}
