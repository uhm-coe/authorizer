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
 * Contains functions for interfacing with WordPress users and syncing between
 * them and users in the Authorizer lists.
 */
class Sync_Userdata extends Singleton {

	/**
	 * Adds all WordPress users in the current site to the approved list,
	 * unless they are already in the blocked list. Also removes them
	 * from the pending list if they are there.
	 *
	 * Runs in plugin activation hook.
	 *
	 * @return void
	 */
	public function add_wp_users_to_approved_list() {
		$options = Options::get_instance();
		// Add current WordPress users to the approved list.
		$auth_multisite_settings_access_users_approved = is_multisite() ? get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', array() ) : array();
		$auth_settings_access_users_pending            = $options->get( 'access_users_pending', Helper::SINGLE_CONTEXT );
		$auth_settings_access_users_approved           = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
		$auth_settings_access_users_blocked            = $options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT );
		$updated                                       = false;
		foreach ( get_users() as $user ) {
			// Skip if user is in blocked list.
			if ( Helper::in_multi_array( $user->user_email, $auth_settings_access_users_blocked ) ) {
				continue;
			}
			// Remove from pending list if there.
			foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
				if ( 0 === strcasecmp( $pending_user['email'], $user->user_email ) ) {
					unset( $auth_settings_access_users_pending[ $key ] );
					$updated = true;
				}
			}
			// Skip if user is in multisite approved list.
			if ( Helper::in_multi_array( $user->user_email, $auth_multisite_settings_access_users_approved ) ) {
				continue;
			}
			// Add to approved list if not there.
			if ( ! Helper::in_multi_array( $user->user_email, $auth_settings_access_users_approved ) ) {
				$approved_user = array(
					'email'      => Helper::lowercase( $user->user_email ),
					'role'       => count( $user->roles ) > 0 ? $user->roles[0] : '',
					'date_added' => wp_date( 'M Y', strtotime( $user->user_registered ) ),
					'local_user' => true,
				);
				array_push( $auth_settings_access_users_approved, $approved_user );
				$updated = true;
			}
		}
		if ( $updated ) {
			update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
			update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
		}
	}


	/**
	 * On an admin page load, check for edge case (network-approved user who has
	 * not yet been added to this particular blog in a multisite). Note: we do
	 * this because check_user_access() runs on the parse_request hook, which
	 * does not fire on wp-admin pages.
	 *
	 * Action: init
	 *
	 * @return void
	 */
	public function init__maybe_add_network_approved_user() {
		global $current_user;
		$options = Options::get_instance();

		// If this is a multisite install and we have a logged in user that's not
		// a member of this blog, but is (network) approved, add them to this blog.
		if (
			is_admin() &&
			is_multisite() &&
			is_user_logged_in() &&
			! is_user_member_of_blog() &&
			Authorization::get_instance()->is_email_in_list( $current_user->user_email, 'approved' )
		) {
			// Get all approved users.
			$auth_settings_access_users_approved = $options->sanitize_user_list(
				array_merge(
					$options->get( 'access_users_approved', Helper::SINGLE_CONTEXT ),
					$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
				)
			);

			// Get user info (we need user role).
			$user_info = Helper::get_user_info_from_list(
				$current_user->user_email,
				$auth_settings_access_users_approved
			);

			// Add user to blog.
			add_user_to_blog( get_current_blog_id(), $current_user->ID, $user_info['role'] );

			// Refresh user permissions.
			$current_user = new \WP_User( $current_user->ID ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}
	}


	/**
	 * Send a welcome email message to a newly approved user (if the "Should
	 * email approved users" setting is enabled).
	 *
	 * @param  string $email Email address to send welcome email to.
	 * @return bool          Whether the email was sent.
	 */
	public function maybe_email_welcome_message( $email ) {
		// Get option for whether to email welcome messages.
		$options                         = Options::get_instance();
		$should_email_new_approved_users = $options->get( 'access_should_email_approved_users' );

		// Do not send welcome email if option not enabled.
		if ( '1' !== $should_email_new_approved_users ) {
			return false;
		}

		// Make sure we didn't just email this user (can happen with
		// multiple admins saving at the same time, or by clicking
		// Approve button too rapidly).
		$recently_sent_emails = get_option( 'auth_settings_recently_sent_emails' );
		if ( false === $recently_sent_emails ) {
			$recently_sent_emails = array();
		}
		foreach ( $recently_sent_emails as $key => $recently_sent_email ) {
			if ( $recently_sent_email['time'] < strtotime( 'now -1 minutes' ) ) {
				// Remove emails sent more than 1 minute ago.
				unset( $recently_sent_emails[ $key ] );
			} elseif ( $recently_sent_email['email'] === $email ) {
				// Sent an email to this user within the last 1 minute, so
				// quit without sending.
				return false;
			}
		}
		// Add the email we're about to send to the list.
		$recently_sent_emails[] = array(
			'email' => $email,
			'time'  => time(),
		);
		update_option( 'auth_settings_recently_sent_emails', $recently_sent_emails );

		// Get welcome email subject and body text.
		$subject = $options->get( 'access_email_approved_users_subject' );
		$body    = apply_filters( 'the_content', $options->get( 'access_email_approved_users_body' ) );

		// Fail if the subject/body options don't exist or are empty.
		if ( is_null( $subject ) || is_null( $body ) || strlen( $subject ) === 0 || strlen( $body ) === 0 ) {
			return false;
		}

		// Replace approved shortcode patterns in subject and body.
		$site_name = get_bloginfo( 'name' );
		$site_url  = get_site_url();
		$subject   = str_replace( '[site_name]', $site_name, $subject );
		$body      = str_replace( '[site_name]', $site_name, $body );
		$body      = str_replace( '[site_url]', $site_url, $body );
		$body      = str_replace( '[user_email]', $email, $body );
		$headers   = 'Content-type: text/html' . "\r\n";

		// Send email.
		wp_mail( $email, $subject, $body, $headers );

		// Indicate mail was sent.
		return true;
	}


	/**
	 * When they successfully log in, make sure WordPress users are in the approved list.
	 *
	 * Action: wp_login
	 *
	 * @param  string $user_login Username of the user logging in.
	 * @param  object $user       WP_User object of the user logging in.
	 * @return void
	 */
	public function ensure_wordpress_user_in_approved_list_on_login( $user_login, $user ) {
		$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles );
	}


	/**
	 * Update user role in approved list if it's changed via bulk action on the
	 * WordPress list users page.
	 *
	 * @hook set_user_role
	 *
	 * @param integer $user_id   The user ID.
	 * @param string  $role      The new role.
	 * @param array   $old_roles An array of the user's previous roles.
	 */
	public function set_user_role_sync_role( $user_id = 0, $role = '', $old_roles = array() ) {
		// Ensure valid user ID and user has permission to edit this user.
		if ( empty( $user_id ) || ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		// Get original user object (fail if not a real WordPress user).
		$userdata = get_userdata( $user_id );
		if ( ! $userdata ) {
			return;
		}

		// If user is in approved list, update his/her associated role.
		if ( Authorization::get_instance()->is_email_in_list( $userdata->user_email, 'approved' ) ) {
			$changed                             = false;
			$options                             = Options::get_instance();
			$auth_settings_access_users_approved = $options->sanitize_user_list( $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT ) );
			foreach ( $auth_settings_access_users_approved as $key => $check_user ) {
				if ( 0 === strcasecmp( $check_user['email'], $userdata->user_email ) ) {
					if ( empty( $role ) ) {
						unset( $auth_settings_access_users_approved[ $key ] );
						$changed = true;
					} elseif ( $auth_settings_access_users_approved[ $key ]['role'] !== $role ) {
						$auth_settings_access_users_approved[ $key ]['role'] = $role;
						$changed = true;
					}
				}
			}
			if ( $changed ) {
				update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
			}
		}
	}


	/**
	 * Sync any email address changes to WordPress accounts to the corresponding
	 * entry in the Authorizer approved list.
	 *
	 * Note: This filter fires in wp_update_user() if the update includes an
	 * email address change, and fires after all security and integrity checks
	 * have been performed, so we can simply update the Authorizer approved
	 * list, changing the email address on the approved entry, and removing any
	 * existing entries that also have the new email address (duplicates).
	 *
	 * Filter: send_email_change_email
	 *
	 * @param bool  $send     Whether to send the email.
	 * @param array $user     The original user array.
	 * @param array $userdata The updated user array.
	 */
	public function edit_user_profile_update_email( $send, $user, $userdata ) {
		$options = Options::get_instance();

		// If we're in multisite, update the email on all sites in the network
		// (and remove from any subsites if it's a network-approved user).
		if ( is_multisite() ) {
			// If it's a multisite approved user, sync the email there.
			$changed_user_is_multisite_user = false;
			if ( Authorization::get_instance()->is_email_in_list( $user['user_email'], 'approved', 'multisite' ) ) {
				$changed_user_is_multisite_user                = true;
				$auth_multisite_settings_access_users_approved = $options->sanitize_user_list(
					$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
				);
				foreach ( $auth_multisite_settings_access_users_approved as $key => $check_user ) {
					// Update old user email in approved list to the new email.
					if ( 0 === strcasecmp( $check_user['email'], $user['user_email'] ) ) {
						$auth_multisite_settings_access_users_approved[ $key ]['email'] = Helper::lowercase( $userdata['user_email'] );
					}
					// If new user email is already in approved list, remove that entry.
					if ( 0 === strcasecmp( $check_user['email'], $userdata['user_email'] ) ) {
						unset( $auth_multisite_settings_access_users_approved[ $key ] );
					}
				}
				update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
			}

			// Go through all approved lists on individual sites and sync this user there.
			// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
			$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
			foreach ( $sites as $site ) {
				$updated                             = false;
				$blog_id                             = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
				$auth_settings_access_users_approved = get_blog_option( $blog_id, 'auth_settings_access_users_approved', array() );
				foreach ( $auth_settings_access_users_approved as $key => $check_user ) {
					// Update old user email in approved list to the new email.
					if ( 0 === strcasecmp( $check_user['email'], $user['user_email'] ) ) {
						// But if the user is already a multisite user, just remove the entry in the subsite.
						if ( $changed_user_is_multisite_user ) {
							unset( $auth_settings_access_users_approved[ $key ] );
						} else {
							$auth_settings_access_users_approved[ $key ]['email'] = Helper::lowercase( $userdata['user_email'] );
						}
						$updated = true;
					}
					// If new user email is already in approved list, remove that entry.
					if ( 0 === strcasecmp( $check_user['email'], $userdata['user_email'] ) ) {
						unset( $auth_settings_access_users_approved[ $key ] );
						$updated = true;
					}
				}
				if ( $updated ) {
					update_blog_option( $blog_id, 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
				}
			}
		} elseif ( Authorization::get_instance()->is_email_in_list( $user['user_email'], 'approved' ) ) {
			// In a single site environment, just find the old user in the approved list and update the email.
			$auth_settings_access_users_approved = $options->sanitize_user_list( $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT ) );
			foreach ( $auth_settings_access_users_approved as $key => $check_user ) {
				// Update old user email in approved list to the new email.
				if ( 0 === strcasecmp( $check_user['email'], $user['user_email'] ) ) {
					$auth_settings_access_users_approved[ $key ]['email'] = Helper::lowercase( $userdata['user_email'] );
				}
				// If new user email is already in approved list, remove that entry.
				if ( 0 === strcasecmp( $check_user['email'], $userdata['user_email'] ) ) {
					unset( $auth_settings_access_users_approved[ $key ] );
				}
			}
			update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
		}

		// We're hooking into this filter merely for its location in the codebase,
		// so make sure to return the filter value unmodified.
		return $send;
	}


	/**
	 * Remove user from authorizer lists when that user is deleted in WordPress.
	 *
	 * Action: delete_user
	 *
	 * @param  int $user_id User ID to remove.
	 * @return void
	 */
	public function remove_user_from_authorizer_when_deleted( $user_id ) {
		$options       = Options::get_instance();
		$user          = get_user_by( 'id', $user_id );
		$deleted_email = $user->user_email;

		// Remove user from pending/approved lists and save.
		$list_names = array( 'access_users_pending', 'access_users_approved' );
		foreach ( $list_names as $list_name ) {
			$user_list    = $options->sanitize_user_list( $options->get( $list_name, Helper::SINGLE_CONTEXT ) );
			$list_changed = false;
			foreach ( $user_list as $key => $existing_user ) {
				if ( 0 === strcasecmp( $deleted_email, $existing_user['email'] ) ) {
					$list_changed = true;
					unset( $user_list[ $key ] );
				}
			}
			if ( $list_changed ) {
				update_option( 'auth_settings_' . $list_name, $user_list );
			}
		}
	}


	/**
	 * Remove multisite user from authorizer lists when that user is deleted from Network Users.
	 *
	 * Action: wpmu_delete_user
	 *
	 * @param  int $user_id User ID to remove.
	 * @return void
	 */
	public function remove_network_user_from_authorizer_when_deleted( $user_id ) {
		$options       = Options::get_instance();
		$user          = get_user_by( 'id', $user_id );
		$deleted_email = $user->user_email;

		// Go through multisite approved user list and remove this user.
		$auth_multisite_settings_access_users_approved = $options->sanitize_user_list(
			$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
		);
		$list_changed                                  = false;
		foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
			if ( 0 === strcasecmp( $deleted_email, $existing_user['email'] ) ) {
				$list_changed = true;
				unset( $auth_multisite_settings_access_users_approved[ $key ] );
			}
		}
		if ( $list_changed ) {
			update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
		}

		// Go through all pending/approved lists on individual sites and remove this user from them.
		// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
		$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
		foreach ( $sites as $site ) {
			$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
			$this->remove_network_user_from_site_when_removed( $user_id, $blog_id );
		}
	}


	/**
	 * Remove multisite user from a specific site's lists when that user is removed from the site.
	 *
	 * Action: remove_user_from_blog
	 *
	 * @param  int $user_id User ID to remove.
	 * @param  int $blog_id Blog ID to remove from.
	 * @return void
	 */
	public function remove_network_user_from_site_when_removed( $user_id, $blog_id ) {
		$user          = get_user_by( 'id', $user_id );
		$deleted_email = $user->user_email;

		$list_names = array( 'access_users_pending', 'access_users_approved' );
		foreach ( $list_names as $list_name ) {
			$user_list    = get_blog_option( $blog_id, 'auth_settings_' . $list_name, array() );
			$list_changed = false;
			foreach ( $user_list as $key => $existing_user ) {
				if ( 0 === strcasecmp( $deleted_email, $existing_user['email'] ) ) {
					$list_changed = true;
					unset( $user_list[ $key ] );
				}
			}
			if ( $list_changed ) {
				update_blog_option( $blog_id, 'auth_settings_' . $list_name, $user_list );
			}
		}
	}


	/**
	 * Helper: Add multisite user to a specific site's approved list.
	 *
	 * @param  int $user_id User ID to add.
	 * @param  int $blog_id Blog ID to add to.
	 * @return void
	 */
	protected function add_network_user_to_site( $user_id, $blog_id ) {
		// Switch to blog.
		switch_to_blog( $blog_id );

		// Get user details and role.
		$options             = Options::get_instance();
		$access_default_role = $options->get( 'access_default_role', Helper::SINGLE_CONTEXT, 'allow override' );
		$user                = get_user_by( 'id', $user_id );
		$user_email          = $user->user_email;
		$user_role           = $user && is_array( $user->roles ) && count( $user->roles ) > 0 ? $user->roles[0] : $access_default_role;

		// Add user to approved list if not already there and not in blocked list.
		$auth_settings_access_users_approved = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
		$auth_settings_access_users_blocked  = $options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT );
		if ( ! Helper::in_multi_array( $user_email, $auth_settings_access_users_approved ) && ! Helper::in_multi_array( $user_email, $auth_settings_access_users_blocked ) ) {
			$approved_user = array(
				'email'      => Helper::lowercase( $user_email ),
				'role'       => $user_role,
				'date_added' => wp_date( 'M Y', strtotime( $user->user_registered ) ),
				'local_user' => true,
			);
			array_push( $auth_settings_access_users_approved, $approved_user );
			update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
		}

		// Restore original blog.
		restore_current_blog();
	}


	/**
	 * Multisite:
	 * When an existing user is invited to the current site (or a new user is created),
	 * add them to the authorizer approved list. This action fires when the admin
	 * doesn't select the "Skip Confirmation Email" option.
	 *
	 * Action: invite_user
	 *
	 * @param int    $user_id     The invited user's ID.
	 * @param array  $role        The role of the invited user (or none if a new user creation).
	 * @param string $newuser_key The key of the invitation.
	 */
	public function add_existing_user_to_authorizer_when_created( $user_id, $role = array(), $newuser_key = '' ) {
		$user = get_user_by( 'id', $user_id );
		$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles, $role );
	}


	/**
	 * Multisite:
	 * When an existing user is invited to the current site (or a new user is created),
	 * add them to the authorizer approved list. This action fires when the admin
	 * selects the "Skip Confirmation Email" option.
	 *
	 * Action: added_existing_user
	 *
	 * @param int   $user_id The invited user's ID.
	 * @param mixed $result  True on success or a WP_Error object if the user doesn't exist.
	 */
	public function add_existing_user_to_authorizer_when_created_noconfirmation( $user_id, $result ) {
		$user = get_user_by( 'id', $user_id );
		$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles );
	}


	/**
	 * Multisite:
	 * When a new user is invited to the current site (or a new user is created),
	 * add them to the authorizer approved list.
	 *
	 * Action: after_signup_user
	 *
	 * @param string $user       User's requested login name.
	 * @param string $user_email User's email address.
	 * @param string $key        User's activation key.
	 * @param array  $meta       Additional signup meta, including initially set roles.
	 */
	public function add_new_user_to_authorizer_when_created( $user, $user_email, $key, $meta ) {
		$user_roles = isset( $meta['new_role'] ) ? array( $meta['new_role'] ) : array();
		$this->add_user_to_authorizer_when_created( $user_email, time(), $user_roles );
	}


	/**
	 * Single site:
	 * When a new user is added in single site mode, add them to the authorizer
	 * approved list.
	 *
	 * Action: edit_user_created_user
	 *
	 * @param int    $user_id ID of the newly created user.
	 * @param string $notify  Type of notification that should happen. See
	 *                        wp_send_new_user_notifications() for more
	 *                        information on possible values.
	 */
	public function add_new_user_to_authorizer_when_created_single_site( $user_id, $notify ) {
		$user = get_user_by( 'id', $user_id );
		$this->add_user_to_authorizer_when_created( $user->user_email, $user->user_registered, $user->roles );
	}


	/**
	 * Helper: When a new user is added/invited to the current site (or a new
	 * user is created), add them to the authorizer approved list.
	 *
	 * @param string $user_email      Email address of user to add.
	 * @param string $date_registered Date user registered.
	 * @param array  $user_roles      Role to add for user.
	 * @param array  $default_role    Default role, if no role specified.
	 */
	protected function add_user_to_authorizer_when_created( $user_email, $date_registered, $user_roles = array(), $default_role = array() ) {
		$options                                       = Options::get_instance();
		$auth_multisite_settings_access_users_approved = is_multisite() ? get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', array() ) : array();
		$auth_settings_access_users_pending            = $options->get( 'access_users_pending', Helper::SINGLE_CONTEXT );
		$auth_settings_access_users_approved           = $options->get( 'access_users_approved', Helper::SINGLE_CONTEXT );
		$auth_settings_access_users_blocked            = $options->get( 'access_users_blocked', Helper::SINGLE_CONTEXT );

		// Get default role if one isn't specified.
		if ( count( $default_role ) < 1 ) {
			$default_role = '';
		} else {
			// If default role was provided, it came from the invite_user hook, and
			// only contains the role's display name. Here we look up the actual role
			// name to save (and default to no role if the display name isn't found).
			global $wp_roles;
			$default_role_display_name = $default_role['name'];
			$default_role              = '';
			if ( ! empty( $wp_roles ) && is_array( $wp_roles->role_names ) ) {
				foreach ( $wp_roles->role_names as $role_name => $display_name ) {
					if ( $default_role_display_name === $display_name ) {
						$default_role = $role_name;
						break;
					}
				}
			}
		}

		$updated = false;

		// Skip if user is in blocked list.
		if ( Helper::in_multi_array( $user_email, $auth_settings_access_users_blocked ) ) {
			return;
		}
		// Remove from pending list if there.
		foreach ( $auth_settings_access_users_pending as $key => $pending_user ) {
			if ( 0 === strcasecmp( $pending_user['email'], $user_email ) ) {
				unset( $auth_settings_access_users_pending[ $key ] );
				$updated = true;
			}
		}
		// Skip if user is in multisite approved list.
		if ( Helper::in_multi_array( $user_email, $auth_multisite_settings_access_users_approved ) ) {
			return;
		}
		// Add to approved list if not there.
		if ( ! Helper::in_multi_array( $user_email, $auth_settings_access_users_approved ) ) {
			$approved_user = array(
				'email'      => Helper::lowercase( $user_email ),
				'role'       => is_array( $user_roles ) && count( $user_roles ) > 0 ? $user_roles[0] : $default_role,
				'date_added' => wp_date( 'M Y', strtotime( $date_registered ) ),
				'local_user' => true,
			);
			array_push( $auth_settings_access_users_approved, $approved_user );
			$updated = true;
		}

		if ( $updated ) {
			update_option( 'auth_settings_access_users_pending', $auth_settings_access_users_pending );
			update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
		}
	}


	/**
	 * Multisite:
	 * When a user is granted super admin status (checkbox on network user edit
	 * screen), add them to the authorizer network approved list. Also remove
	 * them from pending/approved list on any individual sites.
	 *
	 * Action: grant_super_admin
	 *
	 * @param int $user_id The user's ID.
	 */
	public function grant_super_admin__add_to_network_approved( $user_id ) {
		$options    = Options::get_instance();
		$user       = get_user_by( 'id', $user_id );
		$user_email = $user->user_email;

		// Add user to multisite approved user list (if not already there).
		$auth_multisite_settings_access_users_approved = $options->sanitize_user_list(
			$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
		);
		if ( ! Helper::in_multi_array( $user_email, $auth_multisite_settings_access_users_approved ) ) {
			$multisite_approved_user = array(
				'email'      => Helper::lowercase( $user_email ),
				'role'       => count( $user->roles ) > 0 ? $user->roles[0] : 'administrator',
				'date_added' => wp_date( 'M Y', strtotime( $user->user_registered ) ),
				'local_user' => true,
			);
			array_push( $auth_multisite_settings_access_users_approved, $multisite_approved_user );
			update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
		}

		// Go through all pending/approved lists on individual sites and remove this user from them.
		// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
		$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
		foreach ( $sites as $site ) {
			$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
			$this->remove_network_user_from_site_when_removed( $user_id, $blog_id );
		}
	}


	/**
	 * Multisite:
	 * When a user's super admin status is revoked (checkbox on network user edit
	 * screen), remove them from the authorizer network approved list. Also add
	 * them to approved list on any individual sites they are already a part of.
	 *
	 * Action: revoke_super_admin
	 *
	 * @param int $user_id The user's ID.
	 */
	public function revoke_super_admin__remove_from_network_approved( $user_id ) {
		$options       = Options::get_instance();
		$user          = get_user_by( 'id', $user_id );
		$revoked_email = $user->user_email;

		// Go through multisite approved user list and remove this user.
		$auth_multisite_settings_access_users_approved = $options->sanitize_user_list(
			$options->get( 'access_users_approved', Helper::NETWORK_CONTEXT )
		);
		$list_changed                                  = false;
		foreach ( $auth_multisite_settings_access_users_approved as $key => $existing_user ) {
			if ( 0 === strcasecmp( $revoked_email, $existing_user['email'] ) ) {
				$list_changed = true;
				unset( $auth_multisite_settings_access_users_approved[ $key ] );
			}
		}
		if ( $list_changed ) {
			update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
		}

		// Go through this user's current sites and add them to the approved list
		// (since they are no longer on the network approved list).
		$sites_of_user = get_blogs_of_user( $user_id );
		foreach ( $sites_of_user as $site ) {
			$blog_id = $site->userblog_id;
			$this->add_network_user_to_site( $user_id, $blog_id );
		}
	}
}
