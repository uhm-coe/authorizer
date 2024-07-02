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

/**
 * Run any database migrations or plugin updates when installing a new version.
 */
class Updates extends Singleton {

	/**
	 * Plugin Update Routines.
	 *
	 * Action: plugins_loaded
	 */
	public function auth_update_check() {
		$options = Options::get_instance();

		// Get current version.
		$needs_updating = false;
		if ( is_multisite() ) {
			$auth_version = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_version' );
		} else {
			$auth_version = get_option( 'auth_version' );
		}

		// Update: migrate user lists to own options (addresses concurrency
		// when saving plugin options, since user lists are changed often
		// and we don't want to overwrite changes to the lists when an
		// admin saves all of the plugin options.)
		// Note: Pending user list is changed whenever a new user tries to
		// log in; approved and blocked lists are changed whenever an admin
		// changes them from the multisite panel, the dashboard widget, or
		// the plugin options page.
		$update_if_older_than = 20140709;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Copy single site user lists to new options (if they exist).
			$auth_settings = get_option( 'auth_settings' );
			if ( is_array( $auth_settings ) && array_key_exists( 'access_users_pending', $auth_settings ) ) {
				update_option( 'auth_settings_access_users_pending', $auth_settings['access_users_pending'] );
				unset( $auth_settings['access_users_pending'] );
				update_option( 'auth_settings', $auth_settings );
			}
			if ( is_array( $auth_settings ) && array_key_exists( 'access_users_approved', $auth_settings ) ) {
				update_option( 'auth_settings_access_users_approved', $auth_settings['access_users_approved'] );
				unset( $auth_settings['access_users_approved'] );
				update_option( 'auth_settings', $auth_settings );
			}
			if ( is_array( $auth_settings ) && array_key_exists( 'access_users_blocked', $auth_settings ) ) {
				update_option( 'auth_settings_access_users_blocked', $auth_settings['access_users_blocked'] );
				unset( $auth_settings['access_users_blocked'] );
				update_option( 'auth_settings', $auth_settings );
			}
			// Copy multisite user lists to new options (if they exist).
			if ( is_multisite() ) {
				$auth_multisite_settings = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', array() );
				if ( is_array( $auth_multisite_settings ) && array_key_exists( 'access_users_pending', $auth_multisite_settings ) ) {
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_pending', $auth_multisite_settings['access_users_pending'] );
					unset( $auth_multisite_settings['access_users_pending'] );
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', $auth_multisite_settings );
				}
				if ( is_array( $auth_multisite_settings ) && array_key_exists( 'access_users_approved', $auth_multisite_settings ) ) {
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings['access_users_approved'] );
					unset( $auth_multisite_settings['access_users_approved'] );
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', $auth_multisite_settings );
				}
				if ( is_array( $auth_multisite_settings ) && array_key_exists( 'access_users_blocked', $auth_multisite_settings ) ) {
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_blocked', $auth_multisite_settings['access_users_blocked'] );
					unset( $auth_multisite_settings['access_users_blocked'] );
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', $auth_multisite_settings );
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added options (forgot to do
		// this, so some users are getting debug log notices about undefined
		// indexes in $auth_settings).
		$update_if_older_than = 20160831;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// Get all blog ids.
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					// Set meaningful defaults for other sites in the network.
					$options->set_default_options();
					// Switch back to original blog.
					restore_current_blog();
				}
			} else {
				// Set meaningful defaults for this site.
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Migrate LDAP passwords encrypted with mcrypt since mcrypt is
		// deprecated as of PHP 7.1. Use openssl library instead.
		$update_if_older_than = 20170510;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			if ( is_multisite() ) {
				// Reencrypt LDAP passwords in each site in the network.
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id       = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					$auth_settings = get_blog_option( $blog_id, 'auth_settings', array() );
					if ( array_key_exists( 'ldap_password', $auth_settings ) && strlen( $auth_settings['ldap_password'] ) > 0 ) {
						$plaintext_ldap_password        = Helper::decrypt( $auth_settings['ldap_password'], 'mcrypt' );
						$auth_settings['ldap_password'] = Helper::encrypt( $plaintext_ldap_password );
						update_blog_option( $blog_id, 'auth_settings', $auth_settings );
					}
				}
			} else {
				// Reencrypt LDAP password on this single-site install.
				$auth_settings = get_option( 'auth_settings', array() );
				if ( array_key_exists( 'ldap_password', $auth_settings ) && strlen( $auth_settings['ldap_password'] ) > 0 ) {
					$plaintext_ldap_password        = Helper::decrypt( $auth_settings['ldap_password'], 'mcrypt' );
					$auth_settings['ldap_password'] = Helper::encrypt( $plaintext_ldap_password );
					update_option( 'auth_settings', $auth_settings );
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Migrate LDAP passwords encrypted with mcrypt since mcrypt is
		// deprecated as of PHP 7.1. Use openssl library instead.
		// Note: Forgot to update the auth_multisite_settings ldap password! Do it here.
		$update_if_older_than = 20170511;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			if ( is_multisite() ) {
				// Reencrypt LDAP password in network (multisite) options.
				$auth_multisite_settings = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', array() );
				if ( array_key_exists( 'ldap_password', $auth_multisite_settings ) && strlen( $auth_multisite_settings['ldap_password'] ) > 0 ) {
					$plaintext_ldap_password                  = Helper::decrypt( $auth_multisite_settings['ldap_password'], 'mcrypt' );
					$auth_multisite_settings['ldap_password'] = Helper::encrypt( $plaintext_ldap_password );
					update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings', $auth_multisite_settings );
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Remove duplicates from approved list caused by authorizer_automatically_approve_login
		// filter not respecting users who are already in the approved list
		// (causing them to get re-added each time they logged in).
		$update_if_older_than = 20170711;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Remove duplicates from approved user lists.
			if ( is_multisite() ) {
				// Remove duplicates from each site in the multisite.
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id                             = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					$auth_settings_access_users_approved = get_blog_option( $blog_id, 'auth_settings_access_users_approved', array() );
					if ( is_array( $auth_settings_access_users_approved ) ) {
						$should_update   = false;
						$distinct_emails = array();
						foreach ( $auth_settings_access_users_approved as $key => $user ) {
							if ( in_array( $user['email'], $distinct_emails, true ) ) {
								$should_update = true;
								unset( $auth_settings_access_users_approved[ $key ] );
							} else {
								$distinct_emails[] = $user['email'];
							}
						}
						if ( $should_update ) {
							update_blog_option( $blog_id, 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
						}
					}
				}
				// Remove duplicates from multisite approved user list.
				$auth_multisite_settings_access_users_approved = get_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', array() );
				if ( is_array( $auth_multisite_settings_access_users_approved ) ) {
					$should_update   = false;
					$distinct_emails = array();
					foreach ( $auth_multisite_settings_access_users_approved as $key => $user ) {
						if ( in_array( $user['email'], $distinct_emails, true ) ) {
							$should_update = true;
							unset( $auth_multisite_settings_access_users_approved[ $key ] );
						} else {
							$distinct_emails[] = $user['email'];
						}
					}
					if ( $should_update ) {
						update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_multisite_settings_access_users_approved', $auth_multisite_settings_access_users_approved );
					}
				}
			} else {
				// Remove duplicates from single site approved user list.
				$auth_settings_access_users_approved = get_option( 'auth_settings_access_users_approved' );
				if ( is_array( $auth_settings_access_users_approved ) ) {
					$should_update   = false;
					$distinct_emails = array();
					foreach ( $auth_settings_access_users_approved as $key => $user ) {
						if ( in_array( $user['email'], $distinct_emails, true ) ) {
							$should_update = true;
							unset( $auth_settings_access_users_approved[ $key ] );
						} else {
							$distinct_emails[] = $user['email'];
						}
					}
					if ( $should_update ) {
						update_option( 'auth_settings_access_users_approved', $auth_settings_access_users_approved );
					}
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default value for newly added option advanced_widget_enabled.
		$update_if_older_than = 20171023;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default value for newly added option advanced_users_per_page.
		$update_if_older_than = 20171215;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default value for newly added options advanced_users_sort_by and advanced_users_sort_order.
		$update_if_older_than = 20171219;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default value for newly added option cas_link_on_username.
		$update_if_older_than = 20190227;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default value for newly added option advanced_disable_wp_login.
		$update_if_older_than = 20200331;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added oauth2 options.
		$update_if_older_than = 20201217;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added oauth2_hosteddomain option.
		$update_if_older_than = 20210624;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added ldap_search_filter option.
		$update_if_older_than = 20210924;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added ldap_test_user option.
		$update_if_older_than = 20220222;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Remove any cached LDAP test password.
		$update_if_older_than = 20220426;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id       = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					$auth_settings = get_blog_option( $blog_id, 'auth_settings', array() );
					if ( array_key_exists( 'ldap_test_pass', $auth_settings ) && strlen( $auth_settings['ldap_test_pass'] ) > 0 ) {
						unset( $auth_settings['ldap_test_pass'] );
						update_blog_option( $blog_id, 'auth_settings', $auth_settings );
					}
				}
			} else {
				$auth_settings = get_option( 'auth_settings', array() );
				if ( array_key_exists( 'ldap_test_pass', $auth_settings ) && strlen( $auth_settings['ldap_test_pass'] ) > 0 ) {
					unset( $auth_settings['ldap_test_pass'] );
					update_option( 'auth_settings', $auth_settings );
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added prevent_override_multisite option.
		$update_if_older_than = 20220506;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for newly added cas_method option.
		$update_if_older_than = 20220818;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options();
					restore_current_blog();
				}
			} else {
				$options->set_default_options();
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Set default values for missed multisite option ldap_test_user.
		$update_if_older_than = 20221101;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			// Provide default values for any $auth_settings options that don't exist.
			$options->set_default_options();
			if ( is_multisite() ) {
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					switch_to_blog( $blog_id );
					$options->set_default_options( array( 'set_multisite_options' => false ) );
					restore_current_blog();
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		// Update: Only save one auth_version in the database on multisite (instead
		// of a version for each subsite, which was unnecessary because the plugin
		// is updated once at the network level). Remove extra auth_version options.
		$update_if_older_than = 20230222;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			if ( is_multisite() ) {
				$network_blog_id = get_main_site_id( get_main_network_id() );
				// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
				$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
				foreach ( $sites as $site ) {
					$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
					// Don't delete auth_version on the main site in the network.
					if ( $network_blog_id === $blog_id ) {
						continue;
					}
					// Remove auth_version on subsites.
					switch_to_blog( $blog_id );
					delete_option( 'auth_version' );
					restore_current_blog();
				}
			}
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}

		/* phpcs:ignore Squiz.PHP.CommentedOutCode.Found
		// Update: TEMPLATE
		$update_if_older_than = YYYYMMDD;
		if ( false === $auth_version || intval( $auth_version ) < $update_if_older_than ) {
			////// PLACE UPDATE CODE HERE
			// Update version to reflect this change has been made.
			$auth_version   = $update_if_older_than;
			$needs_updating = true;
		}
		*/

		// Save new version number if we performed any updates.
		if ( $needs_updating ) {
			if ( is_multisite() ) {
				update_blog_option( get_main_site_id( get_main_network_id() ), 'auth_version', $auth_version );
			} else {
				update_option( 'auth_version', $auth_version );
			}
		}
	}
}
