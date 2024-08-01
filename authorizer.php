<?php
/**
 * Plugin Name:       Authorizer
 * Plugin URI:        https://github.com/uhm-coe/authorizer
 * Description:       Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., OAuth2, Google, LDAP, or CAS).
 * Version:           3.9.1
 * Requires at least: 4.9
 * Requires PHP:      7.4
 * Author:            Paul Ryan <prar@hawaii.edu>
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       authorizer
 *
 * Portions forked from Restricted Site Access plugin:
 *   http://wordpress.org/plugins/restricted-site-access/
 * Portions forked from wpCAS plugin:
 *   http://wordpress.org/extend/plugins/cas-authentication/
 * Portions forked from Limit Login Attempts:
 *   http://wordpress.org/plugins/limit-login-attempts/
 *
 * @package authorizer
 */

namespace Authorizer;

require_once __DIR__ . '/polyfills.php';

require_once __DIR__ . '/src/authorizer/abstract-class-singleton.php';

require_once __DIR__ . '/src/authorizer/class-wp-plugin-authorizer.php';

require_once __DIR__ . '/src/authorizer/class-helper.php';

require_once __DIR__ . '/src/authorizer/class-updates.php';

require_once __DIR__ . '/src/authorizer/class-authentication.php';
require_once __DIR__ . '/src/authorizer/class-authorization.php';
require_once __DIR__ . '/src/authorizer/class-login-form.php';
require_once __DIR__ . '/src/authorizer/class-dashboard-widget.php';
require_once __DIR__ . '/src/authorizer/class-ajax-endpoints.php';
require_once __DIR__ . '/src/authorizer/class-sync-userdata.php';
require_once __DIR__ . '/src/authorizer/class-admin-page.php';

require_once __DIR__ . '/src/authorizer/class-options.php';

require_once __DIR__ . '/src/authorizer/options/class-access-lists.php';
require_once __DIR__ . '/src/authorizer/options/class-login-access.php';
require_once __DIR__ . '/src/authorizer/options/class-public-access.php';
require_once __DIR__ . '/src/authorizer/options/class-external.php';

require_once __DIR__ . '/src/authorizer/options/external/class-oauth2.php';
require_once __DIR__ . '/src/authorizer/options/external/class-google.php';
require_once __DIR__ . '/src/authorizer/options/external/class-cas.php';
require_once __DIR__ . '/src/authorizer/options/external/class-ldap.php';

require_once __DIR__ . '/src/authorizer/options/class-advanced.php';

/**
 * Add composer libraries.
 */
require_once __DIR__ . '/vendor/autoload.php';

/**
 * Helper function to always return the path to the plugin's entry point. Used
 * when locating asset paths using plugins_url().
 */
function plugin_root() {
	return __FILE__;
}

// Instantiate the plugin class.
WP_Plugin_Authorizer::get_instance();
