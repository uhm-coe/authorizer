<?php
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

namespace Authorizer;

/**
 * Static class of helper methods.
 */
class Helper {

	/**
	 * Constants for determining our admin context (network or individual site).
	 */
	const NETWORK_CONTEXT = 'multisite_admin';
	const SINGLE_CONTEXT  = 'single_admin';


	/**
	 * HTML allowed when rendering translatable strings in the Authorizer UI.
	 * This is passed to wp_kses() when sanitizing HMTL strings.
	 *
	 * @var array
	 */
	public static $allowed_html = array(
		'a'      => array(
			'class'  => array(),
			'href'   => array(),
			'style'  => array(),
			'target' => array(),
			'title'  => array(),
		),
		'b'      => array(),
		'br'     => array(),
		'div'    => array(
			'class' => array(),
		),
		'em'     => array(),
		'hr'     => array(),
		'i'      => array(),
		'input'  => array(
			'aria-describedby' => array(),
			'class'            => array(),
			'id'               => array(),
			'name'             => array(),
			'size'             => array(),
			'type'             => array(),
			'value'            => array(),
		),
		'label'  => array(
			'class' => array(),
			'for'   => array(),
		),
		'p'      => array(
			'style' => array(),
		),
		'span'   => array(
			'aria-hidden' => array(),
			'class'       => array(),
			'id'          => array(),
			'style'       => array(),
		),
		'strong' => array(),
	);

	/**
	 * Encryption key (not secret!).
	 *
	 * @var string
	 */
	protected static $key = "8QxnrvjdtweisvCBKEY!+0\0\0";

	/**
	 * Encryption salt (not secret!).
	 *
	 * @var string
	 */
	protected static $iv = 'R_O2D]jPn]1[fhJl!-P1.oe';


	/**
	 * Grabs the admin context (single site or multisite) from the passed
	 * arguments.
	 *
	 * @param  array $args  Args (e.g., 'context' => Helper::NETWORK_CONTEXT).
	 * @return string       Current mode.
	 */
	public static function get_context( $args ) {
		if (
			is_array( $args ) &&
			array_key_exists( 'context', $args ) &&
			self::NETWORK_CONTEXT === $args['context']
		) {
			return self::NETWORK_CONTEXT;
		} else {
			return self::SINGLE_CONTEXT;
		}
	}


	/**
	 * Helper function to generate an HTML class name for an option (used in
	 * Authorizer Settings in the Approved User list).
	 *
	 * @param  string  $suffix            Unique part of class name.
	 * @param  boolean $is_multisite_user Whether to add an auth-multisite class.
	 * @return string                     Class name, e.g., "auth-email auth-multisite-email".
	 */
	public static function get_css_class_name_for_option( $suffix = '', $is_multisite_user = false ) {
		return $is_multisite_user ? "auth-$suffix auth-multisite-$suffix" : "auth-$suffix";
	}


	/**
	 * Basic encryption using a public (not secret!) key. Used for general
	 * database obfuscation of passwords.
	 *
	 * @param  string $text    String to encrypt.
	 * @param  string $library Encryption library to use (openssl).
	 * @return string          Encrypted string.
	 */
	public static function encrypt( $text, $library = 'openssl' ) {
		$result = '';

		// Use openssl library (better) if it is enabled.
		if ( function_exists( 'openssl_encrypt' ) && 'openssl' === $library ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			$result = base64_encode(
				openssl_encrypt(
					$text,
					'AES-256-CBC',
					hash( 'sha256', self::$key ),
					0,
					substr( hash( 'sha256', self::$iv ), 0, 16 )
				)
			);
		} elseif ( function_exists( 'mcrypt_encrypt' ) ) { // Use mcrypt library (deprecated in PHP 7.1) if php5-mcrypt extension is enabled.
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			$result = base64_encode( mcrypt_encrypt( MCRYPT_RIJNDAEL_256, self::$key, $text, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' ) );
		} else { // Fall back to basic obfuscation.
			$length = strlen( $text );
			for ( $i = 0; $i < $length; $i++ ) {
				$char    = substr( $text, $i, 1 );
				$keychar = substr( self::$key, ( $i % strlen( self::$key ) ) - 1, 1 );
				$char    = chr( ord( $char ) + ord( $keychar ) );
				$result .= $char;
			}
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			$result = base64_encode( $result );
		}

		return $result;
	}


	/**
	 * Basic decryption using a public (not secret!) key. Used for general
	 * database obfuscation of passwords.
	 *
	 * @param  string $secret  String to encrypt.
	 * @param  string $library Encryption lib to use (openssl).
	 * @return string          Decrypted string
	 */
	public static function decrypt( $secret, $library = 'openssl' ) {
		$result = '';

		// Use openssl library (better) if it is enabled.
		if ( function_exists( 'openssl_decrypt' ) && 'openssl' === $library ) {
			$result = openssl_decrypt(
				base64_decode( $secret ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
				'AES-256-CBC',
				hash( 'sha256', self::$key ),
				0,
				substr( hash( 'sha256', self::$iv ), 0, 16 )
			);
		} elseif ( function_exists( 'mcrypt_decrypt' ) ) { // Use mcrypt library (deprecated in PHP 7.1) if php5-mcrypt extension is enabled.
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			$secret = base64_decode( $secret );
			$result = rtrim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, self::$key, $secret, MCRYPT_MODE_ECB, 'abcdefghijklmnopqrstuvwxyz012345' ), "\0$result" );
		} else { // Fall back to basic obfuscation.
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			$secret = base64_decode( $secret );
			$length = strlen( $secret );
			for ( $i = 0; $i < $length; $i++ ) {
				$char    = substr( $secret, $i, 1 );
				$keychar = substr( self::$key, ( $i % strlen( self::$key ) ) - 1, 1 );
				$char    = chr( ord( $char ) - ord( $keychar ) );
				$result .= $char;
			}
		}

		return $result;
	}


	/**
	 * In a multisite environment, returns true if the current user is logged
	 * in and a user of the current blog. In single site mode, simply returns
	 * true if the current user is logged in.
	 *
	 * @return bool Whether current user is logged in and a user of the current blog.
	 */
	public static function is_user_logged_in_and_blog_user() {
		$is_user_logged_in_and_blog_user = false;
		if ( is_multisite() ) {
			$is_user_logged_in_and_blog_user = is_user_logged_in() && is_user_member_of_blog( get_current_user_id() );
		} else {
			$is_user_logged_in_and_blog_user = is_user_logged_in();
		}
		return $is_user_logged_in_and_blog_user;
	}


	/**
	 * Helper function to get all available usermeta keys as an array.
	 *
	 * @return array All usermeta keys for user.
	 */
	public static function get_all_usermeta_keys() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$usermeta_keys = $wpdb->get_col( "SELECT DISTINCT $wpdb->usermeta.meta_key FROM $wpdb->usermeta" );
		return $usermeta_keys;
	}


	/**
	 * Helper function that prints option tags for a select element for all
	 * roles the current user has permission to assign.
	 *
	 * @param  string $selected_role Which role should be selected in the dropdown.
	 * @param  string $disable_input 'disabled' if select element should be disabled.
	 * @param  int    $admin_mode    Helper::NETWORK_CONTEXT if we are in that context.
	 * @return void
	 */
	public static function wp_dropdown_permitted_roles( $selected_role = 'subscriber', $disable_input = 'not disabled', $admin_mode = self::SINGLE_CONTEXT ) {
		$roles        = get_editable_roles();
		$current_user = wp_get_current_user();

		// If we're in network admin, also show any roles that might exist only on
		// specific sites in the network (themes can add their own roles).
		if ( self::NETWORK_CONTEXT === $admin_mode ) {
			// phpcs:ignore WordPress.WP.DeprecatedFunctions.wp_get_sitesFound
			$sites = function_exists( 'get_sites' ) ? get_sites() : wp_get_sites( array( 'limit' => PHP_INT_MAX ) );
			foreach ( $sites as $site ) {
				$blog_id = function_exists( 'get_sites' ) ? $site->blog_id : $site['blog_id'];
				switch_to_blog( $blog_id );
				$roles = array_merge( $roles, get_editable_roles() );
				restore_current_blog();
			}
			$unique_role_names = array();
			foreach ( $roles as $role_name => $role_info ) {
				if ( array_key_exists( $role_name, $unique_role_names ) ) {
					unset( $roles[ $role_name ] );
				} else {
					$unique_role_names[ $role_name ] = true;
				}
			}
		}

		// If the currently selected role exists, but is not in the list of roles,
		// the current user is not permitted to assign it. Assume they can't edit
		// that user's role at all. Return only the one role for the dropdown list.
		if ( strlen( $selected_role ) > 0 && ! array_key_exists( $selected_role, $roles ) && ! is_null( get_role( $selected_role ) ) ) {
			return;
		}

		// Print an option element for each permitted role.
		foreach ( $roles as $name => $role ) {
			$is_selected = $selected_role === $name;

			// Don't let a user change their own role (but network admins always can).
			$is_disabled = $selected_role !== $name && 'disabled' === $disable_input && ! ( is_multisite() && current_user_can( 'manage_network' ) );
			?>
			<option value="<?php echo esc_attr( $name ); ?>"<?php selected( $is_selected ); ?><?php disabled( $is_disabled ); ?>><?php echo esc_html( $role['name'] ); ?></option>
			<?php
		}

		// Print default role (no role).
		$is_selected = strlen( $selected_role ) === 0 || ! array_key_exists( $selected_role, $roles );
		$is_disabled = strlen( $selected_role ) > 0 && 'disabled' === $disable_input && ! ( is_multisite() && current_user_can( 'manage_network' ) );
		?>
		<option value=""<?php selected( $is_selected ); ?><?php disabled( $is_disabled ); ?>><?php esc_html_e( '&mdash; No role for this site &mdash;', 'authorizer' ); ?></option>
		<?php
	}


	/**
	 * Helper function to search a multidimensional array for a value.
	 *
	 * @param  string $needle           Value to search for.
	 * @param  array  $haystack         Multidimensional array to search.
	 * @param  string $strict_mode      'strict' if strict comparisons should be used.
	 * @param  string $case_sensitivity 'case sensitive' if comparisons should respect case.
	 * @return bool                     Whether needle was found.
	 */
	public static function in_multi_array( $needle = '', $haystack = array(), $strict_mode = 'not strict', $case_sensitivity = 'case insensitive' ) {
		if ( ! is_array( $haystack ) ) {
			return false;
		}
		if ( 'case insensitive' === $case_sensitivity ) {
			$needle = strtolower( $needle );
		}
		foreach ( $haystack as $item ) {
			if ( 'case insensitive' === $case_sensitivity && ! is_array( $item ) ) {
				$item = strtolower( $item );
			}
			if ( ( 'strict' === $strict_mode ? $item === $needle : $item == $needle ) || ( is_array( $item ) && self::in_multi_array( $needle, $item, $strict_mode, $case_sensitivity ) ) ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
				return true;
			}
		}
		return false;
	}


	/**
	 * Helper function to discover the email addresses in a value in a
	 * multidimensional array.
	 *
	 * @param  array $haystack Multidimensional array, possibly containing an email.
	 * @param  array $emails   Array of email addresses found.
	 * @return array            Array of Discovered emails, or empty array.
	 */
	public static function find_emails_in_multi_array( $haystack, &$emails = array() ) {
		if ( is_array( $haystack ) ) {
			foreach ( $haystack as $key => $value ) {
				self::find_emails_in_multi_array( $value, $emails );
			}
		} elseif ( filter_var( $haystack, FILTER_VALIDATE_EMAIL ) ) {
			$emails[] = $haystack;
		}

		return $emails;
	}


	/**
	 * Helper function to determine if an URL is accessible.
	 *
	 * @param  string $url URL that should be publicly reachable.
	 * @return boolean     Whether the URL is publicly reachable.
	 */
	public static function url_is_accessible( $url ) {
		// Use wp_remote_retrieve_response_code() to retrieve the URL.
		$response      = wp_remote_get( $url );
		$response_code = wp_remote_retrieve_response_code( $response );

		// Return true if the document has loaded successfully without any redirection or error.
		return $response_code >= 200 && $response_code < 400;
	}


	/**
	 * Helper function to reconstruct a URL split using parse_url().
	 *
	 * @param  array $parts Array returned from parse_url().
	 * @return string       URL.
	 */
	public static function build_url( $parts = array() ) {
		return (
			( isset( $parts['scheme'] ) ? "{$parts['scheme']}:" : '' ) .
			( ( isset( $parts['user'] ) || isset( $parts['host'] ) ) ? '//' : '' ) .
			( isset( $parts['user'] ) ? "{$parts['user']}" : '' ) .
			( isset( $parts['pass'] ) ? ":{$parts['pass']}" : '' ) .
			( isset( $parts['user'] ) ? '@' : '' ) .
			( isset( $parts['host'] ) ? "{$parts['host']}" : '' ) .
			( isset( $parts['port'] ) ? ":{$parts['port']}" : '' ) .
			( isset( $parts['path'] ) ? "{$parts['path']}" : '' ) .
			( isset( $parts['query'] ) ? "?{$parts['query']}" : '' ) .
			( isset( $parts['fragment'] ) ? "#{$parts['fragment']}" : '' )
		);
	}


	/**
	 * Helper function to get a single user info array from one of the access
	 * control lists (pending, approved, or blocked).
	 *
	 * @param  string $email           Email address to retrieve info for.
	 * @param  array  $user_info_list  List to get info from.
	 * @return mixed                   false if not found, otherwise: array(
	 *                                   'email' => '',
	 *                                   'role' => '',
	 *                                   'date_added' => '',
	 *                                   ['usermeta' => [''|array()]]
	 *                                 );
	 */
	public static function get_user_info_from_list( $email, $user_info_list ) {
		foreach ( $user_info_list as $user_info ) {
			if ( 0 === strcasecmp( $user_info['email'], $email ) ) {
				return $user_info;
			}
		}
		return false;
	}

	/**
	 * Helper function to convert a string to lowercase.  Prefers to use mb_strtolower,
	 * but will fall back to strtolower if the former is not available.
	 *
	 * @param  string $str String to convert to lowercase.
	 * @return string      Input in lowercase.
	 */
	public static function lowercase( $str ) {
		return function_exists( 'mb_strtolower' ) ? mb_strtolower( $str ) : strtolower( $str );
	}


	/**
	 * Helper function to convert seconds to human readable text.
	 *
	 * @see: http://csl.name/php-secs-to-human-text/
	 *
	 * @param  int $secs Seconds to display as readable text.
	 * @return string    Readable version of number of seconds.
	 */
	public static function seconds_as_sentence( $secs ) {
		$units = array(
			'week'   => 3600 * 24 * 7,
			'day'    => 3600 * 24,
			'hour'   => 3600,
			'minute' => 60,
			'second' => 1,
		);

		// Specifically handle zero.
		if ( 0 === intval( $secs ) ) {
			return '0 seconds';
		}

		$s = '';

		foreach ( $units as $name => $divisor ) {
			$quot = intval( $secs / $divisor );
			if ( $quot ) {
				$s    .= "$quot $name";
				$s    .= ( abs( $quot ) > 1 ? 's' : '' ) . ', ';
				$secs -= $quot * $divisor;
			}
		}

		return substr( $s, 0, -2 );
	}


	/**
	 * Helper function to show a number as an ordinal (e.g., 5 as 5th).
	 *
	 * @see: https://stackoverflow.com/questions/3109978/display-numbers-with-ordinal-suffix-in-php
	 *
	 * @param  int $number Number to show as an ordinal.
	 * @return string      Number as an ordinal string.
	 */
	public static function ordinal( $number = 0 ) {
		$ends = array( 'th', 'st', 'nd', 'rd', 'th', 'th', 'th', 'th', 'th', 'th' );
		if ( $number % 100 >= 11 && $number % 100 <= 13 ) {
			return $number . 'th';
		} else {
			return $number . $ends[ $number % 10 ];
		}
	}


	/**
	 * Generate CAS or OAuth2 authentication URL (wp-login.php URL with reauth=1 removed
	 * and external=cas or external=oauth2 added).
	 *
	 * @param string $provider External service provider type (e.g., 'cas', or 'oauth2').
	 * @param int    $id       CAS server number (e.g., 1).
	 */
	public static function modify_current_url_for_external_login( $provider = 'cas', $id = 1 ) {
		// Construct the URL of the current page (wp-login.php).
		$url = '';
		if ( isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
			$url = set_url_scheme( esc_url_raw( wp_unslash( $_SERVER['HTTP_HOST'] ) ) . esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) );
		}

		// If we have a login form embedded elsewhere than wp-login.php, alter the
		// URL to point to wp-login.php with a redirect to the current page. This
		// will happen if the [authorizer_login_form] shortcode is used.
		if ( false === strpos( $url, 'wp-login.php' ) ) {
			$url = wp_login_url( $url );
		}

		// Edge case: If the WPS Hide Login plugin is installed, redirect to home
		// page after logging in instead of the plugin's login endpoint, which will
		// redirect to /wp-admin.
		if ( class_exists( '\WPS\WPS_Hide_Login\Plugin' ) ) {
			$url = wp_login_url( home_url() );
		}

		// Parse the URL into its components.
		$parsed_url = wp_parse_url( $url );

		// Fix up the querystring values (remove reauth, make sure external=cas).
		$querystring = array();
		if ( array_key_exists( 'query', $parsed_url ) ) {
			parse_str( $parsed_url['query'], $querystring );
		}
		unset( $querystring['reauth'] );
		$querystring['external'] = $provider;
		$querystring['id']       = $id;
		$parsed_url['query']     = http_build_query( $querystring );

		// Return the URL as a string.
		return self::unparse_url( $parsed_url );
	}


	/**
	 * Reconstruct a URL after it has been deconstructed with parse_url().
	 *
	 * @param  array $parsed_url Keys from parse_url().
	 * @return string            URL constructed from the components in $parsed_url.
	 */
	public static function unparse_url( $parsed_url = array() ) {
		$scheme   = isset( $parsed_url['scheme'] ) ? $parsed_url['scheme'] . '://' : '';
		$host     = isset( $parsed_url['host'] ) ? $parsed_url['host'] : '';
		$port     = isset( $parsed_url['port'] ) ? ':' . $parsed_url['port'] : '';
		$user     = isset( $parsed_url['user'] ) ? $parsed_url['user'] : '';
		$pass     = isset( $parsed_url['pass'] ) ? ':' . $parsed_url['pass'] : '';
		$pass     = $user || $pass ? "$pass@" : '';
		$path     = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';
		$query    = isset( $parsed_url['query'] ) ? '?' . $parsed_url['query'] : '';
		$fragment = isset( $parsed_url['fragment'] ) ? '#' . $parsed_url['fragment'] : '';

		return "$scheme$user$pass$host$port$path$query$fragment";
	}
}
