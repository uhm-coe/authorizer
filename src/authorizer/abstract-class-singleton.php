<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

namespace Authorizer;

/**
 * Base class that all other classes extend (provides static accessor variable).
 */
abstract class Singleton {
	/**
	 * Instances of any child classes.
	 *
	 * @var object[] Array of objects of any instantiated child classes.
	 */
	private static $instances = array();


	/**
	 * Access the singleton instance of the requested class (create a new one if
	 * needed).
	 *
	 * @return object Object of the requested class.
	 */
	public static function get_instance() {
		$class = get_called_class();
		if ( ! isset( self::$instances[ $class ] ) ) {
			self::$instances[ $class ] = new static();
		}

		return self::$instances[ $class ];
	}


	/**
	 * Disable constructor to prevent creation of multiple instances (protected
	 * so we can create a new instance within get_instance() though).
	 */
	protected function __construct() {
	}

	/**
	 * Disable cloning of singletons.
	 */
	private function __clone() {
	}
}
