<?php
/**
 * Authorizer
 *
 * @license  GPL-2.0+
 * @link     https://github.com/uhm-coe/authorizer
 * @package  authorizer
 */

if ( ! function_exists( 'array_key_last' ) ) {
	/**
	 * Polyfill for array_key_last(), used in class-cas.php. Not available in PHP
	 * versions below 7.3.
	 *
	 * Get the last key of the given array without affecting the internal array
	 *  pointer.
	 *
	 * @param  array $arr An array.
	 *
	 * @return mixed The last key of array if the array is not empty; NULL otherwise.
	 */
	function array_key_last( $arr ) {
		$key = null;
		if ( is_array( $arr ) ) {
			end( $arr );
			$key = key( $arr );
		}

		return $key;
	}
}
