<?php

/**
 * Polyfill for array_key_last(), used in class-cas.php. Not available in PHP
 * versions below 7.3.
 *
 * Get the last key of the given array without affecting the internal array
 *  pointer.
 *
 * @param  array $array An array.
 *
 * @return mixed The last key of array if the array is not empty; NULL otherwise.
 */
if ( ! function_exists( 'array_key_last' ) ) {
	function array_key_last( $array ) {
		$key = null;
		if ( is_array( $array ) ) {
			end( $array );
			$key = key( $array );
		}

		return $key;
	}
}

