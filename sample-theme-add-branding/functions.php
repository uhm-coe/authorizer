<?php

// Custom function to add a branding option to the Authorizer plugin.
function my_authorizer_add_branding_option( $branding_options ) {
	$new_branding_option = array(
		'value' => 'your_brand',
		'description' => 'Custom Your Brand Login Screen',
		'css_url' => get_stylesheet_directory_uri() . '/extend/authorizer/example/css/example.css',
		'js_url' => get_stylesheet_directory_uri() . '/extend/authorizer/example/js/example.js',
	);
	array_push( $branding_options, $new_branding_option );
	return $branding_options;
}
add_filter( 'authorizer_add_branding_option', 'my_authorizer_add_branding_option' );
