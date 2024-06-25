/**
 * UI wiring for Authorizer Settings page.
 */

/* global window, document, setTimeout, sessionStorage, ajaxurl, authL10n, history */
( function( $ ) {

	// Milliseconds for jQuery UI animations to complete.
	var animationSpeed = 300;
	// Milliseconds for shake animation (reject email address) to complete.
	var shakeSpeed = 600;

	/**
	 * Wiring and UI for Authorizer Settings page.
	 */

	// Switch between pages in the Approved User list.
	// @calls php wp_ajax_refresh_approved_user_list.
	function refreshApprovedUserList( currentPage, searchTerm ) {
		var $list = $( '#list_auth_settings_access_users_approved' );
		var $spinner = $( '<span class="spinner is-active"></span>' ).css({
			position: 'relative',
			top: '40%',
			left: '-240px',
		});
		var $overlay = $( '<div id="list_auth_settings_access_users_approved_overlay"></div>' ).css({
			'background-color': '#f1f1f1',
			'z-index': 1,
			opacity: 0.8,
			position: 'absolute',
			top: $list.position().top + parseInt( $list.css( 'margin-top' ) ),
			left: $list.position().left,
			width: $list.width(),
			height: $list.height(),
		});
		$overlay.append( $spinner );

		// Show overlay and wait cursor.
		$list.after( $overlay );
		$( 'html' ).addClass( 'busy' );

		$.post( ajaxurl, {
			action: 'refresh_approved_user_list',
			nonce: $( '#nonce_save_auth_settings' ).val(),
			is_network_admin: authL10n.is_network_admin, // eslint-disable-line camelcase
			paged: currentPage,
			search: searchTerm,
		}, function( response ) {
			if ( response.success ) {
				// Update user list and total user and page count.
				$( '#list_auth_settings_access_users_approved' ).html( response.html );
				$( '.displaying-num' ).html( response.total_users_html );
				$( '.total-pages' ).html( response.total_pages_html );

				// Adjust our current page if the query changed the total page count.
				if ( currentPage > response.total_pages ) {
					currentPage = response.total_pages;
				}

				// Update pager elements.
				refreshApprovedUserPager( currentPage );

				// Update querystring with new paged param value (but don't reload the page).
				if ( history.pushState ) {
					var url = window.location.href;
					url = updateQueryStringParameter( url, 'paged', currentPage );
					url = updateQueryStringParameter( url, 'search', searchTerm );
					window.history.pushState( { path: url }, '', url );
				}
			}
			// Remove overlay and wait cursor.
			$overlay.remove();
			$( 'html' ).removeClass( 'busy' );
		}).fail( function() {
			// Remove overlay and wait cursor.
			$overlay.remove();
			$( 'html' ).removeClass( 'busy' );
		});
	}

	// Update the pager elements when changing pages.
	function refreshApprovedUserPager( currentPage ) {
		var totalPages = parseInt( $( '.total-pages' ).first().text().replace( /[^0-9]/g, '' ), 10 ) || 1;

		// If total number of pages changed (because a search filter reduced it), make
		// sure current page is not larger than it.
		if ( currentPage > totalPages ) {
			currentPage = totalPages;
		}
		if ( currentPage < 1 ) {
			currentPage = 1;
		}
		if ( totalPages < 1 ) {
			totalPages = 1;
		}

		// Update current page text input.
		$( '#current-page-selector' ).val( currentPage );

		// Update current page span.
		$( '#table-paging .current-page-text' ).text( currentPage );

		// Update first page button.
		var $first = $( '.first-page' );
		if ( $first.is( 'a' ) && currentPage <= 1 ) {
			$first.replaceWith( '<span class="button disabled first-page tablenav-pages-navspan" aria-hidden="true">&laquo;</span>' );
		} else if ( $first.is( 'span' ) && currentPage > 1 ) {
			$first.replaceWith( '<a class="button first-page" href="' + updateQueryStringParameter( window.location.href, 'paged', '1' ) + '"><span class="screen-reader-text">' + authL10n.first_page + '</span><span aria-hidden="true">&laquo;</span></a>' );
		}

		// Update prev page button.
		var $prev = $( '.prev-page' );
		if ( $prev.is( 'a' ) && currentPage <= 1 ) {
			$prev.replaceWith( '<span class="button disabled prev-page tablenav-pages-navspan" aria-hidden="true">&lsaquo;</span>' );
		} else if ( currentPage > 1 ) {
			$prev.replaceWith( '<a class="button prev-page" href="' + updateQueryStringParameter( window.location.href, 'paged', currentPage - 1 ) + '"><span class="screen-reader-text">' + authL10n.prev_page + '</span><span aria-hidden="true">&lsaquo;</span></a>' );
		}

		// Update next button.
		var $next = $( '.next-page' );
		if ( $next.is( 'a' ) && currentPage >= totalPages ) {
			$next.replaceWith( '<span class="button disabled next-page tablenav-pages-navspan" aria-hidden="true">&rsaquo;</span>' );
		} else if ( currentPage < totalPages ) {
			$next.replaceWith( '<a class="button next-page" href="' + updateQueryStringParameter( window.location.href, 'paged', currentPage + 1 ) + '"><span class="screen-reader-text">' + authL10n.next_page + '</span><span aria-hidden="true">&rsaquo;</span></a>' );
		}

		// Update last button.
		var $last = $( '.last-page' );
		if ( $last.is( 'a' ) && currentPage >= totalPages ) {
			$last.replaceWith( '<span class="button disabled last-page tablenav-pages-navspan" aria-hidden="true">&raquo;</span>' );
		} else if ( $last.is( 'span' ) && currentPage < totalPages ) {
			$last.replaceWith( '<a class="button last-page" href="' + updateQueryStringParameter( window.location.href, 'paged', totalPages ) + '"><span class="screen-reader-text">' + authL10n.next_page + '</span><span aria-hidden="true">&raquo;</span></a>' );
		}
	}

	// Make changes to one of the user lists (pending, approved, blocked) via ajax.
	// @calls php wp_ajax_update_auth_user.
	function updateAuthUser( caller, setting, usersToEdit ) {
		var accessUsersPending = [],
			accessUsersApproved = [],
			accessUsersBlocked = [],
			nonce = $( '#nonce_save_auth_settings' ).val();

		// Defaults:
		// setting = 'access_users_pending' or 'access_users_approved' or 'access_users_blocked',
		// usersToEdit = [
		// 	{
		//    email: 'johndoe@example.com',
		//    role: 'subscriber',
		//    date_added: 'Jun 2014',
		//    edit_action: 'add' or 'remove' or 'change_role',
		//    local_user: true or false,
		//    multisite_user: true or false,
		//  }, {
		//   ...
		//  }
		// ]
		setting = typeof setting !== 'undefined' ? setting : 'none';

		// If we are only editing a single user, make that user the only item in the array.
		usersToEdit = typeof usersToEdit !== 'undefined' ? usersToEdit : [];
		if ( ! Array.isArray( usersToEdit ) ) {
			usersToEdit = [ usersToEdit ];
		}

		// Enable wait cursor.
		$( 'html' ).addClass( 'busy' );

		// Disable button (prevent duplicate clicks).
		$( caller ).attr( 'disabled', 'disabled' );

		// Enable spinner by element that triggered this event (caller).
		var $row = $( caller ).closest( 'li' );
		if ( $row.length > 0 ) {
			var $spinner = $( '<span class="spinner is-active"></span>' ).css({
				position: 'absolute',
				top: $row.position().top,
				left: $row.position().left + $row.width(),
			});
			$row.append( $spinner );
		}

		// Grab the value of the setting we are saving.
		if ( setting === 'access_users_pending' ) {
			accessUsersPending = usersToEdit;
		} else if ( setting === 'access_users_approved' ) {
			accessUsersApproved = usersToEdit;
		} else if ( setting === 'access_users_blocked' ) {
			accessUsersBlocked = usersToEdit;
		}

		$.post( ajaxurl, {
			action: 'update_auth_user',
			setting: setting,
			access_users_pending: accessUsersPending, // eslint-disable-line camelcase
			access_users_approved: accessUsersApproved, // eslint-disable-line camelcase
			access_users_blocked: accessUsersBlocked, // eslint-disable-line camelcase
			nonce: nonce,
		}, function( response ) {
			// Server responded, but if success isn't true it failed to save.
			var succeeded = response.success;
			var spinnerText = succeeded ? authL10n.saved + '.' : '<span class="attention">' + authL10n.failed + '.</span>';
			var spinnerWait = succeeded ? 500 : 2000;

			// Remove any new user entries that were rejected by the server.
			if ( response.invalid_emails.length > 0 ) {
				for ( var i = 0; i < response.invalid_emails.length; i++ ) {
					var duplicateEmail = response.invalid_emails[i];
					$( 'li.new-user .auth-email[value="' + duplicateEmail + '"]' )
						.siblings( '.spinner' ).addClass( 'duplicate' ).append( '<span class="spinner-text"><span class="attention">' + authL10n.duplicate + '.</span></span>' )
						.parent().fadeOut( spinnerWait, function() { $( this ).remove(); }); // jshint ignore:line
				}
			}

			// Show message ('Saved', 'Failed', or 'Saved, removing duplicates').
			$( 'form .spinner:not(:has(.spinner-text)):not(.duplicate)' ).append( '<span class="spinner-text">' + spinnerText + '</span>' ).delay( spinnerWait ).hide( animationSpeed, function() {
				$( this ).remove();
			});
			$( caller ).removeAttr( 'disabled' );

			// Disable wait cursor.
			$( 'html' ).removeClass( 'busy' );
		}).fail( function() {
			// Fail fires if the server doesn't respond or responds with 500 codes
			var succeeded = false;
			var spinnerText = succeeded ? authL10n.saved + '.' : '<span class="attention">' + authL10n.failed + '.</span>';
			var spinnerWait = succeeded ? 500 : 2000;
			$( 'form .spinner:not(:has(.spinner-text))' ).append( '<span class="spinner-text">' + spinnerText + '</span>' ).delay( spinnerWait ).hide( animationSpeed, function() {
				$( this ).remove();
			});
			$( caller ).removeAttr( 'disabled' );

			// Disable wait cursor.
			$( 'html' ).removeClass( 'busy' );
		});
	}


	// Hide or show (with overlay) the multisite settings based on the "multisite override" setting.
	function hideMultisiteSettingsIfDisabled() {
		if ( $( '#auth_settings_multisite_override' ).length === 0 ) {
			return;
		}

		var settings = $( '#auth_multisite_settings' );
		var overlay = $( '#auth_multisite_settings_disabled_overlay' );

		if ( $( '#auth_settings_multisite_override' ).is( ':checked' ) ) {
			overlay.hide( animationSpeed );
		} else {
			overlay.css({
				'background-color': '#f1f1f1',
				'z-index': 1,
				opacity: 0.8,
				position: 'absolute',
				top: settings.position().top,
				left: settings.position().left,
				width: settings.width(),
				height: settings.height() + 50,
			});
			overlay.show();
		}
	}

	// Helper function to remove duplicate entries from an array of strings.
	function removeDuplicatesFromArrayOfStrings( arrayOfStrings ) {
		var seen = {};
		return arrayOfStrings.filter( function( item ) {
			return seen.hasOwnProperty( item ) ? false : ( seen[item] = true );
		});
	}

	// Helper function to hide/show wordpress option
	function animateOption( action, option ) {
		if ( action === 'show' ) {
			option.fadeIn( animationSpeed );
			$( 'th, td', option ).removeClass( 'hide-animate hide-no-animate' );
		} else if ( action === 'hide' ) {
			option.fadeOut( animationSpeed );
			$( 'td, th', option ).addClass( 'hide-animate' );
		} else if ( action === 'hide_immediately' ) {
			option.hide();
			$( 'td, th', option ).addClass( 'hide-no-animate' );
		}
	}

	// Helper function to grab a querystring param value by name
	function getParameterByName( needle, haystack ) {
		needle = needle.replace( /[\[]/, '\\\[').replace(/[\]]/, '\\\]' ); // eslint-disable-line no-useless-escape
		var regex = new RegExp( '[\\?&]' + needle + '=([^&#]*)' );
		var results = regex.exec( haystack );
		if ( results === null ) {
			return '';
		} else {
			return decodeURIComponent( results[1].replace( /\+/g, ' ' ) );
		}
	}

	// Helper function to return a short date (e.g., Jul 2013) for today's date
	function getShortDate( date ) {
		date = typeof date !== 'undefined' ? date : new Date();
		var month = '';
		switch ( date.getMonth() ) {
			case 0: month = 'Jan'; break;
			case 1: month = 'Feb'; break;
			case 2: month = 'Mar'; break;
			case 3: month = 'Apr'; break;
			case 4: month = 'May'; break;
			case 5: month = 'Jun'; break;
			case 6: month = 'Jul'; break;
			case 7: month = 'Aug'; break;
			case 8: month = 'Sep'; break;
			case 9: month = 'Oct'; break;
			case 10: month = 'Nov'; break;
			case 11: month = 'Dec'; break;
		}
		return month + ' ' + date.getFullYear();
	}

	// Helper function to grab a querystring value
	function getQuerystringValuesByKey( key ) {
		var re = new RegExp( '(?:\\?|&)' + key + '=(.*?)(?=&|$)', 'gi' );
		var matchingValues = [];
		var match;
		while ( ( match = re.exec( document.location.search ) ) !== null ) {
			matchingValues.push( match[1] );
		}
		return matchingValues;
	}

	// Helper function to check if an email address is valid. If allowWildcardEmail
	// is true, then any string starting with an @ is valid.
	function validEmail( email, allowWildcardEmail ) {
		allowWildcardEmail = typeof allowWildcardEmail !== 'undefined' ? allowWildcardEmail : false;
		var re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		return email.length > 0 && ( re.test( email ) || email.startsWith( '@' ) );
	}

	// Helper function to set or update a querystring value.
	function updateQueryStringParameter( uri, key, value ) {
		// Remove the hash before operating on the URI.
		var i = uri.indexOf( '#' );
		var hash = i === -1 ? '' : uri.substr( i );
		uri = i === -1 ? uri : uri.substr( 0, i );

		var re = new RegExp( '([?&])' + key + '=.*?(&|$)', 'i' );
		var separator = uri.indexOf( '?' ) !== -1 ? '&' : '?';

		if ( ! value ) {
			// Remove key-value pair if empty.
			uri = uri.replace( new RegExp( '([?&]?)' + key + '=[^&]*', 'i' ), '' );
			if ( uri.slice( -1 ) === '?' ) {
				uri = uri.slice( 0, -1 );
			}
			// Replace first occurrence of & by ? if no ? is present.
			if ( uri.indexOf( '?' ) === -1 ) {
				uri = uri.replace( /&/, '?' );
			}
		} else if ( uri.match( re ) ) {
			uri = uri.replace( re, '$1' + key + '=' + value + '$2' );
		} else {
			uri = uri + separator + key + '=' + value;
		}
		return uri + hash;
	}


	/**
	 * Wire up actions when document has loaded.
	 */


	$( document ).ready( function() {
		// Grab references to form elements that we will show/hide on page load
		/* eslint-disable camelcase */
		var auth_settings_access_role_receive_pending_emails = $( '#auth_settings_access_role_receive_pending_emails' ).closest( 'tr' );
		var auth_settings_access_pending_redirect_to_message = $( '#wp-auth_settings_access_pending_redirect_to_message-wrap' ).closest( 'tr' );
		var auth_settings_access_blocked_redirect_to_message = $( '#wp-auth_settings_access_blocked_redirect_to_message-wrap' ).closest( 'tr' );
		var auth_settings_access_should_email_approved_users = $( '#auth_settings_access_should_email_approved_users' ).closest( 'tr' );
		var auth_settings_access_email_approved_users_subject = $( '#auth_settings_access_email_approved_users_subject' ).closest( 'tr' );
		var auth_settings_access_email_approved_users_body = $( '#wp-auth_settings_access_email_approved_users_body-wrap' ).closest( 'tr' );
		var auth_settings_access_public_pages = $( '#auth_settings_access_public_pages' ).closest( 'tr' );
		var auth_settings_access_redirect_to_login = $( '#radio_auth_settings_access_redirect_to_login' ).closest( 'tr' );
		var auth_settings_access_public_warning = $( '#radio_auth_settings_access_public_warning' ).closest( 'tr' );
		var auth_settings_access_redirect_to_message = $( '#wp-auth_settings_access_redirect_to_message-wrap' ).closest( 'tr' );
		var auth_settings_external_oauth2_provider = $( '#auth_settings_oauth2_provider' ).closest( 'tr' );
		var auth_settings_external_oauth2_custom_label = $( '#auth_settings_oauth2_custom_label' ).closest( 'tr' );
		var auth_settings_external_oauth2_clientid = $( '#auth_settings_oauth2_clientid' ).closest( 'tr' );
		var auth_settings_external_oauth2_clientsecret = $( '#auth_settings_oauth2_clientsecret' ).closest( 'tr' );
		var auth_settings_external_oauth2_hosteddomain = $( '#auth_settings_oauth2_hosteddomain' ).closest( 'tr' );
		var auth_settings_external_oauth2_tenant_id = $( '#auth_settings_oauth2_tenant_id' ).closest( 'tr' );
		var auth_settings_external_oauth2_url_authorize = $( '#auth_settings_oauth2_url_authorize' ).closest( 'tr' );
		var auth_settings_external_oauth2_url_token = $( '#auth_settings_oauth2_url_token' ).closest( 'tr' );
		var auth_settings_external_oauth2_url_resource = $( '#auth_settings_oauth2_url_resource' ).closest( 'tr' );
		var auth_settings_external_oauth2_auto_login = $( '#auth_settings_oauth2_auto_login' ).closest( 'tr' );
		var auth_settings_external_google_clientid = $( '#auth_settings_google_clientid' ).closest( 'tr' );
		var auth_settings_external_google_clientsecret = $( '#auth_settings_google_clientsecret' ).closest( 'tr' );
		var auth_settings_external_google_hosteddomain = $( '#auth_settings_google_hosteddomain' ).closest( 'tr' );
		var auth_settings_external_cas_auto_login = $( '#auth_settings_cas_auto_login' ).closest( 'tr' );
		var auth_settings_external_cas_custom_label = $( '#auth_settings_cas_custom_label' ).closest( 'tr' );
		var auth_settings_external_cas_host = $( '#auth_settings_cas_host' ).closest( 'tr' );
		var auth_settings_external_cas_port = $( '#auth_settings_cas_port' ).closest( 'tr' );
		var auth_settings_external_cas_path = $( '#auth_settings_cas_path' ).closest( 'tr' );
		var auth_settings_external_cas_method = $( '#auth_settings_cas_method' ).closest( 'tr' );
		var auth_settings_external_cas_version = $( '#auth_settings_cas_version' ).closest( 'tr' );
		var auth_settings_external_cas_attr_email = $( '#auth_settings_cas_attr_email' ).closest( 'tr' );
		var auth_settings_external_cas_attr_first_name = $( '#auth_settings_cas_attr_first_name' ).closest( 'tr' );
		var auth_settings_external_cas_attr_last_name = $( '#auth_settings_cas_attr_last_name' ).closest( 'tr' );
		var auth_settings_external_cas_attr_update_on_login = $( '#auth_settings_cas_attr_update_on_login' ).closest( 'tr' );
		var auth_settings_external_cas_link_on_username = $( '#auth_settings_cas_link_on_username' ).closest( 'tr' );
		var auth_settings_external_ldap_host = $( '#auth_settings_ldap_host' ).closest( 'tr' );
		var auth_settings_external_ldap_port = $( '#auth_settings_ldap_port' ).closest( 'tr' );
		var auth_settings_external_ldap_search_base = $( '#auth_settings_ldap_search_base' ).closest( 'tr' );
		var auth_settings_external_ldap_search_filter = $( '#auth_settings_ldap_search_filter' ).closest( 'tr' );
		var auth_settings_external_ldap_uid = $( '#auth_settings_ldap_uid' ).closest( 'tr' );
		var auth_settings_external_ldap_attr_email = $( '#auth_settings_ldap_attr_email' ).closest( 'tr' );
		var auth_settings_external_ldap_user = $( '#auth_settings_ldap_user' ).closest( 'tr' );
		var auth_settings_external_ldap_password = $( '#auth_settings_ldap_password' ).closest( 'tr' );
		var auth_settings_external_ldap_tls = $( '#auth_settings_ldap_tls' ).closest( 'tr' );
		var auth_settings_external_ldap_lostpassword_url = $( '#auth_settings_ldap_lostpassword_url' ).closest( 'tr' );
		var auth_settings_external_ldap_attr_first_name = $( '#auth_settings_ldap_attr_first_name' ).closest( 'tr' );
		var auth_settings_external_ldap_attr_last_name = $( '#auth_settings_ldap_attr_last_name' ).closest( 'tr' );
		var auth_settings_external_ldap_attr_update_on_login = $( '#auth_settings_ldap_attr_update_on_login' ).closest( 'tr' );
		var auth_settings_external_ldap_test_user = $( '#auth_settings_ldap_test_user' ).closest( 'tr' );
		/* eslint-enable */

		// Hide settings unless "Only approved users" is checked
		if ( ! $( '#radio_auth_settings_access_who_can_login_approved_users' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_access_role_receive_pending_emails );
			animateOption( 'hide_immediately', auth_settings_access_pending_redirect_to_message );
			animateOption( 'hide_immediately', auth_settings_access_blocked_redirect_to_message );
			animateOption( 'hide_immediately', auth_settings_access_should_email_approved_users );
		}

		// Hide Welcome email body/subject options if "Send welcome email" is off.
		if ( ! $( '#auth_settings_access_should_email_approved_users' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_access_email_approved_users_subject );
			animateOption( 'hide_immediately', auth_settings_access_email_approved_users_body );
		}

		// On load: Show/hide public access options if everyone can see site
		if ( ! $( '#radio_auth_settings_access_who_can_view_logged_in_users' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_access_public_pages );
			animateOption( 'hide_immediately', auth_settings_access_redirect_to_login );
			animateOption( 'hide_immediately', auth_settings_access_public_warning );
			animateOption( 'hide_immediately', auth_settings_access_redirect_to_message );
		}

		// Hide OAuth2 options if unchecked.
		if ( ! $( '#auth_settings_oauth2' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_external_oauth2_provider );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_custom_label );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_clientid );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_clientsecret );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_hosteddomain );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_auto_login );
		}

		// Hide OAuth2 generic options if generic isn't chosen.
		if ( ! $( '#auth_settings_oauth2' ).is( ':checked' ) || 'generic' !== $( '#auth_settings_oauth2_provider' ).val() ) {
			animateOption( 'hide_immediately', auth_settings_external_oauth2_url_authorize );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_url_token );
			animateOption( 'hide_immediately', auth_settings_external_oauth2_url_resource );
		}

		// Hide OAuth2 Tenant ID if azure isn't chosen.
		if ( ! $( '#auth_settings_oauth2' ).is( ':checked' ) || 'azure' !== $( '#auth_settings_oauth2_provider' ).val() ) {
			animateOption( 'hide_immediately', auth_settings_external_oauth2_tenant_id );
		}

		// Hide Google options if unchecked
		if ( ! $( '#auth_settings_google' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_external_google_clientid );
			animateOption( 'hide_immediately', auth_settings_external_google_clientsecret );
			animateOption( 'hide_immediately', auth_settings_external_google_hosteddomain );
		}

		// Hide CAS options if unchecked
		if ( ! $( '#auth_settings_cas' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_external_cas_auto_login );
			animateOption( 'hide_immediately', auth_settings_external_cas_custom_label );
			animateOption( 'hide_immediately', auth_settings_external_cas_host );
			animateOption( 'hide_immediately', auth_settings_external_cas_port );
			animateOption( 'hide_immediately', auth_settings_external_cas_path );
			animateOption( 'hide_immediately', auth_settings_external_cas_method );
			animateOption( 'hide_immediately', auth_settings_external_cas_version );
			animateOption( 'hide_immediately', auth_settings_external_cas_attr_email );
			animateOption( 'hide_immediately', auth_settings_external_cas_attr_first_name );
			animateOption( 'hide_immediately', auth_settings_external_cas_attr_last_name );
			animateOption( 'hide_immediately', auth_settings_external_cas_attr_update_on_login );
			animateOption( 'hide_immediately', auth_settings_external_cas_link_on_username );
		}

		// Hide LDAP options if unchecked
		if ( ! $( '#auth_settings_ldap' ).is( ':checked' ) ) {
			animateOption( 'hide_immediately', auth_settings_external_ldap_host );
			animateOption( 'hide_immediately', auth_settings_external_ldap_port );
			animateOption( 'hide_immediately', auth_settings_external_ldap_search_base );
			animateOption( 'hide_immediately', auth_settings_external_ldap_search_filter );
			animateOption( 'hide_immediately', auth_settings_external_ldap_uid );
			animateOption( 'hide_immediately', auth_settings_external_ldap_attr_email );
			animateOption( 'hide_immediately', auth_settings_external_ldap_user );
			animateOption( 'hide_immediately', auth_settings_external_ldap_password );
			animateOption( 'hide_immediately', auth_settings_external_ldap_tls );
			animateOption( 'hide_immediately', auth_settings_external_ldap_lostpassword_url );
			animateOption( 'hide_immediately', auth_settings_external_ldap_attr_first_name );
			animateOption( 'hide_immediately', auth_settings_external_ldap_attr_last_name );
			animateOption( 'hide_immediately', auth_settings_external_ldap_attr_update_on_login );
			animateOption( 'hide_immediately', auth_settings_external_ldap_test_user );
		}

		// Event handler: Hide "Handle unauthorized visitors" option if access is granted to "Everyone"
		$( 'input[name="auth_settings[access_who_can_login]"]' ).on( 'change', function() {
			// Hide settings unless "Only approved users" is checked
			var action = $( '#radio_auth_settings_access_who_can_login_approved_users' ).is( ':checked' ) ? 'show' : 'hide';
			animateOption( action, auth_settings_access_role_receive_pending_emails );
			animateOption( action, auth_settings_access_pending_redirect_to_message );
			animateOption( action, auth_settings_access_blocked_redirect_to_message );
			animateOption( action, auth_settings_access_should_email_approved_users );
			action = action === 'show' && $( '#auth_settings_access_should_email_approved_users' ).is( ':checked' ) ? 'show' : 'hide_immediately';
			animateOption( action, auth_settings_access_email_approved_users_subject );
			animateOption( action, auth_settings_access_email_approved_users_body );
		});

		// Event handler: Hide Welcome email body/subject options if "Send welcome email" is off.
		$( 'input[name="auth_settings[access_should_email_approved_users]"]' ).on( 'change', function() {
			var action = $( this ).is( ':checked' ) ? 'show' : 'hide';
			animateOption( action, auth_settings_access_email_approved_users_subject );
			animateOption( action, auth_settings_access_email_approved_users_body );
		});

		// Event handler: Hide "Handle unauthorized visitors" option if access is granted to "Everyone"
		$( 'input[name="auth_settings[access_who_can_view]"]' ).on( 'change', function() {
			var action = $( '#radio_auth_settings_access_who_can_view_everyone' ).is( ':checked' ) ? 'hide' : 'show';
			animateOption( action, auth_settings_access_redirect_to_login );
			animateOption( action, auth_settings_access_redirect_to_message );
			animateOption( action, auth_settings_access_public_pages );
			animateOption( action, auth_settings_access_public_warning );
		});

		// Event handler: Show/hide OAuth2 options based on checkbox.
		$( 'input[name="auth_settings[oauth2]"]' ).on( 'change', function() {
			var action = $( this ).is( ':checked' ) ? 'show' : 'hide';
			animateOption( action, auth_settings_external_oauth2_provider );
			animateOption( action, auth_settings_external_oauth2_custom_label );
			animateOption( action, auth_settings_external_oauth2_clientid );
			animateOption( action, auth_settings_external_oauth2_clientsecret );
			animateOption( action, auth_settings_external_oauth2_hosteddomain );
			animateOption( action, auth_settings_external_oauth2_auto_login );
		});

		// Event handler: Show/hide OAuth2 generic options based on provider.
		$( 'select[name="auth_settings[oauth2_provider]"]' ).on( 'change', function() {
			var action = 'generic' === $( this ).val() ? 'show' : 'hide';
			animateOption( action, auth_settings_external_oauth2_url_authorize );
			animateOption( action, auth_settings_external_oauth2_url_token );
			animateOption( action, auth_settings_external_oauth2_url_resource );
			action = 'azure' === $( this ).val() ? 'show' : 'hide';
			animateOption( action, auth_settings_external_oauth2_tenant_id );
		});

		// Event handler: Show/hide Google options based on checkbox
		$( 'input[name="auth_settings[google]"]' ).on( 'change', function() {
			var action = $( this ).is( ':checked' ) ? 'show' : 'hide';
			animateOption( action, auth_settings_external_google_clientid );
			animateOption( action, auth_settings_external_google_clientsecret );
			animateOption( action, auth_settings_external_google_hosteddomain );
		});

		// Event handler: Show/hide CAS options based on checkbox
		$( 'input[name="auth_settings[cas]"]' ).on( 'change', function() {
			var action = $( this ).is( ':checked' ) ? 'show' : 'hide';
			animateOption( action, auth_settings_external_cas_auto_login );
			animateOption( action, auth_settings_external_cas_custom_label );
			animateOption( action, auth_settings_external_cas_host );
			animateOption( action, auth_settings_external_cas_port );
			animateOption( action, auth_settings_external_cas_path );
			animateOption( action, auth_settings_external_cas_method );
			animateOption( action, auth_settings_external_cas_version );
			animateOption( action, auth_settings_external_cas_attr_email );
			animateOption( action, auth_settings_external_cas_attr_first_name );
			animateOption( action, auth_settings_external_cas_attr_last_name );
			animateOption( action, auth_settings_external_cas_attr_update_on_login );
			animateOption( action, auth_settings_external_cas_link_on_username );
		});

		// Event handler: Show/hide LDAP options based on checkbox
		$( 'input[name="auth_settings[ldap]"]' ).on( 'change', function() {
			var action = $( this ).is( ':checked' ) ? 'show' : 'hide';
			animateOption( action, auth_settings_external_ldap_host );
			animateOption( action, auth_settings_external_ldap_port );
			animateOption( action, auth_settings_external_ldap_search_base );
			animateOption( action, auth_settings_external_ldap_search_filter );
			animateOption( action, auth_settings_external_ldap_uid );
			animateOption( action, auth_settings_external_ldap_attr_email );
			animateOption( action, auth_settings_external_ldap_user );
			animateOption( action, auth_settings_external_ldap_password );
			animateOption( action, auth_settings_external_ldap_tls );
			animateOption( action, auth_settings_external_ldap_lostpassword_url );
			animateOption( action, auth_settings_external_ldap_attr_first_name );
			animateOption( action, auth_settings_external_ldap_attr_last_name );
			animateOption( action, auth_settings_external_ldap_attr_update_on_login );
			animateOption( action, auth_settings_external_ldap_test_user );
		});

		// Event handler: Test LDAP settings.
		$( '#ldap_test_user_submit' ).on( 'click', function( event ) {
			event.preventDefault();
			$( 'html' ).addClass( 'busy' );
			$( '#ldap_test_user_spinner' ).addClass( 'is-active' );

			$.post( ajaxurl, {
				action: 'auth_settings_ldap_test_user',
				username: $( 'input[name="auth_settings[ldap_test_user]"]' ).val(),
				password: $( 'input#auth_settings_ldap_test_pass' ).val(),
				nonce: $( '#nonce_save_auth_settings' ).val(),
			}).done( function ( data ) {
				$( '#ldap_test_user_result' ).show().val( data.message );
			}).always( function () {
				$( 'html' ).removeClass( 'busy' );
				$( '#ldap_test_user_spinner' ).removeClass( 'is-active' );
			});
		} );

		// Show save button if usermeta field is modified.
		$( 'form input.auth-usermeta' ).on( 'keyup', function( event ) {
			// Don't do anything if tab or arrow keys were pressed.
			if ( event.which === 9 || event.which === 37 || event.which === 38 || event.which === 39 || event.which === 40 ) {
				return;
			}
			$( this ).siblings( '.button' ).css( 'display', 'inline-block' );
		});

		// List management function: pressing enter in the new approved or new
		// blocked user (email or role field) adds the user to the list.
		$( '#new_approved_user_email, #new_approved_user_role, #new_blocked_user_email' ).on( 'keyup', function( event ) {
			// For textareas, make Enter add the user; for inputs, make enter add the user.
			if ( $( this ).is( 'textarea' ) ) {
				// Enter key adds a newline; Enter key with Ctrl, Alt, Shift, or Meta adds the user.
				if ( event.which === 13 && ( event.ctrlKey || event.altKey || event.metaKey ) ) {
					$( this ).parent().find( 'a.button-add-user' ).trigger( 'click' );
					event.preventDefault();
				}
			} else if ( event.which === 13 ) { // Enter key on input[type="text"]
				$( this ).parent().find( 'a.button-add-user' ).trigger( 'click' );
				event.preventDefault();
			}
		});

		// Don't submit form (i.e., save options) when hitting enter in any user list field.
		$( 'input.auth-email, select.auth-role, input.auth-date-added, input.auth-usermeta' ).on( 'keydown', function( event ) {
			if ( event.which === 13 ) { // Enter key
				event.preventDefault();
				return false;
			}
		});

		// Enable the user-friendly multiselect form element on the options page.
		$( '#auth_settings_access_public_pages' ).multiSelect({
			selectableOptgroup: true,
			selectableHeader: '<div class="custom-header">' + authL10n.private_pages + '</div>',
			selectionHeader: '<div class="custom-header">' + authL10n.public_pages + '</div>',
		});

		// Switch to the first tab (or the tab indicated in sessionStorage, or the
		// querystring). Note: only do this on the settings page, not the dashboard
		// widget.
		if ( ! $( '#auth_dashboard_widget' ).length ) {
			var tab = '';
			if ( getQuerystringValuesByKey( 'tab' ).length > 0 ) {
				tab = getQuerystringValuesByKey( 'tab' )[0];
			} else if ( sessionStorage.getItem( 'tab' ) ) {
				tab = sessionStorage.getItem( 'tab' );
			}
			if ( $.inArray( tab, [ 'access_lists', 'access_login', 'access_public', 'external', 'advanced' ] ) < 0 ) {
				tab = 'access_lists';
			}
			window.chooseTab( tab, animationSpeed );
		}

		// Hide/show multisite settings based on override checkbox.
		$( 'input[name="auth_settings[multisite_override]"]' ).on( 'change', function() {
			hideMultisiteSettingsIfDisabled();
		});
		hideMultisiteSettingsIfDisabled();

		// Wire up pager events on Approved User list (first/last/next/previous
		// buttons, go to page text input, and search.
		$( '#current-page-selector, #user-search-input' ).on( 'keydown', function( event ) {
			if ( event.which === 13 ) { // Enter key
				var searchTerm = $( '#user-search-input' ).val();
				var currentPage = parseInt( $( this ).val(), 10 ) || 1;
				var totalPages = parseInt( $( '.total-pages' ).first().text().replace( /[^0-9]/g, '' ), 10 ) || 1;

				// Make sure current page is between 1 and max pages.
				if ( currentPage < 1 ) {
					currentPage = 1;
				} else if ( currentPage > totalPages ) {
					currentPage = totalPages;
				}

				// Update user list with users on next page.
				refreshApprovedUserList( currentPage, searchTerm );

				// Prevent default behavior.
				event.preventDefault();
				return false;
			}
		});

		$( '.tablenav' ).on( 'click', '.pagination-links a, #search-submit', function( event ) {
			var searchTerm = $( '#user-search-input' ).val();
			var currentPage = parseInt( getParameterByName( 'paged', $( this ).attr( 'href' ) ), 10 ) || 1;
			var totalPages = parseInt( $( '.total-pages' ).first().text().replace( /[^0-9]/g, '' ), 10 ) || 1;
			if ( currentPage > totalPages ) {
				currentPage = totalPages;
			}

			// Update user list with users on next page.
			refreshApprovedUserList( currentPage, searchTerm );

			// Remove focus from clicked element.
			$( this ).blur();

			// Prevent default behavior.
			event.preventDefault();
			return false;
		});

		// Enable growable textarea for new user field.
		$( 'textarea#new_approved_user_email' ).autogrow();

		// Enable growable textarea for config fields.
		$( 'textarea#auth_settings_ldap_host' ).autogrow();
		$( 'textarea#auth_settings_ldap_search_base' ).autogrow();
		$( 'textarea#auth_settings_ldap_search_filter' ).autogrow();
		$( 'textarea#auth_settings_oauth2_hosteddomain' ).autogrow();
		$( 'textarea#auth_settings_google_hosteddomain' ).autogrow();

	});


	/**
	 * Globals.
	 */


	// Switch between option tabs.
	window.chooseTab = function( listName, delay ) {
		// default delay is 0
		delay = 'undefined' !== typeof delay ? delay : 0;

		// default to the access list tab
		listName = 'undefined' !== typeof listName ? listName : 'access_lists';

		// Hide all tab content, then show selected tab content
		$( 'div.section_info, div.section_info + table' ).hide();
		$( '#section_info_' + listName + ', #section_info_' + listName + ' + table' ).show();

		// Set active tab
		$( '.nav-tab-wrapper a' ).removeClass( 'nav-tab-active' );
		$( 'a.nav-tab-' + listName ).addClass( 'nav-tab-active' );

		// Hide site options if they are overridden by a multisite setting.
		setTimeout( window.hideMultisiteOverriddenOptions, delay );

		// Hide Save Changes button if we're on the access lists page (changing
		// access lists saves automatically via AJAX).
		$( 'body:not(.network-admin) #submit' ).toggle( 'access_lists' !== listName );

		// Save user's active tab to sessionStorage (so we can restore it on reload).
		// Note: session storage persists until the browser tab is closed.
		sessionStorage.setItem( 'tab', listName );

		// Check whether to fade logo.
		fadeLogo();
	};

	// Hide (with overlay) site options if overridden by a multisite option.
	window.hideMultisiteOverriddenOptions = function() {
		$( '.auth_multisite_override_overlay' ).each( function() {
			// Option to hide is stored in the overlay's id with 'overlay-hide-' prefix.
			var optionContainerToHide = $( this ).closest( 'tr' );
			if ( optionContainerToHide.length > 0 ) {
				$( this ).css({
					'background-color': '#f1f1f1',
					'z-index': 1,
					opacity: 0.8,
					position: 'absolute',
					width: '100%',
					height: optionContainerToHide.height(),
				});
				$( this ).show();
			}
		});
	};

	// Update user's usermeta field.
	// @calls php wp_ajax_update_auth_usermeta.
	window.authUpdateUsermeta = function( caller ) {
		var $caller = $( caller ),
			$usermeta = $caller.parent().children( '.auth-usermeta' ),
			email = $caller.siblings( '.auth-email' ).val(),
			usermeta = $usermeta.val(),
			nonce = $( '#nonce_save_auth_settings' ).val();

		// Remove reference to caller if it's the usermeta field itself (not a button triggering the save).
		if ( $caller.hasClass( 'auth-usermeta' ) ) {
			$caller = $();
		}

		// Disable inputs, show spinner.
		$caller.attr( 'disabled', 'disabled' );
		$usermeta.attr( 'disabled', 'disabled' );
		var $row = $usermeta.closest( 'li' );
		var $spinner = $( '<span class="spinner is-active"></span>' ).css({
			position: 'absolute',
			top: $row.position().top,
			left: $row.position().left + $row.width(),
		});
		$usermeta.after( $spinner );
		$( 'html' ).addClass( 'busy' );

		// Call ajax save function.
		$.post( ajaxurl, {
			action: 'update_auth_usermeta',
			email: email,
			usermeta: usermeta,
			nonce: nonce,
		}, function( response ) {
			var succeeded = response === 'success';
			var spinnerText = succeeded ? authL10n.saved + '.' : '<span class="attention">' + authL10n.failed + '.</span>';
			var spinnerWait = succeeded ? 500 : 2000;

			// Enable inputs, remove spinner.
			$caller.removeAttr( 'disabled' );
			$usermeta.removeAttr( 'disabled' );
			$( 'form .spinner:not(:has(.spinner-text))' ).animate( { width: '60px' }, 'fast' ).append( '<span class="spinner-text">' + spinnerText + '</span>' ).delay( spinnerWait ).hide( animationSpeed, function() {
				$( this ).remove();
			});
			$( 'html' ).removeClass( 'busy' );

		}).fail( function() {
			var succeeded = false;
			var spinnerText = succeeded ? authL10n.saved + '.' : '<span class="attention">' + authL10n.failed + '.</span>';
			var spinnerWait = succeeded ? 500 : 2000;

			// Enable inputs, remove spinner.
			$caller.removeAttr( 'disabled' );
			$usermeta.removeAttr( 'disabled' );
			$( 'form .spinner:not(:has(.spinner-text))' ).animate( { width: '60px' }, 'fast' ).append( '<span class="spinner-text">' + spinnerText + '</span>' ).delay( spinnerWait ).hide( animationSpeed, function() {
				$( this ).remove();
			});
			$( 'html' ).removeClass( 'busy' );

		});
	};

	// Update user's role.
	window.authChangeRole = function( caller, isMultisite ) {
		// Set default for multisite flag (run different save routine if multisite)
		isMultisite = typeof isMultisite !== 'undefined' ? isMultisite : false;

		var email = $( caller ).parent().find( '.auth-email' );
		var role = $( caller ).parent().find( '.auth-role' );
		var dateAdded = $( caller ).parent().find( '.auth-date-added' );

		var user = {
			email: email.val(),
			role: role.val(),
			date_added: dateAdded.val(), // eslint-disable-line camelcase
			edit_action: 'change_role', // eslint-disable-line camelcase
			multisite_user: isMultisite, // eslint-disable-line camelcase
		};

		// Update the options in the database with this change.
		updateAuthUser( caller, 'access_users_approved', user );

		return true;
	};

	// Update user's role (multisite options page).
	window.authMultisiteChangeRole = function( caller ) {
		var isMultisite = true;
		window.authChangeRole( caller, isMultisite );
	};

	// Add user to list (list = blocked or approved).
	window.authAddUser = function( caller, list, shouldCreateLocalAccount, isMultisite ) {
		// Skip email address validation if adding from pending list (not user-editable).
		var skipValidation = $( caller ).parent().parent().attr( 'id' ) === 'list_auth_settings_access_users_pending';

		// Skip email address validation if we're banning an existing user (since they're already in a list).
		var blockingNewUser = $( caller ).attr( 'id' ).indexOf( 'block_user_new' ) > -1;
		skipValidation = skipValidation || ( $( caller ).attr( 'id' ).indexOf( 'block_user' ) > -1 && ! blockingNewUser );

		// Set default for multisite flag (run different save routine if multisite)
		isMultisite = 'undefined' !== typeof isMultisite ? isMultisite : false;

		// Default to the approved list.
		list = 'undefined' !== typeof list ? list : 'approved';

		// Default to not creating a local account.
		shouldCreateLocalAccount = 'undefined' !== typeof shouldCreateLocalAccount ? shouldCreateLocalAccount : false;

		var email = $( caller ).parent().find( '.auth-email' );
		var role = $( caller ).parent().find( '.auth-role' );
		var dateAdded = $( caller ).parent().find( '.auth-date-added' );

		// Helper variable for disabling buttons while processing. This will be
		// set differently if our clicked button is nested in a div (below).
		var buttons = caller;

		// Button (caller) might be nested in a div, so we need to walk up one more level
		if ( 0 === email.length || 0 === role.length ) {
			email = $( caller ).parent().parent().find( '.auth-email' );
			role = $( caller ).parent().parent().find( '.auth-role' );
			dateAdded = $( caller ).parent().parent().find( '.auth-date-added' );
			buttons = $( caller ).parent().children();
		}

		// Support a single email address, or multiple (separated by newlines, commas, semicolons, or spaces).
		var emails = $.trim( email.val() ).replace( /mailto:/g, '' ).split( /[\s,;]+/ );

		// Remove any invalid email addresses.
		if ( ! skipValidation ) {
			// Check if the email(s) being added is well-formed.
			emails = emails.filter( function( emailToValidate ) {
				return validEmail( emailToValidate, blockingNewUser );
			});
			// Remove any duplicates in the list of emails to add.
			emails = removeDuplicatesFromArrayOfStrings( emails );
		}

		// Shake and quit if no valid email addresses exist.
		if ( 1 > emails.length ) {
			$( '#new_' + list + '_user_email' ).parent().effect( 'shake', shakeSpeed );
			return false;
		}

		$( buttons ).attr( 'disabled', 'disabled' );

		var users = [];
		for ( var i = 0; i < emails.length; i++ ) {
			var user = {
				email: emails[i],
				role: role.val(),
				date_added: dateAdded.val(), // eslint-disable-line camelcase
				edit_action: 'add', // eslint-disable-line camelcase
				local_user: shouldCreateLocalAccount, // eslint-disable-line camelcase
				multisite_user: isMultisite, // eslint-disable-line camelcase
			};
			users.push( user );

			// Get next highest user ID.
			var nextId = 1 + Math.max.apply(
				null,
				// eslint-disable-next-line no-unused-vars
				$( '#list_auth_settings_access_users_' + list + ' li .auth-email' ).map( function( el ) { // jshint ignore:line
					return parseInt( this.id.replace( 'auth_multisite_settings_access_users_' + list + '_', '' ).replace( 'auth_settings_access_users_' + list + '_', '' ), 10 );
				})
			);

			// Add the new item.
			var authJsPrefix  = isMultisite ? 'authMultisite' : 'auth';
			var multisiteIcon = isMultisite ? '<a title="WordPress Multisite user" class="button disabled auth-multisite-user dashicons-before dashicons-admin-site"></a>' : '';
			var banButton     = isMultisite || 'approved' !== list ? '' : '<a class="button button-primary dashicons-before dashicons-remove" id="block_user_' + nextId + '" onclick="' + authJsPrefix + 'AddUser( this, \'blocked\', false ); ' + authJsPrefix + 'IgnoreUser( this, \'approved\' );" title="' + authL10n.block_ban_user + '"></a>';
			var ignoreButton  = '<a class="button dashicons-before dashicons-no" id="ignore_user_' + nextId + '" onclick="' + authJsPrefix + 'IgnoreUser( this, \'' + list + '\' );" title="' + authL10n.remove_user + '"></a>';
			$( ' \
				<li id="new_user_' + nextId + '" class="new-user" style="display: none;"> \
					<input type="text" id="auth_settings_access_users_' + list + '_' + nextId + '" name="auth_settings[access_users_' + list + '][' + nextId + '][email]" value="' + user.email + '" readonly="true" class="auth-email" /> \
					<select name="auth_settings[access_users_' + list + '][' + nextId + '][role]" class="auth-role" onchange="' + authJsPrefix + 'ChangeRole( this );"> \
					</select> \
					<input type="text" name="auth_settings[access_users_' + list + '][' + nextId + '][date_added]" value="' + getShortDate() + '" readonly="true" class="auth-date-added" /> \
					' + multisiteIcon + banButton + ignoreButton + ' \
					<span class="spinner is-active"></span> \
				</li> \
			' ).appendTo( '#list_auth_settings_access_users_' + list ).slideDown( 250 );

			// Populate the role dropdown in the new element. Because clone() doesn't
			// save selected state on select elements, set that too.
			$( 'option', role ).clone().appendTo( '#new_user_' + nextId + ' .auth-role' );
			$( '#new_user_' + nextId + ' .auth-role' ).val( role.val() );
		}

		// Remove the 'empty list' item if it exists.
		$( '#list_auth_settings_access_users_' + list + ' li.auth-empty' ).remove();

		// Update the options in the database with this change.
		updateAuthUser( buttons, 'access_users_' + list, users );

		// Reset the new user textboxes
		if ( email.hasClass( 'new' ) ) {
			email.val( '' ).keydown();
		}

		// Re-enable the action buttons now that we're done saving.
		$( buttons ).removeAttr( 'disabled' );
		return true;
	};

	// Add user to list (multisite options page).
	window.authMultisiteAddUser = function( caller, list, shouldCreateLocalAccount ) {
		var isMultisite = true;

		// Default to the approved list.
		list = typeof list !== 'undefined' ? list : 'approved';

		// Default to not creating a local account.
		shouldCreateLocalAccount = typeof shouldCreateLocalAccount !== 'undefined' ? shouldCreateLocalAccount : false;

		// There currently is no multisite blocked list, so do nothing.
		if ( list === 'blocked' ) {
			return;
		}

		window.authAddUser( caller, list, shouldCreateLocalAccount, isMultisite );
	};

	// Remove user from list.
	window.authIgnoreUser = function( caller, listName, isMultisite ) {
		// Set default for multisite flag (run different save routine if multisite)
		isMultisite = typeof isMultisite !== 'undefined' ? isMultisite : false;

		// Set default list if not provided.
		listName = typeof listName !== 'undefined' ? listName : 'approved';

		var email = $( caller ).parent().find( '.auth-email' );

		var user = {
			email: email.val(),
			role: '',
			date_added: '', // eslint-disable-line camelcase
			edit_action: 'remove', // eslint-disable-line camelcase
			multisite_user: isMultisite, // eslint-disable-line camelcase
		};

		// Show an 'empty list' message if we're deleting the last item
		var list = $( caller ).closest( 'ul' );
		if ( $( 'li', list ).length <= 1 ) {
			$( list ).append( '<li class="auth-empty"><em>' + authL10n.no_users_in + ' ' + listName + '</em></li>' );
		}

		$( caller ).parent().slideUp( 250, function() {
			// Remove the list item.
			$( this ).remove();

			// Update the options in the database with this change.
			updateAuthUser( caller, 'access_users_' + listName, user );
		});
	};

	// Remove user from list (multisite options page).
	window.authMultisiteIgnoreUser = function( caller, listName ) {
		var isMultisite = true;

		// Set default list if not provided.
		listName = typeof listName !== 'undefined' ? listName : '';

		window.authIgnoreUser( caller, listName, isMultisite );
	};

	// Save Authorizer Settings (multisite).
	// @calls php wp_ajax_save_auth_multisite_settings.
	/* eslint-disable camelcase */
	window.saveAuthMultisiteSettings = function( caller ) {
		// Enable wait cursor.
		$( 'html' ).addClass( 'busy' );

		// Disable button (prevent duplicate clicks).
		$( caller ).attr( 'disabled', 'disabled' );

		// Enable spinner by element that triggered this event (caller).
		var $spinner = $( '<span class="spinner is-active"></span>' ).css({
			position: 'absolute',
			top: $( caller ).position().top,
			left: $( caller ).position().left + $( caller ).width() + 20,
		});
		$( caller ).after( $spinner );

		// Get form elements to save.
		var params = {
			action: 'save_auth_multisite_settings',
			nonce: $( '#nonce_save_auth_settings' ).val(),
		};

		params.multisite_override = $( '#auth_settings_multisite_override' ).is( ':checked' ) ? '1' : '';

		params.prevent_override_multisite = $( '#auth_settings_prevent_override_multisite' ).is( ':checked' ) ? '1' : '';

		params.access_who_can_login = $( 'form input[name="auth_settings[access_who_can_login]"]:checked' ).val();

		params.access_who_can_view = $( 'form input[name="auth_settings[access_who_can_view]"]:checked' ).val();

		params.access_users_approved = {};
		$( '#list_auth_settings_access_users_approved li' ).each( function( index ) {
			var user = {};
			user.email = $( '.auth-email', this ).val();
			user.role = $( '.auth-role', this ).val();
			user.date_added = $( '.auth-date-added', this ).val();
			user.local_user = $( '.auth-local-user', this ).length !== 0;
			params.access_users_approved[index] = user;
		});

		params.access_default_role = $( '#auth_settings_access_default_role' ).val();

		params.oauth2 = $( '#auth_settings_oauth2' ).is( ':checked' ) ? '1' : '';
		params.oauth2_provider = $( '#auth_settings_oauth2_provider' ).val();
		params.oauth2_custom_label = $( '#auth_settings_oauth2_custom_label' ).val();
		params.oauth2_clientid = $( '#auth_settings_oauth2_clientid' ).val();
		params.oauth2_clientsecret = $( '#auth_settings_oauth2_clientsecret' ).val();
		params.oauth2_hosteddomain = $( '#auth_settings_oauth2_hosteddomain' ).val();
		params.oauth2_tenant_id = $( '#auth_settings_oauth2_tenant_id' ).val();
		params.oauth2_url_authorize = $( '#auth_settings_oauth2_url_authorize' ).val();
		params.oauth2_url_token = $( '#auth_settings_oauth2_url_token' ).val();
		params.oauth2_url_resource = $( '#auth_settings_oauth2_url_resource' ).val();
		params.oauth2_auto_login = $( '#auth_settings_oauth2_auto_login' ).is( ':checked' ) ? '1' : '';

		params.google = $( '#auth_settings_google' ).is( ':checked' ) ? '1' : '';
		params.google_clientid = $( '#auth_settings_google_clientid' ).val();
		params.google_clientsecret = $( '#auth_settings_google_clientsecret' ).val();
		params.google_hosteddomain = $( '#auth_settings_google_hosteddomain' ).val();

		params.cas = $( '#auth_settings_cas' ).is( ':checked' ) ? '1' : '';
		params.cas_auto_login = $( '#auth_settings_cas_auto_login' ).is( ':checked' ) ? '1' : '';
		params.cas_custom_label = $( '#auth_settings_cas_custom_label' ).val();
		params.cas_host = $( '#auth_settings_cas_host' ).val();
		params.cas_port = $( '#auth_settings_cas_port' ).val();
		params.cas_path = $( '#auth_settings_cas_path' ).val();
		params.cas_method = $( '#auth_settings_cas_method' ).val();
		params.cas_version = $( '#auth_settings_cas_version' ).val();
		params.cas_attr_email = $( '#auth_settings_cas_attr_email' ).val();
		params.cas_attr_first_name = $( '#auth_settings_cas_attr_first_name' ).val();
		params.cas_attr_last_name = $( '#auth_settings_cas_attr_last_name' ).val();
		params.cas_attr_update_on_login = $( '#auth_settings_cas_attr_update_on_login' ).val();
		params.cas_link_on_username = $( '#auth_settings_cas_link_on_username' ).is( ':checked' ) ? '1' : '';

		params.ldap = $( '#auth_settings_ldap' ).is( ':checked' ) ? '1' : '';
		params.ldap_host = $( '#auth_settings_ldap_host' ).val();
		params.ldap_port = $( '#auth_settings_ldap_port' ).val();
		params.ldap_search_base = $( '#auth_settings_ldap_search_base' ).val();
		params.ldap_search_filter = $( '#auth_settings_ldap_search_filter' ).val();
		params.ldap_uid = $( '#auth_settings_ldap_uid' ).val();
		params.ldap_attr_email = $( '#auth_settings_ldap_attr_email' ).val();
		params.ldap_user = $( '#auth_settings_ldap_user' ).val();
		params.ldap_password = $( '#auth_settings_ldap_password' ).val();
		params.ldap_tls = $( '#auth_settings_ldap_tls' ).is( ':checked' ) ? '1' : '';
		params.ldap_lostpassword_url = $( '#auth_settings_ldap_lostpassword_url' ).val();
		params.ldap_attr_first_name = $( '#auth_settings_ldap_attr_first_name' ).val();
		params.ldap_attr_last_name = $( '#auth_settings_ldap_attr_last_name' ).val();
		params.ldap_attr_update_on_login = $( '#auth_settings_ldap_attr_update_on_login' ).val();
		params.ldap_test_user = $( '#auth_settings_ldap_test_user' ).val();

		params.advanced_lockouts = {
			attempts_1: $( '#auth_settings_advanced_lockouts_attempts_1' ).val(),
			duration_1: $( '#auth_settings_advanced_lockouts_duration_1' ).val(),
			attempts_2: $( '#auth_settings_advanced_lockouts_attempts_2' ).val(),
			duration_2: $( '#auth_settings_advanced_lockouts_duration_2' ).val(),
			reset_duration: $( '#auth_settings_advanced_lockouts_reset_duration' ).val(),
		};
		params.advanced_hide_wp_login = $( '#auth_settings_advanced_hide_wp_login' ).is( ':checked' ) ? '1' : '';
		params.advanced_disable_wp_login = $( '#auth_settings_advanced_disable_wp_login' ).is( ':checked' ) ? '1' : '';
		params.advanced_widget_enabled = $( '#auth_settings_advanced_widget_enabled' ).is( ':checked' ) ? '1' : '';
		params.advanced_users_per_page = $( '#auth_settings_advanced_users_per_page' ).val();
		params.advanced_users_sort_by = $( '#auth_settings_advanced_users_sort_by' ).val();
		params.advanced_users_sort_order = $( '#auth_settings_advanced_users_sort_order' ).val();

		$.post( ajaxurl, params, function( response ) {
			var succeeded = response === 'success';
			var spinnerText = succeeded ? authL10n.saved + '.' : '<span class="attention">' + authL10n.failed + '.</span>';
			var spinnerWait = succeeded ? 500 : 2000;
			$( 'form .spinner:not(:has(.spinner-text))' ).append( '<span class="spinner-text">' + spinnerText + '</span>' ).delay( spinnerWait ).hide( animationSpeed, function() {
				$( this ).remove();
			});
			$( caller ).removeAttr( 'disabled' );

			// Disable wait cursor.
			$( 'html' ).removeClass( 'busy' );
		}).fail( function() {
			// Fail fires if the server doesn't respond
			var succeeded = false;
			var spinnerText = succeeded ? authL10n.saved + '.' : '<span class="attention">' + authL10n.failed + '.</span>';
			var spinnerWait = succeeded ? 500 : 2000;
			$( 'form .spinner:not(:has(.spinner-text))' ).append( '<span class="spinner-text">' + spinnerText + '</span>' ).delay( spinnerWait ).hide( animationSpeed, function() {
				$( this ).remove();
			});
			$( caller ).removeAttr( 'disabled' );

			// Disable wait cursor.
			$( 'html' ).removeClass( 'busy' );
		});
	};
	/* eslint-enable camelcase */

	// Fade in/out Authorizer logo in bottom right on Settings.
	$(document).on( 'scroll', function () {
		fadeLogo();
	});

	function fadeLogo() {
		if ( getScrollPercent() < 90 ) {
			$( '#wpwrap' ).removeClass( 'not-faded' );
		} else {
			$( '#wpwrap' ).addClass( 'not-faded' );
		}
	}

	function getScrollPercent() {
		var h = document.documentElement,
			b = document.body,
			st = 'scrollTop',
			sh = 'scrollHeight';
		return ( h[st] || b[st] ) / ( ( h[sh] || b[sh] ) - h.clientHeight ) * 100;
	}

	/* ========================================================================
	 * Portions below from Bootstrap.
	 * ========================================================================
	 * Bootstrap: dropdown.js v3.1.1
	 * http://getbootstrap.com/javascript/#dropdowns
	 * ========================================================================
	 * Copyright 2011-2014 Twitter, Inc.
	 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
	 * ======================================================================== */

	// DROPDOWN CLASS DEFINITION
	// =========================
	var backdrop = '.dropdown-backdrop';
	var toggle = '[data-toggle=dropdown]';
	var Dropdown = function( element ) { // eslint-disable-line func-style
		$( element ).on( 'click.bs.dropdown', this.toggle );
	};

	Dropdown.prototype.toggle = function( event ) {
		var $this = $( this );

		if ( $this.is( '.disabled, :disabled' ) ) {
			return;
		}

		var $parent = getParent( $this );
		var isActive = $parent.hasClass( 'open' );

		clearMenus();

		if ( ! isActive ) {
			if ( 'ontouchstart' in document.documentElement && ! $parent.closest( '.navbar-nav' ).length ) {
				// if mobile we use a backdrop because click events don't delegate
				$( '<div class="dropdown-backdrop"/>' ).insertAfter( $( this ) ).on( 'click', clearMenus );
			}

			var relatedTarget = { relatedTarget: this };
			$parent.trigger( event = $.Event( 'show.bs.dropdown', relatedTarget ) );

			if ( event.isDefaultPrevented() ) {
				return;
			}

			$parent
				.toggleClass( 'open' )
				.trigger( 'shown.bs.dropdown', relatedTarget);

			$this.focus();
		}

		return false;
	};

	Dropdown.prototype.keydown = function( event ) {
		if ( ! /(38|40|27)/.test( event.keyCode ) ) {
			return;
		}

		var $this = $( this );

		event.preventDefault();
		event.stopPropagation();

		if ( $this.is( '.disabled, :disabled' ) ) {
			return;
		}

		var $parent = getParent( $this );
		var isActive = $parent.hasClass( 'open' );

		if ( ! isActive || ( isActive && event.keyCode === 27 ) ) {
			if ( event.which === 27 ) {
				$parent.find( toggle ).focus();
			}
			return $this.click();
		}

		var desc = ' li:not(.divider):visible a';
		var $items = $parent.find( '[role=menu]' + desc + ', [role=listbox]' + desc);

		if ( ! $items.length ) {
			return;
		}

		var index = $items.index($items.filter( ':focus' ));

		if ( event.keyCode === 38 && index > 0 ) {
			index--; // up
		}
		if ( event.keyCode === 40 && index < $items.length - 1 ) {
			index++; // down
		}
		if ( ! ~index ) {
			index = 0;
		}

		$items.eq(index).focus();
	};

	function clearMenus( event ) {
		$(backdrop).remove();
		$(toggle).each( function() {
			var $parent = getParent($( this ));
			var relatedTarget = { relatedTarget: this };
			if ( ! $parent.hasClass( 'open' ) ) {
				return;
			}
			$parent.trigger( event = $.Event( 'hide.bs.dropdown', relatedTarget ) );
			if ( event.isDefaultPrevented() ) {
				return;
			}
			$parent.removeClass( 'open' ).trigger( 'hidden.bs.dropdown', relatedTarget);
		});
	}

	function getParent( $this ) {
		var selector = $this.attr( 'data-target' );

		if ( ! selector ) {
			selector = $this.attr( 'href' );
			selector = selector && /#[A-Za-z]/.test(selector) && selector.replace(/.*(?=#[^\s]*$)/, '' ); // strip for ie7
		}

		var $parent = selector && $(selector);

		return $parent && $parent.length ? $parent : $this.parent();
	}

	// DROPDOWN PLUGIN DEFINITION
	// ==========================
	var old = $.fn.dropdown;
	$.fn.dropdown = function( option ) {
		return this.each( function() {
			var $this = $( this );
			var data = $this.data( 'bs.dropdown' );

			if ( ! data ) {
				$this.data( 'bs.dropdown', ( data = new Dropdown( this ) ) );
			}
			if ( 'string' === typeof option ) {
				data[option].call( $this );
			}
		});
	};
	$.fn.dropdown.Constructor = Dropdown;

	// DROPDOWN NO CONFLICT
	// ====================
	$.fn.dropdown.noConflict = function() {
		$.fn.dropdown = old;
		return this;
	};

	// APPLY TO STANDARD DROPDOWN ELEMENTS
	// ===================================
	$(document)
		.on( 'click.bs.dropdown.data-api', clearMenus)
		.on( 'click.bs.dropdown.data-api', '.dropdown form', function( event ) { event.stopPropagation(); })
		.on( 'click.bs.dropdown.data-api', toggle, Dropdown.prototype.toggle)
		.on( 'keydown.bs.dropdown.data-api', toggle + ', [role=menu], [role=listbox]', Dropdown.prototype.keydown);

} )( jQuery );
