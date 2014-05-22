var animation_speed = 300;
var shake_speed = 600;



// Switch between option tabs.
function chooseTab( list_name, delay ) {
  var $ = jQuery;

  // default delay is 0
  delay = typeof delay !== 'undefined' ? delay : 0;

  // default to the access list tab
  list_name = typeof list_name !== 'undefined' ? list_name : 'access_list';

  // Hide all tab content, then show selected tab content
  $('div.section_info, div.section_info + table').hide();
  $('#section_info_' + list_name + ', #section_info_' + list_name + ' + table').show();

  // Set active tab
  $('.nav-tab-wrapper a').removeClass('nav-tab-active');
  $('a.nav-tab-' + list_name).addClass('nav-tab-active');

  // Hide site options if they are overridden by a multisite setting.
  setTimeout( hide_multisite_overridden_options, delay );
}

// Remove user from list (multisite options page).
function auth_multisite_add_user( caller, list, create_local_account ) {
  create_local_account = typeof create_local_account !== 'undefined' ? create_local_account : false;
  var is_multisite = true;
  auth_add_user( caller, list, create_local_account, is_multisite );
}
// Add user to list (list = blocked or approved).
function auth_add_user( caller, list, create_local_account, is_multisite ) {
  var $ = jQuery;

  // Set default for multisite flag (run different save routine if multisite)
  is_multisite = typeof is_multisite !== 'undefined' ? is_multisite : false;

  // default to the approved list
  list = typeof list !== 'undefined' ? list : 'approved';
  create_local_account = typeof create_local_account !== 'undefined' ? create_local_account : false;

  var username = $(caller).parent().find('.auth-username');
  var email = $(caller).parent().find('.auth-email');
  var role = $(caller).parent().find('.auth-role');

  // Helper variable for disabling buttons while processing. This will be
  // set differently if our clicked button is nested in a div (below).
  var buttons = caller;

  // Button (caller) might be nested in a div, so we need to walk up one more level
  if ( username.length === 0 || email.length === 0 || role.length === 0 ) {
    username = $(caller).parent().parent().find('.auth-username');
    email = $(caller).parent().parent().find('.auth-email');
    role = $(caller).parent().parent().find('.auth-role');
    buttons = $(caller).parent().children();
  }

  var next_id = $('#list_auth_settings_access_users_' + list + ' li').length;
  var validated = true;

  if ( $.trim(username.val()) == '' )
    return false;

  $(buttons).attr('disabled', 'disabled');

  // Check if the course being added already exists in the list.
  if ( validated ) {
    $('#list_auth_settings_access_users_' + list + ' input.auth-username').each(function() {
      if ( this.value == username.val() ) {
        validated = false;
        $(this).parent().effect('shake', shake_speed);
        $(buttons).removeAttr('disabled');
        return false;
      }
    });
  }

  // Check if the name being added already exists in the list.
  if ( validated ) {
    $('#list_auth_settings_access_users_' + list + ' input.auth-email').each(function() {
      if ( this.value == email.val() ) {
        validated = false;
        $(this).parent().effect('shake', shake_speed);
        $(buttons).removeAttr('disabled');
        return false;
      }
    });
  }

  if ( validated ) {
    // Add the new item.
    var local_icon = create_local_account ? '&nbsp;<a title="Local WordPress user" class="auth-local-user"><span class="glyphicon glyphicon-user"></span></a>' : '';
    $(' \
      <li id="new_user_' + next_id + '" style="display: none;"> \
        <input type="text" name="auth_settings[access_users_' + list + '][' + next_id + '][username]" value="' + username.val() + '" readonly="true" class="auth-username" /> \
        <input type="text" id="auth_settings_access_users_' + list + '_' + next_id + '" name="auth_settings[access_users_' + list + '][' + next_id + '][email]" value="' + email.val() + '" readonly="true" class="auth-email" /> \
        <select name="auth_settings[access_users_' + list + '][' + next_id + '][role]" class="auth-role" onchange="save_auth_settings(this);"> \
        </select> \
        <input type="text" name="auth_settings[access_users_' + list + '][' + next_id + '][date_added]" value="' + getShortDate() + '" readonly="true" class="auth-date-added" /> \
        <input type="button" class="button" onclick="auth_ignore_user(this);" value="&times;" /> ' + local_icon + ' \
        <span class="spinner"></span> \
      </li> \
    ').appendTo('#list_auth_settings_access_users_' + list + '').slideDown(250);

    // Populate the role dropdown in the new element. Because clone() doesn't
    // save selected state on select elements, set that too.
    $('option', role).clone().appendTo('#new_user_' + next_id + ' .auth-role');
    $('#new_user_' + next_id + ' .auth-role').val(role.val());

    // Remove the 'empty list' item if it exists.
    $('#list_auth_settings_access_users_' + list + ' li.auth-empty').remove();

    // Reset the new user textboxes
    username.val('');
    email.val('');
    $(buttons).removeAttr('disabled');

    // Update the options in the database with this change.
    if ( is_multisite ) {
      save_auth_multisite_settings( caller, create_local_account );
    } else {
      save_auth_settings( buttons, create_local_account );
    }

    return true;
  }
}

// Remove user from list (multisite options page).
function auth_multisite_ignore_user( caller, list_name ) {
  var is_multisite = true;
  auth_ignore_user( caller, list_name, is_multisite );
}
// Remove user from list.
function auth_ignore_user( caller, list_name, is_multisite ) {
  var $ = jQuery;

  // Set default for multisite flag (run different save routine if multisite)
  is_multisite = typeof is_multisite !== 'undefined' ? is_multisite : false;

  // Show an 'empty list' message if we're deleting the last item
  list_name = typeof list_name !== 'undefined' ? list_name : '';
  var list = $(caller).parent().parent();
  if ( $('li', list).length <= 1 ) {
    $(list).append('<li class="auth-empty"><em>No ' + list_name + ' users</em></li>');
  }

  $(caller).parent().slideUp(250, function() {
    // Remove the list item.
    $(this).remove();

    // Update the options in the database with this change.
    if ( is_multisite ) {
      save_auth_multisite_settings( caller );
    } else {
      save_auth_settings( caller );
    }
  });
}


// Save options from dashboard widget.
function save_auth_settings( caller, create_local_account ) {
  var $ = jQuery;

  $(caller).attr('disabled', 'disabled');
  $(caller).last().after('<span class="spinner"></span>');
  $('form .spinner').show();

  var access_restriction = $('form input[name="auth_settings[access_restriction]"]:checked').val();

  var access_users_pending = new Object();
  $('#list_auth_settings_access_users_pending li').each(function(index) {
    var user = new Object();
    user['username'] = $('.auth-username', this).val();
    user['email'] = $('.auth-email', this).val();
    user['role'] = $('.auth-role', this).val();
    access_users_pending[index] = user;
  });

  var access_users_approved = new Object();
  $('#list_auth_settings_access_users_approved li').each(function(index) {
    var user = new Object();
    user['username'] = $('.auth-username', this).val();
    user['email'] = $('.auth-email', this).val();
    user['role'] = $('.auth-role', this).val();
    user['date_added'] = $('.auth-date-added', this).val();
    user['local_user'] = $('.auth-local-user', this).length !== 0;
    access_users_approved[index] = user;
  });

  // If admin clicked 'add local user', mark the last user in the list of approved
  // users as a local user (the last user is the user the admin just added).
  if ( create_local_account ) {
    access_users_approved[Object.keys( access_users_approved ).length - 1]['local_user'] = true;
  }

  var access_users_blocked = new Object();
  $('#list_auth_settings_access_users_blocked li').each(function( index ) {
    var user = new Object();
    user['username'] = $('.auth-username', this).val();
    user['email'] = $('.auth-email', this).val();
    user['role'] = $('.auth-role', this).val();
    user['date_added'] = $('.auth-date-added', this).val();
    access_users_blocked[index] = user;
  });

  var nonce_save_auth_settings = $('#nonce_save_auth_settings').val();

  $.post(ajaxurl, {
    action: 'save_auth_dashboard_widget',
    'access_restriction': access_restriction,
    'access_users_pending': access_users_pending,
    'access_users_approved': access_users_approved,
    'access_users_blocked': access_users_blocked,
    'nonce_save_auth_settings': nonce_save_auth_settings,
  }, function( response ) {
    $('form .spinner').remove();
    $(caller).removeAttr('disabled');
    if (response==0) { // failed
      return false;
    } else { // succeeded
      return true;
    }
  });
}


// Multisite functions
function save_auth_multisite_settings( caller ) {
  var $ = jQuery;

  $(caller).attr('disabled', 'disabled');
  $(caller).last().after('<span class="spinner"></span>');
  $('form .spinner').show();

  // Get form elements to save

  var nonce_save_auth_settings = $('#nonce_save_auth_settings').val();

  var multisite_override = $('#auth_settings_multisite_override').is(':checked') ? '1' : '';

  var access_restriction = $('form input[name="auth_settings[access_restriction]"]:checked').val();

  var access_users_approved = new Object();
  $('#list_auth_settings_access_users_approved li').each(function( index ) {
    var user = new Object();
    user['username'] = $('.auth-username', this).val();
    user['email'] = $('.auth-email', this).val();
    user['role'] = $('.auth-role', this).val();
    user['date_added'] = $('.auth-date-added', this).val();
    user['local_user'] = $('.auth-local-user', this).length !== 0;
    access_users_approved[index] = user;
  });

  var access_default_role = $('#auth_settings_access_default_role').val();

  var external_service = $('form input[name="auth_settings[external_service]"]:checked').val();

  var cas_host = $('#auth_settings_cas_host').val();
  var cas_port = $('#auth_settings_cas_port').val();
  var cas_path = $('#auth_settings_cas_path').val();

  var ldap_host = $('#auth_settings_ldap_host').val();
  var ldap_port = $('#auth_settings_ldap_port').val();
  var ldap_search_base = $('#auth_settings_ldap_search_base').val();
  var ldap_uid = $('#auth_settings_ldap_uid').val();
  var ldap_user = $('#auth_settings_ldap_user').val();
  var ldap_password = $('#auth_settings_ldap_password').val();
  var ldap_tls = $('#auth_settings_ldap_tls').is(':checked') ? '1' : '';

  var advanced_lockouts = {
    'attempts_1': $('#auth_settings_advanced_lockouts_attempts_1').val(),
    'duration_1': $('#auth_settings_advanced_lockouts_duration_1').val(),
    'attempts_2': $('#auth_settings_advanced_lockouts_attempts_2').val(),
    'duration_2': $('#auth_settings_advanced_lockouts_duration_2').val(),
    'reset_duration': $('#auth_settings_advanced_lockouts_reset_duration').val()
  }

  var advanced_lostpassword_url = $('#auth_settings_advanced_lostpassword_url').val();

  var advanced_branding = $('form input[name="auth_settings[advanced_branding]"]:checked').val();

  $.post(ajaxurl, {
    action: 'save_auth_multisite_settings',
    'nonce_save_auth_settings': nonce_save_auth_settings,
    'multisite_override': multisite_override,
    'access_restriction': access_restriction,
    'access_users_approved': access_users_approved,
    'access_default_role': access_default_role,
    'external_service': external_service,
    'cas_host': cas_host,
    'cas_port': cas_port,
    'cas_path': cas_path,
    'ldap_host': ldap_host,
    'ldap_port': ldap_port,
    'ldap_search_base': ldap_search_base,
    'ldap_uid': ldap_uid,
    'ldap_user': ldap_user,
    'ldap_password': ldap_password,
    'ldap_tls': ldap_tls,
    'advanced_lockouts': advanced_lockouts,
    'advanced_lostpassword_url': advanced_lostpassword_url,
    'advanced_branding': advanced_branding,
  }, function( response ) {
    $('form .spinner').remove();
    $(caller).removeAttr('disabled');
    if ( response==0 ) { // failed
      return false;
    } else { // succeeded
      return true;
    }
  });
}

// Hide or show (with overlay) the multisite settings based on the "multisite override" setting.
function hide_multisite_settings_if_disabled() {
  var $ = jQuery;

  if ( $('#auth_settings_multisite_override').length == 0 )
    return;

  var settings = $('#auth_multisite_settings');
  var overlay = $('#auth_multisite_settings_disabled_overlay')

  if ( $('#auth_settings_multisite_override').is(':checked') ) {
    overlay.hide(animation_speed);
  } else {
    overlay.css({
      'background-color': '#f1f1f1',
      'z-index': 1,
      'opacity': 0.8,
      'position': 'absolute',
      'top': settings.position().top,
      'left': settings.position().left,
      'width': settings.width(),
      'height': settings.height(),
    });
    overlay.show();
  }
}

// Hide (with overlay) site options if overridden by a multisite option.
function hide_multisite_overridden_options() {
  var $ = jQuery;

  $('.auth_multisite_override_overlay').each( function() {
    // Option to hide is stored in the overlay's id with 'overlay-hide-' prefix.
    var option_id_to_hide = $(this).attr('id').replace('overlay-hide-','');
    var option_container_to_hide = $('#' + option_id_to_hide).closest('tr');
    $(this).css({
      'background-color': '#f1f1f1',
      'z-index': 1,
      'opacity': 0.8,
      'position': 'absolute',
      'top': option_container_to_hide.position().top,
      'left': option_container_to_hide.position().left,
      'width': option_container_to_hide.width(),
      'height': option_container_to_hide.height(),
    });
    $(this).show();
  });
}



// Helper function to grab a querystring param value by name
function getParameterByName( needle, haystack ) {
  needle = needle.replace( /[\[]/, "\\\[").replace(/[\]]/, "\\\]" );
  var regex = new RegExp( "[\\?&]" + needle + "=([^&#]*)" );
  var results = regex.exec( haystack );
  if( results == null )
    return '';
  else
    return decodeURIComponent( results[1].replace( /\+/g, " " ) );
}

// Helper function to generate a random string
function getRandomId() {
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for ( var i=0; i < 5; i++ )
    text += possible.charAt( Math.floor( Math.random() * possible.length ) );
  return text;
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

// Helper function to grab the TLD from a FQDN
function getTLDFromFQDN( fqdn ) {
  fqdn = typeof fqdn !== 'undefined' ? fqdn : '';
  if ( fqdn == '' ) return 'example.com';
  var matches = fqdn.match( /[^.]*\.[^.]*$/ );
  return matches.length > 0 ? matches[0] : '';
}

// Helper function to get the username from an email address
function getUsernameFromEmail( email ) {
  email = typeof email !== 'undefined' ? email : '';
  return email.split( "@" )[0];
}

// Helper function to grab a querystring value
function querystring( key ) {
  var re = new RegExp( '(?:\\?|&)'+key+'=(.*?)(?=&|$)', 'gi' );
  var r = [], m;
  while ( ( m = re.exec( document.location.search ) ) != null )
    r.push( m[1] );
  return r;
}


jQuery(document).ready(function($){
  // Grab references to form elements that we will show/hide on page load
  var auth_settings_access_redirect_to_login = $('#radio_auth_settings_access_redirect_to_login').closest('tr');
  var auth_settings_access_redirect_to_message = $('#wp-auth_settings_access_redirect_to_message-wrap').closest('tr');
  var auth_settings_access_users_pending = $('#list_auth_settings_access_users_pending').closest('tr');
  var auth_settings_access_users_approved = $('#list_auth_settings_access_users_approved').closest('tr');
  var auth_settings_access_users_blocked = $('#list_auth_settings_access_users_blocked').closest('tr');
  var auth_settings_access_role_receive_pending_emails = $('#auth_settings_access_role_receive_pending_emails').closest('tr');
  var auth_settings_access_pending_redirect_to_message = $('#wp-auth_settings_access_pending_redirect_to_message-wrap').closest('tr');
  var auth_settings_access_public_pages = $('#auth_settings_access_public_pages').closest('tr');
  var auth_settings_external_settings_table = $('#auth_settings_external_service_cas').closest('table');
  var auth_settings_external_service_cas = $('#radio_auth_settings_external_service_cas').closest('tr');
  var auth_settings_external_cas_host = $('#auth_settings_cas_host').closest('tr');
  var auth_settings_external_cas_port = $('#auth_settings_cas_port').closest('tr');
  var auth_settings_external_cas_path = $('#auth_settings_cas_path').closest('tr');
  var auth_settings_external_ldap_host = $('#auth_settings_ldap_host').closest('tr');
  var auth_settings_external_ldap_port = $('#auth_settings_ldap_port').closest('tr');
  var auth_settings_external_ldap_search_base = $('#auth_settings_ldap_search_base').closest('tr');
  var auth_settings_external_ldap_uid = $('#auth_settings_ldap_uid').closest('tr');
  var auth_settings_external_ldap_user = $('#auth_settings_ldap_user').closest('tr');
  var auth_settings_external_ldap_password = $('#auth_settings_ldap_password').closest('tr');
  var auth_settings_external_ldap_tls = $('#auth_settings_ldap_tls').closest('tr');

  // Wrap the th and td in the rows above so we can animate their heights (can't animate tr heights with jquery)
  $('th, td', auth_settings_access_redirect_to_login).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_redirect_to_message).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_users_pending).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_users_approved).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_users_blocked).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_role_receive_pending_emails).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_pending_redirect_to_message).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_public_pages).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_cas_host).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_cas_port).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_cas_path).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_host).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_port).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_search_base).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_uid).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_user).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_password).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_external_ldap_tls).wrapInner('<div class="animated_wrapper" />');

  // If we're viewing the dashboard widget, reset a couple of the relevant
  // option variables (since they're aren't nested in table rows).
  if ( $('#auth_dashboard_widget').length ) {
    auth_settings_access_users_pending = $('#list_auth_settings_access_users_pending').closest('div');
    auth_settings_access_users_approved = $('#list_auth_settings_access_users_approved').closest('div');
    auth_settings_access_users_blocked = $('#list_auth_settings_access_users_blocked').closest('div');
    $(auth_settings_access_users_pending).wrapInner('<div class="animated_wrapper" />');
    $(auth_settings_access_users_approved).wrapInner('<div class="animated_wrapper" />');
    $(auth_settings_access_users_blocked).wrapInner('<div class="animated_wrapper" />');

    // Remove the helper link, since there are no tabs on the dashboard widget
    $('#dashboard_link_approved_users').contents().unwrap();
  }

  // On load: Show/hide pending/approved/blocked list options
  if ( !$('#radio_auth_settings_access_restriction_approved_users').is(':checked') ) {
    $('div.animated_wrapper', auth_settings_access_users_pending).hide();
    $('div.animated_wrapper', auth_settings_access_users_approved).hide();
    $('div.animated_wrapper', auth_settings_access_users_blocked).hide();
    $('div.animated_wrapper', auth_settings_access_role_receive_pending_emails).hide();
    $('div.animated_wrapper', auth_settings_access_pending_redirect_to_message).hide();
  }

  // On load: Show/hide CAS/LDAP options based on which is selected
  if ( $('#radio_auth_settings_external_service_cas').is(':checked') ) {
    $('div.animated_wrapper', auth_settings_external_ldap_host).hide();
    $('div.animated_wrapper', auth_settings_external_ldap_port).hide();
    $('div.animated_wrapper', auth_settings_external_ldap_search_base).hide();
    $('div.animated_wrapper', auth_settings_external_ldap_uid).hide();
    $('div.animated_wrapper', auth_settings_external_ldap_user).hide();
    $('div.animated_wrapper', auth_settings_external_ldap_password).hide();
    $('div.animated_wrapper', auth_settings_external_ldap_tls).hide();

    $('td, th', auth_settings_external_ldap_host).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_ldap_port).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_ldap_search_base).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_ldap_uid).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_ldap_user).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_ldap_password).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_ldap_tls).animate({ padding: '0px' }, { duration: animation_speed });
  } else {
    $('div.animated_wrapper', auth_settings_external_cas_host).hide();
    $('div.animated_wrapper', auth_settings_external_cas_port).hide();
    $('div.animated_wrapper', auth_settings_external_cas_path).hide();

    $('td, th', auth_settings_external_cas_host).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_cas_port).animate({ padding: '0px' }, { duration: animation_speed });
    $('td, th', auth_settings_external_cas_path).animate({ padding: '0px' }, { duration: animation_speed });
  }

  // Event handler: Hide "Handle unauthorized visitors" option if access is granted to "Everyone"
  $('input[name="auth_settings[access_restriction]"]').change(function(){
    if ( $('#radio_auth_settings_access_restriction_everyone').is(':checked') ) {
      $('div.animated_wrapper', auth_settings_access_redirect_to_login).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_redirect_to_message).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_public_pages).slideUp(animation_speed);
    } else {
      $('div.animated_wrapper', auth_settings_access_redirect_to_login).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_redirect_to_message).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_public_pages).slideDown(animation_speed);
      $('input[name="auth_settings[access_redirect]"]').trigger('change');
    }
  
    // Hide user whitelist unless "Only specific students below" is checked
    if ( ! $('#radio_auth_settings_access_restriction_approved_users').is(':checked') ) {
      $('div.animated_wrapper', auth_settings_access_users_pending).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_users_approved).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_users_blocked).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_role_receive_pending_emails).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_pending_redirect_to_message).slideUp(animation_speed);
    } else {
      $('div.animated_wrapper', auth_settings_access_users_pending).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_users_approved).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_users_blocked).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_role_receive_pending_emails).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_pending_redirect_to_message).slideDown(animation_speed);
    }
  });

  // Event handler: show/hide CAS/LDAP options based on selection.
  $('input[name="auth_settings[external_service]"]').change(function() {
    if ( $('#radio_auth_settings_external_service_cas').is(':checked') ) {
      $('div.animated_wrapper', auth_settings_external_cas_host).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_cas_port).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_cas_path).slideDown(animation_speed);

      $('div.animated_wrapper', auth_settings_external_ldap_host).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_port).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_search_base).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_uid).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_user).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_password).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_tls).slideUp(animation_speed);

      $('th', auth_settings_external_cas_host).animate({ padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_cas_port).animate({ padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_cas_path).animate({ padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('td', auth_settings_external_cas_host).animate({ padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_cas_port).animate({ padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_cas_path).animate({ padding: '15px 10px' }, { duration: animation_speed });

      $('td, th', auth_settings_external_ldap_host).animate(       { padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_ldap_port).animate(       { padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_ldap_search_base).animate({ padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_ldap_uid).animate(        { padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_ldap_user).animate(       { padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_ldap_password).animate(   { padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_ldap_tls).animate(        { padding: '0px' }, { duration: animation_speed });
    } else {
      $('div.animated_wrapper', auth_settings_external_cas_host).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_cas_port).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_external_cas_path).slideUp(animation_speed);

      $('div.animated_wrapper', auth_settings_external_ldap_host).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_port).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_search_base).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_uid).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_user).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_password).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_external_ldap_tls).slideDown(animation_speed);

      $('td, th', auth_settings_external_cas_host).animate({ padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_cas_port).animate({ padding: '0px' }, { duration: animation_speed });
      $('td, th', auth_settings_external_cas_path).animate({ padding: '0px' }, { duration: animation_speed });

      $('th', auth_settings_external_ldap_host).animate(       { padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_ldap_port).animate(       { padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_ldap_search_base).animate({ padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_ldap_uid).animate(        { padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_ldap_user).animate(       { padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_ldap_password).animate(   { padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('th', auth_settings_external_ldap_tls).animate(        { padding: '20px 10px 20px 0' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_host).animate(       { padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_port).animate(       { padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_search_base).animate({ padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_uid).animate(        { padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_user).animate(       { padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_password).animate(   { padding: '15px 10px' }, { duration: animation_speed });
      $('td', auth_settings_external_ldap_tls).animate(        { padding: '15px 10px' }, { duration: animation_speed });
    }
  });

  // List management function: pressing enter in the username, email, or role
  // field adds the user to the list. Additionally, if the email field is
  // blank, it gets constructed from the username field (and vice versa).
  $('form input.auth-username, form input.auth-email, form select.auth-role').bind('keyup', function(e) {
    if ( e.which == 13 ) { // Enter key
      $(this).parent().find('input[type="button"]').trigger('click');
      return false;
    } else if ( $(this).hasClass('auth-username') ) {
      var host = '';
      if ( $('#radio_auth_settings_external_service_cas').is(':checked') || $('#auth_settings_external_service').val() == 'cas' ) {
        host = $('#auth_settings_cas_host').val();
      } else if ( $('#radio_auth_settings_external_service_ldap').is(':checked') || $('#auth_settings_external_service').val() == 'ldap' ) {
        host = $('#auth_settings_ldap_host').val();
      }
      $(this).siblings('.auth-email').val($(this).val() + '@' + getTLDFromFQDN(host));
    } else if ( $(this).hasClass('auth-email') ) {
      $(this).siblings('.auth-username').val(getUsernameFromEmail($(this).val()));
    }
  });
  $('form input.auth-username, form input.auth-email').bind('keydown', function(e) {
    if ( e.which == 13 ) { // Enter key
      e.preventDefault();
      return false;
    }
  });

  // Enable the user-friendly multiselect form element on the options page.
  $('#auth_settings_access_public_pages').multiSelect({
    selectableOptgroup: true,
    selectableHeader: '<div class="custom-header">Private Pages</div>',
    selectionHeader: '<div class="custom-header">Public Pages</div>',
  });

  // Switch to the first tab (or the tab indicated in the querystring).
  var tab = querystring( 'tab' );
  if ( tab.length > 0 && $.inArray( tab[0], [ 'access_lists', 'access', 'access_public', 'external', 'advanced' ] ) >= 0 ) {
    chooseTab( tab, animation_speed );
  } else {
    chooseTab( 'access_lists' );
  }

  // Hide/show multisite settings based on override checkbox.
  $('input[name="auth_settings[multisite_override]"]').change(function() {
    hide_multisite_settings_if_disabled();
  });
  hide_multisite_settings_if_disabled();

});


/**
 * Portions below from Bootstrap
 * http://getbootstrap.com/getting-started/#download
 */


/*!
 * Bootstrap v3.1.1 (http://getbootstrap.com)
 * Copyright 2011-2014 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 */

if (typeof jQuery === 'undefined') { throw new Error('Bootstrap\'s JavaScript requires jQuery') }

/* ========================================================================
 * Bootstrap: dropdown.js v3.1.1
 * http://getbootstrap.com/javascript/#dropdowns
 * ========================================================================
 * Copyright 2011-2014 Twitter, Inc.
 * Licensed under MIT (https://github.com/twbs/bootstrap/blob/master/LICENSE)
 * ======================================================================== */


+function ($) {
  'use strict';

  // DROPDOWN CLASS DEFINITION
  // =========================

  var backdrop = '.dropdown-backdrop'
  var toggle   = '[data-toggle=dropdown]'
  var Dropdown = function (element) {
    $(element).on('click.bs.dropdown', this.toggle)
  }

  Dropdown.prototype.toggle = function (e) {
    var $this = $(this)

    if ($this.is('.disabled, :disabled')) return

    var $parent  = getParent($this)
    var isActive = $parent.hasClass('open')

    clearMenus()

    if (!isActive) {
      if ('ontouchstart' in document.documentElement && !$parent.closest('.navbar-nav').length) {
        // if mobile we use a backdrop because click events don't delegate
        $('<div class="dropdown-backdrop"/>').insertAfter($(this)).on('click', clearMenus)
      }

      var relatedTarget = { relatedTarget: this }
      $parent.trigger(e = $.Event('show.bs.dropdown', relatedTarget))

      if (e.isDefaultPrevented()) return

      $parent
        .toggleClass('open')
        .trigger('shown.bs.dropdown', relatedTarget)

      $this.focus()
    }

    return false
  }

  Dropdown.prototype.keydown = function (e) {
    if (!/(38|40|27)/.test(e.keyCode)) return

    var $this = $(this)

    e.preventDefault()
    e.stopPropagation()

    if ($this.is('.disabled, :disabled')) return

    var $parent  = getParent($this)
    var isActive = $parent.hasClass('open')

    if (!isActive || (isActive && e.keyCode == 27)) {
      if (e.which == 27) $parent.find(toggle).focus()
      return $this.click()
    }

    var desc = ' li:not(.divider):visible a'
    var $items = $parent.find('[role=menu]' + desc + ', [role=listbox]' + desc)

    if (!$items.length) return

    var index = $items.index($items.filter(':focus'))

    if (e.keyCode == 38 && index > 0)                 index--                        // up
    if (e.keyCode == 40 && index < $items.length - 1) index++                        // down
    if (!~index)                                      index = 0

    $items.eq(index).focus()
  }

  function clearMenus(e) {
    $(backdrop).remove()
    $(toggle).each(function () {
      var $parent = getParent($(this))
      var relatedTarget = { relatedTarget: this }
      if (!$parent.hasClass('open')) return
      $parent.trigger(e = $.Event('hide.bs.dropdown', relatedTarget))
      if (e.isDefaultPrevented()) return
      $parent.removeClass('open').trigger('hidden.bs.dropdown', relatedTarget)
    })
  }

  function getParent($this) {
    var selector = $this.attr('data-target')

    if (!selector) {
      selector = $this.attr('href')
      selector = selector && /#[A-Za-z]/.test(selector) && selector.replace(/.*(?=#[^\s]*$)/, '') //strip for ie7
    }

    var $parent = selector && $(selector)

    return $parent && $parent.length ? $parent : $this.parent()
  }


  // DROPDOWN PLUGIN DEFINITION
  // ==========================

  var old = $.fn.dropdown

  $.fn.dropdown = function (option) {
    return this.each(function () {
      var $this = $(this)
      var data  = $this.data('bs.dropdown')

      if (!data) $this.data('bs.dropdown', (data = new Dropdown(this)))
      if (typeof option == 'string') data[option].call($this)
    })
  }

  $.fn.dropdown.Constructor = Dropdown


  // DROPDOWN NO CONFLICT
  // ====================

  $.fn.dropdown.noConflict = function () {
    $.fn.dropdown = old
    return this
  }


  // APPLY TO STANDARD DROPDOWN ELEMENTS
  // ===================================

  $(document)
    .on('click.bs.dropdown.data-api', clearMenus)
    .on('click.bs.dropdown.data-api', '.dropdown form', function (e) { e.stopPropagation() })
    .on('click.bs.dropdown.data-api', toggle, Dropdown.prototype.toggle)
    .on('keydown.bs.dropdown.data-api', toggle + ', [role=menu], [role=listbox]', Dropdown.prototype.keydown)

}(jQuery);
