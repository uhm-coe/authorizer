var animation_speed = 300;
var shake_speed = 600;



// Switch between option tabs.
function chooseTab(listName) {
  // default to the access list tab
  listName = typeof listName !== 'undefined' ? listName : 'access_list';

  // Hide all tab content, then show selected tab content
  jQuery('div.section_info, div.section_info + table').hide();
  jQuery('#section_info_' + listName + ', #section_info_' + listName + ' + table').show();

  // Set active tab
  jQuery('.nav-tab-wrapper a').removeClass('nav-tab-active');
  jQuery('a.nav-tab-' + listName).addClass('nav-tab-active');
}

// Add user to list (list = blocked or approved).
function auth_add_user(caller, list) {
  // default to the approved list
  list = typeof list !== 'undefined' ? list : 'approved';

  var username = jQuery(caller).parent().find('.auth-username');
  var email = jQuery(caller).parent().find('.auth-email');
  var role = jQuery(caller).parent().find('.auth-role');
  var nextId = jQuery('#list_auth_settings_access_users_' + list + ' li').length;
  var validated = true;

  if (jQuery.trim(username.val()) == '')
    return false;

  jQuery(caller).attr('disabled', 'disabled');

  // Check if the course being added already exists in the list.
  if (validated) {
    jQuery('#list_auth_settings_access_users_' + list + ' input.auth-username').each(function() {
      if (this.value == username.val()) {
        validated = false;
        jQuery(this).parent().effect('shake', shake_speed);
        jQuery(caller).removeAttr('disabled');
        return false;
      }
    });
  }

  // Check if the name being added already exists in the list.
  if (validated) {
    jQuery('#list_auth_settings_access_users_' + list + ' input.auth-email').each(function() {
      if (this.value == email.val()) {
        validated = false;
        jQuery(this).parent().effect('shake', shake_speed);
        jQuery(caller).removeAttr('disabled');
        return false;
      }
    });
  }

  if (validated) {
    // Add the new item.
    jQuery(' \
      <li id="new_user_' + nextId + '" style="display: none;"> \
        <input type="text" name="auth_settings[access_users_' + list + '][' + nextId + '][username]" value="' + username.val() + '" readonly="true" class="auth-username" /> \
        <input type="text" id="auth_settings_access_users_' + list + '_' + nextId + '" name="auth_settings[access_users_' + list + '][' + nextId + '][email]" value="' + email.val() + '" readonly="true" class="auth-email" /> \
        <select name="auth_settings[access_users_' + list + '][' + nextId + '][role]" class="auth-role" onchange="save_auth_settings_access(this);"> \
        </select> \
        <input type="text" name="auth_settings[access_users_' + list + '][' + nextId + '][date_added]" value="' + getShortDate() + '" readonly="true" class="auth-date-added" /> \
        <input type="button" class="button" onclick="auth_ignore_user(this);" value="&times;" /> \
        <span class="spinner"></span> \
      </li> \
    ').appendTo('#list_auth_settings_access_users_' + list + '').slideDown(250);

    // Populate the role dropdown in the new element. Because clone() doesn't
    // save selected state on select elements, set that too.
    jQuery('option', role).clone().appendTo('#new_user_' + nextId + ' .auth-role');
    jQuery('#new_user_' + nextId + ' .auth-role').val(role.val());

    // Remove the 'empty list' item if it exists.
    jQuery('#list_auth_settings_access_users_' + list + ' li.auth-empty').remove();

    // Reset the new user textboxes
    username.val('');
    email.val('');
    jQuery(caller).removeAttr('disabled');

    // Update the options in the database with this change.
    save_auth_settings_access(caller);

    return true;
  }
}

// Remove user from list.
function auth_ignore_user(caller, listName) {
  // Show an 'empty list' message if we're deleting the last item
  listName = typeof listName !== 'undefined' ? listName : '';
  var list = jQuery(caller).parent().parent();
  if (jQuery('li', list).length <= 1) {
    jQuery(list).append('<li class="auth-empty"><em>No ' + listName + ' users</em></li>');
  }

  jQuery(caller).parent().slideUp(250,function() {
    // Remove the list item.
    jQuery(this).remove();

    // Update the options in the database with this change.
    save_auth_settings_access(caller);
  });
}



// Save options from dashboard widget.
function save_auth_settings_access(caller) {
  jQuery(caller).attr('disabled', 'disabled');
  jQuery(caller).after('<span class="spinner"></span>');
  jQuery('form .spinner').show();

  var access_restriction = jQuery('form input[name="auth_settings[access_restriction]"]:checked').val();

  var access_users_pending = new Object();
  jQuery('#list_auth_settings_access_users_pending li').each(function(index) {
    var user = new Object();
    user['username'] = jQuery('.auth-username', this).val();
    user['email'] = jQuery('.auth-email', this).val();
    user['role'] = jQuery('.auth-role', this).val();
    access_users_pending[index] = user;
  });

  var access_users_approved = new Object();
  jQuery('#list_auth_settings_access_users_approved li').each(function(index) {
    var user = new Object();
    user['username'] = jQuery('.auth-username', this).val();
    user['email'] = jQuery('.auth-email', this).val();
    user['role'] = jQuery('.auth-role', this).val();
    user['date_added'] = jQuery('.auth-date-added', this).val();
    access_users_approved[index] = user;
  });

  var access_users_blocked = new Object();
  jQuery('#list_auth_settings_access_users_blocked li').each(function(index) {
    var user = new Object();
    user['username'] = jQuery('.auth-username', this).val();
    user['email'] = jQuery('.auth-email', this).val();
    user['role'] = jQuery('.auth-role', this).val();
    user['date_added'] = jQuery('.auth-date-added', this).val();
    access_users_blocked[index] = user;
  });

  var nonce_save_auth_settings_access = jQuery('#nonce_save_auth_settings_access').val();

  jQuery.post(ajaxurl, {
    action: 'save_auth_dashboard_widget',
    'access_restriction': access_restriction,
    'access_users_pending': access_users_pending,
    'access_users_approved': access_users_approved,
    'access_users_blocked': access_users_blocked,
    'nonce_save_auth_settings_access': nonce_save_auth_settings_access,
  }, function(response) {
    jQuery('form .spinner').remove();
    jQuery(caller).removeAttr('disabled');
    if (response==0) { // failed
      return false;
    } else { // succeeded
      return true;
    }
  });
}



// Helper function to grab a querystring param value by name
function getParameterByName(needle, haystack) {
  needle = needle.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
  var regexS = "[\\?&]" + needle + "=([^&#]*)";
  var regex = new RegExp(regexS);
  var results = regex.exec(haystack);
  if(results == null)
    return "";
  else
    return decodeURIComponent(results[1].replace(/\+/g, " "));
}

// Helper function to generate a random string
function getRandomId() {
  var text = "";
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (var i=0; i < 5; i++)
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  return text;
}

// Helper function to return a short date (e.g., Jul 2013) for today's date
function getShortDate(date) {
  date = typeof date !== 'undefined' ? date : new Date();
  var month = '';
  switch (date.getMonth()) {
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
function getTLDFromFQDN(fqdn) {
  fqdn = typeof fqdn !== 'undefined' ? fqdn : '';
  var matches = fqdn.match(/[^.]*\.[^.]*$/);
  return matches.length > 0 ? matches[0] : '';
}

// Helper function to get the username from an email address
function getUsernameFromEmail(email) {
  email = typeof email !== 'undefined' ? email : '';
  return email.split("@")[0];
}


jQuery(document).ready(function($){
  // Show and hide specific options on page load
  var auth_settings_access_redirect_to_login = $('#radio_auth_settings_access_redirect_to_login').closest('tr');
  var auth_settings_access_redirect_to_url = $('#auth_settings_access_redirect_to_url').closest('tr');
  var auth_settings_access_redirect_to_message = $('#wp-auth_settings_access_redirect_to_message-wrap').closest('tr');
  var auth_settings_access_users_pending = $('#list_auth_settings_access_users_pending').closest('tr');
  var auth_settings_access_users_approved = $('#list_auth_settings_access_users_approved').closest('tr');
  var auth_settings_access_users_blocked = $('#list_auth_settings_access_users_blocked').closest('tr');
  var auth_settings_access_role_receive_pending_emails = $('#auth_settings_access_role_receive_pending_emails').closest('tr');
  var auth_settings_access_pending_redirect_to_message = $('#wp-auth_settings_access_pending_redirect_to_message-wrap').closest('tr');
  var auth_settings_access_public_pages = $('#auth_settings_access_public_pages').closest('tr');

  // Wrap the th and td in the rows above so we can animate their heights (can't animate tr heights with jquery)
  $('th, td', auth_settings_access_redirect_to_login).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_redirect_to_url).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_redirect_to_message).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_users_pending).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_users_approved).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_users_blocked).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_role_receive_pending_emails).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_pending_redirect_to_message).wrapInner('<div class="animated_wrapper" />');
  $('th, td', auth_settings_access_public_pages).wrapInner('<div class="animated_wrapper" />');

  // If we're viewing the dashboard widget, reset a couple of the relevant
  // option variables (since they're aren't nested in table rows).
  if ($('#auth_dashboard_widget').length) {
    auth_settings_access_users_pending = $('#list_auth_settings_access_users_pending').closest('div');
    auth_settings_access_users_approved = $('#list_auth_settings_access_users_approved').closest('div');
    auth_settings_access_users_blocked = $('#list_auth_settings_access_users_blocked').closest('div');
    $(auth_settings_access_users_pending).wrapInner('<div class="animated_wrapper" />');
    $(auth_settings_access_users_approved).wrapInner('<div class="animated_wrapper" />');
    $(auth_settings_access_users_blocked).wrapInner('<div class="animated_wrapper" />');

    // Remove the helper link, since there are no tabs on the dashboard widget
    $('#dashboard_link_approved_users').contents().unwrap();
  }

  if (!$('#radio_auth_settings_access_redirect_to_url').is(':checked')) {
    $('div.animated_wrapper', auth_settings_access_redirect_to_url).hide();
  }
  if (!$('#radio_auth_settings_access_redirect_to_message').is(':checked')) {
    $('div.animated_wrapper', auth_settings_access_redirect_to_message).hide();
  }

  if (!$('#radio_auth_settings_access_restriction_approved_users').is(':checked')) {
    $('div.animated_wrapper', auth_settings_access_users_pending).hide();
    $('div.animated_wrapper', auth_settings_access_users_approved).hide();
    $('div.animated_wrapper', auth_settings_access_users_blocked).hide();
    $('div.animated_wrapper', auth_settings_access_role_receive_pending_emails).hide();
    $('div.animated_wrapper', auth_settings_access_pending_redirect_to_message).hide();
  }

  // show and hide specific options based on "Handle unauthorized visitors" selection
  $('input[name="auth_settings[access_redirect]"]').change(function() {
    if ($('#radio_auth_settings_access_redirect_to_url').is(':checked')) {
      $('div.animated_wrapper', auth_settings_access_redirect_to_url).slideDown(animation_speed);
    } else {
      $('div.animated_wrapper', auth_settings_access_redirect_to_url).slideUp(animation_speed);
    }
    if ($('#radio_auth_settings_access_redirect_to_message').is(':checked')) {
      $('div.animated_wrapper', auth_settings_access_redirect_to_message).slideDown(animation_speed);
    } else {
      $('div.animated_wrapper', auth_settings_access_redirect_to_message).slideUp(animation_speed);
    }
  });

  // Hide "Handle unauthorized visitors" option if access is granted to "Everyone"
  $('input[name="auth_settings[access_restriction]"]').change(function(){
    if ($('#radio_auth_settings_access_restriction_everyone').is(':checked')) {
      $('div.animated_wrapper', auth_settings_access_redirect_to_login).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_redirect_to_url).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_redirect_to_message).slideUp(animation_speed);
      $('div.animated_wrapper', auth_settings_access_public_pages).slideUp(animation_speed);
    } else {
      $('div.animated_wrapper', auth_settings_access_redirect_to_login).slideDown(animation_speed);
      $('div.animated_wrapper', auth_settings_access_public_pages).slideDown(animation_speed);
      $('input[name="auth_settings[access_redirect]"]').trigger('change');
    }
  
    // Hide user whitelist unless "Only specific students below" is checked
    if (!$('#radio_auth_settings_access_restriction_approved_users').is(':checked')) {
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

  // List management function: pressing enter in the username, email, or role
  // field adds the user to the list. Additionally, if the email field is
  // blank, it gets constructed from the username field (and vice versa).
  $('form input.auth-username, form input.auth-email, form select.auth-role').bind('keyup', function(e) {
    if (e.which == 13) { // Enter key
      $(this).siblings('input[type=button]').trigger('click');
      return false;
    } else if ($(this).hasClass('auth-username')) {
      $(this).siblings('.auth-email').val($(this).val() + '@' + getTLDFromFQDN($('#auth_settings_cas_host').val()));
    } else if ($(this).hasClass('auth-email')) {
      $(this).siblings('.auth-username').val(getUsernameFromEmail($(this).val()));
    }
  });
  $('form input.auth-username, form input.auth-email').bind('keydown', function(e) {
    if (e.which == 13) { // Enter key
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

  // Switch to the first tab.
  chooseTab('access_lists');

});
