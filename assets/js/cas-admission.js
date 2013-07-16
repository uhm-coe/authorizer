var animation_speed = 300;
var shake_speed = 600;



// Add user to blacklist.
function cas_block_user(caller) {
  var username = jQuery(caller).parent().find('.cas-username');
  var email = jQuery(caller).parent().find('.cas-email');
  var role = jQuery(caller).parent().find('.cas-role');
  var nextId = jQuery('#list_cas_settings_access_users_blocked li').length;
  var validated = true;

  if (jQuery.trim(username.val()) == '')
    return false;

  jQuery(caller).attr('disabled', 'disabled');
  jQuery(caller).append('<img src="/wp-admin/images/loading.gif" style="vertical-align: middle; padding-left: 4px;" id="cas_loading" />');

  // Check if the course being added already exists in the list.
  jQuery('#list_cas_settings_access_users_blocked input.cas-username').each(function() {
    if (this.value == username.val()) {
      jQuery(this).parent().effect('shake',shake_speed);
      jQuery(caller).removeAttr('disabled');
      jQuery('#cas_loading').remove();
      validated = false;
    }
  });

  // Check if the course being added already exists in the list.
  jQuery('#list_cas_settings_access_users_blocked input.cas-email').each(function() {
    if (this.value == email.val()) {
      jQuery(this).parent().effect('shake',shake_speed);
      jQuery(caller).removeAttr('disabled');
      jQuery('#cas_loading').remove();
      validated = false;
    }
  });

  if (validated) {
    jQuery(' \
      <li style="display: none;"> \
        <input type="text" name="cas_settings[access_users_blocked][' + nextId + '][username]" value="' + username.val() + '" readonly="true" style="width: 80px;" class="cas-username" /> \
        <input type="text" id="cas_settings_access_users_blocked_' + nextId + '" name="cas_settings[access_users_blocked][' + nextId + '][email]" value="' + email.val() + '" readonly="true" style="width: 180px;" class="cas-email" /> \
        <select name="cas_settings[access_users_blocked][' + nextId + '][role]" class="cas-role"> \
          <option value="' + role.val() + '" selected="selected">' + role.val().charAt(0).toUpperCase() + role.val().slice(1) + '</option> \
        </select> \
        <input type="text" name="cas_settings[access_users_blocked][' + nextId + '][date_added]" value="' + getShortDate() + '" readonly="true" style="width: 65px;" class="cas-date-added" /> \
        <input type="button" class="button" onclick="cas_ignore_user(this);" value="x" /> \
      </li> \
    ').appendTo('#list_cas_settings_access_users_blocked').slideDown(250);

    // Reset the new blocked user textboxes
    username.val('');
    email.val('');
    jQuery(caller).removeAttr('disabled');
    jQuery('#cas_loading').remove();
    return true;
  }
}
// Remove user from blacklist.
function cas_ignore_user(caller) {
  jQuery(caller).parent().slideUp(250,function(){ jQuery(this).remove(); });
}



// Save options from dashboard widget.
function save_cas_settings_access(caller) {
  jQuery('#cas_settings_access_form .spinner').show();
  jQuery(caller).attr('disabled', 'disabled');

  var access_restriction = jQuery('#cas_settings_access_form input[name="cas_settings[access_restriction]"]:checked').val();
  var access_courses = new Array();
  jQuery('#cas_settings_access_form input[name="cas_settings[access_courses][]"]').each(function() {
    access_courses.push(jQuery(this).val());
  });
  var nonce_save_cas_settings_access = jQuery('#nonce_save_cas_settings_access').val();

  jQuery.post(ajaxurl, {
    action: 'save_sakai_dashboard_widget',
    'access_restriction': access_restriction,
    'access_courses': access_courses,
    'nonce_save_cas_settings_access': nonce_save_cas_settings_access,
  }, function(response) {
    jQuery('#cas_settings_access_form .spinner').hide();
    jQuery(caller).removeAttr('disabled');
    if (response==0) { // failed checking course
      return false;
    } else { // succeeded checking course
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


jQuery(document).ready(function($){
  // Show and hide specific options on page load
  var cas_settings_access_redirect_to_login = $('#radio_cas_settings_access_redirect_to_login').closest('tr');
  var cas_settings_access_redirect_to_url = $('#cas_settings_access_redirect_to_url').closest('tr');
  var cas_settings_access_redirect_to_message = $('#wp-cas_settings_access_redirect_to_message-wrap').closest('tr');
  var cas_settings_access_redirect_to_page = $('#cas_settings_access_redirect_to_page').closest('tr');
  var cas_settings_users_pending = $('#list_cas_settings_users_pending').closest('tr');
  var cas_settings_users_approved = $('#list_cas_settings_users_approved').closest('tr');
  var cas_settings_access_users_blocked = $('#list_cas_settings_access_users_blocked').closest('tr');

  // Wrap the th and td in the rows above so we can animate their heights (can't animate tr heights with jquery)
  $('th, td', cas_settings_access_redirect_to_login).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_redirect_to_url).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_redirect_to_message).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_redirect_to_page).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_users_pending).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_users_approved).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_users_blocked).wrapInner('<div class="animated_wrapper" />');

  if (!$('#radio_cas_settings_access_redirect_to_url').is(':checked')) {
    $('div.animated_wrapper', cas_settings_access_redirect_to_url).hide();
  }
  if (!$('#radio_cas_settings_access_redirect_to_message').is(':checked')) {
    $('div.animated_wrapper', cas_settings_access_redirect_to_message).hide();
  }
  if (!$('#radio_cas_settings_access_redirect_to_page').is(':checked')) {
    $('div.animated_wrapper', cas_settings_access_redirect_to_page).hide();
  }

  if (!$('#radio_cas_settings_access_restriction_approved_cas').is(':checked')) {
    $('div.animated_wrapper', cas_settings_users_pending).hide();
    $('div.animated_wrapper', cas_settings_users_approved).hide();
    $('div.animated_wrapper', cas_settings_access_users_blocked).hide();
  }

  // show and hide specific options based on "Handle unauthorized visitors" selection
  $('input[name="cas_settings[access_redirect]"]').change(function() {
    if ($('#radio_cas_settings_access_redirect_to_url').is(':checked')) {
      $('div.animated_wrapper', cas_settings_access_redirect_to_url).slideDown(animation_speed);
    } else {
      $('div.animated_wrapper', cas_settings_access_redirect_to_url).slideUp(animation_speed);
    }
    if ($('#radio_cas_settings_access_redirect_to_message').is(':checked')) {
      $('div.animated_wrapper', cas_settings_access_redirect_to_message).slideDown(animation_speed);
    } else {
      $('div.animated_wrapper', cas_settings_access_redirect_to_message).slideUp(animation_speed);
    }
    if ($('#radio_cas_settings_access_redirect_to_page').is(':checked')) {
      $('div.animated_wrapper', cas_settings_access_redirect_to_page).slideDown(animation_speed);
    } else {
      $('div.animated_wrapper', cas_settings_access_redirect_to_page).slideUp(animation_speed);
    }
  });

  // Hide "Handle unauthorized visitors" option if access is granted to "Everyone"
  $('input[name="cas_settings[access_restriction]"]').change(function(){
    if ($('#radio_cas_settings_access_restriction_everyone').is(':checked')) {
      $('div.animated_wrapper', cas_settings_access_redirect_to_login).slideUp(animation_speed);
      $('div.animated_wrapper', cas_settings_access_redirect_to_url).slideUp(animation_speed);
      $('div.animated_wrapper', cas_settings_access_redirect_to_message).slideUp(animation_speed);
      $('div.animated_wrapper', cas_settings_access_redirect_to_page).slideUp(animation_speed);
    } else {
      $('div.animated_wrapper', cas_settings_access_redirect_to_login).slideDown(animation_speed);
      $('input[name="cas_settings[access_redirect]"]').trigger('change');
    }
  
    // Hide user whitelist unless "Only specific students below" is checked
    if (!$('#radio_cas_settings_access_restriction_approved_cas').is(':checked')) {
      $('div.animated_wrapper', cas_settings_users_pending).slideUp(animation_speed);
      $('div.animated_wrapper', cas_settings_users_approved).slideUp(animation_speed);
      $('div.animated_wrapper', cas_settings_access_users_blocked).slideUp(animation_speed);
    } else {
      $('div.animated_wrapper', cas_settings_users_pending).slideDown(animation_speed);
      $('div.animated_wrapper', cas_settings_users_approved).slideDown(animation_speed);
      $('div.animated_wrapper', cas_settings_access_users_blocked).slideDown(animation_speed);
    }
  });

});
