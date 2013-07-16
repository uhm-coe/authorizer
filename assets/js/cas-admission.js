var add_btn_course;
var animation_speed = 300;
var shake_speed = 600;


// Add course to whitelist.
function cas_add_course(course) {
  if (jQuery.trim(course) == '')
    return false;

  add_btn_course.attr('disabled', 'disabled');

  // Check if the course being added already exists in the list.
  jQuery('#list_cas_settings_access_courses input[type=text]').each(function() {
    if (this.value == course) {
      jQuery(this).parent().effect('shake',shake_speed);
      add_btn_course.removeAttr('disabled');
      return false;
    }
  });

  jQuery('#newcourse').css('background', 'url(/wp-admin/images/loading.gif) no-repeat 253px 2px');
  jQuery.post(ajaxurl, {
    action: 'cas_course_check', 
    'sakai_site_id': course, 
    'sakai_base_url': jQuery('#cas_settings_sakai_base_url').val() 
  }, function(response) {
    jQuery('#newcourse').css('background', 'none');
    if (response==0) { // failed checking course
      jQuery('#newcourse').parent().effect('shake',shake_speed);
      add_btn_course.removeAttr('disabled');
      return false;
    } else { // succeeded checking course
      jQuery('<li style="display: none;"><input type="text" name="cas_settings[access_courses][]" value="' + course + '" readonly="true" style="width:275px;" /> <input type="button" class="button" onclick="cas_remove_course(this);" value="&minus;" /> <span class="description">' + response + '</span></div>').appendTo('#list_cas_settings_access_courses').slideDown(250);
      // Reset the new course textbox if we successfully added this course
      if (course == jQuery('#newcourse').val())
        jQuery('#newcourse').val('');
      jQuery('#addcourse').removeAttr('disabled');
      return true;
    }
  });
}
// Remove course from whitelist.
function cas_remove_course(btnObj) {
  jQuery(btnObj).parent().slideUp(250,function(){ jQuery(this).remove(); });
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


jQuery(document).ready(function($){
  // hide and show relevant pieces
  add_btn_course = $('#addcourse');

  // Show and hide specific options on page load
  var cas_settings_access_redirect_to_login = $('#radio_cas_settings_access_redirect_to_login').closest('tr');
  var cas_settings_access_redirect_to_url = $('#cas_settings_access_redirect_to_url').closest('tr');
  var cas_settings_access_redirect_to_message = $('#wp-cas_settings_access_redirect_to_message-wrap').closest('tr');
  var cas_settings_access_redirect_to_page = $('#cas_settings_access_redirect_to_page').closest('tr');
  var cas_settings_users_pending = $('#list_cas_settings_users_pending').closest('tr');
  var cas_settings_users_approved = $('#list_cas_settings_users_approved').closest('tr');
  var cas_settings_users_blocked = $('#list_cas_settings_users_blocked').closest('tr');

  // Wrap the th and td in the rows above so we can animate their heights (can't animate tr heights with jquery)
  $('th, td', cas_settings_access_redirect_to_login).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_redirect_to_url).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_redirect_to_message).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_access_redirect_to_page).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_users_pending).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_users_approved).wrapInner('<div class="animated_wrapper" />');
  $('th, td', cas_settings_users_blocked).wrapInner('<div class="animated_wrapper" />');

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
    $('div.animated_wrapper', cas_settings_users_blocked).hide();
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
      $('div.animated_wrapper', cas_settings_users_blocked).slideUp(animation_speed);
    } else {
      $('div.animated_wrapper', cas_settings_users_pending).slideDown(animation_speed);
      $('div.animated_wrapper', cas_settings_users_approved).slideDown(animation_speed);
      $('div.animated_wrapper', cas_settings_users_blocked).slideDown(animation_speed);
    }
  });

});
