// Add IP address to whitelist.
function lsa_add_ip(ip) {
  var shake_speed = 600;

  if ( jQuery.trim(ip) == '' )
    return false;

  add_btn.attr('disabled', 'disabled');

  // Check if the IP address being added already exists in the list.
  jQuery('#list_lsa_settings_access_ips input[type=text]').each(function() {
    if (this.value == ip) {
      jQuery(this).parent().effect('shake',shake_speed);
      add_btn.removeAttr('disabled');
      return false;
    }
  });

  jQuery.post(ajaxurl, { action: 'lsa_ip_check', 'ip_address': ip }, function(response) {
    if (response) { // failed checking ip
      jQuery('#newip').parent().effect('shake',shake_speed);
      add_btn.removeAttr('disabled');
      return false;
    } else { // succeeded checking ip
      jQuery('<li style="display: none;"><input type="text" name="lsa_settings[access_ips][]" value="' + ip + '" readonly="true" /> <input type="button" class="button" onclick="lsa_remove_ip(this);" value="Remove" /></div>').appendTo('#list_lsa_settings_access_ips').slideDown(250);
      // Reset the new ip textbox if we successfully added this ip
      if (ip == jQuery('#newip').val())
        jQuery('#newip').val('');
      jQuery('#addip').removeAttr('disabled');
      return true;
    }
  } );
}

// Remove IP address from whitelist.
function lsa_remove_ip(btnObj) {
  jQuery(btnObj).parent().slideUp(250,function(){ jQuery(this).remove(); });
}


var add_btn;
var animation_speed = 300;


jQuery(document).ready(function($){
  // hide and show relevant pieces
  add_btn = $('#addip');

  // Show and hide specific options on page load
  var lsa_settings_access_redirect_to_login = $('#radio_lsa_settings_access_redirect_to_login').closest('tr');
  var lsa_settings_access_redirect_to_url = $('#lsa_settings_access_redirect_to_url').closest('tr');
  var lsa_settings_access_redirect_to_message = $('#wp-lsa_settings_access_redirect_to_message-wrap').closest('tr');
  var lsa_settings_access_redirect_to_page = $('#lsa_settings_access_redirect_to_page').closest('tr');
  if (!$('#radio_lsa_settings_access_redirect_to_url').is(':checked'))
    lsa_settings_access_redirect_to_url.hide();
  if (!$('#radio_lsa_settings_access_redirect_to_message').is(':checked'))
    lsa_settings_access_redirect_to_message.hide();
  if (!$('#radio_lsa_settings_access_redirect_to_page').is(':checked'))
    lsa_settings_access_redirect_to_page.hide();

  // show and hide specific options based on "Handle unauthorized visitors" selection
  $('input[name="lsa_settings[access_redirect]"]').change(function(){
    if ($('#radio_lsa_settings_access_redirect_to_url').is(':checked'))
      lsa_settings_access_redirect_to_url.show();
    else
      lsa_settings_access_redirect_to_url.hide(animation_speed);

    if ($('#radio_lsa_settings_access_redirect_to_message').is(':checked'))
      lsa_settings_access_redirect_to_message.show();
    else
      lsa_settings_access_redirect_to_message.hide(animation_speed);

    if ($('#radio_lsa_settings_access_redirect_to_page').is(':checked'))
      lsa_settings_access_redirect_to_page.show();
    else
      lsa_settings_access_redirect_to_page.hide(animation_speed);
  });

  // Hide "Handle unauthorized visitors" option if access is granted to "Everyone"
  $('input[name="lsa_settings[access_restriction]"]').change(function(){
    if ($('#radio_lsa_settings_access_restriction_everyone').is(':checked'))
      lsa_settings_access_redirect_to_login.hide();
    else
      lsa_settings_access_redirect_to_login.show(animation_speed);
  });
});
