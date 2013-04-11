=== LDAP Sakai Authorization ===
Contributors: figureone
Tags: ldap, authentication, authorization, sakai, education, laulima
Requires at least: 3.0.1
Tested up to: 3.5
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

LDAP Sakai Authorization restricts access to students enrolled in university courses, using LDAP for authentication and Sakai for course rosters.

== Description ==

*LDAP Sakai Authorization* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It replaces the default WordPress login/authorization system with one relying on an LDAP server. Further, it communicates with a Sakai-based course management system (e.g., Laulima at the University of Hawai'i) to retrieve course rosters that it can use to restrict access to only students enrolled in a specific course.

*LDAP Sakai Authorization* requires the following:

* **LDAP server** (plugin needs the host, search base, directory user and password);
* **Sakai-based CMS** (plugin needs the base URL).

*LDAP Sakai Authorization* provides the following options:

* **Authentication**: Local (no LDAP); Local first, then LDAP; LDAP-only (except for admins);
* **Access restriction**: Everyone (no restriction); University members; Specific course(s).

== Installation ==

1. Upload the `ldap-sakai-auth` directory to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Specify your server details in the 'Settings' menu in WordPress

== Frequently Asked Questions ==

= Where is this plugin used? =

The [University of Hawai'i][uh], which stores student, faculty, and staff directory information in LDAP, and runs a [Sakai][sakai]-based course management system called [Laulima][laulima].

[uh]: http://hawaii.edu/
[sakai]: http://www.sakaiproject.org/
[laulima]: https://laulima.hawaii.edu/

== Screenshots ==

1. Options screen.

== Changelog ==

= 1.0 =
* First stable release.

= 0.1 =
* Initial development build.
* Wed Apr 10, 2013

== Upgrade Notice ==

= 1.0 =
Upgrade now to get the latest features.
