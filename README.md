openam-wordpress-plugin
=======================

Wordpress plugin to authenticate using OpenAM

=== Plugin Name ===
Contributors: forgerock1
Donate link: http://www.forgerock.org/
Tags: OpenAM, Authentication, REST, OpenAM 11.0.1, OpenAM 12.0, Wordpress 3.9
Requires at least: 3.9
Tested up to: 3.9.2
Stable tag: 0.6
License: CDDLv1.0
License URI: http://forgerock.org/projects/cddlv1-0/

Integrate Wordpress Authentication with OpenAM. Authenticates directly from the Wordpress login screen, without redirection. Implements SSO if there is already a session going on with OpenAM. Lightweight implementation using REST.

== Description ==
Integrate Wordpress Authentication with OpenAM without the need of a Policy Agent. if the authentication module or service chain in OpenAM requires user and password only, then it authenticates directly from the Wordpress login screen, i.e. no redirect to OpenAM needed. If the authentication module or service chain requires additional credentials than user/password, then it can redirect to the OpenAM login page. Implements SSO if there is already a session set up with OpenAM. Lightweight implementation using REST.

It looks for a session cookie in the domain where the WordPress is installed, if there is no such session cookie, then it will require to authenticate. Once the authentication has taken place, it will set the session in the cookie that you have configured in the plug-in (this is usually the same cookie as the one the OpenAM is using). 

We have implemented this plugin keeping in mind that the previous plugins to use OpenSSO have not evolved, hence have become obsolete or unusable with the newest version of Wordpress. Also this plugin takes advantage of the REST interface in OpenAM and makes it lightweight.  

No Policy Agent is needed in the server where Wordpress is running.

**Contributing**
The easiest way to contribute to this plugin is to submit a GitHub pull request. Here's the repo:
https://github.com/openam-wordpress-plugin

Version 0.5 
First drop
Implements Authentication and SSO with OpenAM.
Version 0.6
Enhanced version


== Installation ==

1. Upload `openam-wordpress-plugin` directory to the `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. As a Wordpress administrator, of to the page 'Settings'>'OpenAM-REST Plugin' and configure your OpenAM parameters

== Frequently Asked Questions ==




== Screenshots ==






== Changelog ==

= 0.5 =
* Initial drop

= 0.6 =
* A more advanced version than the initial drop. 
* Realm, Module, Service Chain are supported
* Supports also redirect to OpenAM, if needed. 
* Optional global logout configurable

== Upgrade Notice ==
