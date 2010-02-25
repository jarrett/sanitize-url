sanitize-url
============

This gem provides a module called `SanitizeUrl`, which you can mix-in anywhere you like. It provides a single method: `sanitize_url`, which accepts a URL and returns one with JavaScript removed and `http://` prepended if necessary. It also fixes some common variations of broken protocols at the beginning of the string.

Why do you need this? Because attackers can sneak JavaScript into URLs, and some browsers may execute it. Say, for example, you have a web app that lets users post links. If you don't sanitize the URLs, you may have a cross-site-scripting vulnerability on your hands. More commonly, well-intentioned users will type URLs without prepending a protocol. If you render these URLs as-in your links, the browser will interpret them as links within your own site, e.g. `http://your-site.com/www.site-they-linked-to.com`.

Basic Usage
===========

	require 'rubygems'
	require 'sanitize-url'
	
	include SanitizeUrl
	
	sanitize_url('www.example.com')

Advanced
========

This gem uses a whitelist approach, killing any protocols that aren't in the list. This should block `javascript:` and `data:` URLs, both of which can be used for XSS. The default list of allowed protocols is:

	http://
	https://
	ftp://
	ftps://
	mailto://
	svn://
	svn+ssh://
	git://

You can pass in your own whitelist like this:

	sanitize_url('http://example.com', :protocols => ['http', 'https'])

If `sanitize_url` receives a URL with a forbidden protocol, it wipes out the entire URL and returns a blank string. You can override this behavior and have it return a string of your choosing like this:

	sanitize_url('javascript:alert("XSS")', :replace_evil_with => 'my replacement')
	# => 'my replacement'

See the spec/sanitize_url_spec.rb for some examples of the how this gem transforms URLs.

Installation
============

	gem install sanitize-url

If that doesn't work, it's probably because the gem is hosted on Gemcutter, and your computer doesn't know about Gemcutter yet. To fix that:

	gem install gemcutter
	gem tumble

Bug Reports
===========

Since this is a security-related gem, you'll rack up mad karma by reporting a bug. If you find a way to sneak executable JavaScript (or any other form of evil) past the filter, please send me a message on GitHub:

http://github.com/inbox/new/jarrett

For most projects, I prefer that people use GitHub's issue tracker. But given the sensitive nature of security vulnerabilities, I prefer private messages for this one.

== Copyright

Copyright (c) 2010 Jarrett Colby. See LICENSE for details.