module SanitizeUrl
	# We only want to dereference certain numerical character references:
	# numbers, letters, : and /
	def self.dereference_code?(decimal_code)
		(decimal_code >= 47 and decimal_code <= 58) or # Numbers
		(decimal_code >= 65 and decimal_code <= 90) or # Uppercase letters
		(decimal_code >= 97 and decimal_code <= 122)   # Lowercase letters
	end
	
	# Decode numeric character references to numbers and letters.
	# The purpose of this is to de-obfuscate malicious strings. Should be
	# transparent to UTF-8, as multi-byte chars should be split up and then
	# reassembled correctly in the output. The character codes for control
	# characters like & and ; cannot appear as part of multi-byte characters,
	# so there's no danger of interpreting part of a multi-byte char as
	# a control character.
	#
	# This is a module method so that it won't pollute the namespace into
	# which the module is mixed in.
	def self.decode_numeric_references(str)
		# Decimal code points, e.g. &#106; &#106 &#0000106; &#0000106
		result = str.gsub(/&#([a-fA-f0-9]+);?/) do |match|
			code = $1.to_i
			dereference_code?(code) ? code.chr : match
		end
		# Hex code points, e.g. &#x6A; &#x6A
		result.gsub(/&#[xX]([a-fA-f0-9]+);?/) do |match|
			code = $1.to_i(16)
			dereference_code?(code) ? code.chr : match
		end
	end
	
	def sanitize_url(url, options = {})
		raise(ArgumentError, 'options[:protocols] must be an array') if options.has_key?(:protocols) and !options[:protocols].is_a?(Array)
		options = {
			:replace_evil_with => '',
			:protocols => ['http', 'https', 'ftp', 'ftps', 'mailto', 'svn', 'svn+ssh', 'git']
		}.merge(options)
		# Decode numeric character references to deobsfuscate
		url = SanitizeUrl.decode_numeric_references(url)
		# Fix broken protocols
		protocol = nil
		url = url.sub(/^(([a-zA-Z\s]+)[\/:]+)/) do
			protocol = $2.downcase
			protocol + '://'
		end
		# If we didn't find anything resembling a protocol, then we need to prepend one.
		# We just use http, since it's the most likely suspect and there's no other way to guess
		unless protocol
			protocol = 'http'
			url = 'http://' + url
		end
		if options[:protocols].include?(protocol)
			url
		else
			options[:replace_evil_with]
		end
	end
end