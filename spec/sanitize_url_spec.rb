require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe SanitizeUrl do
	include SanitizeUrl
	
	describe '#sanitize_url' do
		it 'replaces JavaScript URLs with options[:replace_evil_with]' do
			urls = [
				'javascript:alert("1");',
				'javascript//:alert("2");',
				'javascript://alert("3");',
				'javascript/:/alert("4");',
				'j a v a script:alert("5");',
				' javascript:alert("6");',
				'JavaScript:alert("7");',
				"java\nscript:alert(\"8\");",
				"java\rscript:alert(\"9\");"
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		it 'replaces data: URLs with options[:replace_evil_with]' do
			urls = [
				'data:text/html;base64,PHNjcmlwdD5hbGVydCgnMScpPC9zY3JpcHQ+',
				'data://text/html;base64,PHNjcmlwdD5hbGVydCgnMicpPC9zY3JpcHQ+',
				'data//:text/html;base64,PHNjcmlwdD5hbGVydCgnMycpPC9zY3JpcHQ+',
				'data/:/text/html;base64,PHNjcmlwdD5hbGVydCgnNCcpPC9zY3JpcHQ+',
				' data:text/html;base64,PHNjcmlwdD5hbGVydCgnNScpPC9zY3JpcHQ+',
				'da ta:text/html;base64,PHNjcmlwdD5hbGVydCgnNicpPC9zY3JpcHQ+',
				'Data:text/html;base64,PHNjcmlwdD5hbGVydCgnNycpPC9zY3JpcHQ+',
				"da\nta:text/html;base64,PHNjcmlwdD5hbGVydCgnOCcpPC9zY3JpcHQ+",
				"da\rta:text/html;base64,PHNjcmlwdD5hbGVydCgnOScpPC9zY3JpcHQ+",
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		context 'with :protocols whitelist' do
			it 'kills anything not on the list' do
				[
					'https://example.com',
					'https:example.com',
					'ftp://example.com',
					'ftp:example.com',
					'data://example.com',
					'data:example.com',
					'javascript://example.com',
					'javascript:example.com',
				].each do |evil_url|
					sanitize_url(evil_url, :protocols => ['http'], :replace_evil_with => 'replaced')
				end
			end
			
			it 'allows anything on the list' do
				[
					'http://example.com',
					'https://example.com'
				].each do |good_url|
					sanitize_url(good_url, :protocols => ['http', 'https']).should == good_url
				end
			end
		end
		
		it 'prepends http:// if no protocol is given' do
			sanitize_url('www.example.com').should == 'http://www.example.com'
		end
		
		it 'replaces evil URLs that are encoded with numerical character references' do
			[
				'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#49;&#39;&#41;',
				'&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x32;&#x27;&#x29;'
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		it 'fixes common mistakes in the protocol' do
			sanitize_url('http//www.example.com').should == 'http://www.example.com'
			sanitize_url('http/www.example.com').should == 'http://www.example.com'
			sanitize_url('http:www.example.com').should == 'http://www.example.com'
			sanitize_url('http:/www.example.com').should == 'http://www.example.com'
			sanitize_url('http//:www.example.com').should == 'http://www.example.com'
		end
		
		it 'does not try to fix broken protocols after the start of the string' do
			sanitize_url('http://example.com/http/foo').should == 'http://example.com/http/foo'
		end
		
		it 'does not prepend an extra http:// if a valid protocol is given' do
			sanitize_url('http://www.example.com').should == 'http://www.example.com'
			sanitize_url('https://www.example.com').should == 'https://www.example.com'
			sanitize_url('ftp://www.example.com').should == 'ftp://www.example.com'
		end
	end
	
	describe '.decode_numeric_references' do
		it 'decodes numbers' do
			(0..9).each do |digit|
				# Digit code points start at decimal 48
				SanitizeUrl.decode_numeric_references('&#' + (48 + digit).to_s + ';').should == digit.to_s
			end
		end
		
		it 'decodes lowercase letters' do
			# Lowercase code point range is 97-122
			(97..122).each do |code_point|
				SanitizeUrl.decode_numeric_references('&#' + code_point.to_s + ';').should == code_point.chr
			end
		end
		
		it 'decodes uppercase letters' do
			# Uppercase code point range is 65-90
			(65..90).each do |code_point|
				SanitizeUrl.decode_numeric_references('&#' + code_point.to_s + ';').should == code_point.chr
			end
		end
		
		it 'decodes forward slashes' do
			SanitizeUrl.decode_numeric_references('&#47').should == '/'
		end
		
		it 'decodes colons' do
			SanitizeUrl.decode_numeric_references('&#58').should == ':'
		end
		
		it 'does not decode special characters other than forward slashes and colons' do
			# Anything between 0 and 127 excluding 48-57, 65-90, and 97-122
			((0..46).to_a + (59..64).to_a + (91..96).to_a + (123..127).to_a).each do |code_point|
				reference = '&#' + code_point.to_s + ';'
				SanitizeUrl.decode_numeric_references(reference).should == reference
			end
		end
		
		it 'does not decode references to characters outside the ASCII range' do
			# Hebrew Alef as a Unicode code point, in hex and decimal
			SanitizeUrl.decode_numeric_references('&#x05D0;').should == '&#x05D0;'
			SanitizeUrl.decode_numeric_references('&#1488').should == '&#1488'
		end
		
		it 'decodes short-form decimal UTF-8 character references with a semicolon' do
			SanitizeUrl.decode_numeric_references('&#106;').should == 'j'
		end
		
		it 'decodes short-form decimal UTF-8 character references without a semicolon' do
			SanitizeUrl.decode_numeric_references('&#106').should == 'j'
		end
		
		it 'decodes long-form decimal UTF-8 character references with a semicolon' do
			SanitizeUrl.decode_numeric_references('&#0000106;').should == 'j'
		end
		
		it 'decodes long-form decimal UTF-8 character references without a semicolon' do
			SanitizeUrl.decode_numeric_references('&#0000106').should == 'j'
		end
		
		it 'decodes hex UTF-8 character references with a semicolon' do
			SanitizeUrl.decode_numeric_references('&#x6A;').should == 'j'
		end
		
		it 'decodes hex UTF-8 character references without a semicolon' do
			SanitizeUrl.decode_numeric_references('&#x6A').should == 'j'
		end
		
		it 'passes through multi-byte UTF-8 characters that are not URL-encoded' do
			# Hebrew Alef in UTF-8
			SanitizeUrl.decode_numeric_references("\xD7\x90").should == "\xD7\x90"
		end
	end
end
