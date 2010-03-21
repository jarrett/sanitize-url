	require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
	
	describe 'Char codes' do
		it 'counts a number as being in the range 48-57' do
			(0..9).each do |num|
				c = num.to_s
				code = c[0].is_a?(String) ? c.ord : c[0]
				code.should == 48 + num
			end
		end
		
		it 'counts an uppercase letter as being in the range 65-90' do
			('A'..'Z').each_with_index do |c, offset|
				code = c[0].is_a?(String) ? c.ord : c[0]
				code.should == 65 + offset
			end
		end
		
		it 'counts a lowercase letter as being in the range 97-122' do
			('a'..'z').each_with_index do |c, offset|
				code = c[0].is_a?(String) ? c.ord : c[0]
				code.should == 97 + offset
			end
		end
		
		['!', '*', "'", '(', ')', ';', ':', '@', '&', '=', '+', '$', ',', '/', '?', '%', '#', '[', ']', '-', '_', '.', '~'].each do |c|
			it "counts #{c} as included in VALID_OPAQUE_CHAR_CODES" do
				code = c[0].is_a?(String) ? c.ord : c[0]
				SanitizeUrl::VALID_OPAQUE_CHAR_CODES.should include(code)
			end
		end
	end