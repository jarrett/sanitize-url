# Copyright sign

#def decimal_code_point_to_url_encoded(code_point)
#	utf_8_str = ([code_point.to_i].pack('U'))
#	'%' + utf_8_str.unpack('H2' * utf_8_str.length).join('%').upcase
#end

hex_code_point = 'A9'
decimal_code_point = '169'
hex_utf_8_bytes = '%C2%A9'

#puts 'Expected: ' + hex_utf_8_bytes
#puts 'Actual:   ' + decimal_code_point_to_url_encoded(decimal_code_point)

evil = 'javascript:alert("XSS")'
puts evil.unpack('H2' * evil.length).join('%').upcase