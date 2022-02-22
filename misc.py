
def list_to_xml_array(l):
	xml = "<array><data>"
	for x in l:
		xml += '<value>'
		if isinstance(x, int):
			xml += f'<int>{x}</int>'
		elif isinstance(x, str):
			xml += f'<string>{x}</string>'
		elif isinstance(x, bool):
			xml += f'<boolean>{x}</boolean>'
		elif isinstance(x, list):
			xml += list_to_xml_array(x)
		else:
			raise ValueError('list_to_xml_array: bad input type')

		xml += '</value>'
	xml += "</data></array>"
	return xml

