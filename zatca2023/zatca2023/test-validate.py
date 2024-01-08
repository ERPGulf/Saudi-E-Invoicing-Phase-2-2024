from lxml import etree

# Load XML and XSLT
xml = etree.parse('sdsign-ed.xml')
xslt = etree.parse('xsl.xsl')

# Transform
transform = etree.XSLT(xslt)
result = transform(xml)

# Print result
print(str(result))
