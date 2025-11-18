"""
XML External Entity (XXE) Vulnerability Demo
OWASP A05:2021 - Security Misconfiguration
"""
import xml.etree.ElementTree as ET
import xml.sax
from lxml import etree
from flask import Flask, request

app = Flask(__name__)

@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    """VULNERABLE: XXE via ElementTree"""
    xml_data = request.data

    # VULNERABLE: Parsing XML without disabling external entities
    try:
        root = ET.fromstring(xml_data)
        return f"Parsed: {root.tag}"
    except Exception as e:
        return str(e), 400

@app.route('/process_xml', methods=['POST'])
def process_xml():
    """VULNERABLE: XXE via lxml"""
    xml_content = request.data

    # VULNERABLE: Using lxml parser without security settings
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_content, parser)

    return f"Root element: {tree.tag}"

def parse_soap_request(soap_xml):
    """VULNERABLE: XXE in SOAP parsing"""
    # VULNERABLE: No external entity restrictions
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(soap_xml, parser)
    return root

class XMLHandler(xml.sax.ContentHandler):
    """VULNERABLE: SAX parser without XXE protection"""
    def __init__(self):
        self.data = []

    def characters(self, content):
        self.data.append(content)

def parse_with_sax(xml_string):
    """VULNERABLE: SAX parsing with external entities enabled"""
    handler = XMLHandler()
    # VULNERABLE: No feature restrictions
    xml.sax.parseString(xml_string, handler)
    return handler.data

@app.route('/upload_config', methods=['POST'])
def upload_config():
    """VULNERABLE: XXE in config file upload"""
    xml_config = request.data

    # VULNERABLE: Parsing user-uploaded XML config
    parser = etree.XMLParser(
        resolve_entities=True,  # VULNERABLE
        no_network=False  # VULNERABLE: Allows network access
    )

    try:
        config = etree.fromstring(xml_config, parser)
        return f"Config loaded: {config.tag}"
    except Exception as e:
        return str(e), 400

def process_svg_upload(svg_content):
    """VULNERABLE: XXE via SVG file"""
    # VULNERABLE: SVG files are XML and can contain XXE
    parser = etree.XMLParser()
    svg = etree.fromstring(svg_content, parser)
    return svg

@app.route('/rss_feed', methods=['POST'])
def parse_rss():
    """VULNERABLE: XXE in RSS feed parsing"""
    rss_xml = request.data

    # VULNERABLE: Parsing external RSS without validation
    root = ET.fromstring(rss_xml)

    items = []
    for item in root.findall('.//item'):
        title = item.find('title').text
        items.append(title)

    return {'items': items}

def import_xml_data(xml_file_path):
    """VULNERABLE: XXE in file import"""
    # VULNERABLE: Parsing XML files with external entities
    tree = etree.parse(xml_file_path)
    root = tree.getroot()
    return root

if __name__ == '__main__':
    # Example XXE payload:
    # <?xml version="1.0"?>
    # <!DOCTYPE foo [
    #   <!ENTITY xxe SYSTEM "file:///etc/passwd">
    # ]>
    # <root>&xxe;</root>
    app.run(debug=True)
