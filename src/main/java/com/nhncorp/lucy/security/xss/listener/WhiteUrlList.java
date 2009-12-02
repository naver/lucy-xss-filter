package com.nhncorp.lucy.security.xss.listener;

import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.nhncorp.lucy.security.xss.config.XssConfiguration;

/**
 * ���대옒�ㅻ뒗 {@code "white-url.xml"} ��諛뷀깢�쇰줈 White List瑜��앹꽦�쒕떎.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22800 $, $Date: 2009-11-27 17:12:20 +0900 (금, 27 11 2009) $
 */
public final class WhiteUrlList {
	private static final String CONFIG = "/white-url.xml";
	private static volatile WhiteUrlList instance;
	private List<Pattern> patterns;
	
	private WhiteUrlList() throws Exception {
		java.net.URL url = XssConfiguration.class.getResource(CONFIG);

		InputStream is = null;

		try {
		
			is = new java.io.FileInputStream(url.getFile());
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Element root = builder.parse(is).getDocumentElement();
			NodeList list = root.getElementsByTagName("pattern");
			
			if (list != null && list.getLength() > 0) {
			
				this.patterns = new ArrayList<Pattern>();
				
				for (int i = 0; i < list.getLength(); i++) {
				
					String value = list.item(i).getTextContent();
					
					if (value != null) {
					
						this.patterns.add(buildPattern(value.trim()));
					}
				}
			}
		} finally {
			if (is != null) {
				try {
				
					is.close();
				} catch (Exception e) {
				
					e.getMessage();
				}
			}
		}

	}

	/**
	 * 
	 * @return WhiteUrlList
	 * @throws Exception Exeception
	 */
	public static synchronized WhiteUrlList getInstance() throws Exception {
		if (instance == null) {

			instance = new WhiteUrlList();
		}

		return instance;
	}

	/**
	 * 
	 * @return WhiteUrlList
	 * @throws Exception Exception
	 */
	public static WhiteUrlList reload() throws Exception {
		instance = null;
		return getInstance();
	}

	/**
	 * 
	 * @param url String
	 * @return boolean
	 */
	public boolean contains(String url) {
		if (url == null || "".equals(url)) {
		
			return false;
		}

		List<Pattern> tempPattern = this.patterns;
		Pattern pattern = null;
		
		for (int i = 0; (tempPattern != null) && i < tempPattern.size(); i++) {
			pattern = tempPattern.get(i);

			//for (Pattern p : this.patterns) {
			if (pattern.matcher(url).matches()) {
				return true;
			}
		}
		
		return false;
	}

	/**
	 * 
	 * @param raw String
	 * @return Pattern
	 */
	private static Pattern buildPattern(String raw) {
		StringWriter writer = new StringWriter();
		writer.write("['\"]?\\s*(?i:");

		int pos = 0;
		int length = raw.length();
	
		for (int i = 0; i < raw.length(); i++) {
			char c = raw.charAt(i);
			boolean flag = false;

			switch (c) {
				case '\\':
				case '+':
				case '{':
				case '}':
				case '[':
				case ']':
				case '^':
				case '$':
				case '&':
				case '.':
				case '?':
				case '(':
				case ')':
				case '*':
					flag = true;
					break;
				default :
			}
			
			if (flag) {
				if (i > pos) {
					writer.write(raw, pos, i - pos);
				}

				if (c == '*') {
					writer.write(".*");
				} else {
					writer.write("\\");
					writer.write(c);
				}
			
				pos = i + 1;
			}
			
		}

		if (length > pos) {
			writer.write(raw, pos, length - pos);
		}

		writer.write(")\\s*['\"]?");

		return Pattern.compile(writer.toString());
	}
}
