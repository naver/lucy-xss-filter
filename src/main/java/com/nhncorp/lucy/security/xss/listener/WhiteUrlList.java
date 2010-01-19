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
 * 이 클래스는 {@code "white-url.xml"} 을 바탕으로 White List를 생성한다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 20085 $, $Date: 2009-02-05 18:19:28 +0900 (목, 05 2 2009) $
 */
public final class WhiteUrlList {

	private static String CONFIG = "/white-url.xml";

	public volatile static WhiteUrlList instance;
	private List<Pattern> patterns;

	private WhiteUrlList() throws Exception {
		java.net.URL url = XssConfiguration.class.getResource(CONFIG);
		InputStream is = new java.io.FileInputStream(url.getFile());

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
	}

	public static WhiteUrlList getInstance() throws Exception {
		if (instance == null) {
			synchronized (WhiteUrlList.class) {
				if (instance == null) {
					instance = new WhiteUrlList();
				}
			}
		}

		return instance;
	}

	public static WhiteUrlList reload() throws Exception {
		instance = null;
		return getInstance();
	}

	public boolean contains(String url) {
		if (url == null || "".equals(url)) {
			return false;
		}

		for (Pattern p : this.patterns) {
			if (p.matcher(url).matches()) {
				return true;
			}
		}
		return false;
	}

	private static Pattern buildPattern(String raw) {
		StringWriter writer = new StringWriter();
		writer.write("['\"]?\\s*(?i:");

		int pos = 0;
		int length = raw.length();
		for (int i = 0; i < raw.length(); i++) {
			char c = raw.charAt(i);
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
				break;
			}
		}

		if (length > pos) {
			writer.write(raw, pos, length - pos);
		}

		writer.write(")\\s*['\"]?");

		return Pattern.compile(writer.toString());
	}
}
