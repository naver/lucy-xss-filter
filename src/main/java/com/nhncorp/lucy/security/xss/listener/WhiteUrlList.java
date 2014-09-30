/*
 *	Copyright 2014 Naver Corp.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *		http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 */	
package com.nhncorp.lucy.security.xss.listener;

import java.io.IOException;
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
 * @author Naver Labs
 * 
 */
public final class WhiteUrlList {
	private static final String CONFIG = "/white-url.xml";

	public volatile static WhiteUrlList instance;
	private List<Pattern> patterns;

	private WhiteUrlList() {
		this.patterns = new ArrayList<Pattern>();

		java.net.URL url = XssConfiguration.class.getResource(CONFIG);
		InputStream is = null;

		try {
			is = new java.io.FileInputStream(url.getFile());
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Element root = builder.parse(is).getDocumentElement();
			NodeList list = root.getElementsByTagName("pattern");
			if (list != null && list.getLength() > 0) {
				for (int i = 0; i < list.getLength(); i++) {
					String value = list.item(i).getTextContent();
					if (value != null) {
						this.patterns.add(buildPattern(value.trim()));
					}
				}
			}
		} catch (Exception ex) {
			System.out.println(ex.toString());
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
				}
			}
		}

	}

	public static WhiteUrlList getInstance() {
		//Double checking
		//if (instance == null) {
		synchronized (WhiteUrlList.class) {
			if (instance == null) {
				instance = new WhiteUrlList();
			}
		}
		//}

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

		if (this.patterns != null) {
			for (Pattern pattern : this.patterns) {
				if (pattern.matcher(url).matches()) {
					return true;
				}
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