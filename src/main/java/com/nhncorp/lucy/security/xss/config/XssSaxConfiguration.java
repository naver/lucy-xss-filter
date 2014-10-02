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
package com.nhncorp.lucy.security.xss.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.nhncorp.lucy.security.xss.event.AttributeListener;
import com.nhncorp.lucy.security.xss.event.ElementListener;

/**
 * 이 클래스는 XSS Filter 설정 내용을 나타낸다. <br/>
 * 만약, 설정 내용을 담고 있는 파일이 존재 하지 않거나 예상치 못한 포멧을 가지고 있다면, Exception을 발생 시킨다.
 *
 * @author Naver Labs
 *
 */
public final class XssSaxConfiguration {
	private static final String DEFAULT_CONFIG = "/lucy-xss-default-sax.xml";

	private Map<String, ElementRule> tags;
	private Map<String, AttributeRule> atts;
//	private boolean neloAsyncLog;
	private String service = "UnknownService";
	private boolean blockingPrefixEnabled;
	private String blockingPrefix = "diabled_";
	private boolean filteringTagInCommentEnabled = true;
	private String filteringTagInCommentType = "strict";
	
	private XssSaxConfiguration() {
		this.tags = new HashMap<String, ElementRule>();
		this.atts = new HashMap<String, AttributeRule>();
	}

	/**
	 * 이 메소드는 특정 파일로부터 XSS Filter 설정 내용을 로딩하여, 새로운 인스턴스를 리턴한다.
	 *
	 * @param file	XSS Filter 설정파일.
	 * @return	XssConfiguration 인스턴스.
	 * @throws Exception	설정 내용을 담고 있는 파일이 예상치 못한 포멧을 가지고 있을 경우 발생.
	 */
	public static XssSaxConfiguration newInstance(String file) throws Exception {
		XssSaxConfiguration config = null;

		//		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
		//		if (is == null) {
		//			is = XssConfiguration.class.getResourceAsStream(DEFAULT_CONFIG);
		//		}

		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();

			config = create(builder, file);

			if (config == null) {
				throw new Exception(String.format("The XSS configuration file [%s] is not a expected xml document.", file));
			}
		} catch (Exception ex) {
			throw new Exception(String.format("Cannot parse the XSS configuration file [%s].", file), ex);
		}

		return config;
	}

	private static XssSaxConfiguration create(DocumentBuilder builder, String file) throws SAXException, IOException {
		XssSaxConfiguration config = null;

		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
		if (is == null) {
			is = XssSaxConfiguration.class.getResourceAsStream(DEFAULT_CONFIG);
		}

		try {
			Element root = builder.parse(is).getDocumentElement();
			String extend = root.getAttribute("extends");
			if (extend != null && !"".equals(extend)) {
				//InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(extend);
				config = create(builder, extend);
			}

			if (config == null) {
				config = new XssSaxConfiguration();
			}

			NodeList list = root.getElementsByTagName("element");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addElementRule(Element.class.cast(list.item(i)));

			}

			list = root.getElementsByTagName("attribute");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addAttributeRule(Element.class.cast(list.item(i)));
			}

/*			list = root.getElementsByTagName("neloAsyncLog");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.enableNeloAsyncLog(Element.class.cast(list.item(i)));
			}*/

			list = root.getElementsByTagName("blockingPrefix");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.enableBlockingPrefix(Element.class.cast(list.item(i)));
			}
			
			list = root.getElementsByTagName("filteringTagInComment");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.enableFilteringTagInComment(Element.class.cast(list.item(i)));
			}

		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException ioe) {
				}
			}

		}

		return config;
	}

	private void enableBlockingPrefix(Element element) {
		String enable = element.getAttribute("enable");
		String prefix = element.getAttribute("prefix");

		if (enable != null && ("true".equalsIgnoreCase(enable) || "false".equalsIgnoreCase(enable))) {
			this.setBlockingPrefixEnabled("true".equalsIgnoreCase(enable) ? true : false);
		}

		if (prefix != null && !prefix.isEmpty()) {
			this.setBlockingPrefix(prefix);
		}

	}

	public ElementRule getElementRule(String tagName) {
		ElementRule rule = null;
		if (tagName != null && this.tags != null && !this.tags.isEmpty()) {
			rule = this.tags.get(tagName.toLowerCase());
		}

		return rule;
	}

	public AttributeRule getAttributeRule(String attName) {
		AttributeRule rule = null;
		if (attName != null && this.atts != null && !this.atts.isEmpty()) {
			rule = this.atts.get(attName.toLowerCase());
		}

		return rule;
	}

	/*private void enableNeloAsyncLog(Element element) {
		String enable = element.getAttribute("enable");
		String serviceName = element.getAttribute("service");

		if (enable != null && ("true".equalsIgnoreCase(enable) || "false".equalsIgnoreCase(enable))) {
			this.setNeloAsyncLog("true".equalsIgnoreCase(enable) ? true : false);
		}

		if (serviceName != null && !serviceName.isEmpty()) {
			this.setService(serviceName);
		}
	}*/

	private void addElementRule(Element element) {
		String name = element.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(element.getAttribute("override"));
		String disable = element.getAttribute("disable");
		String removeTag = element.getAttribute("removeTag");

		if (name == null || "".equals(name)) {
			return;
		}

		ElementRule rule = null;
		if (override) {
			rule = this.tags.get(name);
		}

		if (rule == null || !override) {
			rule = new ElementRule(name);
			this.tags.put(name.toLowerCase(), rule);
		}

		if (removeTag != null && ("true".equalsIgnoreCase(removeTag) || "false".equalsIgnoreCase(removeTag))) {
			rule.setRemoveTag("true".equalsIgnoreCase(removeTag) ? true : false);
		}

		if (disable != null && ("true".equalsIgnoreCase(disable) || "false".equalsIgnoreCase(disable))) {
			rule.setDisabled("true".equalsIgnoreCase(disable) ? true : false);
		}

		NodeList list = element.getElementsByTagName("attributes");

		list = element.getElementsByTagName("listener");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			String className = list.item(i).getTextContent();
			if (className != null) {
				try {
					Object obj = Class.forName(className.trim()).newInstance();
					rule.addListener(ElementListener.class.cast(obj));
				} catch (Exception ex) {
					// ignore
				}
			}
		}
	}

	private void addAttributeRule(Element element) {
		String name = element.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(element.getAttribute("override"));
		String disable = element.getAttribute("disable");
		//Base64Decoding
		String base64Decoding = element.getAttribute("base64Decoding");
		String exceptionTagList = element.getAttribute("exceptionTagList");

		if (name == null || "".equals(name)) {
			return;
		}

		AttributeRule rule = null;
		if (override) {
			rule = this.atts.get(name);
		}

		if (rule == null || !override) {
			rule = new AttributeRule(name);
			this.atts.put(name.toLowerCase(), rule);
		}

		if (disable != null && ("true".equalsIgnoreCase(disable) || "false".equalsIgnoreCase(disable))) {
			rule.setDisabled("true".equalsIgnoreCase(disable) ? true : false);
		}

		if (exceptionTagList != null && exceptionTagList.length() > 0) {
			String[] tokens = exceptionTagList.split(",");
			if (tokens != null) {
				for (int i = 0; i < tokens.length; i++) {
					if (tokens[i] != null) {
						String exceptionTag = tokens[i].trim();
						rule.addExceptionTag(exceptionTag);
					}
				}
			}
		}

		//Base64Decoding
		if (base64Decoding != null && ("true".equalsIgnoreCase(base64Decoding) || "false".equalsIgnoreCase(base64Decoding))) {
			rule.setBase64Decoding("true".equalsIgnoreCase(base64Decoding) ? true : false);
		}

		NodeList list = element.getElementsByTagName("allowedPattern");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			rule.addAllowedPattern(list.item(i).getTextContent());
		}

		list = element.getElementsByTagName("notAllowedPattern");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			rule.addNotAllowedPattern(list.item(i).getTextContent());
		}

		list = element.getElementsByTagName("listener");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			String className = list.item(i).getTextContent();
			if (className != null) {
				try {
					Object obj = Class.forName(className.trim()).newInstance();
					rule.addListener(AttributeListener.class.cast(obj));
				} catch (Exception ex) {
					// ignore
				}
			}
		}
	}

/*	public void setNeloAsyncLog(boolean neloAsyncLog) {
		this.neloAsyncLog = neloAsyncLog;
	}

	public boolean enableNeloAsyncLog() {
		return neloAsyncLog;
	}
*/
	public void setService(String service) {
		this.service = service;
	}

	public String getService() {
		return service;
	}

	public void setBlockingPrefixEnabled(boolean isEnableBlockingPrefix) {

		this.blockingPrefixEnabled = isEnableBlockingPrefix;
	}

	public boolean isEnableBlockingPrefix() {

		return this.blockingPrefixEnabled;
	}

	public void setBlockingPrefix(String blockingPrefix) {
		this.blockingPrefix = blockingPrefix;
	}

	public String getBlockingPrefix() {
		return blockingPrefix;
	}
	
	private void enableFilteringTagInComment(Element element) {
		String enable = element.getAttribute("enable");
		String type = element.getAttribute("type");

		if (enable != null && ("true".equalsIgnoreCase(enable) || "false".equalsIgnoreCase(enable))) {
			this.setFilteringTagInCommentEnabled("true".equalsIgnoreCase(enable) ? true : false);
		}

		if (type != null && !type.isEmpty()) {
			this.setFilteringTagInCommentType(type);
		}
	}

	private void setFilteringTagInCommentType(String type) {
		this.filteringTagInCommentType = type;
		//strict or config
	}
	
	private void setFilteringTagInCommentEnabled(boolean enabled) {
		this.filteringTagInCommentEnabled = enabled;
	}

	public boolean isFilteringTagInCommentEnabled() {
		return this.filteringTagInCommentEnabled;
	}

	public boolean isNoTagAllowedInComment() {
		return "strict".endsWith(this.filteringTagInCommentType);
	}
}
