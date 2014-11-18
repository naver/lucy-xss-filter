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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
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
public final class XssConfiguration {
	private static final String DEFAULT_CONFIG = "/lucy-xss-default.xml";

	private Map<String, ElementRule> tags;
	private Map<String, AttributeRule> atts;
	private Map<String, Set<String>> tagGroups;
	private Map<String, Set<String>> attGroups;
	//private boolean neloAsyncLog;
	private String service = "UnknownService";
	private boolean blockingPrefixEnabled;
	private String blockingPrefix = "diabled_";
	private boolean filteringTagInCommentEnabled = true;
	private String filteringTagInCommentType = "strict";

	private Map<String, Set<String>> childElementRef; //elementGroup - key Element Group을 하위에 포함할 수 있는 Element
	private Map<String, Set<String>> childElementGroupRef; // elementGroup - key Group에 포함되는 ChildGroup
	private Map<String, Set<String>> parentElementGroupRef; // elementGroup - key Group을 포함하는 ParentGroup

	private Map<String, Set<String>> childAttrRef; // attrGroup - key Attribute Group을 포함할 수 있는 Element
	private Map<String, Set<String>> childAttrGroupRef; // attrGroup - key Group에 포함되는 ChildGroup
	private Map<String, Set<String>> parentAttrGroupRef; // attrGroup - key Group을 포함하는 ParentGroup

	private XssConfiguration() {
		this.tags = new HashMap<String, ElementRule>();
		this.atts = new HashMap<String, AttributeRule>();
		this.tagGroups = new HashMap<String, Set<String>>();
		this.attGroups = new HashMap<String, Set<String>>();

		this.childElementRef = new HashMap<String, Set<String>>();
		this.childElementGroupRef = new HashMap<String, Set<String>>();
		this.parentElementGroupRef = new HashMap<String, Set<String>>();

		this.childAttrRef = new HashMap<String, Set<String>>();
		this.childAttrGroupRef = new HashMap<String, Set<String>>();
		this.parentAttrGroupRef = new HashMap<String, Set<String>>();
	}

	/**
	 * 이 메소드는 특정 파일로부터 XSS Filter 설정 내용을 로딩하여, 새로운 인스턴스를 리턴한다.
	 *
	 * @param file	XSS Filter 설정파일.
	 * @return	XssConfiguration 인스턴스.
	 * @throws Exception	설정 내용을 담고 있는 파일이 예상치 못한 포멧을 가지고 있을 경우 발생.
	 */
	public static XssConfiguration newInstance(String file) throws Exception {
		XssConfiguration config = null;

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

		config.closeConfigurationResource();
		return config;
	}

	private static XssConfiguration create(DocumentBuilder builder, String file) throws SAXException, IOException {
		XssConfiguration config = null;

		InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(file);
		if (is == null) {
			is = XssConfiguration.class.getResourceAsStream(DEFAULT_CONFIG);
		}

		try {
			Element root = builder.parse(is).getDocumentElement();
			String extend = root.getAttribute("extends");
			if (extend != null && !"".equals(extend)) {
				//InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(extend);
				config = create(builder, extend);
			}

			if (config == null) {
				config = new XssConfiguration();
			}

			// 항상 element rule 이전에 Group을 먼저 정의한다.
			// 정의된 Group이 rule에 영향을 주기 때문이다.
			NodeList list = root.getElementsByTagName("elementGroup");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addElementGroup(Element.class.cast(list.item(i)));
			}

			list = root.getElementsByTagName("attributeGroup");
			for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
				config.addAttributeGroup(Element.class.cast(list.item(i)));
			}

			list = root.getElementsByTagName("element");
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
		String endTag = element.getAttribute("endTag");
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

		if (endTag != null && ("true".equalsIgnoreCase(endTag) || "false".equalsIgnoreCase(endTag))) {
			rule.setEndTag("true".equalsIgnoreCase(endTag) ? true : false);
		}

		if (removeTag != null && ("true".equalsIgnoreCase(removeTag) || "false".equalsIgnoreCase(removeTag))) {
			rule.setRemoveTag("true".equalsIgnoreCase(removeTag) ? true : false);
		}

		if (disable != null && ("true".equalsIgnoreCase(disable) || "false".equalsIgnoreCase(disable))) {
			rule.setDisabled("true".equalsIgnoreCase(disable) ? true : false);
		}

		NodeList list = element.getElementsByTagName("attributes");
		if (list != null && list.getLength() > 0) {
			Element attributes = Element.class.cast(list.item(0));

			list = attributes.getChildNodes();
			this.addAttrGroupRef(list, name);
			rule.addAllowedAttributes(this.getReferences(list, this.attGroups, null));
		}

		list = element.getElementsByTagName("elements");
		if (list != null && list.getLength() > 0) {
			Element elements = Element.class.cast(list.item(0));

			list = elements.getChildNodes();
			this.addElementGroupRef(list, name);
			rule.addAllowedElements(this.getReferences(list, this.tagGroups, null));
		}

		list = element.getElementsByTagName("listener");
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			String className = list.item(i).getTextContent();
			if (className != null) {
				try {
					Object obj = Class.forName(className.trim()).newInstance();
					rule.addListener(ElementListener.class.cast(obj));
				} catch (Exception ex) {
					System.out.println(name + "태그의 " + className + "(ElementListener) 설정 중 오류 발생. xml 설정을 확인하세요. " + ex.toString());
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
					System.out.println(name + "속성의 " + className + "(AttributeListener) 설정 중 오류 발생. xml 설정을 확인하세요. " + ex.toString());
					// ignore
				}
			}
		}
	}

	private void addElementGroup(Element element) {

		String name = element.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(element.getAttribute("override"));

		if (name == null || "".equals(name)) {
			return;
		}

		Set<String> tagGroup = null;

		if (override) {
			tagGroup = this.tagGroups.get(name);
		}

		if (tagGroup == null) {
			tagGroup = new HashSet<String>();
		}

		NodeList list = element.getElementsByTagName("ref");
		Set<String> nestedGroups = new HashSet<String>();
		Collection<String> refs = this.getReferences(list, this.tagGroups, nestedGroups);
		if (refs != null && !refs.isEmpty()) {
			tagGroup.addAll(refs);
		}

		if (nestedGroups != null && !nestedGroups.isEmpty()) {
			Set<String> childGroup = new HashSet<String>();
			for (String nestedGroup : nestedGroups) {
				if (this.childElementGroupRef.containsKey(nestedGroup)) {
					childGroup.addAll(this.childElementGroupRef.get(nestedGroup));
				}

				Set<String> parentElementGroup = this.parentElementGroupRef.get(nestedGroup);
				if (parentElementGroup == null) {
					parentElementGroup = new HashSet<String>();
				}
				parentElementGroup.add(name);
				this.parentElementGroupRef.put(nestedGroup, parentElementGroup);
			}

			if (!childGroup.isEmpty()) {
				nestedGroups.addAll(childGroup);
			}

			this.childElementGroupRef.put(name, nestedGroups);
		}

		this.tagGroups.put(name, tagGroup);

		if (this.parentElementGroupRef.containsKey(name)) {
			for (String parentName : this.parentElementGroupRef.get(name)) {
				this.tagGroups.get(parentName).addAll(tagGroup);
			}
		}

		if (override) {

			/**
			 * TO-DO :
			 */
			Set<String> elementSet = this.childElementRef.get(name);

			if (elementSet != null) {

				for (String tagName : elementSet) {
					ElementRule rule = this.tags.get(tagName);
					rule.addAllowedElements(refs);
				}
			}
		}
	}

	private void addAttributeGroup(Element element) {
		String name = element.getAttribute("name");
		boolean override = !"false".equalsIgnoreCase(element.getAttribute("override"));

		if (name == null || "".equals(name)) {
			return;
		}

		Set<String> attGroup = null;

		if (override) {
			attGroup = this.attGroups.get(name);
		}

		if (attGroup == null) {
			attGroup = new HashSet<String>();
		}

		NodeList list = element.getElementsByTagName("ref");
		Set<String> nestedGroups = new HashSet<String>();
		Collection<String> refs = this.getReferences(list, this.attGroups, nestedGroups);
		if (refs != null && !refs.isEmpty()) {
			attGroup.addAll(refs);
		}

		if (nestedGroups != null && !nestedGroups.isEmpty()) {
			Set<String> childGroup = new HashSet<String>();
			for (String nestedGroup : nestedGroups) {
				if (this.childAttrGroupRef.containsKey(nestedGroup)) {
					childGroup.addAll(this.childAttrGroupRef.get(nestedGroup));
				}

				Set<String> parentElementGroup = this.parentAttrGroupRef.get(nestedGroup);
				if (parentElementGroup == null) {
					parentElementGroup = new HashSet<String>();
				}
				parentElementGroup.add(name);
				this.parentAttrGroupRef.put(nestedGroup, parentElementGroup);
			}

			if (!childGroup.isEmpty()) {
				nestedGroups.addAll(childGroup);
			}

			this.childAttrGroupRef.put(name, nestedGroups);
		}

		this.attGroups.put(name, attGroup);

		if (this.parentAttrGroupRef.containsKey(name)) {
			for (String parentName : this.parentAttrGroupRef.get(name)) {
				this.attGroups.get(parentName).addAll(attGroup);
			}
		}

		if (override) {
			/**
			 * TO-DO :
			 */
			Set<String> elementSet = this.childAttrRef.get(name);

			if (elementSet != null) {

				for (String tagName : elementSet) {
					ElementRule rule = this.tags.get(tagName);
					rule.addAllowedAttributes(refs);
				}
			}
		}
	}

	private void addElementGroupRef(NodeList list, String tagName) {

		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			Node node = list.item(i);
			if (!(node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("ref"))) {
				continue;
			}

			Element ref = Element.class.cast(node);
			String tagGroupName = ref.getAttribute("name");
			Set<String> nestedGroupNames = new HashSet<String>();

			if (this.tagGroups.containsKey(tagGroupName)) { //elementGroup name 이면,
				nestedGroupNames.add(tagGroupName);
				Set<String> tagGroupSet = this.childElementGroupRef.get(tagGroupName);

				if (tagGroupSet != null) {
					nestedGroupNames.addAll(tagGroupSet);
				}

				for (String groupName : nestedGroupNames) {
					if (this.childElementRef.containsKey(groupName)) {
						Set<String> elementList = this.childElementRef.get(groupName);
						elementList.add(tagName);
					} else {
						Set<String> newElementSet = new HashSet<String>();
						newElementSet.add(tagName);
						this.childElementRef.put(groupName, newElementSet);
					}
				}

			}
		}

	}

	private void addAttrGroupRef(NodeList list, String tagName) {

		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			Node node = list.item(i);
			if (!(node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("ref"))) {
				continue;
			}

			Element ref = Element.class.cast(node);
			String attGroupName = ref.getAttribute("name");
			Set<String> nestedAttNames = new HashSet<String>();

			if (this.attGroups.containsKey(attGroupName)) { //att ref가 앞서 선언된 AttGroup 이면,
				nestedAttNames.add(attGroupName);
				Set<String> attGroupSet = this.childAttrGroupRef.get(attGroupName); // 이 attGroup이 또다른 attGroup을 child로 가지고 있는지 확

				if (attGroupSet != null) { // childGroup을 가지고 있다면,
					nestedAttNames.addAll(attGroupSet); // 추가
				}

				for (String groupName : nestedAttNames) { // 모든 attGroup에 대해
					if (this.childAttrRef.containsKey(groupName)) { // 해당 attGroup을 가질 수 있는 Element를 추출 하여
						Set<String> elementList = this.childAttrRef.get(groupName);
						elementList.add(tagName); // 모든 attGroup에 현재 tagName을 연결
					} else {
						Set<String> newElementSet = new HashSet<String>();
						newElementSet.add(tagName);
						this.childAttrRef.put(groupName, newElementSet);
					}
				}
			}
		}

	}

	private Collection<String> getReferences(NodeList list, Map<String, Set<String>> groups, Set<String> nestedGroups) {
		Collection<String> result = new ArrayList<String>();
		for (int i = 0; list.getLength() > 0 && i < list.getLength(); i++) {
			Node node = list.item(i);
			if (!(node.getNodeType() == Node.ELEMENT_NODE && node.getNodeName().equals("ref"))) {
				continue;
			}

			Element ref = Element.class.cast(node);
			String name = ref.getAttribute("name");
			if (groups.containsKey(name)) {

				if (nestedGroups != null) {
					nestedGroups.add(name);
				}

				Set<String> names = new HashSet<String>(groups.get(name));
				NodeList excludes = ref.getElementsByTagName("excludes");
				if (excludes != null && excludes.getLength() > 0) {
					Collection<String> tmp = this.getReferences(Element.class.cast(excludes.item(0)).getElementsByTagName("ref"), groups, null);
					if (tmp != null && !tmp.isEmpty()) {
						names.removeAll(tmp);
					}
				}

				if (!names.isEmpty()) {
					result.addAll(names);
				}
			} else {
				result.add(name);
			}
		}

		return result;
	}

/*	public void setNeloAsyncLog(boolean neloAsyncLog) {
		this.neloAsyncLog = neloAsyncLog;
	}

	public boolean enableNeloAsyncLog() {
		return neloAsyncLog;
	}*/

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

	public void closeConfigurationResource() {

		this.childElementRef = null;
		this.childElementGroupRef = null;
		this.parentElementGroupRef = null;

		this.childAttrGroupRef = null;
		this.childAttrRef = null;
		this.parentAttrGroupRef = null;
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
